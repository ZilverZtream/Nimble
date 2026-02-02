use anyhow::Result;
use nimble_net::peer::{PeerConnection, PeerMessage, PeerState};
use nimble_storage::disk::DiskStorage;
use nimble_util::bitfield::Bitfield;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use crate::endgame::{BlockId, EndgameMode};

const MAX_PEERS_PER_TORRENT: usize = 50;
const MAX_CONNECT_ATTEMPTS: usize = 5;
const MAX_CONNECT_PER_SECOND: usize = 10;
const BLOCK_SIZE: u32 = 16384;
const MAX_PENDING_PER_PEER: usize = 5;
const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(60);
const MAX_CANDIDATE_PEERS: usize = 2000;
const BLOCK_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const FAILED_PEER_TTL: Duration = Duration::from_secs(300);
const CONNECTION_RATE_WINDOW: Duration = Duration::from_secs(1);

pub struct PeerManager {
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    piece_count: usize,
    piece_length: u64,
    total_length: u64,
    metadata_only: bool,
    pending_metadata: Option<Vec<u8>>,
    peers: HashMap<SocketAddrV4, ManagedPeer>,
    candidate_peers: VecDeque<SocketAddrV4>,
    failed_peers: HashMap<SocketAddrV4, (Instant, usize)>,
    piece_picker: PiecePicker,
    endgame: EndgameMode,
    pending_upload_requests: Vec<(SocketAddrV4, u32, u32, u32)>,
    connection_attempts: VecDeque<Instant>,
    last_connection_attempt: Instant,
}

struct ManagedPeer {
    connection: PeerConnection,
    pending_blocks: Vec<BlockRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BlockRequest {
    piece: u32,
    offset: u32,
    length: u32,
    sent_at: Instant,
}

impl PeerManager {
    pub fn new(
        info_hash: [u8; 20],
        peer_id: [u8; 20],
        piece_count: usize,
        piece_length: u64,
        total_length: u64,
    ) -> Self {
        PeerManager {
            info_hash,
            peer_id,
            piece_count,
            piece_length,
            total_length,
            metadata_only: false,
            pending_metadata: None,
            peers: HashMap::new(),
            candidate_peers: VecDeque::new(),
            failed_peers: HashMap::new(),
            piece_picker: PiecePicker::new(piece_count),
            endgame: EndgameMode::new(),
            pending_upload_requests: Vec::new(),
            connection_attempts: VecDeque::new(),
            last_connection_attempt: Instant::now(),
        }
    }

    pub fn new_metadata_only(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        PeerManager {
            info_hash,
            peer_id,
            piece_count: 0,
            piece_length: 0,
            total_length: 0,
            metadata_only: true,
            pending_metadata: None,
            peers: HashMap::new(),
            candidate_peers: VecDeque::new(),
            failed_peers: HashMap::new(),
            piece_picker: PiecePicker::new(0),
            endgame: EndgameMode::new(),
            pending_upload_requests: Vec::new(),
            connection_attempts: VecDeque::new(),
            last_connection_attempt: Instant::now(),
        }
    }

    pub fn add_peers(&mut self, addrs: &[SocketAddrV4]) {
        for &addr in addrs {
            if self.candidate_peers.len() >= MAX_CANDIDATE_PEERS {
                break;
            }

            if !self.peers.contains_key(&addr) && !self.candidate_peers.contains(&addr) {
                let should_add = self
                    .failed_peers
                    .get(&addr)
                    .map(|(time, count)| {
                        *count < MAX_CONNECT_ATTEMPTS && time.elapsed() >= CONNECT_RETRY_DELAY
                    })
                    .unwrap_or(true);

                if should_add {
                    self.candidate_peers.push_back(addr);
                }
            }
        }
    }

    pub fn accept_incoming(&mut self, connection: PeerConnection, addr: SocketAddrV4) -> Result<()> {
        if self.peers.len() >= MAX_PEERS_PER_TORRENT {
            anyhow::bail!("peer limit reached");
        }

        if self.peers.contains_key(&addr) {
            anyhow::bail!("peer already connected");
        }

        self.peers.insert(
            addr,
            ManagedPeer {
                connection,
                pending_blocks: Vec::new(),
            },
        );

        Ok(())
    }

    pub fn tick(&mut self, mut storage: Option<&mut DiskStorage>) -> Result<PeerManagerStats> {
        let mut stats = PeerManagerStats::default();

        self.connect_to_candidates();
        self.check_block_timeouts();

        let mut pieces_received = Vec::new();
        let mut peers_to_remove = Vec::new();
        let mut pex_added = HashSet::new();
        let mut pex_dropped = HashSet::new();

        for (&addr, peer) in self.peers.iter_mut() {
            match peer.connection.state() {
                PeerState::Connected => {
                    match Self::handle_peer_messages(peer, &mut self.piece_picker, &mut self.endgame, addr) {
                        Ok(blocks) => {
                            if let Some(update) = peer.connection.take_pex_updates() {
                                for addr in update.added {
                                    pex_added.insert(addr);
                                }
                                for addr in update.dropped {
                                    pex_dropped.insert(addr);
                                }
                            }

                            if !self.metadata_only {
                                if let Some(storage) = storage.as_mut() {
                                    for (index, begin, data) in blocks {
                                        if let Err(_) = storage.write_block(index as u64, begin, &data) {
                                            self.piece_picker.cancel_piece(index as usize);
                                        }
                                    }
                                }
                            }

                            if self.metadata_only && self.pending_metadata.is_none() {
                                if let Some(metadata) = peer.connection.take_metadata() {
                                    self.pending_metadata = Some(metadata);
                                }
                            }

                            if !self.metadata_only
                                && !peer.connection.is_choking()
                                && peer.pending_blocks.len() < MAX_PENDING_PER_PEER
                            {
                                Self::request_blocks(
                                    peer,
                                    &mut self.piece_picker,
                                    &mut self.endgame,
                                    addr,
                                    self.piece_length,
                                    self.total_length,
                                    self.piece_count,
                                );
                            }

                            if !self.metadata_only {
                                if storage.is_some() {
                                    let requests = peer.connection.take_peer_requests();
                                    for req in requests {
                                        self.pending_upload_requests.push((addr, req.index, req.begin, req.length));
                                    }
                                }
                            }

                            stats.downloaded = stats.downloaded.saturating_add(peer.connection.downloaded());
                            stats.uploaded = stats.uploaded.saturating_add(peer.connection.uploaded());
                        }
                        Err(_) => {
                            peers_to_remove.push(addr);
                        }
                    }
                }
                PeerState::Disconnected => {
                    peers_to_remove.push(addr);
                }
                _ => {}
            }
        }

        if let Some(storage) = storage.as_mut() {
            for piece_index in storage.poll_verifications() {
                pieces_received.push(piece_index as u32);
                self.piece_picker.mark_completed(piece_index as usize);
            }

            for piece_index in storage.take_failed_pieces() {
                self.piece_picker.cancel_piece(piece_index as usize);
            }

            let pieces_remaining = self.piece_count - self.piece_picker.completed_count();
            let blocks_remaining = self.piece_picker.pending_blocks.len();
            self.endgame.update_state(pieces_remaining, blocks_remaining);
        }

        for piece_index in &pieces_received {
            for (_, peer) in self.peers.iter_mut() {
                if peer.connection.state() == PeerState::Connected {
                    let _ = peer.connection.send_have(*piece_index);
                }
            }
        }

        if !self.metadata_only {
            if let Some(storage) = storage.as_mut() {
                for (addr, index, begin, length) in self.pending_upload_requests.drain(..) {
                    if self.peers.contains_key(&addr) {
                        let _ = storage.request_read_block(index as u64, begin, length, Some(addr));
                    }
                }

                let completed_reads = storage.poll_read_completions();
                for (peer_addr, piece_index, block_offset, data) in completed_reads {
                    if let Some(addr) = peer_addr {
                        if let Some(peer) = self.peers.get_mut(&addr) {
                            if peer.connection.state() == PeerState::Connected {
                                let _ = peer.connection.send_piece(piece_index as u32, block_offset, data);
                            }
                        }
                    }
                }
            }
        }

        for addr in peers_to_remove {
            if let Some(peer) = self.peers.remove(&addr) {
                for block in peer.pending_blocks {
                    self.piece_picker
                        .cancel_block(block.piece as usize, block.offset);
                }

                if let Some(bitfield) = peer.connection.bitfield() {
                    for piece in 0..bitfield.len() {
                        if bitfield.get(piece) {
                            self.piece_picker.update_availability(piece, false);
                        }
                    }
                }

                self.endgame.remove_peer(&addr);

                let entry = self.failed_peers.entry(addr).or_insert((Instant::now(), 0));
                entry.0 = Instant::now();
                entry.1 += 1;
            }
        }

        if !pex_added.is_empty() {
            let addrs: Vec<_> = pex_added.into_iter().collect();
            self.add_peers(&addrs);
        }
        if !pex_dropped.is_empty() {
            self.apply_pex_dropped(&pex_dropped);
        }

        stats.connected_peers = self.peers.len() as u32;
        stats.candidate_peers = self.candidate_peers.len() as u32;
        stats.pieces_completed = storage
            .as_deref()
            .map(|storage| storage.bitfield().count_ones() as u32)
            .unwrap_or(0);
        stats.pieces_total = self.piece_count as u32;

        Ok(stats)
    }

    fn connect_to_candidates(&mut self) {
        let now = Instant::now();

        while let Some(&oldest) = self.connection_attempts.front() {
            if now.duration_since(oldest) > CONNECTION_RATE_WINDOW {
                self.connection_attempts.pop_front();
            } else {
                break;
            }
        }

        let budget = MAX_CONNECT_PER_SECOND.saturating_sub(self.connection_attempts.len());
        if budget == 0 {
            return;
        }

        let mut attempts = 0;
        while self.peers.len() < MAX_PEERS_PER_TORRENT && attempts < budget {
            let addr = match self.candidate_peers.pop_front() {
                Some(a) => a,
                None => break,
            };

            self.connection_attempts.push_back(now);
            attempts += 1;

            let mut conn =
                PeerConnection::new_v4(addr, self.info_hash, self.peer_id, self.piece_count);

            match conn.connect() {
                Ok(()) => {
                    let _ = conn.set_interested(true);

                    self.peers.insert(
                        addr,
                        ManagedPeer {
                            connection: conn,
                            pending_blocks: Vec::new(),
                        },
                    );
                }
                Err(_) => {
                    let entry = self.failed_peers.entry(addr).or_insert((Instant::now(), 0));
                    entry.0 = Instant::now();
                    entry.1 += 1;
                }
            }
        }

        self.last_connection_attempt = now;
    }

    fn apply_pex_dropped(&mut self, dropped: &HashSet<SocketAddrV4>) {
        if dropped.is_empty() {
            return;
        }
        self.candidate_peers.retain(|addr| !dropped.contains(addr));
    }

    fn check_block_timeouts(&mut self) {
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            let timed_out: Vec<BlockRequest> = peer
                .pending_blocks
                .iter()
                .filter(|req| now.duration_since(req.sent_at) > BLOCK_REQUEST_TIMEOUT)
                .copied()
                .collect();

            for req in timed_out {
                peer.pending_blocks.retain(|r| !(r.piece == req.piece && r.offset == req.offset));
                self.piece_picker.cancel_block(req.piece as usize, req.offset);
            }
        }

        self.failed_peers.retain(|_, (timestamp, _)| {
            now.duration_since(*timestamp) < FAILED_PEER_TTL
        });
    }

    fn is_timeout_error(e: &anyhow::Error) -> bool {
        use std::io::ErrorKind;

        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            return matches!(io_err.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock);
        }

        let error_msg = e.to_string();
        error_msg.contains("timed out")
            || error_msg.contains("WSAETIMEDOUT")
            || error_msg.contains("10060")
    }

    fn is_fatal_error(e: &anyhow::Error) -> bool {
        use std::io::ErrorKind;

        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            return matches!(
                io_err.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::NotConnected
                    | ErrorKind::ConnectionRefused
            );
        }

        let error_msg = e.to_string();
        error_msg.contains("connection closed")
            || error_msg.contains("not connected")
            || error_msg.contains("info hash mismatch")
            || error_msg.contains("invalid protocol")
            || error_msg.contains("message too large")
    }

    fn handle_peer_messages(
        peer: &mut ManagedPeer,
        picker: &mut PiecePicker,
        endgame: &mut EndgameMode,
        peer_addr: SocketAddrV4,
    ) -> Result<Vec<(u32, u32, Vec<u8>)>> {
        let mut received_blocks = Vec::new();

        loop {
            match peer.connection.recv_message() {
                Ok(Some(msg)) => match msg {
                    PeerMessage::Piece {
                        index,
                        begin,
                        block,
                    } => {
                        peer.pending_blocks
                            .retain(|r| !(r.piece == index && r.offset == begin));
                        peer.connection.complete_request(index, begin);
                        received_blocks.push((index, begin, block));

                        let block_id = BlockId::new(index, begin);
                        endgame.record_completion(block_id);
                    }
                    PeerMessage::Unchoke => {}
                    PeerMessage::Choke => {
                        for block in peer.pending_blocks.drain(..) {
                            picker.cancel_block(block.piece as usize, block.offset);
                        }
                    }
                    PeerMessage::Have { piece_index } => {
                        picker.update_availability(piece_index as usize, true);
                    }
                    PeerMessage::Bitfield { bitfield } => {
                        let bf = Bitfield::from_bytes(&bitfield, picker.piece_count());
                        for i in 0..bf.len() {
                            if bf.get(i) {
                                picker.update_availability(i, true);
                            }
                        }
                    }
                    _ => {}
                },
                Ok(None) => break,
                Err(e) => {
                    if Self::is_timeout_error(&e) {
                        break;
                    }
                    if Self::is_fatal_error(&e) {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        Ok(received_blocks)
    }

    fn request_blocks(
        peer: &mut ManagedPeer,
        picker: &mut PiecePicker,
        endgame: &mut EndgameMode,
        peer_addr: SocketAddrV4,
        piece_length: u64,
        total_length: u64,
        piece_count: usize,
    ) {
        while peer.pending_blocks.len() < MAX_PENDING_PER_PEER {
            let piece_index = match picker.pick_piece(&peer.connection) {
                Some(idx) => idx,
                None => break,
            };

            let piece_len = if piece_index == piece_count - 1 {
                let remainder = total_length % piece_length;
                if remainder == 0 {
                    piece_length
                } else {
                    remainder
                }
            } else {
                piece_length
            };

            let block_count = ((piece_len + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) as u32;

            for block_idx in 0..block_count {
                if peer.pending_blocks.len() >= MAX_PENDING_PER_PEER {
                    break;
                }

                let offset = block_idx * BLOCK_SIZE;
                let length = if block_idx == block_count - 1 {
                    let remaining = piece_len - offset as u64;
                    remaining.min(BLOCK_SIZE as u64) as u32
                } else {
                    BLOCK_SIZE
                };

                let block_id = BlockId::new(piece_index as u32, offset);

                if !endgame.is_active() && picker.is_block_pending(piece_index, offset) {
                    continue;
                }

                if !endgame.can_request_block(block_id) {
                    continue;
                }

                let req = BlockRequest {
                    piece: piece_index as u32,
                    offset,
                    length,
                    sent_at: Instant::now(),
                };

                if peer
                    .connection
                    .request_block(req.piece, req.offset, req.length)
                    .is_ok()
                {
                    peer.pending_blocks.push(req);
                    picker.mark_block_pending(piece_index, offset);
                    endgame.record_request(block_id, peer_addr);
                }
            }

            picker.mark_piece_downloading(piece_index);
        }
    }

    pub fn connected_peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn piece_picker(&self) -> &PiecePicker {
        &self.piece_picker
    }

    pub fn sync_completed_pieces(&mut self, bitfield: &Bitfield) {
        for i in 0..bitfield.len() {
            if bitfield.get(i) {
                self.piece_picker.mark_completed(i);
            }
        }
    }

    pub fn take_metadata(&mut self) -> Option<Vec<u8>> {
        self.pending_metadata.take()
    }
}

#[derive(Debug, Default)]
pub struct PeerManagerStats {
    pub connected_peers: u32,
    pub candidate_peers: u32,
    pub downloaded: u64,
    pub uploaded: u64,
    pub pieces_completed: u32,
    pub pieces_total: u32,
}

use std::collections::BTreeMap;

pub struct PiecePicker {
    piece_count: usize,
    completed: Bitfield,
    downloading: Bitfield,
    availability: Vec<u32>,
    pending_blocks: HashSet<(usize, u32)>,
    rarity_buckets: BTreeMap<u32, Vec<usize>>,
}

impl PiecePicker {
    pub fn new(piece_count: usize) -> Self {
        PiecePicker {
            piece_count,
            completed: Bitfield::new(piece_count),
            downloading: Bitfield::new(piece_count),
            availability: vec![0; piece_count],
            pending_blocks: HashSet::new(),
            rarity_buckets: BTreeMap::new(),
        }
    }

    pub fn piece_count(&self) -> usize {
        self.piece_count
    }

    pub fn update_availability(&mut self, piece: usize, has: bool) {
        if piece >= self.piece_count {
            return;
        }

        let old_rarity = self.availability[piece];

        if has {
            self.availability[piece] = self.availability[piece].saturating_add(1);
        } else {
            self.availability[piece] = self.availability[piece].saturating_sub(1);
        }

        let new_rarity = self.availability[piece];

        if old_rarity != new_rarity && !self.completed.get(piece) && !self.downloading.get(piece) {
            if old_rarity > 0 {
                if let Some(bucket) = self.rarity_buckets.get_mut(&old_rarity) {
                    bucket.retain(|&p| p != piece);
                    if bucket.is_empty() {
                        self.rarity_buckets.remove(&old_rarity);
                    }
                }
            }

            if new_rarity > 0 {
                self.rarity_buckets.entry(new_rarity).or_insert_with(Vec::new).push(piece);
            }
        }
    }

    pub fn pick_piece(&self, peer: &PeerConnection) -> Option<usize> {
        for (_rarity, pieces) in self.rarity_buckets.iter() {
            for &piece in pieces {
                if self.completed.get(piece) {
                    continue;
                }
                if self.downloading.get(piece) {
                    continue;
                }
                if !peer.has_piece(piece as u32) {
                    continue;
                }
                return Some(piece);
            }
        }
        None
    }

    pub fn mark_piece_downloading(&mut self, piece: usize) {
        if !self.downloading.get(piece) {
            let rarity = self.availability[piece];
            if rarity > 0 {
                if let Some(bucket) = self.rarity_buckets.get_mut(&rarity) {
                    bucket.retain(|&p| p != piece);
                    if bucket.is_empty() {
                        self.rarity_buckets.remove(&rarity);
                    }
                }
            }
            self.downloading.set(piece, true);
        }
    }

    pub fn mark_completed(&mut self, piece: usize) {
        let rarity = self.availability[piece];
        if rarity > 0 {
            if let Some(bucket) = self.rarity_buckets.get_mut(&rarity) {
                bucket.retain(|&p| p != piece);
                if bucket.is_empty() {
                    self.rarity_buckets.remove(&rarity);
                }
            }
        }
        self.completed.set(piece, true);
        self.downloading.set(piece, false);
        self.pending_blocks.retain(|&(p, _)| p != piece);
    }

    pub fn cancel_piece(&mut self, piece: usize) {
        if self.downloading.get(piece) {
            let rarity = self.availability[piece];
            if rarity > 0 && !self.completed.get(piece) {
                self.rarity_buckets.entry(rarity).or_insert_with(Vec::new).push(piece);
            }
            self.downloading.set(piece, false);
        }
        self.pending_blocks.retain(|&(p, _)| p != piece);
    }

    pub fn is_block_pending(&self, piece: usize, offset: u32) -> bool {
        self.pending_blocks.contains(&(piece, offset))
    }

    pub fn mark_block_pending(&mut self, piece: usize, offset: u32) {
        self.pending_blocks.insert((piece, offset));
    }

    pub fn cancel_block(&mut self, piece: usize, offset: u32) {
        self.pending_blocks.remove(&(piece, offset));
    }

    pub fn is_complete(&self) -> bool {
        self.completed.count_ones() == self.piece_count
    }

    pub fn completed_count(&self) -> usize {
        self.completed.count_ones()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_piece_picker_new() {
        let picker = PiecePicker::new(100);
        assert_eq!(picker.piece_count(), 100);
        assert!(!picker.is_complete());
    }

    #[test]
    fn test_piece_picker_mark_completed() {
        let mut picker = PiecePicker::new(10);
        picker.mark_completed(5);
        assert_eq!(picker.completed_count(), 1);
    }

    #[test]
    fn test_piece_picker_availability() {
        let mut picker = PiecePicker::new(10);
        picker.update_availability(3, true);
        picker.update_availability(3, true);
        assert_eq!(picker.availability[3], 2);
        picker.update_availability(3, false);
        assert_eq!(picker.availability[3], 1);
    }
}

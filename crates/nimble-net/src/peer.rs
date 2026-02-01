use anyhow::{Context, Result};
use nimble_util::bitfield::Bitfield;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::extension::{
    create_nimble_handshake, has_extension_bit, set_extension_bit, ExtendedMessage,
    ExtensionHandshake, ExtensionState, EXTENSION_UT_METADATA, EXTENSION_UT_PEX,
};
use crate::sockets::TcpSocket;
use crate::ut_metadata::{
    verify_metadata_infohash, UtMetadataMessage, UtMetadataMessageType, UtMetadataState,
};
use crate::ut_pex::parse_pex;

const PROTOCOL_STRING: &[u8] = b"BitTorrent protocol";
const HANDSHAKE_LENGTH: usize = 68;
const MAX_MESSAGE_LENGTH: u32 = 32768 + 9;
const MAX_EXTENDED_MESSAGE_LENGTH: u32 = 1024 * 1024;
const BLOCK_SIZE: u32 = 16384;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);
const MAX_PENDING_REQUESTS: usize = 16;
const EXTENDED_MESSAGE_ID: u8 = 20;
const PEX_MIN_INTERVAL: Duration = Duration::from_secs(30);
const TEMP_RECV_BUFFER_SIZE: usize = 8192;

fn is_timeout_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("timed out") || msg.contains("WSAETIMEDOUT") || msg.contains("10060")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvState {
    ReadingLength,
    ReadingMessage { msg_len: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMessageId {
    Choke = 0,
    Unchoke = 1,
    Interested = 2,
    NotInterested = 3,
    Have = 4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel = 8,
    Extended = 20,
}

impl PeerMessageId {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PeerMessageId::Choke),
            1 => Some(PeerMessageId::Unchoke),
            2 => Some(PeerMessageId::Interested),
            3 => Some(PeerMessageId::NotInterested),
            4 => Some(PeerMessageId::Have),
            5 => Some(PeerMessageId::Bitfield),
            6 => Some(PeerMessageId::Request),
            7 => Some(PeerMessageId::Piece),
            8 => Some(PeerMessageId::Cancel),
            20 => Some(PeerMessageId::Extended),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum PeerMessage {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have {
        piece_index: u32,
    },
    Bitfield {
        bitfield: Vec<u8>,
    },
    Request {
        index: u32,
        begin: u32,
        length: u32,
    },
    Piece {
        index: u32,
        begin: u32,
        block: Vec<u8>,
    },
    Cancel {
        index: u32,
        begin: u32,
        length: u32,
    },
    Extended {
        ext_type: u8,
        payload: Vec<u8>,
    },
}

impl PeerMessage {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            PeerMessage::KeepAlive => {
                vec![0, 0, 0, 0]
            }
            PeerMessage::Choke => {
                vec![0, 0, 0, 1, PeerMessageId::Choke as u8]
            }
            PeerMessage::Unchoke => {
                vec![0, 0, 0, 1, PeerMessageId::Unchoke as u8]
            }
            PeerMessage::Interested => {
                vec![0, 0, 0, 1, PeerMessageId::Interested as u8]
            }
            PeerMessage::NotInterested => {
                vec![0, 0, 0, 1, PeerMessageId::NotInterested as u8]
            }
            PeerMessage::Have { piece_index } => {
                let mut buf = vec![0, 0, 0, 5, PeerMessageId::Have as u8];
                buf.extend_from_slice(&piece_index.to_be_bytes());
                buf
            }
            PeerMessage::Bitfield { bitfield } => {
                let len = 1 + bitfield.len() as u32;
                let mut buf = Vec::with_capacity(4 + len as usize);
                buf.extend_from_slice(&len.to_be_bytes());
                buf.push(PeerMessageId::Bitfield as u8);
                buf.extend_from_slice(bitfield);
                buf
            }
            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                let mut buf = vec![0, 0, 0, 13, PeerMessageId::Request as u8];
                buf.extend_from_slice(&index.to_be_bytes());
                buf.extend_from_slice(&begin.to_be_bytes());
                buf.extend_from_slice(&length.to_be_bytes());
                buf
            }
            PeerMessage::Piece {
                index,
                begin,
                block,
            } => {
                let len = 9 + block.len() as u32;
                let mut buf = Vec::with_capacity(4 + len as usize);
                buf.extend_from_slice(&len.to_be_bytes());
                buf.push(PeerMessageId::Piece as u8);
                buf.extend_from_slice(&index.to_be_bytes());
                buf.extend_from_slice(&begin.to_be_bytes());
                buf.extend_from_slice(block);
                buf
            }
            PeerMessage::Cancel {
                index,
                begin,
                length,
            } => {
                let mut buf = vec![0, 0, 0, 13, PeerMessageId::Cancel as u8];
                buf.extend_from_slice(&index.to_be_bytes());
                buf.extend_from_slice(&begin.to_be_bytes());
                buf.extend_from_slice(&length.to_be_bytes());
                buf
            }
            PeerMessage::Extended { ext_type, payload } => {
                let len = 2 + payload.len() as u32;
                let mut buf = Vec::with_capacity(4 + len as usize);
                buf.extend_from_slice(&len.to_be_bytes());
                buf.push(EXTENDED_MESSAGE_ID);
                buf.push(*ext_type);
                buf.extend_from_slice(payload);
                buf
            }
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(PeerMessage::KeepAlive);
        }

        let msg_id = PeerMessageId::from_u8(data[0]).context("invalid message id")?;

        match msg_id {
            PeerMessageId::Choke => Ok(PeerMessage::Choke),
            PeerMessageId::Unchoke => Ok(PeerMessage::Unchoke),
            PeerMessageId::Interested => Ok(PeerMessage::Interested),
            PeerMessageId::NotInterested => Ok(PeerMessage::NotInterested),
            PeerMessageId::Have => {
                if data.len() < 5 {
                    anyhow::bail!("have message too short");
                }
                let piece_index = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Ok(PeerMessage::Have { piece_index })
            }
            PeerMessageId::Bitfield => {
                let bitfield = data[1..].to_vec();
                Ok(PeerMessage::Bitfield { bitfield })
            }
            PeerMessageId::Request => {
                if data.len() < 13 {
                    anyhow::bail!("request message too short");
                }
                let index = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let begin = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                let length = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
                Ok(PeerMessage::Request {
                    index,
                    begin,
                    length,
                })
            }
            PeerMessageId::Piece => {
                if data.len() < 9 {
                    anyhow::bail!("piece message too short");
                }
                let index = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let begin = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                let block = data[9..].to_vec();
                Ok(PeerMessage::Piece {
                    index,
                    begin,
                    block,
                })
            }
            PeerMessageId::Cancel => {
                if data.len() < 13 {
                    anyhow::bail!("cancel message too short");
                }
                let index = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let begin = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
                let length = u32::from_be_bytes([data[9], data[10], data[11], data[12]]);
                Ok(PeerMessage::Cancel {
                    index,
                    begin,
                    length,
                })
            }
            PeerMessageId::Extended => {
                if data.len() < 2 {
                    anyhow::bail!("extended message too short");
                }
                let ext_type = data[1];
                let payload = data[2..].to_vec();
                Ok(PeerMessage::Extended { ext_type, payload })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Handshaking,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, Copy)]
pub struct PendingRequest {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
    pub sent_at: Instant,
}

#[derive(Debug, Default)]
pub struct PexUpdate {
    pub added: Vec<SocketAddrV4>,
    pub added_v6: Vec<SocketAddrV6>,
    pub dropped: Vec<SocketAddrV4>,
    pub dropped_v6: Vec<SocketAddrV6>,
}

pub struct PeerConnection {
    socket: TcpSocket,
    addr: SocketAddr,
    state: PeerState,
    info_hash: [u8; 20],
    our_peer_id: [u8; 20],
    their_peer_id: Option<[u8; 20]>,
    am_choking: bool,
    am_interested: bool,
    peer_choking: bool,
    peer_interested: bool,
    bitfield: Option<Bitfield>,
    piece_count: usize,
    pending_requests: Vec<PendingRequest>,
    last_message_sent: Instant,
    last_message_received: Instant,
    downloaded: u64,
    uploaded: u64,
    recv_buffer: Vec<u8>,
    recv_state: RecvState,
    temp_recv_buf: [u8; TEMP_RECV_BUFFER_SIZE],
    extensions_enabled: bool,
    extension_state: Option<ExtensionState>,
    listen_port: u16,
    metadata_size: Option<u32>,
    metadata_state: Option<UtMetadataState>,
    metadata: Option<Vec<u8>>,
    metadata_requests_sent: bool,
    pex_added: Vec<SocketAddrV4>,
    pex_added_v6: Vec<SocketAddrV6>,
    pex_dropped: Vec<SocketAddrV4>,
    pex_dropped_v6: Vec<SocketAddrV6>,
    last_pex_received: Option<Instant>,
}

impl PeerConnection {
    pub fn new(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Self {
        Self::with_options(addr, info_hash, our_peer_id, piece_count, 6881, None)
    }

    pub fn new_v4(
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Self {
        Self::new(SocketAddr::V4(addr), info_hash, our_peer_id, piece_count)
    }

    pub fn with_options(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
        listen_port: u16,
        metadata_size: Option<u32>,
    ) -> Self {
        let now = Instant::now();
        let socket = TcpSocket::new_for_addr(&addr).expect("failed to create socket");
        PeerConnection {
            socket,
            addr,
            state: PeerState::Connecting,
            info_hash,
            our_peer_id,
            their_peer_id: None,
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            bitfield: None,
            piece_count,
            pending_requests: Vec::new(),
            last_message_sent: now,
            last_message_received: now,
            downloaded: 0,
            uploaded: 0,
            recv_buffer: Vec::new(),
            recv_state: RecvState::ReadingLength,
            temp_recv_buf: [0u8; TEMP_RECV_BUFFER_SIZE],
            extensions_enabled: false,
            extension_state: None,
            listen_port,
            metadata_size,
            metadata_state: None,
            metadata: None,
            metadata_requests_sent: false,
            pex_added: Vec::new(),
            pex_added_v6: Vec::new(),
            pex_dropped: Vec::new(),
            pex_dropped_v6: Vec::new(),
            last_pex_received: None,
        }
    }

    pub fn connect(&mut self) -> Result<()> {
        self.socket.connect(self.addr.clone())?;
        self.state = PeerState::Handshaking;
        self.do_handshake()
    }

    fn do_handshake(&mut self) -> Result<()> {
        let mut reserved = [0u8; 8];
        set_extension_bit(&mut reserved);

        let mut handshake = Vec::with_capacity(HANDSHAKE_LENGTH);
        handshake.push(19);
        handshake.extend_from_slice(PROTOCOL_STRING);
        handshake.extend_from_slice(&reserved);
        handshake.extend_from_slice(&self.info_hash);
        handshake.extend_from_slice(&self.our_peer_id);

        self.socket.send_all(&handshake)?;

        let mut response = [0u8; HANDSHAKE_LENGTH];
        self.socket.recv_exact(&mut response)?;

        if response[0] != 19 {
            anyhow::bail!("invalid protocol string length: {}", response[0]);
        }

        if &response[1..20] != PROTOCOL_STRING {
            anyhow::bail!("invalid protocol string");
        }

        let their_reserved: [u8; 8] = response[20..28].try_into().unwrap();
        let their_info_hash: [u8; 20] = response[28..48].try_into().unwrap();
        if their_info_hash != self.info_hash {
            anyhow::bail!("info hash mismatch");
        }

        let their_peer_id: [u8; 20] = response[48..68].try_into().unwrap();
        self.their_peer_id = Some(their_peer_id);
        self.state = PeerState::Connected;
        self.last_message_received = Instant::now();

        self.extensions_enabled = has_extension_bit(&their_reserved);

        if self.extensions_enabled {
            self.init_extension_state();
            self.send_extension_handshake()?;
        }

        Ok(())
    }

    fn init_extension_state(&mut self) {
        let our_hs = create_nimble_handshake(self.listen_port, self.metadata_size);
        self.extension_state = Some(ExtensionState::new(our_hs));
    }

    fn send_extension_handshake(&mut self) -> Result<()> {
        if let Some(ref mut ext_state) = self.extension_state {
            if ext_state.handshake_sent {
                return Ok(());
            }

            let msg = ExtendedMessage::Handshake(ext_state.our_handshake.clone());
            let data = msg.serialize();
            self.socket.send_all(&data)?;
            ext_state.handshake_sent = true;
            self.last_message_sent = Instant::now();
        }
        Ok(())
    }

    pub fn send_message(&mut self, msg: &PeerMessage) -> Result<()> {
        if self.state != PeerState::Connected {
            anyhow::bail!("not connected");
        }

        let data = msg.serialize();
        self.socket.send_all(&data)?;
        self.last_message_sent = Instant::now();

        match msg {
            PeerMessage::Piece { block, .. } => {
                self.uploaded += block.len() as u64;
            }
            _ => {}
        }

        Ok(())
    }

    pub fn recv_message(&mut self) -> Result<Option<PeerMessage>> {
        if self.state != PeerState::Connected {
            anyhow::bail!("not connected");
        }

        loop {
            match self.recv_state {
                RecvState::ReadingLength => {
                    let needed = 4 - self.recv_buffer.len();
                    if needed > 0 {
                        let read_len = needed.min(TEMP_RECV_BUFFER_SIZE);
                        match self.socket.recv(&mut self.temp_recv_buf[..read_len]) {
                            Ok(0) => {
                                anyhow::bail!("connection closed");
                            }
                            Ok(n) => {
                                self.recv_buffer.extend_from_slice(&self.temp_recv_buf[..n]);
                            }
                            Err(e) => {
                                if is_timeout_error(&e) {
                                    return Ok(None);
                                }
                                return Err(e);
                            }
                        }
                    }

                    if self.recv_buffer.len() == 4 {
                        let msg_len =
                            u32::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1], self.recv_buffer[2], self.recv_buffer[3]]);

                        if msg_len > MAX_MESSAGE_LENGTH {
                            anyhow::bail!("message too large: {} bytes", msg_len);
                        }

                        if msg_len == 0 {
                            self.recv_buffer.clear();
                            self.recv_state = RecvState::ReadingLength;
                            self.last_message_received = Instant::now();
                            return Ok(Some(PeerMessage::KeepAlive));
                        }

                        self.recv_buffer.clear();
                        self.recv_state = RecvState::ReadingMessage { msg_len };
                    } else {
                        return Ok(None);
                    }
                }
                RecvState::ReadingMessage { msg_len } => {
                    let needed = msg_len as usize - self.recv_buffer.len();
                    if needed > 0 {
                        let read_len = needed.min(TEMP_RECV_BUFFER_SIZE);
                        match self.socket.recv(&mut self.temp_recv_buf[..read_len]) {
                            Ok(0) => {
                                anyhow::bail!("connection closed");
                            }
                            Ok(n) => {
                                self.recv_buffer.extend_from_slice(&self.temp_recv_buf[..n]);
                            }
                            Err(e) => {
                                if is_timeout_error(&e) {
                                    return Ok(None);
                                }
                                return Err(e);
                            }
                        }
                    }

                    if self.recv_buffer.len() == msg_len as usize {
                        let msg = PeerMessage::parse(&self.recv_buffer)?;
                        self.apply_incoming_message(&msg);
                        self.recv_buffer.clear();
                        self.recv_state = RecvState::ReadingLength;
                        self.last_message_received = Instant::now();
                        return Ok(Some(msg));
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn apply_incoming_message(&mut self, msg: &PeerMessage) {
        match msg {
            PeerMessage::Choke => {
                self.peer_choking = true;
                self.pending_requests.clear();
            }
            PeerMessage::Unchoke => {
                self.peer_choking = false;
            }
            PeerMessage::Interested => {
                self.peer_interested = true;
            }
            PeerMessage::NotInterested => {
                self.peer_interested = false;
            }
            PeerMessage::Have { piece_index } => {
                if let Some(ref mut bf) = self.bitfield {
                    bf.set(*piece_index as usize, true);
                }
            }
            PeerMessage::Bitfield { bitfield } => {
                let mut bf = Bitfield::new(self.piece_count);
                for (i, &byte) in bitfield.iter().enumerate() {
                    for bit in 0..8 {
                        let idx = i * 8 + bit;
                        if idx < self.piece_count && (byte & (0x80 >> bit)) != 0 {
                            bf.set(idx, true);
                        }
                    }
                }
                self.bitfield = Some(bf);
            }
            PeerMessage::Piece { block, .. } => {
                self.downloaded += block.len() as u64;
            }
            PeerMessage::Extended { ext_type, payload } => {
                self.handle_extended_message(*ext_type, payload);
            }
            _ => {}
        }
    }

    fn handle_extended_message(&mut self, ext_type: u8, payload: &[u8]) {
        if ext_type == 0 {
            if let Ok(their_hs) = ExtensionHandshake::parse(payload) {
                if let Some(ref mut ext_state) = self.extension_state {
                    ext_state.their_handshake = Some(their_hs);
                    ext_state.handshake_received = true;
                    if let Some(size) = ext_state.metadata_size() {
                        self.init_metadata_state(size);
                    }
                    self.maybe_request_metadata();
                }
            }
            return;
        }

        if let Some(ut_metadata_id) = self.ut_metadata_peer_id() {
            if ext_type == ut_metadata_id {
                self.handle_ut_metadata(payload);
                return;
            }
        }

        if let Some(ut_pex_id) = self.ut_pex_peer_id() {
            if ext_type == ut_pex_id {
                self.handle_ut_pex(payload);
            }
        }
    }

    fn ut_metadata_peer_id(&self) -> Option<u8> {
        self.extension_state
            .as_ref()
            .and_then(|state| state.their_id_for(EXTENSION_UT_METADATA))
    }

    fn ut_pex_peer_id(&self) -> Option<u8> {
        self.extension_state
            .as_ref()
            .and_then(|state| state.their_id_for(EXTENSION_UT_PEX))
    }

    fn init_metadata_state(&mut self, size: u32) {
        if self.metadata_state.is_none() {
            if let Ok(state) = UtMetadataState::new(size) {
                self.metadata_state = Some(state);
                self.metadata_requests_sent = false;
            }
        }
        self.maybe_request_metadata();
    }

    fn handle_ut_metadata(&mut self, payload: &[u8]) {
        let msg = match UtMetadataMessage::parse(payload) {
            Ok(msg) => msg,
            Err(_) => return,
        };

        match msg.msg_type {
            UtMetadataMessageType::Request => {}
            UtMetadataMessageType::Reject => {}
            UtMetadataMessageType::Data => {
                if self.metadata_state.is_none() {
                    if let Some(size) = msg.total_size {
                        self.init_metadata_state(size);
                    }
                }

                if let Some(state) = self.metadata_state.as_mut() {
                    if let Ok(Some(metadata)) = state.insert_piece(msg.piece, &msg.data) {
                        if verify_metadata_infohash(&metadata, self.info_hash) {
                            self.metadata = Some(metadata);
                            self.metadata_state = None;
                            self.metadata_requests_sent = true;
                        } else {
                            self.metadata_state = None;
                            self.metadata = None;
                            self.metadata_requests_sent = false;
                        }
                    }
                }
            }
        }
        self.maybe_request_metadata();
    }

    fn maybe_request_metadata(&mut self) {
        if self.metadata_requests_sent {
            return;
        }

        let (state, ut_metadata_id) =
            match (self.metadata_state.as_ref(), self.ut_metadata_peer_id()) {
                (Some(state), Some(id)) => (state, id),
                _ => return,
            };

        for piece in 0..state.piece_count() as u32 {
            let payload = UtMetadataMessage::build_request(piece);
            let _ = self.send_extended_message(ut_metadata_id, &payload);
        }

        self.metadata_requests_sent = true;
    }

    fn handle_ut_pex(&mut self, payload: &[u8]) {
        let now = Instant::now();
        if let Some(last) = self.last_pex_received {
            if now.duration_since(last) < PEX_MIN_INTERVAL {
                return;
            }
        }

        let msg = match parse_pex(payload) {
            Ok(msg) => msg,
            Err(_) => return,
        };

        self.last_pex_received = Some(now);

        if !msg.added.is_empty() {
            self.pex_added.extend(msg.added);
        }
        if !msg.dropped.is_empty() {
            self.pex_dropped.extend(msg.dropped);
        }
    }

    pub fn set_interested(&mut self, interested: bool) -> Result<()> {
        if interested != self.am_interested {
            self.am_interested = interested;
            if interested {
                self.send_message(&PeerMessage::Interested)?;
            } else {
                self.send_message(&PeerMessage::NotInterested)?;
            }
        }
        Ok(())
    }

    pub fn set_choking(&mut self, choking: bool) -> Result<()> {
        if choking != self.am_choking {
            self.am_choking = choking;
            if choking {
                self.send_message(&PeerMessage::Choke)?;
            } else {
                self.send_message(&PeerMessage::Unchoke)?;
            }
        }
        Ok(())
    }

    pub fn request_block(&mut self, index: u32, begin: u32, length: u32) -> Result<()> {
        if self.peer_choking {
            anyhow::bail!("peer is choking us");
        }

        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            anyhow::bail!("too many pending requests");
        }

        if length > BLOCK_SIZE {
            anyhow::bail!("block size too large: {}", length);
        }

        self.send_message(&PeerMessage::Request {
            index,
            begin,
            length,
        })?;

        self.pending_requests.push(PendingRequest {
            index,
            begin,
            length,
            sent_at: Instant::now(),
        });

        Ok(())
    }

    pub fn cancel_request(&mut self, index: u32, begin: u32, length: u32) -> Result<()> {
        self.pending_requests
            .retain(|r| !(r.index == index && r.begin == begin && r.length == length));
        self.send_message(&PeerMessage::Cancel {
            index,
            begin,
            length,
        })
    }

    pub fn complete_request(&mut self, index: u32, begin: u32) {
        self.pending_requests
            .retain(|r| !(r.index == index && r.begin == begin));
    }

    pub fn send_keepalive(&mut self) -> Result<()> {
        if self.last_message_sent.elapsed() >= KEEPALIVE_INTERVAL {
            self.send_message(&PeerMessage::KeepAlive)?;
        }
        Ok(())
    }

    pub fn send_have(&mut self, piece_index: u32) -> Result<()> {
        self.send_message(&PeerMessage::Have { piece_index })
    }

    pub fn send_bitfield(&mut self, bitfield: &Bitfield) -> Result<()> {
        let bytes = bitfield_to_bytes(bitfield);
        self.send_message(&PeerMessage::Bitfield { bitfield: bytes })
    }

    pub fn has_piece(&self, index: u32) -> bool {
        self.bitfield
            .as_ref()
            .map(|bf| bf.get(index as usize))
            .unwrap_or(false)
    }

    pub fn is_choking(&self) -> bool {
        self.peer_choking
    }

    pub fn is_interested(&self) -> bool {
        self.am_interested
    }

    pub fn peer_is_interested(&self) -> bool {
        self.peer_interested
    }

    pub fn am_choking(&self) -> bool {
        self.am_choking
    }

    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    pub fn downloaded(&self) -> u64 {
        self.downloaded
    }

    pub fn uploaded(&self) -> u64 {
        self.uploaded
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr.clone()
    }

    pub fn addr_v4(&self) -> Option<SocketAddrV4> {
        match self.addr {
            SocketAddr::V4(addr) => Some(addr),
            _ => None,
        }
    }

    pub fn peer_id(&self) -> Option<&[u8; 20]> {
        self.their_peer_id.as_ref()
    }

    pub fn extensions_enabled(&self) -> bool {
        self.extensions_enabled
    }

    pub fn extension_state(&self) -> Option<&ExtensionState> {
        self.extension_state.as_ref()
    }

    pub fn extension_state_mut(&mut self) -> Option<&mut ExtensionState> {
        self.extension_state.as_mut()
    }

    pub fn peer_supports_extension(&self, name: &str) -> bool {
        self.extension_state
            .as_ref()
            .map(|s| s.peer_supports(name))
            .unwrap_or(false)
    }

    pub fn peer_metadata_size(&self) -> Option<u32> {
        self.extension_state
            .as_ref()
            .and_then(|s| s.metadata_size())
    }

    pub fn send_extended_message(&mut self, ext_id: u8, payload: &[u8]) -> Result<()> {
        let msg = PeerMessage::Extended {
            ext_type: ext_id,
            payload: payload.to_vec(),
        };
        self.send_message(&msg)
    }

    pub fn take_pex_updates(&mut self) -> Option<PexUpdate> {
        if self.pex_added.is_empty() && self.pex_added_v6.is_empty()
            && self.pex_dropped.is_empty() && self.pex_dropped_v6.is_empty() {
            return None;
        }

        Some(PexUpdate {
            added: std::mem::take(&mut self.pex_added),
            added_v6: std::mem::take(&mut self.pex_added_v6),
            dropped: std::mem::take(&mut self.pex_dropped),
            dropped_v6: std::mem::take(&mut self.pex_dropped_v6),
        })
    }

    pub fn take_metadata(&mut self) -> Option<Vec<u8>> {
        self.metadata.take()
    }

    pub fn disconnect(&mut self) {
        self.socket.close();
        self.state = PeerState::Disconnected;
    }
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn bitfield_to_bytes(bf: &Bitfield) -> Vec<u8> {
    let byte_count = (bf.len() + 7) / 8;
    let mut bytes = vec![0u8; byte_count];
    for i in 0..bf.len() {
        if bf.get(i) {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_serialize() {
        let msg = PeerMessage::KeepAlive;
        let data = msg.serialize();
        assert_eq!(data, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_choke_serialize() {
        let msg = PeerMessage::Choke;
        let data = msg.serialize();
        assert_eq!(data, vec![0, 0, 0, 1, 0]);
    }

    #[test]
    fn test_unchoke_serialize() {
        let msg = PeerMessage::Unchoke;
        let data = msg.serialize();
        assert_eq!(data, vec![0, 0, 0, 1, 1]);
    }

    #[test]
    fn test_interested_serialize() {
        let msg = PeerMessage::Interested;
        let data = msg.serialize();
        assert_eq!(data, vec![0, 0, 0, 1, 2]);
    }

    #[test]
    fn test_have_serialize() {
        let msg = PeerMessage::Have { piece_index: 42 };
        let data = msg.serialize();
        assert_eq!(data, vec![0, 0, 0, 5, 4, 0, 0, 0, 42]);
    }

    #[test]
    fn test_request_serialize() {
        let msg = PeerMessage::Request {
            index: 1,
            begin: 0,
            length: 16384,
        };
        let data = msg.serialize();
        assert_eq!(data.len(), 17);
        assert_eq!(data[4], 6);
    }

    #[test]
    fn test_piece_serialize() {
        let msg = PeerMessage::Piece {
            index: 0,
            begin: 0,
            block: vec![1, 2, 3, 4],
        };
        let data = msg.serialize();
        assert_eq!(data.len(), 17);
        assert_eq!(data[4], 7);
        assert_eq!(&data[13..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_parse_choke() {
        let data = vec![0];
        let msg = PeerMessage::parse(&data).unwrap();
        assert!(matches!(msg, PeerMessage::Choke));
    }

    #[test]
    fn test_parse_have() {
        let data = vec![4, 0, 0, 0, 100];
        let msg = PeerMessage::parse(&data).unwrap();
        match msg {
            PeerMessage::Have { piece_index } => assert_eq!(piece_index, 100),
            _ => panic!("expected Have"),
        }
    }

    #[test]
    fn test_parse_request() {
        let data = vec![6, 0, 0, 0, 5, 0, 0, 64, 0, 0, 0, 64, 0];
        let msg = PeerMessage::parse(&data).unwrap();
        match msg {
            PeerMessage::Request {
                index,
                begin,
                length,
            } => {
                assert_eq!(index, 5);
                assert_eq!(begin, 16384);
                assert_eq!(length, 16384);
            }
            _ => panic!("expected Request"),
        }
    }

    #[test]
    fn test_bitfield_conversion() {
        let mut bf = Bitfield::new(10);
        bf.set(0, true);
        bf.set(7, true);
        bf.set(9, true);
        let bytes = bitfield_to_bytes(&bf);
        assert_eq!(bytes[0], 0x81);
        assert_eq!(bytes[1], 0x40);
    }

    #[test]
    fn test_extended_serialize() {
        let msg = PeerMessage::Extended {
            ext_type: 0,
            payload: vec![b'd', b'e'],
        };
        let data = msg.serialize();
        assert_eq!(data[0..4], [0, 0, 0, 4]);
        assert_eq!(data[4], 20);
        assert_eq!(data[5], 0);
        assert_eq!(&data[6..], &[b'd', b'e']);
    }

    #[test]
    fn test_parse_extended() {
        let data = vec![20, 1, b'd', b'e'];
        let msg = PeerMessage::parse(&data).unwrap();
        match msg {
            PeerMessage::Extended { ext_type, payload } => {
                assert_eq!(ext_type, 1);
                assert_eq!(payload, vec![b'd', b'e']);
            }
            _ => panic!("expected Extended"),
        }
    }
}

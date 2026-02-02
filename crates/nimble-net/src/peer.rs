use anyhow::{Context, Result};
use nimble_util::bitfield::Bitfield;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, Instant};

use crate::encryption::{MseHandshake, MseStage, MSE_KEY_LENGTH};
use crate::extension::{
    create_nimble_handshake, has_extension_bit, ExtendedMessage, ExtensionHandshake,
    ExtensionState, EXTENSION_UT_METADATA, EXTENSION_UT_PEX,
};
use crate::handshake::{BitTorrentHandshake, HandshakeProtocol, HandshakeStep};
use crate::sockets::TcpSocket;
use crate::ut_metadata::{
    verify_metadata_infohash, UtMetadataMessage, UtMetadataMessageType, UtMetadataState,
};
use crate::ut_pex::parse_pex;

const MAX_MESSAGE_LENGTH: u32 = 32768 + 9;
const MAX_BITFIELD_BYTES: u32 = 262144;
const MAX_EXTENDED_MESSAGE_LENGTH: u32 = 1024 * 1024;
const BLOCK_SIZE: u32 = 16384;
const MAX_BLOCK_SIZE: u32 = 32768;
const MAX_REASONABLE_PIECE_SIZE: u64 = 64 * 1024 * 1024;
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(120);
const MAX_PENDING_REQUESTS: usize = 16;
const MAX_PEER_REQUESTS: usize = 500;
const EXTENDED_MESSAGE_ID: u8 = 20;
const PEX_MIN_INTERVAL: Duration = Duration::from_secs(30);
const UT_METADATA_MAX_REQUESTS_PER_SECOND: usize = 10;
const UT_METADATA_RATE_WINDOW: Duration = Duration::from_secs(1);
const MAX_PEX_PEERS_PER_MESSAGE: usize = 200;

/// RFC-101 Step 2: Fixed-size receive buffer for zero-allocation message parsing.
/// 256KB is required to support bitfields up to MAX_BITFIELD_BYTES (262144).
const RECV_BUFFER_SIZE: usize = 256 * 1024;

/// RFC-101 Step 4: Batched message queue limits.
/// Flush if queue exceeds 4KB to avoid memory buildup.
const MAX_QUEUE_BYTES: usize = 4096;
/// Flush if oldest message in queue is older than 100ms.
const MAX_QUEUE_AGE_MS: u64 = 100;

const MAX_CHOKE_SIZE: u32 = 1;
const MAX_UNCHOKE_SIZE: u32 = 1;
const MAX_INTERESTED_SIZE: u32 = 1;
const MAX_NOT_INTERESTED_SIZE: u32 = 1;
const MAX_HAVE_SIZE: u32 = 5;
const MAX_REQUEST_SIZE: u32 = 13;
const MAX_CANCEL_SIZE: u32 = 13;
const MAX_PIECE_SIZE: u32 = 32768 + 9;

fn is_timeout_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("timed out") || msg.contains("WSAETIMEDOUT") || msg.contains("10060")
}

fn validate_message_size(msg_len: u32, data: &[u8]) -> Result<(), anyhow::Error> {
    if data.is_empty() {
        return Ok(());
    }

    let msg_id = data[0];

    let max_size = match PeerMessageId::from_u8(msg_id) {
        Some(PeerMessageId::Choke) => MAX_CHOKE_SIZE,
        Some(PeerMessageId::Unchoke) => MAX_UNCHOKE_SIZE,
        Some(PeerMessageId::Interested) => MAX_INTERESTED_SIZE,
        Some(PeerMessageId::NotInterested) => MAX_NOT_INTERESTED_SIZE,
        Some(PeerMessageId::Have) => MAX_HAVE_SIZE,
        Some(PeerMessageId::Request) => MAX_REQUEST_SIZE,
        Some(PeerMessageId::Cancel) => MAX_CANCEL_SIZE,
        Some(PeerMessageId::Piece) => MAX_PIECE_SIZE,
        Some(PeerMessageId::Bitfield) => MAX_BITFIELD_BYTES,
        Some(PeerMessageId::Extended) => MAX_EXTENDED_MESSAGE_LENGTH,
        None => return Err(anyhow::anyhow!("invalid message id: {}", msg_id)),
    };

    if msg_len > max_size {
        return Err(anyhow::anyhow!(
            "message type {} size {} exceeds limit {}",
            msg_id,
            msg_len,
            max_size
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvState {
    ReadingLength,
    ReadingMessageType { msg_len: u32 },
    ReadingMessage { msg_len: u32, validated: bool },
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
                let block_len = data.len() - 9;
                if block_len > MAX_BLOCK_SIZE as usize {
                    anyhow::bail!("piece block too large: {} bytes (max {})", block_len, MAX_BLOCK_SIZE);
                }
                if block_len == 0 {
                    anyhow::bail!("piece block cannot be empty");
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

#[derive(Debug, PartialEq, Eq)]
enum HandshakePhase {
    Mse(MseHandshakeState),
    BitTorrent,
}

#[derive(Debug, PartialEq, Eq)]
enum MseHandshakeState {
    SendPublicKey { offset: usize },
    ReceivePublicKey { received: usize },
    SendVc { offset: usize, vc: [u8; 8] },
    ReceiveVc { received: usize },
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
    peer_requests: Vec<PendingRequest>,
    last_message_sent: Instant,
    last_message_received: Instant,
    downloaded: u64,
    uploaded: u64,
    /// RFC-101 Step 2: Fixed-size receive buffer to eliminate allocation churn.
    /// Uses a heap-allocated box to avoid stack overflow while maintaining
    /// predictable memory usage. Reused for all control messages.
    recv_buffer: Box<[u8; RECV_BUFFER_SIZE]>,
    /// Current position in recv_buffer (amount of valid data).
    recv_cursor: usize,
    recv_state: RecvState,
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
    ut_metadata_request_count: usize,
    ut_metadata_window_start: Instant,
    mse_handshake: Option<MseHandshake>,
    encryption_enabled: bool,
    handshake: Option<Box<dyn HandshakeProtocol>>,
    handshake_phase: Option<HandshakePhase>,
    /// RFC-101 Step 4: Outbound message queue for batching Have messages.
    /// Messages are serialized and queued, then flushed together to reduce syscalls.
    outbound_queue: Vec<u8>,
    /// Timestamp when first message was added to current queue batch.
    /// Used to enforce MAX_QUEUE_AGE_MS limit.
    queue_first_message_time: Option<Instant>,
}

impl PeerConnection {
    pub fn new(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Self::with_options(addr, info_hash, our_peer_id, piece_count, 6881, None)
    }

    pub fn new_v4(
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Self::new(SocketAddr::V4(addr), info_hash, our_peer_id, piece_count)
    }

    pub fn new_v6(
        addr: SocketAddrV6,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Self::new(SocketAddr::V6(addr), info_hash, our_peer_id, piece_count)
    }

    pub fn with_options(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
        listen_port: u16,
        metadata_size: Option<u32>,
    ) -> Result<Self> {
        let now = Instant::now();
        let socket = TcpSocket::new_for_addr(&addr)
            .context("failed to create socket")?;
        let mse_handshake = Some(MseHandshake::new_initiator(&info_hash));
        Ok(PeerConnection {
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
            peer_requests: Vec::new(),
            last_message_sent: now,
            last_message_received: now,
            downloaded: 0,
            uploaded: 0,
            // RFC-101 Step 2: Fixed-size buffer to eliminate allocation churn
            recv_buffer: Box::new([0u8; RECV_BUFFER_SIZE]),
            recv_cursor: 0,
            recv_state: RecvState::ReadingLength,
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
            ut_metadata_request_count: 0,
            ut_metadata_window_start: now,
            mse_handshake,
            encryption_enabled: false,
            handshake: None,
            handshake_phase: None,
            // RFC-101 Step 4: Initialize empty outbound queue
            outbound_queue: Vec::with_capacity(MAX_QUEUE_BYTES),
            queue_first_message_time: None,
        })
    }

    #[cfg(target_os = "windows")]
    pub fn from_accepted(
        socket: windows_sys::Win32::Networking::WinSock::SOCKET,
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        their_peer_id: [u8; 20],
        piece_count: usize,
        listen_port: u16,
        mse_handshake: Option<MseHandshake>,
    ) -> Result<Self> {
        use crate::sockets::TcpSocket;
        let socket = TcpSocket::from_raw_socket(socket, SocketAddr::V4(addr))?;
        let now = Instant::now();

        let encryption_enabled = mse_handshake.is_some();
        let mut conn = PeerConnection {
            socket,
            addr: SocketAddr::V4(addr),
            state: PeerState::Connected,
            info_hash,
            our_peer_id,
            their_peer_id: Some(their_peer_id),
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            bitfield: None,
            piece_count,
            pending_requests: Vec::new(),
            peer_requests: Vec::new(),
            last_message_sent: now,
            last_message_received: now,
            downloaded: 0,
            uploaded: 0,
            // RFC-101 Step 2: Fixed-size buffer to eliminate allocation churn
            recv_buffer: Box::new([0u8; RECV_BUFFER_SIZE]),
            recv_cursor: 0,
            recv_state: RecvState::ReadingLength,
            extensions_enabled: true,
            extension_state: None,
            listen_port,
            metadata_size: None,
            metadata_state: None,
            metadata: None,
            metadata_requests_sent: false,
            pex_added: Vec::new(),
            pex_added_v6: Vec::new(),
            pex_dropped: Vec::new(),
            pex_dropped_v6: Vec::new(),
            last_pex_received: None,
            ut_metadata_request_count: 0,
            ut_metadata_window_start: now,
            mse_handshake,
            encryption_enabled,
            handshake: None,
            handshake_phase: None,
            // RFC-101 Step 4: Initialize empty outbound queue
            outbound_queue: Vec::with_capacity(MAX_QUEUE_BYTES),
            queue_first_message_time: None,
        };

        conn.init_extension_state();
        conn.send_extension_handshake()?;

        Ok(conn)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn from_accepted(
        stream: std::net::TcpStream,
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        their_peer_id: [u8; 20],
        piece_count: usize,
        listen_port: u16,
        mse_handshake: Option<MseHandshake>,
    ) -> Result<Self> {
        use crate::sockets::TcpSocket;
        let socket = TcpSocket::from_raw_socket(stream, SocketAddr::V4(addr))?;
        let now = Instant::now();

        let encryption_enabled = mse_handshake.is_some();
        let mut conn = PeerConnection {
            socket,
            addr: SocketAddr::V4(addr),
            state: PeerState::Connected,
            info_hash,
            our_peer_id,
            their_peer_id: Some(their_peer_id),
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            bitfield: None,
            piece_count,
            pending_requests: Vec::new(),
            peer_requests: Vec::new(),
            last_message_sent: now,
            last_message_received: now,
            downloaded: 0,
            uploaded: 0,
            // RFC-101 Step 2: Fixed-size buffer to eliminate allocation churn
            recv_buffer: Box::new([0u8; RECV_BUFFER_SIZE]),
            recv_cursor: 0,
            recv_state: RecvState::ReadingLength,
            extensions_enabled: true,
            extension_state: None,
            listen_port,
            metadata_size: None,
            metadata_state: None,
            metadata: None,
            metadata_requests_sent: false,
            pex_added: Vec::new(),
            pex_added_v6: Vec::new(),
            pex_dropped: Vec::new(),
            pex_dropped_v6: Vec::new(),
            last_pex_received: None,
            ut_metadata_request_count: 0,
            ut_metadata_window_start: now,
            mse_handshake,
            encryption_enabled,
            handshake: None,
            handshake_phase: None,
            // RFC-101 Step 4: Initialize empty outbound queue
            outbound_queue: Vec::with_capacity(MAX_QUEUE_BYTES),
            queue_first_message_time: None,
        };

        conn.init_extension_state();
        conn.send_extension_handshake()?;

        Ok(conn)
    }

    pub fn connect(&mut self) -> Result<()> {
        self.socket.connect(self.addr.clone())?;
        self.state = PeerState::Handshaking;
        self.recv_cursor = 0;
        self.recv_state = RecvState::ReadingLength;
        self.encryption_enabled = false;
        self.handshake = None;
        self.handshake_phase = None;

        self.socket.set_nonblocking(true)?;
        self.start_handshake();
        self.tick_handshake()?;
        Ok(())
    }

    pub fn poll(&mut self) -> Result<()> {
        if self.state == PeerState::Handshaking {
            self.tick_handshake()?;
        }
        Ok(())
    }

    fn start_handshake(&mut self) {
        if self.mse_handshake.is_some() {
            self.handshake_phase = Some(HandshakePhase::Mse(MseHandshakeState::SendPublicKey {
                offset: 0,
            }));
            return;
        }

        self.begin_bittorrent_handshake();
    }

    fn begin_bittorrent_handshake(&mut self) {
        self.handshake = Some(Box::new(BitTorrentHandshake::new(
            self.info_hash,
            self.our_peer_id,
        )));
        self.handshake_phase = Some(HandshakePhase::BitTorrent);
        self.recv_cursor = 0;
    }

    fn read_handshake_bytes(&mut self, target: usize, decrypt: bool) -> Result<bool> {
        if self.recv_cursor >= target {
            return Ok(true);
        }

        let remaining = target - self.recv_cursor;
        let available = RECV_BUFFER_SIZE - self.recv_cursor;
        let read_len = remaining.min(available);
        let start = self.recv_cursor;
        match self.socket.recv(&mut self.recv_buffer[start..start + read_len]) {
            Ok(0) => {
                anyhow::bail!("connection closed");
            }
            Ok(n) => {
                if decrypt {
                    if let Some(ref mut mse) = self.mse_handshake {
                        mse.decrypt(&mut self.recv_buffer[start..start + n]);
                    }
                }
                self.recv_cursor += n;
                Ok(self.recv_cursor >= target)
            }
            Err(e) => {
                if is_timeout_error(&e) {
                    return Ok(false);
                }
                Err(e)
            }
        }
    }

    pub fn tick_handshake(&mut self) -> Result<()> {
        if self.state != PeerState::Handshaking {
            anyhow::bail!("not handshaking");
        }

        loop {
            let phase = match self.handshake_phase.take() {
                Some(phase) => phase,
                None => return Ok(()),
            };

            match phase {
                HandshakePhase::Mse(mut state) => {
                    let completed = self.tick_mse_handshake(&mut state)?;
                    if completed {
                        self.encryption_enabled = true;
                        self.begin_bittorrent_handshake();
                        continue;
                    }
                    self.handshake_phase = Some(HandshakePhase::Mse(state));
                    return Ok(());
                }
                HandshakePhase::BitTorrent => {
                    self.handshake_phase = Some(HandshakePhase::BitTorrent);
                    return self.tick_bittorrent_handshake();
                }
            }
        }
    }

    fn tick_mse_handshake(&mut self, state: &mut MseHandshakeState) -> Result<bool> {
        match state {
            MseHandshakeState::SendPublicKey { offset } => {
                let mut key_buf = [0u8; MSE_KEY_LENGTH];
                {
                    let mse = self
                        .mse_handshake
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("MSE handshake not initialized"))?;
                    key_buf.copy_from_slice(mse.get_public_key());
                }
                if *offset < key_buf.len() {
                    let sent = self.socket.send(&key_buf[*offset..])?;
                    if sent == 0 {
                        anyhow::bail!("connection closed");
                    }
                    *offset += sent;
                }
                if *offset >= key_buf.len() {
                    *state = MseHandshakeState::ReceivePublicKey { received: 0 };
                    self.recv_cursor = 0;
                }
                Ok(false)
            }
            MseHandshakeState::ReceivePublicKey { received } => {
                if *received < MSE_KEY_LENGTH {
                    let target = MSE_KEY_LENGTH;
                    if !self.read_handshake_bytes(target, false)? {
                        return Ok(false);
                    }
                    *received = self.recv_cursor;
                }
                if *received < MSE_KEY_LENGTH {
                    return Ok(false);
                }

                let info_hash = self.info_hash;
                {
                    let mse = self
                        .mse_handshake
                        .as_mut()
                        .ok_or_else(|| anyhow::anyhow!("MSE handshake not initialized"))?;
                    mse.compute_shared_secret(&self.recv_buffer[..MSE_KEY_LENGTH], &info_hash)
                        .map_err(|e| anyhow::anyhow!("MSE handshake failed: {}", e))?;

                    let mut vc = [0u8; 8];
                    mse.encrypt(&mut vc);
                    *state = MseHandshakeState::SendVc { offset: 0, vc };
                }
                self.recv_cursor = 0;
                Ok(false)
            }
            MseHandshakeState::SendVc { offset, vc } => {
                if *offset < vc.len() {
                    let sent = self.socket.send(&vc[*offset..])?;
                    if sent == 0 {
                        anyhow::bail!("connection closed");
                    }
                    *offset += sent;
                }
                if *offset >= vc.len() {
                    *state = MseHandshakeState::ReceiveVc { received: 0 };
                    self.recv_cursor = 0;
                }
                Ok(false)
            }
            MseHandshakeState::ReceiveVc { received } => {
                if *received < 8 {
                    if !self.read_handshake_bytes(8, false)? {
                        return Ok(false);
                    }
                    *received = self.recv_cursor;
                }
                if *received < 8 {
                    return Ok(false);
                }

                let mut their_vc = [0u8; 8];
                their_vc.copy_from_slice(&self.recv_buffer[..8]);
                let mse = self
                    .mse_handshake
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("MSE handshake not initialized"))?;
                mse.decrypt(&mut their_vc);

                if their_vc != [0u8; 8] {
                    anyhow::bail!("invalid MSE verification constant");
                }

                mse.set_stage(MseStage::Established);
                Ok(true)
            }
        }
    }

    fn tick_bittorrent_handshake(&mut self) -> Result<()> {
        loop {
            let step = {
                let handshake = self
                    .handshake
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("handshake not initialized"))?;
                handshake.step(&self.recv_buffer[..self.recv_cursor])?
            };

            match step {
                HandshakeStep::Write { mut data } => {
                    if self.encryption_enabled {
                        if let Some(ref mut mse) = self.mse_handshake {
                            mse.encrypt(&mut data);
                        }
                    }
                    self.socket.send_all(&data)?;
                    return Ok(());
                }
                HandshakeStep::Read { min_bytes } => {
                    let decrypted = self.encryption_enabled;
                    if !self.read_handshake_bytes(min_bytes, decrypted)? {
                        return Ok(());
                    }
                }
                HandshakeStep::Complete {
                    peer_id,
                    reserved_bytes,
                    ..
                } => {
                    self.their_peer_id = Some(peer_id);
                    self.state = PeerState::Connected;
                    self.last_message_received = Instant::now();
                    self.extensions_enabled = has_extension_bit(&reserved_bytes);
                    self.handshake = None;
                    self.handshake_phase = None;
                    self.recv_cursor = 0;
                    self.recv_state = RecvState::ReadingLength;

                    if self.extensions_enabled {
                        self.init_extension_state();
                        self.send_extension_handshake()?;
                    }

                    if self.am_interested {
                        self.send_message(&PeerMessage::Interested)?;
                    }

                    return Ok(());
                }
            }
        }
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

        let mut data = msg.serialize();

        if self.encryption_enabled {
            if let Some(ref mut mse) = self.mse_handshake {
                mse.encrypt(&mut data);
            }
        }

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
                    let needed = 4 - self.recv_cursor;
                    if needed > 0 {
                        let read_len = needed.min(RECV_BUFFER_SIZE - self.recv_cursor);
                        match self.socket.recv(&mut self.recv_buffer[self.recv_cursor..self.recv_cursor + read_len]) {
                            Ok(0) => {
                                anyhow::bail!("connection closed");
                            }
                            Ok(n) => {
                                if self.encryption_enabled {
                                    if let Some(ref mut mse) = self.mse_handshake {
                                        mse.decrypt(&mut self.recv_buffer[self.recv_cursor..self.recv_cursor + n]);
                                    }
                                }
                                self.recv_cursor += n;
                            }
                            Err(e) => {
                                if is_timeout_error(&e) {
                                    return Ok(None);
                                }
                                return Err(e);
                            }
                        }
                    }

                    if self.recv_cursor >= 4 {
                        let msg_len =
                            u32::from_be_bytes([self.recv_buffer[0], self.recv_buffer[1], self.recv_buffer[2], self.recv_buffer[3]]);

                        if msg_len == 0 {
                            self.recv_cursor = 0;
                            self.recv_state = RecvState::ReadingLength;
                            self.last_message_received = Instant::now();
                            return Ok(Some(PeerMessage::KeepAlive));
                        }

                        if msg_len > MAX_EXTENDED_MESSAGE_LENGTH {
                            anyhow::bail!("message too large: {} bytes (absolute max {})", msg_len, MAX_EXTENDED_MESSAGE_LENGTH);
                        }

                        // Check if message fits in fixed buffer
                        if msg_len as usize > RECV_BUFFER_SIZE {
                            anyhow::bail!("message {} bytes exceeds fixed buffer size {}", msg_len, RECV_BUFFER_SIZE);
                        }

                        self.recv_cursor = 0;
                        self.recv_state = RecvState::ReadingMessageType { msg_len };
                    } else {
                        return Ok(None);
                    }
                }
                RecvState::ReadingMessageType { msg_len } => {
                    if self.recv_cursor == 0 {
                        let read_len = 1;
                        match self.socket.recv(&mut self.recv_buffer[..read_len]) {
                            Ok(0) => {
                                anyhow::bail!("connection closed");
                            }
                            Ok(n) => {
                                if self.encryption_enabled {
                                    if let Some(ref mut mse) = self.mse_handshake {
                                        mse.decrypt(&mut self.recv_buffer[..n]);
                                    }
                                }
                                self.recv_cursor = n;
                            }
                            Err(e) => {
                                if is_timeout_error(&e) {
                                    return Ok(None);
                                }
                                return Err(e);
                            }
                        }
                    }

                    if self.recv_cursor > 0 {
                        validate_message_size(msg_len, &self.recv_buffer[..self.recv_cursor])?;
                        self.recv_state = RecvState::ReadingMessage { msg_len, validated: true };
                    } else {
                        return Ok(None);
                    }
                }
                RecvState::ReadingMessage { msg_len, validated: _ } => {
                    let needed = msg_len as usize - self.recv_cursor;
                    if needed > 0 {
                        let read_len = needed.min(RECV_BUFFER_SIZE - self.recv_cursor);
                        match self.socket.recv(&mut self.recv_buffer[self.recv_cursor..self.recv_cursor + read_len]) {
                            Ok(0) => {
                                anyhow::bail!("connection closed");
                            }
                            Ok(n) => {
                                if self.encryption_enabled {
                                    if let Some(ref mut mse) = self.mse_handshake {
                                        mse.decrypt(&mut self.recv_buffer[self.recv_cursor..self.recv_cursor + n]);
                                    }
                                }
                                self.recv_cursor += n;
                            }
                            Err(e) => {
                                if is_timeout_error(&e) {
                                    return Ok(None);
                                }
                                return Err(e);
                            }
                        }
                    }

                    if self.recv_cursor == msg_len as usize {
                        let msg = PeerMessage::parse(&self.recv_buffer[..self.recv_cursor])?;
                        self.apply_incoming_message(&msg);
                        self.recv_cursor = 0;
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
                let expected_bytes = (self.piece_count + 7) / 8;
                if bitfield.len() != expected_bytes {
                    return;
                }
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
            PeerMessage::Request { index, begin, length } => {
                if !self.am_choking && self.peer_interested {
                    if *length == 0 || *length > MAX_BLOCK_SIZE {
                        return;
                    }
                    if *index as usize >= self.piece_count {
                        return;
                    }
                    if *begin % BLOCK_SIZE != 0 {
                        return;
                    }
                    if (*begin as u64) + (*length as u64) > MAX_REASONABLE_PIECE_SIZE {
                        return;
                    }
                    if (*begin as u64).checked_add(*length as u64).is_none() {
                        return;
                    }
                    if self.peer_requests.len() >= MAX_PEER_REQUESTS {
                        return;
                    }
                    self.peer_requests.push(PendingRequest {
                        index: *index,
                        begin: *begin,
                        length: *length,
                        sent_at: Instant::now(),
                    });
                }
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
            UtMetadataMessageType::Request => {
                let now = Instant::now();
                if now.duration_since(self.ut_metadata_window_start) >= UT_METADATA_RATE_WINDOW {
                    self.ut_metadata_request_count = 0;
                    self.ut_metadata_window_start = now;
                }

                self.ut_metadata_request_count += 1;
                if self.ut_metadata_request_count > UT_METADATA_MAX_REQUESTS_PER_SECOND {
                    return;
                }

                if let Some(metadata) = &self.metadata {
                    let piece_index = msg.piece as usize;
                    let total_size = metadata.len() as u32;
                    let piece_size = 16 * 1024;
                    let piece_count = (metadata.len() + piece_size - 1) / piece_size;

                    if piece_index < piece_count {
                        let start = piece_index * piece_size;
                        let end = (start + piece_size).min(metadata.len());
                        let piece_data = &metadata[start..end];

                        let response = UtMetadataMessage::build_data(msg.piece, total_size, piece_data);
                        if let Some(ut_metadata_id) = self.extension_state.as_ref()
                            .and_then(|s| s.our_id_for(EXTENSION_UT_METADATA))
                        {
                            let _ = self.send_message(&PeerMessage::Extended {
                                ext_type: ut_metadata_id,
                                payload: response,
                            });
                        }
                    } else {
                        let response = UtMetadataMessage::build_reject(msg.piece);
                        if let Some(ut_metadata_id) = self.extension_state.as_ref()
                            .and_then(|s| s.our_id_for(EXTENSION_UT_METADATA))
                        {
                            let _ = self.send_message(&PeerMessage::Extended {
                                ext_type: ut_metadata_id,
                                payload: response,
                            });
                        }
                    }
                } else {
                    let response = UtMetadataMessage::build_reject(msg.piece);
                    if let Some(ut_metadata_id) = self.extension_state.as_ref()
                        .and_then(|s| s.our_id_for(EXTENSION_UT_METADATA))
                    {
                        let _ = self.send_message(&PeerMessage::Extended {
                            ext_type: ut_metadata_id,
                            payload: response,
                        });
                    }
                }
            }
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
            let remaining_capacity = MAX_PEX_PEERS_PER_MESSAGE.saturating_sub(self.pex_added.len());
            let to_add = msg.added.len().min(remaining_capacity);
            self.pex_added.extend(&msg.added[..to_add]);
        }
        if !msg.dropped.is_empty() {
            let remaining_capacity = MAX_PEX_PEERS_PER_MESSAGE.saturating_sub(self.pex_dropped.len());
            let to_drop = msg.dropped.len().min(remaining_capacity);
            self.pex_dropped.extend(&msg.dropped[..to_drop]);
        }
    }

    pub fn set_interested(&mut self, interested: bool) -> Result<()> {
        if interested != self.am_interested {
            self.am_interested = interested;
            if self.state != PeerState::Connected {
                return Ok(());
            }
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

        if index >= self.piece_count as u32 {
            anyhow::bail!("piece index out of bounds: {} >= {}", index, self.piece_count);
        }

        if begin > MAX_REASONABLE_PIECE_SIZE as u32 {
            anyhow::bail!("block offset out of bounds: {}", begin);
        }

        if begin.saturating_add(length) > MAX_REASONABLE_PIECE_SIZE as u32 {
            anyhow::bail!("block end offset out of bounds: {} + {}", begin, length);
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

    pub fn take_peer_requests(&mut self) -> Vec<PendingRequest> {
        std::mem::take(&mut self.peer_requests)
    }

    pub fn send_piece(&mut self, index: u32, begin: u32, block: Vec<u8>) -> Result<()> {
        self.send_message(&PeerMessage::Piece { index, begin, block })
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

    pub fn bitfield(&self) -> Option<&Bitfield> {
        self.bitfield.as_ref()
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

    /// Returns the raw socket handle for use with poll_readable_sockets().
    /// Used by PeerManager to implement decoupled readiness polling (RFC-101 Step 1).
    pub fn raw_socket(&self) -> crate::sockets::RawSocket {
        self.socket.raw_socket()
    }

    /// RFC-101 Step 4: Queue a message for batched sending.
    /// Messages are serialized and added to the outbound queue.
    /// Use `flush_queue()` or `tick()` to actually send.
    fn queue_message(&mut self, msg: &PeerMessage) {
        let data = msg.serialize();

        // Start tracking queue age if this is the first message
        if self.queue_first_message_time.is_none() {
            self.queue_first_message_time = Some(Instant::now());
        }

        // Encrypt if needed
        let mut data = data;
        if self.encryption_enabled {
            if let Some(ref mut mse) = self.mse_handshake {
                mse.encrypt(&mut data);
            }
        }

        self.outbound_queue.extend_from_slice(&data);
    }

    /// RFC-101 Step 4: Flush all queued messages to the socket.
    /// Returns Ok(()) if queue was empty or all data was sent.
    pub fn flush_queue(&mut self) -> Result<()> {
        if self.outbound_queue.is_empty() {
            return Ok(());
        }

        self.socket.send_all(&self.outbound_queue)?;
        self.outbound_queue.clear();
        self.queue_first_message_time = None;
        self.last_message_sent = Instant::now();

        Ok(())
    }

    /// RFC-101 Step 4: Auto-flush logic for batched messages.
    /// Flushes if queue exceeds MAX_QUEUE_BYTES or oldest message exceeds MAX_QUEUE_AGE_MS.
    /// Should be called once per tick.
    pub fn tick(&mut self) -> Result<()> {
        if self.outbound_queue.is_empty() {
            return Ok(());
        }

        let should_flush = self.outbound_queue.len() > MAX_QUEUE_BYTES
            || self.queue_first_message_time
                .map(|t| t.elapsed().as_millis() as u64 > MAX_QUEUE_AGE_MS)
                .unwrap_or(false);

        if should_flush {
            self.flush_queue()?;
        }

        Ok(())
    }

    /// RFC-101 Step 4: Queue a Have message for batched sending.
    /// Does NOT send immediately - use `flush_queue()` or `tick()` to send.
    /// This reduces syscalls when multiple pieces complete in quick succession.
    pub fn send_have_batched(&mut self, piece_index: u32) {
        self.queue_message(&PeerMessage::Have { piece_index });
    }

    /// Returns the current outbound queue size in bytes.
    pub fn outbound_queue_size(&self) -> usize {
        self.outbound_queue.len()
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

    pub fn set_metadata(&mut self, metadata: Vec<u8>) {
        self.metadata = Some(metadata);
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

pub enum AnyPeerConnection {
    Tcp(PeerConnection),
    Utp(crate::utp_peer::UtpPeerConnection),
}

impl AnyPeerConnection {
    pub fn new_tcp(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Ok(AnyPeerConnection::Tcp(PeerConnection::new(addr, info_hash, our_peer_id, piece_count)?))
    }

    pub fn new_tcp_v4(
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Ok(AnyPeerConnection::Tcp(PeerConnection::new_v4(addr, info_hash, our_peer_id, piece_count)?))
    }

    pub fn new_tcp_v6(
        addr: SocketAddrV6,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Ok(AnyPeerConnection::Tcp(PeerConnection::new_v6(addr, info_hash, our_peer_id, piece_count)?))
    }

    pub fn new_utp(
        addr: SocketAddr,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
        listen_port: u16,
    ) -> Result<Self> {
        Ok(AnyPeerConnection::Utp(crate::utp_peer::UtpPeerConnection::new(
            addr,
            info_hash,
            our_peer_id,
            piece_count,
            listen_port,
        )?))
    }

    pub fn new_utp_v4(
        addr: SocketAddrV4,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Ok(AnyPeerConnection::Utp(crate::utp_peer::UtpPeerConnection::new_v4(
            addr,
            info_hash,
            our_peer_id,
            piece_count,
        )?))
    }

    pub fn new_utp_v6(
        addr: SocketAddrV6,
        info_hash: [u8; 20],
        our_peer_id: [u8; 20],
        piece_count: usize,
    ) -> Result<Self> {
        Ok(AnyPeerConnection::Utp(crate::utp_peer::UtpPeerConnection::new_v6(
            addr,
            info_hash,
            our_peer_id,
            piece_count,
        )?))
    }

    pub fn connect(&mut self) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.connect(),
            AnyPeerConnection::Utp(conn) => conn.connect(),
        }
    }

    pub fn poll(&mut self) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.poll(),
            AnyPeerConnection::Utp(conn) => conn.poll(),
        }
    }

    pub fn state(&self) -> PeerState {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.state(),
            AnyPeerConnection::Utp(conn) => conn.state(),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.addr(),
            AnyPeerConnection::Utp(conn) => conn.addr(),
        }
    }

    pub fn addr_v4(&self) -> Option<SocketAddrV4> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.addr_v4(),
            AnyPeerConnection::Utp(conn) => conn.addr_v4(),
        }
    }

    pub fn downloaded(&self) -> u64 {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.downloaded(),
            AnyPeerConnection::Utp(conn) => conn.downloaded(),
        }
    }

    pub fn uploaded(&self) -> u64 {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.uploaded(),
            AnyPeerConnection::Utp(conn) => conn.uploaded(),
        }
    }

    pub fn is_choking(&self) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.is_choking(),
            AnyPeerConnection::Utp(conn) => conn.is_choking(),
        }
    }

    pub fn is_interested(&self) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.is_interested(),
            AnyPeerConnection::Utp(conn) => conn.is_interested(),
        }
    }

    pub fn peer_is_interested(&self) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.peer_is_interested(),
            AnyPeerConnection::Utp(conn) => conn.peer_is_interested(),
        }
    }

    pub fn am_choking(&self) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.am_choking(),
            AnyPeerConnection::Utp(conn) => conn.am_choking(),
        }
    }

    pub fn has_piece(&self, index: u32) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.has_piece(index),
            AnyPeerConnection::Utp(conn) => conn.has_piece(index),
        }
    }

    pub fn pending_request_count(&self) -> usize {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.pending_request_count(),
            AnyPeerConnection::Utp(conn) => conn.pending_request_count(),
        }
    }

    pub fn peer_id(&self) -> Option<&[u8; 20]> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.peer_id(),
            AnyPeerConnection::Utp(conn) => conn.peer_id(),
        }
    }

    pub fn set_interested(&mut self, interested: bool) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.set_interested(interested),
            AnyPeerConnection::Utp(conn) => conn.set_interested(interested),
        }
    }

    pub fn set_choking(&mut self, choking: bool) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.set_choking(choking),
            AnyPeerConnection::Utp(conn) => conn.set_choking(choking),
        }
    }

    pub fn request_block(&mut self, index: u32, begin: u32, length: u32) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.request_block(index, begin, length),
            AnyPeerConnection::Utp(conn) => conn.request_block(index, begin, length),
        }
    }

    pub fn cancel_request(&mut self, index: u32, begin: u32, length: u32) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.cancel_request(index, begin, length),
            AnyPeerConnection::Utp(conn) => conn.cancel_request(index, begin, length),
        }
    }

    pub fn complete_request(&mut self, index: u32, begin: u32) {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.complete_request(index, begin),
            AnyPeerConnection::Utp(conn) => conn.complete_request(index, begin),
        }
    }

    pub fn send_keepalive(&mut self) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.send_keepalive(),
            AnyPeerConnection::Utp(conn) => conn.send_keepalive(),
        }
    }

    pub fn send_have(&mut self, piece_index: u32) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.send_have(piece_index),
            AnyPeerConnection::Utp(conn) => conn.send_have(piece_index),
        }
    }

    pub fn send_bitfield(&mut self, bitfield: &Bitfield) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.send_bitfield(bitfield),
            AnyPeerConnection::Utp(conn) => conn.send_bitfield(bitfield),
        }
    }

    pub fn send_piece(&mut self, index: u32, begin: u32, block: Vec<u8>) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.send_piece(index, begin, block),
            AnyPeerConnection::Utp(conn) => {
                let msg = PeerMessage::Piece { index, begin, block };
                conn.send_message(&msg)
            }
        }
    }

    pub fn extensions_enabled(&self) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.extensions_enabled(),
            AnyPeerConnection::Utp(conn) => conn.extensions_enabled(),
        }
    }

    pub fn extension_state(&self) -> Option<&ExtensionState> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.extension_state(),
            AnyPeerConnection::Utp(conn) => conn.extension_state(),
        }
    }

    pub fn peer_supports_extension(&self, name: &str) -> bool {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.peer_supports_extension(name),
            AnyPeerConnection::Utp(conn) => conn.peer_supports_extension(name),
        }
    }

    pub fn peer_metadata_size(&self) -> Option<u32> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.peer_metadata_size(),
            AnyPeerConnection::Utp(conn) => conn.peer_metadata_size(),
        }
    }

    pub fn send_extended_message(&mut self, ext_id: u8, payload: &[u8]) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.send_extended_message(ext_id, payload),
            AnyPeerConnection::Utp(conn) => conn.send_extended_message(ext_id, payload),
        }
    }

    pub fn take_pex_updates(&mut self) -> Option<PexUpdate> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.take_pex_updates(),
            AnyPeerConnection::Utp(conn) => conn.take_pex_updates(),
        }
    }

    pub fn take_metadata(&mut self) -> Option<Vec<u8>> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.take_metadata(),
            AnyPeerConnection::Utp(conn) => conn.take_metadata(),
        }
    }

    pub fn take_peer_requests(&mut self) -> Vec<crate::peer::PendingRequest> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.take_peer_requests(),
            AnyPeerConnection::Utp(_) => Vec::new(),
        }
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, AnyPeerConnection::Tcp(_))
    }

    pub fn is_utp(&self) -> bool {
        matches!(self, AnyPeerConnection::Utp(_))
    }

    pub fn disconnect(&mut self) {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.disconnect(),
            AnyPeerConnection::Utp(conn) => conn.disconnect(),
        }
    }

    pub fn bitfield(&self) -> Option<&Bitfield> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.bitfield(),
            AnyPeerConnection::Utp(_) => None,
        }
    }

    pub fn recv_message(&mut self) -> Result<Option<PeerMessage>> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.recv_message(),
            AnyPeerConnection::Utp(conn) => conn.recv_message(),
        }
    }

    pub fn raw_socket(&self) -> crate::sockets::RawSocket {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.raw_socket(),
            AnyPeerConnection::Utp(_) => 0,
        }
    }

    pub fn tick_handshake(&mut self) -> Result<()> {
        match self {
            AnyPeerConnection::Tcp(conn) => conn.tick_handshake(),
            AnyPeerConnection::Utp(_) => Ok(()),
        }
    }
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

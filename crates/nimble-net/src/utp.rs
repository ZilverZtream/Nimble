use anyhow::{Context, Result};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::time::{Duration, Instant};

const UTP_VERSION: u8 = 1;
const UTP_HEADER_SIZE: usize = 20;
const MAX_PACKET_SIZE: usize = 1400;
const MAX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - UTP_HEADER_SIZE;
const MIN_PACKET_SIZE: usize = 150;
const MAX_CWND_INCREASE_BYTES_PER_RTT: u32 = 3000;
const TARGET_DELAY_US: i64 = 100_000;
const MAX_DELAY_BASE_HISTORY: usize = 13;
const INIT_CWND: u32 = 2 * MAX_PACKET_SIZE as u32;
const MIN_CWND: u32 = MIN_PACKET_SIZE as u32;
const MAX_CWND: u32 = 1024 * 1024;
const MAX_SEND_BUFFER: usize = 1024 * 1024;
const MAX_RECV_BUFFER: usize = 1024 * 1024;
const DUPLICATE_ACK_THRESHOLD: u32 = 3;
const RETRANSMIT_TIMEOUT_MIN_MS: u64 = 500;
const RETRANSMIT_TIMEOUT_MAX_MS: u64 = 60_000;
const KEEPALIVE_INTERVAL_MS: u64 = 29_000;
const CONNECTION_TIMEOUT_MS: u64 = 30_000;
const MAX_RETRANSMITS: u32 = 6;
const MAX_WINDOW_SIZE: u32 = 1024 * 1024;
const SACK_EXTENSION: u8 = 1;
const MAX_SACK_SIZE: usize = 32;
const MAX_INFLIGHT_PACKETS: usize = 1024;
const MAX_REORDER_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_SEQUENCE_GAP: u16 = 16384;
const PACKET_POOL_BUFFER_SIZE: usize = 2048;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Data = 0,
    Fin = 1,
    State = 2,
    Reset = 3,
    Syn = 4,
}

impl PacketType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(PacketType::Data),
            1 => Some(PacketType::Fin),
            2 => Some(PacketType::State),
            3 => Some(PacketType::Reset),
            4 => Some(PacketType::Syn),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    SynSent,
    SynRecv,
    Connected,
    FinSent,
    Reset,
    Destroy,
}

#[derive(Debug, Clone)]
pub struct UtpHeader {
    pub packet_type: PacketType,
    pub version: u8,
    pub extension: u8,
    pub connection_id: u16,
    pub timestamp_us: u32,
    pub timestamp_diff_us: u32,
    pub wnd_size: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
}

impl UtpHeader {
    pub fn new(packet_type: PacketType, conn_id: u16, seq_nr: u16, ack_nr: u16) -> Self {
        UtpHeader {
            packet_type,
            version: UTP_VERSION,
            extension: 0,
            connection_id: conn_id,
            timestamp_us: 0,
            timestamp_diff_us: 0,
            wnd_size: MAX_WINDOW_SIZE,
            seq_nr,
            ack_nr,
        }
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < UTP_HEADER_SIZE {
            anyhow::bail!("packet too short: {} bytes", data.len());
        }

        let ver_type = data[0];
        let version = ver_type & 0x0F;
        let ptype = ver_type >> 4;

        if version != UTP_VERSION {
            anyhow::bail!("unsupported uTP version: {}", version);
        }

        let packet_type = PacketType::from_u8(ptype)
            .ok_or_else(|| anyhow::anyhow!("invalid packet type: {}", ptype))?;

        let extension = data[1];
        let connection_id = u16::from_be_bytes([data[2], data[3]]);
        let timestamp_us = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let timestamp_diff_us = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let wnd_size = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let seq_nr = u16::from_be_bytes([data[16], data[17]]);
        let ack_nr = u16::from_be_bytes([data[18], data[19]]);

        let mut header_end = UTP_HEADER_SIZE;
        let mut ext = extension;
        while ext != 0 && header_end + 2 <= data.len() {
            let next_ext = data[header_end];
            let ext_len = data[header_end + 1] as usize;
            header_end += 2 + ext_len;
            if header_end > data.len() {
                anyhow::bail!("extension beyond packet boundary");
            }
            ext = next_ext;
        }

        Ok((
            UtpHeader {
                packet_type,
                version,
                extension,
                connection_id,
                timestamp_us,
                timestamp_diff_us,
                wnd_size,
                seq_nr,
                ack_nr,
            },
            header_end,
        ))
    }

    pub fn serialize(&self, buf: &mut [u8]) {
        debug_assert!(buf.len() >= UTP_HEADER_SIZE);
        buf[0] = ((self.packet_type as u8) << 4) | (self.version & 0x0F);
        buf[1] = self.extension;
        buf[2..4].copy_from_slice(&self.connection_id.to_be_bytes());
        buf[4..8].copy_from_slice(&self.timestamp_us.to_be_bytes());
        buf[8..12].copy_from_slice(&self.timestamp_diff_us.to_be_bytes());
        buf[12..16].copy_from_slice(&self.wnd_size.to_be_bytes());
        buf[16..18].copy_from_slice(&self.seq_nr.to_be_bytes());
        buf[18..20].copy_from_slice(&self.ack_nr.to_be_bytes());
    }
}

#[derive(Debug, Clone)]
struct InFlightPacket {
    seq_nr: u16,
    data: PacketBuffer,
    sent_at: Instant,
    retransmits: u32,
    need_resend: bool,
}

struct PacketPoolInner {
    buffers: Vec<Box<[u8; PACKET_POOL_BUFFER_SIZE]>>,
}

#[derive(Clone)]
struct PacketPool {
    inner: Rc<RefCell<PacketPoolInner>>,
}

impl PacketPool {
    fn new() -> Self {
        PacketPool {
            inner: Rc::new(RefCell::new(PacketPoolInner { buffers: Vec::new() })),
        }
    }

    fn checkout(&self) -> PacketBuffer {
        let buffer = self.inner
            .borrow_mut()
            .buffers
            .pop()
            .unwrap_or_else(|| Box::new([0u8; PACKET_POOL_BUFFER_SIZE]));

        PacketBuffer {
            pool: self.clone(),
            buffer: Some(buffer),
            len: 0,
        }
    }

    fn checkin(&self, buffer: Box<[u8; PACKET_POOL_BUFFER_SIZE]>) {
        self.inner.borrow_mut().buffers.push(buffer);
    }
}

struct PacketBuffer {
    pool: PacketPool,
    buffer: Option<Box<[u8; PACKET_POOL_BUFFER_SIZE]>>,
    len: usize,
}

impl PacketBuffer {
    fn as_slice(&self) -> &[u8] {
        let buffer = self.buffer.as_ref().expect("packet buffer missing");
        &buffer[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut().expect("packet buffer missing")
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    fn checkin(mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.checkin(buffer);
        }
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pool.checkin(buffer);
        }
    }
}

enum OutgoingPacket {
    Owned(PacketBuffer),
    Inflight(u16),
}

struct DelayHistory {
    samples: VecDeque<u32>,
    base_delay: u32,
}

impl DelayHistory {
    fn new() -> Self {
        DelayHistory {
            samples: VecDeque::with_capacity(MAX_DELAY_BASE_HISTORY),
            base_delay: u32::MAX,
        }
    }

    fn add_sample(&mut self, delay_us: u32) {
        if delay_us < self.base_delay {
            self.base_delay = delay_us;
        }
        self.samples.push_back(delay_us);
        if self.samples.len() > MAX_DELAY_BASE_HISTORY {
            self.samples.pop_front();
            self.recalculate_base();
        }
    }

    fn recalculate_base(&mut self) {
        self.base_delay = self.samples.iter().copied().min().unwrap_or(u32::MAX);
    }

    fn current_delay(&self) -> u32 {
        self.samples.back().copied().unwrap_or(0).saturating_sub(self.base_delay)
    }
}

pub struct CongestionControl {
    cwnd: u32,
    ssthresh: u32,
    bytes_acked: u32,
    delay_history: DelayHistory,
    slow_start: bool,
    in_fast_recovery: bool,
    rtt_us: u32,
    rtt_var_us: u32,
    rto_ms: u64,
}

impl CongestionControl {
    fn new() -> Self {
        CongestionControl {
            cwnd: INIT_CWND,
            ssthresh: MAX_CWND,
            bytes_acked: 0,
            delay_history: DelayHistory::new(),
            slow_start: true,
            in_fast_recovery: false,
            rtt_us: 0,
            rtt_var_us: 0,
            rto_ms: RETRANSMIT_TIMEOUT_MIN_MS,
        }
    }

    fn on_ack(&mut self, bytes_acked: u32, delay_us: u32, inflight: u32) {
        self.delay_history.add_sample(delay_us);

        if self.in_fast_recovery {
            self.cwnd = self.ssthresh;
            self.slow_start = false;
            self.in_fast_recovery = false;
            self.bytes_acked = self.bytes_acked.saturating_add(bytes_acked);
            return;
        }

        if self.slow_start {
            self.cwnd = self.cwnd.saturating_add(bytes_acked);
            if self.cwnd >= self.ssthresh {
                self.slow_start = false;
            }
        } else {
            let our_delay = self.delay_history.current_delay() as i64;
            let off_target = TARGET_DELAY_US - our_delay;
            let delay_factor = off_target as f64 / TARGET_DELAY_US as f64;
            let acked_limited = bytes_acked.min(self.cwnd);
            let window_factor = acked_limited as f64 / self.cwnd.max(1) as f64;
            let scaled_gain = (MAX_CWND_INCREASE_BYTES_PER_RTT as f64 * delay_factor * window_factor) as i32;
            let new_cwnd = (self.cwnd as i64 + scaled_gain as i64).max(MIN_CWND as i64) as u32;
            self.cwnd = new_cwnd.min(MAX_CWND);
        }

        self.bytes_acked = self.bytes_acked.saturating_add(bytes_acked);
    }

    fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = self.ssthresh.saturating_add(3 * MAX_PACKET_SIZE as u32);
        self.slow_start = false;
        self.in_fast_recovery = true;
    }

    fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(MIN_CWND);
        self.cwnd = MIN_CWND;
        self.slow_start = false;
        self.rto_ms = (self.rto_ms * 2).min(RETRANSMIT_TIMEOUT_MAX_MS);
    }

    fn update_rtt(&mut self, rtt_us: u32) {
        if self.rtt_us == 0 {
            self.rtt_us = rtt_us;
            self.rtt_var_us = rtt_us / 2;
        } else {
            let rtt_diff = if rtt_us > self.rtt_us {
                rtt_us - self.rtt_us
            } else {
                self.rtt_us - rtt_us
            };
            self.rtt_var_us = (3 * self.rtt_var_us + rtt_diff) / 4;
            self.rtt_us = (7 * self.rtt_us + rtt_us) / 8;
        }

        let rto_us = self.rtt_us + 4 * self.rtt_var_us;
        self.rto_ms = (rto_us / 1000).max(RETRANSMIT_TIMEOUT_MIN_MS as u32) as u64;
        self.rto_ms = self.rto_ms.min(RETRANSMIT_TIMEOUT_MAX_MS);
    }

    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    pub fn rtt_us(&self) -> u32 {
        self.rtt_us
    }

    pub fn rto_ms(&self) -> u64 {
        self.rto_ms
    }
}

pub struct UtpSocket {
    state: ConnectionState,
    addr: SocketAddr,
    conn_id_recv: u16,
    conn_id_send: u16,
    seq_nr: u16,
    ack_nr: u16,
    last_ack_nr: u16,
    send_buffer: VecDeque<u8>,
    recv_buffer: VecDeque<u8>,
    inflight: HashMap<u16, InFlightPacket>,
    inflight_bytes: u32,
    peer_wnd_size: u32,
    our_wnd_size: u32,
    congestion: CongestionControl,
    last_recv_time: Instant,
    last_send_time: Instant,
    last_timestamp_us: u32,
    last_timestamp_diff_us: u32,
    duplicate_acks: u32,
    epoch_start: Instant,
    fin_sent: bool,
    fin_received: bool,
    fin_seq_nr: Option<u16>,
    outgoing_packets: Vec<OutgoingPacket>,
    reorder_buffer: HashMap<u16, Vec<u8>>,
    reorder_buffer_bytes: usize,
    sack_ranges: Vec<(u16, u16)>,
    packet_pool: PacketPool,
}

impl UtpSocket {
    pub fn new_outgoing(addr: SocketAddr) -> Self {
        let conn_id = rand_u16();
        let now = Instant::now();
        UtpSocket {
            state: ConnectionState::Idle,
            addr,
            conn_id_recv: conn_id,
            conn_id_send: conn_id.wrapping_add(1),
            seq_nr: 1,
            ack_nr: 0,
            last_ack_nr: 0,
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            inflight: HashMap::new(),
            inflight_bytes: 0,
            peer_wnd_size: MAX_WINDOW_SIZE,
            our_wnd_size: MAX_WINDOW_SIZE,
            congestion: CongestionControl::new(),
            last_recv_time: now,
            last_send_time: now,
            last_timestamp_us: 0,
            last_timestamp_diff_us: 0,
            duplicate_acks: 0,
            epoch_start: now,
            fin_sent: false,
            fin_received: false,
            fin_seq_nr: None,
            outgoing_packets: Vec::new(),
            reorder_buffer: HashMap::new(),
            reorder_buffer_bytes: 0,
            sack_ranges: Vec::new(),
            packet_pool: PacketPool::new(),
        }
    }

    pub fn new_incoming(addr: SocketAddr, conn_id: u16, seq_nr: u16, timestamp_us: u32) -> Self {
        let now = Instant::now();
        let timestamp_diff = micros_since(&now).saturating_sub(timestamp_us);
        UtpSocket {
            state: ConnectionState::SynRecv,
            addr,
            conn_id_recv: conn_id.wrapping_add(1),
            conn_id_send: conn_id,
            seq_nr: 1,
            ack_nr: seq_nr,
            last_ack_nr: seq_nr,
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            inflight: HashMap::new(),
            inflight_bytes: 0,
            peer_wnd_size: MAX_WINDOW_SIZE,
            our_wnd_size: MAX_WINDOW_SIZE,
            congestion: CongestionControl::new(),
            last_recv_time: now,
            last_send_time: now,
            last_timestamp_us: timestamp_us,
            last_timestamp_diff_us: timestamp_diff,
            duplicate_acks: 0,
            epoch_start: now,
            fin_sent: false,
            fin_received: false,
            fin_seq_nr: None,
            outgoing_packets: Vec::new(),
            reorder_buffer: HashMap::new(),
            reorder_buffer_bytes: 0,
            sack_ranges: Vec::new(),
            packet_pool: PacketPool::new(),
        }
    }

    pub fn initiate_connect(&mut self) {
        self.state = ConnectionState::SynSent;
        let packet = self.build_packet(PacketType::Syn, &[]);
        let seq = self.seq_nr.wrapping_sub(1);
        self.inflight.insert(
            seq,
            InFlightPacket {
                seq_nr: seq,
                data: packet,
                sent_at: Instant::now(),
                retransmits: 0,
                need_resend: false,
            },
        );
        self.outgoing_packets.push(OutgoingPacket::Inflight(seq));
    }

    pub fn accept(&mut self) {
        self.state = ConnectionState::Connected;
        let packet = self.build_packet(PacketType::State, &[]);
        self.outgoing_packets.push(OutgoingPacket::Owned(packet));
    }

    pub fn send(&mut self, data: &[u8]) -> Result<usize> {
        if self.state != ConnectionState::Connected {
            anyhow::bail!("socket not connected");
        }

        let available = MAX_SEND_BUFFER.saturating_sub(self.send_buffer.len());
        let to_queue = data.len().min(available);
        self.send_buffer.extend(&data[..to_queue]);
        Ok(to_queue)
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.recv_buffer.len());
        for i in 0..to_read {
            buf[i] = self.recv_buffer.pop_front().unwrap();
        }
        to_read
    }

    pub fn recv_available(&self) -> usize {
        self.recv_buffer.len()
    }

    pub fn close(&mut self) {
        if self.state == ConnectionState::Connected && !self.fin_sent {
            self.fin_sent = true;
            self.state = ConnectionState::FinSent;
        }
    }

    pub fn reset(&mut self) {
        let packet = self.build_packet(PacketType::Reset, &[]);
        self.outgoing_packets.push(OutgoingPacket::Owned(packet));
        self.state = ConnectionState::Reset;
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Reset | ConnectionState::Destroy)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn addr_v4(&self) -> Option<SocketAddrV4> {
        match self.addr {
            SocketAddr::V4(a) => Some(a),
            _ => None,
        }
    }

    pub fn addr_v6(&self) -> Option<SocketAddrV6> {
        match self.addr {
            SocketAddr::V6(a) => Some(a),
            _ => None,
        }
    }

    pub fn conn_id_recv(&self) -> u16 {
        self.conn_id_recv
    }

    pub fn conn_id_send(&self) -> u16 {
        self.conn_id_send
    }

    pub fn rtt_us(&self) -> u32 {
        self.congestion.rtt_us()
    }

    pub fn cwnd(&self) -> u32 {
        self.congestion.cwnd()
    }

    pub fn inflight_bytes(&self) -> u32 {
        self.inflight_bytes
    }

    pub fn process_packet(&mut self, data: &[u8]) -> Result<()> {
        let (header, header_len) = UtpHeader::parse(data)?;

        if !self.validate_connection_id(&header) {
            anyhow::bail!("connection ID mismatch");
        }

        let now = Instant::now();
        self.last_recv_time = now;

        let our_timestamp = micros_since(&now);
        self.last_timestamp_us = header.timestamp_us;
        self.last_timestamp_diff_us = our_timestamp.saturating_sub(header.timestamp_us);

        self.peer_wnd_size = header.wnd_size;

        match header.packet_type {
            PacketType::Reset => {
                self.state = ConnectionState::Reset;
                return Ok(());
            }
            PacketType::Syn => {
                return Ok(());
            }
            PacketType::State => {
                self.process_ack(&header);
                if self.state == ConnectionState::SynSent {
                    self.state = ConnectionState::Connected;
                    self.ack_nr = header.seq_nr;
                    self.last_ack_nr = header.seq_nr;
                    self.inflight.clear();
                    self.inflight_bytes = 0;
                }
            }
            PacketType::Data => {
                self.process_ack(&header);
                let payload = &data[header_len..];
                if !payload.is_empty() {
                    self.process_data(&header, payload);
                }
            }
            PacketType::Fin => {
                self.process_ack(&header);
                self.fin_received = true;
                self.fin_seq_nr = Some(header.seq_nr);
                if wrapping_cmp(header.seq_nr, self.ack_nr) == std::cmp::Ordering::Greater {
                    let expected = self.ack_nr.wrapping_add(1);
                    if header.seq_nr == expected {
                        self.ack_nr = header.seq_nr;
                    }
                }
                self.send_ack();
                if self.fin_sent && self.inflight.is_empty() {
                    self.state = ConnectionState::Destroy;
                } else if !self.fin_sent {
                    self.close();
                }
            }
        }

        Ok(())
    }

    fn validate_connection_id(&self, header: &UtpHeader) -> bool {
        header.connection_id == self.conn_id_recv
            || header.connection_id == self.conn_id_send
            || (self.state == ConnectionState::SynSent
                && header.connection_id == self.conn_id_recv.wrapping_sub(1))
    }

    fn process_ack(&mut self, header: &UtpHeader) {
        let ack_nr = header.ack_nr;

        if self.ack_nr == header.seq_nr || self.state == ConnectionState::SynRecv {
            self.last_ack_nr = ack_nr;
        }

        let mut acked_bytes = 0u32;
        let mut acked_seqs = Vec::new();

        for (&seq, pkt) in &self.inflight {
            if wrapping_cmp(seq, ack_nr) != std::cmp::Ordering::Greater {
                acked_seqs.push(seq);
                acked_bytes += pkt.data.len() as u32;
            }
        }

        let rtt_sample = if !acked_seqs.is_empty() {
            self.inflight.get(&acked_seqs[acked_seqs.len() - 1])
                .map(|p| p.sent_at.elapsed().as_micros() as u32)
        } else {
            None
        };

        for seq in acked_seqs {
            if let Some(pkt) = self.inflight.remove(&seq) {
                self.inflight_bytes = self.inflight_bytes.saturating_sub(pkt.data.len as u32);
                pkt.data.checkin();
            }
        }

        if let Some(rtt) = rtt_sample {
            self.congestion.update_rtt(rtt);
        }

        if acked_bytes > 0 {
            self.congestion.on_ack(acked_bytes, header.timestamp_diff_us, self.inflight_bytes);
            self.duplicate_acks = 0;
        } else if !self.inflight.is_empty() {
            self.duplicate_acks += 1;
            if self.duplicate_acks == DUPLICATE_ACK_THRESHOLD {
                if let Some(oldest_seq) = self.oldest_inflight_seq() {
                    let now = Instant::now();
                    self.queue_retransmit(oldest_seq, now);
                }
                self.congestion.on_loss();
            } else if self.duplicate_acks > DUPLICATE_ACK_THRESHOLD {
                self.congestion.cwnd = self.congestion.cwnd.saturating_add(MAX_PACKET_SIZE as u32);
            }
        }

        self.parse_sack(header);
    }

    fn parse_sack(&mut self, _header: &UtpHeader) {
    }

    fn process_data(&mut self, header: &UtpHeader, payload: &[u8]) {
        let expected_seq = self.ack_nr.wrapping_add(1);

        if header.seq_nr == expected_seq {
            if self.recv_buffer.len() + payload.len() <= MAX_RECV_BUFFER {
                self.recv_buffer.extend(payload);
                self.ack_nr = header.seq_nr;
                self.deliver_reordered();
            }
        } else if wrapping_cmp(header.seq_nr, expected_seq) == std::cmp::Ordering::Greater {
            let seq_gap = header.seq_nr.wrapping_sub(expected_seq);
            if seq_gap > MAX_SEQUENCE_GAP {
                return;
            }

            if self.reorder_buffer.len() < MAX_INFLIGHT_PACKETS
                && self.reorder_buffer_bytes + payload.len() <= MAX_REORDER_BUFFER_BYTES {
                self.reorder_buffer_bytes += payload.len();
                self.reorder_buffer.insert(header.seq_nr, payload.to_vec());
            }
        }

        self.send_ack();
    }

    fn deliver_reordered(&mut self) {
        loop {
            let next_seq = self.ack_nr.wrapping_add(1);
            if let Some(data) = self.reorder_buffer.remove(&next_seq) {
                if self.recv_buffer.len() + data.len() <= MAX_RECV_BUFFER {
                    self.reorder_buffer_bytes = self.reorder_buffer_bytes.saturating_sub(data.len());
                    self.recv_buffer.extend(&data);
                    self.ack_nr = next_seq;
                } else {
                    self.reorder_buffer.insert(next_seq, data);
                    break;
                }
            } else {
                break;
            }
        }
    }

    fn send_ack(&mut self) {
        let packet = self.build_packet(PacketType::State, &[]);
        self.outgoing_packets.push(OutgoingPacket::Owned(packet));
    }

    pub fn tick(&mut self) {
        self.outgoing_packets.clear();

        let now = Instant::now();

        if self.last_recv_time.elapsed() > Duration::from_millis(CONNECTION_TIMEOUT_MS) {
            if self.state != ConnectionState::Idle {
                self.state = ConnectionState::Destroy;
            }
            return;
        }

        self.check_retransmits(now);

        self.send_pending_data();

        if self.fin_sent && self.state == ConnectionState::FinSent && !self.inflight.contains_key(&self.seq_nr) {
            let packet = self.build_packet(PacketType::Fin, &[]);
            let seq = self.seq_nr.wrapping_sub(1);
            self.inflight.insert(
                seq,
                InFlightPacket {
                    seq_nr: seq,
                    data: packet,
                    sent_at: now,
                    retransmits: 0,
                    need_resend: false,
                },
            );
            self.outgoing_packets.push(OutgoingPacket::Inflight(seq));
        }

        if self.last_send_time.elapsed() > Duration::from_millis(KEEPALIVE_INTERVAL_MS)
            && self.state == ConnectionState::Connected
        {
            self.send_ack();
            self.last_send_time = now;
        }
    }

    fn check_retransmits(&mut self, now: Instant) {
        let rto = Duration::from_millis(self.congestion.rto_ms());
        let mut to_resend = Vec::new();

        for (seq, pkt) in &mut self.inflight {
            if pkt.need_resend || pkt.sent_at.elapsed() > rto {
                if pkt.retransmits >= MAX_RETRANSMITS {
                    self.state = ConnectionState::Destroy;
                    return;
                }
                to_resend.push(*seq);
            }
        }

        if !to_resend.is_empty() {
            self.congestion.on_timeout();
        }

        for seq in to_resend {
            self.queue_retransmit(seq, now);
        }
    }

    fn send_pending_data(&mut self) {
        if self.state != ConnectionState::Connected {
            return;
        }

        let available_window = self.effective_window();

        while !self.send_buffer.is_empty() && self.inflight_bytes < available_window {
            let chunk_size = (available_window - self.inflight_bytes) as usize;
            let chunk_size = chunk_size.min(MAX_PAYLOAD_SIZE).min(self.send_buffer.len());

            if chunk_size == 0 {
                break;
            }

            let payload: Vec<u8> = self.send_buffer.drain(..chunk_size).collect();
            let packet = self.build_packet(PacketType::Data, &payload);
            let seq = self.seq_nr.wrapping_sub(1);

            self.inflight.insert(
                seq,
                InFlightPacket {
                    seq_nr: seq,
                    data: packet,
                    sent_at: Instant::now(),
                    retransmits: 0,
                    need_resend: false,
                },
            );
            self.inflight_bytes += (UTP_HEADER_SIZE + payload.len()) as u32;
            self.outgoing_packets.push(OutgoingPacket::Inflight(seq));
        }
    }

    fn effective_window(&self) -> u32 {
        self.congestion.cwnd().min(self.peer_wnd_size)
    }

    fn build_packet(&mut self, ptype: PacketType, payload: &[u8]) -> PacketBuffer {
        let now = Instant::now();
        let timestamp = micros_since(&now);

        let mut header = UtpHeader::new(
            ptype,
            self.conn_id_send,
            self.seq_nr,
            self.ack_nr,
        );
        header.timestamp_us = timestamp;
        header.timestamp_diff_us = self.last_timestamp_diff_us;
        header.wnd_size = self.our_wnd_size.saturating_sub(self.recv_buffer.len() as u32);

        let total_len = UTP_HEADER_SIZE + payload.len();
        let mut packet = self.packet_pool.checkout();
        packet.set_len(total_len);
        let buf = packet.as_mut_slice();
        header.serialize(&mut buf[..UTP_HEADER_SIZE]);
        buf[UTP_HEADER_SIZE..total_len].copy_from_slice(payload);

        if ptype == PacketType::Data || ptype == PacketType::Syn || ptype == PacketType::Fin {
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }

        self.last_send_time = now;
        packet
    }

    fn oldest_inflight_seq(&self) -> Option<u16> {
        self.inflight.keys().copied().min_by(|a, b| wrapping_cmp(*a, *b))
    }

    fn queue_retransmit(&mut self, seq: u16, now: Instant) {
        if let Some(pkt) = self.inflight.get_mut(&seq) {
            pkt.sent_at = now;
            pkt.retransmits += 1;
            pkt.need_resend = false;
            self.outgoing_packets.push(OutgoingPacket::Inflight(seq));
        }
    }

    fn flush_outgoing<F>(&mut self, mut send_fn: F) -> Result<()>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<usize>,
    {
        let outgoing = std::mem::take(&mut self.outgoing_packets);
        for packet in outgoing {
            match packet {
                OutgoingPacket::Owned(buffer) => {
                    let _ = send_fn(buffer.as_slice(), self.addr)?;
                }
                OutgoingPacket::Inflight(seq) => {
                    if let Some(pkt) = self.inflight.get(&seq) {
                        let _ = send_fn(pkt.data.as_slice(), self.addr)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn micros_since(instant: &Instant) -> u32 {
    let epoch = std::time::SystemTime::UNIX_EPOCH;
    let now = std::time::SystemTime::now();
    let since_epoch = now.duration_since(epoch).unwrap_or_default();
    (since_epoch.as_micros() & 0xFFFF_FFFF) as u32
}

fn rand_u16() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64);
    hasher.finish() as u16
}

fn wrapping_cmp(a: u16, b: u16) -> std::cmp::Ordering {
    let diff = a.wrapping_sub(b) as i16;
    if diff > 0 {
        std::cmp::Ordering::Greater
    } else if diff < 0 {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Equal
    }
}

pub struct UtpMultiplexer {
    sockets: HashMap<(SocketAddr, u16), UtpSocket>,
    pending_incoming: VecDeque<UtpSocket>,
    bound_addr: SocketAddr,
}

impl UtpMultiplexer {
    pub fn new(bound_addr: SocketAddr) -> Self {
        UtpMultiplexer {
            sockets: HashMap::new(),
            pending_incoming: VecDeque::new(),
            bound_addr,
        }
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<u16> {
        let mut socket = UtpSocket::new_outgoing(addr);
        socket.initiate_connect();
        let conn_id = socket.conn_id_recv();
        self.sockets.insert((addr, conn_id), socket);
        Ok(conn_id)
    }

    pub fn accept(&mut self) -> Option<(SocketAddr, u16)> {
        if let Some(socket) = self.pending_incoming.pop_front() {
            let addr = socket.addr();
            let conn_id = socket.conn_id_recv();
            self.sockets.insert((addr, conn_id), socket);
            Some((addr, conn_id))
        } else {
            None
        }
    }

    pub fn process_incoming<F>(&mut self, data: &[u8], from: SocketAddr, mut send_fn: F) -> Result<()>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<usize>,
    {
        let (header, _) = UtpHeader::parse(data)?;

        if header.packet_type == PacketType::Syn {
            let mut socket = UtpSocket::new_incoming(from, header.connection_id, header.seq_nr, header.timestamp_us);
            socket.accept();
            socket.flush_outgoing(&mut send_fn)?;
            self.pending_incoming.push_back(socket);
            return Ok(());
        }

        let key_recv = (from, header.connection_id);
        let key_send = (from, header.connection_id.wrapping_add(1));

        let key = if self.sockets.contains_key(&key_recv) {
            Some(key_recv)
        } else if self.sockets.contains_key(&key_send) {
            Some(key_send)
        } else {
            None
        };

        if let Some(key) = key {
            if let Some(socket) = self.sockets.get_mut(&key) {
                socket.process_packet(data)?;
                socket.flush_outgoing(&mut send_fn)?;
            }
        }

        Ok(())
    }

    pub fn get_socket(&mut self, addr: SocketAddr, conn_id: u16) -> Option<&mut UtpSocket> {
        self.sockets.get_mut(&(addr, conn_id))
    }

    pub fn remove_socket(&mut self, addr: SocketAddr, conn_id: u16) -> Option<UtpSocket> {
        self.sockets.remove(&(addr, conn_id))
    }

    pub fn tick<F>(&mut self, mut send_fn: F) -> Result<()>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<usize>,
    {
        let mut to_remove = Vec::new();

        for (key, socket) in &mut self.sockets {
            socket.tick();
            socket.flush_outgoing(&mut send_fn)?;
            if socket.is_closed() {
                to_remove.push(*key);
            }
        }

        for key in to_remove {
            self.sockets.remove(&key);
        }

        Ok(())
    }

    pub fn flush_socket<F>(&mut self, addr: SocketAddr, conn_id: u16, mut send_fn: F) -> Result<()>
    where
        F: FnMut(&[u8], SocketAddr) -> Result<usize>,
    {
        if let Some(socket) = self.sockets.get_mut(&(addr, conn_id)) {
            socket.flush_outgoing(&mut send_fn)?;
        }
        Ok(())
    }

    pub fn socket_count(&self) -> usize {
        self.sockets.len()
    }

    pub fn pending_connections(&self) -> usize {
        self.pending_incoming.len()
    }
}

#[cfg(target_os = "windows")]
mod windows_udp {
    use super::*;
    use windows_sys::Win32::Networking::WinSock::{
        self, INVALID_SOCKET, SOCKET, SOCKET_ERROR, AF_INET, AF_INET6, SOCK_DGRAM,
        IPPROTO_UDP, FIONBIO, SOCKADDR_IN, SOCKADDR_IN6, SD_BOTH, WSAEWOULDBLOCK,
        SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO, SO_REUSEADDR, IPV6_V6ONLY,
    };

    const RECV_BUFFER_SIZE: usize = 2048;
    const RECV_TIMEOUT_MS: u32 = 100;

    pub struct UdpSocketRaw {
        socket: SOCKET,
        is_v6: bool,
    }

    impl UdpSocketRaw {
        pub fn new_v4() -> Result<Self> {
            init_winsock()?;

            let socket = unsafe {
                WinSock::socket(AF_INET as i32, SOCK_DGRAM, IPPROTO_UDP)
            };

            if socket == INVALID_SOCKET {
                let err = get_last_error();
                anyhow::bail!("socket() failed: error {}", err);
            }

            let sock = UdpSocketRaw { socket, is_v6: false };
            sock.configure()?;
            Ok(sock)
        }

        pub fn new_v6() -> Result<Self> {
            init_winsock()?;

            let socket = unsafe {
                WinSock::socket(AF_INET6 as i32, SOCK_DGRAM, IPPROTO_UDP)
            };

            if socket == INVALID_SOCKET {
                let err = get_last_error();
                anyhow::bail!("socket() failed: error {}", err);
            }

            let v6only: i32 = 1;
            unsafe {
                WinSock::setsockopt(
                    socket,
                    windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
                    IPV6_V6ONLY as i32,
                    &v6only as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            let sock = UdpSocketRaw { socket, is_v6: true };
            sock.configure()?;
            Ok(sock)
        }

        fn configure(&self) -> Result<()> {
            let mut mode: u32 = 1;
            let result = unsafe {
                WinSock::ioctlsocket(self.socket, FIONBIO as i32, &mut mode)
            };
            if result == SOCKET_ERROR {
                anyhow::bail!("ioctlsocket(FIONBIO) failed: {}", get_last_error());
            }

            let recv_timeout = RECV_TIMEOUT_MS as i32;
            unsafe {
                WinSock::setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_RCVTIMEO,
                    &recv_timeout as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            let reuse: i32 = 1;
            unsafe {
                WinSock::setsockopt(
                    self.socket,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    &reuse as *const i32 as *const u8,
                    std::mem::size_of::<i32>() as i32,
                );
            }

            Ok(())
        }

        pub fn bind(&self, addr: SocketAddr) -> Result<()> {
            match addr {
                SocketAddr::V4(v4) => {
                    let sockaddr = sockaddr_from_v4(v4);
                    let result = unsafe {
                        WinSock::bind(
                            self.socket,
                            &sockaddr as *const SOCKADDR_IN as *const WinSock::SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN>() as i32,
                        )
                    };
                    if result == SOCKET_ERROR {
                        anyhow::bail!("bind() failed: {}", get_last_error());
                    }
                }
                SocketAddr::V6(v6) => {
                    let sockaddr = sockaddr_from_v6(v6);
                    let result = unsafe {
                        WinSock::bind(
                            self.socket,
                            &sockaddr as *const SOCKADDR_IN6 as *const WinSock::SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN6>() as i32,
                        )
                    };
                    if result == SOCKET_ERROR {
                        anyhow::bail!("bind() failed: {}", get_last_error());
                    }
                }
            }
            Ok(())
        }

        pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
            let result = match addr {
                SocketAddr::V4(v4) => {
                    let sockaddr = sockaddr_from_v4(v4);
                    unsafe {
                        WinSock::sendto(
                            self.socket,
                            data.as_ptr(),
                            data.len() as i32,
                            0,
                            &sockaddr as *const SOCKADDR_IN as *const WinSock::SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN>() as i32,
                        )
                    }
                }
                SocketAddr::V6(v6) => {
                    let sockaddr = sockaddr_from_v6(v6);
                    unsafe {
                        WinSock::sendto(
                            self.socket,
                            data.as_ptr(),
                            data.len() as i32,
                            0,
                            &sockaddr as *const SOCKADDR_IN6 as *const WinSock::SOCKADDR,
                            std::mem::size_of::<SOCKADDR_IN6>() as i32,
                        )
                    }
                }
            };

            if result == SOCKET_ERROR {
                let err = get_last_error();
                if err == WSAEWOULDBLOCK as i32 {
                    return Ok(0);
                }
                anyhow::bail!("sendto() failed: {}", err);
            }

            Ok(result as usize)
        }

        pub fn recv_from(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>> {
            let mut from_v4: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            let mut from_v6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            let mut from_len = if self.is_v6 {
                std::mem::size_of::<SOCKADDR_IN6>() as i32
            } else {
                std::mem::size_of::<SOCKADDR_IN>() as i32
            };

            let result = if self.is_v6 {
                unsafe {
                    WinSock::recvfrom(
                        self.socket,
                        buf.as_mut_ptr(),
                        buf.len() as i32,
                        0,
                        &mut from_v6 as *mut SOCKADDR_IN6 as *mut WinSock::SOCKADDR,
                        &mut from_len,
                    )
                }
            } else {
                unsafe {
                    WinSock::recvfrom(
                        self.socket,
                        buf.as_mut_ptr(),
                        buf.len() as i32,
                        0,
                        &mut from_v4 as *mut SOCKADDR_IN as *mut WinSock::SOCKADDR,
                        &mut from_len,
                    )
                }
            };

            if result == SOCKET_ERROR {
                let err = get_last_error();
                if err == WSAEWOULDBLOCK as i32 || err == 10060 {
                    return Ok(None);
                }
                anyhow::bail!("recvfrom() failed: {}", err);
            }

            let addr = if self.is_v6 {
                sockaddr_to_v6(&from_v6)
            } else {
                sockaddr_to_v4(&from_v4)
            };

            Ok(Some((result as usize, addr)))
        }

        pub fn close(&mut self) {
            if self.socket != INVALID_SOCKET {
                unsafe {
                    WinSock::shutdown(self.socket, SD_BOTH);
                    WinSock::closesocket(self.socket);
                }
                self.socket = INVALID_SOCKET;
            }
        }
    }

    impl Drop for UdpSocketRaw {
        fn drop(&mut self) {
            self.close();
        }
    }

    fn sockaddr_from_v4(addr: SocketAddrV4) -> SOCKADDR_IN {
        let ip_bytes = addr.ip().octets();
        SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: addr.port().to_be(),
            sin_addr: WinSock::IN_ADDR {
                S_un: WinSock::IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip_bytes),
                },
            },
            sin_zero: [0; 8],
        }
    }

    fn sockaddr_from_v6(addr: SocketAddrV6) -> SOCKADDR_IN6 {
        let ip_bytes = addr.ip().octets();
        SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: addr.port().to_be(),
            sin6_flowinfo: addr.flowinfo(),
            sin6_addr: WinSock::IN6_ADDR {
                u: WinSock::IN6_ADDR_0 {
                    Byte: ip_bytes,
                },
            },
            sin6_scope_id: addr.scope_id(),
        }
    }

    fn sockaddr_to_v4(addr: &SOCKADDR_IN) -> SocketAddr {
        let ip_bytes = unsafe { addr.sin_addr.S_un.S_addr.to_ne_bytes() };
        let ip = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
        let port = u16::from_be(addr.sin_port);
        SocketAddr::V4(SocketAddrV4::new(ip, port))
    }

    fn sockaddr_to_v6(addr: &SOCKADDR_IN6) -> SocketAddr {
        let ip_bytes = unsafe { addr.sin6_addr.u.Byte };
        let ip = std::net::Ipv6Addr::from(ip_bytes);
        let port = u16::from_be(addr.sin6_port);
        SocketAddr::V6(SocketAddrV6::new(ip, port, addr.sin6_flowinfo, addr.sin6_scope_id))
    }

    fn get_last_error() -> i32 {
        unsafe { WinSock::WSAGetLastError() }
    }

    static WINSOCK_INIT: std::sync::Once = std::sync::Once::new();

    fn init_winsock() -> Result<()> {
        use windows_sys::Win32::Networking::WinSock::WSADATA;
        static mut INIT_RESULT: Option<i32> = None;

        WINSOCK_INIT.call_once(|| {
            let mut wsa_data: WSADATA = unsafe { std::mem::zeroed() };
            let result = unsafe {
                WinSock::WSAStartup(0x0202, &mut wsa_data)
            };
            unsafe { INIT_RESULT = Some(result); }
        });

        unsafe {
            if let Some(result) = INIT_RESULT {
                if result != 0 {
                    anyhow::bail!("WSAStartup failed: {}", result);
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
mod unix_udp {
    use super::*;
    use std::net::UdpSocket;

    pub struct UdpSocketRaw {
        socket: UdpSocket,
    }

    impl UdpSocketRaw {
        pub fn new_v4() -> Result<Self> {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.set_nonblocking(true)?;
            Ok(UdpSocketRaw { socket })
        }

        pub fn new_v6() -> Result<Self> {
            let socket = UdpSocket::bind("[::]:0")?;
            socket.set_nonblocking(true)?;
            Ok(UdpSocketRaw { socket })
        }

        pub fn bind(&self, addr: SocketAddr) -> Result<()> {
            Ok(())
        }

        pub fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
            match self.socket.send_to(data, addr) {
                Ok(n) => Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(e.into()),
            }
        }

        pub fn recv_from(&self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>> {
            match self.socket.recv_from(buf) {
                Ok((n, addr)) => Ok(Some((n, addr))),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e.into()),
            }
        }

        pub fn close(&mut self) {
        }
    }
}

#[cfg(target_os = "windows")]
pub use windows_udp::UdpSocketRaw;

#[cfg(not(target_os = "windows"))]
pub use unix_udp::UdpSocketRaw;

pub struct UtpListener {
    socket_v4: Option<UdpSocketRaw>,
    socket_v6: Option<UdpSocketRaw>,
    multiplexer_v4: UtpMultiplexer,
    multiplexer_v6: UtpMultiplexer,
    recv_buf: [u8; 2048],
}

impl UtpListener {
    pub fn new(port: u16, enable_v6: bool) -> Result<Self> {
        let v4_addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, port));
        let socket_v4 = UdpSocketRaw::new_v4()?;
        socket_v4.bind(v4_addr)?;

        let socket_v6 = if enable_v6 {
            let v6_addr = SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, port, 0, 0));
            let socket = UdpSocketRaw::new_v6()?;
            socket.bind(v6_addr)?;
            Some(socket)
        } else {
            None
        };

        Ok(UtpListener {
            socket_v4: Some(socket_v4),
            socket_v6,
            multiplexer_v4: UtpMultiplexer::new(v4_addr),
            multiplexer_v6: UtpMultiplexer::new(SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::UNSPECIFIED, port, 0, 0
            ))),
            recv_buf: [0u8; 2048],
        })
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<u16> {
        match addr {
            SocketAddr::V4(_) => {
                let conn_id = self.multiplexer_v4.connect(addr)?;
                if let Some(socket) = &self.socket_v4 {
                    self.multiplexer_v4.flush_socket(addr, conn_id, |data, dest| {
                        socket.send_to(data, dest)
                    })?;
                }
                Ok(conn_id)
            }
            SocketAddr::V6(_) => {
                let conn_id = self.multiplexer_v6.connect(addr)?;
                if let Some(socket) = &self.socket_v6 {
                    self.multiplexer_v6.flush_socket(addr, conn_id, |data, dest| {
                        socket.send_to(data, dest)
                    })?;
                }
                Ok(conn_id)
            }
        }
    }

    pub fn accept(&mut self) -> Option<(SocketAddr, u16)> {
        self.multiplexer_v4.accept().or_else(|| self.multiplexer_v6.accept())
    }

    pub fn poll(&mut self) -> Result<()> {
        if let Some(socket) = &self.socket_v4 {
            while let Some((len, from)) = socket.recv_from(&mut self.recv_buf)? {
                self.multiplexer_v4.process_incoming(&self.recv_buf[..len], from, |data, addr| {
                    socket.send_to(data, addr)
                })?;
            }
        }

        if let Some(socket) = &self.socket_v6 {
            while let Some((len, from)) = socket.recv_from(&mut self.recv_buf)? {
                self.multiplexer_v6.process_incoming(&self.recv_buf[..len], from, |data, addr| {
                    socket.send_to(data, addr)
                })?;
            }
        }

        Ok(())
    }

    pub fn tick(&mut self) -> Result<()> {
        if let Some(socket) = &self.socket_v4 {
            self.multiplexer_v4.tick(|data, addr| socket.send_to(data, addr))?;
        }

        if let Some(socket) = &self.socket_v6 {
            self.multiplexer_v6.tick(|data, addr| socket.send_to(data, addr))?;
        }

        Ok(())
    }

    pub fn get_socket(&mut self, addr: SocketAddr, conn_id: u16) -> Option<&mut UtpSocket> {
        match addr {
            SocketAddr::V4(_) => self.multiplexer_v4.get_socket(addr, conn_id),
            SocketAddr::V6(_) => self.multiplexer_v6.get_socket(addr, conn_id),
        }
    }

    pub fn send(&mut self, addr: SocketAddr, conn_id: u16, data: &[u8]) -> Result<usize> {
        let socket = match addr {
            SocketAddr::V4(_) => self.multiplexer_v4.get_socket(addr, conn_id),
            SocketAddr::V6(_) => self.multiplexer_v6.get_socket(addr, conn_id),
        };

        if let Some(socket) = socket {
            socket.send(data)
        } else {
            anyhow::bail!("socket not found")
        }
    }

    pub fn recv(&mut self, addr: SocketAddr, conn_id: u16, buf: &mut [u8]) -> usize {
        let socket = match addr {
            SocketAddr::V4(_) => self.multiplexer_v4.get_socket(addr, conn_id),
            SocketAddr::V6(_) => self.multiplexer_v6.get_socket(addr, conn_id),
        };

        if let Some(socket) = socket {
            socket.recv(buf)
        } else {
            0
        }
    }

    pub fn close_socket(&mut self, addr: SocketAddr, conn_id: u16) {
        let socket = match addr {
            SocketAddr::V4(_) => self.multiplexer_v4.get_socket(addr, conn_id),
            SocketAddr::V6(_) => self.multiplexer_v6.get_socket(addr, conn_id),
        };

        if let Some(socket) = socket {
            socket.close();
        }
    }

    pub fn socket_count(&self) -> usize {
        self.multiplexer_v4.socket_count() + self.multiplexer_v6.socket_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialize_parse() {
        let header = UtpHeader::new(PacketType::Data, 12345, 100, 99);
        let mut buf = [0u8; 20];
        header.serialize(&mut buf);

        let (parsed, _) = UtpHeader::parse(&buf).unwrap();
        assert_eq!(parsed.packet_type, PacketType::Data);
        assert_eq!(parsed.connection_id, 12345);
        assert_eq!(parsed.seq_nr, 100);
        assert_eq!(parsed.ack_nr, 99);
    }

    #[test]
    fn test_header_packet_types() {
        for ptype in [PacketType::Data, PacketType::Fin, PacketType::State, PacketType::Reset, PacketType::Syn] {
            let header = UtpHeader::new(ptype, 1, 1, 0);
            let mut buf = [0u8; 20];
            header.serialize(&mut buf);
            let (parsed, _) = UtpHeader::parse(&buf).unwrap();
            assert_eq!(parsed.packet_type, ptype);
        }
    }

    #[test]
    fn test_wrapping_cmp() {
        assert_eq!(wrapping_cmp(0, 0), std::cmp::Ordering::Equal);
        assert_eq!(wrapping_cmp(1, 0), std::cmp::Ordering::Greater);
        assert_eq!(wrapping_cmp(0, 1), std::cmp::Ordering::Less);
        assert_eq!(wrapping_cmp(0, 65535), std::cmp::Ordering::Greater);
        assert_eq!(wrapping_cmp(65535, 0), std::cmp::Ordering::Less);
        assert_eq!(wrapping_cmp(32768, 0), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_socket_outgoing_creation() {
        let addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 6881));
        let socket = UtpSocket::new_outgoing(addr);
        assert_eq!(socket.state(), ConnectionState::Idle);
        assert_eq!(socket.addr(), addr);
    }

    #[test]
    fn test_socket_initiate_connect() {
        let addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 6881));
        let mut socket = UtpSocket::new_outgoing(addr);
        socket.initiate_connect();
        assert_eq!(socket.state(), ConnectionState::SynSent);
        let packet = socket.inflight.values().next().expect("missing syn packet");
        assert!(packet.data.len() >= UTP_HEADER_SIZE);
        let (header, _) = UtpHeader::parse(packet.data.as_slice()).unwrap();
        assert_eq!(header.packet_type, PacketType::Syn);
    }

    #[test]
    fn test_multiplexer_connect() {
        let bound = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(0, 0, 0, 0), 6881));
        let mut mux = UtpMultiplexer::new(bound);
        let target = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 6882));
        let conn_id = mux.connect(target).unwrap();
        assert!(conn_id != 0);
        let mut captured = None;
        mux.flush_socket(target, conn_id, |data, _| {
            captured = Some(data.to_vec());
            Ok(data.len())
        }).unwrap();
        let packet = captured.expect("missing syn packet");
        assert!(packet.len() >= UTP_HEADER_SIZE);
        assert_eq!(mux.socket_count(), 1);
    }

    #[test]
    fn test_congestion_control_initial() {
        let cc = CongestionControl::new();
        assert_eq!(cc.cwnd(), INIT_CWND);
        assert_eq!(cc.rtt_us(), 0);
    }

    #[test]
    fn test_congestion_control_ack() {
        let mut cc = CongestionControl::new();
        let initial_cwnd = cc.cwnd();
        cc.on_ack(1000, 50000, 1000);
        assert!(cc.cwnd() >= initial_cwnd);
    }

    #[test]
    fn test_congestion_control_loss() {
        let mut cc = CongestionControl::new();
        cc.cwnd = 100000;
        cc.on_loss();
        assert!(cc.cwnd() < 100000);
    }

    #[test]
    fn test_socket_send_buffer() {
        let addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 6881));
        let mut socket = UtpSocket::new_outgoing(addr);
        socket.state = ConnectionState::Connected;
        let data = vec![0u8; 1000];
        let sent = socket.send(&data).unwrap();
        assert_eq!(sent, 1000);
    }

    #[test]
    fn test_socket_recv_buffer() {
        let addr = SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::new(127, 0, 0, 1), 6881));
        let mut socket = UtpSocket::new_outgoing(addr);
        socket.recv_buffer.extend(&[1, 2, 3, 4, 5]);
        let mut buf = [0u8; 10];
        let read = socket.recv(&mut buf);
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], &[1, 2, 3, 4, 5]);
    }
}

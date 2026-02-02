use anyhow::{anyhow, Result};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

const PROTOCOL_ID: u64 = 0x41727101980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;

const MAX_RETRIES: u32 = 8;
const BASE_TIMEOUT_SECS: u64 = 15;
const MAX_TIMEOUT_SECS: u64 = 3840;
const MAX_RESPONSE_SIZE: usize = 2048;
const CONNECTION_ID_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpTrackerEvent {
    None = 0,
    Completed = 1,
    Started = 2,
    Stopped = 3,
}

#[derive(Debug, Clone)]
pub struct UdpAnnounceRequest<'a> {
    pub info_hash: &'a [u8; 20],
    pub peer_id: &'a [u8; 20],
    pub downloaded: u64,
    pub left: u64,
    pub uploaded: u64,
    pub event: UdpTrackerEvent,
    pub ip: u32,
    pub key: u32,
    pub num_want: i32,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct UdpAnnounceResponse {
    pub interval: u32,
    pub leechers: u32,
    pub seeders: u32,
    pub peers: Vec<SocketAddrV4>,
}

struct ConnectionState {
    connection_id: u64,
    obtained_at: Instant,
}

pub struct UdpTracker {
    socket: UdpSocket,
    addr: SocketAddrV4,
    connection: Option<ConnectionState>,
}

impl UdpTracker {
    pub fn new(addr: SocketAddrV4) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(BASE_TIMEOUT_SECS)))?;
        socket.set_write_timeout(Some(Duration::from_secs(BASE_TIMEOUT_SECS)))?;
        socket.connect(addr)?;

        Ok(UdpTracker {
            socket,
            addr,
            connection: None,
        })
    }

    pub fn announce(&mut self, request: &UdpAnnounceRequest) -> Result<UdpAnnounceResponse> {
        self.ensure_connected()?;
        self.do_announce(request)
    }

    fn ensure_connected(&mut self) -> Result<()> {
        let needs_connect = match &self.connection {
            Some(conn) => conn.obtained_at.elapsed() >= CONNECTION_ID_LIFETIME,
            None => true,
        };

        if needs_connect {
            self.do_connect()?;
        }

        Ok(())
    }

    fn do_connect(&mut self) -> Result<()> {
        let transaction_id = generate_transaction_id();

        let mut retries = 0;
        loop {
            let timeout = calculate_timeout(retries);
            self.socket.set_read_timeout(Some(timeout))?;

            let request = build_connect_request(transaction_id);
            self.socket.send(&request)?;

            let mut buf = [0u8; 16];
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    if n < 16 {
                        if retries >= MAX_RETRIES {
                            return Err(anyhow!("connect response too short: {} bytes", n));
                        }
                        retries += 1;
                        continue;
                    }

                    let response_action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let response_txn_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                    if response_txn_id != transaction_id {
                        if retries >= MAX_RETRIES {
                            return Err(anyhow!(
                                "transaction ID mismatch: expected {}, got {}",
                                transaction_id,
                                response_txn_id
                            ));
                        }
                        retries += 1;
                        continue;
                    }

                    if response_action != ACTION_CONNECT {
                        return Err(anyhow!(
                            "unexpected action in connect response: {}",
                            response_action
                        ));
                    }

                    let connection_id = u64::from_be_bytes([
                        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
                    ]);

                    self.connection = Some(ConnectionState {
                        connection_id,
                        obtained_at: Instant::now(),
                    });

                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(anyhow!("connect timed out after {} retries", MAX_RETRIES));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(anyhow!("connect timed out after {} retries", MAX_RETRIES));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn do_announce(&mut self, req: &UdpAnnounceRequest) -> Result<UdpAnnounceResponse> {
        let connection_id = self
            .connection
            .as_ref()
            .ok_or_else(|| anyhow!("not connected"))?
            .connection_id;

        let transaction_id = generate_transaction_id();

        let mut retries = 0;
        loop {
            let timeout = calculate_timeout(retries);
            self.socket.set_read_timeout(Some(timeout))?;

            let request = build_announce_request(connection_id, transaction_id, req);
            self.socket.send(&request)?;

            let mut buf = [0u8; MAX_RESPONSE_SIZE];
            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    if n < 20 {
                        if retries >= MAX_RETRIES {
                            return Err(anyhow!("announce response too short: {} bytes", n));
                        }
                        retries += 1;
                        continue;
                    }

                    let response_action = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let response_txn_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

                    if response_txn_id != transaction_id {
                        if retries >= MAX_RETRIES {
                            return Err(anyhow!(
                                "transaction ID mismatch: expected {}, got {}",
                                transaction_id,
                                response_txn_id
                            ));
                        }
                        retries += 1;
                        continue;
                    }

                    if response_action == 3 {
                        let msg_len = n - 8;
                        let msg =
                            String::from_utf8_lossy(&buf[8..8 + msg_len.min(256)]).to_string();
                        return Err(anyhow!("tracker error: {}", msg));
                    }

                    if response_action != ACTION_ANNOUNCE {
                        return Err(anyhow!(
                            "unexpected action in announce response: {}",
                            response_action
                        ));
                    }

                    return parse_announce_response(&buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(anyhow!("announce timed out after {} retries", MAX_RETRIES));
                    }
                    self.connection = None;
                    self.ensure_connected()?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    retries += 1;
                    if retries > MAX_RETRIES {
                        return Err(anyhow!("announce timed out after {} retries", MAX_RETRIES));
                    }
                    self.connection = None;
                    self.ensure_connected()?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn addr(&self) -> SocketAddrV4 {
        self.addr
    }
}

fn generate_transaction_id() -> u32 {
    let bytes = nimble_util::ids::generate_random_bytes::<4>()
        .expect("failed to generate transaction ID");
    u32::from_be_bytes(bytes)
}

fn calculate_timeout(retry: u32) -> Duration {
    let secs = BASE_TIMEOUT_SECS * 2u64.pow(retry.min(8));
    Duration::from_secs(secs.min(MAX_TIMEOUT_SECS))
}

fn build_connect_request(transaction_id: u32) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    buf[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    buf[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    buf
}

fn build_announce_request(
    connection_id: u64,
    transaction_id: u32,
    req: &UdpAnnounceRequest,
) -> [u8; 98] {
    let mut buf = [0u8; 98];

    buf[0..8].copy_from_slice(&connection_id.to_be_bytes());
    buf[8..12].copy_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    buf[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    buf[16..36].copy_from_slice(req.info_hash);
    buf[36..56].copy_from_slice(req.peer_id);
    buf[56..64].copy_from_slice(&req.downloaded.to_be_bytes());
    buf[64..72].copy_from_slice(&req.left.to_be_bytes());
    buf[72..80].copy_from_slice(&req.uploaded.to_be_bytes());
    buf[80..84].copy_from_slice(&(req.event as u32).to_be_bytes());
    buf[84..88].copy_from_slice(&req.ip.to_be_bytes());
    buf[88..92].copy_from_slice(&req.key.to_be_bytes());
    buf[92..96].copy_from_slice(&req.num_want.to_be_bytes());
    buf[96..98].copy_from_slice(&req.port.to_be_bytes());

    buf
}

fn parse_announce_response(data: &[u8]) -> Result<UdpAnnounceResponse> {
    if data.len() < 20 {
        return Err(anyhow!("announce response too short"));
    }

    let interval = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let leechers = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
    let seeders = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    let peers_data = &data[20..];
    if peers_data.len() % 6 != 0 {
        return Err(anyhow!("peers data length is not a multiple of 6"));
    }

    let mut peers = Vec::new();
    for chunk in peers_data.chunks_exact(6) {
        let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        if port > 0 {
            peers.push(SocketAddrV4::new(ip, port));
        }
    }

    Ok(UdpAnnounceResponse {
        interval,
        leechers,
        seeders,
        peers,
    })
}

pub fn parse_udp_tracker_url(url: &str) -> Result<SocketAddrV4> {
    if !url.starts_with("udp://") {
        return Err(anyhow!("URL must start with udp://"));
    }

    let rest = &url[6..];
    let host_port = match rest.find('/') {
        Some(idx) => &rest[..idx],
        None => rest,
    };

    let (host, port_str) = match host_port.rfind(':') {
        Some(idx) => (&host_port[..idx], &host_port[idx + 1..]),
        None => return Err(anyhow!("missing port in UDP tracker URL")),
    };

    let port: u16 = port_str
        .split('/')
        .next()
        .unwrap_or(port_str)
        .parse()
        .map_err(|_| anyhow!("invalid port"))?;

    let ip: Ipv4Addr = host
        .parse()
        .or_else(|_| resolve_hostname(host))
        .map_err(|_| anyhow!("failed to resolve hostname: {}", host))?;

    Ok(SocketAddrV4::new(ip, port))
}

fn resolve_hostname(hostname: &str) -> Result<Ipv4Addr> {
    use std::net::ToSocketAddrs;

    let addrs: Vec<_> = format!("{}:0", hostname).to_socket_addrs()?.collect();

    for addr in addrs {
        if let std::net::SocketAddr::V4(v4) = addr {
            return Ok(*v4.ip());
        }
    }

    Err(anyhow!("no IPv4 address found for hostname"))
}

pub fn announce(tracker_url: &str, request: &UdpAnnounceRequest) -> Result<UdpAnnounceResponse> {
    let addr = parse_udp_tracker_url(tracker_url)?;
    let mut tracker = UdpTracker::new(addr)?;
    tracker.announce(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_connect_request() {
        let txn_id = 0x12345678;
        let request = build_connect_request(txn_id);

        assert_eq!(&request[0..8], &PROTOCOL_ID.to_be_bytes());
        assert_eq!(
            u32::from_be_bytes([request[8], request[9], request[10], request[11]]),
            ACTION_CONNECT
        );
        assert_eq!(
            u32::from_be_bytes([request[12], request[13], request[14], request[15]]),
            txn_id
        );
    }

    #[test]
    fn test_build_announce_request() {
        let info_hash = [1u8; 20];
        let peer_id = [2u8; 20];

        let req = UdpAnnounceRequest {
            info_hash: &info_hash,
            peer_id: &peer_id,
            downloaded: 1000,
            left: 2000,
            uploaded: 500,
            event: UdpTrackerEvent::Started,
            ip: 0,
            key: 0x12345678,
            num_want: -1,
            port: 6881,
        };

        let conn_id = 0xABCDEF0123456789;
        let txn_id = 0xDEADBEEF;
        let request = build_announce_request(conn_id, txn_id, &req);

        assert_eq!(&request[0..8], &conn_id.to_be_bytes());
        assert_eq!(
            u32::from_be_bytes([request[8], request[9], request[10], request[11]]),
            ACTION_ANNOUNCE
        );
        assert_eq!(
            u32::from_be_bytes([request[12], request[13], request[14], request[15]]),
            txn_id
        );
        assert_eq!(&request[16..36], &info_hash);
        assert_eq!(&request[36..56], &peer_id);
        assert_eq!(u16::from_be_bytes([request[96], request[97]]), 6881);
    }

    #[test]
    fn test_parse_announce_response() {
        let mut data = vec![0u8; 32];
        data[8..12].copy_from_slice(&1800u32.to_be_bytes());
        data[12..16].copy_from_slice(&5u32.to_be_bytes());
        data[16..20].copy_from_slice(&10u32.to_be_bytes());
        data[20..24].copy_from_slice(&[127, 0, 0, 1]);
        data[24..26].copy_from_slice(&6881u16.to_be_bytes());
        data[26..30].copy_from_slice(&[192, 168, 1, 100]);
        data[30..32].copy_from_slice(&6882u16.to_be_bytes());

        let response = parse_announce_response(&data).unwrap();

        assert_eq!(response.interval, 1800);
        assert_eq!(response.leechers, 5);
        assert_eq!(response.seeders, 10);
        assert_eq!(response.peers.len(), 2);
        assert_eq!(response.peers[0].ip(), &Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(response.peers[0].port(), 6881);
        assert_eq!(response.peers[1].ip(), &Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(response.peers[1].port(), 6882);
    }

    #[test]
    fn test_parse_udp_tracker_url() {
        let result = parse_udp_tracker_url("udp://127.0.0.1:6969/announce");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.ip(), &Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(addr.port(), 6969);
    }

    #[test]
    fn test_parse_udp_tracker_url_no_path() {
        let result = parse_udp_tracker_url("udp://127.0.0.1:6969");
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 6969);
    }

    #[test]
    fn test_parse_udp_tracker_url_invalid() {
        assert!(parse_udp_tracker_url("http://example.com:6969").is_err());
        assert!(parse_udp_tracker_url("udp://example.com").is_err());
    }

    #[test]
    fn test_calculate_timeout() {
        assert_eq!(calculate_timeout(0), Duration::from_secs(15));
        assert_eq!(calculate_timeout(1), Duration::from_secs(30));
        assert_eq!(calculate_timeout(2), Duration::from_secs(60));
        assert_eq!(calculate_timeout(8), Duration::from_secs(3840));
        assert_eq!(calculate_timeout(10), Duration::from_secs(3840));
    }

    #[test]
    fn test_generate_transaction_id() {
        let id1 = generate_transaction_id();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let id2 = generate_transaction_id();
        assert_ne!(id1, id2);
    }
}

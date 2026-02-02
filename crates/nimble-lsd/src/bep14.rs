use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::net::{UdpSocket, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

const LSD_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 192, 152, 143);
const LSD_PORT: u16 = 6771;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(120);
const MIN_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(60);
const PEER_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_MESSAGES_PER_TICK: usize = 100;
const MAX_PEERS_PER_INFOHASH: usize = 200;

pub struct LsdClient {
    socket: Option<UdpSocket>,
    torrents: HashMap<[u8; 20], TorrentAnnounce>,
    discovered_peers: HashMap<[u8; 20], HashMap<SocketAddrV4, Instant>>,
    listen_port: u16,
}

struct TorrentAnnounce {
    last_announce: Option<Instant>,
    cookie: String,
}

impl LsdClient {
    pub fn new(listen_port: u16) -> Self {
        LsdClient {
            socket: None,
            torrents: HashMap::new(),
            discovered_peers: HashMap::new(),
            listen_port,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LSD_PORT))
            .context("Failed to bind LSD socket")?;

        socket
            .set_nonblocking(true)
            .context("Failed to set non-blocking mode")?;

        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .context("Failed to set read timeout")?;

        Self::join_multicast(&socket)?;

        self.socket = Some(socket);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn join_multicast(socket: &UdpSocket) -> Result<()> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IP_ADD_MEMBERSHIP, SOCKET,
        };

        #[repr(C)]
        struct IpMreq {
            imr_multiaddr: [u8; 4],
            imr_interface: [u8; 4],
        }

        let mreq = IpMreq {
            imr_multiaddr: LSD_MULTICAST_ADDR.octets(),
            imr_interface: [0, 0, 0, 0],
        };

        let sock = socket.as_raw_socket() as SOCKET;
        let result = unsafe {
            setsockopt(
                sock,
                IPPROTO_IP as i32,
                IP_ADD_MEMBERSHIP as i32,
                &mreq as *const IpMreq as *const u8,
                std::mem::size_of::<IpMreq>() as i32,
            )
        };

        if result != 0 {
            anyhow::bail!("Failed to join multicast group");
        }

        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    fn join_multicast(socket: &UdpSocket) -> Result<()> {
        socket
            .join_multicast_v4(&LSD_MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)
            .context("Failed to join multicast group")
    }

    pub fn add_torrent(&mut self, info_hash: [u8; 20]) {
        if !self.torrents.contains_key(&info_hash) {
            self.torrents.insert(
                info_hash,
                TorrentAnnounce {
                    last_announce: None,
                    cookie: Self::generate_cookie(),
                },
            );
            self.discovered_peers.insert(info_hash, HashMap::new());
        }
    }

    pub fn remove_torrent(&mut self, info_hash: &[u8; 20]) {
        self.torrents.remove(info_hash);
        self.discovered_peers.remove(info_hash);
    }

    fn generate_cookie() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let hash = (nanos.wrapping_mul(0x45d9f3b) ^ 0x9e3779b9) as u32;
        format!("{:08x}", hash)
    }

    pub fn tick(&mut self) -> Result<()> {
        let socket = match self.socket.as_ref() {
            Some(s) => s,
            None => return Ok(()),
        };

        self.process_incoming_messages()?;
        self.cleanup_expired_peers();

        let now = Instant::now();

        let torrents_to_announce: Vec<_> = self
            .torrents
            .iter()
            .filter(|(_, announce)| {
                announce
                    .last_announce
                    .map(|last| now.duration_since(last) >= ANNOUNCE_INTERVAL)
                    .unwrap_or(true)
            })
            .map(|(ih, _)| *ih)
            .collect();

        for info_hash in torrents_to_announce {
            if let Err(e) = self.send_announce(info_hash) {
                eprintln!("LSD announce error for {}: {}", hex::encode(info_hash), e);
            }
        }

        Ok(())
    }

    fn send_announce(&mut self, info_hash: [u8; 20]) -> Result<()> {
        let socket = self.socket.as_ref().context("No socket available")?;

        let announce = self.torrents.get_mut(&info_hash).context("Torrent not found")?;

        let message = format!(
            "BT-SEARCH * HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             Port: {}\r\n\
             Infohash: {}\r\n\
             cookie: {}\r\n\
             \r\n",
            LSD_MULTICAST_ADDR,
            LSD_PORT,
            self.listen_port,
            hex::encode(info_hash),
            announce.cookie
        );

        socket
            .send_to(
                message.as_bytes(),
                SocketAddrV4::new(LSD_MULTICAST_ADDR, LSD_PORT),
            )
            .context("Failed to send LSD announce")?;

        announce.last_announce = Some(Instant::now());

        Ok(())
    }

    fn process_incoming_messages(&mut self) -> Result<()> {
        if self.socket.is_none() {
            return Ok(());
        }

        let mut buf = vec![0u8; 2048];
        let mut messages_to_process = Vec::new();

        loop {
            if messages_to_process.len() >= MAX_MESSAGES_PER_TICK {
                break;
            }

            let socket = self.socket.as_ref().unwrap();
            match socket.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    if n == 0 {
                        continue;
                    }

                    let message = String::from_utf8_lossy(&buf[..n]).to_string();
                    messages_to_process.push((message, addr));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    break;
                }
                Err(e) => {
                    eprintln!("LSD receive error: {}", e);
                    break;
                }
            }
        }

        for (message, addr) in messages_to_process {
            if let Err(e) = self.handle_message(&message, addr) {
                eprintln!("LSD message handling error: {}", e);
            }
        }

        Ok(())
    }

    fn handle_message(&mut self, message: &str, addr: std::net::SocketAddr) -> Result<()> {
        if !message.starts_with("BT-SEARCH * HTTP/1.1") {
            return Ok(());
        }

        let mut port = None;
        let mut info_hash = None;
        let mut cookie = None;

        for line in message.lines().skip(1) {
            let line = line.trim();
            if line.is_empty() {
                break;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    "port" => {
                        port = value.parse::<u16>().ok();
                    }
                    "infohash" => {
                        if let Ok(bytes) = hex::decode(value) {
                            if bytes.len() == 20 {
                                let mut hash = [0u8; 20];
                                hash.copy_from_slice(&bytes);
                                info_hash = Some(hash);
                            }
                        }
                    }
                    "cookie" => {
                        cookie = Some(value.to_string());
                    }
                    _ => {}
                }
            }
        }

        if let (Some(port), Some(info_hash)) = (port, info_hash) {
            if let Some(our_announce) = self.torrents.get(&info_hash) {
                if let Some(their_cookie) = cookie {
                    if their_cookie == our_announce.cookie {
                        return Ok(());
                    }
                }

                if let std::net::SocketAddr::V4(v4_addr) = addr {
                    let peer_addr = SocketAddrV4::new(*v4_addr.ip(), port);

                    if peer_addr.port() == 0 || peer_addr.port() == self.listen_port {
                        return Ok(());
                    }

                    if let Some(peers) = self.discovered_peers.get_mut(&info_hash) {
                        if peers.len() >= MAX_PEERS_PER_INFOHASH && !peers.contains_key(&peer_addr) {
                            if let Some(oldest_peer) = peers.iter()
                                .min_by_key(|(_, &time)| time)
                                .map(|(addr, _)| *addr)
                            {
                                peers.remove(&oldest_peer);
                            }
                        }
                        peers.insert(peer_addr, Instant::now());
                    }
                }
            }
        }

        Ok(())
    }

    pub fn get_discovered_peers(&mut self, info_hash: &[u8; 20]) -> Vec<SocketAddrV4> {
        let now = Instant::now();

        if let Some(peers) = self.discovered_peers.get_mut(info_hash) {
            peers.retain(|_, &mut discovered_at| now.duration_since(discovered_at) < PEER_TIMEOUT);
            peers.keys().copied().collect()
        } else {
            Vec::new()
        }
    }

    fn cleanup_expired_peers(&mut self) {
        let now = Instant::now();

        for peers in self.discovered_peers.values_mut() {
            peers.retain(|_, &mut discovered_at| now.duration_since(discovered_at) < PEER_TIMEOUT);
        }
    }

    pub fn clear_discovered_peers(&mut self, info_hash: &[u8; 20]) {
        if let Some(peers) = self.discovered_peers.get_mut(info_hash) {
            peers.clear();
        }
    }
}

impl Default for LsdClient {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = LsdClient::new(6881);
        assert_eq!(client.listen_port, 6881);
        assert!(client.socket.is_none());
    }

    #[test]
    fn test_add_remove_torrent() {
        let mut client = LsdClient::new(6881);
        let info_hash = [1u8; 20];

        client.add_torrent(info_hash);
        assert!(client.torrents.contains_key(&info_hash));
        assert!(client.discovered_peers.contains_key(&info_hash));

        client.remove_torrent(&info_hash);
        assert!(!client.torrents.contains_key(&info_hash));
        assert!(!client.discovered_peers.contains_key(&info_hash));
    }

    #[test]
    fn test_announce_message_format() {
        let message = format!(
            "BT-SEARCH * HTTP/1.1\r\n\
             Host: 239.192.152.143:6771\r\n\
             Port: 6881\r\n\
             Infohash: {}\r\n\
             cookie: abc123\r\n\
             \r\n",
            "a" .repeat(40)
        );

        assert!(message.starts_with("BT-SEARCH * HTTP/1.1"));
        assert!(message.contains("Port: 6881"));
        assert!(message.contains("cookie: abc123"));
    }

    #[test]
    fn test_get_discovered_peers() {
        let mut client = LsdClient::new(6881);
        let info_hash = [1u8; 20];

        client.add_torrent(info_hash);

        let peers = client.get_discovered_peers(&info_hash);
        assert_eq!(peers.len(), 0);

        if let Some(peer_set) = client.discovered_peers.get_mut(&info_hash) {
            peer_set.insert(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 6882));
        }

        let peers = client.get_discovered_peers(&info_hash);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_cookie_generation() {
        let cookie1 = LsdClient::generate_cookie();
        let cookie2 = LsdClient::generate_cookie();

        assert_eq!(cookie1.len(), 8);
        assert_eq!(cookie2.len(), 8);
    }
}

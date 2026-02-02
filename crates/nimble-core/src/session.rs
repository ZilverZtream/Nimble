use anyhow::Result;
use nimble_bencode::torrent::{parse_info_dict, parse_torrent, InfoHash, TorrentInfo};
use nimble_dht::node::DhtNode;
use nimble_lsd::bep14::LsdClient;
use nimble_nat::nat_pmp::{NatPmpClient, Protocol as NatProtocol};
use nimble_nat::upnp::UpnpClient;
use nimble_net::listener::PeerListener;
use nimble_net::peer::PeerConnection;
use nimble_net::tracker_http::TrackerEvent;
use nimble_storage::disk::DiskStorage;
use nimble_util::ids::peer_id_20;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{SocketAddrV4, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::magnet::parse_magnet;
use crate::peer_manager::PeerManager;
use crate::tracker_worker::{AnnounceTask, AnnounceWorker};

pub struct Session {
    torrents: HashMap<String, TorrentEntry>,
    download_dir: PathBuf,
    peer_id: [u8; 20],
    listen_port: u16,
    dht: Option<DhtNode>,
    dht_socket: Option<UdpSocket>,
    announce_worker: AnnounceWorker,
    pending_announces: HashSet<String>,
    peer_listener: Option<PeerListener>,
    nat_pmp: Option<NatPmpClient>,
    upnp: Option<UpnpClient>,
    lsd: Option<LsdClient>,
    mapped_port: Option<u16>,
}

pub enum TorrentEntry {
    Active(ActiveTorrent),
    Magnet(MagnetState),
}

pub struct ActiveTorrent {
    pub info: TorrentInfo,
    pub storage: DiskStorage,
    pub paused: bool,
    pub tracker: TrackerState,
    pub peer_manager: PeerManager,
    pub stats: TorrentStats,
    pub last_dht_query: Option<Instant>,
}

pub struct MagnetState {
    pub info_hash: [u8; 20],
    pub trackers: Vec<String>,
    pub paused: bool,
    pub tracker: TrackerState,
    pub peer_manager: PeerManager,
    pub stats: TorrentStats,
    pub last_dht_query: Option<Instant>,
}

pub struct TrackerState {
    pub last_announce: Option<Instant>,
    pub next_announce: Option<Instant>,
    pub interval: Duration,
    pub peers: Vec<SocketAddrV4>,
    pub consecutive_failures: u32,
    pub current_tier: usize,
    pub current_tracker_in_tier: usize,
    pub retry_interval: Duration,
}

#[derive(Debug, Default, Clone)]
pub struct TorrentStats {
    pub downloaded: u64,
    pub uploaded: u64,
    pub connected_peers: u32,
    pub pieces_completed: u32,
    pub pieces_total: u32,
}

#[derive(Debug, Default)]
pub struct SessionStats {
    pub active_torrents: u32,
    pub total_download_rate: u64,
    pub total_upload_rate: u64,
    pub total_peers: u32,
}

impl Session {
    pub fn new(
        download_dir: PathBuf,
        listen_port: u16,
        enable_dht: bool,
        enable_upnp: bool,
        enable_nat_pmp: bool,
        enable_lsd: bool,
    ) -> Self {
        let (dht, dht_socket) = if enable_dht {
            let socket = UdpSocket::bind(("0.0.0.0", listen_port))
                .ok()
                .and_then(|s| {
                    s.set_nonblocking(true).ok()?;
                    Some(s)
                });
            (Some(DhtNode::new()), socket)
        } else {
            (None, None)
        };

        let peer_listener = PeerListener::new(listen_port).ok();
        if peer_listener.is_none() {
            eprintln!("Failed to create peer listener on port {}", listen_port);
        }

        let mut nat_pmp = if enable_nat_pmp {
            let mut client = NatPmpClient::new();
            match client.discover() {
                Ok(_) => {
                    if let Ok(port) = client.add_port_mapping(listen_port, listen_port, NatProtocol::Tcp, None) {
                        eprintln!("NAT-PMP: Mapped TCP port {} -> {}", listen_port, port);
                    }
                    Some(client)
                }
                Err(e) => {
                    eprintln!("NAT-PMP discovery failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let mut upnp = if enable_upnp && nat_pmp.is_none() {
            let mut client = UpnpClient::new();
            match client.discover() {
                Ok(_) => {
                    eprintln!("UPnP: Gateway discovered");
                    Some(client)
                }
                Err(e) => {
                    eprintln!("UPnP discovery failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let mut lsd = if enable_lsd {
            let mut client = LsdClient::new(listen_port);
            match client.start() {
                Ok(_) => {
                    eprintln!("LSD: Started on port {}", listen_port);
                    Some(client)
                }
                Err(e) => {
                    eprintln!("LSD start failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let mut session = Session {
            torrents: HashMap::new(),
            download_dir,
            peer_id: peer_id_20().expect("Failed to generate peer ID"),
            listen_port,
            dht,
            dht_socket,
            announce_worker: AnnounceWorker::new(),
            pending_announces: HashSet::new(),
            peer_listener,
            nat_pmp,
            upnp,
            lsd,
            mapped_port: None,
        };

        if let Err(e) = session.load_saved_torrents() {
            eprintln!("Failed to load saved torrents: {}", e);
        }

        session
    }

    fn load_saved_torrents(&mut self) -> Result<()> {
        let entries = match fs::read_dir(&self.download_dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "torrent" {
                    if let Err(e) = self.load_torrent_from_file(&path) {
                        eprintln!("Failed to load torrent from {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(())
    }

    fn load_torrent_from_file(&mut self, path: &PathBuf) -> Result<()> {
        let data = fs::read(path)?;
        let info = parse_torrent(&data)?;
        let infohash = info.infohash.to_hex();

        if self.torrents.contains_key(&infohash) {
            return Ok(());
        }

        let storage = DiskStorage::new(&info, self.download_dir.clone())?;

        let tracker = TrackerState {
            last_announce: None,
            next_announce: Some(Instant::now()),
            interval: Duration::from_secs(1800),
            peers: Vec::new(),
            consecutive_failures: 0,
            current_tier: 0,
            current_tracker_in_tier: 0,
            retry_interval: Duration::from_secs(60),
        };

        let mut peer_manager = PeerManager::new(
            *info.infohash.as_bytes(),
            self.peer_id,
            info.pieces.len(),
            info.piece_length,
            info.total_length,
        );

        peer_manager.sync_completed_pieces(storage.bitfield());

        let stats = TorrentStats {
            pieces_total: info.pieces.len() as u32,
            pieces_completed: storage.bitfield().count_ones() as u32,
            ..Default::default()
        };

        let piece_count = info.pieces.len();
        let info_hash_bytes = *info.infohash.as_bytes();
        let is_private = info.private;

        let state = ActiveTorrent {
            info,
            storage,
            paused: false,
            tracker,
            peer_manager,
            stats,
            last_dht_query: None,
        };

        self.torrents
            .insert(infohash.clone(), TorrentEntry::Active(state));

        if let Some(listener) = self.peer_listener.as_mut() {
            listener.register_infohash(info_hash_bytes, self.peer_id, piece_count);
        }

        if !is_private {
            if let Some(lsd) = self.lsd.as_mut() {
                lsd.add_torrent(info_hash_bytes);
            }
        }

        Ok(())
    }

    pub fn add_torrent_file(&mut self, path: &str) -> Result<String> {
        let data = fs::read(path)?;
        let info = parse_torrent(&data)?;
        let infohash = info.infohash.to_hex();

        let torrent_save_path = self
            .download_dir
            .join(format!("{}.torrent", infohash));
        if !torrent_save_path.exists() {
            fs::write(&torrent_save_path, &data)?;
        }

        let storage = DiskStorage::new(&info, self.download_dir.clone())?;

        let tracker = TrackerState {
            last_announce: None,
            next_announce: Some(Instant::now()),
            interval: Duration::from_secs(1800),
            peers: Vec::new(),
            consecutive_failures: 0,
            current_tier: 0,
            current_tracker_in_tier: 0,
            retry_interval: Duration::from_secs(60),
        };

        let mut peer_manager = PeerManager::new(
            *info.infohash.as_bytes(),
            self.peer_id,
            info.pieces.len(),
            info.piece_length,
            info.total_length,
        );

        peer_manager.sync_completed_pieces(storage.bitfield());

        let stats = TorrentStats {
            pieces_total: info.pieces.len() as u32,
            ..Default::default()
        };

        let piece_count = info.pieces.len();
        let info_hash_bytes = *info.infohash.as_bytes();
        let is_private = info.private;

        let state = ActiveTorrent {
            info,
            storage,
            paused: false,
            tracker,
            peer_manager,
            stats,
            last_dht_query: None,
        };

        self.torrents
            .insert(infohash.clone(), TorrentEntry::Active(state));

        if let Some(listener) = self.peer_listener.as_mut() {
            listener.register_infohash(info_hash_bytes, self.peer_id, piece_count);
        }

        if !is_private {
            if let Some(lsd) = self.lsd.as_mut() {
                lsd.add_torrent(info_hash_bytes);
            }
        }

        Ok(infohash)
    }

    pub fn add_magnet(&mut self, uri: &str) -> Result<String> {
        let magnet = parse_magnet(uri)?;
        let infohash = InfoHash(magnet.info_hash).to_hex();
        if self.torrents.contains_key(&infohash) {
            anyhow::bail!("torrent already exists");
        }

        let tracker = TrackerState {
            last_announce: None,
            next_announce: if magnet.trackers.is_empty() {
                None
            } else {
                Some(Instant::now())
            },
            interval: Duration::from_secs(1800),
            peers: Vec::new(),
            consecutive_failures: 0,
            current_tier: 0,
            current_tracker_in_tier: 0,
            retry_interval: Duration::from_secs(60),
        };

        let peer_manager = PeerManager::new_metadata_only(magnet.info_hash, self.peer_id);

        let stats = TorrentStats::default();

        let state = MagnetState {
            info_hash: magnet.info_hash,
            trackers: magnet.trackers,
            paused: false,
            tracker,
            peer_manager,
            stats,
            last_dht_query: None,
        };

        self.torrents
            .insert(infohash.clone(), TorrentEntry::Magnet(state));

        if let Some(listener) = self.peer_listener.as_mut() {
            listener.register_infohash(magnet.info_hash, self.peer_id, 0);
        }

        if let Some(lsd) = self.lsd.as_mut() {
            lsd.add_torrent(magnet.info_hash);
        }

        Ok(infohash)
    }

    pub fn pause_all(&mut self) {
        for torrent in self.torrents.values_mut() {
            match torrent {
                TorrentEntry::Active(state) => state.paused = true,
                TorrentEntry::Magnet(state) => state.paused = true,
            }
        }
    }

    pub fn resume_all(&mut self) {
        for torrent in self.torrents.values_mut() {
            match torrent {
                TorrentEntry::Active(state) => state.paused = false,
                TorrentEntry::Magnet(state) => state.paused = false,
            }
        }
    }

    pub fn active_count(&self) -> u32 {
        self.torrents.len() as u32
    }

    pub fn tick(&mut self) -> Vec<String> {
        let mut log_lines = Vec::new();
        let now = Instant::now();
        let peer_id = self.peer_id;
        let listen_port = self.listen_port;
        let mut upgrades = Vec::new();

        log_lines.extend(self.process_incoming_peers());
        log_lines.extend(self.process_dht_incoming());
        log_lines.extend(self.process_lsd());

        if let Some(nat_pmp) = self.nat_pmp.as_mut() {
            let _ = nat_pmp.renew_mappings();
        }

        while let Some(result) = self.announce_worker.try_recv_result() {
            self.pending_announces.remove(&result.infohash_hex);

            if let Some(torrent) = self.torrents.get_mut(&result.infohash_hex) {
                match torrent {
                    TorrentEntry::Active(torrent) => {
                        if result.success {
                            torrent.tracker.last_announce = Some(now);
                            torrent.tracker.consecutive_failures = 0;
                            torrent.tracker.current_tier = 0;
                            torrent.tracker.current_tracker_in_tier = 0;
                            torrent.tracker.retry_interval = Duration::from_secs(60);
                            if let Some(interval) = result.interval {
                                torrent.tracker.interval = Duration::from_secs(interval as u64);
                            }
                            torrent.tracker.next_announce = Some(now + torrent.tracker.interval);
                            torrent.tracker.peers = result.peers.clone();
                            torrent.peer_manager.add_peers(&result.peers);

                            log_lines.push(format!(
                                "Tracker announce for {}: {} peers",
                                &result.infohash_hex[..8],
                                result.peers.len()
                            ));
                        } else {
                            torrent.tracker.consecutive_failures = torrent.tracker.consecutive_failures.saturating_add(1);
                            Self::advance_tracker_tier(&mut torrent.tracker, &torrent.info.announce_list);

                            let max_retry = Duration::from_secs(1800);
                            let next_retry = torrent.tracker.retry_interval.min(max_retry);
                            torrent.tracker.next_announce = Some(now + next_retry);
                            torrent.tracker.retry_interval = (torrent.tracker.retry_interval * 2).min(max_retry);

                            if let Some(error) = &result.error {
                                log_lines.push(format!(
                                    "Tracker announce failed for {} (failures: {}, next retry in {}s): {}",
                                    &result.infohash_hex[..8],
                                    torrent.tracker.consecutive_failures,
                                    next_retry.as_secs(),
                                    error
                                ));
                            }
                        }
                    }
                    TorrentEntry::Magnet(torrent) => {
                        if result.success {
                            torrent.tracker.last_announce = Some(now);
                            torrent.tracker.consecutive_failures = 0;
                            torrent.tracker.current_tracker_in_tier = 0;
                            torrent.tracker.retry_interval = Duration::from_secs(60);
                            if let Some(interval) = result.interval {
                                torrent.tracker.interval = Duration::from_secs(interval as u64);
                            }
                            torrent.tracker.next_announce = Some(now + torrent.tracker.interval);
                            torrent.tracker.peers = result.peers.clone();
                            torrent.peer_manager.add_peers(&result.peers);

                            log_lines.push(format!(
                                "Magnet announce for {}: {} peers",
                                &result.infohash_hex[..8],
                                result.peers.len()
                            ));
                        } else {
                            torrent.tracker.consecutive_failures = torrent.tracker.consecutive_failures.saturating_add(1);
                            if !torrent.trackers.is_empty() {
                                torrent.tracker.current_tracker_in_tier = (torrent.tracker.current_tracker_in_tier + 1) % torrent.trackers.len();
                            }

                            let max_retry = Duration::from_secs(1800);
                            let next_retry = torrent.tracker.retry_interval.min(max_retry);
                            torrent.tracker.next_announce = Some(now + next_retry);
                            torrent.tracker.retry_interval = (torrent.tracker.retry_interval * 2).min(max_retry);

                            if let Some(error) = &result.error {
                                log_lines.push(format!(
                                    "Magnet announce failed for {} (failures: {}, next retry in {}s): {}",
                                    &result.infohash_hex[..8],
                                    torrent.tracker.consecutive_failures,
                                    next_retry.as_secs(),
                                    error
                                ));
                            }
                        }
                    }
                }
            }
        }

        if let Some(dht) = self.dht.as_mut() {
            log_lines.extend(dht.tick());

            let dht_nodes = dht.known_nodes();
            for (infohash_hex, torrent) in self.torrents.iter_mut() {
                match torrent {
                    TorrentEntry::Active(t) => {
                        if t.paused {
                            continue;
                        }

                        if t.info.private {
                            continue;
                        }

                        let tracker_failing = t.tracker.consecutive_failures >= 2;
                        let needs_peers = t.stats.connected_peers < 10;
                        let use_dht = needs_peers || tracker_failing;

                        if use_dht && dht_nodes > 0 {
                            let should_query = match t.last_dht_query {
                                None => true,
                                Some(last) => now.duration_since(last) >= Duration::from_secs(5),
                            };

                            if should_query {
                                dht.announce_peer(*t.info.infohash.as_bytes());
                                t.last_dht_query = Some(now);
                                if tracker_failing {
                                    log_lines.push(format!(
                                        "DHT fallback for {}: tracker failed {} times",
                                        &infohash_hex[..8],
                                        t.tracker.consecutive_failures
                                    ));
                                }
                            }
                        }
                    }
                    TorrentEntry::Magnet(t) => {
                        if !t.paused && dht_nodes > 0 {
                            let tracker_failing = t.tracker.consecutive_failures >= 2;
                            let has_no_trackers = t.trackers.is_empty();
                            let interval_secs = if tracker_failing || has_no_trackers { 5 } else { 10 };

                            let should_query = match t.last_dht_query {
                                None => true,
                                Some(last) => now.duration_since(last) >= Duration::from_secs(interval_secs),
                            };

                            if should_query {
                                dht.announce_peer(t.info_hash);
                                t.last_dht_query = Some(now);
                                if tracker_failing {
                                    log_lines.push(format!(
                                        "DHT fallback for {}: tracker failed {} times",
                                        &infohash_hex[..8],
                                        t.tracker.consecutive_failures
                                    ));
                                } else if has_no_trackers {
                                    log_lines.push(format!(
                                        "DHT primary for {}: no trackers available",
                                        &infohash_hex[..8]
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            if let Some(socket) = self.dht_socket.as_ref() {
                for (addr, payload) in dht.take_pending_packets() {
                    let _ = socket.send_to(&payload, addr);
                }
            }
        }

        for (infohash, torrent) in self.torrents.iter_mut() {
            match torrent {
                TorrentEntry::Active(torrent) => {
                    if torrent.paused {
                        continue;
                    }

                    let should_announce = torrent
                        .tracker
                        .next_announce
                        .map(|next| now >= next)
                        .unwrap_or(false);

                    if should_announce && !self.pending_announces.contains(infohash) {
                        if let Some(announce_url) = Self::get_tracker_url(&torrent.info, &torrent.tracker) {
                            self.pending_announces.insert(infohash.clone());
                            let task = AnnounceTask {
                                infohash_hex: infohash.clone(),
                                url: announce_url,
                                info_hash: *torrent.info.infohash.as_bytes(),
                                peer_id,
                                port: listen_port,
                                uploaded: torrent.stats.uploaded,
                                downloaded: torrent.stats.downloaded,
                                left: torrent.info.total_length.saturating_sub(
                                    (torrent.stats.pieces_completed as u64) * torrent.info.piece_length,
                                ),
                                event: TrackerEvent::None,
                            };
                            self.announce_worker.submit_announce(task);
                        }
                    }

                    match torrent.peer_manager.tick(Some(&mut torrent.storage)) {
                        Ok(peer_stats) => {
                            torrent.stats.downloaded = peer_stats.downloaded;
                            torrent.stats.uploaded = peer_stats.uploaded;
                            torrent.stats.connected_peers = peer_stats.connected_peers;
                            torrent.stats.pieces_completed = peer_stats.pieces_completed;
                            torrent.stats.pieces_total = peer_stats.pieces_total;

                            if peer_stats.connected_peers > 0 || peer_stats.pieces_completed > 0 {
                                log_lines.push(format!(
                                    "{}: {} peers, {}/{} pieces",
                                    &infohash[..8],
                                    peer_stats.connected_peers,
                                    peer_stats.pieces_completed,
                                    peer_stats.pieces_total
                                ));
                            }
                        }
                        Err(e) => {
                            log_lines.push(format!(
                                "Peer manager error for {}: {}",
                                &infohash[..8],
                                e
                            ));
                        }
                    }
                }
                TorrentEntry::Magnet(torrent) => {
                    if torrent.paused {
                        continue;
                    }

                    let should_announce = torrent
                        .tracker
                        .next_announce
                        .map(|next| now >= next)
                        .unwrap_or(false);

                    if should_announce && !self.pending_announces.contains(infohash) {
                        if let Some(announce_url) = torrent.trackers.get(torrent.tracker.current_tracker_in_tier).cloned() {
                            self.pending_announces.insert(infohash.clone());
                            let task = AnnounceTask {
                                infohash_hex: infohash.clone(),
                                url: announce_url,
                                info_hash: torrent.info_hash,
                                peer_id,
                                port: listen_port,
                                uploaded: torrent.stats.uploaded,
                                downloaded: torrent.stats.downloaded,
                                left: 0,
                                event: TrackerEvent::None,
                            };
                            self.announce_worker.submit_announce(task);
                        }
                    }

                    match torrent.peer_manager.tick(None) {
                        Ok(peer_stats) => {
                            torrent.stats.downloaded = peer_stats.downloaded;
                            torrent.stats.uploaded = peer_stats.uploaded;
                            torrent.stats.connected_peers = peer_stats.connected_peers;
                            torrent.stats.pieces_completed = 0;
                            torrent.stats.pieces_total = 0;

                            if peer_stats.connected_peers > 0 {
                                log_lines.push(format!(
                                    "{}: {} peers, waiting for metadata",
                                    &infohash[..8],
                                    peer_stats.connected_peers
                                ));
                            }
                        }
                        Err(e) => {
                            log_lines.push(format!(
                                "Peer manager error for {}: {}",
                                &infohash[..8],
                                e
                            ));
                        }
                    }

                    if let Some(metadata) = torrent.peer_manager.take_metadata() {
                        match Self::promote_magnet(
                            metadata,
                            torrent,
                            self.download_dir.clone(),
                            self.peer_id,
                        ) {
                            Ok(active) => {
                                upgrades.push((infohash.clone(), active));
                                log_lines.push(format!(
                                    "{}: metadata received, starting torrent",
                                    &infohash[..8]
                                ));
                            }
                            Err(e) => {
                                log_lines.push(format!(
                                    "Magnet metadata parse failed for {}: {}",
                                    &infohash[..8],
                                    e
                                ));
                            }
                        }
                    }
                }
            }
        }

        for (infohash, state) in upgrades {
            let info_hash_bytes = *state.info.infohash.as_bytes();
            let piece_count = state.info.pieces.len();
            let is_private = state.info.private;

            if let Some(listener) = self.peer_listener.as_mut() {
                listener.register_infohash(info_hash_bytes, self.peer_id, piece_count);
            }

            if !is_private {
                if let Some(lsd) = self.lsd.as_mut() {
                    lsd.add_torrent(info_hash_bytes);
                }
            }

            self.torrents.insert(infohash, TorrentEntry::Active(state));
        }

        log_lines
    }

    pub fn dht_nodes(&self) -> u32 {
        self.dht.as_ref().map(|dht| dht.known_nodes()).unwrap_or(0)
    }

    fn promote_magnet(
        metadata: Vec<u8>,
        torrent: &MagnetState,
        download_dir: PathBuf,
        peer_id: [u8; 20],
    ) -> Result<ActiveTorrent> {
        let mut info = parse_info_dict(&metadata)?;
        if info.infohash.as_bytes() != &torrent.info_hash {
            anyhow::bail!("infohash mismatch after metadata download");
        }

        let (announce, announce_list) = Self::trackers_to_announce(&torrent.trackers);
        info.announce = announce;
        info.announce_list = announce_list;

        let storage = DiskStorage::new(&info, download_dir)?;

        let mut peer_manager = PeerManager::new(
            *info.infohash.as_bytes(),
            peer_id,
            info.pieces.len(),
            info.piece_length,
            info.total_length,
        );

        peer_manager.sync_completed_pieces(storage.bitfield());

        let stats = TorrentStats {
            pieces_total: info.pieces.len() as u32,
            ..Default::default()
        };

        let tracker = TrackerState {
            last_announce: None,
            next_announce: if info.announce.is_some() {
                Some(Instant::now())
            } else {
                None
            },
            interval: Duration::from_secs(1800),
            peers: Vec::new(),
            consecutive_failures: 0,
            current_tier: 0,
            current_tracker_in_tier: 0,
            retry_interval: Duration::from_secs(60),
        };

        Ok(ActiveTorrent {
            info,
            storage,
            paused: torrent.paused,
            tracker,
            peer_manager,
            stats,
            last_dht_query: torrent.last_dht_query,
        })
    }

    fn trackers_to_announce(trackers: &[String]) -> (Option<String>, Vec<Vec<String>>) {
        let announce = trackers.first().cloned();
        let mut announce_list = Vec::new();
        for tracker in trackers {
            announce_list.push(vec![tracker.clone()]);
        }
        (announce, announce_list)
    }

    fn get_tracker_url(info: &TorrentInfo, tracker_state: &TrackerState) -> Option<String> {
        if !info.announce_list.is_empty() {
            if let Some(tier) = info.announce_list.get(tracker_state.current_tier) {
                if let Some(url) = tier.get(tracker_state.current_tracker_in_tier) {
                    return Some(url.clone());
                }
            }
        }
        info.announce.clone()
    }

    fn advance_tracker_tier(tracker_state: &mut TrackerState, announce_list: &[Vec<String>]) {
        if announce_list.is_empty() {
            return;
        }

        let current_tier = &announce_list[tracker_state.current_tier];
        tracker_state.current_tracker_in_tier += 1;

        if tracker_state.current_tracker_in_tier >= current_tier.len() {
            tracker_state.current_tracker_in_tier = 0;
            tracker_state.current_tier += 1;

            if tracker_state.current_tier >= announce_list.len() {
                tracker_state.current_tier = 0;
            }
        }
    }

    pub fn get_session_stats(&self) -> SessionStats {
        let mut stats = SessionStats::default();

        for torrent in self.torrents.values() {
            match torrent {
                TorrentEntry::Active(state) => {
                    if !state.paused {
                        stats.active_torrents += 1;
                        stats.total_peers += state.stats.connected_peers;
                    }
                }
                TorrentEntry::Magnet(state) => {
                    if !state.paused {
                        stats.active_torrents += 1;
                        stats.total_peers += state.stats.connected_peers;
                    }
                }
            }
        }

        stats
    }

    pub fn get_torrent_stats(&self, infohash: &str) -> Option<&TorrentStats> {
        match self.torrents.get(infohash) {
            Some(TorrentEntry::Active(state)) => Some(&state.stats),
            Some(TorrentEntry::Magnet(state)) => Some(&state.stats),
            None => None,
        }
    }

    pub fn shutdown(&mut self) -> Result<()> {
        if let Some(listener) = self.peer_listener.as_mut() {
            listener.close();
        }

        if let Some(nat_pmp) = self.nat_pmp.as_mut() {
            let _ = nat_pmp.delete_all_mappings();
        }

        for (infohash, torrent) in self.torrents.iter_mut() {
            if let TorrentEntry::Active(state) = torrent {
                if let Err(e) = state.storage.close() {
                    eprintln!("Failed to close storage for {}: {}", infohash, e);
                }
            }
        }
        Ok(())
    }

    fn process_lsd(&mut self) -> Vec<String> {
        let mut log_lines = Vec::new();
        let Some(lsd) = self.lsd.as_mut() else {
            return log_lines;
        };

        if let Err(e) = lsd.tick() {
            eprintln!("LSD tick error: {}", e);
        }

        for (infohash_hex, torrent) in self.torrents.iter_mut() {
            let (info_hash, is_private) = match torrent {
                TorrentEntry::Active(t) => (*t.info.infohash.as_bytes(), t.info.private),
                TorrentEntry::Magnet(t) => (t.info_hash, false),
            };

            if is_private {
                continue;
            }

            let discovered = lsd.get_discovered_peers(&info_hash);
            if !discovered.is_empty() {
                match torrent {
                    TorrentEntry::Active(t) => t.peer_manager.add_peers(&discovered),
                    TorrentEntry::Magnet(t) => t.peer_manager.add_peers(&discovered),
                }

                log_lines.push(format!(
                    "LSD discovered {} peers for {}",
                    discovered.len(),
                    &infohash_hex[..8]
                ));

                lsd.clear_discovered_peers(&info_hash);
            }
        }

        log_lines
    }

    fn process_incoming_peers(&mut self) -> Vec<String> {
        let mut log_lines = Vec::new();
        let Some(listener) = self.peer_listener.as_mut() else {
            return log_lines;
        };

        let accepted = match listener.poll() {
            Ok(peers) => peers,
            Err(_) => return log_lines,
        };

        for accepted_peer in accepted {
            let infohash_hex = InfoHash(accepted_peer.info_hash).to_hex();

            let torrent = match self.torrents.get_mut(&infohash_hex) {
                Some(t) => t,
                None => continue,
            };

            let piece_count = match torrent {
                TorrentEntry::Active(t) => t.info.pieces.len(),
                TorrentEntry::Magnet(_) => 0,
            };

            #[cfg(target_os = "windows")]
            let connection = match PeerConnection::from_accepted(
                accepted_peer.socket,
                accepted_peer.addr,
                accepted_peer.info_hash,
                self.peer_id,
                accepted_peer.their_peer_id,
                piece_count,
                self.listen_port,
                accepted_peer.mse_handshake,
            ) {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            #[cfg(not(target_os = "windows"))]
            let connection = match PeerConnection::from_accepted(
                accepted_peer.stream,
                accepted_peer.addr,
                accepted_peer.info_hash,
                self.peer_id,
                accepted_peer.their_peer_id,
                piece_count,
                self.listen_port,
                accepted_peer.mse_handshake,
            ) {
                Ok(conn) => conn,
                Err(_) => continue,
            };

            let result = match torrent {
                TorrentEntry::Active(t) => {
                    t.peer_manager.accept_incoming(connection, accepted_peer.addr)
                }
                TorrentEntry::Magnet(t) => {
                    t.peer_manager.accept_incoming(connection, accepted_peer.addr)
                }
            };

            if result.is_ok() {
                log_lines.push(format!(
                    "Accepted incoming peer for {} from {}",
                    &infohash_hex[..8],
                    accepted_peer.addr
                ));
            }
        }

        log_lines
    }

    fn process_dht_incoming(&mut self) -> Vec<String> {
        let mut log_lines = Vec::new();
        let Some(socket) = self.dht_socket.as_ref() else {
            return log_lines;
        };
        let Some(dht) = self.dht.as_mut() else {
            return log_lines;
        };

        let mut buf = [0u8; 4096];
        let mut packets_processed = 0;
        const MAX_PACKETS_PER_TICK: usize = 100;
        let mut all_discovered_peers: HashMap<[u8; 20], Vec<SocketAddrV4>> = HashMap::new();

        loop {
            if packets_processed >= MAX_PACKETS_PER_TICK {
                break;
            }

            match socket.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    packets_processed += 1;
                    if let std::net::SocketAddr::V4(v4_addr) = addr {
                        if let Ok(outcome) = dht.handle_packet(v4_addr, &buf[..len]) {
                            if let Some(response_msg) = outcome.response {
                                use nimble_dht::rpc::encode_message;
                                let response_payload = encode_message(&response_msg);
                                let _ = socket.send_to(&response_payload, v4_addr);
                            }

                            for (peer_addr, info_hash) in outcome.discovered_peers {
                                all_discovered_peers
                                    .entry(info_hash)
                                    .or_insert_with(Vec::new)
                                    .push(peer_addr);
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        for (info_hash, peers) in all_discovered_peers {
            let infohash_hex = nimble_bencode::torrent::InfoHash(info_hash).to_hex();
            if let Some(torrent) = self.torrents.get_mut(&infohash_hex) {
                match torrent {
                    TorrentEntry::Active(torrent) => {
                        torrent.peer_manager.add_peers(&peers);
                        log_lines.push(format!(
                            "DHT peers for {}: {} peers",
                            &infohash_hex[..8],
                            peers.len()
                        ));
                    }
                    TorrentEntry::Magnet(torrent) => {
                        torrent.peer_manager.add_peers(&peers);
                        log_lines.push(format!(
                            "DHT peers for {}: {} peers",
                            &infohash_hex[..8],
                            peers.len()
                        ));
                    }
                }
            }
        }

        log_lines
    }
}

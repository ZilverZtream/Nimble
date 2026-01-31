use anyhow::Result;
use nimble_bencode::torrent::{parse_torrent, TorrentInfo};
use nimble_net::tracker_http::{announce, AnnounceRequest, TrackerEvent};
use nimble_storage::disk::DiskStorage;
use nimble_util::ids::peer_id_20;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Session {
    torrents: HashMap<String, TorrentState>,
    download_dir: PathBuf,
    peer_id: [u8; 20],
    listen_port: u16,
}

pub struct TorrentState {
    pub info: TorrentInfo,
    pub storage: DiskStorage,
    pub paused: bool,
    pub tracker: TrackerState,
}

pub struct TrackerState {
    pub last_announce: Option<Instant>,
    pub next_announce: Option<Instant>,
    pub interval: Duration,
    pub peers: Vec<SocketAddrV4>,
}

impl Session {
    pub fn new(download_dir: PathBuf, listen_port: u16) -> Self {
        Session {
            torrents: HashMap::new(),
            download_dir,
            peer_id: peer_id_20(),
            listen_port,
        }
    }

    pub fn add_torrent_file(&mut self, path: &str) -> Result<String> {
        let data = fs::read(path)?;
        let info = parse_torrent(&data)?;
        let infohash = info.infohash.to_hex();

        let storage = DiskStorage::new(&info, self.download_dir.clone())?;

        let tracker = TrackerState {
            last_announce: None,
            next_announce: Some(Instant::now()),
            interval: Duration::from_secs(1800),
            peers: Vec::new(),
        };

        let state = TorrentState {
            info,
            storage,
            paused: false,
            tracker,
        };

        self.torrents.insert(infohash.clone(), state);
        Ok(infohash)
    }

    pub fn pause_all(&mut self) {
        for torrent in self.torrents.values_mut() {
            torrent.paused = true;
        }
    }

    pub fn resume_all(&mut self) {
        for torrent in self.torrents.values_mut() {
            torrent.paused = false;
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

        for (infohash, torrent) in self.torrents.iter_mut() {
            if torrent.paused {
                continue;
            }

            let should_announce = torrent
                .tracker
                .next_announce
                .map(|next| now >= next)
                .unwrap_or(false);

            if should_announce {
                if let Some(announce_url) = torrent.info.announce.clone() {
                    match Self::announce_tracker(torrent, &announce_url, TrackerEvent::None, &peer_id, listen_port) {
                        Ok(peer_count) => {
                            log_lines.push(format!(
                                "Tracker announce for {}: {} peers",
                                infohash, peer_count
                            ));
                        }
                        Err(e) => {
                            log_lines.push(format!(
                                "Tracker announce failed for {}: {}",
                                infohash, e
                            ));
                        }
                    }
                }
            }
        }

        log_lines
    }

    fn announce_tracker(
        torrent: &mut TorrentState,
        url: &str,
        event: TrackerEvent,
        peer_id: &[u8; 20],
        listen_port: u16,
    ) -> Result<usize> {
        let request = AnnounceRequest {
            info_hash: torrent.info.infohash.as_bytes(),
            peer_id,
            port: listen_port,
            uploaded: 0,
            downloaded: 0,
            left: torrent.info.total_length,
            compact: true,
            event,
        };

        let response = announce(url, &request)?;

        if let Some(failure) = response.failure_reason {
            return Err(anyhow::anyhow!("Tracker failure: {}", failure));
        }

        torrent.tracker.last_announce = Some(Instant::now());
        torrent.tracker.interval = Duration::from_secs(response.interval as u64);
        torrent.tracker.next_announce = Some(Instant::now() + torrent.tracker.interval);
        torrent.tracker.peers = response.peers.clone();

        Ok(response.peers.len())
    }
}

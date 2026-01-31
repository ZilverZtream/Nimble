use anyhow::Result;
use nimble_bencode::torrent::{parse_torrent, TorrentInfo};
use std::collections::HashMap;
use std::fs;

pub struct Session {
    torrents: HashMap<String, TorrentState>,
}

pub struct TorrentState {
    pub info: TorrentInfo,
    pub paused: bool,
}

impl Session {
    pub fn new() -> Self {
        Session {
            torrents: HashMap::new(),
        }
    }

    pub fn add_torrent_file(&mut self, path: &str) -> Result<String> {
        let data = fs::read(path)?;
        let info = parse_torrent(&data)?;
        let infohash = info.infohash.to_hex();

        let state = TorrentState {
            info,
            paused: false,
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
}

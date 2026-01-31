use anyhow::Result;
use nimble_bencode::torrent::{parse_torrent, TorrentInfo};
use nimble_storage::disk::DiskStorage;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub struct Session {
    torrents: HashMap<String, TorrentState>,
    download_dir: PathBuf,
}

pub struct TorrentState {
    pub info: TorrentInfo,
    pub storage: DiskStorage,
    pub paused: bool,
}

impl Session {
    pub fn new(download_dir: PathBuf) -> Self {
        Session {
            torrents: HashMap::new(),
            download_dir,
        }
    }

    pub fn add_torrent_file(&mut self, path: &str) -> Result<String> {
        let data = fs::read(path)?;
        let info = parse_torrent(&data)?;
        let infohash = info.infohash.to_hex();

        let storage = DiskStorage::new(&info, self.download_dir.clone())?;

        let state = TorrentState {
            info,
            storage,
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

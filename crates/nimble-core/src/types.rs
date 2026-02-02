use std::sync::mpsc;

#[derive(Clone, Debug)]
pub enum Command {
    AddTorrentFile { path: String },
    AddMagnet { uri: String },
    PauseAll,
    ResumeAll,
    PauseTorrent { infohash: String },
    ResumeTorrent { infohash: String },
    RemoveTorrent { infohash: String },
    RemoveTorrentWithData { infohash: String },
    ForceRecheck { infohash: String },
    OpenFolder { infohash: String },
    CopyMagnetLink { infohash: String },
    GetTorrentList,
    Shutdown,
}

#[derive(Clone, Debug)]
pub enum Event {
    Started,
    Stopped,
    Stats(EngineStats),
    TorrentList(Vec<TorrentInfo>),
    MagnetLink(String),
    LogLine(String),
}

#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    pub active_torrents: u32,
    pub dl_rate_bps: u64,
    pub ul_rate_bps: u64,
    pub dht_nodes: u32,
}

#[derive(Clone, Debug)]
pub struct TorrentInfo {
    pub infohash: String,
    pub name: String,
    pub state: TorrentState,
    pub pieces_completed: u32,
    pub pieces_total: u32,
    pub downloaded: u64,
    pub uploaded: u64,
    pub connected_peers: u32,
    pub total_size: u64,
    pub trackers: Vec<String>,
    pub is_private: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TorrentState {
    Downloading,
    Seeding,
    Paused,
    FetchingMetadata,
    Error,
}

pub type CommandSender = mpsc::SyncSender<Command>;
pub type EventReceiver = mpsc::Receiver<Event>;

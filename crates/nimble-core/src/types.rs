use std::sync::mpsc;

#[derive(Clone, Debug)]
pub enum Command {
    AddTorrentFile { path: String },
    AddMagnet { uri: String },
    PauseAll,
    ResumeAll,
    Shutdown,
}

#[derive(Clone, Debug)]
pub enum Event {
    Started,
    Stopped,
    Stats(EngineStats),
    LogLine(String),
}

#[derive(Clone, Debug, Default)]
pub struct EngineStats {
    pub active_torrents: u32,
    pub dl_rate_bps: u64,
    pub ul_rate_bps: u64,
    pub dht_nodes: u32,
}

pub type CommandSender = mpsc::Sender<Command>;
pub type EventReceiver = mpsc::Receiver<Event>;

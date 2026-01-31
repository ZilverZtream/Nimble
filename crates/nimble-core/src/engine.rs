use anyhow::Result;
use std::sync::mpsc;
use std::thread;

use crate::settings::EngineSettings;
use crate::types::{Command, CommandSender, Event, EventReceiver, EngineStats};

#[derive(Clone)]
pub struct EngineHandle {
    pub tx: CommandSender,
}

pub fn start(_settings: EngineSettings) -> Result<(EngineHandle, EventReceiver)> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
    let (evt_tx, evt_rx) = mpsc::channel::<Event>();

    thread::spawn(move || {
        let _ = evt_tx.send(Event::Started);

        // Placeholder engine loop.
        // Future:
        // - session manager
        // - torrent lifecycle
        // - networking schedulers
        // - storage + resume
        let mut stats = EngineStats::default();

        loop {
            match cmd_rx.recv() {
                Ok(Command::Shutdown) | Err(_) => break,
                Ok(Command::PauseAll) => { /* TODO */ }
                Ok(Command::ResumeAll) => { /* TODO */ }
                Ok(Command::AddTorrentFile { .. }) => { stats.active_torrents += 1; }
                Ok(Command::AddMagnet { .. }) => { stats.active_torrents += 1; }
            }

            let _ = evt_tx.send(Event::Stats(stats.clone()));
        }

        let _ = evt_tx.send(Event::Stopped);
    });

    Ok((EngineHandle { tx: cmd_tx }, evt_rx))
}

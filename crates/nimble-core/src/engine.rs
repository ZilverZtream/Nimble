use anyhow::Result;
use std::sync::mpsc;
use std::thread;

use crate::session::Session;
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

        let mut session = Session::new();
        let mut stats = EngineStats::default();

        loop {
            match cmd_rx.recv() {
                Ok(Command::Shutdown) | Err(_) => break,

                Ok(Command::PauseAll) => {
                    session.pause_all();
                    let _ = evt_tx.send(Event::LogLine("Paused all torrents".to_string()));
                }

                Ok(Command::ResumeAll) => {
                    session.resume_all();
                    let _ = evt_tx.send(Event::LogLine("Resumed all torrents".to_string()));
                }

                Ok(Command::AddTorrentFile { path }) => {
                    match session.add_torrent_file(&path) {
                        Ok(infohash) => {
                            let msg = format!("Added torrent: {} ({})", path, infohash);
                            let _ = evt_tx.send(Event::LogLine(msg));
                        }
                        Err(e) => {
                            let msg = format!("Failed to add torrent {}: {}", path, e);
                            let _ = evt_tx.send(Event::LogLine(msg));
                        }
                    }
                }

                Ok(Command::AddMagnet { uri }) => {
                    let msg = format!("Magnet not yet implemented: {}", uri);
                    let _ = evt_tx.send(Event::LogLine(msg));
                }
            }

            stats.active_torrents = session.active_count();
            let _ = evt_tx.send(Event::Stats(stats.clone()));
        }

        let _ = evt_tx.send(Event::Stopped);
    });

    Ok((EngineHandle { tx: cmd_tx }, evt_rx))
}

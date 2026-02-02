use anyhow::Result;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::session::Session;
use crate::settings::EngineSettings;
use crate::types::{Command, CommandSender, EngineStats, Event, EventReceiver};

const TICK_INTERVAL_MS: u64 = 20;
const STATS_UPDATE_INTERVAL_MS: u64 = 1000;

#[derive(Clone)]
pub struct EngineHandle {
    pub tx: CommandSender,
}

pub fn start(settings: EngineSettings) -> Result<(EngineHandle, EventReceiver)> {
    let (cmd_tx, cmd_rx) = mpsc::channel::<Command>();
    let (evt_tx, evt_rx) = mpsc::channel::<Event>();

    thread::spawn(move || {
        let _ = evt_tx.send(Event::Started);

        let download_dir = PathBuf::from(&settings.download_dir);
        let mut session = Session::new(
            download_dir,
            settings.listen_port,
            settings.enable_dht,
            settings.enable_upnp,
            settings.enable_nat_pmp,
            settings.enable_lsd,
            settings.max_active_torrents,
        );
        let mut stats = EngineStats::default();

        let tick_interval = Duration::from_millis(TICK_INTERVAL_MS);
        let stats_interval = Duration::from_millis(STATS_UPDATE_INTERVAL_MS);
        let mut last_stats_update = Instant::now();

        loop {
            match cmd_rx.recv_timeout(tick_interval) {
                Ok(Command::Shutdown) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}

                Ok(Command::PauseAll) => {
                    session.pause_all();
                    let _ = evt_tx.send(Event::LogLine("Paused all torrents".to_string()));
                }

                Ok(Command::ResumeAll) => {
                    session.resume_all();
                    let _ = evt_tx.send(Event::LogLine("Resumed all torrents".to_string()));
                }

                Ok(Command::AddTorrentFile { path }) => match session.add_torrent_file(&path) {
                    Ok(infohash) => {
                        let msg = format!("Added torrent: {} ({})", path, infohash);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to add torrent {}: {}", path, e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::AddMagnet { uri }) => match session.add_magnet(&uri) {
                    Ok(infohash) => {
                        let msg = format!("Added magnet: {} ({})", uri, infohash);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to add magnet {}: {}", uri, e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },
            }

            for log_line in session.tick() {
                let _ = evt_tx.send(Event::LogLine(log_line));
            }

            if last_stats_update.elapsed() >= stats_interval {
                stats.active_torrents = session.active_count();
                stats.dht_nodes = session.dht_nodes();
                let _ = evt_tx.send(Event::Stats(stats.clone()));
                last_stats_update = Instant::now();
            }
        }

        if let Err(e) = session.shutdown() {
            let _ = evt_tx.send(Event::LogLine(format!("Shutdown error: {}", e)));
        }

        let _ = evt_tx.send(Event::Stopped);
    });

    Ok((EngineHandle { tx: cmd_tx }, evt_rx))
}

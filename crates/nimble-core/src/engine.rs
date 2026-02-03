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
const COMMAND_CHANNEL_SIZE: usize = 128;

#[cfg(windows)]
fn to_wide_null(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[derive(Clone)]
pub struct EngineHandle {
    pub tx: CommandSender,
}

pub fn start(settings: EngineSettings) -> Result<(EngineHandle, EventReceiver)> {
    let (cmd_tx, cmd_rx) = mpsc::sync_channel::<Command>(COMMAND_CHANNEL_SIZE);
    // Use unbounded channel for events to prevent engine thread blocking
    // if UI is slow to process events. This trades memory for guaranteed
    // forward progress in the core engine thread.
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
            settings.enable_ipv6,
            settings.enable_utp,
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

                Ok(Command::PauseTorrent { infohash }) => match session.pause_torrent(&infohash) {
                    Ok(_) => {
                        let msg = format!("Paused torrent: {}", &infohash[..8]);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to pause torrent {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::ResumeTorrent { infohash }) => match session.resume_torrent(&infohash) {
                    Ok(_) => {
                        let msg = format!("Resumed torrent: {}", &infohash[..8]);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to resume torrent {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::RemoveTorrent { infohash }) => match session.remove_torrent(&infohash, false) {
                    Ok(_) => {
                        let msg = format!("Removed torrent: {}", &infohash[..8]);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to remove torrent {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::RemoveTorrentWithData { infohash }) => match session.remove_torrent(&infohash, true) {
                    Ok(_) => {
                        let msg = format!("Removed torrent and data: {}", &infohash[..8]);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to remove torrent with data {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::ForceRecheck { infohash }) => match session.force_recheck(&infohash) {
                    Ok(_) => {
                        let msg = format!("Force recheck started: {}", &infohash[..8]);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to force recheck {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::OpenFolder { infohash }) => match session.get_torrent_folder(&infohash) {
                    Ok(path) => {
                        #[cfg(target_os = "windows")]
                        {
                            let evt_tx_clone = evt_tx.clone();
                            let infohash_clone = infohash.clone();
                            thread::spawn(move || {
                                use std::os::windows::ffi::OsStrExt;
                                use std::path::Path;

                                // Determine the directory to open
                                // If path is a file, use its parent directory. If it's a directory, use it directly.
                                let target_dir = Path::new(&path);
                                let folder_to_open = if target_dir.is_file() {
                                    // For single-file torrents, open the parent directory
                                    target_dir.parent().unwrap_or(target_dir)
                                } else {
                                    // For multi-file torrents, open the torrent directory itself
                                    target_dir
                                };

                                let path_wide: Vec<u16> = std::ffi::OsStr::new(folder_to_open)
                                    .encode_wide()
                                    .chain(std::iter::once(0))
                                    .collect();

                                unsafe {
                                    use windows_sys::Win32::UI::Shell::ShellExecuteW;
                                    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW;

                                    // Use "explore" verb instead of "open" to prevent executing files
                                    // "explore" always opens a folder view, never executes files
                                    let verb_wide = to_wide_null("explore");

                                    let result = ShellExecuteW(
                                        0,
                                        verb_wide.as_ptr(),
                                        path_wide.as_ptr(),
                                        std::ptr::null(),
                                        std::ptr::null(),
                                        SW_SHOW,
                                    );
                                    if result <= 32 {
                                        let msg = format!("Failed to open folder for {}", &infohash_clone[..8]);
                                        let _ = evt_tx_clone.send(Event::LogLine(msg));
                                    } else {
                                        let msg = format!("Opened folder for {}", &infohash_clone[..8]);
                                        let _ = evt_tx_clone.send(Event::LogLine(msg));
                                    }
                                }
                            });
                        }
                        #[cfg(not(target_os = "windows"))]
                        {
                            let msg = format!("Open folder not supported on this platform");
                            let _ = evt_tx.send(Event::LogLine(msg));
                        }
                    }
                    Err(e) => {
                        let msg = format!("Failed to get folder for {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::CopyMagnetLink { infohash }) => match session.get_magnet_link(&infohash) {
                    Ok(magnet) => {
                        let _ = evt_tx.send(Event::MagnetLink(magnet));
                        let msg = format!("Copied magnet link for {}", &infohash[..8]);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                    Err(e) => {
                        let msg = format!("Failed to get magnet link for {}: {}", &infohash[..8], e);
                        let _ = evt_tx.send(Event::LogLine(msg));
                    }
                },

                Ok(Command::GetTorrentList) => {
                    let torrent_list = session.get_torrent_list();
                    let _ = evt_tx.send(Event::TorrentList(torrent_list));
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

#[cfg(all(test, windows))]
mod tests {
    use super::to_wide_null;

    #[test]
    fn to_wide_null_appends_single_terminator() {
        let buf = to_wide_null("explore");
        assert_eq!(buf.last().copied(), Some(0));
        assert_eq!(buf.len(), "explore".encode_utf16().count() + 1);
    }
}

use nimble_bencode::torrent::parse_torrent;
use nimble_core::engine;
use nimble_core::settings::EngineSettings;
use nimble_core::types::{Command, Event};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn write_test_torrent(dir: &Path) -> (PathBuf, String) {
    let torrent = b"d8:announce21:http://example.com:804:infod6:lengthi1024e4:name8:test.txt12:piece lengthi262144e6:pieces20:\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13ee";

    let info = parse_torrent(torrent).expect("parse test torrent");
    let infohash = info.infohash.to_hex();

    let torrent_path = dir.join("test.torrent");
    fs::write(&torrent_path, torrent).expect("write test torrent");

    (torrent_path, infohash)
}

fn unique_temp_dir() -> PathBuf {
    let mut path = env::temp_dir();
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time works")
        .as_nanos();
    let pid = std::process::id();
    path.push(format!("nimble_test_{}_{}", pid, since_epoch));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[test]
fn add_torrent_workflow_emits_log_line() {
    let temp_dir = unique_temp_dir();
    let (torrent_path, infohash) = write_test_torrent(&temp_dir);

    let mut settings = EngineSettings::load_default().expect("default settings");
    settings.download_dir = temp_dir.to_string_lossy().to_string();

    let (handle, events) = engine::start(settings).expect("engine start");

    let started = events
        .recv_timeout(Duration::from_secs(2))
        .expect("engine started event");
    assert!(matches!(started, Event::Started));

    handle
        .tx
        .send(Command::AddTorrentFile {
            path: torrent_path.to_string_lossy().to_string(),
        })
        .expect("send add torrent command");

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_add = None;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(remaining) {
            Ok(Event::LogLine(line)) => {
                if line.contains("Added torrent") {
                    saw_add = Some(line);
                    break;
                }
            }
            Ok(_) => continue,
            Err(err) => panic!("timed out waiting for add torrent event: {:?}", err),
        }
    }

    let log_line = saw_add.expect("add torrent log line");
    assert!(log_line.contains(&infohash));

    handle.tx.send(Command::Shutdown).expect("shutdown");

    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(remaining) {
            Ok(Event::Stopped) => break,
            Ok(_) => continue,
            Err(err) => panic!("missing stopped event: {:?}", err),
        }
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

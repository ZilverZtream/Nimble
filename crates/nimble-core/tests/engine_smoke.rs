use nimble_core::engine;
use nimble_core::settings::EngineSettings;
use nimble_core::types::{Command, Event};
use std::time::{Duration, Instant};

#[test]
fn engine_starts_and_stops() {
    let mut settings = EngineSettings::load_default().expect("default settings");
    settings.download_dir = "Downloads".to_string();

    let (handle, events) = engine::start(settings).expect("engine start");

    let started = events
        .recv_timeout(Duration::from_secs(2))
        .expect("engine started event");
    assert!(matches!(started, Event::Started));

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
}

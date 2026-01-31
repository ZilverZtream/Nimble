// Tiny logger. No allocation-heavy formatting in hot paths.
// In release, compile-time level filtering can be used.

#[derive(Copy, Clone, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

pub fn log(_level: Level, _msg: &str) {
    // Placeholder: route to OutputDebugStringW or a ring buffer.
}

pub fn info(msg: &str) { log(Level::Info, msg); }
pub fn warn(msg: &str) { log(Level::Warn, msg); }
pub fn error(msg: &str) { log(Level::Error, msg); }
pub fn debug(msg: &str) { log(Level::Debug, msg); }

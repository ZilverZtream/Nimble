use anyhow::Result;
use nimble_core::{EngineHandle, EngineSettings, EventReceiver};

pub fn start_engine() -> Result<(EngineHandle, EventReceiver)> {
    let settings = EngineSettings::load_default()?;
    nimble_core::engine::start(settings)
}

use anyhow::Result;
use std::path::PathBuf;

pub fn init_runtime_dirs() -> Result<()> {
    // Placeholder: create config/resume dirs if needed.
    let _ = runtime_root_dir()?;
    Ok(())
}

pub fn runtime_root_dir() -> Result<PathBuf> {
    // Placeholder: portable mode detection:
    // - if nimble.toml exists beside exe => use that directory.
    // - else use %AppData%\Nimble
    Ok(std::env::current_dir()?)
}

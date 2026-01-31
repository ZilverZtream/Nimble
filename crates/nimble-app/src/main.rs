#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod tray;
mod ui_status;
mod ui_settings;

use anyhow::Result;

fn main() -> Result<()> {
    // Windows-only: explicit guard.
    #[cfg(not(windows))]
    {
        anyhow::bail!("Nimble is Windows-only for now.");
    }

    #[cfg(windows)]
    {
        config::init_runtime_dirs()?;
        let (engine, events) = app::start_engine()?;
        tray::run_tray_loop(engine, events)?;
        Ok(())
    }
}

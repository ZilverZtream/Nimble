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
        if let Err(e) = run_app() {
            show_error_dialog(&format!("Nimble failed to start:\n\n{}", e));
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(windows)]
fn run_app() -> Result<()> {
    config::init_runtime_dirs()?;
    let (engine, events) = app::start_engine()?;
    tray::run_tray_loop(engine, events)?;
    Ok(())
}

#[cfg(windows)]
fn show_error_dialog(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};

    let title: Vec<u16> = "Nimble Error".encode_utf16().chain(std::iter::once(0)).collect();
    let msg: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        MessageBoxW(0, msg.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

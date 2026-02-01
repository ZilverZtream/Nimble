use anyhow::Result;
use crate::ui_status;
use nimble_core::{EngineHandle, EventReceiver};
use nimble_util::log;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    UI::Shell::*,
    UI::WindowsAndMessaging::*,
    System::LibraryLoader::*,
    UI::Controls::Dialogs::*,
};

#[cfg(windows)]
const WM_APP: u32 = 0x8000;

#[cfg(windows)]
const WM_TRAYICON: u32 = WM_APP + 1;
#[cfg(windows)]
const TRAY_UID: u32 = 1;

#[cfg(windows)]
const GWLP_USERDATA: i32 = -21;

pub fn run_tray_loop(engine: EngineHandle, _events: EventReceiver) -> Result<()> {
    #[cfg(not(windows))]
    {
        anyhow::bail!("Windows-only.");
    }

    #[cfg(windows)]
    unsafe {
        let hinstance = GetModuleHandleW(std::ptr::null());
        if hinstance == 0 {
            anyhow::bail!("GetModuleHandleW failed");
        }

        let class_name = widestr("NimbleTrayWindowClass");
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: 0,
            hCursor: 0,
            hbrBackground: 0,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };

        if RegisterClassW(&wc) == 0 {
            anyhow::bail!("RegisterClassW failed");
        }

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            widestr("Nimble").as_ptr(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            hinstance,
            std::ptr::null_mut(),
        );

        if hwnd == 0 {
            anyhow::bail!("CreateWindowExW failed");
        }

        // Store engine handle in window user data
        let engine_ptr = Box::into_raw(Box::new(engine));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, engine_ptr as isize);

        add_tray_icon(hwnd)?;

        log::info("Nimble tray started.");

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        remove_tray_icon(hwnd);

        // Clean up engine handle
        let engine_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut EngineHandle;
        if !engine_ptr.is_null() {
            let _ = Box::from_raw(engine_ptr);
        }

        Ok(())
    }
}

#[cfg(windows)]
unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            if lparam as u32 == WM_RBUTTONUP {
                show_tray_menu(hwnd);
                return 0;
            }
            0
        }
        WM_COMMAND => {
            let cmd_id = (wparam & 0xffff) as u16;
            match cmd_id {
                1001 => { handle_add_torrent_file(hwnd); }
                1002 => { handle_add_magnet(hwnd); }
                1003 => { handle_open_downloads(hwnd); }
                1004 => { handle_status_window(hwnd); }
                1005 => { handle_pause_all(hwnd); }
                1006 => { handle_resume_all(hwnd); }
                1007 => { handle_settings(hwnd); }
                1099 => { handle_quit(hwnd); }
                _ => {}
            }
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(windows)]
unsafe fn add_tray_icon(hwnd: HWND) -> Result<()> {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;

    // Tooltip
    let tip = widestr("Nimble");
    // Copy into fixed buffer
    let dst = nid.szTip.as_mut_ptr();
    let src = tip.as_ptr();
    // szTip is 128 wide chars in NOTIFYICONDATAW
    for i in 0..128 {
        *dst.add(i) = *src.add(i);
        if *src.add(i) == 0 {
            break;
        }
    }

    if Shell_NotifyIconW(NIM_ADD, &mut nid) == 0 {
        anyhow::bail!("Shell_NotifyIconW(NIM_ADD) failed");
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    let _ = Shell_NotifyIconW(NIM_DELETE, &mut nid);
}

#[cfg(windows)]
unsafe fn show_tray_menu(hwnd: HWND) {
    let hmenu = CreatePopupMenu();
    if hmenu == 0 { return; }

    let _ = AppendMenuW(hmenu, MF_STRING, 1001, widestr("Add Torrent File...").as_ptr());
    let _ = AppendMenuW(hmenu, MF_STRING, 1002, widestr("Add Magnet Link...").as_ptr());
    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    let _ = AppendMenuW(hmenu, MF_STRING, 1003, widestr("Open Downloads Folder").as_ptr());
    let _ = AppendMenuW(hmenu, MF_STRING, 1004, widestr("Status Window...").as_ptr());
    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    let _ = AppendMenuW(hmenu, MF_STRING, 1005, widestr("Pause All").as_ptr());
    let _ = AppendMenuW(hmenu, MF_STRING, 1006, widestr("Resume All").as_ptr());
    let _ = AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    let _ = AppendMenuW(hmenu, MF_STRING, 1007, widestr("Settings...").as_ptr());
    let _ = AppendMenuW(hmenu, MF_STRING, 1099, widestr("Quit").as_ptr());

    let mut pt: POINT = std::mem::zeroed();
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);

    let _ = TrackPopupMenu(hmenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, std::ptr::null());
    DestroyMenu(hmenu);
}

#[cfg(windows)]
unsafe fn get_engine(hwnd: HWND) -> Option<&'static EngineHandle> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut EngineHandle;
    if ptr.is_null() {
        None
    } else {
        Some(&*ptr)
    }
}

#[cfg(windows)]
unsafe fn handle_add_torrent_file(hwnd: HWND) {
    use nimble_core::types::Command;

    let mut ofn: OPENFILENAMEW = std::mem::zeroed();
    let mut filename_buf = vec![0u16; 260];

    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = filename_buf.as_mut_ptr();
    ofn.nMaxFile = 260;
    ofn.lpstrFilter = widestr("Torrent Files\0*.torrent\0All Files\0*.*\0").as_ptr();
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if GetOpenFileNameW(&mut ofn) != 0 {
        let len = filename_buf.iter().position(|&c| c == 0).unwrap_or(filename_buf.len());
        let path = String::from_utf16_lossy(&filename_buf[..len]);

        if let Some(engine) = get_engine(hwnd) {
            let _ = engine.tx.send(Command::AddTorrentFile { path });
        }
    }
}

#[cfg(windows)]
unsafe fn handle_add_magnet(hwnd: HWND) {
    use nimble_core::types::Command;
    use windows_sys::Win32::System::DataExchange::{OpenClipboard, GetClipboardData, CloseClipboard};
    use windows_sys::Win32::System::Memory::GlobalLock;

    const CF_UNICODETEXT: u32 = 13;
    const MB_OKCANCEL: u32 = 1;
    const MB_ICONINFORMATION: u32 = 64;
    const IDOK: i32 = 1;

    let message = widestr("Please copy the magnet link to your clipboard, then click OK.");
    let title = widestr("Add Magnet Link");

    let result = MessageBoxW(hwnd, message.as_ptr(), title.as_ptr(), MB_OKCANCEL | MB_ICONINFORMATION);

    if result == IDOK {
        if OpenClipboard(hwnd) != 0 {
            let h_data = GetClipboardData(CF_UNICODETEXT);
            if h_data != 0 {
                let p_data = GlobalLock(h_data) as *const u16;
                if !p_data.is_null() {
                    let mut len = 0;
                    while *p_data.add(len) != 0 && len < 8192 {
                        len += 1;
                    }

                    let uri_slice = std::slice::from_raw_parts(p_data, len);
                    let uri = String::from_utf16_lossy(uri_slice);

                    if uri.starts_with("magnet:") {
                        if let Some(engine) = get_engine(hwnd) {
                            let _ = engine.tx.send(Command::AddMagnet { uri });
                            log::info("Added magnet link from clipboard");
                        }
                    } else {
                        log::info("Clipboard does not contain a valid magnet link");
                    }

                    windows_sys::Win32::System::Memory::GlobalUnlock(h_data);
                }
            }
            CloseClipboard();
        } else {
            log::info("Failed to open clipboard");
        }
    }
}

#[cfg(windows)]
unsafe fn handle_open_downloads(_hwnd: HWND) {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let settings = match nimble_core::settings::EngineSettings::load_default() {
        Ok(s) => s,
        Err(e) => {
            log::info(&format!("Failed to load settings: {}", e));
            return;
        }
    };

    let download_dir = std::path::PathBuf::from(&settings.download_dir);
    let absolute_path = if download_dir.is_absolute() {
        download_dir
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(download_dir),
            Err(_) => {
                log::info("Failed to get current directory");
                return;
            }
        }
    };

    if !absolute_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&absolute_path) {
            log::info(&format!("Failed to create downloads directory: {}", e));
            return;
        }
    }

    let path_wide = widestr(&absolute_path.to_string_lossy());
    let result = ShellExecuteW(
        0,
        widestr("open").as_ptr(),
        path_wide.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        SW_SHOWNORMAL,
    );

    if result <= 32 {
        log::info(&format!("Failed to open downloads folder, error code: {}", result));
    }
}

#[cfg(windows)]
unsafe fn handle_status_window(hwnd: HWND) {
    if let Err(err) = ui_status::open_status_window(hwnd) {
        log::info(&format!("Status window failed: {err:?}"));
    }
}

#[cfg(windows)]
unsafe fn handle_pause_all(hwnd: HWND) {
    use nimble_core::types::Command;

    if let Some(engine) = get_engine(hwnd) {
        let _ = engine.tx.send(Command::PauseAll);
    }
}

#[cfg(windows)]
unsafe fn handle_resume_all(hwnd: HWND) {
    use nimble_core::types::Command;

    if let Some(engine) = get_engine(hwnd) {
        let _ = engine.tx.send(Command::ResumeAll);
    }
}

#[cfg(windows)]
unsafe fn handle_settings(hwnd: HWND) {
    let settings = match nimble_core::settings::EngineSettings::load_default() {
        Ok(s) => s,
        Err(e) => {
            log::info(&format!("Failed to load settings: {}", e));
            return;
        }
    };

    let settings_text = format!(
        "Current Settings:\n\n\
        Download Directory: {}\n\
        Listen Port: {}\n\n\
        DHT: {}\n\
        PEX: {}\n\
        LSD: {}\n\
        UPnP: {}\n\
        NAT-PMP: {}\n\
        IPv6: {}\n\
        µTP: {}\n\n\
        Max Connections (Global): {}\n\
        Max Connections (Per Torrent): {}\n\
        Max Active Torrents: {}\n\n\
        Download Limit: {} KiB/s\n\
        Upload Limit: {} KiB/s\n\n\
        Cache Size: {} MB\n\
        Write Behind: {}\n\
        Preallocate: {}",
        settings.download_dir,
        settings.listen_port,
        if settings.enable_dht { "Enabled" } else { "Disabled" },
        if settings.enable_pex { "Enabled" } else { "Disabled" },
        if settings.enable_lsd { "Enabled" } else { "Disabled" },
        if settings.enable_upnp { "Enabled" } else { "Disabled" },
        if settings.enable_nat_pmp { "Enabled" } else { "Disabled" },
        if settings.enable_ipv6 { "Enabled" } else { "Disabled" },
        if settings.enable_utp { "Enabled" } else { "Disabled" },
        settings.max_connections_global,
        settings.max_connections_per_torrent,
        settings.max_active_torrents,
        if settings.dl_limit_kib == 0 { "Unlimited".to_string() } else { settings.dl_limit_kib.to_string() },
        if settings.ul_limit_kib == 0 { "Unlimited".to_string() } else { settings.ul_limit_kib.to_string() },
        settings.cache_mb,
        if settings.write_behind { "Enabled" } else { "Disabled" },
        if settings.preallocate { "Enabled" } else { "Disabled" },
    );

    const MB_OK: u32 = 0;
    const MB_ICONINFORMATION: u32 = 64;

    MessageBoxW(
        hwnd,
        widestr(&settings_text).as_ptr(),
        widestr("Nimble Settings").as_ptr(),
        MB_OK | MB_ICONINFORMATION,
    );
}

#[cfg(windows)]
unsafe fn handle_quit(hwnd: HWND) {
    use nimble_core::types::Command;

    if let Some(engine) = get_engine(hwnd) {
        let _ = engine.tx.send(Command::Shutdown);
    }
    PostQuitMessage(0);
}

#[cfg(windows)]
fn widestr(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

use anyhow::Result;
use crate::ui_status;
use nimble_core::types::{EngineStats, Event};
use nimble_core::{EngineHandle, EventReceiver};
use nimble_util::log;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Mutex;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    Graphics::Gdi::*,
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
const WM_ENGINE_EVENT: u32 = WM_APP + 2;
#[cfg(windows)]
const TRAY_UID: u32 = 1;

#[cfg(windows)]
const GWLP_USERDATA: i32 = -21;

#[cfg(windows)]
static TRAY_HWND: AtomicIsize = AtomicIsize::new(0);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrayState {
    Idle,
    Active,
    Paused,
    Error,
}

#[cfg(windows)]
struct TrayIcons {
    idle: HICON,
    active: HICON,
    paused: HICON,
    error: HICON,
}

#[cfg(windows)]
static mut ICONS: Option<TrayIcons> = None;

#[cfg(windows)]
struct TrayData {
    state: TrayState,
    stats: EngineStats,
    is_paused: bool,
}

#[cfg(windows)]
static TRAY_DATA: Mutex<TrayData> = Mutex::new(TrayData {
    state: TrayState::Idle,
    stats: EngineStats {
        active_torrents: 0,
        dl_rate_bps: 0,
        ul_rate_bps: 0,
        dht_nodes: 0,
    },
    is_paused: false,
});

#[cfg(windows)]
unsafe fn create_tray_icons() -> TrayIcons {
    TrayIcons {
        idle: create_colored_icon(0x80, 0x80, 0x80),    // Gray
        active: create_colored_icon(0x00, 0xC8, 0x50),  // Green
        paused: create_colored_icon(0xFF, 0xA5, 0x00),  // Orange
        error: create_colored_icon(0xE0, 0x40, 0x40),   // Red
    }
}

#[cfg(windows)]
unsafe fn create_colored_icon(r: u8, g: u8, b: u8) -> HICON {
    const SIZE: i32 = 16;
    const PIXELS: usize = (SIZE * SIZE) as usize;

    let hdc_screen = GetDC(0);
    let hdc_mem = CreateCompatibleDC(hdc_screen);
    let hbm_color = CreateCompatibleBitmap(hdc_screen, SIZE, SIZE);
    let old_bm = SelectObject(hdc_mem, hbm_color);

    let brush_bg = CreateSolidBrush(RGB(0, 0, 0));
    let rect = RECT { left: 0, top: 0, right: SIZE, bottom: SIZE };
    FillRect(hdc_mem, &rect, brush_bg);
    DeleteObject(brush_bg);

    let brush_fg = CreateSolidBrush(RGB(r, g, b));
    let ellipse_rect = RECT { left: 2, top: 2, right: SIZE - 2, bottom: SIZE - 2 };
    SelectObject(hdc_mem, brush_fg);
    let null_pen = GetStockObject(NULL_PEN);
    SelectObject(hdc_mem, null_pen);
    Ellipse(hdc_mem, ellipse_rect.left, ellipse_rect.top, ellipse_rect.right, ellipse_rect.bottom);
    DeleteObject(brush_fg);

    SelectObject(hdc_mem, old_bm);
    DeleteDC(hdc_mem);
    ReleaseDC(0, hdc_screen);

    let mut mask_bits = [0xFFu8; PIXELS / 8];
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x - SIZE / 2;
            let dy = y - SIZE / 2;
            if dx * dx + dy * dy <= (SIZE / 2 - 2) * (SIZE / 2 - 2) {
                let bit_idx = (y * SIZE + x) as usize;
                let byte_idx = bit_idx / 8;
                let bit_off = 7 - (bit_idx % 8);
                mask_bits[byte_idx] &= !(1 << bit_off);
            }
        }
    }
    let hbm_mask = CreateBitmap(SIZE, SIZE, 1, 1, mask_bits.as_ptr() as *const _);

    let icon_info = ICONINFO {
        fIcon: TRUE,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: hbm_mask,
        hbmColor: hbm_color,
    };
    let hicon = CreateIconIndirect(&icon_info);

    DeleteObject(hbm_mask);
    DeleteObject(hbm_color);

    hicon
}

#[cfg(windows)]
const fn RGB(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

#[cfg(windows)]
unsafe fn destroy_tray_icons(icons: &TrayIcons) {
    DestroyIcon(icons.idle);
    DestroyIcon(icons.active);
    DestroyIcon(icons.paused);
    DestroyIcon(icons.error);
}

#[cfg(windows)]
unsafe fn get_icon_for_state(state: TrayState) -> HICON {
    match &ICONS {
        Some(icons) => match state {
            TrayState::Idle => icons.idle,
            TrayState::Active => icons.active,
            TrayState::Paused => icons.paused,
            TrayState::Error => icons.error,
        },
        None => 0,
    }
}

pub fn run_tray_loop(engine: EngineHandle, events: EventReceiver) -> Result<()> {
    #[cfg(not(windows))]
    {
        let _ = (engine, events);
        anyhow::bail!("Windows-only.");
    }

    #[cfg(windows)]
    unsafe {
        ICONS = Some(create_tray_icons());

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

        TRAY_HWND.store(hwnd, Ordering::SeqCst);

        let engine_ptr = Box::into_raw(Box::new(engine));
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, engine_ptr as isize);

        add_tray_icon(hwnd)?;

        std::thread::spawn(move || {
            event_listener_thread(events);
        });

        log::info("Nimble tray started.");

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        remove_tray_icon(hwnd);

        let engine_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut EngineHandle;
        if !engine_ptr.is_null() {
            let _ = Box::from_raw(engine_ptr);
        }

        if let Some(ref icons) = ICONS {
            destroy_tray_icons(icons);
        }
        ICONS = None;

        Ok(())
    }
}

#[cfg(windows)]
fn event_listener_thread(events: EventReceiver) {
    use std::time::Duration;

    loop {
        match events.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                let hwnd = TRAY_HWND.load(Ordering::SeqCst);
                if hwnd == 0 {
                    break;
                }
                unsafe {
                    match event {
                        Event::Stats(stats) => {
                            {
                                match TRAY_DATA.lock() {
                                    Ok(mut data) => {
                                        data.stats = stats.clone();
                                        let new_state = if data.is_paused {
                                            TrayState::Paused
                                        } else if stats.active_torrents > 0 {
                                            TrayState::Active
                                        } else {
                                            TrayState::Idle
                                        };
                                        if new_state != data.state {
                                            data.state = new_state;
                                        }
                                    }
                                    Err(e) => {
                                        log::info(&format!("Tray mutex poisoned (stats): {}", e));
                                        continue;
                                    }
                                }
                            }
                            PostMessageW(hwnd, WM_ENGINE_EVENT, 0, 0);
                        }
                        Event::TorrentList(torrents) => {
                            ui_status::update_torrents_from_event(torrents);
                        }
                        Event::MagnetLink(magnet) => {
                            copy_to_clipboard(&magnet);
                        }
                        Event::Started => {
                            log::info("Engine started event received");
                        }
                        Event::Stopped => {
                            break;
                        }
                        Event::LogLine(_) => {}
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let hwnd = TRAY_HWND.load(Ordering::SeqCst);
                if hwnd == 0 {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
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
        WM_ENGINE_EVENT => {
            update_tray_icon_and_tooltip(hwnd);
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
            TRAY_HWND.store(0, Ordering::SeqCst);
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
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = get_icon_for_state(TrayState::Idle);

    let tip = widestr("Nimble - Idle");
    copy_tooltip(&mut nid.szTip, &tip);

    if Shell_NotifyIconW(NIM_ADD, &mut nid) == 0 {
        anyhow::bail!("Shell_NotifyIconW(NIM_ADD) failed");
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn copy_tooltip(dst: &mut [u16; 128], src: &[u16]) {
    let len = src.len().min(127);
    for i in 0..len {
        dst[i] = src[i];
    }
    dst[len] = 0;
}

#[cfg(windows)]
unsafe fn update_tray_icon_and_tooltip(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_ICON | NIF_TIP;

    let (state, stats) = {
        match TRAY_DATA.lock() {
            Ok(data) => (data.state, data.stats.clone()),
            Err(_) => return,
        }
    };

    nid.hIcon = get_icon_for_state(state);
    let tooltip = format_tooltip(&stats, state);
    let tip_wide = widestr(&tooltip);
    copy_tooltip(&mut nid.szTip, &tip_wide);

    Shell_NotifyIconW(NIM_MODIFY, &mut nid);
}

#[cfg(windows)]
fn format_tooltip(stats: &EngineStats, state: TrayState) -> String {
    let state_str = match state {
        TrayState::Idle => "Idle",
        TrayState::Active => "Active",
        TrayState::Paused => "Paused",
        TrayState::Error => "Error",
    };

    let dl_rate = format_speed(stats.dl_rate_bps);
    let ul_rate = format_speed(stats.ul_rate_bps);

    if stats.active_torrents > 0 || stats.dl_rate_bps > 0 || stats.ul_rate_bps > 0 {
        format!(
            "Nimble - {}\nD: {} | U: {}\n{} torrent(s) | {} DHT",
            state_str, dl_rate, ul_rate, stats.active_torrents, stats.dht_nodes
        )
    } else {
        format!("Nimble - {}", state_str)
    }
}

#[cfg(windows)]
fn format_speed(bps: u64) -> String {
    if bps == 0 {
        "0 B/s".to_string()
    } else if bps < 1024 {
        format!("{} B/s", bps)
    } else if bps < 1024 * 1024 {
        format!("{:.1} KB/s", bps as f64 / 1024.0)
    } else {
        format!("{:.2} MB/s", bps as f64 / (1024.0 * 1024.0))
    }
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
    let engine_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const EngineHandle;
    if engine_ptr.is_null() {
        log::info("Engine handle not found");
        return;
    }
    let engine = (*engine_ptr).clone();
    if let Err(err) = ui_status::open_status_window(hwnd, engine) {
        log::info(&format!("Status window failed: {err:?}"));
    }
}

#[cfg(windows)]
unsafe fn handle_pause_all(hwnd: HWND) {
    use nimble_core::types::Command;

    {
        if let Ok(mut data) = TRAY_DATA.lock() {
            data.is_paused = true;
            data.state = TrayState::Paused;
        }
    }
    update_tray_icon_and_tooltip(hwnd);

    if let Some(engine) = get_engine(hwnd) {
        let _ = engine.tx.send(Command::PauseAll);
    }
}

#[cfg(windows)]
unsafe fn handle_resume_all(hwnd: HWND) {
    use nimble_core::types::Command;

    {
        if let Ok(mut data) = TRAY_DATA.lock() {
            data.is_paused = false;
            let new_state = if data.stats.active_torrents > 0 {
                TrayState::Active
            } else {
                TrayState::Idle
            };
            data.state = new_state;
        }
    }
    update_tray_icon_and_tooltip(hwnd);

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
unsafe fn copy_to_clipboard(text: &str) {
    use windows_sys::Win32::System::DataExchange::{OpenClipboard, CloseClipboard, EmptyClipboard, SetClipboardData};
    use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    use std::ptr::copy_nonoverlapping;

    const CF_UNICODETEXT: u32 = 13;

    if OpenClipboard(0) == 0 {
        return;
    }

    EmptyClipboard();

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let size = wide.len() * 2;

    let hglob = GlobalAlloc(GMEM_MOVEABLE, size);
    if hglob == 0 {
        CloseClipboard();
        return;
    }

    let locked = GlobalLock(hglob);
    if locked.is_null() {
        CloseClipboard();
        return;
    }

    copy_nonoverlapping(wide.as_ptr(), locked as *mut u16, wide.len());
    GlobalUnlock(hglob);

    SetClipboardData(CF_UNICODETEXT, hglob as isize);
    CloseClipboard();
}

#[cfg(windows)]
fn widestr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

use anyhow::Result;
use nimble_core::{EngineHandle, EventReceiver};
use nimble_util::log;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    UI::Shell::*,
    UI::WindowsAndMessaging::*,
    System::LibraryLoader::*,
};

#[cfg(windows)]
const WM_APP: u32 = 0x8000;

// NOTE:
// This is a minimal placeholder tray loop. It establishes a hidden window
// and registers a tray icon. Menu actions are wired but most commands are stubs.

#[cfg(windows)]
const WM_TRAYICON: u32 = WM_APP + 1;
#[cfg(windows)]
const TRAY_UID: u32 = 1;

pub fn run_tray_loop(_engine: EngineHandle, _events: EventReceiver) -> Result<()> {
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

        add_tray_icon(hwnd)?;

        log::info("Nimble tray started.");

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, 0, 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        remove_tray_icon(hwnd);
        Ok(())
    }
}

#[cfg(windows)]
unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            // Placeholder: right-click opens menu.
            if lparam as u32 == WM_RBUTTONUP {
                show_tray_menu(hwnd);
                return 0;
            }
            0
        }
        WM_COMMAND => {
            // Placeholder: handle menu selections.
            let cmd_id = (wparam & 0xffff) as u16;
            match cmd_id {
                1001 => { /* Add Torrent File... */ }
                1002 => { /* Add Magnet Link... */ }
                1003 => { /* Open Downloads Folder */ }
                1004 => { /* Status Window... */ }
                1005 => { /* Pause All */ }
                1006 => { /* Resume All */ }
                1007 => { /* Settings... */ }
                1099 => { PostQuitMessage(0); }
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
fn widestr(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

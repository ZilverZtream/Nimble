use anyhow::Result;
use nimble_core::types::{Command, TorrentInfo, TorrentState};
use nimble_core::EngineHandle;
use std::collections::HashMap;
use std::sync::Once;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    System::LibraryLoader::*,
    UI::WindowsAndMessaging::*,
    UI::Controls::*,
};

#[cfg(windows)]
const STATUS_CLASS_NAME: &str = "NimbleStatusWindowClass";
#[cfg(windows)]
const STATUS_WINDOW_TITLE: &str = "Nimble Status";

#[cfg(windows)]
const IDC_LISTVIEW: usize = 1001;
#[cfg(windows)]
const IDM_PAUSE: usize = 2001;
#[cfg(windows)]
const IDM_RESUME: usize = 2002;
#[cfg(windows)]
const IDM_REMOVE: usize = 2003;
#[cfg(windows)]
const IDM_REMOVE_DATA: usize = 2004;
#[cfg(windows)]
const IDM_RECHECK: usize = 2005;
#[cfg(windows)]
const IDM_OPEN_FOLDER: usize = 2006;
#[cfg(windows)]
const IDM_COPY_MAGNET: usize = 2007;

#[cfg(windows)]
const WM_UPDATE_LIST: u32 = WM_USER + 1;
#[cfg(windows)]
const UPDATE_TIMER_ID: usize = 100;
#[cfg(windows)]
const UPDATE_INTERVAL_MS: u32 = 500;

#[cfg(windows)]
static REGISTER_CLASS: Once = Once::new();
#[cfg(windows)]
static STATUS_HWND: AtomicIsize = AtomicIsize::new(0);

#[cfg(windows)]
struct StatusWindowData {
    listview: HWND,
    engine: EngineHandle,
    torrents: HashMap<String, TorrentInfo>,
    selected_infohash: Option<String>,
}

#[cfg(windows)]
type StatusWindowDataPtr = *mut StatusWindowData;

#[cfg(windows)]
pub fn open_status_window(owner: HWND, engine: EngineHandle) -> Result<()> {
    unsafe {
        let existing = STATUS_HWND.load(Ordering::SeqCst) as HWND;
        if existing != 0 && IsWindow(existing) != 0 {
            ShowWindow(existing, SW_SHOW);
            SetForegroundWindow(existing);
            return Ok(());
        }

        register_status_window_class()?;

        let hinstance = GetModuleHandleW(std::ptr::null());
        if hinstance == 0 {
            anyhow::bail!("GetModuleHandleW failed");
        }

        let hwnd = CreateWindowExW(
            0,
            widestr(STATUS_CLASS_NAME).as_ptr(),
            widestr(STATUS_WINDOW_TITLE).as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            800,
            500,
            owner,
            0,
            hinstance,
            std::ptr::null_mut(),
        );

        if hwnd == 0 {
            anyhow::bail!("CreateWindowExW failed");
        }

        let listview = CreateWindowExW(
            0,
            widestr("SysListView32").as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
            0,
            0,
            100,
            100,
            hwnd,
            IDC_LISTVIEW as HMENU,
            hinstance,
            std::ptr::null_mut(),
        );

        if listview == 0 {
            DestroyWindow(hwnd);
            anyhow::bail!("Failed to create ListView");
        }

        SendMessageW(listview, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT as LPARAM);

        setup_listview_columns(listview);

        let data = Box::new(StatusWindowData {
            listview,
            engine,
            torrents: HashMap::new(),
            selected_infohash: None,
        });

        SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(data) as isize);

        SetTimer(hwnd, UPDATE_TIMER_ID, UPDATE_INTERVAL_MS, None);

        STATUS_HWND.store(hwnd as isize, Ordering::SeqCst);

        PostMessageW(hwnd, WM_UPDATE_LIST, 0, 0);

        Ok(())
    }
}

#[cfg(windows)]
unsafe fn setup_listview_columns(listview: HWND) {
    let columns = [
        ("Name", 200),
        ("Status", 100),
        ("Progress", 80),
        ("Peers", 60),
        ("Down", 100),
        ("Up", 100),
        ("Size", 100),
    ];

    for (idx, (name, width)) in columns.iter().enumerate() {
        let name_wide = widestr(name);
        let mut lvc = LVCOLUMNW {
            mask: LVCF_TEXT | LVCF_WIDTH,
            fmt: LVCFMT_LEFT,
            cx: *width,
            pszText: name_wide.as_ptr() as *mut u16,
            cchTextMax: name_wide.len() as i32,
            iSubItem: idx as i32,
            iImage: 0,
            iOrder: 0,
        };
        SendMessageW(listview, LVM_INSERTCOLUMNW, idx, &lvc as *const _ as LPARAM);
    }
}

#[cfg(windows)]
unsafe fn update_torrent_list(data: &mut StatusWindowData) {
    let _ = data.engine.tx.send(Command::GetTorrentList);
}

#[cfg(windows)]
pub fn update_torrents_from_event(torrents: Vec<TorrentInfo>) {
    unsafe {
        let hwnd = STATUS_HWND.load(Ordering::SeqCst) as HWND;
        if hwnd == 0 || IsWindow(hwnd) == 0 {
            return;
        }

        let data_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as StatusWindowDataPtr;
        if data_ptr.is_null() {
            return;
        }

        let data = &mut *data_ptr;

        data.torrents.clear();
        for torrent in torrents {
            data.torrents.insert(torrent.infohash.clone(), torrent);
        }

        refresh_listview(data);
    }
}

#[cfg(windows)]
unsafe fn refresh_listview(data: &mut StatusWindowData) {
    let listview = data.listview;

    SendMessageW(listview, WM_SETREDRAW, 0, 0);

    let count = SendMessageW(listview, LVM_GETITEMCOUNT, 0, 0);
    for _ in 0..count {
        SendMessageW(listview, LVM_DELETEITEM, 0, 0);
    }

    let mut torrents: Vec<_> = data.torrents.values().collect();
    torrents.sort_by(|a, b| a.name.cmp(&b.name));

    for (idx, torrent) in torrents.iter().enumerate() {
        insert_torrent_item(listview, idx, torrent);
    }

    SendMessageW(listview, WM_SETREDRAW, 1, 0);
    InvalidateRect(listview, std::ptr::null(), TRUE);
}

#[cfg(windows)]
unsafe fn insert_torrent_item(listview: HWND, idx: usize, torrent: &TorrentInfo) {
    let name_wide = widestr(&torrent.name);
    let mut lvi = LVITEMW {
        mask: LVIF_TEXT,
        iItem: idx as i32,
        iSubItem: 0,
        state: 0,
        stateMask: 0,
        pszText: name_wide.as_ptr() as *mut u16,
        cchTextMax: name_wide.len() as i32,
        iImage: 0,
        lParam: 0,
        iIndent: 0,
        iGroupId: 0,
        cColumns: 0,
        puColumns: std::ptr::null_mut(),
        piColFmt: std::ptr::null_mut(),
        iGroup: 0,
    };
    SendMessageW(listview, LVM_INSERTITEMW, 0, &lvi as *const _ as LPARAM);

    let status_text = match torrent.state {
        TorrentState::Downloading => "Downloading",
        TorrentState::Seeding => "Seeding",
        TorrentState::Paused => "Paused",
        TorrentState::FetchingMetadata => "Fetching",
        TorrentState::Error => "Error",
    };
    set_subitem(listview, idx, 1, status_text);

    let progress = if torrent.pieces_total > 0 {
        (torrent.pieces_completed as f32 / torrent.pieces_total as f32) * 100.0
    } else {
        0.0
    };
    set_subitem(listview, idx, 2, &format!("{:.1}%", progress));

    set_subitem(listview, idx, 3, &torrent.connected_peers.to_string());

    set_subitem(listview, idx, 4, &format_bytes(torrent.downloaded));
    set_subitem(listview, idx, 5, &format_bytes(torrent.uploaded));
    set_subitem(listview, idx, 6, &format_bytes(torrent.total_size));
}

#[cfg(windows)]
unsafe fn set_subitem(listview: HWND, item: usize, subitem: usize, text: &str) {
    let text_wide = widestr(text);
    let mut lvi = LVITEMW {
        mask: LVIF_TEXT,
        iItem: item as i32,
        iSubItem: subitem as i32,
        state: 0,
        stateMask: 0,
        pszText: text_wide.as_ptr() as *mut u16,
        cchTextMax: text_wide.len() as i32,
        iImage: 0,
        lParam: 0,
        iIndent: 0,
        iGroupId: 0,
        cColumns: 0,
        puColumns: std::ptr::null_mut(),
        piColFmt: std::ptr::null_mut(),
        iGroup: 0,
    };
    SendMessageW(listview, LVM_SETITEMW, 0, &lvi as *const _ as LPARAM);
}

#[cfg(windows)]
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(windows)]
unsafe fn get_selected_infohash(data: &StatusWindowData) -> Option<String> {
    let listview = data.listview;
    let selected = SendMessageW(listview, LVM_GETNEXTITEM, -1isize as usize, LVNI_SELECTED);
    if selected < 0 {
        return None;
    }

    let mut torrents: Vec<_> = data.torrents.values().collect();
    torrents.sort_by(|a, b| a.name.cmp(&b.name));

    torrents.get(selected as usize).map(|t| t.infohash.clone())
}

#[cfg(windows)]
unsafe fn show_context_menu(hwnd: HWND, data: &mut StatusWindowData) {
    let infohash = match get_selected_infohash(data) {
        Some(h) => h,
        None => return,
    };

    data.selected_infohash = Some(infohash.clone());

    let torrent = match data.torrents.get(&infohash) {
        Some(t) => t,
        None => return,
    };

    let hmenu = CreatePopupMenu();
    if hmenu == 0 {
        return;
    }

    let pause_text = if torrent.state == TorrentState::Paused {
        "Resume"
    } else {
        "Pause"
    };
    let pause_id = if torrent.state == TorrentState::Paused {
        IDM_RESUME
    } else {
        IDM_PAUSE
    };

    AppendMenuW(hmenu, MF_STRING, pause_id, widestr(pause_text).as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(hmenu, MF_STRING, IDM_OPEN_FOLDER, widestr("Open Containing Folder").as_ptr());
    if !torrent.is_private {
        AppendMenuW(hmenu, MF_STRING, IDM_COPY_MAGNET, widestr("Copy Magnet Link").as_ptr());
    }
    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(hmenu, MF_STRING, IDM_RECHECK, widestr("Force Recheck").as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(hmenu, MF_STRING, IDM_REMOVE, widestr("Remove").as_ptr());
    AppendMenuW(hmenu, MF_STRING, IDM_REMOVE_DATA, widestr("Remove + Delete Data").as_ptr());

    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);

    TrackPopupMenu(hmenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, std::ptr::null());
    DestroyMenu(hmenu);
}

#[cfg(windows)]
unsafe fn handle_context_menu_command(data: &mut StatusWindowData, cmd_id: usize) {
    let infohash = match data.selected_infohash.as_ref() {
        Some(h) => h.clone(),
        None => return,
    };

    let command = match cmd_id {
        IDM_PAUSE => Command::PauseTorrent { infohash },
        IDM_RESUME => Command::ResumeTorrent { infohash },
        IDM_REMOVE => Command::RemoveTorrent { infohash },
        IDM_REMOVE_DATA => Command::RemoveTorrentWithData { infohash },
        IDM_RECHECK => Command::ForceRecheck { infohash },
        IDM_OPEN_FOLDER => Command::OpenFolder { infohash },
        IDM_COPY_MAGNET => Command::CopyMagnetLink { infohash },
        _ => return,
    };

    let _ = data.engine.tx.send(command);

    PostMessageW(STATUS_HWND.load(Ordering::SeqCst) as HWND, WM_UPDATE_LIST, 0, 0);
}

#[cfg(not(windows))]
pub fn open_status_window(_owner: usize, _engine: EngineHandle) -> Result<()> {
    anyhow::bail!("Windows-only.");
}

#[cfg(not(windows))]
pub fn update_torrents_from_event(_torrents: Vec<TorrentInfo>) {}

#[cfg(windows)]
unsafe fn register_status_window_class() -> Result<()> {
    let mut class_result = Ok(());
    REGISTER_CLASS.call_once(|| {
        let hinstance = GetModuleHandleW(std::ptr::null());
        if hinstance == 0 {
            class_result = Err(anyhow::anyhow!("GetModuleHandleW failed"));
            return;
        }

        let class_name = widestr(STATUS_CLASS_NAME);
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(status_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: 0,
            hCursor: LoadCursorW(0, IDC_ARROW as _),
            hbrBackground: (COLOR_WINDOW + 1) as HBRUSH,
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };

        if RegisterClassW(&wc) == 0 {
            class_result = Err(anyhow::anyhow!("RegisterClassW failed"));
        }
    });
    class_result
}

#[cfg(windows)]
unsafe extern "system" fn status_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let data_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as StatusWindowDataPtr;

    match msg {
        WM_SIZE => {
            if !data_ptr.is_null() {
                let data = &*data_ptr;
                let width = (lparam & 0xFFFF) as i32;
                let height = ((lparam >> 16) & 0xFFFF) as i32;
                SetWindowPos(
                    data.listview,
                    0,
                    0,
                    0,
                    width,
                    height,
                    SWP_NOZORDER,
                );
            }
            0
        }
        WM_TIMER => {
            if wparam == UPDATE_TIMER_ID && !data_ptr.is_null() {
                let data = &mut *data_ptr;
                update_torrent_list(data);
            }
            0
        }
        WM_UPDATE_LIST => {
            if !data_ptr.is_null() {
                let data = &mut *data_ptr;
                update_torrent_list(data);
            }
            0
        }
        WM_NOTIFY => {
            if !data_ptr.is_null() {
                let data = &mut *data_ptr;
                let nmhdr = &*(lparam as *const NMHDR);
                if nmhdr.hwndFrom == data.listview && nmhdr.code == NM_RCLICK {
                    show_context_menu(hwnd, data);
                    return 0;
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_COMMAND => {
            if !data_ptr.is_null() {
                let data = &mut *data_ptr;
                let cmd_id = (wparam & 0xFFFF) as usize;
                handle_context_menu_command(data, cmd_id);
            }
            0
        }
        WM_CLOSE => {
            if !data_ptr.is_null() {
                KillTimer(hwnd, UPDATE_TIMER_ID);
            }
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            if !data_ptr.is_null() {
                let data = Box::from_raw(data_ptr);
                drop(data);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            STATUS_HWND.store(0, Ordering::SeqCst);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(windows)]
fn widestr(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::widestr;

    #[test]
    fn widestr_is_null_terminated() {
        let buf = widestr("Nimble");
        assert_eq!(buf.last().copied(), Some(0));
    }
}

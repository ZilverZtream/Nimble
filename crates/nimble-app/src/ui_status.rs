use anyhow::Result;
use std::sync::Once;
use std::sync::atomic::{AtomicIsize, Ordering};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::*,
    System::LibraryLoader::*,
    UI::WindowsAndMessaging::*,
};

#[cfg(windows)]
const STATUS_CLASS_NAME: &str = "NimbleStatusWindowClass";

#[cfg(windows)]
const STATUS_WINDOW_TITLE: &str = "Nimble Status";

#[cfg(windows)]
static REGISTER_CLASS: Once = Once::new();

#[cfg(windows)]
static STATUS_HWND: AtomicIsize = AtomicIsize::new(0);

#[cfg(windows)]
pub fn open_status_window(owner: HWND) -> Result<()> {
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
            640,
            420,
            owner,
            0,
            hinstance,
            std::ptr::null_mut(),
        );

        if hwnd == 0 {
            anyhow::bail!("CreateWindowExW failed");
        }

        STATUS_HWND.store(hwnd as isize, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn open_status_window(_owner: usize) -> Result<()> {
    anyhow::bail!("Windows-only.");
}

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
    match msg {
        WM_CLOSE => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
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

pub fn now_ms() -> u64 {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

        unsafe {
            let mut frequency: i64 = 0;
            let mut counter: i64 = 0;

            if QueryPerformanceFrequency(&mut frequency) == 0 || frequency == 0 {
                return 0;
            }

            if QueryPerformanceCounter(&mut counter) == 0 {
                return 0;
            }

            ((counter as u128 * 1000) / frequency as u128) as u64
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

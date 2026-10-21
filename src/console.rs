//! Windows niceties for a double-clicked exe: ask for elevation when the
//! adapter needs it, and keep the window open long enough to read errors.

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Console::GetConsoleProcessList;
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    pub fn is_admin() -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }

    /// True when this process owns its console window (started by
    /// double-click, not from a terminal).
    pub fn own_console() -> bool {
        let mut pids = [0u32; 4];
        unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 4) <= 1 }
    }

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    /// Starts this exe again as Administrator with the same arguments.
    pub fn relaunch_elevated() -> bool {
        let Ok(exe) = std::env::current_exe() else {
            return false;
        };
        let params: Vec<String> = std::env::args()
            .skip(1)
            .map(|a| format!("\"{}\"", a.replace('"', "\\\"")))
            .collect();
        let params = params.join(" ");
        let cwd = std::env::current_dir().unwrap_or_default();
        let verb = wide("runas".as_ref());
        let file = wide(exe.as_os_str());
        let params = wide(params.as_ref());
        let dir = wide(cwd.as_os_str());
        let h = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                dir.as_ptr(),
                SW_SHOWNORMAL,
            )
        };
        h as isize > 32
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn is_admin() -> bool {
        true
    }
    pub fn own_console() -> bool {
        false
    }
    pub fn relaunch_elevated() -> bool {
        false
    }
}

pub use imp::*;

pub fn pause_if_own_console() {
    if own_console() {
        eprintln!("\nPress Enter to close this window.");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
}

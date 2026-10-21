//! The OS-facing virtual interface.
//!
//! Both backends expose the same shape: a blocking reader thread that feeds
//! packets into an mpsc channel, and a writer thread draining another one.
//! The adapter lives for the whole run, across reconnects.

use anyhow::Result;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::Device;
#[cfg(windows)]
pub use windows::Device;

pub struct Tun {
    pub from_os: mpsc::Receiver<Vec<u8>>,
    pub to_os: mpsc::Sender<Vec<u8>>,
    pub device: Device,
}

pub fn create(name: &str, mtu: u16) -> Result<Tun> {
    #[cfg(any(windows, target_os = "linux"))]
    return Device::create(name, mtu);
    #[cfg(not(any(windows, target_os = "linux")))]
    anyhow::bail!("no TUN backend for this OS yet ({name}, {mtu})");
}

#[cfg(windows)]
pub fn mask(prefix_len: u8) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(
        u32::MAX
            .checked_shl(32 - u32::from(prefix_len))
            .unwrap_or(0),
    )
}

#[cfg(target_os = "linux")]
pub use linux::ip as linux_ip;

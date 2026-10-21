//! Linux /dev/net/tun backend, mainly so the client can be developed and
//! tested on Linux before running it on Windows. Needs CAP_NET_ADMIN.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::mpsc;

use super::Tun;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub fn ip(args: &[&str]) -> Result<()> {
    let st = Command::new("ip")
        .args(args)
        .status()
        .context("running `ip`")?;
    if !st.success() {
        bail!("`ip {}` failed", args.join(" "));
    }
    Ok(())
}

pub struct Device {
    pub name: String,
}

impl Device {
    pub fn create(name: &str, mtu: u16) -> Result<Tun> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .context("opening /dev/net/tun")?;
        let mut req = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (d, s) in req
            .name
            .iter_mut()
            .zip(name.bytes().take(libc::IFNAMSIZ - 1))
        {
            *d = s as libc::c_char;
        }
        if unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &req) } < 0 {
            return Err(std::io::Error::last_os_error()).context("TUNSETIFF (need CAP_NET_ADMIN)");
        }
        ip(&["link", "set", "dev", name, "mtu", &mtu.to_string(), "up"])?;

        let file = Arc::new(file);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);

        let reader: Arc<File> = file.clone();
        std::thread::Builder::new()
            .name("tun-rx".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65535];
                loop {
                    match (&*reader).read(&mut buf) {
                        Ok(n) => {
                            if in_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("tun read: {e}");
                            return;
                        }
                    }
                }
            })?;
        std::thread::Builder::new()
            .name("tun-tx".into())
            .spawn(move || {
                while let Some(pkt) = out_rx.blocking_recv() {
                    if let Err(e) = (&*file).write_all(&pkt) {
                        tracing::debug!("tun write: {e}");
                    }
                }
            })?;

        tracing::info!(%name, "TUN device up");
        Ok(Tun {
            from_os: in_rx,
            to_os: out_tx,
            device: Device {
                name: name.to_string(),
            },
        })
    }

    pub fn set_address(&self, address: Ipv4Addr, prefix_len: u8) -> Result<()> {
        ip(&["addr", "flush", "dev", &self.name])?;
        ip(&[
            "addr",
            "add",
            &format!("{address}/{prefix_len}"),
            "dev",
            &self.name,
        ])
    }

    pub fn set_dns(&self, servers: &[Ipv4Addr]) -> Result<()> {
        tracing::info!("not changing DNS on Linux; VPN DNS servers: {servers:?}");
        Ok(())
    }
}

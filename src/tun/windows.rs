//! Wintun backend. Needs Administrator rights to create the adapter, and
//! `wintun.dll` (from https://www.wintun.net): either next to the executable,
//! or embedded at build time (see build.rs), in which case it is written next
//! to the executable on first use.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc;

use super::Tun;

#[cfg(embed_wintun)]
const WINTUN_DLL: &[u8] = include_bytes!(env!("OVPN_WINTUN_DLL_PATH"));

fn load_wintun() -> Result<wintun::Wintun> {
    if let Ok(w) = unsafe { wintun::load() } {
        return Ok(w);
    }
    #[cfg(embed_wintun)]
    {
        // Next to the exe, not in %TEMP%: that folder is exactly as trusted as
        // the exe itself, so an elevated ovpn won't load a DLL that a less
        // trusted process could have planted.
        let path = std::env::current_exe()?.with_file_name("wintun.dll");
        if std::fs::read(&path).ok().as_deref() != Some(WINTUN_DLL) {
            std::fs::write(&path, WINTUN_DLL)
                .with_context(|| format!("writing {}", path.display()))?;
            tracing::info!("extracted {}", path.display());
        }
        return unsafe { wintun::load_from_path(&path) }.context("loading the bundled wintun.dll");
    }
    #[allow(unreachable_code)]
    {
        anyhow::bail!(
            "wintun.dll not found; download it from https://www.wintun.net and put it next to ovpn.exe"
        )
    }
}

pub struct Device {
    adapter: Arc<wintun::Adapter>,
}

impl Device {
    pub fn create(name: &str, mtu: u16) -> Result<Tun> {
        let wintun = load_wintun()?;
        let adapter = match wintun::Adapter::open(&wintun, name) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, name, "OpenVPN-rs", None)
                .context("creating the Wintun adapter (run ovpn.exe as Administrator)")?,
        };
        adapter
            .set_mtu(usize::from(mtu))
            .context("setting adapter MTU")?;

        let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);

        let reader = session.clone();
        std::thread::Builder::new()
            .name("wintun-rx".into())
            .spawn(move || loop {
                match reader.receive_blocking() {
                    Ok(p) => {
                        if in_tx.blocking_send(p.bytes().to_vec()).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("wintun receive: {e}");
                        return;
                    }
                }
            })?;

        let writer = session;
        std::thread::Builder::new()
            .name("wintun-tx".into())
            .spawn(move || {
                while let Some(pkt) = out_rx.blocking_recv() {
                    let Ok(len) = u16::try_from(pkt.len()) else {
                        continue;
                    };
                    match writer.allocate_send_packet(len) {
                        Ok(mut p) => {
                            p.bytes_mut().copy_from_slice(&pkt);
                            writer.send_packet(p);
                        }
                        Err(e) => tracing::debug!("wintun send: {e}"),
                    }
                }
            })?;

        tracing::info!(%name, "Wintun adapter up");
        Ok(Tun {
            from_os: in_rx,
            to_os: out_tx,
            device: Device { adapter },
        })
    }

    pub fn set_address(&self, address: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.adapter
            .set_network_addresses_tuple(
                IpAddr::V4(address),
                IpAddr::V4(super::mask(prefix_len)),
                None,
            )
            .context("setting adapter address")?;
        Ok(())
    }

    pub fn set_dns(&self, servers: &[Ipv4Addr]) -> Result<()> {
        let s: Vec<IpAddr> = servers.iter().copied().map(IpAddr::V4).collect();
        self.adapter
            .set_dns_servers(&s)
            .context("setting DNS servers")?;
        // A low interface metric makes Windows ask the VPN's DNS first.
        let idx = self.index()?;
        let st = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "interface",
                &idx.to_string(),
                "metric=1",
            ])
            .stdout(std::process::Stdio::null())
            .status();
        if !st.is_ok_and(|s| s.success()) {
            tracing::warn!(
                "could not lower the adapter metric; DNS may also go to your normal servers"
            );
        }
        Ok(())
    }

    pub fn index(&self) -> Result<u32> {
        self.adapter
            .get_adapter_index()
            .context("reading the adapter index")
    }
}

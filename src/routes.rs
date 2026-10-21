//! System routes for the tunnel. Everything added here is removed again when
//! the [`Routes`] guard drops (on disconnect or Ctrl+C), so a reconnect can
//! reach the server over the normal network.

use anyhow::Result;
use std::net::Ipv4Addr;

use crate::tun::Device;

/// A route to add: destination, prefix length, and whether it goes through
/// the tunnel (true) or via the original default gateway (false).
#[derive(Debug, Clone, Copy)]
pub struct RouteSpec {
    pub dest: Ipv4Addr,
    pub prefix: u8,
    pub via_tunnel: bool,
}

pub struct Routes {
    added: Vec<sys::Added>,
}

impl Routes {
    pub fn apply(dev: &Device, specs: &[RouteSpec]) -> Result<Routes> {
        let mut r = Routes { added: Vec::new() };
        for s in specs {
            match sys::add(dev, s) {
                Ok(Some(a)) => r.added.push(a),
                Ok(None) => {}
                Err(e) => {
                    // Undo what we did so far, then fail.
                    drop(r);
                    return Err(e);
                }
            }
            tracing::debug!(dest = %s.dest, prefix = s.prefix, tunnel = s.via_tunnel, "route added");
        }
        Ok(r)
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        for a in self.added.drain(..).rev() {
            if let Err(e) = sys::remove(&a) {
                tracing::warn!("removing route: {e:#}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::RouteSpec;
    use crate::tun::Device;
    use anyhow::{anyhow, Context, Result};
    use std::process::Command;

    pub struct Added(Vec<String>);

    fn via_default(dest: &str) -> Result<Vec<String>> {
        let out = Command::new("ip")
            .args(["-4", "route", "get", dest])
            .output()
            .context("running `ip route get`")?;
        let s = String::from_utf8_lossy(&out.stdout);
        let words: Vec<&str> = s.split_whitespace().collect();
        let mut v = Vec::new();
        for key in ["via", "dev"] {
            if let Some(i) = words.iter().position(|w| *w == key) {
                v.push(key.to_string());
                v.push(
                    words
                        .get(i + 1)
                        .ok_or_else(|| anyhow!("bad `ip route get` output"))?
                        .to_string(),
                );
            }
        }
        Ok(v)
    }

    pub fn add(dev: &Device, s: &RouteSpec) -> Result<Option<Added>> {
        let dest = format!("{}/{}", s.dest, s.prefix);
        let mut args = vec!["route".to_string(), "replace".into(), dest.clone()];
        if s.via_tunnel {
            args.extend(["dev".into(), dev.name.clone()]);
        } else {
            args.extend(via_default(&s.dest.to_string())?);
        }
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        crate::tun::linux_ip(&a)?;
        Ok(Some(Added(vec!["route".into(), "del".into(), dest])))
    }

    pub fn remove(a: &Added) -> Result<()> {
        let a: Vec<&str> = a.0.iter().map(String::as_str).collect();
        crate::tun::linux_ip(&a)
    }
}

#[cfg(windows)]
mod sys {
    use super::RouteSpec;
    use crate::tun::Device;
    use anyhow::{bail, Result};
    use std::net::Ipv4Addr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CreateIpForwardEntry2, DeleteIpForwardEntry2, GetBestRoute2, InitializeIpForwardEntry,
        MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

    pub struct Added(Box<MIB_IPFORWARD_ROW2>);

    const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
    /// MIB_IPPROTO_NETMGMT: a static route added by management software.
    const PROTO_NETMGMT: i32 = 3;

    fn sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
        let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        s.Ipv4.sin_family = AF_INET;
        s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        s
    }

    /// The interface and next hop Windows uses for `dest` right now.
    fn best_route(dest: Ipv4Addr) -> Result<(u32, SOCKADDR_INET)> {
        let d = sockaddr(dest);
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        let mut src: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &d,
                0,
                &mut row,
                &mut src,
            )
        };
        if rc != 0 {
            bail!("no route to {dest} (GetBestRoute2 error {rc})");
        }
        Ok((row.InterfaceIndex, row.NextHop))
    }

    pub fn add(dev: &Device, s: &RouteSpec) -> Result<Option<Added>> {
        let mut row: Box<MIB_IPFORWARD_ROW2> = Box::new(unsafe { std::mem::zeroed() });
        unsafe { InitializeIpForwardEntry(&mut *row) };
        if s.via_tunnel {
            row.InterfaceIndex = dev.index()?;
            row.NextHop = sockaddr(Ipv4Addr::UNSPECIFIED);
        } else {
            let (ifindex, next_hop) = best_route(s.dest)?;
            row.InterfaceIndex = ifindex;
            row.NextHop = next_hop;
        }
        row.DestinationPrefix.Prefix = sockaddr(s.dest);
        row.DestinationPrefix.PrefixLength = s.prefix;
        row.Metric = 0;
        row.Protocol = PROTO_NETMGMT;
        let rc = unsafe { CreateIpForwardEntry2(&*row) };
        match rc {
            0 => Ok(Some(Added(row))),
            ERROR_OBJECT_ALREADY_EXISTS => Ok(None),
            _ => bail!("adding route {}/{} failed (error {rc})", s.dest, s.prefix),
        }
    }

    pub fn remove(a: &Added) -> Result<()> {
        let rc = unsafe { DeleteIpForwardEntry2(&*a.0) };
        if rc != 0 {
            bail!("DeleteIpForwardEntry2 error {rc}");
        }
        Ok(())
    }
}

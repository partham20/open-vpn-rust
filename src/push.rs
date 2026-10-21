//! The server's PUSH_REPLY, and the compression framing it selects.

use anyhow::{anyhow, Context, Result};
use std::net::Ipv4Addr;

use crate::config::Config;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    #[default]
    None,
    /// `comp-lzo`: a 0xFA "not compressed" byte in front.
    Lzo,
    /// `compress` / `compress lz4`: 0xFB in front, first byte moved to the end.
    Swap,
    /// `compress stub-v2` / `lz4-v2`: escape only packets starting with 0x50.
    V2,
}

const NO_COMPRESS: u8 = 0xFA;
const LZO_COMPRESSED: u8 = 0x66;
const NO_COMPRESS_SWAP: u8 = 0xFB;
const LZ4_COMPRESSED: u8 = 0x69;
const V2_INDICATOR: u8 = 0x50;
const V2_LZ4: u8 = 1;

impl Compression {
    fn from_option(name: &str, arg: Option<&str>) -> Option<Compression> {
        match name {
            "comp-lzo" => Some(Compression::Lzo),
            "compress" => Some(match arg {
                Some("stub-v2") | Some("lz4-v2") => Compression::V2,
                Some("lzo") => Compression::Lzo,
                _ => Compression::Swap,
            }),
            _ => None,
        }
    }

    pub fn compress(self, ip: &[u8]) -> Vec<u8> {
        match self {
            Compression::None => ip.to_vec(),
            Compression::Lzo => [&[NO_COMPRESS][..], ip].concat(),
            Compression::Swap => {
                let mut v = Vec::with_capacity(ip.len() + 1);
                v.push(NO_COMPRESS_SWAP);
                if let Some((first, rest)) = ip.split_first() {
                    v.extend_from_slice(rest);
                    v.push(*first);
                }
                v
            }
            Compression::V2 => {
                if ip.first() == Some(&V2_INDICATOR) {
                    [&[V2_INDICATOR, 0][..], ip].concat()
                } else {
                    ip.to_vec()
                }
            }
        }
    }

    /// Returns None for packets we cannot decode (logged).
    pub fn decompress(self, mut p: Vec<u8>) -> Option<Vec<u8>> {
        match self {
            Compression::None => Some(p),
            Compression::Lzo => match *p.first()? {
                NO_COMPRESS => Some(p.split_off(1)),
                LZO_COMPRESSED => {
                    tracing::warn!("dropping an LZO-compressed packet (LZO is not supported)");
                    None
                }
                _ => Some(p),
            },
            Compression::Swap => match *p.first()? {
                NO_COMPRESS_SWAP => {
                    let last = p.pop()?;
                    p[0] = last;
                    Some(p)
                }
                LZ4_COMPRESSED => {
                    let last = p.pop()?;
                    p[0] = last;
                    lz4(&p[1..])
                }
                NO_COMPRESS => Some(p.split_off(1)),
                _ => Some(p),
            },
            Compression::V2 => {
                if p.first() == Some(&V2_INDICATOR) && p.len() >= 2 {
                    match p[1] {
                        0 => Some(p.split_off(2)),
                        V2_LZ4 => lz4(&p[2..]),
                        _ => None,
                    }
                } else {
                    Some(p)
                }
            }
        }
    }
}

fn lz4(src: &[u8]) -> Option<Vec<u8>> {
    let mut out = vec![0u8; 65536];
    match lz4_flex::block::decompress_into(src, &mut out) {
        Ok(n) => {
            out.truncate(n);
            Some(out)
        }
        Err(e) => {
            tracing::debug!("lz4: {e}");
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub net: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Default)]
pub struct PushReply {
    pub raw: String,
    pub local_ip: Option<Ipv4Addr>,
    /// Netmask (topology subnet) or peer address (net30/p2p) from `ifconfig`.
    pub ifconfig_second: Option<Ipv4Addr>,
    pub topology_subnet: bool,
    pub route_gateway: Option<Ipv4Addr>,
    pub redirect_gateway: bool,
    pub routes: Vec<Route>,
    pub dns: Vec<Ipv4Addr>,
    pub cipher: Option<String>,
    pub peer_id: Option<u32>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub tun_mtu: Option<u16>,
    pub tls_ekm: bool,
    pub auth_token: Option<String>,
    pub compression: Compression,
    pub block_outside_dns: bool,
}

impl PushReply {
    pub fn parse(s: &str, cfg: &Config) -> Result<PushReply> {
        let mut p = PushReply {
            raw: s.to_string(),
            ..Default::default()
        };
        p.compression = if cfg.comp_lzo {
            Compression::Lzo
        } else if let Some(c) = &cfg.compress {
            Compression::from_option("compress", Some(c.as_str()).filter(|s| !s.is_empty()))
                .unwrap_or_default()
        } else {
            Compression::None
        };
        for opt in s.split(',') {
            let words: Vec<&str> = opt.split_whitespace().collect();
            let Some((&name, args)) = words.split_first() else {
                continue;
            };
            let ip = |i: usize| -> Result<Ipv4Addr> {
                args.get(i)
                    .ok_or_else(|| anyhow!("{name}: missing argument"))?
                    .parse()
                    .with_context(|| format!("{name}: bad address"))
            };
            match name {
                "ifconfig" => {
                    p.local_ip = Some(ip(0)?);
                    p.ifconfig_second = ip(1).ok();
                }
                "topology" => p.topology_subnet = args.first() == Some(&"subnet"),
                "route-gateway" => p.route_gateway = ip(0).ok(),
                "redirect-gateway" | "redirect-private" => {
                    if name == "redirect-gateway" {
                        p.redirect_gateway = true;
                    }
                }
                "route" => {
                    let net = ip(0)?;
                    let mask = args
                        .get(1)
                        .map(|m| m.parse())
                        .transpose()
                        .context("route: bad mask")?
                        .unwrap_or(Ipv4Addr::BROADCAST);
                    let gateway = args.get(2).and_then(|g| g.parse().ok());
                    p.routes.push(Route { net, mask, gateway });
                }
                "dhcp-option" => {
                    if args.first() == Some(&"DNS") {
                        if let Ok(a) = ip(1) {
                            p.dns.push(a);
                        }
                    }
                }
                "dns" => {
                    // OpenVPN 2.6 "dns server 0 address 1.2.3.4"
                    if args.first() == Some(&"server") && args.get(2) == Some(&"address") {
                        for a in &args[3..] {
                            if let Ok(a) = a.parse::<Ipv4Addr>() {
                                p.dns.push(a);
                            }
                        }
                    }
                }
                "block-outside-dns" => p.block_outside_dns = true,
                "cipher" => p.cipher = args.first().map(|s| s.to_string()),
                "peer-id" => p.peer_id = args.first().and_then(|s| s.parse().ok()),
                "ping" => p.ping = args.first().and_then(|s| s.parse().ok()),
                "ping-restart" => p.ping_restart = args.first().and_then(|s| s.parse().ok()),
                "tun-mtu" => p.tun_mtu = args.first().and_then(|s| s.parse().ok()),
                "key-derivation" => p.tls_ekm |= args.first() == Some(&"tls-ekm"),
                "protocol-flags" => p.tls_ekm |= args.contains(&"tls-ekm"),
                "auth-token" => p.auth_token = args.first().map(|s| s.to_string()),
                "comp-lzo" | "compress" => {
                    if let Some(c) = Compression::from_option(name, args.first().copied()) {
                        p.compression = c;
                    }
                }
                _ => {}
            }
        }
        p.dns.dedup();
        Ok(p)
    }

    /// Prefix length for the adapter address.
    pub fn prefix_len(&self) -> u8 {
        match (self.topology_subnet, self.ifconfig_second) {
            (true, Some(mask)) => u32::from(mask).count_ones() as u8,
            // net30 / p2p: a /30 holds both ends.
            _ => 30,
        }
    }

    /// The VPN-side next hop for routes.
    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.route_gateway.or(if self.topology_subnet {
            None
        } else {
            self.ifconfig_second
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_roundtrips() {
        for c in [
            Compression::None,
            Compression::Lzo,
            Compression::Swap,
            Compression::V2,
        ] {
            for pkt in [vec![0x45, 1, 2, 3], vec![0x50, 9]] {
                assert_eq!(c.decompress(c.compress(&pkt)).unwrap(), pkt, "{c:?}");
            }
        }
    }
}

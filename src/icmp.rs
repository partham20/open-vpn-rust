//! Just enough IPv4/ICMP to ping through the tunnel without a TUN device
//! (`--no-tun --ping`), which tests the whole VPN path without admin rights.

use std::net::Ipv4Addr;

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in data.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += u32::from(w);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"ovpn-rs ping payload 0123456789");
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());

    let total = (20 + icmp.len()) as u16;
    let mut ip = vec![0x45, 0];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&seq.to_be_bytes());
    ip.extend_from_slice(&[0, 0, 64, 1, 0, 0]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// If `pkt` is an echo reply with our id, returns (source, seq).
pub fn parse_echo_reply(pkt: &[u8], id: u16) -> Option<(Ipv4Addr, u16)> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0xf) * 4;
    let icmp = pkt.get(ihl..)?;
    if icmp.len() < 8 || icmp[0] != 0 || u16::from_be_bytes([icmp[4], icmp[5]]) != id {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    Some((src, u16::from_be_bytes([icmp[6], icmp[7]])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_header_checksum_verifies() {
        let p = echo_request(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(1, 1, 1, 1), 7, 1);
        assert_eq!(checksum(&p[..20]), 0);
        assert_eq!(checksum(&p[20..]), 0);
    }
}

//! OpenVPN packet opcodes and the control-packet layout.

use anyhow::{bail, Result};

pub const P_CONTROL_HARD_RESET_CLIENT_V1: u8 = 1;
pub const P_CONTROL_HARD_RESET_SERVER_V1: u8 = 2;
pub const P_CONTROL_SOFT_RESET_V1: u8 = 3;
pub const P_CONTROL_V1: u8 = 4;
pub const P_ACK_V1: u8 = 5;
pub const P_DATA_V1: u8 = 6;
pub const P_CONTROL_HARD_RESET_CLIENT_V2: u8 = 7;
pub const P_CONTROL_HARD_RESET_SERVER_V2: u8 = 8;
pub const P_DATA_V2: u8 = 9;

pub fn opcode(b: u8) -> u8 {
    b >> 3
}

pub fn key_id(b: u8) -> u8 {
    b & 7
}

pub fn op_byte(op: u8, key_id: u8) -> u8 {
    (op << 3) | (key_id & 7)
}

/// The part of a control packet after the opcode, session id and any
/// tls-auth/tls-crypt replay header.
#[derive(Debug, Default, Clone)]
pub struct ControlBody {
    pub acks: Vec<u32>,
    pub remote_sid: Option<[u8; 8]>,
    /// Absent for P_ACK_V1.
    pub packet_id: Option<u32>,
    pub payload: Vec<u8>,
}

impl ControlBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(1 + self.acks.len() * 4 + 12 + self.payload.len());
        b.push(self.acks.len() as u8);
        for a in &self.acks {
            b.extend_from_slice(&a.to_be_bytes());
        }
        if !self.acks.is_empty() {
            b.extend_from_slice(&self.remote_sid.unwrap_or_default());
        }
        if let Some(p) = self.packet_id {
            b.extend_from_slice(&p.to_be_bytes());
        }
        b.extend_from_slice(&self.payload);
        b
    }

    pub fn decode(op: u8, b: &[u8]) -> Result<ControlBody> {
        let mut c = ControlBody::default();
        let Some((&n, mut rest)) = b.split_first() else {
            bail!("empty control body");
        };
        if rest.len() < usize::from(n) * 4 {
            bail!("short ack list");
        }
        for _ in 0..n {
            c.acks
                .push(u32::from_be_bytes(rest[..4].try_into().unwrap()));
            rest = &rest[4..];
        }
        if n > 0 {
            if rest.len() < 8 {
                bail!("short ack session id");
            }
            c.remote_sid = Some(rest[..8].try_into().unwrap());
            rest = &rest[8..];
        }
        if op != P_ACK_V1 {
            if rest.len() < 4 {
                bail!("short control packet id");
            }
            c.packet_id = Some(u32::from_be_bytes(rest[..4].try_into().unwrap()));
            rest = &rest[4..];
        }
        c.payload = rest.to_vec();
        Ok(c)
    }
}

/// The payload of an OpenVPN keepalive ping.
pub const PING_MAGIC: [u8; 16] = [
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb, 0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
];

/// The prefix of an OCC (options consistency check) message.
pub const OCC_MAGIC: [u8; 16] = [
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81, 0x41, 0x46, 0xa2, 0xa9, 0x0c, 0xc0, 0x3c, 0x9d,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = ControlBody {
            acks: vec![0, 1],
            remote_sid: Some([9; 8]),
            packet_id: Some(3),
            payload: b"tls".to_vec(),
        };
        let d = ControlBody::decode(P_CONTROL_V1, &b.encode()).unwrap();
        assert_eq!(d.acks, vec![0, 1]);
        assert_eq!(d.remote_sid, Some([9; 8]));
        assert_eq!(d.packet_id, Some(3));
        assert_eq!(d.payload, b"tls");
    }
}

//! Crypto for both channels: the control-channel wrappers (tls-auth,
//! tls-crypt), the OpenVPN PRF, and the data-channel ciphers.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, StreamCipher};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};

use crate::config::{Digest, StaticKey};

pub fn hmac(d: Digest, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).expect("hmac takes any key");
            for p in parts {
                m.update(p);
            }
            m.finalize().into_bytes().to_vec()
        }};
    }
    match d {
        Digest::Sha1 => run!(sha1::Sha1),
        Digest::Sha256 => run!(sha2::Sha256),
        Digest::Sha384 => run!(sha2::Sha384),
        Digest::Sha512 => run!(sha2::Sha512),
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// TLS 1.0 P_hash.
fn p_hash<M: Mac + KeyInit + Clone>(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    let mac = <M as KeyInit>::new_from_slice(secret).expect("hmac takes any key");
    let mut a = {
        let mut m = mac.clone();
        m.update(seed);
        m.finalize().into_bytes()
    };
    let mut pos = 0;
    while pos < out.len() {
        let mut m = mac.clone();
        m.update(&a);
        m.update(seed);
        let block = m.finalize().into_bytes();
        for (o, b) in out[pos..].iter_mut().zip(block.iter()) {
            *o ^= b;
        }
        pos += block.len();
        let mut m = mac.clone();
        m.update(&a);
        a = m.finalize().into_bytes();
    }
}

/// The TLS 1.0 PRF (MD5 xor SHA1), as OpenVPN uses it without tls-ekm.
pub fn tls1_prf(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    out.fill(0);
    let half = secret.len().div_ceil(2);
    p_hash::<Hmac<md5::Md5>>(&secret[..half], seed, out);
    p_hash::<Hmac<sha1::Sha1>>(&secret[secret.len() - half..], seed, out);
}

/// `openvpn_PRF`: seed = label || client_seed || server_seed [|| sids].
pub fn openvpn_prf(
    secret: &[u8],
    label: &str,
    client_seed: &[u8],
    server_seed: &[u8],
    sids: Option<(&[u8; 8], &[u8; 8])>,
    out: &mut [u8],
) {
    let mut seed = Vec::new();
    seed.extend_from_slice(label.as_bytes());
    seed.extend_from_slice(client_seed);
    seed.extend_from_slice(server_seed);
    if let Some((c, s)) = sids {
        seed.extend_from_slice(c);
        seed.extend_from_slice(s);
    }
    tls1_prf(secret, &seed, out);
}

// ---------------------------------------------------------------------------
// Control channel wrapping

/// Wraps and unwraps control packets. `op_sid` is the opcode byte plus the
/// 8-byte session id; `body` is everything after the replay packet-id.
pub enum Wrap {
    None,
    Auth {
        digest: Digest,
        send_key: Vec<u8>,
        recv_key: Vec<u8>,
        pid: u32,
        time: u32,
    },
    Crypt {
        enc_key: [u8; 32],
        enc_hmac: [u8; 32],
        dec_key: [u8; 32],
        dec_hmac: [u8; 32],
        pid: u32,
        time: u32,
    },
}

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

impl Wrap {
    pub fn tls_auth(key: &StaticKey, direction: Option<u8>, digest: Digest) -> Wrap {
        let n = digest.len();
        // Slot layout: cipher0 hmac0 cipher1 hmac1. Direction 1 (the usual
        // client side) sends with hmac1 and receives with hmac0.
        let (send, recv) = match direction {
            Some(1) => (key.slot(3), key.slot(1)),
            Some(_) => (key.slot(1), key.slot(3)),
            None => (key.slot(1), key.slot(1)),
        };
        Wrap::Auth {
            digest,
            send_key: send[..n].to_vec(),
            recv_key: recv[..n].to_vec(),
            pid: 1,
            time: now_secs(),
        }
    }

    pub fn tls_crypt(key: &StaticKey) -> Wrap {
        // Clients always use the inverse key direction for tls-crypt.
        let k = |i: usize| -> [u8; 32] { key.slot(i)[..32].try_into().unwrap() };
        Wrap::Crypt {
            enc_key: k(2),
            enc_hmac: k(3),
            dec_key: k(0),
            dec_hmac: k(1),
            pid: 1,
            time: now_secs(),
        }
    }

    pub fn wrap(&mut self, op_sid: &[u8], body: &[u8]) -> Vec<u8> {
        match self {
            Wrap::None => [op_sid, body].concat(),
            Wrap::Auth {
                digest,
                send_key,
                pid,
                time,
                ..
            } => {
                let mut replay = [0u8; 8];
                replay[..4].copy_from_slice(&pid.to_be_bytes());
                replay[4..].copy_from_slice(&time.to_be_bytes());
                *pid += 1;
                let tag = hmac(*digest, send_key, &[&replay, op_sid, body]);
                [op_sid, &tag, &replay, body].concat()
            }
            Wrap::Crypt {
                enc_key,
                enc_hmac,
                pid,
                time,
                ..
            } => {
                let mut header = op_sid.to_vec();
                header.extend_from_slice(&pid.to_be_bytes());
                header.extend_from_slice(&time.to_be_bytes());
                *pid += 1;
                let tag = hmac(Digest::Sha256, enc_hmac, &[&header, body]);
                let mut ct = body.to_vec();
                let mut c = Aes256Ctr::new((&*enc_key).into(), tag[..16].into());
                c.apply_keystream(&mut ct);
                [&header[..], &tag, &ct].concat()
            }
        }
    }

    /// Returns the plain body (after the replay id), or an error if the
    /// packet fails authentication.
    pub fn unwrap(&self, pkt: &[u8]) -> Result<Vec<u8>> {
        if pkt.len() < 9 {
            bail!("short control packet");
        }
        let op_sid = &pkt[..9];
        match self {
            Wrap::None => Ok(pkt[9..].to_vec()),
            Wrap::Auth {
                digest, recv_key, ..
            } => {
                let n = digest.len();
                if pkt.len() < 9 + n + 8 {
                    bail!("short tls-auth packet");
                }
                let tag = &pkt[9..9 + n];
                let replay = &pkt[9 + n..9 + n + 8];
                let body = &pkt[9 + n + 8..];
                let want = hmac(*digest, recv_key, &[replay, op_sid, body]);
                if !ct_eq(tag, &want) {
                    bail!("tls-auth HMAC mismatch (wrong key or key-direction?)");
                }
                Ok(body.to_vec())
            }
            Wrap::Crypt {
                dec_key, dec_hmac, ..
            } => {
                if pkt.len() < 17 + 32 {
                    bail!("short tls-crypt packet");
                }
                let header = &pkt[..17];
                let tag = &pkt[17..49];
                let mut body = pkt[49..].to_vec();
                let mut c = Aes256Ctr::new(dec_key.into(), tag[..16].into());
                c.apply_keystream(&mut body);
                let want = hmac(Digest::Sha256, dec_hmac, &[header, &body]);
                if !ct_eq(tag, &want) {
                    bail!("tls-crypt authentication failed (wrong key?)");
                }
                Ok(body)
            }
        }
    }
}

fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Data channel

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes128Cbc,
    Aes256Cbc,
}

impl CipherKind {
    pub fn parse(s: &str) -> Option<CipherKind> {
        Some(match s.to_ascii_uppercase().as_str() {
            "AES-128-GCM" => CipherKind::Aes128Gcm,
            "AES-256-GCM" => CipherKind::Aes256Gcm,
            "CHACHA20-POLY1305" => CipherKind::ChaCha20Poly1305,
            "AES-128-CBC" => CipherKind::Aes128Cbc,
            "AES-256-CBC" => CipherKind::Aes256Cbc,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            CipherKind::Aes128Gcm => "AES-128-GCM",
            CipherKind::Aes256Gcm => "AES-256-GCM",
            CipherKind::ChaCha20Poly1305 => "CHACHA20-POLY1305",
            CipherKind::Aes128Cbc => "AES-128-CBC",
            CipherKind::Aes256Cbc => "AES-256-CBC",
        }
    }

    pub fn is_aead(self) -> bool {
        !matches!(self, CipherKind::Aes128Cbc | CipherKind::Aes256Cbc)
    }

    fn key_len(self) -> usize {
        match self {
            CipherKind::Aes128Gcm | CipherKind::Aes128Cbc => 16,
            _ => 32,
        }
    }
}

/// One direction of a data channel key.
struct DirKey {
    cipher: Vec<u8>,
    hmac: Vec<u8>,
}

/// Data-channel keys for one key_id, built from the 256-byte key block.
pub struct DataKeys {
    kind: CipherKind,
    digest: Digest,
    out: DirKey,
    inn: DirKey,
    send_pid: u32,
    recv_pid: u32,
}

impl DataKeys {
    /// `block` holds key2: [cipher0 64][hmac0 64][cipher1 64][hmac1 64].
    /// The client sends with key 0 and receives with key 1.
    pub fn new(kind: CipherKind, digest: Digest, block: &[u8; 256]) -> DataKeys {
        let kl = kind.key_len();
        let hl = if kind.is_aead() { 8 } else { digest.len() };
        DataKeys {
            kind,
            digest,
            out: DirKey {
                cipher: block[0..kl].to_vec(),
                hmac: block[64..64 + hl].to_vec(),
            },
            inn: DirKey {
                cipher: block[128..128 + kl].to_vec(),
                hmac: block[192..192 + hl].to_vec(),
            },
            send_pid: 1,
            recv_pid: 0,
        }
    }

    /// Encrypts `payload`. `header` is the opcode byte (V1) or the 4-byte
    /// opcode+peer-id (V2); the result includes it.
    pub fn encrypt(&mut self, header: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        let pid = self.send_pid;
        self.send_pid = self
            .send_pid
            .checked_add(1)
            .ok_or_else(|| anyhow!("packet id wrapped"))?;
        let pid_b = pid.to_be_bytes();
        if self.kind.is_aead() {
            let mut iv = [0u8; 12];
            iv[..4].copy_from_slice(&pid_b);
            iv[4..].copy_from_slice(&self.out.hmac[..8]);
            // For P_DATA_V2 the opcode/peer-id is authenticated too.
            let ad = if header.len() == 4 {
                [header, &pid_b].concat()
            } else {
                pid_b.to_vec()
            };
            let mut buf = payload.to_vec();
            let tag = aead_seal(self.kind, &self.out.cipher, &iv, &ad, &mut buf)?;
            let mut out = Vec::with_capacity(header.len() + 4 + 16 + buf.len());
            out.extend_from_slice(header);
            out.extend_from_slice(&pid_b);
            out.extend_from_slice(&tag);
            out.extend_from_slice(&buf);
            Ok(out)
        } else {
            let iv: [u8; 16] = rand::random();
            let mut plain = pid_b.to_vec();
            plain.extend_from_slice(payload);
            let ct = cbc_encrypt(self.kind, &self.out.cipher, &iv, &plain);
            let tag = hmac(self.digest, &self.out.hmac, &[&iv, &ct]);
            Ok([header, &tag, &iv, &ct].concat())
        }
    }

    /// Decrypts a data packet body (after the `header_len` header bytes).
    pub fn decrypt(&mut self, pkt: &[u8], header_len: usize) -> Result<Vec<u8>> {
        let header = &pkt[..header_len];
        let rest = &pkt[header_len..];
        let (pid, payload) = if self.kind.is_aead() {
            if rest.len() < 20 {
                bail!("short data packet");
            }
            let pid_b: [u8; 4] = rest[..4].try_into().unwrap();
            let tag: [u8; 16] = rest[4..20].try_into().unwrap();
            let mut iv = [0u8; 12];
            iv[..4].copy_from_slice(&pid_b);
            iv[4..].copy_from_slice(&self.inn.hmac[..8]);
            let ad = if header_len == 4 {
                [header, &pid_b].concat()
            } else {
                pid_b.to_vec()
            };
            let mut buf = rest[20..].to_vec();
            aead_open(self.kind, &self.inn.cipher, &iv, &ad, &mut buf, &tag)?;
            (u32::from_be_bytes(pid_b), buf)
        } else {
            let n = self.digest.len();
            if rest.len() < n + 16 + 16 {
                bail!("short data packet");
            }
            let (tag, rest) = rest.split_at(n);
            let want = hmac(self.digest, &self.inn.hmac, &[rest]);
            if !ct_eq(tag, &want) {
                bail!("data packet HMAC mismatch");
            }
            let (iv, ct) = rest.split_at(16);
            let plain = cbc_decrypt(self.kind, &self.inn.cipher, iv, ct)?;
            if plain.len() < 4 {
                bail!("short data packet");
            }
            (
                u32::from_be_bytes(plain[..4].try_into().unwrap()),
                plain[4..].to_vec(),
            )
        };
        // TCP delivers in order, so a strictly increasing id is the replay check.
        if pid <= self.recv_pid {
            bail!("replayed data packet id {pid}");
        }
        self.recv_pid = pid;
        Ok(payload)
    }
}

fn aead_seal(
    kind: CipherKind,
    key: &[u8],
    iv: &[u8; 12],
    ad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; 16]> {
    let tag = match kind {
        CipherKind::Aes128Gcm => {
            aes_gcm::Aes128Gcm::new_from_slice(key)?.encrypt_in_place_detached(iv.into(), ad, buf)
        }
        CipherKind::Aes256Gcm => {
            aes_gcm::Aes256Gcm::new_from_slice(key)?.encrypt_in_place_detached(iv.into(), ad, buf)
        }
        CipherKind::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)?
            .encrypt_in_place_detached(iv.into(), ad, buf),
        _ => unreachable!(),
    }
    .map_err(|_| anyhow!("encrypt failed"))?;
    Ok(tag.into())
}

fn aead_open(
    kind: CipherKind,
    key: &[u8],
    iv: &[u8; 12],
    ad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Result<()> {
    match kind {
        CipherKind::Aes128Gcm => aes_gcm::Aes128Gcm::new_from_slice(key)?
            .decrypt_in_place_detached(iv.into(), ad, buf, tag.into()),
        CipherKind::Aes256Gcm => aes_gcm::Aes256Gcm::new_from_slice(key)?
            .decrypt_in_place_detached(iv.into(), ad, buf, tag.into()),
        CipherKind::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new_from_slice(key)?
            .decrypt_in_place_detached(iv.into(), ad, buf, tag.into()),
        _ => unreachable!(),
    }
    .map_err(|_| anyhow!("data packet failed authentication"))
}

fn cbc_encrypt(kind: CipherKind, key: &[u8], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    use aes::cipher::block_padding::Pkcs7;
    match kind {
        CipherKind::Aes128Cbc => cbc::Encryptor::<aes::Aes128>::new(key.into(), iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plain),
        CipherKind::Aes256Cbc => cbc::Encryptor::<aes::Aes256>::new(key.into(), iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plain),
        _ => unreachable!(),
    }
}

fn cbc_decrypt(kind: CipherKind, key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::block_padding::Pkcs7;
    match kind {
        CipherKind::Aes128Cbc => cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct),
        CipherKind::Aes256Cbc => cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into())
            .decrypt_padded_vec_mut::<Pkcs7>(ct),
        _ => unreachable!(),
    }
    .map_err(|_| anyhow!("bad CBC padding"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_rfc2246_shape() {
        // Sanity: deterministic and depends on every input.
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        openvpn_prf(b"secret", "label", b"c", b"s", None, &mut a);
        openvpn_prf(b"secret", "label", b"c", b"t", None, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn tls_crypt_roundtrip_with_mirror() {
        let mut k2 = [0u8; 256];
        for (i, b) in k2.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = StaticKey(k2);
        let mut client = Wrap::tls_crypt(&key);
        // A server-side view: swap directions.
        let server = match Wrap::tls_crypt(&key) {
            Wrap::Crypt {
                enc_key,
                enc_hmac,
                dec_key,
                dec_hmac,
                pid,
                time,
            } => Wrap::Crypt {
                enc_key: dec_key,
                enc_hmac: dec_hmac,
                dec_key: enc_key,
                dec_hmac: enc_hmac,
                pid,
                time,
            },
            _ => unreachable!(),
        };
        let op_sid = [0x38u8, 1, 2, 3, 4, 5, 6, 7, 8];
        let pkt = client.wrap(&op_sid, b"hello body");
        assert_eq!(server.unwrap(&pkt).unwrap(), b"hello body");
    }

    #[test]
    fn data_roundtrip() {
        let mut block = [0u8; 256];
        for (i, b) in block.iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        let mut mirror = [0u8; 256];
        mirror[..128].copy_from_slice(&block[128..]);
        mirror[128..].copy_from_slice(&block[..128]);
        for kind in [
            CipherKind::Aes256Gcm,
            CipherKind::ChaCha20Poly1305,
            CipherKind::Aes256Cbc,
        ] {
            let mut a = DataKeys::new(kind, Digest::Sha512, &block);
            let mut b = DataKeys::new(kind, Digest::Sha512, &mirror);
            let hdr = [0x48, 0, 0, 1];
            let pkt = a.encrypt(&hdr, b"ip packet").unwrap();
            assert_eq!(b.decrypt(&pkt, 4).unwrap(), b"ip packet");
            assert!(b.decrypt(&pkt, 4).is_err(), "replay must fail");
        }
    }
}

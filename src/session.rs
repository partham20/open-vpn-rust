//! The OpenVPN protocol state machine, independent of sockets and TUN.
//!
//! Feed it wire packets with [`Session::on_packet`] and IP packets with
//! [`Session::encrypt`]; collect wire packets to send from
//! [`Session::take_outgoing`] and events from [`Session::take_events`].

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use rustls::ClientConnection;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{Config, TlsWrapKey};
use crate::crypto::{openvpn_prf, CipherKind, DataKeys, Wrap};
use crate::packet::*;
use crate::push::PushReply;

/// Control packets in flight before we wait for acks (OpenVPN's window is 4+).
const SEND_WINDOW: usize = 4;
/// Largest TLS chunk per control packet; keeps packets under OpenVPN's tls-mtu.
const MAX_CONTROL_PAYLOAD: usize = 1000;
const MAX_ACKS_PER_PACKET: usize = 4;

pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
pub enum Event {
    /// The first key is up and the server pushed its options.
    Connected(Box<PushReply>),
    /// A renegotiated key took over.
    Rekeyed(u8),
    AuthFailed(String),
    /// Server asked us to reconnect (RESTART) or to stop (HALT).
    Restart(String),
    Halt(String),
}

struct ClientKeySource {
    pre_master: [u8; 48],
    random1: [u8; 32],
    random2: [u8; 32],
}

struct ServerKeySource {
    random1: [u8; 32],
    random2: [u8; 32],
}

struct KeyState {
    key_id: u8,
    tls: ClientConnection,
    send_pid: u32,
    unacked: BTreeMap<u32, ()>,
    /// Control packets (opcode, payload) waiting for room in the window.
    queued: VecDeque<(u8, Vec<u8>)>,
    recv_next: u32,
    recv_ahead: BTreeMap<u32, Vec<u8>>,
    pending_acks: Vec<u32>,
    plaintext: Vec<u8>,
    tls_started: bool,
    km_sent: bool,
    client_src: ClientKeySource,
    server_src: Option<ServerKeySource>,
    data: Option<DataKeys>,
    started: Instant,
}

pub struct Session {
    cfg: Arc<Config>,
    tls_cfg: Arc<rustls::ClientConfig>,
    wrap: Wrap,
    local_sid: [u8; 8],
    remote_sid: Option<[u8; 8]>,
    keys: Vec<KeyState>,
    /// key_id used for sending data.
    primary: Option<u8>,
    creds: Option<Credentials>,
    auth_token: Option<String>,
    outgoing: VecDeque<Vec<u8>>,
    events: VecDeque<Event>,
    push_parts: Vec<String>,
    push: Option<PushReply>,
    last_push_request: Option<Instant>,
    cipher: Option<CipherKind>,
    pub last_recv: Instant,
    /// Use the TLS exporter for data keys if the server agrees (tests can
    /// turn this off to exercise the PRF path).
    pub offer_ekm: bool,
}

impl Session {
    pub fn new(
        cfg: Arc<Config>,
        tls_cfg: Arc<rustls::ClientConfig>,
        creds: Option<Credentials>,
    ) -> Session {
        let wrap = match &cfg.tls_wrap {
            TlsWrapKey::None => Wrap::None,
            TlsWrapKey::Auth(k, dir) => Wrap::tls_auth(k, *dir, cfg.auth),
            TlsWrapKey::Crypt(k) => Wrap::tls_crypt(k),
        };
        let mut local_sid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut local_sid);
        Session {
            cfg,
            tls_cfg,
            wrap,
            local_sid,
            remote_sid: None,
            keys: Vec::new(),
            primary: None,
            creds,
            auth_token: None,
            outgoing: VecDeque::new(),
            events: VecDeque::new(),
            push_parts: Vec::new(),
            push: None,
            last_push_request: None,
            cipher: None,
            last_recv: Instant::now(),
            offer_ekm: true,
        }
    }

    /// Sends the initial hard reset.
    pub fn start(&mut self) -> Result<()> {
        let ks = self.new_key_state(0)?;
        self.keys.push(ks);
        self.send_control(0, P_CONTROL_HARD_RESET_CLIENT_V2, Vec::new());
        Ok(())
    }

    pub fn take_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    pub fn take_events(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn is_connected(&self) -> bool {
        self.primary.is_some()
    }

    fn new_key_state(&self, key_id: u8) -> Result<KeyState> {
        let name = rustls_pki_types::ServerName::try_from("openvpn-server")?.to_owned();
        let tls = ClientConnection::new(self.tls_cfg.clone(), name)?;
        let mut rng = rand::thread_rng();
        let mut src = ClientKeySource {
            pre_master: [0; 48],
            random1: [0; 32],
            random2: [0; 32],
        };
        rng.fill_bytes(&mut src.pre_master);
        rng.fill_bytes(&mut src.random1);
        rng.fill_bytes(&mut src.random2);
        Ok(KeyState {
            key_id,
            tls,
            send_pid: 0,
            unacked: BTreeMap::new(),
            queued: VecDeque::new(),
            recv_next: 0,
            recv_ahead: BTreeMap::new(),
            pending_acks: Vec::new(),
            plaintext: Vec::new(),
            tls_started: false,
            km_sent: false,
            client_src: src,
            server_src: None,
            data: None,
            started: Instant::now(),
        })
    }

    fn key_index(&self, key_id: u8) -> Option<usize> {
        self.keys.iter().position(|k| k.key_id == key_id)
    }

    // -----------------------------------------------------------------------
    // Control channel output

    fn send_control(&mut self, key_id: u8, op: u8, payload: Vec<u8>) {
        let Some(i) = self.key_index(key_id) else {
            return;
        };
        self.keys[i].queued.push_back((op, payload));
        self.flush_queue(i);
    }

    fn flush_queue(&mut self, i: usize) {
        while self.keys[i].unacked.len() < SEND_WINDOW {
            let Some((op, payload)) = self.keys[i].queued.pop_front() else {
                break;
            };
            let ks = &mut self.keys[i];
            let pid = ks.send_pid;
            ks.send_pid += 1;
            ks.unacked.insert(pid, ());
            let n = ks.pending_acks.len().min(MAX_ACKS_PER_PACKET);
            let acks: Vec<u32> = ks.pending_acks.drain(..n).collect();
            let body = ControlBody {
                remote_sid: if acks.is_empty() {
                    None
                } else {
                    self.remote_sid
                },
                acks,
                packet_id: Some(pid),
                payload,
            };
            let key_id = ks.key_id;
            self.emit(op, key_id, &body);
        }
    }

    fn emit(&mut self, op: u8, key_id: u8, body: &ControlBody) {
        let mut op_sid = [0u8; 9];
        op_sid[0] = op_byte(op, key_id);
        op_sid[1..].copy_from_slice(&self.local_sid);
        let pkt = self.wrap.wrap(&op_sid, &body.encode());
        self.outgoing.push_back(pkt);
    }

    /// Sends any acks that did not ride along on a control packet.
    fn flush_acks(&mut self) {
        for i in 0..self.keys.len() {
            while !self.keys[i].pending_acks.is_empty() {
                let ks = &mut self.keys[i];
                let n = ks.pending_acks.len().min(MAX_ACKS_PER_PACKET);
                let acks: Vec<u32> = ks.pending_acks.drain(..n).collect();
                let key_id = ks.key_id;
                let body = ControlBody {
                    acks,
                    remote_sid: self.remote_sid,
                    packet_id: None,
                    payload: Vec::new(),
                };
                self.emit(P_ACK_V1, key_id, &body);
            }
        }
    }

    /// Moves TLS records produced by rustls into control packets.
    fn pump_tls_out(&mut self, i: usize) -> Result<()> {
        let mut buf = Vec::new();
        while self.keys[i].tls.wants_write() {
            self.keys[i].tls.write_tls(&mut buf)?;
        }
        let key_id = self.keys[i].key_id;
        for chunk in buf.chunks(MAX_CONTROL_PAYLOAD) {
            self.send_control(key_id, P_CONTROL_V1, chunk.to_vec());
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Input

    pub fn on_packet(&mut self, pkt: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(&first) = pkt.first() else {
            return Ok(None);
        };
        let op = opcode(first);
        let kid = key_id(first);
        self.last_recv = Instant::now();
        match op {
            P_DATA_V1 | P_DATA_V2 => {
                let header_len = if op == P_DATA_V2 { 4 } else { 1 };
                if pkt.len() < header_len {
                    return Ok(None);
                }
                let Some(i) = self.key_index(kid) else {
                    tracing::debug!("data packet for unknown key {kid}");
                    return Ok(None);
                };
                let Some(dk) = self.keys[i].data.as_mut() else {
                    return Ok(None);
                };
                let plain = match dk.decrypt(pkt, header_len) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!("dropping data packet: {e}");
                        return Ok(None);
                    }
                };
                let comp = self
                    .push
                    .as_ref()
                    .map(|p| p.compression)
                    .unwrap_or_default();
                let Some(ip) = comp.decompress(plain) else {
                    return Ok(None);
                };
                if ip == PING_MAGIC || ip.starts_with(&OCC_MAGIC) {
                    return Ok(None);
                }
                Ok(Some(ip))
            }
            P_CONTROL_HARD_RESET_SERVER_V2 | P_CONTROL_V1 | P_ACK_V1 | P_CONTROL_SOFT_RESET_V1 => {
                let body = match self.wrap.unwrap(pkt) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!("dropping control packet: {e}");
                        return Ok(None);
                    }
                };
                let sid: [u8; 8] = pkt[1..9].try_into().unwrap();
                let cb = ControlBody::decode(op, &body)?;
                self.on_control(op, kid, sid, cb)?;
                Ok(None)
            }
            P_CONTROL_HARD_RESET_CLIENT_V1 | P_CONTROL_HARD_RESET_SERVER_V1 => {
                bail!("server speaks the old key-method 1 protocol, which is not supported")
            }
            other => {
                tracing::debug!("ignoring opcode {other}");
                Ok(None)
            }
        }
    }

    fn on_control(&mut self, op: u8, kid: u8, sid: [u8; 8], cb: ControlBody) -> Result<()> {
        match self.remote_sid {
            None if op == P_CONTROL_HARD_RESET_SERVER_V2 => self.remote_sid = Some(sid),
            Some(s) if s == sid => {}
            _ => {
                tracing::debug!("control packet from unexpected session");
                return Ok(());
            }
        }
        if op == P_CONTROL_SOFT_RESET_V1 && self.key_index(kid).is_none() {
            tracing::info!("server started renegotiation (key {kid})");
            let ks = self.new_key_state(kid)?;
            self.keys.push(ks);
            // Keep the current key plus the new one.
            while self.keys.len() > 3 {
                let oldest = self
                    .keys
                    .iter()
                    .enumerate()
                    .filter(|(_, k)| Some(k.key_id) != self.primary && k.key_id != kid)
                    .min_by_key(|(_, k)| k.started)
                    .map(|(i, _)| i);
                match oldest {
                    Some(i) => {
                        self.keys.remove(i);
                    }
                    None => break,
                }
            }
            self.send_control(kid, P_CONTROL_SOFT_RESET_V1, Vec::new());
        }
        let Some(i) = self.key_index(kid) else {
            tracing::debug!("control packet for unknown key {kid}");
            return Ok(());
        };
        // Acks for our packets.
        for a in &cb.acks {
            self.keys[i].unacked.remove(a);
        }
        if let Some(pid) = cb.packet_id {
            let ks = &mut self.keys[i];
            if !ks.pending_acks.contains(&pid) {
                ks.pending_acks.push(pid);
            }
            if pid >= ks.recv_next {
                ks.recv_ahead.insert(pid, cb.payload);
            }
            // Deliver in order.
            while let Some(p) = ks.recv_ahead.remove(&ks.recv_next) {
                ks.recv_next += 1;
                if !p.is_empty() {
                    let mut rd: &[u8] = &p;
                    while !rd.is_empty() {
                        ks.tls.read_tls(&mut rd)?;
                    }
                }
            }
        }
        self.advance(i)?;
        self.flush_queue(i);
        self.flush_acks();
        Ok(())
    }

    /// Drives TLS and the key exchange for key state `i` as far as it goes.
    fn advance(&mut self, i: usize) -> Result<()> {
        // Server's reset arrived: start the TLS handshake.
        if !self.keys[i].tls_started && self.keys[i].recv_next > 0 {
            self.keys[i].tls_started = true;
        }
        if !self.keys[i].tls_started {
            return Ok(());
        }
        let state = self.keys[i]
            .tls
            .process_new_packets()
            .map_err(|e| anyhow!("TLS handshake with the server failed: {e}"))?;
        if state.plaintext_bytes_to_read() > 0 {
            let mut buf = vec![0u8; state.plaintext_bytes_to_read()];
            self.keys[i].tls.reader().read_exact(&mut buf)?;
            self.keys[i].plaintext.extend_from_slice(&buf);
        }
        if !self.keys[i].tls.is_handshaking() && !self.keys[i].km_sent {
            self.keys[i].km_sent = true;
            let msg = self.key_method_2(i);
            self.keys[i].tls.writer().write_all(&msg)?;
            tracing::debug!(key = self.keys[i].key_id, "TLS up, sent key-method 2");
        }
        self.pump_tls_out(i)?;
        self.read_plaintext(i)?;
        Ok(())
    }

    fn key_method_2(&self, i: usize) -> Vec<u8> {
        let ks = &self.keys[i];
        let mut m = Vec::new();
        m.extend_from_slice(&0u32.to_be_bytes());
        m.push(2);
        m.extend_from_slice(&ks.client_src.pre_master);
        m.extend_from_slice(&ks.client_src.random1);
        m.extend_from_slice(&ks.client_src.random2);
        write_string(&mut m, &self.options_string());
        match &self.creds {
            Some(c) => {
                write_string(&mut m, &c.username);
                write_string(&mut m, self.auth_token.as_deref().unwrap_or(&c.password));
            }
            None => {
                m.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
        write_string(&mut m, &self.peer_info());
        m
    }

    fn options_string(&self) -> String {
        let wrap = match self.cfg.tls_wrap {
            TlsWrapKey::Auth(..) => ",tls-auth",
            _ => "",
        };
        format!(
            "V4,dev-type tun,link-mtu 1559,tun-mtu {},proto TCPv4_CLIENT,keydir 1,cipher AES-256-GCM,auth {},keysize 256{wrap},key-method 2,tls-client",
            self.cfg.tun_mtu,
            self.cfg.auth.name()
        )
    }

    fn peer_info(&self) -> String {
        let plat = if cfg!(windows) { "win" } else { "linux" };
        // IV_PROTO: 2 = DATA_V2, 8 = TLS key export.
        let proto = if self.offer_ekm { 2 | 8 } else { 2 };
        format!(
            "IV_VER=2.6.12\nIV_PLAT={plat}\nIV_PROTO={proto}\nIV_NCP=2\n\
             IV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-128-CBC\n\
             IV_TCPNL=1\nIV_LZO_STUB=1\nIV_COMP_STUB=1\nIV_COMP_STUBv2=1\n\
             IV_GUI_VER=ovpn-rs_{}\n",
            env!("CARGO_PKG_VERSION")
        )
    }

    fn read_plaintext(&mut self, i: usize) -> Result<()> {
        if self.keys[i].server_src.is_none() {
            let p = &self.keys[i].plaintext;
            // u32 0, u8 key method, random1, random2, options string.
            if p.len() < 69 + 2 {
                return Ok(());
            }
            if p[4] != 2 {
                bail!("server uses key method {}, need 2", p[4]);
            }
            let olen = u16::from_be_bytes([p[69], p[70]]) as usize;
            if p.len() < 71 + olen {
                return Ok(());
            }
            let src = ServerKeySource {
                random1: p[5..37].try_into().unwrap(),
                random2: p[37..69].try_into().unwrap(),
            };
            tracing::debug!(
                "server options: {}",
                String::from_utf8_lossy(&p[71..71 + olen]).trim_end_matches('\0')
            );
            // The rest of the key-method reply (empty user/pass/peer-info
            // strings) carries nothing we need; text messages are
            // NUL-terminated, so leftover zero bytes are harmless.
            self.keys[i].plaintext.clear();
            self.keys[i].server_src = Some(src);
            if self.push.is_none() {
                self.send_push_request(i)?;
            } else {
                // A renegotiated key: derive its data keys right away.
                self.derive_data_keys(i)?;
                let kid = self.keys[i].key_id;
                self.primary = Some(kid);
                self.events.push_back(Event::Rekeyed(kid));
            }
        }
        // NUL-terminated control messages.
        while let Some(pos) = self.keys[i].plaintext.iter().position(|&b| b == 0) {
            let msg: Vec<u8> = self.keys[i].plaintext.drain(..=pos).collect();
            let msg = String::from_utf8_lossy(&msg[..msg.len() - 1]).into_owned();
            if !msg.is_empty() {
                self.on_message(i, &msg)?;
            }
        }
        Ok(())
    }

    fn send_push_request(&mut self, i: usize) -> Result<()> {
        self.keys[i].tls.writer().write_all(b"PUSH_REQUEST\0")?;
        self.last_push_request = Some(Instant::now());
        self.pump_tls_out(i)
    }

    fn on_message(&mut self, i: usize, msg: &str) -> Result<()> {
        if let Some(rest) = msg.strip_prefix("PUSH_REPLY") {
            if self.push.is_some() {
                return Ok(());
            }
            let rest = rest.trim_start_matches(',');
            let more = rest.split(',').any(|o| o.trim() == "push-continuation 2");
            self.push_parts.push(rest.to_string());
            if more {
                return Ok(());
            }
            let push = PushReply::parse(&self.push_parts.join(","), &self.cfg)?;
            self.push_parts.clear();
            if let Some(t) = &push.auth_token {
                self.auth_token = Some(t.clone());
            }
            let cipher = push
                .cipher
                .clone()
                .or_else(|| self.cfg.cipher.clone())
                .ok_or_else(|| anyhow!("server did not push a cipher and the config has none"))?;
            self.cipher = Some(
                CipherKind::parse(&cipher)
                    .ok_or_else(|| anyhow!("data cipher {cipher} is not supported"))?,
            );
            self.push = Some(push);
            self.derive_data_keys(i)?;
            self.primary = Some(self.keys[i].key_id);
            let push = self.push.clone().unwrap();
            self.events.push_back(Event::Connected(Box::new(push)));
        } else if let Some(r) = msg.strip_prefix("AUTH_FAILED") {
            let r = r.trim_start_matches(',');
            self.events.push_back(Event::AuthFailed(if r.is_empty() {
                "the server rejected the username or password".into()
            } else {
                r.to_string()
            }));
        } else if msg.starts_with("RESTART") {
            self.events.push_back(Event::Restart(msg.to_string()));
        } else if msg.starts_with("HALT") {
            self.events.push_back(Event::Halt(msg.to_string()));
        } else if let Some(info) = msg.strip_prefix("INFO") {
            tracing::info!("server: {}", info.trim_start_matches(','));
        } else {
            tracing::debug!("control message: {msg}");
        }
        Ok(())
    }

    fn derive_data_keys(&mut self, i: usize) -> Result<()> {
        let cipher = self.cipher.context("no data cipher negotiated")?;
        let ekm = self.offer_ekm && self.push.as_ref().is_some_and(|p| p.tls_ekm);
        let mut block = [0u8; 256];
        let ks = &self.keys[i];
        if ekm {
            ks.tls
                .export_keying_material(&mut block, b"EXPORTER-OpenVPN-datakeys", None)
                .map_err(|e| anyhow!("TLS key export: {e}"))?;
        } else {
            let srv = ks.server_src.as_ref().context("no server key source")?;
            let remote_sid = self.remote_sid.context("no server session id")?;
            let mut master = [0u8; 48];
            openvpn_prf(
                &ks.client_src.pre_master,
                "OpenVPN master secret",
                &ks.client_src.random1,
                &srv.random1,
                None,
                &mut master,
            );
            openvpn_prf(
                &master,
                "OpenVPN key expansion",
                &ks.client_src.random2,
                &srv.random2,
                Some((&self.local_sid, &remote_sid)),
                &mut block,
            );
        }
        tracing::debug!(
            key = ks.key_id,
            ekm,
            cipher = cipher.name(),
            "data keys ready"
        );
        self.keys[i].data = Some(DataKeys::new(cipher, self.cfg.auth, &block));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Data channel output

    pub fn encrypt(&mut self, ip: &[u8]) -> Result<()> {
        let Some(kid) = self.primary else {
            return Ok(());
        };
        let Some(i) = self.key_index(kid) else {
            return Ok(());
        };
        let push = self.push.as_ref().context("not connected")?;
        let payload = push.compression.compress(ip);
        let header: Vec<u8> = match push.peer_id {
            Some(id) => {
                let b = id.to_be_bytes();
                vec![op_byte(P_DATA_V2, kid), b[1], b[2], b[3]]
            }
            None => vec![op_byte(P_DATA_V1, kid)],
        };
        let dk = self.keys[i].data.as_mut().context("no data keys")?;
        let pkt = dk.encrypt(&header, &payload)?;
        self.outgoing.push_back(pkt);
        Ok(())
    }

    pub fn send_ping(&mut self) -> Result<()> {
        self.encrypt(&PING_MAGIC)
    }

    /// Periodic work: PUSH_REQUEST retries and handshake timeouts.
    pub fn tick(&mut self) -> Result<()> {
        if self.push.is_none() {
            if let Some(t) = self.last_push_request {
                if t.elapsed() > Duration::from_secs(2) {
                    if let Some(i) = self.keys.iter().position(|k| k.server_src.is_some()) {
                        self.send_push_request(i)?;
                    }
                }
            }
            if let Some(k) = self.keys.first() {
                if k.started.elapsed() > Duration::from_secs(60) {
                    bail!("no reply from the server within 60 s (TLS handshake or push did not complete)");
                }
            }
        }
        Ok(())
    }
}

/// OpenVPN's length-prefixed, NUL-terminated string.
fn write_string(buf: &mut Vec<u8>, s: &str) {
    let len = s.len() + 1;
    buf.extend_from_slice(&(len as u16).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

//! Parser for the subset of .ovpn client configs that this client supports.
//!
//! Unknown directives are ignored (with a debug log), so a typical provider
//! config loads as is. File references (`ca ca.crt`) are resolved relative
//! to the config file; inline `<ca>...</ca>` blocks work too.

use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Remote {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Digest {
    pub fn parse(s: &str) -> Result<Digest> {
        Ok(match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Digest::Sha1,
            "SHA256" => Digest::Sha256,
            "SHA384" => Digest::Sha384,
            "SHA512" => Digest::Sha512,
            _ => bail!("unsupported auth digest {s:?}"),
        })
    }

    pub fn len(self) -> usize {
        match self {
            Digest::Sha1 => 20,
            Digest::Sha256 => 32,
            Digest::Sha384 => 48,
            Digest::Sha512 => 64,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Digest::Sha1 => "SHA1",
            Digest::Sha256 => "SHA256",
            Digest::Sha384 => "SHA384",
            Digest::Sha512 => "SHA512",
        }
    }
}

/// An OpenVPN static key (the 2048-bit `tls-auth` / `tls-crypt` key file).
#[derive(Clone)]
pub struct StaticKey(pub [u8; 256]);

impl StaticKey {
    pub fn parse(text: &str) -> Result<StaticKey> {
        let mut in_key = false;
        let mut hex_str = String::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with("-----BEGIN OpenVPN Static key") {
                in_key = true;
            } else if line.starts_with("-----END OpenVPN Static key") {
                break;
            } else if in_key {
                hex_str.push_str(line);
            }
        }
        let bytes = hex::decode(&hex_str).context("static key is not valid hex")?;
        let key: [u8; 256] = bytes
            .try_into()
            .map_err(|b: Vec<u8>| anyhow!("static key is {} bytes, want 256", b.len()))?;
        Ok(StaticKey(key))
    }

    /// One of the four 64-byte slots: cipher0, hmac0, cipher1, hmac1.
    pub fn slot(&self, i: usize) -> &[u8] {
        &self.0[i * 64..(i + 1) * 64]
    }
}

#[derive(Clone)]
pub enum TlsWrapKey {
    None,
    /// `tls-auth`, with its key-direction (None = bidirectional).
    Auth(StaticKey, Option<u8>),
    Crypt(StaticKey),
}

#[derive(Clone)]
pub struct Config {
    pub remotes: Vec<Remote>,
    pub remote_random: bool,
    pub ca_pem: String,
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub tls_wrap: TlsWrapKey,
    pub auth: Digest,
    /// `cipher` (fallback for servers without cipher negotiation).
    pub cipher: Option<String>,
    pub data_ciphers: Vec<String>,
    pub auth_user_pass: bool,
    /// Credentials file named by `auth-user-pass <file>`, or inline block.
    pub auth_file: Option<AuthSource>,
    pub verify_x509_name: Option<(String, String)>,
    pub remote_cert_tls_server: bool,
    pub tun_mtu: u16,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub comp_lzo: bool,
    pub compress: Option<String>,
}

#[derive(Clone)]
pub enum AuthSource {
    File(PathBuf),
    Inline(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let dir = path.parent().unwrap_or(Path::new("."));
        Config::parse(&text, dir)
    }

    pub fn parse(text: &str, dir: &Path) -> Result<Config> {
        let mut c = Config {
            remotes: Vec::new(),
            remote_random: false,
            ca_pem: String::new(),
            cert_pem: None,
            key_pem: None,
            tls_wrap: TlsWrapKey::None,
            auth: Digest::Sha1,
            cipher: None,
            data_ciphers: Vec::new(),
            auth_user_pass: false,
            auth_file: None,
            verify_x509_name: None,
            remote_cert_tls_server: false,
            tun_mtu: 1500,
            ping: None,
            ping_restart: None,
            comp_lzo: false,
            compress: None,
        };
        let mut proto: Option<String> = None;
        let mut port: u16 = 1194;
        let mut key_direction: Option<u8> = None;
        let mut tls_auth_dir: Option<u8> = None;
        let mut tls_auth: Option<String> = None;
        let mut tls_crypt: Option<String> = None;
        let mut remote_specs: Vec<(String, Option<u16>, Option<String>)> = Vec::new();

        let read_ref = |name: &str| -> Result<String> {
            let p = dir.join(name);
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
        };

        let mut lines = text.lines();
        while let Some(raw) = lines.next() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            // Inline blocks: <ca> ... </ca>
            if let Some(tag) = line.strip_prefix('<').and_then(|l| l.strip_suffix('>')) {
                if tag.starts_with('/') {
                    continue;
                }
                let end = format!("</{tag}>");
                let mut body = String::new();
                for l in lines.by_ref() {
                    if l.trim() == end {
                        break;
                    }
                    body.push_str(l);
                    body.push('\n');
                }
                match tag {
                    "ca" => c.ca_pem = body,
                    "cert" => c.cert_pem = Some(body),
                    "key" => c.key_pem = Some(body),
                    "tls-auth" => tls_auth = Some(body),
                    "tls-crypt" => tls_crypt = Some(body),
                    "tls-crypt-v2" => bail!("tls-crypt-v2 is not supported yet"),
                    "auth-user-pass" => {
                        c.auth_user_pass = true;
                        c.auth_file = Some(AuthSource::Inline(body));
                    }
                    other => tracing::debug!("ignoring inline block <{other}>"),
                }
                continue;
            }

            let args = split_args(line);
            let Some((name, a)) = args.split_first() else {
                continue;
            };
            let arg = |i: usize| a.get(i).map(String::as_str);
            match name.as_str() {
                "remote" => {
                    let host = arg(0).ok_or_else(|| anyhow!("remote needs a host"))?;
                    let p = arg(1).map(str::parse).transpose().context("remote port")?;
                    remote_specs.push((host.to_string(), p, arg(2).map(str::to_string)));
                }
                "port" | "rport" => port = arg(0).unwrap_or("1194").parse().context("port")?,
                "proto" => proto = arg(0).map(str::to_string),
                "remote-random" => c.remote_random = true,
                "ca" => c.ca_pem = read_ref(arg(0).unwrap_or(""))?,
                "cert" => c.cert_pem = Some(read_ref(arg(0).unwrap_or(""))?),
                "key" => c.key_pem = Some(read_ref(arg(0).unwrap_or(""))?),
                "tls-auth" => {
                    if let Some(f) = arg(0) {
                        if f != "[inline]" {
                            tls_auth = Some(read_ref(f)?);
                        }
                    }
                    tls_auth_dir = arg(1).map(str::parse).transpose().context("tls-auth dir")?;
                }
                "tls-crypt" => {
                    if let Some(f) = arg(0) {
                        if f != "[inline]" {
                            tls_crypt = Some(read_ref(f)?);
                        }
                    }
                }
                "tls-crypt-v2" => bail!("tls-crypt-v2 is not supported yet"),
                "key-direction" => {
                    key_direction = arg(0)
                        .map(str::parse)
                        .transpose()
                        .context("key-direction")?
                }
                "auth" => c.auth = Digest::parse(arg(0).unwrap_or("SHA1"))?,
                "cipher" => c.cipher = arg(0).map(str::to_string),
                "data-ciphers" | "ncp-ciphers" => {
                    c.data_ciphers = arg(0)
                        .unwrap_or("")
                        .split(':')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                }
                "auth-user-pass" => {
                    c.auth_user_pass = true;
                    if let Some(f) = arg(0) {
                        c.auth_file = Some(AuthSource::File(dir.join(f)));
                    }
                }
                "verify-x509-name" => {
                    if let Some(n) = arg(0) {
                        let kind = arg(1).unwrap_or("subject").to_string();
                        c.verify_x509_name = Some((n.to_string(), kind));
                    }
                }
                "remote-cert-tls" => c.remote_cert_tls_server = arg(0) == Some("server"),
                "tun-mtu" => c.tun_mtu = arg(0).unwrap_or("1500").parse().context("tun-mtu")?,
                "ping" => c.ping = arg(0).map(str::parse).transpose().context("ping")?,
                "ping-restart" => {
                    c.ping_restart = arg(0).map(str::parse).transpose().context("ping-restart")?
                }
                "keepalive" => {
                    c.ping = arg(0).map(str::parse).transpose().context("keepalive")?;
                    c.ping_restart = arg(1).map(str::parse).transpose().context("keepalive")?;
                }
                "comp-lzo" => c.comp_lzo = true,
                "compress" => c.compress = Some(arg(0).unwrap_or("").to_string()),
                "dev" => {
                    if !arg(0).unwrap_or("tun").starts_with("tun") {
                        bail!(
                            "only `dev tun` is supported (config has `dev {}`)",
                            arg(0).unwrap_or("")
                        );
                    }
                }
                "http-proxy" | "socks-proxy" => bail!("{name} is not supported yet"),
                "pkcs12" => bail!("pkcs12 is not supported; use inline <cert>/<key>"),
                other => tracing::debug!("ignoring directive {other}"),
            }
        }

        for (host, p, pr) in remote_specs {
            let pr = pr.or_else(|| proto.clone()).unwrap_or_else(|| "udp".into());
            if !pr.starts_with("tcp") {
                tracing::warn!("skipping remote {host} ({pr}): only TCP is supported");
                continue;
            }
            c.remotes.push(Remote {
                host,
                port: p.unwrap_or(port),
            });
        }
        if c.remotes.is_empty() {
            bail!("no TCP `remote` in the config (this client only does TCP; download the TCP version of the config)");
        }
        if c.ca_pem.trim().is_empty() {
            bail!("the config has no CA certificate (`ca` or <ca>)");
        }
        c.tls_wrap = if let Some(k) = tls_crypt {
            TlsWrapKey::Crypt(StaticKey::parse(&k).context("tls-crypt key")?)
        } else if let Some(k) = tls_auth {
            TlsWrapKey::Auth(
                StaticKey::parse(&k).context("tls-auth key")?,
                tls_auth_dir.or(key_direction),
            )
        } else {
            TlsWrapKey::None
        };
        if c.cert_pem.is_some() != c.key_pem.is_some() {
            bail!("the config has a client cert without a key, or the other way round");
        }
        if !c.auth_user_pass && c.cert_pem.is_none() {
            bail!("the config has neither auth-user-pass nor a client certificate");
        }
        Ok(c)
    }
}

/// Splits a config line into words, honouring double quotes and backslashes.
fn split_args(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quote = false;
    let mut has = false;
    let mut chars = line.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quote = !in_quote;
                has = true;
            }
            '\\' if in_quote => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '#' | ';' if !in_quote && !has && cur.is_empty() => break,
            c if c.is_whitespace() && !in_quote => {
                if has || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "-----BEGIN OpenVPN Static key V1-----\n";

    fn key_block() -> String {
        let mut s = String::from(KEY);
        for _ in 0..16 {
            s.push_str(&"ab".repeat(16));
            s.push('\n');
        }
        s.push_str("-----END OpenVPN Static key V1-----\n");
        s
    }

    #[test]
    fn parses_windscribe_style() {
        let text = format!(
            "client\ndev tun\nproto tcp\nremote in-021.windscribe.com 443\n\
             cipher AES-256-GCM\nauth SHA512\nkey-direction 1\nauth-user-pass\n\
             <ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n</ca>\n\
             <tls-auth>\n{}</tls-auth>\n",
            key_block()
        );
        let c = Config::parse(&text, Path::new(".")).unwrap();
        assert_eq!(c.remotes[0].host, "in-021.windscribe.com");
        assert_eq!(c.remotes[0].port, 443);
        assert_eq!(c.auth, Digest::Sha512);
        assert!(matches!(c.tls_wrap, TlsWrapKey::Auth(_, Some(1))));
        assert!(c.auth_user_pass);
    }

    #[test]
    fn rejects_udp_only() {
        let text = "remote x 1194 udp\nauth-user-pass\n<ca>\nX\n</ca>\n";
        assert!(Config::parse(text, Path::new(".")).is_err());
    }

    #[test]
    fn split_quotes() {
        assert_eq!(
            split_args(r#"verify-x509-name "C=US, CN=a b" subject"#),
            vec!["verify-x509-name", "C=US, CN=a b", "subject"]
        );
    }
}

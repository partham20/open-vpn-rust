//! ovpn: a small, portable OpenVPN client. One executable, a provider's
//! .ovpn file, and a username/password; it connects over TCP and routes
//! traffic through the VPN.

mod config;
mod console;
mod crypto;
mod icmp;
mod packet;
mod push;
mod routes;
mod session;
mod tls;
mod tun;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use config::{AuthSource, Config};
use push::PushReply;
use routes::{RouteSpec, Routes};
use session::{Credentials, Event, Session};

#[derive(Parser, Debug)]
#[command(version, about = "A small portable OpenVPN client (TCP only)")]
struct Args {
    /// The .ovpn config file. Defaults to the only .ovpn file next to the exe
    /// or in the current folder.
    config: Option<PathBuf>,

    /// File with the username on the first line and the password on the
    /// second (the same format as OpenVPN's auth-user-pass file). Without it
    /// you are asked at a prompt.
    #[arg(long)]
    auth_file: Option<PathBuf>,

    /// Don't create a network adapter; only test the tunnel (use with --ping).
    #[arg(long)]
    no_tun: bool,

    /// With --no-tun: ping this address through the tunnel (default: the VPN gateway).
    #[arg(long)]
    ping: Option<Ipv4Addr>,

    /// With --no-tun: stop after this many ping replies.
    #[arg(long, default_value_t = 4)]
    count: u32,

    /// Don't send all internet traffic through the VPN; only pushed routes.
    #[arg(long)]
    no_redirect: bool,

    /// Don't change DNS servers.
    #[arg(long)]
    no_dns: bool,

    /// Name of the network adapter.
    #[arg(long, default_value = "OpenVPN-rs")]
    adapter: String,

    /// More logging (-v debug, -vv trace).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Derive data keys with the old PRF even if the server supports tls-ekm.
    #[arg(long, hide = true)]
    no_ekm: bool,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    if !args.no_tun && !console::is_admin() {
        if console::own_console() && console::relaunch_elevated() {
            return std::process::ExitCode::SUCCESS;
        }
        eprintln!("error: ovpn needs Administrator rights to create the network adapter.");
        eprintln!("Run it from an Administrator terminal (or use --no-tun --ping 1.1.1.1 to test without one).");
        console::pause_if_own_console();
        return std::process::ExitCode::FAILURE;
    }
    let level = match args.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("ovpn={level},warn").into()),
        )
        .with_target(false)
        .init();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let code = match rt.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    };
    console::pause_if_own_console();
    code
}

fn find_config() -> Result<PathBuf> {
    let mut dirs = vec![std::env::current_dir()?];
    if let Some(d) = std::env::current_exe()?.parent() {
        dirs.push(d.to_path_buf());
    }
    for d in dirs {
        let found: Vec<PathBuf> = std::fs::read_dir(&d)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("ovpn"))
            })
            .collect();
        match found.len() {
            0 => continue,
            1 => return Ok(found[0].clone()),
            _ => bail!(
                "several .ovpn files in {}; name the one to use: ovpn <file.ovpn>",
                d.display()
            ),
        }
    }
    bail!("no .ovpn file given; usage: ovpn <file.ovpn>")
}

fn read_auth_file(text: &str) -> Result<Credentials> {
    let mut lines = text.lines().map(str::trim);
    let username = lines.next().unwrap_or("").to_string();
    let password = lines.next().unwrap_or("").to_string();
    if username.is_empty() {
        bail!("the credentials file is empty (want username on line 1, password on line 2)");
    }
    Ok(Credentials { username, password })
}

fn credentials(args: &Args, cfg: &Config) -> Result<Option<Credentials>> {
    if !cfg.auth_user_pass {
        return Ok(None);
    }
    if let Some(p) = &args.auth_file {
        let t = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        return read_auth_file(&t).map(Some);
    }
    match &cfg.auth_file {
        Some(AuthSource::File(p)) => {
            let t =
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            return read_auth_file(&t).map(Some);
        }
        Some(AuthSource::Inline(t)) => return read_auth_file(t).map(Some),
        None => {}
    }
    eprint!("Username: ");
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let password = rpassword::prompt_password("Password: ")?;
    Ok(Some(Credentials {
        username: username.trim().to_string(),
        password,
    }))
}

async fn run(args: Args) -> Result<()> {
    let path = match &args.config {
        Some(p) => p.clone(),
        None => find_config()?,
    };
    let cfg = Arc::new(Config::load(&path)?);
    tracing::info!("config {}", path.display());
    let tls_cfg = tls::client_config(&cfg)?;
    let creds = credentials(&args, &cfg)?;
    let creds = creds.map(Arc::new);

    let mut tun: Option<tun::Tun> = None;
    let mut backoff = Duration::from_secs(2);
    let mut remotes = cfg.remotes.clone();
    if cfg.remote_random {
        remotes.shuffle(&mut rand::thread_rng());
    }
    let mut attempt = 0usize;
    loop {
        let remote = &remotes[attempt % remotes.len()];
        attempt += 1;
        let started = Instant::now();
        let creds = creds.as_ref().map(|c| Credentials {
            username: c.username.clone(),
            password: c.password.clone(),
        });
        let res = tokio::select! {
            r = connect_once(&args, &cfg, &tls_cfg, creds, &remote.host, remote.port, &mut tun) => r,
            _ = tokio::signal::ctrl_c() => Ok(Outcome::Stop),
        };
        match res {
            Ok(Outcome::Stop) => {
                tracing::info!("disconnected");
                return Ok(());
            }
            Ok(Outcome::Reconnect(why)) => tracing::warn!("connection lost ({why}); reconnecting"),
            Err(e) => {
                if e.downcast_ref::<Fatal>().is_some() {
                    return Err(e);
                }
                tracing::warn!("{e:#}");
            }
        }
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(2);
        }
        tracing::info!("retrying in {} s", backoff.as_secs());
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Errors that a reconnect will not fix.
#[derive(Debug)]
struct Fatal(String);

impl std::fmt::Display for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

enum Outcome {
    Stop,
    Reconnect(String),
}

async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}"))?
        .collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
        .ok_or_else(|| anyhow!("{host} has no addresses"))
}

/// The ping target and our address in --no-tun mode.
struct Pinger {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    seq: u16,
    sent: std::collections::HashMap<u16, Instant>,
    replies: u32,
}

async fn connect_once(
    args: &Args,
    cfg: &Arc<Config>,
    tls_cfg: &Arc<rustls::ClientConfig>,
    creds: Option<Credentials>,
    host: &str,
    port: u16,
    tun_slot: &mut Option<tun::Tun>,
) -> Result<Outcome> {
    let addr = resolve(host, port).await?;
    tracing::info!("connecting to {host} ({addr}) over TCP");
    let stream = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow!("TCP connect to {addr} timed out"))?
        .with_context(|| format!("TCP connect to {addr}"))?;
    stream.set_nodelay(true)?;
    let (mut rd, mut wr) = stream.into_split();

    // Reader: length-prefixed packets from the server.
    let (frame_tx, mut frames) = mpsc::channel::<Vec<u8>>(1024);
    let reader = tokio::spawn(async move {
        let mut len = [0u8; 2];
        loop {
            if rd.read_exact(&mut len).await.is_err() {
                return;
            }
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if rd.read_exact(&mut buf).await.is_err() || frame_tx.send(buf).await.is_err() {
                return;
            }
        }
    });
    // Writer: one task owns the socket's write half.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1024);
    let writer = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            let mut f = Vec::with_capacity(pkt.len() + 2);
            f.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
            f.extend_from_slice(&pkt);
            if wr.write_all(&f).await.is_err() {
                return;
            }
        }
    });
    let _guard = AbortOnDrop(vec![reader, writer]);

    let mut s = Session::new(cfg.clone(), tls_cfg.clone(), creds);
    s.offer_ekm = !args.no_ekm;
    s.start()?;

    // Held until this connection ends; dropping it removes the routes.
    let mut _routes: Option<Routes> = None;
    let mut push: Option<PushReply> = None;
    let mut pinger: Option<Pinger> = None;
    let mut ping_every = Duration::from_secs(10);
    let mut restart_after = Duration::from_secs(120);
    let mut last_ping_sent = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    // A placeholder channel for when there is no TUN yet.
    let (_idle_tx, mut idle_rx) = mpsc::channel::<Vec<u8>>(1);

    loop {
        // Send whatever the session produced.
        while let Some(p) = s.take_outgoing() {
            if out_tx.send(p).await.is_err() {
                return Ok(Outcome::Reconnect("socket closed".into()));
            }
        }
        while let Some(ev) = s.take_events() {
            match ev {
                Event::Connected(p) => {
                    let p = *p;
                    ping_every = Duration::from_secs(p.ping.or(cfg.ping).unwrap_or(10).max(1));
                    restart_after =
                        Duration::from_secs(p.ping_restart.or(cfg.ping_restart).unwrap_or(120).max(10));
                    let local = p
                        .local_ip
                        .ok_or_else(|| anyhow!("server pushed no ifconfig address"))?;
                    tracing::debug!("push: {}", p.raw);
                    if args.no_tun {
                        let dst = args
                            .ping
                            .or(p.gateway())
                            .ok_or_else(|| anyhow!("no --ping target and no VPN gateway"))?;
                        tracing::info!("connected: VPN address {local}; pinging {dst} through the tunnel");
                        pinger = Some(Pinger {
                            src: local,
                            dst,
                            id: rand::random(),
                            seq: 0,
                            sent: Default::default(),
                            replies: 0,
                        });
                    } else {
                        if tun_slot.is_none() {
                            let mtu = p.tun_mtu.unwrap_or(cfg.tun_mtu);
                            *tun_slot = Some(tun::create(&args.adapter, mtu).map_err(|e| Fatal(format!("{e:#}")))?);
                        }
                        let dev = &tun_slot.as_ref().unwrap().device;
                        dev.set_address(local, p.prefix_len())?;
                        _routes = Some(Routes::apply(dev, &route_specs(&p, addr, args.no_redirect))?);
                        if !args.no_dns && !p.dns.is_empty() {
                            if let Err(e) = dev.set_dns(&p.dns) {
                                tracing::warn!("{e:#}");
                            }
                        }
                        let all = p.redirect_gateway && !args.no_redirect;
                        tracing::info!(
                            "connected: VPN address {local}/{}, DNS {:?}{}",
                            p.prefix_len(),
                            p.dns,
                            if all { ", all traffic goes through the VPN" } else { "" }
                        );
                        println!("Connected. Press Ctrl+C to disconnect.");
                    }
                    push = Some(p);
                }
                Event::Rekeyed(k) => tracing::debug!("switched to renegotiated key {k}"),
                Event::AuthFailed(why) => {
                    return Err(Fatal(format!(
                        "authentication failed: {why} (Windscribe needs the OpenVPN username/password from its config generator page, not your account login)"
                    ))
                    .into())
                }
                Event::Restart(m) => return Ok(Outcome::Reconnect(format!("server sent {m}"))),
                Event::Halt(m) => return Err(Fatal(format!("server sent {m}")).into()),
            }
        }

        let from_os = match tun_slot.as_mut() {
            Some(t) if push.is_some() => &mut t.from_os,
            _ => &mut idle_rx,
        };
        tokio::select! {
            f = frames.recv() => {
                let Some(f) = f else {
                    return Ok(Outcome::Reconnect("server closed the connection".into()));
                };
                if let Some(ip) = s.on_packet(&f)? {
                    if let Some(pg) = pinger.as_mut() {
                        if let Some((src, seq)) = icmp::parse_echo_reply(&ip, pg.id) {
                            if let Some(t) = pg.sent.remove(&seq) {
                                pg.replies += 1;
                                println!("reply from {src}: seq={seq} time={:.1} ms", t.elapsed().as_secs_f64() * 1000.0);
                                if pg.replies >= args.count {
                                    return Ok(Outcome::Stop);
                                }
                            }
                        }
                    } else if let Some(t) = tun_slot.as_ref() {
                        let _ = t.to_os.try_send(ip);
                    }
                }
            }
            p = from_os.recv() => {
                if let Some(p) = p {
                    s.encrypt(&p)?;
                }
            }
            _ = tick.tick() => {
                s.tick()?;
                if s.is_connected() {
                    if last_ping_sent.elapsed() >= ping_every {
                        s.send_ping()?;
                        last_ping_sent = Instant::now();
                    }
                    if s.last_recv.elapsed() > restart_after {
                        return Ok(Outcome::Reconnect(format!("nothing from the server for {} s", restart_after.as_secs())));
                    }
                    if let Some(pg) = pinger.as_mut() {
                        pg.seq = pg.seq.wrapping_add(1);
                        pg.sent.insert(pg.seq, Instant::now());
                        s.encrypt(&icmp::echo_request(pg.src, pg.dst, pg.id, pg.seq))?;
                    }
                }
            }
        }
    }
}

fn route_specs(p: &PushReply, server: SocketAddr, no_redirect: bool) -> Vec<RouteSpec> {
    let mut v = Vec::new();
    let redirect = p.redirect_gateway && !no_redirect;
    if redirect {
        if let IpAddr::V4(ip) = server.ip() {
            // Keep the VPN connection itself off the tunnel.
            v.push(RouteSpec {
                dest: ip,
                prefix: 32,
                via_tunnel: false,
            });
        }
        for half in [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)] {
            v.push(RouteSpec {
                dest: half,
                prefix: 1,
                via_tunnel: true,
            });
        }
    }
    for r in &p.routes {
        let prefix = u32::from(r.mask).count_ones() as u8;
        let net = Ipv4Addr::from(u32::from(r.net) & u32::from(r.mask));
        v.push(RouteSpec {
            dest: net,
            prefix,
            via_tunnel: true,
        });
    }
    v
}

struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

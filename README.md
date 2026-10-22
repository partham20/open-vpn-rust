# ovpn: a portable OpenVPN client in Rust

One `ovpn.exe`, your provider's `.ovpn` file, and a username/password. It
connects over **TCP**, creates a Wintun network adapter, and sends your
internet traffic through the VPN. No installer and no OpenVPN service. The
Wintun driver DLL is built into the exe and written next to it on first run.

Tested against OpenVPN 2.6 servers. Made with Windscribe's configs in mind.

## Quick start (Windows, Windscribe)

1. Download `ovpn.exe` from the [latest release](https://github.com/partham20/open-vpn-rust/releases/latest).
2. On windscribe.com open **Config Generators → OpenVPN**, pick a location,
   choose **TCP** (port 443 works on most networks), and download the `.ovpn`
   file. On the same page, click **Get Credentials**. These OpenVPN
   credentials are *not* your Windscribe account login.
3. Put the `.ovpn` file in the same folder as `ovpn.exe`.
4. Double-click `ovpn.exe` and approve the admin prompt. Or, in an
   Administrator PowerShell:

   ```powershell
   .\ovpn.exe .\Windscribe-Mumbai-TCP.ovpn
   ```

5. Enter the username and password when asked. When you see `Connected`,
   all traffic goes through the VPN. Press **Ctrl+C** to disconnect. Routes
   are removed and the adapter goes away.

To skip the prompt, put the username on line 1 and the password on line 2 of
a text file, and pass `--auth-file creds.txt`. Keep that file private.

## Running in the background (no window)

Download `start-ovpn.ps1` and `vpn.bat` from the release and put them next to
`ovpn.exe` and your `.ovpn` file (your Downloads folder works). Then:

| Do this | To |
| --- | --- |
| double-click `vpn.bat` (or `vpn start`) | connect in the background, with no window |
| `vpn stop` | disconnect |
| `vpn status` | see whether it's running, plus the last log lines |
| `vpn login` | enter the username and password again |
| `vpn install` | also connect at every boot and keep reconnecting (`vpn uninstall` undoes it) |

Each command asks for Administrator rights. The first run asks for the
OpenVPN username and password and saves them in
`C:\ProgramData\ovpn\auth.txt`, which only Administrators can read. The log
is `C:\ProgramData\ovpn\ovpn.log`. If the folder has several `.ovpn` files,
the newest is used; choose one with `vpn start -Config file.ovpn`. You can
also run the script directly:
`powershell -ExecutionPolicy Bypass -File .\start-ovpn.ps1 -Status`.

`ovpn.exe` still shows up in Task Manager, like any program. It just has no
window.

## Options

```
ovpn [CONFIG.ovpn] [--auth-file FILE] [--no-redirect] [--no-dns] [--adapter NAME] [-v]
ovpn [CONFIG.ovpn] --no-tun [--ping 1.1.1.1] [--count 4]
```

* `--no-tun --ping 1.1.1.1` connects and pings through the tunnel without
  creating an adapter. This needs no admin rights, so it's a quick test on a
  locked-down machine.
* `--no-redirect` keeps your normal internet. Only routes the server pushes go
  through the VPN.
* `--no-dns` leaves DNS servers alone.
* `--log-file FILE` appends the log to a file instead of the console (used by
  the background scripts).
* `-v` / `-vv` print debug or trace logs.

It reconnects on its own if the connection drops (with back-off). It stops
on a wrong password.

## What's supported

* TCP transport (`proto tcp`, `tcp-client`, or `remote host port tcp`)
* `tls-auth` (any `auth` digest, `key-direction`) and `tls-crypt`
* TLS 1.2 / 1.3 via rustls, verified against the config's CA,
  `remote-cert-tls server`, and `verify-x509-name`
* `auth-user-pass` (prompt, file, or inline block), optional client cert/key
* Data ciphers: AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305 and
  AES-256/128-CBC with HMAC. Negotiated with the server (NCP).
* Key derivation with TLS-EKM (OpenVPN 2.6) or the classic PRF
* `P_DATA_V2` with peer-id, compression framing stubs (`comp-lzo no`,
  `compress`, `stub-v2`, LZ4 decompression)
* Server-initiated renegotiation (`reneg-sec`), keepalive and ping-restart,
  `auth-token`
* Pushed `ifconfig` (subnet and net30), `route`, `redirect-gateway`,
  `dhcp-option DNS`

Not supported yet: UDP, `tls-crypt-v2`, proxies, IPv6 inside the tunnel, LZO
decompression, and a kill switch. During a reconnect, traffic briefly uses
your normal connection.

## Building

```
cargo build --release
```

To embed `wintun.dll`, set `OVPN_WINTUN_DLL` to the amd64 `wintun.dll` from
<https://www.wintun.net> at build time. Releases are built by
`.github/workflows/release.yml` on `windows-latest`. Run it from the Actions
tab with a tag such as `v0.1.1`.

On Linux the same binary works with `/dev/net/tun`. That's how it's tested:
it runs against a real OpenVPN 2.6 server in a network namespace.

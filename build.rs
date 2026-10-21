//! Optionally embed wintun.dll in the binary, so Windows users need only one
//! file. Set `OVPN_WINTUN_DLL` to the path of the amd64 wintun.dll at build time.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(embed_wintun)");
    println!("cargo::rerun-if-env-changed=OVPN_WINTUN_DLL");
    if let Ok(path) = std::env::var("OVPN_WINTUN_DLL") {
        println!("cargo::rerun-if-changed={path}");
        println!("cargo::rustc-cfg=embed_wintun");
        println!("cargo::rustc-env=OVPN_WINTUN_DLL_PATH={path}");
    }
}

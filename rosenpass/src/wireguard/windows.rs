use anyhow::{bail, Context, Result};
use log::{debug, error};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::net::Ipv4Addr;
use crate::util::b64_writer;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows WireGuard backend using native `wg.exe`
pub fn set_psk(
    dev: &str,
    peer_pk: &str,
    psk: &[u8],
    extra: &[String],
) -> Result<()> {
    let wg_path = locate_wg_exe()?;

    let mut child = Command::new(&wg_path)
        .arg("set")
        .arg(dev)
        .arg("peer")
        .arg(peer_pk)
        .arg("preshared-key")
        .arg("stdin")
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .creation_flags(0x08000000) // 🚫 Prevents window popup
        .spawn()
        .context("failed to start wg.exe")?;

    {
        let mut stdin = child.stdin.take().context("failed to open wg stdin")?;
        b64_writer(&mut stdin).write_all(psk)?;
    } // ✅ CRITICAL: closes stdin

    let output = child.wait_with_output()?;

    if output.status.success() {
        debug!("successfully passed PSK to wg (windows)");
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        error!("wg.exe failed: {}", err);
        bail!("wg.exe PSK injection failed: {}", err);
    }
}

fn locate_wg_exe() -> Result<PathBuf> {
    // ✅ 1. Prefer local tools folder first
    let local = PathBuf::from("tools/wireguard/bin/wg.exe");
    if local.exists() {
        return Ok(local);
    }

    // 2. Fallback to PATH
    if let Ok(p) = which::which("wg.exe") {
        return Ok(p);
    }

    // 3. Fallback to system install
    let default = PathBuf::from(r"C:\Program Files\WireGuard\wg.exe");
    if default.exists() {
        return Ok(default);
    }

    bail!("wg.exe not found in tools/, PATH, or Program Files");
}


/// No-op on Windows (native driver is managed by WireGuard service)
pub fn shutdown_all() {
    // Nothing required on Windows when using wg.exe
}


pub fn ensure_interface(dev: &str) -> Result<()> {
    let exe = PathBuf::from("tools/wireguard/bin/wireguard.exe");

    let status = Command::new(&exe)
        .arg("/installtunnelservice")
        .arg(dev)
        .creation_flags(0x08000000)
        .status()
        .context("failed to run wireguard.exe")?;

    if status.success() {
        Ok(())
    } else {
        bail!("failed to install WireGuard tunnel service: {:?}", status);
    }
}


/// Assign a static IPv4 address to the interface
pub fn set_interface_ipv4(dev: &str, ip: Ipv4Addr, prefix: u8) -> Result<()> {
    let mask = prefix_to_netmask(prefix);

    let status = Command::new("netsh")
        .arg("interface")
        .arg("ip")
        .arg("set")
        .arg("address")
        .arg(dev)
        .arg("static")
        .arg(ip.to_string())
        .arg(mask)
        .creation_flags(0x08000000)
        .status()
        .context("failed to run netsh ip set")?;

    if status.success() {
        Ok(())
    } else {
        bail!("netsh set address failed: {:?}", status);
    }
}

/// Add route for VPN subnet
pub fn add_route(network: Ipv4Addr, prefix: u8, dev_ip: Ipv4Addr) -> Result<()> {
    let mask = prefix_to_netmask(prefix);

    let status = Command::new("route")
        .arg("add")
        .arg(network.to_string())
        .arg("mask")
        .arg(mask)
        .arg(dev_ip.to_string())
        .creation_flags(0x08000000)
        .status()
        .context("failed to add route")?;

    if status.success() {
        Ok(())
    } else {
        bail!("route add failed: {:?}", status);
    }
}

/// Allow UDP traffic on a port through Windows Firewall
pub fn allow_udp_firewall(port: u16, name: &str) -> Result<()> {
    let status = Command::new("netsh")
        .arg("advfirewall")
        .arg("firewall")
        .arg("add")
        .arg("rule")
        .arg(format!("name={}", name))
        .arg("dir=in")
        .arg("action=allow")
        .arg("protocol=UDP")
        .arg(format!("localport={}", port))
        .creation_flags(0x08000000)
        .status()
        .context("failed to add firewall rule")?;

    if status.success() {
        Ok(())
    } else {
        bail!("firewall rule add failed: {:?}", status);
    }
}

/// Convert CIDR prefix → subnet mask
fn prefix_to_netmask(prefix: u8) -> String {
    let mask: u32 = if prefix == 0 {
        0
    } else {
        0xffffffffu32 << (32 - prefix)
    };

    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    )
}

use anyhow::{Result, anyhow};
use log::{debug, error};
use std::io::Write;
use std::process::{Command, Stdio};
use std::thread;
use std::net::Ipv4Addr;

use crate::util::b64_writer;

/// Linux WireGuard backend using the `wg` CLI.
pub fn set_psk(
    dev: &str,
    peer_pk: &str,
    psk: &[u8],
    extra: &[String],
) -> Result<()> {
    let mut child = Command::new("wg")
        .arg("set")
        .arg(dev)
        .arg("peer")
        .arg(peer_pk)
        .arg("preshared-key")
        .arg("/dev/stdin")
        .stdin(Stdio::piped())
        .args(extra)
        .spawn()?;

    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            anyhow!("failed to open wg stdin")
        })?;
        b64_writer(&mut stdin).write_all(psk)?;
    } // ✅ stdin closed properly

    thread::spawn(move || {
        let status = child.wait();

        if let Ok(status) = status {
            if status.success() {
                debug!("successfully passed psk to wg")
            } else {
                error!("could not pass psk to wg {:?}", status)
            }
        } else {
            error!("wait failed: {:?}", status)
        }
    });

    Ok(())
}

pub fn shutdown_all() {}

pub fn ensure_interface(_dev: &str) -> Result<()> {
    Ok(())
}

pub fn set_interface_ipv4(
    _dev: &str,
    _ip: Ipv4Addr,
    _prefix: u8,
) -> Result<()> {
    Ok(())
}

pub fn add_route(
    _network: Ipv4Addr,
    _prefix: u8,
    _dev_ip: Ipv4Addr,
) -> Result<()> {
    Ok(())
}

pub fn allow_udp_firewall(_port: u16, _name: &str) -> Result<()> {
    Ok(())
}

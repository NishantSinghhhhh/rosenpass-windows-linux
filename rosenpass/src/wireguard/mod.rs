//! Cross-platform WireGuard API surface for rosenpass.
//!
//! This module only re-exports the platform-specific implementations so
//! callers can use `crate::wireguard::set_psk(...)` and
//! `crate::wireguard::shutdown_all()` regardless of platform.
//!
//! Platform modules must provide:
//!   - `pub fn set_psk(dev: &str, peer_pk: &str, psk: &[u8], extra: &[String]) -> anyhow::Result<()>`
//!   - `pub fn shutdown_all()`
//!
//! We re-export the functions directly so names are identical across platforms.

#[cfg(windows)]
pub mod windows;

#[cfg(not(windows))]
pub mod linux;

// Re-export a unified API
#[cfg(windows)]
pub use windows::{
    set_psk,
    shutdown_all,
    ensure_interface,
    set_interface_ipv4,
    add_route,
    allow_udp_firewall,
};


#[cfg(not(windows))]
pub use linux::{set_psk, shutdown_all};

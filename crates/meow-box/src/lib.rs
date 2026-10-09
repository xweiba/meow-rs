//! meow box: the core as a small side router (旁路由) on the LAN, Linux only.
//!
//! One process becomes a device of its own on the wire: its own MAC (wired;
//! on Wi-Fi the host's) and IP (DHCP or static) through an AF_PACKET socket
//! on `--iface`, without touching the host's network settings. On that IP
//! it serves a config page (TCP 80) and DNS (UDP/TCP 53), and it carries
//! the traffic of every device that sets its gateway to that IP into the
//! core, which runs in-process over a socket pair standing in for a TUN
//! device (the phones' `tun.file-descriptor` path).
//!
//! ```text
//! wire ⇄ raw socket ⇄ switch ─ ARP / ping / TCP 80, 53 → smoltcp → page, DNS over TCP
//!                            ├ DHCP replies           → DHCP client
//!                            ├ UDP 53 to the box      → DNS front
//!                            └ routed traffic         → socket pair → core (TUN)
//! core replies → socket pair → switch (IP→MAC, ARP on a miss) → raw socket
//! ```
//!
//! The core's config comes from `meow_paopao` (the app's own config code
//! and defaults); the core itself, and fetching subscriptions, are supplied
//! by the embedder through [`CoreHost`] (meow-app's `meow box`).

use std::future::Future;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod admin;
#[cfg(target_os = "linux")]
mod app;
/// The core's config as the box runs it (public for embedders' checks).
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
mod ctl;
#[cfg(target_os = "linux")]
mod dhcp;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod frame;
#[cfg(target_os = "linux")]
mod geodata;
#[cfg(target_os = "linux")]
mod run;
#[cfg(target_os = "linux")]
mod stack;
#[cfg(target_os = "linux")]
mod store;
#[cfg(target_os = "linux")]
mod switch;
#[cfg(target_os = "linux")]
mod sys;

/// `meow box` options.
#[derive(Debug, Clone, clap::Args)]
pub struct Options {
    /// Network interface to join (default: the one of the default route)
    #[arg(long)]
    pub iface: Option<String>,
    /// The box's address: `dhcp`, or static like `192.168.1.50/24`
    #[arg(long, default_value = "dhcp")]
    pub ip: String,
    /// Default gateway with a static address (e.g. `192.168.1.1`)
    #[arg(long)]
    pub gateway: Option<Ipv4Addr>,
    /// Data directory (password, settings, subscriptions, core cache);
    /// default `/var/lib/paopao-box` as root, else
    /// `~/.local/share/paopao-box`
    #[arg(long)]
    pub data: Option<PathBuf>,
}

/// A future the host returns (subscription downloads).
pub type HostFuture<T> = Pin<Box<dyn Future<Output = anyhow::Result<T>> + Send>>;

/// What the embedder supplies: the core and a direct HTTP client.
pub trait CoreHost: Send + Sync + 'static {
    /// Starts the core with `config` (YAML) over the TUN descriptor
    /// `tun_fd`, whose ownership passes to the core (it closes it when it
    /// stops). Returns once the core is up, or why it failed. Blocks.
    fn start(&self, home: &Path, config: &str, tun_fd: i32) -> anyhow::Result<()>;
    /// Stops the core and waits until it has let go of its descriptor.
    /// Blocks.
    fn stop(&self);
    /// Downloads `url` over a direct connection (subscriptions).
    fn fetch(&self, url: &str) -> HostFuture<Vec<u8>>;
}

/// Runs the box until Ctrl-C / SIGTERM.
#[cfg(target_os = "linux")]
pub fn run(opts: &Options, host: Arc<dyn CoreHost>) -> anyhow::Result<()> {
    run::run(opts, host)
}

/// The box is Linux only.
#[cfg(not(target_os = "linux"))]
pub fn run(_opts: &Options, _host: Arc<dyn CoreHost>) -> anyhow::Result<()> {
    anyhow::bail!("meow box is Linux only")
}

//! Android / iOS: routes belong to the platform VPN (the device comes in
//! through `tun.file-descriptor`), so there is nothing to install here.

use ipnet::IpNet;

pub(super) struct RouteGuard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RouteFailure {
    Skip,
    SplitOrFail,
}

impl RouteGuard {
    pub(super) fn setup(
        _if_index: u32,
        _nets: &[IpNet],
        _on_failure: RouteFailure,
    ) -> std::io::Result<Self> {
        Err(std::io::Error::other(
            "tun auto-route: routes belong to the platform VPN here",
        ))
    }

    pub(super) fn conflict(&self) -> bool {
        false
    }
}

/// What `choose_default` decides on the desktop platforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DefaultChoice {
    pub iface: Option<String>,
    pub physical_route_missing: bool,
    pub full_tunnel: Option<String>,
    pub physical: Option<String>,
}

fn unsupported<T>() -> std::io::Result<T> {
    Err(std::io::Error::other(
        "routes and the default interface are managed by the platform VPN here",
    ))
}

pub(super) fn route_snapshot() -> std::io::Result<meow_common::route_table::RouteTable> {
    unsupported()
}

pub(super) fn detect_default(
    _table: &meow_common::route_table::RouteTable,
    _via: meow_common::route_table::DefaultVia,
    _current: Option<&str>,
) -> std::io::Result<DefaultChoice> {
    unsupported()
}

pub(super) fn watch_route_changes(_on_change: impl Fn()) -> std::io::Result<()> {
    unsupported()
}

pub fn is_container_like(_name: &str) -> bool {
    false
}

pub fn interface_addresses() -> Vec<(String, ipnet::IpNet)> {
    Vec::new()
}

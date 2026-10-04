//! Android / iOS: routes belong to the platform VPN (the device comes in
//! through `tun.file-descriptor`), so there is nothing to install here.

use ipnet::IpNet;

pub(super) struct RouteGuard;

impl RouteGuard {
    pub(super) fn setup(_if_index: u32, _nets: &[IpNet]) -> std::io::Result<Self> {
        Err(std::io::Error::other(
            "tun auto-route: routes belong to the platform VPN here",
        ))
    }
}

pub(super) fn default_interface() -> std::io::Result<String> {
    Err(std::io::Error::other(
        "default interface: managed by the platform VPN here",
    ))
}

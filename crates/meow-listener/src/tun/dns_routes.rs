//! Capture the system's upstream DNS through the TUN without rewriting
//! resolver configuration. Host routes beat on-link LAN routes; outbound
//! sockets still use the original interface binding. The routes belong to
//! this TUN generation, never the Flutter panel. Other VPN resolvers keep
//! their routes and the existing split-DNS passthrough semantics.

use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use meow_common::route_table::{self, IfaceDns, RouteIfaceKind};

use super::route::{RouteFailure, RouteGuard};

fn servers(rows: &[IfaceDns], ipv6: bool) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for row in rows {
        if matches!(row.kind, RouteIfaceKind::OwnTun | RouteIfaceKind::OtherVpn) {
            continue;
        }
        for &ip in &row.servers {
            // Local resolvers cannot be intercepted with a route. Their
            // upstream queries are captured instead. Scoped link-local v6
            // addresses must retain their physical scope.
            let local = ip.is_loopback()
                || ip.is_unspecified()
                || matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local());
            if !local && (ip.is_ipv4() || ipv6) && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out.sort();
    out
}

struct State {
    stopped: bool,
    index: u32,
    ipv6: bool,
    routes: Vec<(IpAddr, RouteGuard)>,
}

impl State {
    fn refresh(&mut self) -> io::Result<()> {
        let wanted = servers(&route_table::iface_dns(), self.ipv6);
        // Install replacements before releasing old routes. Failed setup
        // drops only the new routes; the running capture remains intact.
        let mut added = Vec::new();
        for &ip in &wanted {
            if self.routes.iter().any(|(old, _)| *old == ip) {
                continue;
            }
            let net = ipnet::IpNet::from(ip);
            let route = RouteGuard::setup(self.index, &[net], RouteFailure::SplitOrFail)?;
            added.push((ip, route));
        }
        self.routes.retain(|(ip, _)| wanted.contains(ip));
        self.routes.extend(added);
        Ok(())
    }
}

/// Owns only the host routes added for this TUN. A lightweight native
/// monitor follows the existing per-interface DNS snapshot; dropping the
/// guard joins it and removes its routes before the adapter disappears.
pub(super) struct DnsRoutes {
    state: Arc<(Mutex<State>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl DnsRoutes {
    pub(super) fn setup(index: u32, ipv6: bool) -> io::Result<Self> {
        let mut state = State {
            stopped: false,
            index,
            ipv6,
            routes: Vec::new(),
        };
        state.refresh()?;
        let state = Arc::new((Mutex::new(state), Condvar::new()));
        let shared = Arc::clone(&state);
        let worker = std::thread::Builder::new()
            .name("tun-dns-routes".into())
            .spawn(move || {
                let (lock, wake) = &*shared;
                let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
                while !state.stopped {
                    let (next, _) = wake
                        .wait_timeout(state, Duration::from_secs(2))
                        .unwrap_or_else(|e| e.into_inner());
                    state = next;
                    if state.stopped {
                        break;
                    }
                    if let Err(e) = state.refresh() {
                        tracing::warn!("system DNS route update failed: {e}");
                    }
                }
                state.routes.clear();
            })?;
        Ok(Self {
            state,
            worker: Some(worker),
        })
    }
}

impl Drop for DnsRoutes {
    fn drop(&mut self) {
        let (lock, wake) = &*self.state;
        lock.lock().unwrap_or_else(|e| e.into_inner()).stopped = true;
        wake.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_physical_dns_only_and_deduplicate() {
        let row = |kind, values: &[&str]| IfaceDns {
            iface: "test".into(),
            kind,
            servers: values.iter().map(|s| s.parse().unwrap()).collect(),
            domains: Vec::new(),
        };
        let rows = [
            row(
                RouteIfaceKind::Physical,
                &["192.168.1.1", "127.0.0.53", "fd00::1", "fe80::1"],
            ),
            row(RouteIfaceKind::Physical, &["192.168.1.1"]),
            row(RouteIfaceKind::OtherVpn, &["10.9.0.1"]),
            row(RouteIfaceKind::OwnTun, &["172.19.0.2"]),
        ];
        assert_eq!(
            servers(&rows, false),
            ["192.168.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(servers(&rows, true).len(), 2);
    }
}

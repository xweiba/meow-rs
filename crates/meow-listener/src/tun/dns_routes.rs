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
            // A physical service and a VPN may name the same address.
            // A host route cannot distinguish their queries, so leave
            // shared VPN resolvers alone rather than stealing their DNS.
            if rows
                .iter()
                .any(|r| r.kind == RouteIfaceKind::OtherVpn && r.servers.contains(&ip))
            {
                continue;
            }
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
        let table = route_table::route_table();
        let wanted: Vec<_> = servers(&route_table::iface_dns(), self.ipv6)
            .into_iter()
            .filter(|ip| {
                table
                    .lookup(*ip)
                    .is_none_or(|r| r.kind != RouteIfaceKind::OtherVpn)
            })
            .collect();
        let index = self.index;
        reconcile(&mut self.routes, &wanted, |ip| {
            let net = ipnet::IpNet::from(ip);
            RouteGuard::setup(index, &[net], RouteFailure::SplitOrFail)
        })
    }
}

/// Install replacements before releasing old routes. On failure only the
/// new guards drop; a partial network update must not dismantle capture.
fn reconcile<R>(
    routes: &mut Vec<(IpAddr, R)>,
    wanted: &[IpAddr],
    mut install: impl FnMut(IpAddr) -> io::Result<R>,
) -> io::Result<()> {
    let mut added = Vec::new();
    for &ip in wanted {
        if !routes.iter().any(|(old, _)| *old == ip) {
            added.push((ip, install(ip)?));
        }
    }
    routes.retain(|(ip, _)| wanted.contains(ip));
    routes.extend(added);
    Ok(())
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
        if index == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS capture needs a TUN interface index",
            ));
        }
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
                let mut state = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !state.stopped {
                    let (next, _) = wake
                        .wait_timeout(state, Duration::from_secs(2))
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stopped = true;
        wake.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // TunDevice's last field flushes caches only after ALL routes,
        // outbound binding and device owners have finished dropping.
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

    #[test]
    fn shared_vpn_resolver_is_not_captured_even_on_a_physical_service() {
        let rows = [RouteIfaceKind::Physical, RouteIfaceKind::OtherVpn].map(|kind| IfaceDns {
            iface: "test".into(),
            kind,
            servers: vec!["192.0.2.53".parse().unwrap()],
            domains: Vec::new(),
        });
        assert!(servers(&rows, true).is_empty());
        assert!(DnsRoutes::setup(0, true).is_err());
    }

    #[test]
    fn route_update_rolls_back_additions_and_keeps_old_capture_on_failure() {
        struct Guard(IpAddr, Arc<Mutex<Vec<IpAddr>>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.1.lock().unwrap().push(self.0);
            }
        }
        let ips: Vec<IpAddr> = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let removed = Arc::new(Mutex::new(Vec::new()));
        let mut routes = vec![(ips[0], Guard(ips[0], Arc::clone(&removed)))];
        let result = reconcile(&mut routes, &ips[1..], |ip| {
            if ip == ips[2] {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            Ok(Guard(ip, Arc::clone(&removed)))
        });
        assert!(result.is_err());
        assert_eq!(routes.iter().map(|r| r.0).collect::<Vec<_>>(), [ips[0]]);
        assert_eq!(*removed.lock().unwrap(), [ips[1]]);
        removed.lock().unwrap().clear();
        reconcile(&mut routes, &ips[1..], |ip| {
            Ok(Guard(ip, Arc::clone(&removed)))
        })
        .unwrap();
        assert_eq!(*removed.lock().unwrap(), [ips[0]]);
        // An unchanged snapshot never installs/adopts the same routes twice.
        reconcile(&mut routes, &ips[1..], |_| panic!("unchanged route")).unwrap();
        drop(routes);
        assert_eq!(*removed.lock().unwrap(), ips);
    }
}

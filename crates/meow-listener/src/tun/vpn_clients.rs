//! PaoPao: find the processes that are another VPN's client, so their own
//! traffic (the tunnel's outer packets, their control connection, their
//! name lookups) is passed through untouched.
//!
//! Linux says who holds a tun/tap device: the descriptor's
//! `/proc/<pid>/fdinfo/<fd>` carries `iff:\t<interface>`. macOS and Windows
//! have no such thing a process may ask about another — there the user
//! names the client (`tun.vpn-client-apps`).
//!
//! The scan runs with the route snapshot (when it changed, and every
//! [`RESCAN_EVERY`] while another VPN's interface exists), never per
//! connection. A kernel tunnel (in-kernel WireGuard) has no process and is
//! not found.

use meow_common::route_table::{self, RouteIfaceKind, RouteTable};

/// The other VPNs' interface names in `table`. Container bridges and VM
/// switches are virtual too, but no process holds them through the tun
/// device: with only those around `/proc` is not walked at all.
fn vpn_interfaces(table: &RouteTable, is_container: impl Fn(&str) -> bool) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for e in table.entries() {
        if e.kind == RouteIfaceKind::OtherVpn
            && !is_container(&e.iface)
            && !names.iter().any(|n| **n == *e.iface)
        {
            names.push(e.iface.to_string());
        }
    }
    names
}

/// Who holds another VPN's device, as last scanned (kept between scans).
static HOLDERS: parking_lot::Mutex<Vec<route_table::VpnClientProc>> =
    parking_lot::Mutex::new(Vec::new());

/// The running well-known clients (`tun.vpn-known-clients`) and when the
/// process list was last read.
static KNOWN: parking_lot::Mutex<(Option<std::time::Instant>, Vec<route_table::VpnClientProc>)> =
    parking_lot::Mutex::new((None, Vec::new()));

/// How often the process list is read for the well-known clients.
const KNOWN_EVERY: std::time::Duration = std::time::Duration::from_secs(4);

/// The well-known clients running now (one pass over the process list at
/// most every [`KNOWN_EVERY`]); none, and nothing read, without any listed.
/// A client named here passes through from before its tunnel exists: its
/// gateway's name gets a real answer and its handshake leaves by the
/// physical interface, so a VPN started after the virtual adapter comes up.
fn known_running() -> Vec<route_table::VpnClientProc> {
    let matchers = route_table::vpn_manual().known_clients.clone();
    let mut known = KNOWN.lock();
    if matchers.is_empty() {
        *known = (None, Vec::new());
        return Vec::new();
    }
    if known.0.is_some_and(|at| at.elapsed() < KNOWN_EVERY) {
        return known.1.clone();
    }
    let found: Vec<route_table::VpnClientProc> = meow_common::running_programs()
        .into_iter()
        .filter(|(_, name, path)| {
            matchers
                .iter()
                .any(|m| route_table::app_matches(m, name, path))
        })
        .map(|(pid, name, path)| route_table::VpnClientProc {
            pid,
            name,
            path,
            iface: String::new(),
        })
        .collect();
    *known = (Some(std::time::Instant::now()), found.clone());
    found
}

/// Refresh the published list of VPN client processes: who holds another
/// VPN's device, and the well-known clients running.
pub(super) fn refresh(table: &RouteTable, changed: bool) {
    let ifaces = vpn_interfaces(table, super::route::is_container_like);
    let holders = if ifaces.is_empty() {
        Vec::new()
    } else if platform::due(changed) {
        platform::scan(&ifaces)
    } else {
        HOLDERS.lock().clone()
    };
    HOLDERS.lock().clone_from(&holders);
    let mut found = holders;
    for k in known_running() {
        if !found.iter().any(|c| c.pid == k.pid) {
            found.push(k);
        }
    }
    if route_table::publish_vpn_clients(found) {
        for c in route_table::vpn_clients().iter() {
            if c.iface.is_empty() {
                tracing::info!(
                    "vpn client: '{}' (pid {}, {}) is a known VPN client; its own traffic is passed through",
                    c.name,
                    c.pid,
                    c.path
                );
            } else {
                tracing::info!(
                    "vpn client: '{}' (pid {}, {}) holds '{}'; its own traffic is passed through",
                    c.name,
                    c.pid,
                    c.path,
                    c.iface
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use meow_common::route_table::{parse_fdinfo_iff, VpnClientProc};
    use std::time::{Duration, Instant};

    /// How often `/proc` is walked while nothing in the routing table
    /// changed (a client that reconnects keeps its interface name but may
    /// be a new process).
    const RESCAN_EVERY: Duration = Duration::from_secs(10);

    pub(super) fn due(changed: bool) -> bool {
        static LAST: parking_lot::Mutex<Option<Instant>> = parking_lot::Mutex::new(None);
        let mut last = LAST.lock();
        if changed || last.is_none_or(|t| t.elapsed() >= RESCAN_EVERY) {
            *last = Some(Instant::now());
            true
        } else {
            false
        }
    }

    /// Walk `/proc/<pid>/fd`: a link to the tun control device whose
    /// fdinfo names one of `ifaces` makes the process that VPN's client.
    /// Needs to read other users' processes — the core runs as root when it
    /// has a TUN; unreadable processes are skipped.
    pub(super) fn scan(ifaces: &[String]) -> Vec<VpnClientProc> {
        let own = std::process::id();
        let mut out: Vec<VpnClientProc> = Vec::new();
        let Ok(procs) = std::fs::read_dir("/proc") else {
            return out;
        };
        for proc in procs.flatten() {
            let Some(pid) = proc
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == own {
                continue;
            }
            let base = proc.path();
            let Ok(fds) = std::fs::read_dir(base.join("fd")) else {
                continue;
            };
            for fd in fds.flatten() {
                let is_tun = std::fs::read_link(fd.path())
                    .is_ok_and(|target| target.as_os_str() == "/dev/net/tun");
                if !is_tun {
                    continue;
                }
                let Ok(info) = std::fs::read_to_string(base.join("fdinfo").join(fd.file_name()))
                else {
                    continue;
                };
                let Some(iface) = parse_fdinfo_iff(&info) else {
                    continue;
                };
                if !ifaces.iter().any(|n| n == iface)
                    || out.iter().any(|c| c.pid == pid && c.iface == iface)
                {
                    continue;
                }
                let path = std::fs::read_link(base.join("exe"))
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                // The file name of the program, as the per-connection
                // process lookup reports it (`comm` is cut at 15 bytes).
                let name = std::path::Path::new(&path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .filter(|n| !n.is_empty())
                    .or_else(|| {
                        std::fs::read_to_string(base.join("comm"))
                            .map(|c| c.trim().to_string())
                            .ok()
                    })
                    .unwrap_or_default();
                out.push(VpnClientProc {
                    pid,
                    name,
                    path,
                    iface: iface.to_string(),
                });
            }
        }
        out.sort_by(|a, b| (&a.iface, a.pid).cmp(&(&b.iface, b.pid)));
        out
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use meow_common::route_table::VpnClientProc;

    pub(super) fn due(_changed: bool) -> bool {
        true
    }

    /// No way to ask who holds another VPN's device here.
    pub(super) fn scan(_ifaces: &[String]) -> Vec<VpnClientProc> {
        Vec::new()
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use meow_common::route_table::{RawRoute, RouteIfaceKind, RouteTable};

    /// Only a tunnel can have a client process: a machine with nothing but
    /// container bridges never has its `/proc` walked.
    #[test]
    fn container_bridges_do_not_trigger_the_scan() {
        let raw = |net: &str, iface: &str| RawRoute {
            net: net.parse().unwrap(),
            iface: iface.into(),
            index: 1,
            gateway: None,
            metric: 0,
            table: None,
            scoped: false,
        };
        let table = RouteTable::build(
            [
                raw("172.17.0.0/16", "docker0"),
                raw("192.168.122.0/24", "virbr0"),
                raw("10.8.0.0/16", "tun0"),
                raw("192.168.1.0/24", "enp3s0"),
                raw("0.0.0.0/1", "meow-tun"),
            ],
            |n| n == "meow-tun",
            |n| {
                if n == "enp3s0" {
                    RouteIfaceKind::Physical
                } else {
                    RouteIfaceKind::OtherVpn
                }
            },
        );
        let names = super::vpn_interfaces(&table, super::super::route::is_container_like);
        assert_eq!(names, ["tun0"]);
    }

    /// The walk itself: this process holds no VPN's device, and an
    /// interface nobody holds finds nobody (no root needed — unreadable
    /// processes are skipped).
    #[test]
    fn the_proc_walk_finds_nobody_for_an_interface_nobody_holds() {
        assert!(super::platform::scan(&["meow-no-such-tun0".to_string()]).is_empty());
    }

    /// A well-known client is found while it runs — before any tunnel
    /// exists — and is gone once it ends; nothing is read without any.
    #[test]
    fn a_running_known_client_is_found_by_its_program() {
        use meow_common::route_table::{install_vpn_manual, VpnManual};
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep runs");
        let pid = child.id();
        let guard = install_vpn_manual(VpnManual {
            known_clients: vec!["name:sleep".into()],
            ..Default::default()
        });
        *super::KNOWN.lock() = (None, Vec::new());
        let found = super::known_running();
        assert!(
            found
                .iter()
                .any(|c| c.pid == pid && c.name == "sleep" && c.iface.is_empty()),
            "{found:?}"
        );
        // Asked again at once: the last pass, the process list not read.
        assert_eq!(super::known_running(), found);
        child.kill().unwrap();
        child.wait().unwrap();
        *super::KNOWN.lock() = (None, Vec::new());
        assert!(!super::known_running().iter().any(|c| c.pid == pid));
        drop(guard);
        assert!(super::known_running().is_empty());
    }
}

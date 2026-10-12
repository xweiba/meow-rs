//! Outbound-interface binding for global route scope (#375, issue #695).
//!
//! `auto-route: global` steers all traffic into the TUN, so every socket
//! meow opens must be bound to the physical interface (via
//! `meow_common::install_outbound_interface`: `SO_BINDTODEVICE` on Linux,
//! `IP_BOUND_IF` on macOS, `IP_UNICAST_IF` on Windows) or it loops back
//! into the device.
//! The binding is per-socket and applied at creation: a socket created
//! before it is installed stays unbound for its whole life, and once the
//! split default routes go in its traffic re-enters the TUN — a QUIC or mux
//! session opened by an early startup dial (geodata download, provider
//! fetch, health probe) then loops until it times out.
//!
//! [`OutboundBinding`] owns one installation of that process-global
//! binding. The binary installs it *before* the config build performs its
//! first dial, and a config reload installs the new configuration's
//! binding before the reload's first dial (both via
//! `meow_api::preinstall_global_route_binding`); either hands it to
//! [`TunListener::with_outbound_binding`]. A listener started without one
//! (the pre-install failed) installs its own before touching routes.
//! Either way the listener's device owns it, so it is given up exactly
//! when the routes it protects go away — listener teardown, reload, or a
//! startup failure.
//!
//! Owners may overlap — a reload's binding is installed while the old
//! listener still runs. The registry is owner-aware
//! (`meow_common::OutboundIfaceGuard`): the newest live owner is in
//! effect, dropping it restores the newest owner still alive, and dropping
//! a superseded owner is a no-op. So a rejected reload restores the
//! running listener's binding, and an old listener torn down after its
//! successor installed never clears the successor's binding.
//!
//! [`TunListener::with_outbound_binding`]: super::TunListener::with_outbound_binding

use std::io;
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use meow_common::outbound_balance::{BalanceOptions, Balancer};
use meow_common::route_table::{self, DefaultVia, RouteTable};
use tracing::{debug, info, warn};

use super::route::{self, DefaultChoice};

/// How often an auto-detected binding looks at the routing table again.
const RECHECK: Duration = Duration::from_secs(2);

/// How long after a route-change event the table is read: a VPN client
/// installs its routes in a burst.
const SETTLE: Duration = Duration::from_millis(150);

/// PaoPao: how the binding behaves next to another VPN (`tun.default-via`,
/// `tun.follow-system-routes`). The default is the behaviour without
/// either key.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutboundPolicy {
    /// Which interface takes what only a default route covers.
    pub default_via: DefaultVia,
    /// Bind each socket by the system routing table (another VPN's pushed
    /// prefixes leave through that VPN) instead of always the default
    /// interface.
    pub follow_routes: bool,
    /// PaoPao (`tun.outbound-interfaces`): spread what would take the
    /// default interface over these physical interfaces, per connection.
    /// `None` (or fewer than two names) = one interface, as before.
    pub balance: Option<BalanceOptions>,
}

/// One owner of the process-global outbound-interface binding; dropping it
/// gives the binding up (the newest owner still alive takes over, or it is
/// cleared when none is left).
///
/// PaoPao: a monitor thread keeps the route snapshot fresh (on route-change
/// events, and every [`RECHECK`] regardless) and — for an auto-detected
/// binding — moves the binding when another uplink took over (cable
/// unplugged, Wi-Fi changed), after seeing the same new one twice (no
/// flapping). An explicit `tun.outbound-interface` stays put.
#[must_use = "dropping the binding gives it up immediately"]
#[derive(Debug)]
pub struct OutboundBinding {
    /// The only strong reference: dropping the binding gives it up at once
    /// (the monitor holds a weak one and ends with it).
    guard: Arc<Mutex<meow_common::OutboundIfaceGuard>>,
}

/// Wake-up shared by every monitor: a generation counter bumped by the
/// route-change listener ([`poke`]).
struct Wake {
    generation: Mutex<u64>,
    changed: Condvar,
}

static WAKE: Wake = Wake {
    generation: Mutex::new(0),
    changed: Condvar::new(),
};

/// Ask every monitor to read the routing table now (routes changed).
pub(super) fn poke() {
    if let Ok(mut generation) = WAKE.generation.lock() {
        *generation = generation.wrapping_add(1);
        WAKE.changed.notify_all();
    }
}

/// Block until [`poke`] moved the generation past `seen` or `deadline`
/// passed. Returns the generation and whether it moved.
fn wait_for_poke(seen: u64, deadline: Instant) -> (u64, bool) {
    let Ok(mut generation) = WAKE.generation.lock() else {
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        return (seen, false);
    };
    while *generation == seen {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return (seen, false);
        }
        match WAKE.changed.wait_timeout(generation, left) {
            Ok((g, _)) => generation = g,
            Err(_) => return (seen, false),
        }
    }
    (*generation, true)
}

/// One process-wide thread turning the OS's route-change notifications into
/// [`poke`]s. Without it (the listener could not be opened) the monitors
/// still poll every [`RECHECK`].
fn start_route_events() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let spawned = std::thread::Builder::new()
            .name("route-events".into())
            .spawn(|| {
                if let Err(e) = route::watch_route_changes(poke) {
                    debug!("route events: unavailable ({e}); polling only");
                }
            });
        if let Err(e) = spawned {
            debug!("route events: no listener thread ({e}); polling only");
        }
    });
}

/// Read the routing table and publish the snapshot. An unreadable table
/// keeps the previous snapshot. The same read tells `balancer` which of its
/// members hold a default route (an unreadable table keeps what it knew).
fn refresh_snapshot(balancer: Option<&Balancer>) -> Arc<RouteTable> {
    let before = route_table::route_table();
    match route::system_routes() {
        Ok(raw) => {
            if let Some(balancer) = balancer {
                balancer.refresh(&route::SystemLinks::from_routes(&raw));
                balancer.sample(Instant::now());
            }
            route_table::publish_route_table(RouteTable::build(
                raw,
                route_table::is_own_tun,
                route::route_kind,
            ));
        }
        Err(e) => debug!("route snapshot: could not list routes: {e}"),
    }
    let table = route_table::route_table();
    let changed = !Arc::ptr_eq(&before, &table);
    super::iface_dns::refresh(&table, changed);
    super::vpn_clients::refresh(&table, changed);
    table
}

/// Publish what [`route::choose_default`] found, keeping the time a full
/// tunnel was first seen.
fn publish_status(choice: &DefaultChoice, policy: &OutboundPolicy) {
    route_table::update_outbound_status(|st| {
        st.default_via = policy.default_via;
        st.follow_routes = policy.follow_routes;
        if st.physical_iface.as_deref() != choice.physical.as_deref() {
            st.physical_iface = choice.physical.as_deref().map(Arc::from);
        }
        if st.physical_route_missing != choice.physical_route_missing {
            if choice.physical_route_missing {
                warn!(
                    "outbound interface: no physical interface holds a default route \
                     (another VPN took it over?); the binding is not moved \
                     (tun.default-via: physical)"
                );
            }
            st.physical_route_missing = choice.physical_route_missing;
        }
        let same = match (&st.full_tunnel, &choice.full_tunnel) {
            (Some((old, _)), Some(new)) => **old == **new,
            (None, None) => true,
            _ => false,
        };
        if !same {
            match &choice.full_tunnel {
                Some(vpn) => info!(
                    "outbound interface: '{vpn}' holds the default route (another VPN in \
                     full-tunnel mode); default-via: {:?}",
                    policy.default_via
                ),
                None => info!("outbound interface: the other VPN gave the default route back"),
            }
            st.full_tunnel = choice
                .full_tunnel
                .as_deref()
                .map(|vpn| (Arc::from(vpn), SystemTime::now()));
        }
    });
}

/// Keeps the snapshot fresh until the binding is gone and — unless the
/// interface is `pinned` by `tun.outbound-interface` — rebinds it to a new
/// default interface once that was chosen on two checks in a row.
fn monitor(
    guard: &Weak<Mutex<meow_common::OutboundIfaceGuard>>,
    policy: &OutboundPolicy,
    pinned: bool,
    balancer: Option<&Balancer>,
) {
    let mut pending: Option<String> = None;
    let mut seen = 0u64;
    let mut next_check = Instant::now() + RECHECK;
    loop {
        let (generation, poked) = wait_for_poke(seen, next_check);
        seen = generation;
        if guard.strong_count() == 0 {
            break;
        }
        if poked {
            std::thread::sleep(SETTLE);
            // Whatever arrived while settling is covered by this read.
            seen = wait_for_poke(seen, Instant::now()).0;
        }
        let table = refresh_snapshot(balancer);
        if Instant::now() < next_check {
            continue;
        }
        next_check = Instant::now() + RECHECK;

        let Some(guard) = guard.upgrade() else { break };
        let Ok(mut g) = guard.lock() else { break };
        // Unreadable default routes (offline a moment): keep the binding.
        let Ok(choice) = route::detect_default(&table, policy.default_via, Some(g.interface()))
        else {
            pending = None;
            continue;
        };
        publish_status(&choice, policy);
        if pinned {
            continue;
        }
        let Some(found) = choice.iface else {
            pending = None;
            continue;
        };
        if g.interface() == found {
            pending = None;
            continue;
        }
        if pending.as_deref() != Some(found.as_str()) {
            debug!("outbound interface: '{found}' is now the default choice; confirming");
            pending = Some(found);
            continue;
        }
        pending = None;
        if let Err(e) = g.rebind(&found) {
            debug!("outbound interface: could not move the binding to '{found}': {e}");
        }
    }
    // The last owner left: nothing follows the snapshot any more.
    if meow_common::outbound_interface().is_none() {
        route_table::clear_route_table();
        route_table::clear_outbound_status();
        route_table::clear_iface_dns();
        route_table::clear_vpn_clients();
    }
}

impl OutboundBinding {
    /// Install the binding for global route scope. `outbound_interface` is
    /// `tun.outbound-interface`; `None` auto-detects the interface carrying
    /// the IPv4 default route (`0.0.0.0/0` — the TUN's own split `/1`
    /// routes are skipped, so detection is safe while a global-scope
    /// listener is still running), by `policy.default_via`.
    ///
    /// Fails closed: an error means nothing is installed, and callers must
    /// not install global routes. Targets other than Linux, macOS and
    /// Windows always fail — they have no per-socket binding (#375).
    pub fn install(outbound_interface: Option<&str>, policy: &OutboundPolicy) -> io::Result<Self> {
        if !cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        )) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "tun auto-route: global is only implemented on Linux, macOS and \
                 Windows (#375); use auto-route: fake-ip on this platform",
            ));
        }
        // PaoPao: two or more members turn balancing on. The live balancer
        // is taken over when the members did not change, so a reload keeps
        // its counters and sticky choices.
        let balancer = policy
            .balance
            .as_ref()
            .filter(|b| b.interfaces.len() >= 2)
            .map(Balancer::obtain);
        // The snapshot first: the very first dial already follows it.
        let table = refresh_snapshot(balancer.as_deref());
        let detected = route::detect_default(&table, policy.default_via, None);
        let iface = match outbound_interface {
            Some(name) => name.to_owned(),
            None => detected
                .as_ref()
                .ok()
                .and_then(|c| c.iface.clone())
                .ok_or_else(|| {
                    let why = match &detected {
                        Err(e) => e.to_string(),
                        Ok(_) => "no IPv4 default route found in the routing table".into(),
                    };
                    io::Error::other(format!(
                        "tun auto-route: global: could not auto-detect the physical \
                         interface ({why}); set tun.outbound-interface explicitly"
                    ))
                })?,
        };
        let mut guard = meow_common::install_outbound_interface(&iface).map_err(|e| {
            io::Error::other(format!(
                "tun auto-route: global: outbound interface binding failed ({e}); \
                 refusing to install default routes without loop avoidance"
            ))
        })?;
        guard.set_follow_routes(policy.follow_routes);
        if let Some(balancer) = &balancer {
            info!(
                "tun: outbound connections spread over {:?} (sticky: {})",
                balancer.names(),
                balancer.sticky()
            );
        }
        guard.set_balance(balancer.clone());
        if let Ok(choice) = &detected {
            publish_status(choice, policy);
        }
        info!(
            "tun: global route scope — outbound sockets bound to '{iface}' \
             (experimental, #375)"
        );
        let guard = Arc::new(Mutex::new(guard));
        start_route_events();
        let weak = Arc::downgrade(&guard);
        let pinned = outbound_interface.is_some();
        let policy = policy.clone();
        let spawned = std::thread::Builder::new()
            .name("outbound-iface".into())
            .spawn(move || monitor(&weak, &policy, pinned, balancer.as_deref()));
        if let Err(e) = spawned {
            debug!("outbound interface: no monitor ({e}); the binding stays put");
        }
        Ok(Self { guard })
    }

    /// The interface this binding is on now.
    pub fn interface(&self) -> String {
        self.guard
            .lock()
            .map(|g| g.interface().to_owned())
            .unwrap_or_default()
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::{OutboundBinding, OutboundPolicy};

    /// Loopback exists on every host.
    const LO: &str = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    /// One test drives every case because the registry is process-global;
    /// separate `#[test]` fns would race each other.
    #[test]
    fn binding_installs_fails_closed_and_composes_across_owners() {
        assert!(meow_common::outbound_interface().is_none());

        // A missing interface fails closed and installs nothing.
        assert!(
            OutboundBinding::install(Some("no-such-iface-zz9"), &OutboundPolicy::default())
                .is_err()
        );
        assert!(meow_common::outbound_interface().is_none());

        let binding = OutboundBinding::install(Some(LO), &OutboundPolicy::default())
            .expect("loopback must exist");
        assert_eq!(binding.interface(), LO);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(binding);
        assert!(meow_common::outbound_interface().is_none());

        // A binding handed to a listener is owned by it: dropping a
        // listener that never ran (startup aborted before the TUN came up)
        // clears the binding instead of leaking it into a TUN-less process.
        let listener = global_listener(
            OutboundBinding::install(Some(LO), &OutboundPolicy::default()).unwrap(),
        );
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(listener);
        assert!(meow_common::outbound_interface().is_none());

        // Reload restart (issue #695): the new config's binding is
        // installed while the old listener still owns its own; tearing the
        // old listener down afterwards must leave the new binding in
        // place (a single-slot registry cleared it here).
        let old = global_listener(
            OutboundBinding::install(Some(LO), &OutboundPolicy::default()).unwrap(),
        );
        let reload = OutboundBinding::install(Some(LO), &OutboundPolicy::default())
            .expect("loopback must exist");
        drop(old);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        let new = global_listener(reload);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(new);
        assert!(meow_common::outbound_interface().is_none());

        // Rejected reload: its binding goes away first, and the running
        // listener's binding is back in effect rather than cleared.
        let running = global_listener(
            OutboundBinding::install(Some(LO), &OutboundPolicy::default()).unwrap(),
        );
        let rejected = OutboundBinding::install(Some(LO), &OutboundPolicy::default())
            .expect("loopback must exist");
        drop(rejected);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(running);
        assert!(meow_common::outbound_interface().is_none());
    }

    fn global_listener(binding: OutboundBinding) -> super::super::TunListener {
        super::super::TunListener::new(
            crate::test_rule_tunnel(),
            super::super::TunListenerConfig {
                device: None,
                mtu: 1500,
                inet4_address: "172.19.0.1/30".parse().unwrap(),
                inet6_address: None,
                auto_route: true,
                route_scope: super::super::TunRouteScope::Global,
                outbound_interface: Some(LO.into()),
                outbound_policy: OutboundPolicy::default(),
                route_exclude: Vec::new(),
                vpn_manual: Default::default(),
                dns_hijack: false,
                udp_timeout: std::time::Duration::from_secs(60),
                max_connections: 0,
                file_descriptor: None,
            },
            "meow-tun-test".into(),
        )
        .with_outbound_binding(binding)
    }
}

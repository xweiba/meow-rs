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
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use tracing::{debug, info};

/// How often an auto-detected binding looks at the routing table again.
const RECHECK: Duration = Duration::from_secs(2);

/// One owner of the process-global outbound-interface binding; dropping it
/// gives the binding up (the newest owner still alive takes over, or it is
/// cleared when none is left).
///
/// PaoPao: an auto-detected binding follows the network — a monitor thread
/// re-detects every [`RECHECK`] and moves the binding when another uplink
/// took over (cable unplugged, Wi-Fi changed), after seeing the same new
/// one twice (no flapping). An explicit `tun.outbound-interface` stays put.
#[must_use = "dropping the binding gives it up immediately"]
#[derive(Debug)]
pub struct OutboundBinding {
    /// The only strong reference: dropping the binding gives it up at once
    /// (the monitor holds a weak one and ends with it).
    guard: Arc<Mutex<meow_common::OutboundIfaceGuard>>,
}

/// Re-detects until the binding is gone, rebinding it to a new default
/// interface once that was seen on two checks in a row.
fn monitor(guard: &Weak<Mutex<meow_common::OutboundIfaceGuard>>) {
    let mut pending: Option<String> = None;
    loop {
        std::thread::sleep(RECHECK);
        if guard.strong_count() == 0 {
            break;
        }
        // No default route at all (offline a moment): keep the binding.
        let Ok(found) = super::route::default_interface() else {
            pending = None;
            continue;
        };
        let Some(guard) = guard.upgrade() else { break };
        let Ok(mut g) = guard.lock() else { break };
        if g.interface() == found {
            pending = None;
            continue;
        }
        if pending.as_deref() != Some(found.as_str()) {
            debug!("outbound interface: '{found}' now holds the default route; confirming");
            pending = Some(found);
            continue;
        }
        pending = None;
        if let Err(e) = g.rebind(&found) {
            debug!("outbound interface: could not move the binding to '{found}': {e}");
        }
    }
}

impl OutboundBinding {
    /// Install the binding for global route scope. `outbound_interface` is
    /// `tun.outbound-interface`; `None` auto-detects the interface carrying
    /// the IPv4 default route (`0.0.0.0/0` — the TUN's own split `/1`
    /// routes are skipped, so detection is safe while a global-scope
    /// listener is still running).
    ///
    /// Fails closed: an error means nothing is installed, and callers must
    /// not install global routes. Targets other than Linux, macOS and
    /// Windows always fail — they have no per-socket binding (#375).
    pub fn install(outbound_interface: Option<&str>) -> io::Result<Self> {
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
        let iface = match outbound_interface {
            Some(name) => name.to_owned(),
            None => super::route::default_interface().map_err(|e| {
                io::Error::other(format!(
                    "tun auto-route: global: could not auto-detect the physical \
                     interface ({e}); set tun.outbound-interface explicitly"
                ))
            })?,
        };
        let guard = meow_common::install_outbound_interface(&iface).map_err(|e| {
            io::Error::other(format!(
                "tun auto-route: global: outbound interface binding failed ({e}); \
                 refusing to install default routes without loop avoidance"
            ))
        })?;
        info!(
            "tun: global route scope — outbound sockets bound to '{iface}' \
             (experimental, #375)"
        );
        let guard = Arc::new(Mutex::new(guard));
        if outbound_interface.is_none() {
            let weak = Arc::downgrade(&guard);
            let spawned = std::thread::Builder::new()
                .name("outbound-iface".into())
                .spawn(move || monitor(&weak));
            if let Err(e) = spawned {
                debug!("outbound interface: no monitor ({e}); the binding stays put");
            }
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
    use super::OutboundBinding;

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
        assert!(OutboundBinding::install(Some("no-such-iface-zz9")).is_err());
        assert!(meow_common::outbound_interface().is_none());

        let binding = OutboundBinding::install(Some(LO)).expect("loopback must exist");
        assert_eq!(binding.interface(), LO);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(binding);
        assert!(meow_common::outbound_interface().is_none());

        // A binding handed to a listener is owned by it: dropping a
        // listener that never ran (startup aborted before the TUN came up)
        // clears the binding instead of leaking it into a TUN-less process.
        let listener = global_listener(OutboundBinding::install(Some(LO)).unwrap());
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(listener);
        assert!(meow_common::outbound_interface().is_none());

        // Reload restart (issue #695): the new config's binding is
        // installed while the old listener still owns its own; tearing the
        // old listener down afterwards must leave the new binding in
        // place (a single-slot registry cleared it here).
        let old = global_listener(OutboundBinding::install(Some(LO)).unwrap());
        let reload = OutboundBinding::install(Some(LO)).expect("loopback must exist");
        drop(old);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        let new = global_listener(reload);
        assert_eq!(meow_common::outbound_interface().as_deref(), Some(LO));
        drop(new);
        assert!(meow_common::outbound_interface().is_none());

        // Rejected reload: its binding goes away first, and the running
        // listener's binding is back in effect rather than cleared.
        let running = global_listener(OutboundBinding::install(Some(LO)).unwrap());
        let rejected = OutboundBinding::install(Some(LO)).expect("loopback must exist");
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

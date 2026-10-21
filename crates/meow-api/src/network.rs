//! PaoPao: read-only views of the system network for the UI — where
//! traffic leaves, the system routes, and the other VPNs we live next to.
//! Everything is built from what the TUN listener's monitor already
//! published (`meow_common::route_table`); the builders are pure.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use meow_common::iface_counters::IfaceBytes;
use meow_common::outbound_balance::{BalanceSnapshot, Link};
use meow_common::route_table::{
    IfaceDns, OutboundStatus, RouteEntry, RouteIfaceKind, RouteTable, VpnClientProc, VpnManual,
};
use serde_json::{json, Value};

/// Specific routes listed per VPN interface in `GET /network/vpns` (the
/// count is always complete).
const VPN_ROUTES_SHOWN: usize = 8;

/// The coexistence fields of `GET /network/outbound`.
///
/// ```json
/// { "fullTunnel": { "iface": "tun0", "since": 1760000000 } | null,
///   "physicalRouteMissing": false,
///   "routeConflict": false,
///   "defaultVia": "physical" | "other-vpn",
///   "followRoutes": false }
/// ```
pub(crate) fn outbound_status_fields(status: &OutboundStatus) -> Value {
    json!({
        "fullTunnel": status.full_tunnel.as_ref().map(|(iface, since)| json!({
            "iface": &**iface,
            "since": epoch_secs(*since),
        })),
        "physicalRouteMissing": status.physical_route_missing,
        "routeConflict": status.route_conflict,
        "defaultVia": status.default_via,
        "followRoutes": status.follow_routes,
    })
}

/// The multi-interface fields of `GET /network/outbound`
/// (`tun.outbound-interfaces`).
///
/// ```json
/// { "candidates": [ { "name": "en0", "kind": "physical" | "unknown" | "virtual",
///                     "ipv4": true, "ipv6": false } ],
///   "balance": null | {
///     "active": true, "sticky": true,
///     "interfaces": [ {
///       "name": "en0",
///       "state": "up" | "no-route" | "missing" | "virtual" | "suspended",
///       "ipv4": true, "ipv6": false,
///       "connections": 3, "assigned": 120,
///       "upload": 1024, "download": 4096, "uploadRate": 0, "downloadRate": 0,
///       "share": 0.5, "latency": 23 | null, "weight": 100,
///       "failures": 0, "retryIn": null | 8, "strictRpFilter": false } ] } }
/// ```
///
/// `candidates`: every interface holding a default route (what the user
/// may choose from — anything not `virtual`). `balance`: `null` unless two
/// or more members are configured; `active` = at least two are usable now.
pub(crate) fn balance_fields(candidates: &[Link], balance: Option<&BalanceSnapshot>) -> Value {
    json!({
        "candidates": candidates.iter().map(|l| json!({
            "name": l.name,
            "kind": l.kind,
            "ipv4": l.v4,
            "ipv6": l.v6,
        })).collect::<Vec<_>>(),
        "balance": balance,
    })
}

fn route_json(e: &RouteEntry) -> Value {
    json!({
        "destination": e.net.to_string(),
        "interface": &*e.iface,
        "kind": e.kind,
        "gateway": e.gateway.map(|g| g.to_string()),
        "isDefault": e.is_default,
        "metric": e.metric,
    })
}

/// `GET /network/routes`: the filtered system routing table in display
/// form, plus where traffic leaves by default.
///
/// ```json
/// { "defaultInterface": "enp3s0" | null,
///   "physicalInterface": "enp3s0" | null,
///   "published": true,
///   "routes": [
///     { "destination": "0.0.0.0/0", "interface": "enp3s0",
///       "kind": "physical" | "other-vpn" | "own-tun" | "other",
///       "gateway": "192.168.1.1" | null, "isDefault": true, "metric": 100 } ] }
/// ```
///
/// `routes` order: default routes (and their split equivalents), then the
/// specific routes longest prefix first, then our own TUN's. `published`:
/// the snapshot is the running monitor's (false: read for this request,
/// no TUN in global mode is up). `defaultInterface`: what outbound sockets
/// bind to by default, null when nothing is bound.
pub(crate) fn routes_body(
    table: &RouteTable,
    default_iface: Option<&str>,
    physical_iface: Option<&str>,
    published: bool,
) -> Value {
    let routes: Vec<Value> = table
        .defaults()
        .iter()
        .chain(table.specific())
        .chain(table.own())
        .map(route_json)
        .collect();
    json!({
        "defaultInterface": default_iface,
        "physicalInterface": physical_iface,
        "published": published,
        "routes": routes,
    })
}

/// What `GET /network/vpns` is built from.
pub(crate) struct VpnView<'a> {
    pub table: &'a RouteTable,
    pub dns: &'a [IfaceDns],
    /// Every interface's addresses (`name`, `address/prefix`).
    pub addresses: &'a [(String, String)],
    /// Every interface's own byte counters, by name.
    pub counters: &'a HashMap<String, IfaceBytes>,
    pub clients: &'a [VpnClientProc],
    pub manual: &'a VpnManual,
    pub status: &'a OutboundStatus,
    pub published: bool,
}

/// `GET /network/vpns`: the other VPNs' interfaces and client programs.
///
/// ```json
/// { "published": true,
///   "vpns": [
///     { "name": "tun0", "tunnel": true,
///       "addresses": ["10.8.0.5/24"],
///       "routeCount": 12, "routes": ["10.8.0.0/16", "172.16.0.0/12"],
///       "dns": ["10.8.0.1"], "searchDomains": ["corp.example.com"],
///       "holdsDefault": false,
///       "rxBytes": 52341234 | null, "txBytes": 1048576 | null } ],
///   "clients": [
///     { "pid": 1234, "name": "openconnect",
///       "path": "/usr/sbin/openconnect", "iface": "tun0" } ],
///   "clientApps": ["name:vpnagentd"],
///   "manualDomains": [
///     { "suffix": "lab.example", "servers": ["10.8.0.1"], "iface": null } ],
///   "gatewayDomains": ["vpn.corp.example"],
///   "fullTunnel": { "iface": "tun0", "since": 1760000000 } | null,
///   "physicalRouteMissing": false, "routeConflict": false,
///   "defaultVia": "physical", "followRoutes": true }
/// ```
///
/// `vpns`: every virtual interface that is not ours and has a route or a
/// DNS configuration; `tunnel` is false for container bridges / VM
/// switches (followed like the rest, but not somebody's VPN — the UI
/// hides them). `routes`: the first few specific routes, `routeCount` all
/// of them. `rxBytes` / `txBytes`: what the interface itself has received
/// and sent since it came up, as the system counts it (this traffic never
/// passes through the core, so no connection lists it); `null` when the
/// system does not tell. `clients`: processes found holding a VPN's device (Linux);
/// `clientApps` / `manualDomains` / `gatewayDomains`: what the
/// configuration says by hand.
/// The last five fields are those of `GET /network/outbound`.
pub(crate) fn vpns_body(view: &VpnView<'_>, is_container: impl Fn(&str) -> bool) -> Value {
    let mut names: Vec<&str> = Vec::new();
    for e in view.table.defaults().iter().chain(view.table.specific()) {
        if e.kind == RouteIfaceKind::OtherVpn && !names.contains(&&*e.iface) {
            names.push(&e.iface);
        }
    }
    for d in view.dns {
        if d.kind == RouteIfaceKind::OtherVpn && !names.contains(&d.iface.as_str()) {
            names.push(&d.iface);
        }
    }
    names.sort_unstable();
    let vpns: Vec<Value> = names
        .iter()
        .map(|name| {
            let routes: Vec<String> = view
                .table
                .specific()
                .filter(|e| &*e.iface == *name)
                .map(|e| e.net.to_string())
                .collect();
            let dns = view.dns.iter().find(|d| d.iface == *name);
            let addresses: Vec<String> = view
                .addresses
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, net)| net.clone())
                .collect();
            let bytes = view.counters.get(*name);
            json!({
                "name": name,
                "tunnel": !is_container(name),
                "addresses": addresses,
                "routeCount": routes.len(),
                "routes": routes.iter().take(VPN_ROUTES_SHOWN).collect::<Vec<_>>(),
                "dns": dns.map(|d| d.servers.iter().map(ToString::to_string).collect::<Vec<_>>())
                    .unwrap_or_default(),
                "searchDomains": dns.map(|d| d.domains.clone()).unwrap_or_default(),
                "holdsDefault": view.table.holds_default(name),
                "rxBytes": bytes.map(|b| b.rx),
                "txBytes": bytes.map(|b| b.tx),
            })
        })
        .collect();
    let manual_domains: Vec<Value> = view
        .manual
        .domains
        .iter()
        .map(|m| {
            json!({
                "suffix": m.suffix,
                "servers": m.servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "iface": m.iface,
            })
        })
        .collect();
    let mut body = json!({
        "published": view.published,
        "vpns": vpns,
        "clients": view.clients,
        "clientApps": view.manual.client_apps,
        "manualDomains": manual_domains,
        "gatewayDomains": view.manual.gateway_domains,
    });
    if let (Some(body), Value::Object(status)) =
        (body.as_object_mut(), outbound_status_fields(view.status))
    {
        body.extend(status);
    }
    body
}

fn epoch_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::route_table::DefaultVia;
    use std::sync::Arc;
    use std::time::Duration;

    /// The exact JSON the app reads for the multi-interface view.
    #[test]
    fn balance_fields_shape() {
        use meow_common::outbound_balance::{
            BalanceOptions, Balancer, DialOutcome, DialScope, LinkKind, LinkSource,
        };
        struct Links(Vec<Link>);
        impl LinkSource for Links {
            fn links(&self) -> Vec<Link> {
                self.0.clone()
            }
            fn kind_of(&self, name: &str) -> Option<LinkKind> {
                (name == "en9").then_some(LinkKind::Physical)
            }
        }
        let link = |name: &str, kind, v6| Link {
            name: name.into(),
            index: 4,
            kind,
            v4: true,
            v6,
            strict_rp_filter: false,
        };
        let links = vec![
            link("en0", LinkKind::Physical, true),
            link("en7", LinkKind::Physical, false),
            link("utun6", LinkKind::Virtual, false),
        ];

        // Not configured: candidates only.
        assert_eq!(
            balance_fields(&links, None),
            json!({
                "candidates": [
                    {"name": "en0", "kind": "physical", "ipv4": true, "ipv6": true},
                    {"name": "en7", "kind": "physical", "ipv4": true, "ipv6": false},
                    {"name": "utun6", "kind": "virtual", "ipv4": true, "ipv6": false},
                ],
                "balance": null,
            })
        );

        let balancer = Balancer::new(&BalanceOptions {
            interfaces: vec!["en0".into(), "en7".into(), "en9".into()],
            sticky: true,
        });
        balancer.refresh(&Links(links));
        let t0 = std::time::Instant::now();
        assert_eq!(balancer.pick(true, None, None, 0, t0).unwrap().member, 0);
        let conn = DialScope::new(None);
        conn.record(&balancer.names()[0], Some((&balancer, 0)));
        conn.add_upload(100);
        conn.add_download(300);
        balancer.report(0, DialOutcome::Connected(Duration::from_millis(23)), t0);
        for _ in 0..3 {
            balancer.report(1, DialOutcome::Failed, t0);
        }
        let snapshot = balancer.snapshot(t0 + Duration::from_secs(2));
        let got = balance_fields(&[], Some(&snapshot));
        assert_eq!(
            got["balance"],
            json!({
                "active": false,
                "sticky": true,
                "interfaces": [
                    {"name": "en0", "state": "up", "ipv4": true, "ipv6": true,
                     "connections": 1, "assigned": 1, "upload": 100, "download": 300,
                     "uploadRate": 0, "downloadRate": 0, "share": 1.0, "latency": 23,
                     "weight": 100, "failures": 0, "retryIn": null, "strictRpFilter": false},
                    {"name": "en7", "state": "suspended", "ipv4": true, "ipv6": false,
                     "connections": 0, "assigned": 0, "upload": 0, "download": 0,
                     "uploadRate": 0, "downloadRate": 0, "share": 0.0, "latency": null,
                     "weight": 100, "failures": 3, "retryIn": 8, "strictRpFilter": false},
                    {"name": "en9", "state": "no-route", "ipv4": false, "ipv6": false,
                     "connections": 0, "assigned": 0, "upload": 0, "download": 0,
                     "uploadRate": 0, "downloadRate": 0, "share": 0.0, "latency": null,
                     "weight": 100, "failures": 0, "retryIn": null, "strictRpFilter": false},
                ],
            })
        );
    }

    #[test]
    fn outbound_status_fields_shape() {
        assert_eq!(
            outbound_status_fields(&OutboundStatus::default()),
            json!({
                "fullTunnel": null,
                "physicalRouteMissing": false,
                "routeConflict": false,
                "defaultVia": "physical",
                "followRoutes": false,
            })
        );
        let status = OutboundStatus {
            full_tunnel: Some((
                Arc::from("tun0"),
                UNIX_EPOCH + Duration::from_secs(1_760_000_000),
            )),
            physical_route_missing: true,
            route_conflict: true,
            default_via: DefaultVia::OtherVpn,
            follow_routes: true,
            physical_iface: None,
        };
        assert_eq!(
            outbound_status_fields(&status),
            json!({
                "fullTunnel": {"iface": "tun0", "since": 1_760_000_000u64},
                "physicalRouteMissing": true,
                "routeConflict": true,
                "defaultVia": "other-vpn",
                "followRoutes": true,
            })
        );
    }

    fn sample_table() -> RouteTable {
        use meow_common::route_table::RawRoute;
        let raw = |net: &str, iface: &str, gw: Option<&str>| RawRoute {
            net: net.parse().unwrap(),
            iface: iface.into(),
            index: 3,
            gateway: gw.map(|g| g.parse().unwrap()),
            metric: 100,
            table: Some(254),
            scoped: false,
        };
        RouteTable::build(
            vec![
                raw("0.0.0.0/0", "enp3s0", Some("192.168.1.1")),
                raw("192.168.1.0/24", "enp3s0", None),
                raw("10.8.0.0/16", "tun0", Some("10.8.0.1")),
                raw("172.16.0.0/12", "tun0", None),
                raw("172.17.0.0/16", "docker0", None),
                raw("0.0.0.0/1", "Meow", None),
            ],
            |n| n == "Meow",
            |n| match n {
                "Meow" => RouteIfaceKind::OwnTun,
                "tun0" | "docker0" => RouteIfaceKind::OtherVpn,
                _ => RouteIfaceKind::Physical,
            },
        )
    }

    #[test]
    fn routes_are_listed_defaults_first_with_their_kind() {
        let body = routes_body(&sample_table(), Some("enp3s0"), Some("enp3s0"), true);
        assert_eq!(body["defaultInterface"], "enp3s0");
        assert_eq!(body["published"], true);
        let routes = body["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 6);
        assert_eq!(
            routes[0],
            json!({"destination": "0.0.0.0/0", "interface": "enp3s0", "kind": "physical",
                   "gateway": "192.168.1.1", "isDefault": true, "metric": 100})
        );
        let vpn = routes
            .iter()
            .find(|r| r["destination"] == "10.8.0.0/16")
            .unwrap();
        assert_eq!(vpn["kind"], "other-vpn");
        assert_eq!(vpn["gateway"], "10.8.0.1");
        assert_eq!(vpn["isDefault"], false);
        let own = routes.last().unwrap();
        assert_eq!(own["kind"], "own-tun");
        assert_eq!(own["gateway"], Value::Null);

        let empty = routes_body(&RouteTable::default(), None, None, false);
        assert_eq!(empty["defaultInterface"], Value::Null);
        assert_eq!(empty["routes"], json!([]));
    }

    #[test]
    fn vpns_list_interfaces_dns_and_client_programs() {
        let table = sample_table();
        let dns = [IfaceDns {
            iface: "tun0".into(),
            kind: RouteIfaceKind::OtherVpn,
            servers: vec!["10.8.0.1".parse().unwrap()],
            domains: vec!["corp.example.com".into()],
        }];
        let addresses = [
            ("tun0".to_string(), "10.8.0.5/24".to_string()),
            ("enp3s0".to_string(), "192.168.1.20/24".to_string()),
        ];
        let clients = [VpnClientProc {
            pid: 1234,
            name: "openconnect".into(),
            path: "/usr/sbin/openconnect".into(),
            iface: "tun0".into(),
        }];
        let manual = VpnManual {
            domains: vec![meow_common::route_table::ManualVpnDomain {
                suffix: "lab.example".into(),
                servers: vec!["10.8.0.1".parse().unwrap()],
                iface: None,
            }],
            client_apps: vec!["name:vpnagentd".into()],
            gateway_domains: vec!["vpn.corp.example".into()],
            known_clients: Vec::new(),
        };
        let status = OutboundStatus {
            follow_routes: true,
            ..Default::default()
        };
        // The system counts tun0; docker0 it does not tell about.
        let counters = HashMap::from([
            (
                "tun0".to_string(),
                IfaceBytes {
                    rx: 5_000_000_000,
                    tx: 1024,
                },
            ),
            ("enp3s0".to_string(), IfaceBytes { rx: 1, tx: 2 }),
        ]);
        let body = vpns_body(
            &VpnView {
                table: &table,
                dns: &dns,
                addresses: &addresses,
                counters: &counters,
                clients: &clients,
                manual: &manual,
                status: &status,
                published: true,
            },
            |n| n.starts_with("docker"),
        );
        assert_eq!(
            body["vpns"],
            json!([
                {"name": "docker0", "tunnel": false, "addresses": [], "routeCount": 1,
                 "routes": ["172.17.0.0/16"], "dns": [], "searchDomains": [],
                 "holdsDefault": false, "rxBytes": null, "txBytes": null},
                {"name": "tun0", "tunnel": true, "addresses": ["10.8.0.5/24"], "routeCount": 2,
                 "routes": ["10.8.0.0/16", "172.16.0.0/12"], "dns": ["10.8.0.1"],
                 "searchDomains": ["corp.example.com"], "holdsDefault": false,
                 "rxBytes": 5_000_000_000u64, "txBytes": 1024},
            ])
        );
        assert_eq!(
            body["clients"],
            json!([{"pid": 1234, "name": "openconnect", "path": "/usr/sbin/openconnect",
                    "iface": "tun0"}])
        );
        assert_eq!(body["clientApps"], json!(["name:vpnagentd"]));
        assert_eq!(
            body["manualDomains"],
            json!([{"suffix": "lab.example", "servers": ["10.8.0.1"], "iface": null}])
        );
        assert_eq!(body["gatewayDomains"], json!(["vpn.corp.example"]));
        assert_eq!(body["followRoutes"], true);
        assert_eq!(body["fullTunnel"], Value::Null);
        assert_eq!(body["defaultVia"], "physical");
    }
}

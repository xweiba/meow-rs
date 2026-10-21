//! Config-parser tests for the `tun:` YAML block (issue #326).
//!
//! These exercise [`meow_config::load_config_from_str`] end-to-end and
//! assert on the resulting `Config.tun` (a [`meow_config::TunConfig`]) —
//! the parser itself (`parse_tun_config`) is exercised through it.
//!
//! # Test plan coverage (T-series)
//!
//! | ID  | Description                                                        |
//! |-----|--------------------------------------------------------------------|
//! | T1  | absent `tun:` → default (disabled)                                 |
//! | T2  | minimal `enable: true` → enabled with defaults                     |
//! | T3  | full section → every typed field lands                             |
//! | T4  | `mtu` below 1280 → hard error                                      |
//! | T5  | invalid `inet4-address` CIDR → hard error                          |
//! | T6  | `dns-hijack: [any:53]` → hijack on                                 |
//! | T7  | `dns-hijack` with only non-53 entries → hijack off (warn-only)     |
//! | T8  | upstream-only fields (`stack`, `strict-route`, …) → warn, not err  |
//! | T8b | `inet6-address` (#375): honoured only under `auto-route: global`,  |
//! |     | string or list form, invalid CIDR → hard error                     |
//! | T9  | `udp-timeout: 0` → hard error                                      |
//! | T10 | `enable: false` with other fields set → parsed but disabled        |
//! | T16 | `TunConfig` semantic equality — the PUT reconcile diff boundary    |
//! |     | (issue #543): respellings/ignored fields equal, real params not  |
//! | T17 | `global_route_outbound_interface` (the pre-build binding gate,    |
//! |     | issue #695) agrees with the parsed `TunConfig`                     |

use std::time::Duration;

use meow_config::load_config_from_str;

async fn expect_load_err(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Ok(_) => panic!("expected load_config_from_str to fail, but it succeeded"),
        Err(e) => e.to_string(),
    }
}

// ─── T1: defaults — no tun: block ─────────────────────────────────────────

#[tokio::test]
async fn t1_no_tun_block_yields_default_disabled() {
    let cfg = load_config_from_str("port: 7890\n")
        .await
        .expect("config must load");
    assert!(!cfg.tun.enable, "default tun must be disabled");
    assert_eq!(cfg.tun.mtu, 1500);
    assert_eq!(cfg.tun.inet4_address.to_string(), "172.19.0.1/30");
    assert!(cfg.tun.auto_route, "auto-route defaults on");
    assert!(!cfg.tun.dns_hijack, "dns-hijack defaults off");
    assert_eq!(
        cfg.tun.max_connections, 256,
        "TUN inherits the global max-connections default"
    );
}

// ─── T2: minimal enable ───────────────────────────────────────────────────

#[tokio::test]
async fn t2_enable_true_with_defaults() {
    let yaml = r#"
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable);
    assert_eq!(cfg.tun.device, None, "device defaults to platform choice");
    assert_eq!(cfg.tun.udp_timeout, Duration::from_secs(60));
}

// ─── T3: full section ─────────────────────────────────────────────────────

#[tokio::test]
async fn t3_full_section_parses_every_field() {
    let yaml = r#"
tun:
  enable: true
  device: meow0
  mtu: 9000
  inet4-address: 198.18.0.1/16
  auto-route: false
  dns-hijack:
    - any:53
  udp-timeout: 120
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable);
    assert_eq!(cfg.tun.device.as_deref(), Some("meow0"));
    assert_eq!(cfg.tun.mtu, 9000);
    assert_eq!(cfg.tun.inet4_address.to_string(), "198.18.0.1/16");
    assert!(!cfg.tun.auto_route);
    assert!(cfg.tun.dns_hijack);
    assert_eq!(cfg.tun.udp_timeout, Duration::from_secs(120));
}

// ─── T4: mtu below the userspace-stack minimum ────────────────────────────

#[tokio::test]
async fn t4_mtu_below_1280_errors() {
    let yaml = r#"
tun:
  enable: true
  mtu: 1000
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("tun.mtu"),
        "error must name tun.mtu: got {err}"
    );
}

// ─── T5: invalid inet4-address ────────────────────────────────────────────

#[tokio::test]
async fn t5_invalid_inet4_address_errors() {
    let yaml = r#"
tun:
  enable: true
  inet4-address: not-a-cidr
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("inet4-address"),
        "error must name inet4-address: got {err}"
    );
}

// ─── T6/T7: dns-hijack entry filtering ────────────────────────────────────

#[tokio::test]
async fn t6_dns_hijack_any_53_enables_hijack() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - any:53
    - 198.18.0.2:53
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.dns_hijack);
}

#[tokio::test]
async fn t7_dns_hijack_non_53_entries_warn_and_disable() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - any:5353
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(
        !cfg.tun.dns_hijack,
        "non-:53 entries must not enable hijack"
    );
}

// ─── T8: upstream-only fields accepted with a warning ─────────────────────

#[tokio::test]
async fn t8_upstream_only_fields_warn_but_load() {
    let yaml = r#"
tun:
  enable: true
  stack: system
  strict-route: true
  auto-detect-interface: true
  inet6-address: fdfe:dcba:9876::1/126
  endpoint-independent-nat: false
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable, "unsupported fields are warn-only");
}

// ─── T8b: inet6-address (#375) ────────────────────────────────────────────
// Opt-in IPv6 capture for global route mode: string or mihomo list form,
// honoured only under `auto-route: global`, validated everywhere.

#[tokio::test]
async fn t8b_inet6_address_is_honoured_only_in_global_mode() {
    let v6 = |yaml: &str| {
        let yaml = yaml.to_string();
        async move { load_config_from_str(&yaml).await.unwrap().tun.inet6_address }
    };
    let want: ipnet::Ipv6Net = "fdfe:dcba:9876::1/126".parse().unwrap();

    // Unset by default — the device stays IPv4-only, in every mode.
    assert_eq!(v6("tun:\n  enable: true\n").await, None);
    assert_eq!(
        v6("tun:\n  enable: true\n  auto-route: global\n").await,
        None
    );

    // Global mode: scalar and mihomo's list form (first entry wins).
    let global = "tun:\n  enable: true\n  auto-route: global\n";
    assert_eq!(
        v6(&format!("{global}  inet6-address: fdfe:dcba:9876::1/126\n")).await,
        Some(want)
    );
    assert_eq!(
        v6(&format!(
            "{global}  inet6-address: [fdfe:dcba:9876::1/126]\n"
        ))
        .await,
        Some(want)
    );
    assert_eq!(
        v6(&format!(
            "{global}  inet6-address:\n    - fdfe:dcba:9876::1/126\n    - fd00::1/64\n"
        ))
        .await,
        Some(want)
    );
    // Empty forms are "unset".
    assert_eq!(v6(&format!("{global}  inet6-address: ''\n")).await, None);
    assert_eq!(v6(&format!("{global}  inet6-address: []\n")).await, None);

    // Every other mode has no IPv6 routes to send into the device: the
    // address is ignored (with a warning), and normalised out so it cannot
    // trigger a listener restart on reload.
    for mode in [
        "",
        "  auto-route: true\n",
        "  auto-route: fake-ip\n",
        "  auto-route: false\n",
    ] {
        let yaml = format!("tun:\n  enable: true\n{mode}  inet6-address: fdfe:dcba:9876::1/126\n");
        assert_eq!(v6(&yaml).await, None, "{yaml}");
    }
}

#[tokio::test]
async fn t8b_invalid_inet6_address_errors_in_every_mode() {
    for yaml in [
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: not-a-cidr\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: 172.19.0.1/30\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: [fdfe::1]\n",
        "tun:\n  enable: true\n  auto-route: global\n  inet6-address: 7\n",
        "tun:\n  enable: true\n  inet6-address: not-a-cidr\n",
    ] {
        let err = expect_load_err(yaml).await;
        assert!(err.contains("inet6-address"), "{yaml}: got {err}");
    }
}

// ─── T9: udp-timeout: 0 ───────────────────────────────────────────────────

#[tokio::test]
async fn t9_udp_timeout_zero_errors() {
    let yaml = r#"
tun:
  enable: true
  udp-timeout: 0
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("udp-timeout"),
        "error must name udp-timeout: got {err}"
    );
}

// ─── T10: disabled section still validates ────────────────────────────────

#[tokio::test]
async fn t10_disabled_section_parses_fields() {
    let yaml = r#"
tun:
  enable: false
  device: meow0
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(!cfg.tun.enable);
    assert_eq!(cfg.tun.device.as_deref(), Some("meow0"));
}

// ─── T11–T14: auto-route modes (#375) ─────────────────────────────────────

#[tokio::test]
async fn t11_auto_route_bool_compat_maps_to_fake_ip() {
    use meow_config::TunRouteMode;

    // mihomo's boolean forms keep working: true = fake-IP scope, false = off.
    let on = load_config_from_str("tun:\n  enable: true\n  auto-route: true\n")
        .await
        .expect("config must load");
    assert!(on.tun.auto_route);
    assert_eq!(on.tun.route_mode, TunRouteMode::FakeIp);

    let off = load_config_from_str("tun:\n  enable: true\n  auto-route: false\n")
        .await
        .expect("config must load");
    assert!(!off.tun.auto_route);

    // Absent → default on, fake-IP scope.
    let default = load_config_from_str("tun:\n  enable: true\n")
        .await
        .expect("config must load");
    assert!(default.tun.auto_route);
    assert_eq!(default.tun.route_mode, TunRouteMode::FakeIp);
}

#[tokio::test]
async fn t12_auto_route_mode_strings() {
    use meow_config::TunRouteMode;

    let fake = load_config_from_str("tun:\n  enable: true\n  auto-route: fake-ip\n")
        .await
        .expect("config must load");
    assert!(fake.tun.auto_route);
    assert_eq!(fake.tun.route_mode, TunRouteMode::FakeIp);

    let global = load_config_from_str("tun:\n  enable: true\n  auto-route: global\n")
        .await
        .expect("config must load");
    assert!(global.tun.auto_route);
    assert_eq!(global.tun.route_mode, TunRouteMode::Global);
}

#[tokio::test]
async fn t13_auto_route_unknown_mode_is_a_hard_error() {
    let err = expect_load_err("tun:\n  enable: true\n  auto-route: everything\n").await;
    assert!(
        err.contains("auto-route") && err.contains("everything"),
        "error must name the field and the bad value: got {err}"
    );
}

#[tokio::test]
async fn t14_outbound_interface_lands_and_empty_is_none() {
    let yaml = "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth0\n";
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interface.as_deref(), Some("eth0"));

    // Empty string is treated as unset (auto-detect), and setting the field
    // in fake-ip mode is warn-only, not an error.
    let yaml = "tun:\n  enable: true\n  outbound-interface: ''\n";
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interface, None);
}

// ─── T14a (PaoPao): outbound balancing keys ──────────────────────────────

#[tokio::test]
async fn t14a_outbound_interfaces_need_two_usable_names() {
    use meow_config::{global_route_balance, global_route_outbound_interface, parse_raw_yaml};
    const HEAD: &str = "tun:\n  enable: true\n  auto-route: global\n";

    // Absent: off, sticky reads true.
    let cfg = load_config_from_str(HEAD).await.expect("config must load");
    assert!(cfg.tun.outbound_interfaces.is_empty());
    assert!(cfg.tun.outbound_sticky);
    assert_eq!(cfg.tun.outbound_interface, None);

    // Two or more: balancing; invalid entries are dropped, not an error.
    let yaml = format!(
        "{HEAD}  outbound-interfaces:\n    - ' en0 '\n    - ''\n    - 7\n    - en0\n    \
         - [x]\n    - 以太网 2\n    - \"bad\\tname\"\n  outbound-sticky: false\n"
    );
    let cfg = load_config_from_str(&yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interfaces, ["en0", "以太网 2"]);
    assert!(!cfg.tun.outbound_sticky);
    assert_eq!(
        cfg.tun.outbound_interface, None,
        "the default stays automatic"
    );
    let raw = parse_raw_yaml(&yaml).unwrap();
    let pre = global_route_balance(raw.tun.as_ref()).expect("balancing");
    assert_eq!(pre.interfaces, cfg.tun.outbound_interfaces);
    assert!(!pre.sticky);
    assert_eq!(
        global_route_outbound_interface(raw.tun.as_ref()),
        Some(None)
    );

    // Sticky by default; an explicit default interface is kept beside it.
    let yaml =
        format!("{HEAD}  outbound-interface: eth0\n  outbound-interfaces: [eth0, eth1, eth2]\n");
    let cfg = load_config_from_str(&yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interfaces, ["eth0", "eth1", "eth2"]);
    assert!(cfg.tun.outbound_sticky);
    assert_eq!(cfg.tun.outbound_interface.as_deref(), Some("eth0"));

    // One usable name: the same as `outbound-interface`, no balancing —
    // unless that key is set itself.
    for list in ["[eth1]", "[eth1, eth1, '']", "eth1"] {
        let yaml = format!("{HEAD}  outbound-interfaces: {list}\n  outbound-sticky: false\n");
        let cfg = load_config_from_str(&yaml).await.expect("config must load");
        assert!(cfg.tun.outbound_interfaces.is_empty(), "{list}");
        assert!(cfg.tun.outbound_sticky, "{list}: normalised while off");
        assert_eq!(
            cfg.tun.outbound_interface.as_deref(),
            Some("eth1"),
            "{list}"
        );
        let raw = parse_raw_yaml(&yaml).unwrap();
        assert!(global_route_balance(raw.tun.as_ref()).is_none());
        assert_eq!(
            global_route_outbound_interface(raw.tun.as_ref()),
            Some(Some("eth1".to_string()))
        );
    }
    let yaml = format!("{HEAD}  outbound-interface: eth0\n  outbound-interfaces: [eth1]\n");
    let cfg = load_config_from_str(&yaml).await.expect("config must load");
    assert_eq!(cfg.tun.outbound_interface.as_deref(), Some("eth0"));

    // Nothing usable, or not a list: off.
    for list in ["[]", "['', 3]", "{a: b}", "~"] {
        let yaml = format!("{HEAD}  outbound-interfaces: {list}\n");
        let cfg = load_config_from_str(&yaml).await.expect("config must load");
        assert!(cfg.tun.outbound_interfaces.is_empty(), "{list}");
        assert_eq!(cfg.tun.outbound_interface, None, "{list}");
    }

    // Outside global mode both keys are ignored (and do not make two
    // otherwise equal sections differ: no listener restart).
    let fake_ip = "tun:\n  enable: true\n  outbound-interfaces: [eth0, eth1]\n  \
                   outbound-sticky: false\n";
    let cfg = load_config_from_str(fake_ip)
        .await
        .expect("config must load");
    let plain = load_config_from_str("tun:\n  enable: true\n")
        .await
        .expect("config must load");
    assert!(cfg.tun.outbound_interfaces.is_empty());
    assert_eq!(cfg.tun, plain.tun);
}

// ─── T14b (PaoPao): coexistence keys ──────────────────────────────────────

#[tokio::test]
async fn t14b_vpn_coexistence_keys_land_in_global_mode_only() {
    use meow_common::route_table::DefaultVia;

    // Absent: the defaults, i.e. the behaviour before the keys existed.
    let cfg = load_config_from_str("tun:\n  enable: true\n  auto-route: global\n")
        .await
        .expect("config must load");
    assert_eq!(cfg.tun.default_via, DefaultVia::Physical);
    assert!(!cfg.tun.follow_system_routes);
    assert!(cfg.tun.route_exclude_address.is_empty());

    let yaml = "tun:\n  enable: true\n  auto-route: global\n  default-via: other-vpn\n  \
                follow-system-routes: true\n  route-exclude-address:\n    - 10.1.2.3/8\n    \
                - 192.168.50.7\n    - fd00::/8\n    - 10.0.0.0/8\n";
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.default_via, DefaultVia::OtherVpn);
    assert!(cfg.tun.follow_system_routes);
    let nets: Vec<String> = cfg
        .tun
        .route_exclude_address
        .iter()
        .map(ToString::to_string)
        .collect();
    // Host bits dropped, a bare address is a host route, duplicates folded.
    assert_eq!(nets, ["10.0.0.0/8", "192.168.50.7/32", "fd00::/8"]);

    // One string instead of a list.
    let yaml =
        "tun:\n  enable: true\n  auto-route: global\n  route-exclude-address: 172.16.0.0/12\n";
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.route_exclude_address.len(), 1);

    // Outside global mode they do nothing and must not reach the restart
    // diff.
    let plain = load_config_from_str("tun:\n  enable: true\n")
        .await
        .expect("config must load")
        .tun;
    let ignored = load_config_from_str(
        "tun:\n  enable: true\n  default-via: other-vpn\n  follow-system-routes: true\n  \
         route-exclude-address:\n    - 10.0.0.0/8\n",
    )
    .await
    .expect("config must load")
    .tun;
    assert_eq!(plain, ignored);

    // Hand-entered VPN names and client programs.
    let yaml = "tun:\n  enable: true\n  auto-route: global\n  vpn-domains:\n    \
                - '+.Corp.Example'\n    - suffix: lab.example\n      servers: [10.8.0.1, '10.8.0.1', 'fd00::53']\n      \
                iface: tun0\n    - corp.example\n  vpn-client-apps:\n    - name:openconnect\n    \
                - ' path:/opt/cisco '\n    - name:openconnect\n";
    let tun = load_config_from_str(yaml)
        .await
        .expect("config must load")
        .tun;
    assert_eq!(tun.vpn_domains.len(), 2);
    assert_eq!(tun.vpn_domains[0].suffix, "corp.example");
    assert!(tun.vpn_domains[0].servers.is_empty());
    assert_eq!(tun.vpn_domains[1].suffix, "lab.example");
    assert_eq!(tun.vpn_domains[1].servers.len(), 2);
    assert_eq!(tun.vpn_domains[1].iface.as_deref(), Some("tun0"));
    assert_eq!(tun.vpn_client_apps, ["name:openconnect", "path:/opt/cisco"]);
    let known = load_config_from_str(
        "tun:\n  enable: true\n  auto-route: global\n  vpn-known-clients:\n    \
         - name:vpnagentd\n    - ' path:/opt/cisco '\n    - name:vpnagentd\n",
    )
    .await
    .expect("config must load")
    .tun;
    assert_eq!(
        known.vpn_known_clients,
        ["name:vpnagentd", "path:/opt/cisco"]
    );
    assert!(known.vpn_client_apps.is_empty());
    let gw = load_config_from_str(
        "tun:\n  enable: true\n  auto-route: global\n  vpn-gateway-domains:\n    \
         - '+.VPN.Corp.Example'\n    - vpn.corp.example\n    - gw.example.\n",
    )
    .await
    .expect("config must load")
    .tun;
    assert_eq!(gw.vpn_gateway_domains, ["vpn.corp.example", "gw.example"]);
    let bad = "tun:\n  enable: true\n  auto-route: global\n  vpn-domains:\n    \
               - suffix: x.example\n      servers: [not-an-ip]\n";
    assert!(load_config_from_str(bad).await.is_err());
    let ignored = load_config_from_str(
        "tun:\n  enable: true\n  vpn-domains: [corp.example]\n  vpn-client-apps: [name:x]\n  \
         vpn-gateway-domains: [gw.example]\n",
    )
    .await
    .expect("config must load")
    .tun;
    assert_eq!(plain, ignored);

    // The raw-document gate the binary uses before the build agrees.
    let raw = meow_config::parse_raw_yaml(yaml).unwrap();
    assert_eq!(
        meow_config::global_route_binding_policy(raw.tun.as_ref()),
        (DefaultVia::Physical, false)
    );
    let raw = meow_config::parse_raw_yaml(
        "tun:\n  enable: true\n  auto-route: global\n  default-via: other-vpn\n  \
         follow-system-routes: true\n",
    )
    .unwrap();
    assert_eq!(
        meow_config::global_route_binding_policy(raw.tun.as_ref()),
        (DefaultVia::OtherVpn, true)
    );
    assert_eq!(
        meow_config::global_route_binding_policy(None),
        (DefaultVia::Physical, false)
    );

    // Bad values are hard errors naming the field.
    let err =
        expect_load_err("tun:\n  enable: true\n  auto-route: global\n  default-via: auto\n").await;
    assert!(err.contains("default-via") && err.contains("auto"), "{err}");
    let err = expect_load_err(
        "tun:\n  enable: true\n  auto-route: global\n  route-exclude-address:\n    - 10.0.0.0/40\n",
    )
    .await;
    assert!(
        err.contains("route-exclude-address") && err.contains("10.0.0.0/40"),
        "{err}"
    );
}

/// `route-exclude-address` is bounded: dozens of entries load, a list that
/// would become thousands of routes is refused (each single address costs
/// one route per prefix bit), and outside global mode the list is not
/// used, so it is not counted either.
#[tokio::test]
async fn t14c_route_exclude_address_is_bounded() {
    let list = |n: usize| -> String {
        (0..n)
            .map(|i| format!("    - 10.{}.{}.1/32\n", i / 250, i % 250))
            .collect()
    };
    let global = |n: usize| {
        format!(
            "tun:\n  enable: true\n  auto-route: global\n  route-exclude-address:\n{}",
            list(n)
        )
    };
    let cfg = load_config_from_str(&global(40)).await.unwrap();
    assert_eq!(cfg.tun.route_exclude_address.len(), 40);

    let err = expect_load_err(&global(2000)).await;
    assert!(
        err.contains("route-exclude-address") && err.contains("at most"),
        "{err}"
    );

    let fake_ip = format!(
        "tun:\n  enable: true\n  route-exclude-address:\n{}",
        list(2000)
    );
    let cfg = load_config_from_str(&fake_ip).await.unwrap();
    assert!(cfg.tun.route_exclude_address.is_empty());

    // A server that is not an address is a hard error too.
    let err = expect_load_err(
        "tun:\n  enable: true\n  auto-route: global\n  vpn-domains:\n    \
         - suffix: corp.example\n      servers: [not-an-ip]\n",
    )
    .await;
    assert!(
        err.contains("vpn-domains") && err.contains("not-an-ip"),
        "{err}"
    );
}

// ─── T15: global max-connections applies to TUN ───────────────────────────

#[tokio::test]
async fn t15_global_max_connections_applies_to_tun() {
    let yaml = r#"
max-connections: 32
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.max_connections, 32);
}

#[tokio::test]
async fn t15b_max_connections_zero_is_unlimited() {
    let yaml = r#"
max-connections: 0
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert_eq!(cfg.tun.max_connections, 0);
}

// ─── T16: semantic equality — the PUT reconcile diff boundary (issue #543) ──
// `PUT /configs` restarts a running TUN listener when the parsed
// `TunConfig` changes, so respellings/ignored fields must compare equal
// and real parameters must not.

#[tokio::test]
async fn t16_tun_config_semantic_equality_boundary() {
    async fn tun(yaml: &str) -> meow_config::TunConfig {
        load_config_from_str(yaml)
            .await
            .expect("config must load")
            .tun
    }

    let explicit_bool = tun("tun:\n  enable: true\n  auto-route: true\n").await;
    let fake_ip_mode = tun("tun:\n  enable: true\n  auto-route: fake-ip\n").await;
    let omitted = tun("tun:\n  enable: true\n").await;
    assert_eq!(explicit_bool, fake_ip_mode, "`true` ≡ `fake-ip` mode");
    assert_eq!(explicit_bool, omitted, "omitted ≡ default fake-ip scope");

    let ignored_fields = tun("tun:\n  enable: true\n  stack: gvisor\n  strict-route: true\n").await;
    assert_eq!(
        explicit_bool, ignored_fields,
        "warn-only upstream fields must not change the diff"
    );

    let explicit_mtu = tun("tun:\n  enable: true\n  mtu: 1500\n").await;
    assert_eq!(explicit_mtu, omitted, "explicit default ≡ omitted");

    assert_ne!(
        omitted,
        tun("tun:\n  enable: true\n  mtu: 9000\n").await,
        "a real mtu change must differ"
    );
    assert_ne!(
        omitted,
        tun("tun:\n  enable: true\n  dns-hijack:\n    - any:53\n").await,
        "a real dns-hijack change must differ"
    );
    assert_ne!(
        omitted,
        tun("max-connections: 512\ntun:\n  enable: true\n").await,
        "inherited max-connections must differ"
    );

    // `outbound-interface` is ignored outside `auto-route: global` — a
    // value that does nothing must not reach the diff, or a PUT touching
    // only it would bounce a healthy fake-ip listener (issue #543
    // review).
    let ignored_iface = tun("tun:\n  enable: true\n  outbound-interface: eth9\n").await;
    assert_eq!(
        omitted, ignored_iface,
        "outbound-interface under fake-ip scope must not change the diff"
    );
    assert_ne!(
        ignored_iface,
        tun("tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth9\n").await,
        "the same field under `global` is real and must differ"
    );

    // Remaining listener inputs are covered by the derived PartialEq —
    // pin a representative from each family so the diff can't silently
    // stop noticing a field (issue #543 review).
    for (yaml, what) in [
        ("tun:\n  enable: true\n  device: tun7\n", "device"),
        (
            "tun:\n  enable: true\n  inet4-address: 10.9.0.1/24\n",
            "inet4-address",
        ),
        ("tun:\n  enable: true\n  udp-timeout: 30\n", "udp-timeout"),
        ("tun:\n  enable: true\n  auto-route: global\n", "route_mode"),
    ] {
        assert_ne!(omitted, tun(yaml).await, "a real {what} change must differ");
    }
}

// ─── T17: the pre-build global-route gate agrees with the parser (#695) ───
// The binary installs the outbound-interface binding from the *raw*
// document before `build_config` dials anything. That gate must select
// exactly the configs the parser turns into an enabled global-scope TUN,
// with the same interface — never a fake-IP / disabled one (zero change
// there), never miss a global one (its early sockets would loop).

#[tokio::test]
async fn t17_global_route_gate_matches_parsed_config() {
    use meow_config::{global_route_outbound_interface, parse_raw_yaml, TunRouteMode};

    for yaml in [
        "port: 7890\n",
        "tun:\n  enable: true\n",
        "tun:\n  enable: false\n  auto-route: global\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: true\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: false\n",
        "tun:\n  enable: true\n  auto-route: fake-ip\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: global\n",
        "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth0\n",
        "tun:\n  enable: true\n  auto-route: global\n  outbound-interface: ''\n",
        "tun:\n  enable: true\n  auto-route: everything\n",
    ] {
        let raw = parse_raw_yaml(yaml).expect("raw YAML must parse");
        let gate = global_route_outbound_interface(raw.tun.as_ref());
        let expected = match load_config_from_str(yaml).await {
            Ok(cfg)
                if cfg.tun.enable
                    && cfg.tun.auto_route
                    && cfg.tun.route_mode == TunRouteMode::Global =>
            {
                Some(cfg.tun.outbound_interface)
            }
            // Not global scope, or rejected by the parser: no early binding.
            _ => None,
        };
        assert_eq!(gate, expected, "{yaml}");
    }

    // Spot-check the global cases explicitly so a regression to "always
    // None" can't pass by matching a parser that also stopped selecting
    // global scope.
    let gate =
        |yaml: &str| global_route_outbound_interface(parse_raw_yaml(yaml).unwrap().tun.as_ref());
    assert_eq!(
        gate("tun:\n  enable: true\n  auto-route: global\n  outbound-interface: eth0\n"),
        Some(Some("eth0".to_owned()))
    );
    assert_eq!(
        gate("tun:\n  enable: true\n  auto-route: global\n"),
        Some(None),
        "no outbound-interface → auto-detect"
    );
}

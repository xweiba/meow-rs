//! The core's config: built by `meow_paopao` from the box's settings and
//! subscriptions exactly as the app builds it (same code, same defaults),
//! then given the box's runtime: the TUN fd of the socket pair, the DNS
//! listener the DNS front asks, the controller on 127.0.0.1 only.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Context as _;
use serde_json::{json, Map, Value};

/// The core's TUN MTU: what one Ethernet frame carries.
pub const TUN_MTU: usize = 1500;

/// Host-side inputs of a build. `Debug` hides the secret.
#[derive(Clone)]
pub struct Runtime {
    /// The core's API (127.0.0.1).
    pub controller: SocketAddr,
    /// The API's secret.
    pub secret: String,
    /// The core's DNS listener (127.0.0.1) the DNS front forwards to.
    pub dns: SocketAddr,
    /// The core's end of the socket pair.
    pub tun_fd: i32,
    /// The box's address, when it has one (subnet conditions in the
    /// settings match on it).
    pub addr: Option<Ipv4Addr>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("controller", &self.controller)
            .field("secret", &"<redacted>")
            .field("dns", &self.dns)
            .field("tun_fd", &self.tun_fd)
            .field("addr", &self.addr)
            .finish()
    }
}

/// The build input (`ProxyController.configInput()` shape): a wired
/// network, no IPv6, the VPN-only switch on (the TUN carries everything,
/// so the app's fake-ip DNS), no route API / speed test / process lookup.
pub fn build_input(
    settings: &Value,
    subscriptions: &[Value],
    rt: &Runtime,
    now_ms: i64,
    utc_offset_min: i64,
) -> Value {
    let addresses: Vec<String> = rt.addr.iter().map(ToString::to_string).collect();
    json!({
        "subscriptions": subscriptions,
        "settings": settings,
        "network": { "kind": "ethernet", "addresses": addresses },
        "ipv6": false,
        "vpnOnly": true,
        "now": now_ms,
        "utcOffset": utc_offset_min,
        "exits": {},
        "resolved": {},
        "strategy": "smart",
        "modules": [],
        "sshSecrets": {},
        "runtime": {
            "controllerPort": rt.controller.port(),
            "secret": rt.secret,
            "logLevel": "warn",
            "ipv6": false,
            "findProcess": false,
        },
    })
}

/// What one build gives the box.
#[derive(Clone)]
pub struct CoreConfig {
    /// The config as YAML (holds secrets: never logged).
    pub yaml: String,
    /// The `paopao-hosts` entries, for the DNS front's real answers.
    pub hosts: Option<Value>,
    /// Names of the lines (proxies) in it.
    pub lines: usize,
}

/// The core's config for these settings and subscriptions.
pub fn core_config(
    settings: &Value,
    subscriptions: &[Value],
    rt: &Runtime,
    now_ms: i64,
    utc_offset_min: i64,
) -> anyhow::Result<CoreConfig> {
    let input = build_input(settings, subscriptions, rt, now_ms, utc_offset_min);
    let out = meow_paopao::build(&meow_paopao::BuildInput::from_json(&input));
    let mut c: Map<String, Value> = out.config;
    // Nothing on the host's ports: devices come in through the TUN.
    c.shift_remove("mixed-port");
    c.insert("allow-lan".into(), false.into());
    c.insert("bind-address".into(), "127.0.0.1".into());
    c.insert(
        "external-controller".into(),
        rt.controller.to_string().into(),
    );
    let dns = c
        .entry("dns")
        .or_insert_with(|| json!({ "enable": true }))
        .as_object_mut()
        .context("dns section is not a mapping")?;
    dns.insert("listen".into(), rt.dns.to_string().into());
    c.insert(
        "tun".into(),
        json!({
            "enable": true,
            "file-descriptor": rt.tun_fd,
            "auto-route": false,
            "mtu": TUN_MTU,
            // DNS a routed device sends to other servers goes to the core
            // too (fake-ip); DNS to the box's own address never enters the
            // TUN (the DNS front answers it).
            "dns-hijack": ["any:53"],
        }),
    );
    let hosts = c.get("paopao-hosts").cloned();
    let lines = c
        .get("proxies")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let yaml = serde_yaml::to_string(&Value::Object(c)).context("config to YAML")?;
    Ok(CoreConfig { yaml, hosts, lines })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> Runtime {
        Runtime {
            controller: "127.0.0.1:41000".parse().unwrap(),
            secret: "s3cret".into(),
            dns: "127.0.0.1:41001".parse().unwrap(),
            tun_fd: 9,
            addr: Some(Ipv4Addr::new(192, 168, 1, 50)),
        }
    }

    fn golden_subscriptions() -> Vec<Value> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../meow-paopao/tests/golden/build/regions--default--v4.json"
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["input"]["subscriptions"].as_array().unwrap().clone()
    }

    fn yaml(c: &CoreConfig) -> serde_yaml::Value {
        serde_yaml::from_str(&c.yaml).unwrap()
    }

    #[test]
    fn default_settings_get_the_box_runtime() {
        let c = core_config(&json!({}), &[], &rt(), 0, 480).unwrap();
        let y = yaml(&c);
        assert!(y.get("mixed-port").is_none());
        assert_eq!(y["allow-lan"], false);
        assert_eq!(y["external-controller"], "127.0.0.1:41000");
        assert_eq!(y["secret"], "s3cret");
        assert_eq!(y["dns"]["listen"], "127.0.0.1:41001");
        assert_eq!(y["dns"]["enhanced-mode"], "fake-ip", "the app's TUN DNS");
        assert_eq!(y["tun"]["file-descriptor"], 9);
        assert_eq!(y["tun"]["auto-route"], false);
        assert_eq!(y["tun"]["mtu"], 1500);
        assert_eq!(y["mode"], "rule");
        assert_eq!(c.lines, 0);
        assert!(c.hosts.is_none());
    }

    #[test]
    fn subscriptions_and_mode_reach_the_config() {
        let subs = golden_subscriptions();
        let smart = core_config(&json!({}), &subs, &rt(), 1, 0).unwrap();
        assert!(smart.lines > 10, "{}", smart.lines);
        let global = core_config(&json!({"mode": "global"}), &subs, &rt(), 1, 0).unwrap();
        let direct = core_config(&json!({"mode": "direct"}), &subs, &rt(), 1, 0).unwrap();
        assert_ne!(smart.yaml, global.yaml);
        assert_ne!(smart.yaml, direct.yaml);
        // The same input builds the same config (hot reload compares).
        assert_eq!(
            smart.yaml,
            core_config(&json!({}), &subs, &rt(), 1, 0).unwrap().yaml
        );
    }

    #[test]
    fn hosts_settings_come_back_for_the_dns_front() {
        let settings = json!({"hosts": [
            {"match": "exact", "pattern": "nas.home", "address": "192.168.1.10"}
        ]});
        let c = core_config(&settings, &[], &rt(), 0, 0).unwrap();
        let rules = crate::dns::HostRule::from_config(c.hosts.as_ref());
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn the_input_is_the_apps_shape() {
        let i = build_input(&json!({"mode": "smart"}), &[], &rt(), 5, 480);
        assert_eq!(i["network"]["addresses"][0], "192.168.1.50");
        assert_eq!(i["vpnOnly"], true);
        assert_eq!(i["runtime"]["controllerPort"], 41000);
        assert_eq!(i["utcOffset"], 480);
        assert!(!format!("{:?}", rt()).contains("s3cret"));
    }
}

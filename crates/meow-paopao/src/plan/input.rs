//! The build input: everything config generation reads, as one JSON
//! document (Dart: `ProxyController.configInput()`).

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::dart::Dv;
use crate::model::network::{effective_settings, NetworkInfo};
use crate::model::settings::ProxySettings;
use crate::model::subscription::Subscription;
use crate::pool::{PoolInput, PoolSource};

/// How the automatic groups choose (Dart `AutoStrategy`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum AutoStrategy {
    /// Per-site learning from real connections (default).
    #[default]
    Smart,
    /// Periodic probe, fastest overall.
    UrlTest,
}

impl AutoStrategy {
    /// The Dart enum name: `smart`, `urlTest`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Smart => "smart",
            Self::UrlTest => "urlTest",
        }
    }

    /// By Dart enum name; anything else is [`AutoStrategy::Smart`].
    pub fn from_name(v: &str) -> Self {
        if v == "urlTest" {
            Self::UrlTest
        } else {
            Self::Smart
        }
    }
}

/// The route API's access (`runtime.route`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteAccess {
    /// The key clients send.
    pub key: String,
    /// Other devices on the local network may use it.
    pub lan: bool,
}

/// Inputs from the running host rather than the user (Dart
/// `RuntimeOptions.toJson`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOptions {
    /// The core's API port.
    pub controller_port: i64,
    /// The core's API secret.
    pub secret: String,
    /// Where the core keeps its cache; None = its default.
    pub cache_file: Option<String>,
    /// The speed-test inbound's port.
    pub speed_test_port: Option<i64>,
    /// `warn` unless set.
    pub log_level: String,
    /// The core may use IPv6 (default true).
    pub ipv6: bool,
    /// The route API, when on.
    pub route: Option<RouteAccess>,
    /// The route API inbound's port.
    pub route_port: Option<i64>,
    /// The MITM inbound's port (modules).
    pub mitm_port: Option<i64>,
    /// Look up every connection's program (desktops).
    pub find_process: bool,
}

impl Default for RuntimeOptions {
    fn default() -> Self {
        Self {
            controller_port: 0,
            secret: String::new(),
            cache_file: None,
            speed_test_port: None,
            log_level: "warn".into(),
            ipv6: true,
            route: None,
            route_port: None,
            mitm_port: None,
            find_process: false,
        }
    }
}

fn int_of(v: Option<&Value>) -> Option<i64> {
    v.and_then(|n| Dv::from_json(n).as_int_opt().ok().flatten())
}

fn str_of(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_owned)
}

fn bool_of(v: Option<&Value>, default: bool) -> bool {
    v.and_then(Value::as_bool).unwrap_or(default)
}

fn strings_of(v: Option<&Value>) -> IndexMap<String, String> {
    v.and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

impl RuntimeOptions {
    /// Reads `runtime`; missing or mistyped fields take the defaults.
    pub fn from_json(v: &Value) -> Self {
        let d = Self::default();
        Self {
            controller_port: int_of(v.get("controllerPort")).unwrap_or(d.controller_port),
            secret: str_of(v.get("secret")).unwrap_or(d.secret),
            cache_file: str_of(v.get("cacheFile")),
            speed_test_port: int_of(v.get("speedTestPort")),
            log_level: str_of(v.get("logLevel")).unwrap_or(d.log_level),
            ipv6: bool_of(v.get("ipv6"), d.ipv6),
            route: v
                .get("route")
                .and_then(Value::as_object)
                .map(|r| RouteAccess {
                    key: str_of(r.get("key")).unwrap_or_default(),
                    lan: bool_of(r.get("lan"), false),
                }),
            route_port: int_of(v.get("routePort")),
            mitm_port: int_of(v.get("mitmPort")),
            find_process: bool_of(v.get("findProcess"), d.find_process),
        }
    }
}

/// Everything a build reads (Dart `ProxyController.configInput()`).
///
/// Settings come as saved; [`BuildInput::effective`] applies the network
/// and `vpn_only`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BuildInput {
    /// In the user's priority order.
    pub subscriptions: Vec<Subscription>,
    /// As saved (raw: not yet applied to the network).
    pub settings: ProxySettings,
    /// The network the device is on.
    pub network: NetworkInfo,
    /// The network can reach IPv6.
    pub ipv6: bool,
    /// Phones: the system VPN covers everything (TUN on, no system proxy).
    pub vpn_only: bool,
    /// Current time, Unix milliseconds.
    pub now: i64,
    /// Measured exit country by `ip:port` / `[v6]:port`.
    pub exits: IndexMap<String, String>,
    /// Server domains (lowercase) resolved to an IP.
    pub resolved: IndexMap<String, String>,
    /// How the automatic groups choose.
    pub strategy: AutoStrategy,
    /// The script modules (`ScriptModule.toJson` without `updatedAt`), not
    /// yet modelled.
    pub modules: Vec<Value>,
    /// SSH credentials by `ssh/<chain>/<hop>`; never logged.
    pub ssh_secrets: IndexMap<String, String>,
    /// Host-side options.
    pub runtime: RuntimeOptions,
}

impl BuildInput {
    /// Reads the build input JSON; missing or mistyped fields read as
    /// empty / false / 0 / defaults.
    pub fn from_json(v: &Value) -> Self {
        Self {
            subscriptions: v
                .get("subscriptions")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Subscription::from_json).collect())
                .unwrap_or_default(),
            settings: ProxySettings::from_json(v.get("settings").unwrap_or(&Value::Null)),
            network: v
                .get("network")
                .and_then(|n| serde_json::from_value(n.clone()).ok())
                .unwrap_or_default(),
            ipv6: bool_of(v.get("ipv6"), false),
            vpn_only: bool_of(v.get("vpnOnly"), false),
            now: int_of(v.get("now")).unwrap_or(0),
            exits: strings_of(v.get("exits")),
            resolved: strings_of(v.get("resolved")),
            strategy: v
                .get("strategy")
                .and_then(Value::as_str)
                .map(AutoStrategy::from_name)
                .unwrap_or_default(),
            modules: v
                .get("modules")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            ssh_secrets: strings_of(v.get("sshSecrets")),
            runtime: RuntimeOptions::from_json(v.get("runtime").unwrap_or(&Value::Null)),
        }
    }

    /// The settings in force (Dart `ProxyController.effective`): the
    /// network's ([`effective_settings`]), and on a VPN-only phone TUN on
    /// with no system proxy.
    pub fn effective(&self) -> ProxySettings {
        let mut e = effective_settings(&self.settings, &self.network);
        if self.vpn_only {
            e.tun = true;
            e.system_proxy = false;
        }
        e
    }

    /// What the pool is built from.
    pub fn pool_input(&self) -> PoolInput {
        PoolInput {
            subscriptions: self
                .subscriptions
                .iter()
                .map(|s| PoolSource {
                    nodes: s.nodes.clone(),
                    usage: s.usage,
                })
                .collect(),
            exits: self.exits.clone(),
            resolved: self.resolved.clone(),
            ipv6: self.ipv6,
            now: self.now,
        }
    }
}

impl<'de> Deserialize<'de> for BuildInput {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(d)?))
    }
}

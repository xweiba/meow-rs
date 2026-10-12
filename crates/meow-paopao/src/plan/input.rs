//! The build input: everything config generation reads, as one JSON
//! document (Dart: `ProxyController.configInput()`).

use std::fmt;
use std::net::IpAddr;

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

/// The route API's access (`runtime.route`). `Debug` hides the key.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RouteAccess {
    /// The key clients send.
    pub key: String,
    /// Other devices on the local network may use it.
    pub lan: bool,
}

/// Inputs from the running host rather than the user (Dart
/// `RuntimeOptions.toJson`). `Debug` hides the API secret and the route key.
#[derive(Clone, PartialEq, Eq)]
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
    /// The app itself as an app matcher (`path:<dir>` / `name:<file>`):
    /// its connections through the TUN go direct. None (phones, an older
    /// controller) = no such rule.
    pub self_app: Option<String>,
    /// Living beside another VPN (desktops, with the TUN). None (phones,
    /// an older controller) = the tun section as before.
    pub vpn: Option<VpnOptions>,
    /// Which interfaces outbound connections leave by (desktops, with the
    /// TUN). None (phones, an older controller, nothing chosen) = the tun
    /// section as before.
    pub outbound: Option<OutboundOptions>,
}

/// `runtime.outbound`: the physical interfaces the user chose for outbound
/// connections. One = leave by it; two or more = spread connections over
/// them (the core chooses per connection, skips one that is down and takes
/// it back when it returns).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundOptions {
    /// Interface names, cleaned, at least one.
    pub interfaces: Vec<String>,
    /// The same destination keeps its interface (default true). Only
    /// means something with two or more interfaces.
    pub sticky: bool,
}

/// Most interfaces kept (the core's `MAX_MEMBERS`).
const OUTBOUND_MAX: usize = 8;
/// Longest interface name kept (the core's `MAX_NAME_LEN`).
const OUTBOUND_NAME_MAX: usize = 255;

impl OutboundOptions {
    /// Reads `runtime.outbound`; None unless it is an object with at least
    /// one usable interface name. A name is trimmed; an empty one, one
    /// with a control character, an over-long one and a repeated one are
    /// dropped, as is everything past the eighth — the same cleaning the
    /// core does (`meow_common::outbound_balance::clean_interfaces`).
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let mut interfaces = list_of(o.get("interfaces"), |x| {
            let name = x.as_str()?.trim();
            (!name.is_empty()
                && name.chars().count() <= OUTBOUND_NAME_MAX
                && !name.chars().any(char::is_control))
            .then(|| name.to_owned())
        });
        interfaces.truncate(OUTBOUND_MAX);
        (!interfaces.is_empty()).then(|| Self {
            interfaces,
            sticky: bool_of(o.get("sticky"), true),
        })
    }
}

/// `runtime.vpn`: what the controller hands down about other VPNs. The
/// core reads their routes, DNS and client processes itself; the lists
/// here are the user's hand-entered fallbacks. Entries the core would
/// refuse (it fails to start on one) are dropped on reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnOptions {
    /// `physical` / `other-vpn`; None = the core's default (`physical`).
    pub default_via: Option<String>,
    /// Destinations inside another VPN's routes leave by that VPN
    /// (default true).
    pub follow_routes: bool,
    /// Networks kept out of the TUN, as `address/prefix`.
    pub exclude_nets: Vec<String>,
    /// Names the other VPN's DNS answers.
    pub internal_domains: Vec<InternalDomain>,
    /// The other VPN's server names.
    pub gateway_domains: Vec<String>,
    /// The other VPN's client programs (`name:<file>` / `path:<file or
    /// directory>`).
    pub client_apps: Vec<String>,
}

/// One of [`VpnOptions::internal_domains`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalDomain {
    /// Lower case, no leading `+.` / `*.`, no dots at the ends.
    pub suffix: String,
    /// DNS server addresses; empty = the VPN interface's own.
    pub servers: Vec<String>,
    /// The interface to ask through; None = the one the servers route by.
    pub iface: Option<String>,
}

/// A domain suffix as the core keeps it; None when nothing is left or it
/// could not be a name.
fn clean_domain(s: &str) -> Option<String> {
    let s = s.trim();
    let s = s
        .strip_prefix("+.")
        .or_else(|| s.strip_prefix("*."))
        .unwrap_or(s)
        .trim_matches('.')
        .to_ascii_lowercase();
    let ok = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    ok.then_some(s)
}

/// `address/prefix` (a bare address = that host); None when it is not one.
fn clean_net(s: &str) -> Option<String> {
    let s = s.trim();
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: IpAddr = addr.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
        None => max,
    };
    Some(format!("{addr}/{prefix}"))
}

/// `name:<file>` / `path:<file or directory>`; None for anything else.
fn clean_client_app(s: &str) -> Option<String> {
    let s = s.trim();
    let (kind, value) = s.split_once(':')?;
    let value = value.trim();
    (matches!(kind, "name" | "path") && !value.is_empty()).then(|| format!("{kind}:{value}"))
}

fn list_of<T: PartialEq>(v: Option<&Value>, read: impl Fn(&Value) -> Option<T>) -> Vec<T> {
    let mut out = Vec::new();
    for item in v.and_then(Value::as_array).into_iter().flatten() {
        if let Some(x) = read(item).filter(|x| !out.contains(x)) {
            out.push(x);
        }
    }
    out
}

impl VpnOptions {
    /// Reads `runtime.vpn`; None unless it is an object.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let text = |read: fn(&str) -> Option<String>| move |x: &Value| x.as_str().and_then(read);
        let internal = |x: &Value| {
            let (suffix, rest) = match x {
                Value::String(s) => (s.as_str(), None),
                Value::Object(m) => (m.get("suffix")?.as_str()?, Some(m)),
                _ => return None,
            };
            Some(InternalDomain {
                suffix: clean_domain(suffix)?,
                servers: list_of(rest.and_then(|m| m.get("servers")), |s| {
                    Some(s.as_str()?.trim().parse::<IpAddr>().ok()?.to_string())
                }),
                iface: rest
                    .and_then(|m| m.get("iface"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|i| !i.is_empty())
                    .map(str::to_owned),
            })
        };
        let mut internal_domains: Vec<InternalDomain> = Vec::new();
        for d in list_of(o.get("internalDomains"), internal) {
            // One entry a suffix: the first wins.
            if !internal_domains.iter().any(|x| x.suffix == d.suffix) {
                internal_domains.push(d);
            }
        }
        Some(Self {
            default_via: str_of(o.get("defaultVia"))
                .filter(|v| matches!(v.as_str(), "physical" | "other-vpn")),
            follow_routes: bool_of(o.get("followRoutes"), true),
            exclude_nets: list_of(o.get("excludeNets"), text(clean_net)),
            internal_domains,
            gateway_domains: list_of(o.get("gatewayDomains"), text(clean_domain)),
            client_apps: list_of(o.get("clientApps"), text(clean_client_app)),
        })
    }
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
            self_app: None,
            vpn: None,
            outbound: None,
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
            self_app: str_of(v.get("selfApp")),
            vpn: v.get("vpn").and_then(VpnOptions::from_json),
            outbound: v.get("outbound").and_then(OutboundOptions::from_json),
        }
    }
}

/// Everything a build reads (Dart `ProxyController.configInput()`).
///
/// Settings come as saved; [`BuildInput::effective`] applies the network
/// and `vpn_only`. `Debug` shows the SSH secrets' keys only (and the
/// runtime without its secrets).
#[derive(Clone, Default, PartialEq)]
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
    /// The local time zone's offset from UTC in minutes (rewrite modules'
    /// cron scripts run on local time); 0 when missing.
    pub utc_offset: i64,
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
            utc_offset: int_of(v.get("utcOffset")).unwrap_or(0),
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

impl fmt::Debug for RouteAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteAccess")
            .field("key", &REDACTED)
            .field("lan", &self.lan)
            .finish()
    }
}

impl fmt::Debug for RuntimeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeOptions")
            .field("controller_port", &self.controller_port)
            .field("secret", &REDACTED)
            .field("cache_file", &self.cache_file)
            .field("speed_test_port", &self.speed_test_port)
            .field("log_level", &self.log_level)
            .field("ipv6", &self.ipv6)
            .field("route", &self.route)
            .field("route_port", &self.route_port)
            .field("mitm_port", &self.mitm_port)
            .field("find_process", &self.find_process)
            .field("self_app", &self.self_app)
            .field("vpn", &self.vpn)
            .finish()
    }
}

impl fmt::Debug for BuildInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secrets: Vec<(&String, &str)> =
            self.ssh_secrets.keys().map(|k| (k, REDACTED)).collect();
        f.debug_struct("BuildInput")
            .field("subscriptions", &self.subscriptions)
            .field("settings", &self.settings)
            .field("network", &self.network)
            .field("ipv6", &self.ipv6)
            .field("vpn_only", &self.vpn_only)
            .field("now", &self.now)
            .field("utc_offset", &self.utc_offset)
            .field("exits", &self.exits)
            .field("resolved", &self.resolved)
            .field("strategy", &self.strategy)
            .field("modules", &self.modules)
            .field("ssh_secrets", &secrets)
            .field("runtime", &self.runtime)
            .finish()
    }
}

/// What `Debug` shows instead of a secret.
const REDACTED: &str = "<redacted>";

impl<'de> Deserialize<'de> for BuildInput {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(d)?))
    }
}

//! Everything the user can change (Dart: `settings.dart`, the data parts of
//! `group_defaults.dart`, `custom_groups.dart`, `hosts.dart`, `ssh.dart`).
//!
//! JSON is the app's persisted settings format. Decoding follows Dart's
//! `fromJson` (lenient: entries it cannot read are dropped, missing fields
//! take the defaults); encoding follows `toJson` key for key, so a decode +
//! encode round trip of what Dart wrote is byte-identical.
//!
//! Only the current format is read. Dart's `fromJson` also migrates older
//! saves (per-entry `on`/`ssid` conditions into named networks, port
//! 17890 → 7890, `members` / `add` lists); the app keeps doing that before
//! handing settings over, so none of it is repeated here.

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::dart::{trim, Dv};
use crate::model::network::{NamedNetwork, WifiProfile};

/// Implements `name()` / `from_name()` for an enum persisted by its Dart
/// enum name.
macro_rules! named_enum {
    ($ty:ident { $($variant:ident => $name:literal),+ $(,)? }) => {
        impl $ty {
            /// The persisted (Dart enum) name.
            pub fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            /// By persisted name; None for anything else.
            pub fn from_name(v: &str) -> Option<Self> {
                match v { $($name => Some(Self::$variant),)+ _ => None }
            }

            fn from_value(v: Option<&Value>) -> Option<Self> {
                v.and_then(Value::as_str).and_then(Self::from_name)
            }
        }
    };
}

/// How traffic is split.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ProxyMode {
    /// China and private addresses direct, the rest through the proxy.
    #[default]
    Smart,
    /// Everything through the proxy (private addresses stay direct).
    Global,
    /// Nothing through the proxy; custom rules still apply.
    Direct,
}
named_enum!(ProxyMode { Smart => "smart", Global => "global", Direct => "direct" });

/// Which proxy core runs the rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum CoreKind {
    /// meow-rs (Clash config): the default.
    #[default]
    Meow,
    /// paopao-core (Go, sing-box).
    Singbox,
}
named_enum!(CoreKind { Meow => "meow", Singbox => "singbox" });

/// What a speed test measures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SpeedTestKind {
    /// Download a test file through each line (default).
    #[default]
    Download,
    /// Round-trip time only.
    Latency,
}
named_enum!(SpeedTestKind { Download => "download", Latency => "latency" });

/// How a group picks among its lines.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum GroupStrategy {
    /// 多点负载 (default): sites spread over the healthy lines.
    #[default]
    Balance,
    /// 测速最优: the lowest latency line.
    Fastest,
    /// 单点: one line the user chose.
    Single,
}
named_enum!(GroupStrategy { Balance => "balance", Fastest => "fastest", Single => "single" });

/// How groups are made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum GroupMode {
    /// PaoPao's layers: regions → 自动选择 → services.
    #[default]
    Layered,
    /// Exactly as the subscriptions wrote them (groups and rules).
    Subscription,
}
named_enum!(GroupMode { Layered => "layered", Subscription => "subscription" });

/// What a custom rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleMatch {
    /// `example.com` matches it and every subdomain.
    Domain,
    /// Exactly this host.
    Exact,
    /// Names containing the text.
    Keyword,
    /// `10.0.0.0/8` or a single address.
    Ip,
    /// Program name (`chrome.exe`, `firefox`); desktop only.
    Process,
}
named_enum!(RuleMatch {
    Domain => "domain",
    Exact => "exact",
    Keyword => "keyword",
    Ip => "ip",
    Process => "process",
});

/// How a hosts entry matches names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostMatch {
    /// Exactly this name.
    Exact,
    /// This name and every subdomain.
    Domain,
    /// Names containing this text.
    Keyword,
    /// A regular expression over the whole name.
    Regex,
    /// A glob over the whole name: `*` any characters, `?` one.
    Wildcard,
}
named_enum!(HostMatch {
    Exact => "exact",
    Domain => "domain",
    Keyword => "keyword",
    Regex => "regex",
    Wildcard => "wildcard",
});

/// Where a custom rule sends traffic. Persisted as `direct`, `proxy`,
/// `block`, `device:<id>`, `line:<tag>`, `iface:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleTarget {
    Direct,
    Proxy,
    Block,
    /// A paired device used as the exit.
    Device(String),
    /// A specific line: an SSH chain (`ssh:<id>`), a group or a node tag.
    Line(String),
    /// Direct, but out of network interface `name` (another VPN's `utun6`).
    Iface(String),
}

impl RuleTarget {
    pub fn encode(&self) -> String {
        match self {
            Self::Direct => "direct".into(),
            Self::Proxy => "proxy".into(),
            Self::Block => "block".into(),
            Self::Device(id) => format!("device:{id}"),
            Self::Line(tag) => format!("line:{tag}"),
            Self::Iface(name) => format!("iface:{name}"),
        }
    }

    /// Anything unrecognised is [`RuleTarget::Proxy`].
    pub fn decode(v: &str) -> Self {
        if v == "direct" {
            Self::Direct
        } else if v == "block" {
            Self::Block
        } else if let Some(id) = v.strip_prefix("device:") {
            Self::Device(id.into())
        } else if let Some(tag) = v.strip_prefix("line:") {
            Self::Line(tag.into())
        } else if let Some(name) = v.strip_prefix("iface:") {
            Self::Iface(name.into())
        } else {
            Self::Proxy
        }
    }
}

/// A user rule: sites matching `value` go to `target`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustomRule {
    pub matches: RuleMatch,
    /// Trimmed, never empty.
    pub value: String,
    pub target: RuleTarget,
    /// Only on this network ([`NamedNetwork::id`]); None = everywhere.
    pub network: Option<String>,
}

impl CustomRule {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("match".into(), self.matches.name().into());
        m.insert("value".into(), self.value.clone().into());
        m.insert("target".into(), self.target.encode().into());
        insert_opt(&mut m, "network", self.network.as_ref());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let matches = RuleMatch::from_value(o.get("match"));
        let value = trim(&str_or_empty(o.get("value"))).to_owned();
        let matches = matches.filter(|_| !value.is_empty())?;
        let target = match o.get("target") {
            Some(t) if !t.is_null() => dart_str(t),
            _ => "proxy".into(),
        };
        Some(Self {
            matches,
            value,
            target: RuleTarget::decode(&target),
            network: string_field(o.get("network")),
        })
    }
}

/// "Send this name to that address" (like /etc/hosts, with more ways to
/// match). In a list the first entry matching a name decides it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostEntry {
    pub matches: HostMatch,
    /// Trimmed, never empty.
    pub pattern: String,
    /// An IPv4 or IPv6 address; None = let the name through unchanged.
    pub address: Option<String>,
    /// Only on this network ([`NamedNetwork::id`]); None = everywhere.
    pub network: Option<String>,
}

impl HostEntry {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("match".into(), self.matches.name().into());
        m.insert("pattern".into(), self.pattern.clone().into());
        insert_opt(&mut m, "address", self.address.as_ref());
        insert_opt(&mut m, "network", self.network.as_ref());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let matches = HostMatch::from_value(o.get("match"));
        let pattern = trim(&str_or_empty(o.get("pattern"))).to_owned();
        let address = trim(&str_or_empty(o.get("address"))).to_owned();
        let matches = matches.filter(|_| !pattern.is_empty())?;
        Some(Self {
            matches,
            pattern,
            address: (!address.is_empty() && address != "null").then_some(address),
            network: string_field(o.get("network")),
        })
    }
}

/// A paired device offered as an exit ("从家里出去"). JSON: `{id, name}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceExit {
    pub device_id: String,
    pub name: String,
}

impl DeviceExit {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.device_id.clone().into());
        m.insert("name".into(), self.name.clone().into());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            device_id: o.get("id")?.as_str()?.to_owned(),
            name: str_or_empty(o.get("name")),
        })
    }
}

/// What a [`GroupDefault`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupDefaultKind {
    /// One region's lines (固定出口 over them for a sticky policy).
    Region,
    /// 速度最快.
    Fastest,
    /// 自动选择.
    Auto,
    /// 负载均衡.
    Balance,
    /// 🚀 节点选择.
    Select,
    /// 直连.
    Direct,
    /// 拦截.
    Block,
}

/// A built-in group's default pick, set in 设置 → 分组默认. Persisted as
/// `region:US`, `fastest`, `auto`, `balance`, `select`, `direct`, `block`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupDefault {
    pub kind: GroupDefaultKind,
    /// For [`GroupDefaultKind::Region`]: the ISO code (two capitals).
    pub region: Option<String>,
}

impl GroupDefault {
    pub fn encode(&self) -> String {
        if let Some(r) = &self.region {
            return format!("region:{r}");
        }
        match self.kind {
            GroupDefaultKind::Region => "region",
            GroupDefaultKind::Fastest => "fastest",
            GroupDefaultKind::Auto => "auto",
            GroupDefaultKind::Balance => "balance",
            GroupDefaultKind::Select => "select",
            GroupDefaultKind::Direct => "direct",
            GroupDefaultKind::Block => "block",
        }
        .into()
    }

    pub fn decode(v: &str) -> Option<Self> {
        if let Some(code) = v.strip_prefix("region:") {
            let two_capitals = code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase());
            return two_capitals.then(|| Self {
                kind: GroupDefaultKind::Region,
                region: Some(code.into()),
            });
        }
        let kind = match v {
            "fastest" => GroupDefaultKind::Fastest,
            "auto" => GroupDefaultKind::Auto,
            "balance" => GroupDefaultKind::Balance,
            "select" => GroupDefaultKind::Select,
            "direct" => GroupDefaultKind::Direct,
            "block" => GroupDefaultKind::Block,
            _ => return None,
        };
        Some(Self { kind, region: None })
    }

    /// Whether policy group `tag` may have it at all: 广告拦截 only 拦截 /
    /// 直连; never a region the service refuses. False for unknown groups.
    pub fn allowed_for(&self, tag: &str) -> bool {
        let Some(&(_, blockable, avoid)) = POLICY_LIMITS.iter().find(|(t, ..)| *t == tag) else {
            return false;
        };
        if blockable {
            return matches!(
                self.kind,
                GroupDefaultKind::Direct | GroupDefaultKind::Block
            );
        }
        self.region.as_deref().is_none_or(|r| !avoid.contains(&r))
    }
}

/// The built-in policy groups' tags with what limits their defaults
/// (`blockable`, `avoidRegions` in Dart's `policies.dart`).
// TODO(L3): read these from the policy catalog once it is ported.
const POLICY_LIMITS: [(&str, bool, &[&str]); 16] = [
    ("policy:ads", true, &[]),
    ("policy:youtube", false, &[]),
    ("policy:google", false, &["HK", "MO", "CN", "RU"]),
    ("policy:ai", false, &["HK", "MO", "CN", "RU"]),
    ("policy:telegram", false, &[]),
    ("policy:social", false, &[]),
    ("policy:netflix", false, &[]),
    ("policy:games", false, &[]),
    ("policy:cnmedia", false, &[]),
    ("policy:media", false, &[]),
    ("policy:dev", false, &[]),
    ("policy:microsoft", false, &[]),
    ("policy:apple", false, &[]),
    ("policy:foreign", false, &[]),
    ("policy:china", false, &[]),
    ("policy:final", false, &[]),
];

/// Tags of user groups start with this (`group:<id>`).
pub const CUSTOM_GROUP_PREFIX: &str = "group:";

/// Outlets a business policy may take beyond its generated members: this
/// machine's interfaces (`iface:<name>`) and SSH chains (`ssh:<id>`).
pub fn is_extra_outlet(tag: &str) -> bool {
    tag.starts_with("iface:") || tag.starts_with("ssh:")
}

/// A business policy the user made (like 🤖 AI 服务): members generated as
/// the built-in ones' plus [`CustomGroup::extras`]; its sites are the user's
/// rules pointing at [`CustomGroup::tag`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CustomGroup {
    /// Stable and short (never the name: names break Clash rule strings).
    pub id: String,
    /// What the user calls it (trimmed, never empty).
    pub name: String,
    /// Extra outlets ([`is_extra_outlet`]).
    pub extras: Vec<String>,
    /// What it uses by default (one of its members); None = 节点选择.
    pub pick: Option<String>,
}

impl CustomGroup {
    /// `group:<id>`.
    pub fn tag(&self) -> String {
        format!("{CUSTOM_GROUP_PREFIX}{}", self.id)
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.id.clone().into());
        m.insert("name".into(), self.name.clone().into());
        if !self.extras.is_empty() {
            m.insert("extras".into(), self.extras.clone().into());
        }
        insert_opt(&mut m, "pick", self.pick.as_ref());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let id = str_or_empty(o.get("id"));
        let name = trim(&str_or_empty(o.get("name"))).to_owned();
        if id.is_empty() || name.is_empty() {
            return None;
        }
        Some(Self {
            id,
            name,
            extras: outlets(o.get("extras")),
            pick: string_field(o.get("pick")),
        })
    }
}

/// Changes to a built-in business policy: outlets added and sites left out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct GroupEdit {
    /// Extra outlets ([`is_extra_outlet`]).
    pub extras: Vec<String>,
    /// Sites its rules no longer take: a domain or address as is, else
    /// `exact:` / `keyword:` / `ip:` / `process:` prefixed. Lower-cased
    /// except program names.
    pub exclude: Vec<String>,
}

impl GroupEdit {
    pub fn is_empty(&self) -> bool {
        self.extras.is_empty() && self.exclude.is_empty()
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if !self.extras.is_empty() {
            m.insert("extras".into(), self.extras.clone().into());
        }
        if !self.exclude.is_empty() {
            m.insert("exclude".into(), self.exclude.clone().into());
        }
        Value::Object(m)
    }

    /// Never fails: anything but an object is an empty edit.
    pub fn from_json(v: &Value) -> Self {
        let Some(o) = v.as_object() else {
            return Self::default();
        };
        let exclude = list(o.get("exclude"))
            .iter()
            .filter_map(|x| {
                let s = dart_str(x);
                let t = trim(&s);
                if t.is_empty() {
                    None
                } else if s.starts_with("process:") {
                    Some(t.to_owned())
                } else {
                    Some(t.to_lowercase())
                }
            })
            .collect();
        Self {
            extras: outlets(o.get("extras")),
            exclude,
        }
    }
}

/// One SSH server in a chain. Its credential is not part of it: the app
/// keeps it under [`SshChain::secret_key`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshHop {
    pub host: String,
    /// Default 22.
    pub port: i64,
    /// Default `root`.
    pub user: String,
    /// `ssh-ed25519 AAAA...` as in known_hosts; None trusts on first use.
    pub host_key: Option<String>,
    /// Private key (true, default) or password (false).
    pub use_key: bool,
}

impl SshHop {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("host".into(), self.host.clone().into());
        m.insert("port".into(), self.port.into());
        m.insert("user".into(), self.user.clone().into());
        insert_opt(&mut m, "host_key", self.host_key.as_ref());
        m.insert("key".into(), self.use_key.into());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            host: o.get("host")?.as_str()?.to_owned(),
            port: int_field(o.get("port")).unwrap_or(22),
            user: match o.get("user") {
                Some(u) if !u.is_null() => dart_str(u),
                _ => "root".into(),
            },
            host_key: string_field(o.get("host_key")),
            use_key: o.get("key") != Some(&Value::Bool(false)),
        })
    }
}

/// "Through A, then B, then out of C": SSH servers reached one inside the
/// other; traffic leaves from the last.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshChain {
    pub id: String,
    /// What the line list shows ("公司跳板 → 内网").
    pub name: String,
    /// Never empty.
    pub hops: Vec<SshHop>,
}

impl SshChain {
    /// The selectable line (and rule target): `ssh:<id>`.
    pub fn tag(&self) -> String {
        format!("ssh:{}", self.id)
    }

    /// Where hop `hop`'s credential is kept: `ssh/<chain>/<hop>`.
    pub fn secret_key(chain_id: &str, hop: usize) -> String {
        format!("ssh/{chain_id}/{hop}")
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.id.clone().into());
        m.insert("name".into(), self.name.clone().into());
        m.insert(
            "hops".into(),
            Value::Array(self.hops.iter().map(SshHop::to_json).collect()),
        );
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let id = o.get("id")?.as_str()?.to_owned();
        let hops: Vec<SshHop> = list(o.get("hops"))
            .iter()
            .filter_map(SshHop::from_json)
            .collect();
        if hops.is_empty() {
            return None;
        }
        let name = match o.get("name") {
            Some(n) if !n.is_null() => dart_str(n),
            _ => id.clone(),
        };
        Some(Self { id, name, hops })
    }
}

/// The selector value for "pick the fastest automatically".
pub const AUTO_SELECT: &str = "auto";

/// The local proxy port programs are pointed at by default.
pub const DEFAULT_MIXED_PORT: i64 = 7890;

/// Everything the user can change. [`Default`] is what a newcomer gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySettings {
    pub mode: ProxyMode,
    /// Node name, group tag, `device:<id>`, or [`AUTO_SELECT`].
    pub selected: String,
    /// Local HTTP + SOCKS port.
    pub mixed_port: i64,
    /// Capture all traffic with a virtual adapter.
    pub tun: bool,
    /// Point the OS proxy settings at `mixed_port` while running.
    pub system_proxy: bool,
    pub rules: Vec<CustomRule>,
    /// Mirror for the rule sets; None = built-in default.
    pub rule_set_base: Option<String>,
    /// SSH jump chains offered as lines.
    pub ssh_chains: Vec<SshChain>,
    /// Networks named once (家里, 公司); entries refer to them by id.
    pub networks: Vec<NamedNetwork>,
    pub hosts: Vec<HostEntry>,
    /// A different mode on certain networks; the first match wins.
    pub wifi_profiles: Vec<WifiProfile>,
    /// Group tag → how it picks (missing = balance).
    pub group_strategies: IndexMap<String, GroupStrategy>,
    /// Group tag → the line chosen for 单点.
    pub group_picks: IndexMap<String, String>,
    pub speed_test: SpeedTestKind,
    /// Policy group tag (`policy:ads` …) → what the user pointed it at.
    pub policies: IndexMap<String, String>,
    pub core: CoreKind,
    /// Other devices on the LAN may route through this proxy.
    pub share_lan: bool,
    /// PaoPao's own service groups first in the rules.
    pub built_in_groups: bool,
    pub group_mode: GroupMode,
    /// Built-in group tag → its default pick (分组默认).
    pub group_defaults: IndexMap<String, GroupDefault>,
    /// The user's own policy groups, in the order shown.
    pub custom_groups: Vec<CustomGroup>,
    /// Built-in group tag → members added or sites left out.
    pub group_edits: IndexMap<String, GroupEdit>,
    /// Line tags switched off for every automatic choice.
    pub disabled_lines: Vec<String>,
    /// The interface direct traffic leaves by while TUN is on; None = auto.
    pub outbound_interface: Option<String>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Smart,
            selected: AUTO_SELECT.into(),
            mixed_port: DEFAULT_MIXED_PORT,
            tun: false,
            system_proxy: true,
            rules: Vec::new(),
            rule_set_base: None,
            ssh_chains: Vec::new(),
            networks: Vec::new(),
            hosts: Vec::new(),
            wifi_profiles: Vec::new(),
            group_strategies: IndexMap::new(),
            group_picks: IndexMap::new(),
            speed_test: SpeedTestKind::Download,
            policies: IndexMap::new(),
            core: CoreKind::Meow,
            share_lan: false,
            built_in_groups: true,
            group_mode: GroupMode::Layered,
            group_defaults: IndexMap::new(),
            custom_groups: Vec::new(),
            group_edits: IndexMap::new(),
            disabled_lines: Vec::new(),
            outbound_interface: None,
        }
    }
}

impl ProxySettings {
    /// Dart `toJson`: defaults and empty collections are left out except the
    /// first five fields and `rules`.
    pub fn to_json(&self) -> Value {
        fn array<T>(items: &[T], f: fn(&T) -> Value) -> Value {
            Value::Array(items.iter().map(f).collect())
        }
        let mut m = Map::new();
        m.insert("mode".into(), self.mode.name().into());
        m.insert("selected".into(), self.selected.clone().into());
        m.insert("mixed_port".into(), self.mixed_port.into());
        m.insert("tun".into(), self.tun.into());
        m.insert("system_proxy".into(), self.system_proxy.into());
        m.insert("rules".into(), array(&self.rules, CustomRule::to_json));
        insert_opt(&mut m, "rule_set_base", self.rule_set_base.as_ref());
        if !self.ssh_chains.is_empty() {
            m.insert("ssh".into(), array(&self.ssh_chains, SshChain::to_json));
        }
        if !self.networks.is_empty() {
            m.insert(
                "networks".into(),
                array(&self.networks, NamedNetwork::to_json),
            );
        }
        if !self.hosts.is_empty() {
            m.insert("hosts".into(), array(&self.hosts, HostEntry::to_json));
        }
        if !self.wifi_profiles.is_empty() {
            m.insert(
                "wifi".into(),
                array(&self.wifi_profiles, WifiProfile::to_json),
            );
        }
        if !self.group_strategies.is_empty() {
            let o = self
                .group_strategies
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.name())))
                .collect();
            m.insert("group_strategy".into(), Value::Object(o));
        }
        if !self.group_picks.is_empty() {
            m.insert("group_pick".into(), string_map(&self.group_picks));
        }
        if self.speed_test != SpeedTestKind::Download {
            m.insert("speed_test".into(), self.speed_test.name().into());
        }
        if !self.policies.is_empty() {
            m.insert("policies".into(), string_map(&self.policies));
        }
        if self.core != CoreKind::Meow {
            m.insert("core".into(), self.core.name().into());
        }
        if self.share_lan {
            m.insert("share_lan".into(), true.into());
        }
        if !self.built_in_groups {
            m.insert("built_in_groups".into(), false.into());
        }
        if self.group_mode != GroupMode::Layered {
            m.insert("group_mode".into(), self.group_mode.name().into());
        }
        if !self.group_defaults.is_empty() {
            let o = self
                .group_defaults
                .iter()
                .map(|(k, v)| (k.clone(), Value::from(v.encode())))
                .collect();
            m.insert("group_defaults".into(), Value::Object(o));
        }
        if !self.custom_groups.is_empty() {
            m.insert(
                "custom_groups".into(),
                array(&self.custom_groups, CustomGroup::to_json),
            );
        }
        if !self.group_edits.is_empty() {
            // As in Dart: empty edits are left out, but the key stays even
            // when that leaves it empty.
            let o = self
                .group_edits
                .iter()
                .filter(|(_, e)| !e.is_empty())
                .map(|(k, e)| (k.clone(), e.to_json()))
                .collect();
            m.insert("group_edits".into(), Value::Object(o));
        }
        if !self.disabled_lines.is_empty() {
            m.insert("disabled_lines".into(), self.disabled_lines.clone().into());
        }
        insert_opt(
            &mut m,
            "outbound_interface",
            self.outbound_interface.as_ref(),
        );
        Value::Object(m)
    }

    /// Dart `fromJson` for the current format (see the module docs).
    pub fn from_json(v: &Value) -> Self {
        let Some(o) = v.as_object() else {
            return Self::default();
        };
        let entries = |k: &str| list(o.get(k));
        Self {
            mode: ProxyMode::from_value(o.get("mode")).unwrap_or_default(),
            selected: match o.get("selected") {
                Some(s) if !s.is_null() => dart_str(s),
                _ => AUTO_SELECT.into(),
            },
            mixed_port: int_field(o.get("mixed_port")).unwrap_or(DEFAULT_MIXED_PORT),
            tun: o.get("tun") == Some(&Value::Bool(true)),
            system_proxy: o.get("system_proxy") != Some(&Value::Bool(false)),
            rules: entries("rules")
                .iter()
                .filter_map(CustomRule::from_json)
                .collect(),
            rule_set_base: string_field(o.get("rule_set_base")),
            ssh_chains: entries("ssh")
                .iter()
                .filter_map(SshChain::from_json)
                .collect(),
            networks: entries("networks")
                .iter()
                .filter_map(NamedNetwork::from_json)
                .collect(),
            hosts: entries("hosts")
                .iter()
                .filter_map(HostEntry::from_json)
                .collect(),
            wifi_profiles: entries("wifi")
                .iter()
                .filter_map(WifiProfile::from_json)
                .collect(),
            group_strategies: object(o.get("group_strategy"))
                .filter_map(|(k, v)| GroupStrategy::from_value(Some(v)).map(|s| (k.clone(), s)))
                .collect(),
            group_picks: object(o.get("group_pick"))
                .map(|(k, v)| (k.clone(), dart_str(v)))
                .collect(),
            speed_test: SpeedTestKind::from_value(o.get("speed_test")).unwrap_or_default(),
            policies: object(o.get("policies"))
                .map(|(k, v)| (k.clone(), dart_str(v)))
                .collect(),
            core: CoreKind::from_value(o.get("core")).unwrap_or_default(),
            share_lan: o.get("share_lan") == Some(&Value::Bool(true)),
            built_in_groups: o.get("built_in_groups") != Some(&Value::Bool(false)),
            group_mode: GroupMode::from_value(o.get("group_mode")).unwrap_or_default(),
            group_defaults: object(o.get("group_defaults"))
                .filter_map(|(k, v)| {
                    let d = GroupDefault::decode(v.as_str()?)?;
                    d.allowed_for(k).then(|| (k.clone(), d))
                })
                .collect(),
            custom_groups: entries("custom_groups")
                .iter()
                .filter_map(CustomGroup::from_json)
                .collect(),
            group_edits: object(o.get("group_edits"))
                .map(|(k, v)| (k.clone(), GroupEdit::from_json(v)))
                .collect(),
            disabled_lines: entries("disabled_lines").iter().map(dart_str).collect(),
            outbound_interface: string_field(o.get("outbound_interface")),
        }
    }
}

impl Serialize for ProxySettings {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> Deserialize<'de> for ProxySettings {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(d)?))
    }
}

// ------------------------------------------------------------ JSON helpers

/// `'$v'`.
pub(crate) fn dart_str(v: &Value) -> String {
    Dv::from_json(v).dart_string()
}

/// `'${v ?? ''}'`.
pub(crate) fn str_or_empty(v: Option<&Value>) -> String {
    v.map(|x| Dv::from_json(x).dart_string_or_empty())
        .unwrap_or_default()
}

/// `v is String ? v : null`, also standing in for `v as String?` (whose
/// failed cast Dart would throw on).
pub(crate) fn string_field(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str).map(str::to_owned)
}

/// `(v as num?)?.toInt()`; anything but a finite number is None.
pub(crate) fn int_field(v: Option<&Value>) -> Option<i64> {
    v.and_then(|x| Dv::from_json(x).as_int_opt().ok().flatten())
}

/// `(v as List?) ?? const []`.
pub(crate) fn list(v: Option<&Value>) -> &[Value] {
    v.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// `((v as Map?) ?? const {}).entries`.
fn object(v: Option<&Value>) -> impl Iterator<Item = (&String, &Value)> {
    v.and_then(Value::as_object).into_iter().flatten()
}

/// Items of a list that are extra outlets, as strings.
fn outlets(v: Option<&Value>) -> Vec<String> {
    list(v)
        .iter()
        .map(dart_str)
        .filter(|x| is_extra_outlet(x))
        .collect()
}

fn insert_opt(m: &mut Map<String, Value>, key: &str, v: Option<&String>) {
    if let Some(v) = v {
        m.insert(key.into(), v.clone().into());
    }
}

fn string_map(m: &IndexMap<String, String>) -> Value {
    Value::Object(
        m.iter()
            .map(|(k, v)| (k.clone(), Value::from(v.clone())))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn group_defaults_drop_what_a_group_cannot_take() {
        let s = ProxySettings::from_json(&json!({
            "group_defaults": {
                "policy:ai": "region:US",
                "policy:google": "region:HK",
                "policy:ads": "region:US",
                "policy:youtube": "region:us",
                "policy:nope": "auto",
                "policy:media": "fastest",
            }
        }));
        let got: Vec<_> = s
            .group_defaults
            .iter()
            .map(|(k, v)| format!("{k}={}", v.encode()))
            .collect();
        assert_eq!(got, ["policy:ai=region:US", "policy:media=fastest"]);
    }

    #[test]
    fn rule_targets_round_trip() {
        for t in [
            "direct",
            "proxy",
            "block",
            "device:d1",
            "line:ssh:x",
            "iface:utun6",
        ] {
            assert_eq!(RuleTarget::decode(t).encode(), t);
        }
        assert_eq!(RuleTarget::decode("whatever"), RuleTarget::Proxy);
    }

    #[test]
    fn empty_group_edits_keep_the_key() {
        let s = ProxySettings::from_json(&json!({"group_edits": {"policy:ai": {}}}));
        assert_eq!(s.to_json()["group_edits"], json!({}));
    }
}

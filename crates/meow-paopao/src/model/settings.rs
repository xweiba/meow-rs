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
use crate::model::policies::policy_by_tag;

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
    /// An app the user picked from a list; the value is an [`AppMatcher`]
    /// string (`path:/Applications/X.app`, `name:chrome.exe`,
    /// `pkg:com.tencent.mm`). One with a prefix this version does not know
    /// is kept but makes no rule.
    App,
}
named_enum!(RuleMatch {
    Domain => "domain",
    Exact => "exact",
    Keyword => "keyword",
    Ip => "ip",
    Process => "process",
    App => "app",
});

/// Which processes an app is, as stored in a [`RuleMatch::App`] value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AppMatcher {
    /// `path:<dir>`: every program under this directory (a macOS `.app`
    /// bundle, its helper processes included).
    Path(String),
    /// `name:<file>`: the program's file name (`chrome.exe` on Windows,
    /// `firefox` on Linux).
    Name(String),
    /// `pkg:<package>`: an Android app (the core reports the package as
    /// the process name).
    Package(String),
}

impl AppMatcher {
    /// None for an unknown prefix, an empty value, or a value a rule line
    /// cannot carry (`,` splits rule lines).
    pub fn parse(v: &str) -> Option<Self> {
        let (kind, value) = v.split_once(':')?;
        let value = trim(value);
        if value.is_empty() || value.contains([',', '\n', '\r']) {
            return None;
        }
        let value = value.to_owned();
        match kind {
            // `/Applications/X.app/` would not take `/Applications/X.app/…`:
            // the core matches the prefix on whole path parts.
            "path" => {
                let dir = value.trim_end_matches(['/', '\\']);
                (!dir.is_empty()).then(|| Self::Path(dir.to_owned()))
            }
            "name" => Some(Self::Name(value)),
            "pkg" => Some(Self::Package(value)),
            _ => None,
        }
    }

    /// The core's condition without a target: `PROCESS-PATH,<dir>` (a
    /// prefix match on whole path parts) or `PROCESS-NAME,<name>`.
    pub fn condition(&self) -> String {
        match self {
            Self::Path(dir) => format!("PROCESS-PATH,{dir}"),
            Self::Name(n) | Self::Package(n) => format!("PROCESS-NAME,{n}"),
        }
    }
}

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
    /// What the user saw when picking it (an app's name); None = show
    /// the value. Display only.
    pub label: Option<String>,
}

impl CustomRule {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("match".into(), self.matches.name().into());
        m.insert("value".into(), self.value.clone().into());
        m.insert("target".into(), self.target.encode().into());
        insert_opt(&mut m, "network", self.network.as_ref());
        insert_opt(&mut m, "label", self.label.as_ref());
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
            label: string_field(o.get("label")),
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
}

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
    /// `exact:` / `keyword:` / `ip:` / `process:` / `app:` prefixed.
    /// Lower-cased except programs and apps.
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
                } else if s.starts_with("process:") || s.starts_with("app:") {
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

/// How one policy uses a shared group it can point at (a region, a kind,
/// ♻️ 自动选择, a subscription's group): one of the group's automatic
/// children or one of its lines, for that policy only. The group's own
/// pick stays the default for everyone else. Persisted as `{"use":
/// "smart" | "balance" | "fastest"}` or `{"use": "line", "line": <tag>}`;
/// following the group's default is no entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GroupUse {
    /// 智能选择.
    Smart,
    /// 负载均衡.
    Balance,
    /// 速度最快.
    Fastest,
    /// One line of the group.
    Line(String),
}

impl GroupUse {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        let name = match self {
            Self::Smart => "smart",
            Self::Balance => "balance",
            Self::Fastest => "fastest",
            Self::Line(_) => "line",
        };
        m.insert("use".into(), name.into());
        if let Self::Line(l) = self {
            m.insert("line".into(), l.clone().into());
        }
        Value::Object(m)
    }

    /// None for anything else (a line without its name, `default` …).
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(match o.get("use")?.as_str()? {
            "smart" => Self::Smart,
            "balance" => Self::Balance,
            "fastest" => Self::Fastest,
            "line" => Self::Line(string_field(o.get("line")).filter(|l| !l.is_empty())?),
            _ => return None,
        })
    }
}

/// A policy's own way of using the groups it points at
/// ([`ProxySettings::policy_use`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyUse {
    /// 固定出口: every site of the policy on one line, chosen by the
    /// automatic mode it uses; None = its built-in
    /// ([`ProxySettings::sticky_of`]).
    pub sticky: Option<bool>,
    /// Shared group tag → how this policy uses it.
    pub groups: IndexMap<String, GroupUse>,
}

impl PolicyUse {
    pub fn is_empty(&self) -> bool {
        self.sticky.is_none() && self.groups.is_empty()
    }

    /// `{"sticky"?, "groups"?}`, each only when set.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if let Some(on) = self.sticky {
            m.insert("sticky".into(), on.into());
        }
        if !self.groups.is_empty() {
            let g = self
                .groups
                .iter()
                .map(|(k, u)| (k.clone(), u.to_json()))
                .collect();
            m.insert("groups".into(), Value::Object(g));
        }
        Value::Object(m)
    }

    /// Never fails: what it cannot read is left out.
    pub fn from_json(v: &Value) -> Self {
        let Some(o) = v.as_object() else {
            return Self::default();
        };
        Self {
            sticky: o.get("sticky").and_then(Value::as_bool),
            groups: object(o.get("groups"))
                .filter_map(|(k, u)| GroupUse::from_json(u).map(|u| (k.clone(), u)))
                .collect(),
        }
    }
}

/// Whether built-in policy `tag` keeps its 固定出口 with no switch saved:
/// one made for it ([`Policy::sticky_exit`], AI) that still uses what it
/// used when 固定出口 was a member of its own — its built-in default or a
/// region default, and no pick of the user's but that member
/// (`<tag>~sticky`). Anything else ran without it and keeps running so.
///
/// [`Policy::sticky_exit`]: crate::model::policies::Policy::sticky_exit
pub fn built_in_sticky(tag: &str, manual: Option<&str>, default: Option<&GroupDefault>) -> bool {
    let old_member = format!("{tag}~sticky");
    policy_by_tag(tag).is_some_and(|p| p.sticky_exit)
        && manual.is_none_or(|m| m == old_member)
        && default.is_none_or(|d| d.kind == GroupDefaultKind::Region)
}

/// A policy's own copy of a shared group is tagged
/// `<policy>@<group><suffix>`: `~auto` / `~balance` / `~fastest` for a
/// mode, `~sticky` for 固定出口, nothing for one line (a selector).
pub const COPY_MARK: char = '@';

/// The suffixes a policy's copy may end in.
const COPY_SUFFIXES: [&str; 4] = ["~sticky", "~auto", "~balance", "~fastest"];

/// The member `tag` stands for in policy `policy` when it is that
/// policy's copy of it (`policy:ai@region:US~fastest` → `region:US`,
/// `policy:ai@auto~fastest~sticky` → `auto~fastest`); None otherwise.
pub fn copy_origin<'a>(policy: &str, tag: &'a str) -> Option<&'a str> {
    let rest = tag.strip_prefix(policy)?.strip_prefix(COPY_MARK)?;
    let origin = COPY_SUFFIXES
        .iter()
        .find_map(|s| rest.strip_suffix(s))
        .unwrap_or(rest);
    (!origin.is_empty()).then_some(origin)
}

/// Whether `tag` may have [`PolicyUse`]: a built-in policy or the user's.
pub fn is_policy_tag(tag: &str) -> bool {
    tag.starts_with(CUSTOM_GROUP_PREFIX) || policy_by_tag(tag).is_some()
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
    /// Policy tag (`policy:ai`, `group:<id>`) → how it uses the shared
    /// groups it points at, and its 固定出口.
    pub policy_use: IndexMap<String, PolicyUse>,
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
            policy_use: IndexMap::new(),
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
        // Empty edits are left out, and the key with them when none is
        // left (B14: Dart wrote `{}`).
        let edits: Map<String, Value> = self
            .group_edits
            .iter()
            .filter(|(_, e)| !e.is_empty())
            .map(|(k, e)| (k.clone(), e.to_json()))
            .collect();
        if !edits.is_empty() {
            m.insert("group_edits".into(), Value::Object(edits));
        }
        if !self.disabled_lines.is_empty() {
            m.insert("disabled_lines".into(), self.disabled_lines.clone().into());
        }
        insert_opt(
            &mut m,
            "outbound_interface",
            self.outbound_interface.as_ref(),
        );
        let uses: Map<String, Value> = self
            .policy_use
            .iter()
            .filter(|(_, u)| !u.is_empty())
            .map(|(k, u)| (k.clone(), u.to_json()))
            .collect();
        if !uses.is_empty() {
            m.insert("policy_use".into(), Value::Object(uses));
        }
        Value::Object(m)
    }

    /// Whether policy `tag` runs with 固定出口 (where it uses an automatic
    /// mode): its switch, else [`built_in_sticky`].
    pub fn sticky_of(&self, tag: &str) -> bool {
        if let Some(on) = self.policy_use.get(tag).and_then(|u| u.sticky) {
            return on;
        }
        built_in_sticky(
            tag,
            self.policies.get(tag).map(String::as_str),
            self.group_defaults.get(tag),
        )
    }

    /// How policy `tag` uses shared group `group`; None = the group's
    /// default.
    pub fn group_use(&self, tag: &str, group: &str) -> Option<&GroupUse> {
        self.policy_use.get(tag)?.groups.get(group)
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
                    // Unknown groups and defaults a group cannot take are
                    // left out (Dart: `decodeGroupDefaults`).
                    let p = policy_by_tag(k)?;
                    let d = GroupDefault::decode(v.as_str()?)?;
                    d.allowed_for(p).then(|| (k.clone(), d))
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
            policy_use: object(o.get("policy_use"))
                .map(|(k, v)| (k.clone(), PolicyUse::from_json(v)))
                .filter(|(_, u)| !u.is_empty())
                .collect(),
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

/// A pick made in the running core (`PUT /proxies/{group}`: PaoPao Menu,
/// paopao-tray) put into the settings (the app's JSON, `settings` of the
/// build input) the way the app's `pickGroup` puts it, so a config built
/// from them later keeps it: 🚀 节点选择's in `selected`, a built-in
/// policy's in `policies` (`DIRECT` / `REJECT` as `direct` / `block`), any
/// other group's in `group_pick` (its old region strategy dropped). A
/// policy's copy of a shared group is recorded as the group it stands for;
/// a pick inside a policy's one-line copy (`<policy>@<group>`) is how that
/// policy uses the group (`policy_use`). A pick that would change whether a
/// policy runs with 固定出口 by default ([`built_in_sticky`]) saves the
/// switch as it was. The speed test's selector, Clash's `GLOBAL` and the
/// groups' own children are no settings. True when the settings changed.
pub fn record_pick(settings: &mut Map<String, Value>, group: &str, member: &str) -> bool {
    use crate::model::outbound_tags as tags;
    if group == tags::SPEED_TEST || group == "GLOBAL" || group.contains('~') {
        return false;
    }
    if let Some((policy, shared)) = group.split_once(COPY_MARK) {
        if is_policy_tag(policy) && !shared.is_empty() {
            return record_use(settings, policy, shared, member);
        }
    }
    let member = copy_origin(group, member).unwrap_or(member);
    let keyed = |settings: &mut Map<String, Value>, key: &str, value: &str| {
        let map = object_entry(settings, key);
        if map.get(group).and_then(Value::as_str) == Some(value) {
            return false;
        }
        map.insert(group.to_owned(), value.into());
        true
    };
    if group == tags::PROXY {
        // ♻️ 自动选择 is AUTO_SELECT, the same name.
        if settings.get("selected").and_then(Value::as_str) == Some(member) {
            return false;
        }
        settings.insert("selected".into(), member.into());
        return true;
    }
    if policy_by_tag(group).is_some() {
        let target = match member {
            "DIRECT" => tags::DIRECT,
            "REJECT" => tags::BLOCK,
            m => m,
        };
        let sticky = raw_built_in_sticky(settings, group);
        if !keyed(settings, "policies", target) {
            return false;
        }
        if sticky != raw_built_in_sticky(settings, group) {
            keep_sticky(settings, group, sticky);
        }
        return true;
    }
    let mut changed = keyed(settings, "group_pick", member);
    if let Some(Value::Object(strategies)) = settings.get_mut("group_strategy") {
        changed |= strategies.shift_remove(group).is_some();
        if strategies.is_empty() {
            settings.remove("group_strategy");
        }
    }
    changed
}

/// `settings[key]` as an object (made one when it is not).
fn object_entry<'a>(settings: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    let v = settings
        .entry(key)
        .or_insert_with(|| Value::Object(Map::new()));
    if !v.is_object() {
        *v = Value::Object(Map::new());
    }
    v.as_object_mut().expect("an object")
}

/// [`built_in_sticky`] over the raw settings, unless the switch is saved
/// (then that).
fn raw_built_in_sticky(settings: &Map<String, Value>, policy: &str) -> bool {
    let saved = settings
        .get("policy_use")
        .and_then(|u| u.get(policy))
        .and_then(|u| u.get("sticky"))
        .and_then(Value::as_bool);
    if let Some(on) = saved {
        return on;
    }
    let manual = settings
        .get("policies")
        .and_then(|p| p.get(policy))
        .and_then(Value::as_str);
    let default = settings
        .get("group_defaults")
        .and_then(|d| d.get(policy))
        .and_then(Value::as_str)
        .and_then(GroupDefault::decode);
    built_in_sticky(policy, manual, default.as_ref())
}

/// Saves policy `policy`'s 固定出口 switch as `on`.
fn keep_sticky(settings: &mut Map<String, Value>, policy: &str, on: bool) {
    let uses = object_entry(settings, "policy_use");
    let entry = object_entry(uses, policy);
    entry.insert("sticky".into(), on.into());
}

/// Member `member` picked in `policy`'s one-line copy of `shared`: one of
/// the group's automatic children is that mode, anything else a line.
fn record_use(settings: &mut Map<String, Value>, policy: &str, shared: &str, member: &str) -> bool {
    let mode = member.strip_prefix(shared).and_then(|suffix| match suffix {
        "~auto" | "~smart" => Some(GroupUse::Smart),
        "~balance" => Some(GroupUse::Balance),
        "~fastest" => Some(GroupUse::Fastest),
        _ => None,
    });
    let want = mode
        .unwrap_or_else(|| GroupUse::Line(member.to_owned()))
        .to_json();
    let uses = object_entry(settings, "policy_use");
    let groups = object_entry(object_entry(uses, policy), "groups");
    if groups.get(shared) == Some(&want) {
        return false;
    }
    groups.insert(shared.to_owned(), want);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn app_rules_keep_their_label_and_old_rules_stay_as_they_were() {
        let rules = json!([
            {"match": "domain", "value": "a.com", "target": "direct"},
            {"match": "app", "value": "path:/Applications/X.app", "target": "proxy",
             "label": "X"},
            {"match": "app", "value": "bundle:new", "target": "block", "network": "n1",
             "label": "Later"},
        ]);
        let s = ProxySettings::from_json(&json!({ "rules": rules }));
        assert_eq!(s.rules.len(), 3);
        assert_eq!(s.rules[0].label, None);
        assert_eq!(s.rules[1].matches, RuleMatch::App);
        assert_eq!(s.rules[1].label.as_deref(), Some("X"));
        // Round trip: no `label` key where there was none, unknown apps kept.
        assert_eq!(s.to_json()["rules"], rules);
        // An unknown match is still dropped.
        let s = ProxySettings::from_json(&json!({
            "rules": [{"match": "uid", "value": "1000"}]
        }));
        assert!(s.rules.is_empty());
        // Program and app names keep their case when left out.
        let e = GroupEdit::from_json(&json!({
            "exclude": ["A.com", "process:QQ", "app:path:/Applications/QQ.app"]
        }));
        assert_eq!(
            e.exclude,
            ["a.com", "process:QQ", "app:path:/Applications/QQ.app"]
        );
    }

    #[test]
    fn app_matchers() {
        use AppMatcher::*;
        for (v, want) in [
            (
                "path:/Applications/X.app",
                Some(Path("/Applications/X.app".into())),
            ),
            (
                "path:/Applications/X.app//",
                Some(Path("/Applications/X.app".into())),
            ),
            ("name: chrome.exe ", Some(Name("chrome.exe".into()))),
            ("pkg:com.tencent.mm", Some(Package("com.tencent.mm".into()))),
            ("path:/", None),
            ("pkg:", None),
            ("uid:1000", None),
            ("firefox", None),
            ("name:a,b", None),
            ("path:/A (1).app", Some(Path("/A (1).app".into()))),
        ] {
            assert_eq!(AppMatcher::parse(v), want, "{v}");
        }
        assert_eq!(Path("/A.app".into()).condition(), "PROCESS-PATH,/A.app");
        assert_eq!(Package("com.x".into()).condition(), "PROCESS-NAME,com.x");
    }

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

    /// B14: no `group_edits: {}` when every edit is empty.
    #[test]
    fn empty_group_edits_are_not_written() {
        let s = ProxySettings::from_json(&json!({"group_edits": {"policy:ai": {}}}));
        assert!(s.to_json().get("group_edits").is_none());
        let s = ProxySettings::from_json(&json!({"group_edits": {
            "policy:ai": {}, "policy:google": {"exclude": ["a.example"]},
        }}));
        assert_eq!(
            s.to_json()["group_edits"],
            json!({"policy:google": {"exclude": ["a.example"]}})
        );
    }

    #[test]
    fn picks_land_where_the_apps_pick_group_puts_them() {
        let mut s = json!({"mode": "smart", "selected": "auto",
            "group_strategy": {"region:HK": "fastest"}})
        .as_object()
        .unwrap()
        .clone();
        assert!(record_pick(&mut s, "proxy", "HK 01"));
        assert!(!record_pick(&mut s, "proxy", "HK 01"));
        assert!(record_pick(&mut s, "policy:ai", "REJECT"));
        assert!(record_pick(&mut s, "policy:google", "region:US"));
        assert!(record_pick(&mut s, "region:HK", "HK 02"));
        for not in ["speedtest", "GLOBAL", "region:HK~fastest"] {
            assert!(!record_pick(&mut s, not, "HK 01"), "{not}");
        }
        // AI ran with 固定出口 by default: picked by hand, it keeps the
        // switch as it was.
        assert_eq!(
            Value::Object(s.clone()),
            json!({"mode": "smart", "selected": "HK 01",
                "policies": {"policy:ai": "block", "policy:google": "region:US"},
                "policy_use": {"policy:ai": {"sticky": true}},
                "group_pick": {"region:HK": "HK 02"}})
        );
        // Read back as the app reads them.
        let p = ProxySettings::from_json(&Value::Object(s));
        assert_eq!(p.selected, "HK 01");
        assert_eq!(p.group_picks["region:HK"], "HK 02");
        assert_eq!(p.policies["policy:ai"], "block");
        assert!(p.group_strategies.is_empty());
        assert!(p.sticky_of("policy:ai"));
        assert!(!p.sticky_of("policy:google"));
    }

    #[test]
    fn picks_in_a_policys_copies_are_how_it_uses_the_group() {
        let mut s = Map::new();
        // The policy's copy of a group, picked in the policy: the group.
        assert!(record_pick(
            &mut s,
            "policy:youtube",
            "policy:youtube@region:US~fastest"
        ));
        assert!(record_pick(&mut s, "group:g1", "group:g1@region:JP"));
        assert!(record_pick(
            &mut s,
            "policy:google",
            "policy:google@auto~fastest~sticky"
        ));
        // A pick inside a one-line copy: how that policy uses the group.
        assert!(record_pick(&mut s, "policy:ai@region:US", "US 1"));
        assert!(!record_pick(&mut s, "policy:ai@region:US", "US 1"));
        assert!(record_pick(
            &mut s,
            "policy:netflix@region:JP",
            "region:JP~fastest"
        ));
        assert!(!record_pick(&mut s, "policy:ai@region:US~fastest", "US 2"));
        assert_eq!(
            Value::Object(s.clone()),
            json!({
                "policies": {"policy:youtube": "region:US", "policy:google": "auto~fastest"},
                "group_pick": {"group:g1": "region:JP"},
                "policy_use": {
                    "policy:ai": {"groups": {"region:US": {"use": "line", "line": "US 1"}}},
                    "policy:netflix": {"groups": {"region:JP": {"use": "fastest"}}},
                },
            })
        );
        let p = ProxySettings::from_json(&Value::Object(s));
        assert_eq!(
            p.group_use("policy:ai", "region:US"),
            Some(&GroupUse::Line("US 1".into()))
        );
        assert_eq!(
            p.group_use("policy:netflix", "region:JP"),
            Some(&GroupUse::Fastest)
        );
        // Saved and read back the same.
        assert_eq!(ProxySettings::from_json(&p.to_json()), p);
    }

    #[test]
    fn policy_use_reads_leniently_and_writes_only_what_is_set() {
        let s = ProxySettings::from_json(&json!({"policy_use": {
            "policy:ai": {"sticky": false, "groups": {
                "region:US": {"use": "line", "line": "US 1"},
                "region:JP": {"use": "line"},
                "region:SG": {"use": "default"},
                "kind:relay": "fastest",
                "auto": {"use": "balance"},
            }},
            "policy:youtube": {},
            "policy:media": 3,
        }}));
        assert_eq!(
            s.to_json()["policy_use"],
            json!({"policy:ai": {"sticky": false, "groups": {
                "region:US": {"use": "line", "line": "US 1"},
                "auto": {"use": "balance"},
            }}})
        );
        assert!(!s.sticky_of("policy:ai"));
        assert!(ProxySettings::default()
            .to_json()
            .get("policy_use")
            .is_none());
    }

    /// Old settings: AI keeps 固定出口 where it ran with it, and only there.
    #[test]
    fn the_built_in_sticky_follows_what_ai_used_before() {
        let of = |v: Value| ProxySettings::from_json(&v).sticky_of("policy:ai");
        assert!(of(json!({})));
        assert!(of(json!({"policies": {"policy:ai": "policy:ai~sticky"}})));
        assert!(of(json!({"group_defaults": {"policy:ai": "region:JP"}})));
        assert!(!of(json!({"policies": {"policy:ai": "region:JP"}})));
        assert!(!of(json!({"group_defaults": {"policy:ai": "fastest"}})));
        assert!(of(json!({"policies": {"policy:ai": "region:JP"},
            "policy_use": {"policy:ai": {"sticky": true}}})));
        // No other policy has it unless switched on.
        let s = ProxySettings::from_json(&json!({}));
        assert!(!s.sticky_of("policy:youtube"));
        assert!(!s.sticky_of("group:g1"));
    }
}

//! Tree groups as meow `proxy-groups:` entries (Dart: `clashGroup`,
//! `clashAutoGroup`).

use serde_json::{Map, Value};

use crate::plan::{AutoStrategy, GroupKind, GroupSpec};

/// The URL automatic groups probe.
const PROBE_URL: &str = "https://www.gstatic.com/generate_204";

/// Seconds between probes of the groups that probe periodically.
const PROBE_INTERVAL: i64 = 300;

/// `{name, type, proxies}` with `members` as `proxies`.
fn head(name: &str, kind: &str, members: Vec<String>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("name".into(), name.into());
    m.insert("type".into(), kind.into());
    m.insert("proxies".into(), members.into());
    m
}

/// One group of the tree as meow writes it (Dart: `clashGroup`):
///
/// - 完全按订阅 (a raw type, not a selector): the provider's type as is;
/// - a selector: its pick first (the core starts on the first member);
/// - 智能选择: [`clash_auto_group`];
/// - 负载均衡 / 速度最快 / 固定出口: meow's `smart` in its
///   `consistent-hashing` / `throughput` / `sticky` mode with the
///   [`AutoStrategy::Smart`] strategy, else `load-balance` / `url-test` /
///   `fallback`.
pub fn clash_group(g: &GroupSpec, strategy: AutoStrategy) -> Map<String, Value> {
    let members = || g.members.clone();
    let smart = strategy == AutoStrategy::Smart;
    if let Some(raw) = g
        .raw_type
        .as_deref()
        .filter(|_| g.kind != GroupKind::Select)
    {
        let mut m = head(&g.tag, raw, members());
        m.insert("url".into(), PROBE_URL.into());
        m.insert("interval".into(), PROBE_INTERVAL.into());
        if raw == "load-balance" {
            m.insert("strategy".into(), "consistent-hashing".into());
        }
        return m;
    }
    let smart_mode = |mode: &str| {
        let mut m = head(&g.tag, "smart", members());
        m.insert("strategy".into(), mode.into());
        m.insert("url".into(), PROBE_URL.into());
        m
    };
    match g.kind {
        GroupKind::Select => {
            let mut proxies: Vec<String> = g.pick.iter().cloned().collect();
            proxies.extend(
                g.members
                    .iter()
                    .filter(|m| Some(*m) != g.pick.as_ref())
                    .cloned(),
            );
            head(&g.tag, "select", proxies)
        }
        GroupKind::Smart => clash_auto_group(&g.tag, &g.members, strategy),
        GroupKind::Balance if smart => smart_mode("consistent-hashing"),
        GroupKind::Balance => {
            let mut m = head(&g.tag, "load-balance", members());
            m.insert("strategy".into(), "consistent-hashing".into());
            m.insert("url".into(), PROBE_URL.into());
            m.insert("interval".into(), PROBE_INTERVAL.into());
            m
        }
        GroupKind::Fastest if smart => smart_mode("throughput"),
        GroupKind::Fastest => clash_auto_group(&g.tag, &g.members, AutoStrategy::UrlTest),
        GroupKind::Sticky if smart => smart_mode("sticky"),
        GroupKind::Sticky => {
            let mut m = head(&g.tag, "fallback", members());
            m.insert("url".into(), PROBE_URL.into());
            m.insert("interval".into(), PROBE_INTERVAL.into());
            m
        }
    }
}

/// An automatic group over `members` (Dart: `clashAutoGroup`): meow's
/// `smart` (per-site learning), or `url-test` with a 50 ms tolerance.
pub fn clash_auto_group(name: &str, members: &[String], s: AutoStrategy) -> Map<String, Value> {
    match s {
        AutoStrategy::Smart => {
            let mut m = head(name, "smart", members.to_vec());
            m.insert("url".into(), PROBE_URL.into());
            m
        }
        AutoStrategy::UrlTest => {
            let mut m = head(name, "url-test", members.to_vec());
            m.insert("url".into(), PROBE_URL.into());
            m.insert("interval".into(), PROBE_INTERVAL.into());
            m.insert("tolerance".into(), 50.into());
            m
        }
    }
}

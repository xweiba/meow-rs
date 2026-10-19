//! L5: the meow config, assembled from the pool, the plan and L4's pieces
//! (Dart: `buildClashConfig` in `clash_config.dart`). The only layer that
//! knows the whole config's shape: key order, listeners, DNS, sniffer,
//! TUN, groups and the rule order.
//!
//! Rule order (first match wins), see [`RULE_ORDER`].
//!
//! Lines are named by the pool's tags ([`crate::pool::node_tags_for`]):
//! the config, the screen's tree and the subscriptions' split all use the
//! same names (B1).
//!
//! Known Dart behaviours kept for parity:
//!
//! - Device exits and `allowLan` are not ported (the controller never
//!   passes them on the meow path): a user rule to a device is REJECT.

mod groups;
mod sections;

use std::collections::HashSet;

use indexmap::IndexSet;
use serde_json::{Map, Value};

use crate::model::settings::{
    AppMatcher, GroupEdit, ProxyMode, ProxySettings, RuleTarget, SshChain,
};
use crate::plan::group_tree::BADGE_SUBSCRIPTION;
use crate::plan::legacy::{line_candidates, moved_region};
use crate::plan::{
    outbound_tags, AutoStrategy, GroupTree, ImportedSplit, RoutePolicy, RuntimeOptions,
};
use crate::pool::{clash_proxy_for, Pool};
use crate::rules::{
    custom_rule_line, iface_tag, module_config, rule_matcher, rule_target, rule_target_tag,
    ssh_proxies, without_sites, ModuleConfig, ScriptModule, SshSecrets,
};

pub use groups::{clash_auto_group, clash_group};

/// Supported interpreter stages (schema identifiers, not routing data).
/// The profile's `order` chooses their actual execution order. Privacy
/// rules run in every mode; only service/subscription splitting is smart-only.
pub const RULE_ORDER: [&str; 10] = [
    "speedtest-in",
    "own-app",
    "in-user",
    "private",
    "user",
    "encrypted-dns",
    "stun",
    "modules",
    "smart",
    "match",
];

/// The speed test's inbound (Dart `OutboundTags.speedTestIn`).
pub const SPEED_TEST_IN: &str = "speedtest-in";

/// The app's own connections that came in through the TUN go direct
/// (`self_app`: `RuntimeOptions::self_app`); through a local port — the
/// app asking for the proxy — they follow the rules like any other. None
/// when `self_app` is not an app matcher a rule line can carry.
pub fn own_app_rule(self_app: &str) -> Option<String> {
    let app = AppMatcher::parse(self_app)?.condition();
    // A name with brackets would break the logic rule's grouping.
    if app.contains(['(', ')']) {
        return None;
    }
    crate::rule_profile::RuleProfile::shipped().template("ownApp", &[("app", &app)])
}

/// What [`build_clash_config`] reads (Dart `buildClashConfig`'s parameters
/// as `ProxyController._launch` passes them).
#[derive(Clone, Copy)]
pub struct EmitInput<'a> {
    /// The line pool: its lines, their tags (the proxies' names) and
    /// groups.
    pub pool: &'a Pool,
    /// The settings in force ([`crate::plan::BuildInput::effective`]).
    pub settings: &'a ProxySettings,
    pub runtime: &'a RuntimeOptions,
    /// The route API's policies, each with a target in the config
    /// ([`crate::plan::offered_route_policies`]); used only when
    /// `runtime.route` is set.
    pub route_policies: &'a [RoutePolicy],
    pub strategy: AutoStrategy,
    /// SSH credentials; written into the chains' proxies, never logged.
    pub ssh_secrets: &'a SshSecrets,
    /// The subscriptions' merged split ([`crate::plan::imported_split`]).
    pub split: &'a ImportedSplit,
    /// The group tree ([`crate::plan::tree_for`] over the same pool,
    /// settings and split): the one the screen shows.
    pub tree: &'a GroupTree,
    /// Every rewrite module (the disabled ones are skipped).
    pub modules: &'a [ScriptModule],
    /// The local time zone's offset in minutes, for cron scripts.
    pub utc_offset: i64,
}

/// A built config and how many lines it could not take.
#[derive(Clone, PartialEq)]
pub struct ClashConfig {
    /// The meow config, keys in Dart's order. Holds secrets (API secret,
    /// SSH credentials, node passwords): never log it.
    pub config: Map<String, Value>,
    /// Lines the core can't run (plain HTTP …), left out of the pool.
    pub unsupported: usize,
}

impl std::fmt::Debug for ClashConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClashConfig")
            .field("config", &format_args!("<{} keys>", self.config.len()))
            .field("unsupported", &self.unsupported)
            .finish()
    }
}

/// What both the config and the rule list are built from: the lines'
/// names, the config's tree and what rules may point at.
struct Plan<'a> {
    input: &'a EmitInput<'a>,
    /// The lines' `proxies:` entries, named by their tags.
    proxies: Vec<Map<String, Value>>,
    tree: &'a GroupTree,
    /// Any line, chain or group a rule may point at.
    choices: HashSet<String>,
}

impl<'a> Plan<'a> {
    fn new(input: &'a EmitInput<'a>) -> Self {
        let s = input.settings;
        let pool = input.pool;
        let names = &pool.tags;
        // The pool holds only lines the core can run.
        let proxies: Vec<Map<String, Value>> = pool
            .nodes
            .iter()
            .zip(names)
            .filter_map(|(n, t)| clash_proxy_for(&n.node, t))
            .collect();
        let ssh_names: Vec<String> = s.ssh_chains.iter().map(SshChain::tag).collect();
        let tree = input.tree;
        let choices = names
            .iter()
            .chain(&ssh_names)
            .chain(tree.groups.iter().map(|g| &g.tag))
            .cloned()
            .collect();
        Self {
            input,
            proxies,
            tree,
            choices,
        }
    }

    fn settings(&self) -> &ProxySettings {
        self.input.settings
    }

    /// Where a user rule's target is, as the core names it: REJECT for a
    /// device (none on this path) or a line that no longer exists (under
    /// none of its old names either, [`line_candidates`]); None for a
    /// target this version cannot read: no rule, its sites go on to the
    /// rules after it.
    fn target(&self, t: &RuleTarget) -> Option<String> {
        match self.resolve(t) {
            TargetState::Same(to) | TargetState::Moved(to) => Some(to),
            TargetState::Gone => Some("REJECT".into()),
            TargetState::Unknown => None,
        }
    }

    fn resolve(&self, t: &RuleTarget) -> TargetState {
        match t {
            RuleTarget::Device(_) => TargetState::Gone,
            RuleTarget::Unknown(_) => TargetState::Unknown,
            RuleTarget::Line(tag) if !self.choices.contains(tag) => {
                let pool = self.input.pool;
                std::iter::once(tag.clone())
                    .chain(line_candidates(tag))
                    .flat_map(|c| {
                        let region = moved_region(&c, pool);
                        std::iter::once(c).chain(region)
                    })
                    .find(|c| c != tag && self.choices.contains(c))
                    .map_or(TargetState::Gone, TargetState::Moved)
            }
            _ => TargetState::Same(rule_target_tag(t)),
        }
    }

    /// A name rules and groups may point at.
    fn known(&self, name: &str) -> bool {
        name == "DIRECT" || name == "REJECT" || self.choices.contains(name)
    }

    fn has_group(&self, tag: &str) -> bool {
        self.tree.by_tag(tag).is_some()
    }

    fn profile(&self) -> &crate::rule_profile::RuleProfile {
        self.input
            .runtime
            .rules_profile
            .as_ref()
            .unwrap_or_else(|| crate::rule_profile::RuleProfile::shipped())
    }

    /// Removed groups follow the file's ordered fallback list. With no
    /// usable configured group, refuse DNS rather than silently bypass it.
    fn dns_policy(&self) -> &str {
        let selected = if self.settings().dns_policy.is_empty() {
            &self.profile().default_dns_policy
        } else {
            &self.settings().dns_policy
        };
        if self.known(selected) {
            selected
        } else {
            self.profile()
                .dns_fallbacks
                .iter()
                .find(|t| self.known(t))
                .map(String::as_str)
                .unwrap_or("REJECT")
        }
    }

    /// Exactly as the subscriptions wrote it: none of our groups.
    fn as_written(&self) -> bool {
        !self.tree.groups.is_empty()
            && self
                .tree
                .groups
                .iter()
                .all(|g| g.badge == Some(BADGE_SUBSCRIPTION))
    }

    /// Match conditions, targets and order all come from the profile;
    /// runtime group exclusions still apply to that group's whole block.
    fn policy_rules(&self, p: &crate::rule_profile::PolicyRules) -> Vec<String> {
        let domestic = if self.known(&self.profile().domestic_policy) {
            &self.profile().domestic_policy
        } else {
            &self.profile().domestic_fallback
        };
        p.rules
            .iter()
            .map(|r| {
                let line =
                    crate::rule_profile::RuleProfile::expand(r, &[("domesticPolicy", domestic)]);
                self.excluded(&p.group, line)
            })
            .collect()
    }

    fn excluded(&self, target: &str, line: String) -> String {
        match self.settings().group_edits.get(target) {
            Some(e) if !e.exclude.is_empty() && GroupEdit::editable(target) => {
                without_sites(&line, &e.exclude)
            }
            _ => line,
        }
    }

    /// The rule lines in [`RULE_ORDER`]. `speed_test`: the speed test's
    /// inbound exists; `own_app`: the app's own rule ([`own_app_rule`]);
    /// `route`: the route API's policies when it is on; `module_rules`:
    /// what the modules add.
    fn rules(
        &self,
        speed_test: bool,
        own_app: Option<String>,
        route: Option<&[RoutePolicy]>,
        module_rules: &[String],
    ) -> Vec<String> {
        let s = self.settings();
        let split = self.input.split;
        let profile = self.profile();
        let mut stages: indexmap::IndexMap<&str, Vec<String>> = indexmap::IndexMap::new();
        if speed_test {
            stages
                .entry("speedtest-in")
                .or_default()
                .extend(profile.template(
                    "speedtest",
                    &[
                        ("inbound", SPEED_TEST_IN),
                        ("target", outbound_tags::SPEED_TEST),
                    ],
                ));
        }
        stages.insert("own-app", own_app.into_iter().collect());
        for p in route
            .unwrap_or_default()
            .iter()
            .filter(|p| !p.target.is_empty())
        {
            let target = match p.target.as_str() {
                outbound_tags::DIRECT => "DIRECT",
                target => target,
            };
            stages
                .entry("in-user")
                .or_default()
                .extend(profile.template("inUser", &[("user", &p.id), ("target", target)]));
        }
        stages.insert("private", profile.private_rules.clone());
        let user: Vec<String> = s
            .rules
            .iter()
            .filter_map(|r| custom_rule_line(r, &self.target(&r.target)?))
            .collect();
        stages.insert("user", user.clone());
        let target = self.dns_policy();
        // Legacy API callers may still provide only the former resolver list.
        let encrypted = self
            .input
            .runtime
            .encrypted_dns_rules
            .as_ref()
            .filter(|_| self.input.runtime.rules_profile.is_none())
            .map(|dns| dns.lines(target))
            .unwrap_or_else(|| {
                profile
                    .encrypted_dns_rules
                    .iter()
                    .map(|r| crate::rule_profile::RuleProfile::expand(r, &[("dnsPolicy", target)]))
                    .collect()
            });
        stages.insert(
            "encrypted-dns",
            encrypted
                .into_iter()
                .map(|r| self.excluded(target, r))
                .collect(),
        );
        stages.insert(
            "stun",
            profile
                .stun_rules
                .iter()
                .map(|r| {
                    self.excluded(
                        target,
                        crate::rule_profile::RuleProfile::expand(r, &[("dnsPolicy", target)]),
                    )
                })
                .collect(),
        );
        stages.insert("modules", module_rules.to_vec());
        let as_written = self.as_written();
        let mut smart = Vec::new();
        if s.mode == ProxyMode::Smart {
            for p in profile
                .policies
                .iter()
                .filter(|p| !p.base && self.has_group(&p.group))
            {
                smart.extend(self.policy_rules(p));
            }
            let built_in: HashSet<&str> = profile
                .policies
                .iter()
                .filter(|p| !p.base && self.has_group(&p.group))
                .map(|p| p.group.as_str())
                .collect();
            let user_matchers: HashSet<String> = user.iter().map(|r| rule_matcher(r)).collect();
            let fresh = |r: &str| !user_matchers.contains(&rule_matcher(r));
            smart.extend(
                split
                    .rules
                    .iter()
                    .filter(|r| built_in.contains(rule_target(r)) && fresh(r))
                    .cloned(),
            );
            smart.extend(
                split
                    .rules
                    .iter()
                    .filter(|r| {
                        !built_in.contains(rule_target(r)) && self.known(rule_target(r)) && fresh(r)
                    })
                    .cloned(),
            );
            if !as_written {
                smart.extend(profile.private_sites.clone());
                for p in profile
                    .policies
                    .iter()
                    .filter(|p| p.base && self.has_group(&p.group))
                {
                    smart.extend(self.policy_rules(p));
                }
            }
        }
        stages.insert("smart", smart);
        let mode = match s.mode {
            ProxyMode::Direct => "direct",
            ProxyMode::Global => "global",
            ProxyMode::Smart => "smart",
        };
        let catch_all = if s.mode == ProxyMode::Smart && as_written {
            split
                .final_target
                .as_deref()
                .or_else(|| profile.final_targets.get(mode).map(String::as_str))
        } else {
            profile.final_targets.get(mode).map(String::as_str)
        }
        .unwrap_or("REJECT");
        stages.insert(
            "match",
            profile
                .template("match", &[("target", catch_all)])
                .into_iter()
                .collect(),
        );
        profile
            .order
            .iter()
            .flat_map(|key| stages.shift_remove(key.as_str()).unwrap_or_default())
            .collect()
    }

    /// Interfaces direct traffic leaves by (rules and groups sending sites
    /// out of another VPN's interface …), each once.
    fn interfaces(&self) -> IndexSet<String> {
        let from_rules = self
            .settings()
            .rules
            .iter()
            .filter_map(|r| match &r.target {
                RuleTarget::Iface(name) => Some(name.clone()),
                _ => None,
            });
        let from_groups = self
            .tree
            .groups
            .iter()
            .flat_map(|g| &g.members)
            .filter_map(|m| m.strip_prefix("iface:").map(str::to_owned));
        from_rules.chain(from_groups).collect()
    }

    fn modules(&self, return_port: Option<i64>) -> ModuleConfig {
        module_config(
            self.input.modules,
            outbound_tags::PROXY,
            return_port,
            self.input.utc_offset,
        )
    }
}

/// Where a user rule's saved target leads in this build.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetState {
    /// There, as saved.
    Same(String),
    /// Saved under an old name of this group (see [`line_candidates`]).
    Moved(String),
    /// A line or group there is none of now: its sites are refused.
    Gone,
    /// A target this version cannot read: the rule makes no line.
    Unknown,
}

/// The user rules' targets that do not lead where they say, by their
/// saved form (`line:…`, as in proxy.json) → `{"state": "moved", "to":
/// tag}`, `{"state": "gone"}` (refused) or `{"state": "unknown"}` (no rule:
/// the sites go on to the rules after it). The rules page marks them.
pub fn rule_target_states(input: &EmitInput<'_>) -> Map<String, Value> {
    let plan = Plan::new(input);
    let mut out = Map::new();
    for r in &input.settings.rules {
        let state = match plan.resolve(&r.target) {
            TargetState::Same(_) => continue,
            TargetState::Moved(to) => serde_json::json!({"state": "moved", "to": to}),
            TargetState::Gone => serde_json::json!({"state": "gone"}),
            TargetState::Unknown => serde_json::json!({"state": "unknown"}),
        };
        out.insert(r.target.encode(), state);
    }
    out
}

/// The meow config (Dart: `buildClashConfig`), keys in Dart's order.
pub fn build_clash_config(input: &EmitInput<'_>) -> ClashConfig {
    let plan = Plan::new(input);
    let s = input.settings;
    let rt = input.runtime;
    let mods = plan.modules(rt.mitm_port);
    let speed_test = rt.speed_test_port.filter(|_| !input.pool.tags.is_empty());
    let route = rt.route.as_ref();
    let lan = route.is_some_and(|r| r.lan);

    let mut c = Map::new();
    c.insert("mixed-port".into(), s.mixed_port.into());
    c.insert(
        "bind-address".into(),
        (if lan { "*" } else { "127.0.0.1" }).into(),
    );
    c.insert("allow-lan".into(), lan.into());
    // Route API: the proxy user name is the policy asked for; programs on
    // this machine without a key keep working.
    if let Some(r) = route {
        let auth: Vec<String> = input
            .route_policies
            .iter()
            .map(|p| format!("{}:{}", p.id, r.key))
            .collect();
        c.insert("authentication".into(), auth.into());
        c.insert(
            "skip-auth-prefixes".into(),
            vec!["127.0.0.1/8", "::1/128"].into(),
        );
    }
    c.insert("mode".into(), "rule".into());
    if rt.find_process {
        c.insert("find-process-mode".into(), "always".into());
    }
    if rt.unified_delay {
        c.insert("unified-delay".into(), true.into());
    }
    if let Some(n) = rt.connection_history {
        c.insert("connection-history-limit".into(), n.max(0).into());
    }
    let level = if rt.log_level == "warn" {
        "warning"
    } else {
        rt.log_level.as_str()
    };
    c.insert("log-level".into(), level.into());
    c.insert("ipv6".into(), rt.ipv6.into());
    c.insert(
        "external-controller".into(),
        format!("127.0.0.1:{}", rt.controller_port).into(),
    );
    c.insert("secret".into(), rt.secret.clone().into());
    c.insert("profile".into(), sections::profile());
    c.insert("geodata".into(), plan.profile().geodata.clone());
    if !s.hosts.is_empty() {
        c.insert(
            "paopao-hosts".into(),
            crate::rules::paopao_hosts(&s.hosts).into(),
        );
    }
    let direct_pick = |group: &str| {
        plan.tree
            .by_tag(group)
            .and_then(|g| g.pick.as_deref())
            .is_some_and(|p| p == "DIRECT" || p == outbound_tags::DIRECT)
    };
    c.insert(
        "dns".into(),
        sections::dns(
            rt.ipv6,
            s.tun,
            plan.dns_policy(),
            plan.profile(),
            direct_pick,
        ),
    );
    c.insert("sniffer".into(), plan.profile().sniffer.clone());
    if s.tun {
        c.insert(
            "tun".into(),
            sections::tun(
                rt.ipv6,
                s.outbound_interface.as_deref(),
                rt.vpn.as_ref(),
                rt.outbound.as_ref(),
            ),
        );
    }
    let mut listeners: Vec<Value> = Vec::new();
    if let Some(port) = speed_test {
        let mut l = Map::new();
        l.insert("name".into(), SPEED_TEST_IN.into());
        l.insert("type".into(), "mixed".into());
        l.insert("port".into(), port.into());
        l.insert("listen".into(), "127.0.0.1".into());
        listeners.push(Value::Object(l));
    }
    if let Some(l) = &mods.listener {
        listeners.push(Value::Object(l.clone()));
    }
    if !listeners.is_empty() {
        c.insert("listeners".into(), listeners.into());
    }

    let mut proxies: Vec<Value> = plan.proxies.iter().cloned().map(Value::Object).collect();
    for chain in &s.ssh_chains {
        proxies.extend(
            ssh_proxies(chain, input.ssh_secrets)
                .into_iter()
                .map(|p| Value::Object(p.into_map())),
        );
    }
    proxies.extend(mods.proxies.iter().cloned().map(Value::Object));
    for name in plan.interfaces() {
        let mut p = Map::new();
        p.insert("name".into(), iface_tag(&name).into());
        p.insert("type".into(), "direct".into());
        p.insert("interface-name".into(), name.into());
        proxies.push(Value::Object(p));
    }
    c.insert("proxies".into(), proxies.into());

    let mut groups: Vec<Value> = plan
        .tree
        .groups
        .iter()
        .map(|g| {
            let mut m = clash_group(g, input.strategy);
            // 后台测速间隔: how often a smart group re-probes its lines.
            if let Some(s) = rt
                .probe_interval
                .filter(|_| m.get("type").and_then(Value::as_str) == Some("smart"))
            {
                m.insert("interval".into(), s.into());
            }
            Value::Object(m)
        })
        .collect();
    if speed_test.is_some() {
        let mut g = Map::new();
        g.insert("name".into(), outbound_tags::SPEED_TEST.into());
        g.insert("type".into(), "select".into());
        g.insert("proxies".into(), input.pool.tags.clone().into());
        groups.push(Value::Object(g));
    }
    c.insert("proxy-groups".into(), groups.into());

    let route_policies = route.map(|_| input.route_policies);
    // Only the TUN brings the app's own connections in.
    let own_app = rt.self_app.as_deref().filter(|_| s.tun).and_then(|name| {
        let app = AppMatcher::parse(name)?.condition();
        if app.contains(['(', ')']) {
            return None;
        }
        plan.profile().template("ownApp", &[("app", &app)])
    });
    let rules = plan.rules(speed_test.is_some(), own_app, route_policies, &mods.rules);
    c.insert("rules".into(), rules.into());
    ClashConfig {
        config: c,
        unsupported: input.pool.unsupported,
    }
}

/// The rules the core tries for the user's own traffic, in order (Dart:
/// `ProxyController.effectiveRules`): `config`'s own `rules:` without the
/// speed test's (`IN-NAME`), the app's own ([`own_app_rule`]) and the
/// route API's (`IN-USER`). One source
/// with the config (B28): Dart built them apart with no MITM port, so the
/// rules page and the conflict check missed the modules' MITM rules.
pub fn effective_rules(config: &Map<String, Value>) -> Vec<String> {
    let own_prefix = crate::rule_profile::RuleProfile::shipped()
        .templates
        .get("ownApp")
        .and_then(|s| s.split("{app}").next())
        .filter(|s| !s.is_empty());
    config
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|r| !r.starts_with("IN-USER,") && !r.starts_with("IN-NAME,"))
        .filter(|r| !own_prefix.is_some_and(|prefix| r.starts_with(prefix)))
        .map(str::to_owned)
        .collect()
}

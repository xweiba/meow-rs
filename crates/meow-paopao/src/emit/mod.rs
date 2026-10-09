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
//! - B2: the config's tree always has the split (the screen's only in smart
//!   mode).
//! - Device exits and `allowLan` are not ported (the controller never
//!   passes them on the meow path): a user rule to a device is REJECT.

mod groups;
mod sections;

use std::collections::HashSet;

use indexmap::IndexSet;
use serde_json::{Map, Value};

use crate::model::settings::{ProxyMode, ProxySettings, RuleTarget, SshChain};
use crate::plan::group_tree::BADGE_SUBSCRIPTION;
use crate::plan::{
    build_group_tree, final_policy, outbound_tags, AutoStrategy, GroupTree, ImportedSplit, Policy,
    RoutePolicy, RuntimeOptions, TreeInput, POLICIES,
};
use crate::pool::{clash_proxy_for, is_usable_node, Pool};
use crate::rules::{
    custom_rule_line, geo_rule, iface_tag, module_config, private_cidr_rules, rule_matcher,
    rule_target, rule_target_tag, ssh_proxies, without_sites, ModuleConfig, ScriptModule,
    SshSecrets, PRIVATE_RULE_SET,
};

pub use groups::{clash_auto_group, clash_group};

/// The order rule lines are written in, as named stages (Dart: the
/// `rules:` list of `buildClashConfig`):
///
/// 1. the speed test's inbound to its selector;
/// 2. the route API's users (`IN-USER`) to their policies;
/// 3. private and loopback ranges direct;
/// 4. the user's rules (a target that no longer exists: REJECT);
/// 5. the rewrite modules' rules;
/// 6. smart mode only: STUN over the proxy, the built-in service groups
///    (QUIC refused first, sites left out by the user excluded), the
///    subscriptions' rules to those groups, the subscriptions' rules to
///    their own groups, then — unless the subscriptions' groups are used
///    exactly as written — local names direct and the basic split;
/// 7. `MATCH`, the catch-all.
pub const RULE_ORDER: [&str; 7] = [
    "speedtest-in",
    "in-user",
    "private",
    "user",
    "modules",
    "smart",
    "match",
];

/// The speed test's inbound (Dart `OutboundTags.speedTestIn`).
pub const SPEED_TEST_IN: &str = "speedtest-in";

/// STUN / TURN ports (RFC 8489 3478 and 5349 for TLS; Google's
/// 19302-19309).
const STUN_PORTS: &str = "3478/5349/19302-19309";

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
    /// The route API's policies; used only when `runtime.route` is set.
    pub route_policies: &'a [RoutePolicy],
    pub strategy: AutoStrategy,
    /// SSH credentials; written into the chains' proxies, never logged.
    pub ssh_secrets: &'a SshSecrets,
    /// The subscriptions' merged split ([`crate::plan::imported_split`]).
    pub split: &'a ImportedSplit,
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
    tree: GroupTree,
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
        let usable: Vec<String> = pool
            .nodes
            .iter()
            .zip(names)
            .filter(|(n, _)| is_usable_node(&n.node))
            .map(|(_, t)| t.clone())
            .collect();
        let ssh_names: Vec<String> = s.ssh_chains.iter().map(SshChain::tag).collect();
        let tree = build_group_tree(&TreeInput {
            lines: names,
            usable: &usable,
            base: &pool.groups,
            settings: s,
            split: input.split,
            extras: &ssh_names,
            smart_mode: s.mode == ProxyMode::Smart,
        });
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
    /// device (none on this path) or a line that no longer exists.
    fn target(&self, t: &RuleTarget) -> String {
        match t {
            RuleTarget::Device(_) => "REJECT".into(),
            RuleTarget::Line(tag) if !self.choices.contains(tag) => "REJECT".into(),
            _ => rule_target_tag(t),
        }
    }

    /// A name rules and groups may point at.
    fn known(&self, name: &str) -> bool {
        name == "DIRECT" || name == "REJECT" || self.choices.contains(name)
    }

    fn has_group(&self, tag: &str) -> bool {
        self.tree.by_tag(tag).is_some()
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

    /// A built-in policy's rules: QUIC to its sites refused first (they fall
    /// back to TCP on the same group), its rule sets, domains, programs and
    /// ranges; each minus the sites the user left out of it.
    fn policy_rules(&self, p: &Policy) -> Vec<String> {
        let tag = p.tag();
        let mut out = Vec::new();
        if p.block_quic {
            for r in p.rule_sets {
                if let Some(site) = r.strip_prefix("geosite-") {
                    out.push(format!(
                        "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,{site})),REJECT"
                    ));
                }
            }
        }
        out.extend(p.rule_sets.iter().map(|r| geo_rule(r, &tag)));
        out.extend(p.domains.iter().map(|d| format!("DOMAIN-SUFFIX,{d},{tag}")));
        out.extend(
            p.processes
                .iter()
                .map(|n| format!("PROCESS-NAME,{n},{tag}")),
        );
        out.extend(p.ip_cidrs.iter().map(|c| {
            let kind = if c.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            format!("{kind},{c},{tag},no-resolve")
        }));
        match self.settings().group_edits.get(&tag) {
            Some(e) if !e.exclude.is_empty() => {
                out.iter().map(|r| without_sites(r, &e.exclude)).collect()
            }
            _ => out,
        }
    }

    /// The rule lines in [`RULE_ORDER`]. `speed_test`: the speed test's
    /// inbound exists; `route`: the route API's policies when it is on;
    /// `module_rules`: what the modules add.
    fn rules(
        &self,
        speed_test: bool,
        route: Option<&[RoutePolicy]>,
        module_rules: &[String],
    ) -> Vec<String> {
        let s = self.settings();
        let split = self.input.split;
        let mut out = Vec::new();
        if speed_test {
            out.push(format!(
                "IN-NAME,{SPEED_TEST_IN},{}",
                outbound_tags::SPEED_TEST
            ));
        }
        for p in route.unwrap_or_default() {
            let t = p.target.as_str();
            if t == outbound_tags::DIRECT || t == outbound_tags::PROXY || self.choices.contains(t) {
                let t = if t == outbound_tags::DIRECT {
                    "DIRECT"
                } else {
                    t
                };
                out.push(format!("IN-USER,{},{t}", p.id));
            }
        }
        out.extend(private_cidr_rules());
        let user: Vec<String> = s
            .rules
            .iter()
            .map(|r| custom_rule_line(r, &self.target(&r.target)))
            .collect();
        out.extend(user.iter().cloned());
        out.extend(module_rules.iter().cloned());
        let as_written = self.as_written();
        if s.mode == ProxyMode::Smart {
            out.push(format!(
                "AND,((NETWORK,UDP),(DST-PORT,{STUN_PORTS})),{}",
                outbound_tags::PROXY
            ));
            for p in POLICIES
                .iter()
                .filter(|p| !p.base && self.has_group(&p.tag()))
            {
                out.extend(self.policy_rules(p));
            }
            let built_in: HashSet<String> = POLICIES
                .iter()
                .filter(|p| !p.base && self.has_group(&p.tag()))
                .map(Policy::tag)
                .collect();
            let is_built_in = |r: &str| built_in.contains(rule_target(r));
            // The user's matchers drop the subscriptions' same ones.
            let user_matchers: HashSet<String> = user.iter().map(|r| rule_matcher(r)).collect();
            let fresh = |r: &str| !user_matchers.contains(&rule_matcher(r));
            out.extend(
                split
                    .rules
                    .iter()
                    .filter(|r| is_built_in(r) && fresh(r))
                    .cloned(),
            );
            out.extend(
                split
                    .rules
                    .iter()
                    .filter(|r| !is_built_in(r) && self.known(rule_target(r)) && fresh(r))
                    .cloned(),
            );
            if !as_written {
                out.push(geo_rule(PRIVATE_RULE_SET, "DIRECT"));
                for p in POLICIES
                    .iter()
                    .filter(|p| p.base && self.has_group(&p.tag()))
                {
                    out.extend(self.policy_rules(p));
                }
            }
        }
        let catch_all = match s.mode {
            ProxyMode::Direct => "DIRECT".to_owned(),
            ProxyMode::Global => outbound_tags::PROXY.to_owned(),
            ProxyMode::Smart if as_written => split
                .final_target
                .clone()
                .unwrap_or_else(|| outbound_tags::PROXY.to_owned()),
            ProxyMode::Smart => final_policy().tag(),
        };
        out.push(format!("MATCH,{catch_all}"));
        out
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
    c.insert("geodata".into(), sections::geodata());
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
    c.insert("dns".into(), sections::dns(rt.ipv6, s.tun, direct_pick));
    c.insert("sniffer".into(), sections::sniffer());
    if s.tun {
        c.insert(
            "tun".into(),
            sections::tun(rt.ipv6, s.outbound_interface.as_deref()),
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
        .map(|g| Value::Object(clash_group(g, input.strategy)))
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
    let rules = plan.rules(speed_test.is_some(), route_policies, &mods.rules);
    c.insert("rules".into(), rules.into());
    ClashConfig {
        config: c,
        unsupported: input.pool.unsupported,
    }
}

/// Every rule the core is (or would be) given, in the order it tries them
/// (Dart: `ProxyController.effectiveRules`): the rules of a config built
/// with no speed test, no route API and no MITM port, so neither `IN-NAME`
/// / `IN-USER` lines nor the modules' MITM rules (only their own rules).
pub fn effective_rules(input: &EmitInput<'_>) -> Vec<String> {
    let plan = Plan::new(input);
    let mods = plan.modules(None);
    plan.rules(false, None, &mods.rules)
        .into_iter()
        .filter(|r| !r.starts_with("IN-USER,") && !r.starts_with("IN-NAME,"))
        .collect()
}

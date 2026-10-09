//! L6 facade: the crate's entry points, typed ([`build`]) and as JSON
//! documents in and out ([`parse_json`], [`build_json`]), the shape the
//! Dart app (and the box's web service) exchange with it.
//!
//! - [`parse_json`]: a subscription body → `{nodes, skipped, split, usage}`
//!   (what `ProxyController` stores for a subscription).
//! - [`build_json`]: `ProxyController.configInput()` → `{config, pool, tree,
//!   rules, routePolicies}`.
//! - [`explain_json`]: the same input and a connection → the rule that
//!   decides it and where it goes ([`explain`]).
//!
//! Failures are `{"error": "..."}`, never a panic across the boundary.

use serde_json::{json, Map, Value};

use crate::emit::{build_clash_config, effective_rules, EmitInput};
use crate::plan::{
    imported_split, offered_route_policies, route_catalog, tree_for, BuildInput, GroupTree,
    RoutePolicy,
};
use crate::pool::{build_pool, Pool};
use crate::rules::matcher::{Connection, Rule, Verdict};
use crate::rules::{ScriptModule, SshSecrets};
use crate::{parse_subscription, usage_from_names};

/// A subscription body → `{nodes, skipped, split, usage}`; `usage` is what
/// the node names say (traffic left / expiry), null when they say nothing.
pub fn parse_json(body: &str) -> Value {
    match parse_subscription(body) {
        Ok(r) => {
            let usage = usage_from_names(r.nodes.iter().map(|n| n.name.as_str()));
            json!({
                "nodes": r.nodes,
                "skipped": r.skipped,
                "split": r.split,
                "usage": usage,
            })
        }
        Err(e) => json!({ "error": e.to_string() }),
    }
}

/// Everything one build produces: the config the core runs and what the
/// screens show beside it.
#[derive(Clone, PartialEq)]
pub struct BuildOutput {
    /// The meow config (keys in Dart's order). Holds secrets: never log it.
    pub config: Map<String, Value>,
    /// The line pool (tags, nodes with exits, region / kind groups).
    pub pool: Pool,
    /// The group tree the screen shows and the config runs
    /// ([`crate::plan::tree_for`]).
    pub tree: GroupTree,
    /// The config's rules, in order, without the route API's and the speed
    /// test's ([`effective_rules`]).
    pub rules: Vec<String>,
    /// What the route API offers (Dart `ProxyController.routePolicies`):
    /// only policies the config has a target for (B29).
    pub route_policies: Vec<RoutePolicy>,
}

impl BuildOutput {
    /// `{config, pool, tree, rules, routePolicies}`; `pool` as
    /// [`Pool::to_json`], `tree` as [`GroupTree::to_json`], the policies as
    /// [`RoutePolicy::to_json`].
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("config".into(), Value::Object(self.config.clone()));
        m.insert("pool".into(), self.pool.to_json());
        m.insert("tree".into(), self.tree.to_json());
        m.insert("rules".into(), self.rules.clone().into());
        m.insert(
            "routePolicies".into(),
            Value::Array(
                self.route_policies
                    .iter()
                    .map(RoutePolicy::to_json)
                    .collect(),
            ),
        );
        Value::Object(m)
    }
}

impl std::fmt::Debug for BuildOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildOutput")
            .field("config", &format_args!("<{} keys>", self.config.len()))
            .field("pool", &self.pool)
            .field("tree", &self.tree)
            .field("rules", &self.rules)
            .field("route_policies", &self.route_policies)
            .finish()
    }
}

/// One build (Dart: what `ProxyController._launch` does with
/// `buildClashConfig`, plus the pool, tree, rules and route policies the
/// controller derives): the pool from the subscriptions, the effective
/// settings, the subscriptions' split, then the config.
///
/// Everything reads the effective settings: the split, the tree, the
/// config and the route policies' SSH chains (Dart listed those from the
/// raw settings, B30).
pub fn build(input: &BuildInput) -> BuildOutput {
    let pool = build_pool(&input.pool_input());
    let settings = input.effective();
    let split = imported_split(input, &pool, &settings);
    // One tree: the screen's and the config's (B2).
    let tree = tree_for(&settings, &pool, &split);
    let route_policies = offered_route_policies(
        route_catalog(&pool.groups, !pool.nodes.is_empty(), &settings.ssh_chains),
        &tree,
        &settings.ssh_chains,
    );
    let modules: Vec<ScriptModule> = input
        .modules
        .iter()
        .filter_map(ScriptModule::from_json)
        .collect();
    let mut secrets = SshSecrets::new();
    for (k, v) in &input.ssh_secrets {
        secrets.insert(k.clone(), v.clone());
    }
    let emit = EmitInput {
        pool: &pool,
        settings: &settings,
        runtime: &input.runtime,
        route_policies: &route_policies,
        strategy: input.strategy,
        ssh_secrets: &secrets,
        split: &split,
        tree: &tree,
        modules: &modules,
        utc_offset: input.utc_offset,
    };
    let config = build_clash_config(&emit).config;
    let rules = effective_rules(&config);
    BuildOutput {
        config,
        pool,
        tree,
        rules,
        route_policies,
    }
}

/// `ProxyController.configInput()` as JSON → [`BuildOutput::to_json`], or
/// `{"error": ...}` when the input is not a JSON object.
pub fn build_json(input: &str) -> Value {
    match serde_json::from_str::<Value>(input) {
        Ok(v) if v.is_object() => build(&BuildInput::from_json(&v)).to_json(),
        Ok(_) => json!({ "error": "input is not a JSON object" }),
        Err(e) => json!({ "error": format!("input is not JSON: {e}") }),
    }
}

/// The rule deciding a connection, and where it leads ([`explain`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The rule line as the config has it.
    pub rule: String,
    /// Its type (`DOMAIN-SUFFIX`, `GEOSITE`, `AND`, `MATCH` …).
    pub kind: String,
    /// What it matches (empty for `MATCH`).
    pub payload: String,
    /// Where it sends the connection.
    pub target: String,
    /// Its place in the config's `rules:`.
    pub index: usize,
    /// `target`, then each select group's pick down to a line, DIRECT,
    /// REJECT or an automatic group (which picks at run time).
    pub path: Vec<String>,
    /// False when only the core can tell whether this rule takes the
    /// connection (a rule set, a domain to look up): the rules after it
    /// may decide instead, so the answer is "not known".
    pub decided: bool,
}

impl Explanation {
    /// `{rule, type, payload, target, index, path, decided}`.
    pub fn to_json(&self) -> Value {
        json!({
            "rule": self.rule,
            "type": self.kind,
            "payload": self.payload,
            "target": self.target,
            "index": self.index,
            "path": self.path,
            "decided": self.decided,
        })
    }
}

/// Which rule of the config built from `input` decides connection `c`, the
/// first that takes it (B5 / D6; Dart's `_roughMatch` looked at the user's
/// rules and the policies' names only). It walks the config's real rule
/// list: private ranges, the user's rules, the modules', the business
/// policies minus their excluded sites, the subscriptions', the basic
/// split, `MATCH`. A rule only the core can evaluate (`GEOSITE`, `GEOIP`,
/// an IP rule for a domain without `no-resolve`, an unknown type) stops
/// the walk undecided. None only when no rule could take it at all.
pub fn explain(input: &BuildInput, c: &Connection) -> Option<Explanation> {
    let out = build(input);
    let rules = out.config.get("rules").and_then(Value::as_array)?;
    rules.iter().enumerate().find_map(|(index, line)| {
        let line = line.as_str()?;
        let rule = Rule::parse(line)?;
        let decided = match rule.check(c) {
            Verdict::No => return None,
            Verdict::Yes => true,
            Verdict::Unknown => false,
        };
        Some(Explanation {
            rule: line.to_owned(),
            kind: rule.kind.to_owned(),
            payload: rule.payload.to_owned(),
            target: rule.target.to_owned(),
            index,
            path: group_path(&out.tree, rule.target),
            decided,
        })
    })
}

/// `target`, then the pick of each select group on the way.
fn group_path(tree: &GroupTree, target: &str) -> Vec<String> {
    let mut path = vec![target.to_owned()];
    let mut at = target;
    while let Some(g) = tree.by_tag(at) {
        if g.kind != crate::plan::GroupKind::Select {
            break;
        }
        let Some(pick) = g.pick.as_deref() else { break };
        if path.iter().any(|p| p == pick) {
            break;
        }
        path.push(pick.to_owned());
        at = pick;
    }
    path
}

/// [`explain`] over JSON: `input` as for [`build_json`], `query`
/// `{host, port?, process?, processPath?, network?}` (`network`: `tcp` by
/// default or `udp`) → [`Explanation::to_json`], `null` when no rule takes it, or
/// `{"error": ...}`.
pub fn explain_json(input: &str, query: &str) -> Value {
    let input = match serde_json::from_str::<Value>(input) {
        Ok(v) if v.is_object() => v,
        Ok(_) => return json!({ "error": "input is not a JSON object" }),
        Err(e) => return json!({ "error": format!("input is not JSON: {e}") }),
    };
    let q = match serde_json::from_str::<Value>(query) {
        Ok(v) if v.is_object() => v,
        _ => return json!({ "error": "query is not a JSON object" }),
    };
    let Some(host) = q.get("host").and_then(Value::as_str) else {
        return json!({ "error": "query has no host" });
    };
    let c = Connection {
        host: host.to_owned(),
        port: q
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok()),
        process: q.get("process").and_then(Value::as_str).map(str::to_owned),
        process_path: q
            .get("processPath")
            .and_then(Value::as_str)
            .map(str::to_owned),
        udp: q
            .get("network")
            .and_then(Value::as_str)
            .is_some_and(|n| n.eq_ignore_ascii_case("udp")),
    };
    explain(&BuildInput::from_json(&input), &c).map_or(Value::Null, |e| e.to_json())
}

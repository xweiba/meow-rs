//! L6 facade: the crate's entry points, typed ([`build`]) and as JSON
//! documents in and out ([`parse_json`], [`build_json`]), the shape the
//! Dart app (and the box's web service) exchange with it.
//!
//! - [`parse_json`]: a subscription body → `{nodes, skipped, split, usage}`
//!   (what `ProxyController` stores for a subscription).
//! - [`build_json`]: `ProxyController.configInput()` → `{config, pool, tree,
//!   rules, routePolicies}`.
//!
//! Failures are `{"error": "..."}`, never a panic across the boundary.

use serde_json::{json, Map, Value};

use crate::emit::{build_clash_config, effective_rules, EmitInput};
use crate::plan::{build_tree, imported_split, route_catalog, BuildInput, GroupTree, RoutePolicy};
use crate::pool::{build_pool, Pool};
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
    /// The group tree the screen shows ([`build_tree`]).
    pub tree: GroupTree,
    /// The rules the core tries, in order, without the route API's and the
    /// speed test's (Dart `ProxyController.effectiveRules`).
    pub rules: Vec<String>,
    /// What the route API offers (Dart `ProxyController.routePolicies`).
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
/// Dart parity: the route policies are listed from the raw settings' SSH
/// chains (`_settings`), the config from the effective settings.
pub fn build(input: &BuildInput) -> BuildOutput {
    let pool = build_pool(&input.pool_input());
    let settings = input.effective();
    let split = imported_split(input, &pool);
    let route_policies = route_catalog(
        &pool.groups,
        !pool.nodes.is_empty(),
        &input.settings.ssh_chains,
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
        nodes: &pool.nodes,
        settings: &settings,
        runtime: &input.runtime,
        route_policies: &route_policies,
        strategy: input.strategy,
        ssh_secrets: &secrets,
        split: &split,
        modules: &modules,
        utc_offset: input.utc_offset,
    };
    let config = build_clash_config(&emit).config;
    let rules = effective_rules(&emit);
    let tree = build_tree(input, &pool);
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

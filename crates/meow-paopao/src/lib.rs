//! PaoPao's config generation as pure functions: no IO, no async, no clock.
//!
//! Ported from the Dart app (`paopao_proxy`) layer by layer; every layer's
//! output must equal the Dart code's for the same input (golden tests under
//! `tests/golden`).
//!
//! - [`model`] (L0): nodes, subscriptions' split and usage, settings, network,
//!   and the static tables they refer to (our outbound tags, the built-in
//!   policies).
//! - [`ingest`] (L1): subscription bodies and share links → nodes.
//! - [`pool`] (L2): subscriptions → one line pool of what the core can run
//!   (nodes as `proxies:` entries), tags, region / kind groups.
//! - [`plan`] (L3): the business policies' groups, the subscriptions'
//!   merged split, the group tree.
//! - [`rules`] (L4): config pieces without the tree: SSH chains as
//!   proxies, hosts, rewrite modules, rule lines.
//! - [`emit`] (L5): the meow config assembled from all of the above.
//! - [`api`] (L6): [`build`], [`explain`] and the JSON entry points; `ffi`
//!   (feature `ffi`, on by default) puts them behind a C ABI:
//!   `paopao_parse`, `paopao_build`, `paopao_explain`, `paopao_free`.

pub mod api;
mod dart;
pub mod emit;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod ingest;
pub mod model;
pub mod plan;
pub mod pool;
pub mod rules;

pub use api::{build, build_json, explain, explain_json, parse_json, BuildOutput, Explanation};
pub use emit::{build_clash_config, effective_rules, ClashConfig, EmitInput};
pub use ingest::{
    parse_share_link, parse_share_links, parse_subscription, usage_from_names, ParseError,
};
pub use model::network::{effective_settings, NetworkInfo, NetworkKind};
pub use model::node::{ParseResult, ProxyNode, SUPPORTED_NODE_TYPES};
pub use model::settings::ProxySettings;
pub use model::subscription::{SubGroup, SubRules, Subscription};
pub use model::usage::Usage;
pub use plan::{
    build_tree, imported_split, offered_route_policies, route_catalog, tree_for, AutoStrategy,
    BuildInput, GroupKind, GroupSpec, GroupTree, ImportedGroup, ImportedSplit, RoutePolicy,
    RuntimeOptions,
};
pub use pool::{
    build_pool, clash_proxy_for, NodeGroup, Pool, PoolInput, PoolNode, PoolSource, Region,
};
pub use rules::matcher::Connection;
pub use rules::{module_config, paopao_hosts, ssh_proxies, ModuleConfig, ScriptModule, SshSecrets};

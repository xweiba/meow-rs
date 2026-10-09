//! PaoPao's config generation as pure functions: no IO, no async, no clock.
//!
//! Ported from the Dart app (`paopao_proxy`) layer by layer; every layer's
//! output must equal the Dart code's for the same input (golden tests under
//! `tests/golden`).
//!
//! - [`model`] (L0): nodes, subscriptions' split and usage, settings, network.
//! - [`ingest`] (L1): subscription bodies and share links → nodes.
//! - [`pool`] (L2): subscriptions → one line pool, tags, region / kind groups.
//! - [`plan`] (L3): business policies, the subscriptions' merged split, the
//!   group tree.
//! - [`rules`] (L4): config pieces without the tree: nodes and SSH chains as
//!   proxies, hosts, rewrite modules, rule lines.
//! - [`emit`] (L5): the meow config assembled from all of the above.
//! - [`api`] (L6): [`build`] and the JSON entry points; `ffi` (feature
//!   `ffi`, on by default) puts them behind a C ABI: `paopao_parse`,
//!   `paopao_build`, `paopao_free`.

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

pub use api::{build, build_json, parse_json, BuildOutput};
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
    build_tree, imported_split, route_catalog, AutoStrategy, BuildInput, GroupKind, GroupSpec,
    GroupTree, ImportedGroup, ImportedSplit, RoutePolicy, RuntimeOptions,
};
pub use pool::{build_pool, NodeGroup, Pool, PoolInput, PoolNode, PoolSource, Region};
pub use rules::{
    clash_proxies, clash_proxy_for, module_config, paopao_hosts, ssh_proxies, ClashProxies,
    ModuleConfig, ScriptModule, SshSecrets,
};

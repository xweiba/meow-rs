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

mod dart;
pub mod ingest;
pub mod model;
pub mod plan;
pub mod pool;
pub mod rules;

pub use ingest::{
    parse_share_link, parse_share_links, parse_subscription, usage_from_names, ParseError,
};
pub use model::network::{effective_settings, NetworkInfo, NetworkKind};
pub use model::node::{ParseResult, ProxyNode, SUPPORTED_NODE_TYPES};
pub use model::settings::ProxySettings;
pub use model::subscription::{SubGroup, SubRules, Subscription};
pub use model::usage::Usage;
pub use plan::{
    build_tree, imported_split, BuildInput, GroupKind, GroupSpec, GroupTree, ImportedGroup,
    ImportedSplit,
};
pub use pool::{build_pool, NodeGroup, Pool, PoolInput, PoolNode, PoolSource, Region};
pub use rules::{
    clash_proxies, clash_proxy_for, module_config, paopao_hosts, ssh_proxies, ClashProxies,
    ModuleConfig, ScriptModule, SshSecrets,
};

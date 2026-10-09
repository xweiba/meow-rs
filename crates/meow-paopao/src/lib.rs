//! PaoPao's config generation as pure functions: no IO, no async, no clock.
//!
//! Ported from the Dart app (`paopao_proxy`) layer by layer; every layer's
//! output must equal the Dart code's for the same input (golden tests under
//! `tests/golden`).
//!
//! - [`model`] (L0): nodes, subscriptions' split and usage, settings, network.
//! - [`ingest`] (L1): subscription bodies and share links → nodes.

mod dart;
pub mod ingest;
pub mod model;

pub use ingest::{
    parse_share_link, parse_share_links, parse_subscription, usage_from_names, ParseError,
};
pub use model::network::{effective_settings, NetworkInfo, NetworkKind};
pub use model::node::{ParseResult, ProxyNode, SUPPORTED_NODE_TYPES};
pub use model::settings::ProxySettings;
pub use model::subscription::{SubGroup, SubRules};
pub use model::usage::Usage;

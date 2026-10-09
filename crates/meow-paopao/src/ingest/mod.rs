//! L1: subscription bodies → nodes, provider split and usage.

mod clash;
mod outbound;
mod parser;
mod uri;
mod usage;
mod yaml;

use std::fmt;

pub use parser::{parse_share_link, parse_share_links, parse_subscription};
pub use usage::usage_from_names;

use crate::dart::Crash;

/// A single share link with a field of an unexpected type
/// ([`parse_share_link`]). In a subscription such an entry is only counted
/// in [`crate::ParseResult::skipped`] (B9), so [`parse_subscription`] does
/// not fail on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl From<Crash> for ParseError {
    fn from(c: Crash) -> Self {
        Self { message: c.0 }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "subscription parse failed: {}", self.message)
    }
}

impl std::error::Error for ParseError {}

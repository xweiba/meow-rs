//! PaoPao 签到助手 engine.
//!
//! Tasks ("open the site, do what was recorded, once a day"), their steps
//! (`api`: re-send a request; `click`: ask an attached app to click in a
//! hidden webview), variables (`{name}` in a step, filled from the app's
//! webview or by the user), the shareable rule format, the serial runner
//! and the daily schedule with catch-up.
//!
//! No UI and no webview here: the crate runs wherever the core runs
//! (desktop, Android, a server, OpenWrt). `meow-api` exposes it under
//! `/checkin`; the core gives it a [`http::Connector`] so requests leave
//! through the core's own outbound path.

pub mod clicks;
pub mod clock;
pub mod engine;
pub mod error;
pub mod expiry;
pub mod http;
pub mod model;
pub mod replay;
pub mod rule;
pub mod site;
pub mod store;
pub mod vars;

pub use clock::{Clock, SystemClock};
pub use engine::{Engine, EngineConfig, EngineTasks};
pub use error::{CheckinError, ErrorKind};
pub use http::{BoxStream, Connector, SystemConnector};
pub use model::Access;

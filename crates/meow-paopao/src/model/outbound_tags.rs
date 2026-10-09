//! Our own outbound tags (Dart `OutboundTags`): the names our groups and
//! outbounds go by in the settings, the route API and the config.

/// 🚀 节点选择.
pub const PROXY: &str = "proxy";
/// ♻️ 自动选择.
pub const AUTO: &str = "auto";
/// ♻️ 自动选择's 智能选择.
pub const SMART: &str = "auto~smart";
/// ♻️ 自动选择's 负载均衡.
pub const BALANCE: &str = "auto~balance";
/// ♻️ 自动选择's 速度最快.
pub const FASTEST: &str = "auto~fastest";
/// The selector the download speed test switches line by line.
pub const SPEED_TEST: &str = "speedtest";
/// Direct (Clash's DIRECT), as stored in settings.
pub const DIRECT: &str = "direct";
/// Refuse (Clash's REJECT), as stored in settings.
pub const BLOCK: &str = "block";

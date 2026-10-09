//! The built-in business policies (Dart: `policies.dart`): one Clash-style
//! selector per kind of traffic the built-in split recognises ("⛔️ 广告拦截",
//! "🌐 国外网站", "🐟 漏网之鱼" …), in rule order. Static data: the settings
//! decode reads it (L0), the plan builds groups and rules from it (S11).

use crate::dart::find_ignore_ascii_case;
use crate::model::outbound_tags;

/// One alternative of a policy's aliases: how a provider's group name
/// (`🎥 Netflix`) is recognised as meaning one of ours (B20, B21).
///
/// English aliases match as whole words, ASCII case ignored: the
/// characters around must not be part of a word (`is_word_char`). Dart
/// matched most of them anywhere, so a group called "Download", "iPad Pro"
/// or "Trinidad" became 广告拦截 (its sites blocked by default), "Harbing"
/// 微软服务 and "Ashbourne" 国外媒体. Chinese aliases match anywhere: Chinese
/// has no spaces between words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasTerm {
    /// The text anywhere (Chinese: `奈飞`).
    Text(&'static str),
    /// The word on its own (`netflix`, `global media`).
    Word(&'static str),
    /// The word or its plural with `s` on its own (`ad`: "AD", "Ads").
    Plural(&'static str),
}

/// Whether `c` continues a word next to an English alias: ASCII letters,
/// digits and `_`, and letters of other alphabetic scripts ("ſtg" and
/// "Ŧg" are not "tg"). Ideographic scripts and everything after them
/// (U+2E80 on: CJK, kana, hangul, fullwidth forms), emoji, spaces and
/// punctuation end a word, so "AI服务" and "TG频道" still name AI and
/// Telegram.
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || c == '_'
        || (!c.is_ascii() && c < '\u{2E80}' && c.is_alphanumeric())
}

impl AliasTerm {
    /// Whether the term matches somewhere in `name` (ASCII case ignored).
    pub fn matches(self, name: &str) -> bool {
        let (word, plural) = match self {
            Self::Text(t) => return find_ignore_ascii_case(name, t, 0).is_some(),
            Self::Word(w) => (w, false),
            Self::Plural(w) => (w, true),
        };
        let ends_word = |at: usize| name[at..].chars().next().is_none_or(|c| !is_word_char(c));
        let mut from = 0;
        while let Some(i) = find_ignore_ascii_case(name, word, from) {
            let end = i + word.len();
            let before = name[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !is_word_char(c));
            let after = ends_word(end)
                || (plural
                    && name
                        .as_bytes()
                        .get(end)
                        .is_some_and(|c| c.eq_ignore_ascii_case(&b's'))
                    && ends_word(end + 1));
            if before && after {
                return true;
            }
            from = i + 1;
        }
        false
    }
}

/// A built-in business policy group (Dart `Policy`). Its group tag is
/// `policy:<id>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Stable id ("ai").
    pub id: &'static str,
    /// Chinese name ("AI 服务").
    pub name: &'static str,
    /// Emoji before the name.
    pub icon: &'static str,
    /// Rule sets (sing-box tags, `geosite-…` / `geoip-…`) whose traffic
    /// this policy decides.
    pub rule_sets: &'static [&'static str],
    /// Address ranges it decides (Telegram's).
    pub ip_cidrs: &'static [&'static str],
    /// Where its traffic goes until the user picks otherwise: `proxy`,
    /// `direct` or `block` (our outbound tags, not Clash's names).
    pub fallback: &'static str,
    /// Offers only 拦截 / 直连 (ads), not the lines.
    pub blockable: bool,
    /// Region codes the service refuses (its group leaves them out).
    pub avoid_regions: &'static [&'static str],
    /// The alias pattern as Dart wrote it (case-insensitive regular
    /// expression), for reference; [`Policy::alias_terms`] is what matches
    /// (whole English words, B20 / B21).
    pub aliases: Option<&'static str>,
    /// Names of provider groups meaning this policy.
    pub alias_terms: &'static [AliasTerm],
    /// The basic split (国外 / 国内 / 漏网之鱼): kept when the built-in
    /// service groups are switched off; its rules come after the
    /// subscriptions' own.
    pub base: bool,
    /// Region code it uses by default when there are lines there (AI: US).
    pub prefer_region: Option<&'static str>,
    /// Its default pick when the group has it (YouTube: `auto~fastest`).
    pub prefer_pick: Option<&'static str>,
    /// QUIC (UDP 443) to its sites refused so they fall back to TCP.
    pub block_quic: bool,
    /// 固定出口 as its default: the whole service on one line.
    pub sticky_exit: bool,
    /// Extra names (and their subdomains) it decides beyond its rule sets.
    pub domains: &'static [&'static str],
    /// Programs whose every connection goes here (`PROCESS-NAME`).
    pub processes: &'static [&'static str],
}

impl Policy {
    /// `policy:<id>`.
    pub fn tag(&self) -> String {
        format!("policy:{}", self.id)
    }

    /// What the user sees, `<icon> <name>`.
    pub fn label(&self) -> String {
        format!("{} {}", self.icon, self.name)
    }

    /// A provider group named `name` means the same as this policy: one of
    /// its [`Policy::alias_terms`] matches. False without aliases.
    pub fn alias_matches(&self, name: &str) -> bool {
        self.alias_terms.iter().any(|t| t.matches(name))
    }

    const fn new(
        id: &'static str,
        name: &'static str,
        icon: &'static str,
        fallback: &'static str,
    ) -> Self {
        Self {
            id,
            name,
            icon,
            rule_sets: &[],
            ip_cidrs: &[],
            fallback,
            blockable: false,
            avoid_regions: &[],
            aliases: None,
            alias_terms: &[],
            base: false,
            prefer_region: None,
            prefer_pick: None,
            block_quic: false,
            sticky_exit: false,
            domains: &[],
            processes: &[],
        }
    }
}

/// Telegram's own address ranges (its apps connect by IP).
pub const TELEGRAM_IPS: [&str; 14] = [
    "91.105.192.0/23",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "149.154.160.0/20",
    "185.76.151.0/24",
    "2001:67c:4e8::/48",
    "2001:b28:f23c::/48",
    "2001:b28:f23d::/48",
    "2001:b28:f23f::/48",
    "2a0a:f280::/32",
];

/// IP lookup and IP quality sites, routed with 🤖 AI 服务 (CN-only ones are
/// left out: they check the domestic address).
pub const IP_CHECK_DOMAINS: [&str; 28] = [
    "ipinfo.io",
    "ipapi.co",
    "ipapi.is",
    "ip-api.com",
    "ipify.org",
    "ipwho.is",
    "ip.sb",
    "ifconfig.me",
    "ifconfig.co",
    "icanhazip.com",
    "ipdata.co",
    "ipgeolocation.io",
    "ipregistry.co",
    "ip2location.io",
    "ip2location.com",
    "iplocation.net",
    "country.is",
    "myip.com",
    "whatismyip.com",
    "whatismyipaddress.com",
    "ipleak.net",
    "browserleaks.com",
    "whoer.net",
    "scamalytics.com",
    "ipqualityscore.com",
    "ping0.cc",
    "ippure.com",
    "ip.skk.moe",
];

/// AI's own extra names (captchas, feature flags, error reports, support
/// chat, payment, sign-in), then [`IP_CHECK_DOMAINS`].
const AI_DOMAINS: [&str; 41] = [
    "challenges.cloudflare.com",
    "arkoselabs.com",
    "statsig.com",
    "statsigapi.net",
    "featuregates.org",
    "featureassets.org",
    "sentry.io",
    "intercom.io",
    "intercomcdn.com",
    "intercomassets.com",
    "stripe.com",
    "stripe.network",
    "auth0.com",
    // IP_CHECK_DOMAINS (Dart spreads the list here).
    "ipinfo.io",
    "ipapi.co",
    "ipapi.is",
    "ip-api.com",
    "ipify.org",
    "ipwho.is",
    "ip.sb",
    "ifconfig.me",
    "ifconfig.co",
    "icanhazip.com",
    "ipdata.co",
    "ipgeolocation.io",
    "ipregistry.co",
    "ip2location.io",
    "ip2location.com",
    "iplocation.net",
    "country.is",
    "myip.com",
    "whatismyip.com",
    "whatismyipaddress.com",
    "ipleak.net",
    "browserleaks.com",
    "whoer.net",
    "scamalytics.com",
    "ipqualityscore.com",
    "ping0.cc",
    "ippure.com",
    "ip.skk.moe",
];

/// Regions most AI / Google services refuse.
const AVOID_CN_HK_MO_RU: [&str; 4] = ["HK", "MO", "CN", "RU"];

use AliasTerm::{Plural, Text, Word};

/// The policies in rule order: the first that matches decides; the last
/// (漏网之鱼) takes the rest. Built-in groups come before the
/// subscriptions' rules; the basic split ([`Policy::base`]) after.
pub static POLICIES: [Policy; 16] = [
    Policy {
        rule_sets: &["geosite-category-ads-all", "geosite-category-httpdns-cn"],
        blockable: true,
        aliases: Some(r"广告|拦截广告|AdBlock|ads?\b|劫持|hijack"),
        alias_terms: &[
            Text("广告"),
            Text("拦截广告"),
            Word("AdBlock"),
            Plural("ad"),
            Text("劫持"),
            Word("hijack"),
        ],
        ..Policy::new("ads", "广告拦截", "⛔️", outbound_tags::BLOCK)
    },
    // Before Google: geosite-google includes YouTube.
    Policy {
        rule_sets: &["geosite-youtube"],
        prefer_pick: Some(outbound_tags::FASTEST),
        block_quic: true,
        aliases: Some("youtube|油管"),
        alias_terms: &[Word("youtube"), Text("油管")],
        ..Policy::new("youtube", "YouTube", "📹", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-google-gemini", "geosite-google"],
        avoid_regions: &AVOID_CN_HK_MO_RU,
        aliases: Some("google|谷歌|gemini"),
        alias_terms: &[Word("google"), Text("谷歌"), Word("gemini")],
        ..Policy::new("google", "Google + Gemini", "💡", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &[
            "geosite-openai",
            "geosite-anthropic",
            "geosite-category-ai-!cn",
            "geosite-perplexity",
            "geosite-xai",
        ],
        domains: &AI_DOMAINS,
        avoid_regions: &AVOID_CN_HK_MO_RU,
        prefer_region: Some("US"),
        sticky_exit: true,
        aliases: Some(r"openai|chatgpt|claude|anthropic|\bai\b|人工智能|copilot|grok|perplexity"),
        alias_terms: &[
            Word("openai"),
            Word("chatgpt"),
            Word("claude"),
            Word("anthropic"),
            Word("ai"),
            Text("人工智能"),
            Word("copilot"),
            Word("grok"),
            Word("perplexity"),
        ],
        ..Policy::new("ai", "AI 服务", "🤖", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-telegram"],
        ip_cidrs: &TELEGRAM_IPS,
        aliases: Some(r"telegram|电报|\btg\b"),
        alias_terms: &[Word("telegram"), Text("电报"), Word("tg")],
        ..Policy::new("telegram", "电报信息", "📲", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &[
            "geosite-twitter",
            "geosite-facebook",
            "geosite-instagram",
            "geosite-discord",
            "geosite-reddit",
            "geosite-whatsapp",
            "geosite-line",
        ],
        aliases: Some("twitter|推特|facebook|脸书|instagram|discord|社交"),
        alias_terms: &[
            Word("twitter"),
            Text("推特"),
            Word("facebook"),
            Text("脸书"),
            Word("instagram"),
            Word("discord"),
            Text("社交"),
        ],
        ..Policy::new("social", "社交媒体", "💬", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-netflix"],
        aliases: Some("netflix|奈飞|网飞"),
        alias_terms: &[Word("netflix"), Text("奈飞"), Text("网飞")],
        ..Policy::new("netflix", "NETFLIX", "🎥", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &[
            "geosite-steam",
            "geosite-epicgames",
            "geosite-playstation",
            "geosite-xbox",
            "geosite-nintendo",
        ],
        aliases: Some("steam|游戏|game|epic|playstation|xbox|nintendo|switch"),
        alias_terms: &[
            Word("steam"),
            Text("游戏"),
            Plural("game"),
            Word("epic"),
            Word("playstation"),
            Word("xbox"),
            Word("nintendo"),
            Word("switch"),
        ],
        ..Policy::new("games", "游戏平台", "🎮", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &[
            "geosite-category-media-cn",
            "geosite-bilibili",
            "geosite-iqiyi",
            "geosite-youku",
        ],
        aliases: Some("国内媒体|哔哩|bilibili|爱奇艺|iqiyi|港澳台"),
        alias_terms: &[
            Text("国内媒体"),
            Text("哔哩"),
            Word("bilibili"),
            Text("爱奇艺"),
            Word("iqiyi"),
            Text("港澳台"),
        ],
        ..Policy::new("cnmedia", "国内媒体", "🌏", outbound_tags::DIRECT)
    },
    Policy {
        rule_sets: &[
            "geosite-spotify",
            "geosite-disney",
            "geosite-hbo",
            "geosite-primevideo",
            "geosite-tiktok",
            "geosite-category-entertainment",
        ],
        aliases: Some("国外媒体|海外媒体|流媒体|spotify|disney|hbo|tiktok|global ?media|streaming"),
        alias_terms: &[
            Text("国外媒体"),
            Text("海外媒体"),
            Text("流媒体"),
            Word("spotify"),
            Word("disney"),
            Word("hbo"),
            Word("tiktok"),
            Word("global media"),
            Word("globalmedia"),
            Word("streaming"),
        ],
        ..Policy::new("media", "国外媒体", "📺", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-github", "geosite-huggingface"],
        aliases: Some("github|开发"),
        alias_terms: &[Word("github"), Text("开发")],
        ..Policy::new("dev", "开发者服务", "💻", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-microsoft", "geosite-onedrive", "geosite-bing"],
        aliases: Some("microsoft|微软|onedrive|bing|azure"),
        alias_terms: &[
            Word("microsoft"),
            Text("微软"),
            Word("onedrive"),
            Word("bing"),
            Word("azure"),
        ],
        ..Policy::new("microsoft", "微软服务", "Ⓜ️", outbound_tags::DIRECT)
    },
    Policy {
        rule_sets: &["geosite-apple"],
        aliases: Some("apple|苹果|icloud"),
        alias_terms: &[Word("apple"), Text("苹果"), Word("icloud")],
        ..Policy::new("apple", "苹果服务", "🍎", outbound_tags::DIRECT)
    },
    Policy {
        rule_sets: &["geosite-geolocation-!cn"],
        base: true,
        ..Policy::new("foreign", "国外网站", "🌐", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-category-games@cn", "geosite-cn", "geoip-cn"],
        // WeChat dials its own addresses (HTTPDNS), Tencent's abroad too:
        // the whole program follows this group.
        processes: &[
            "WeChat",
            "WeChatAppEx Helper",
            "Weixin.exe",
            "WeChat.exe",
            "WeChatAppEx.exe",
            "com.tencent.mm",
        ],
        base: true,
        ..Policy::new("china", "国内网站", "🇨🇳", outbound_tags::DIRECT)
    },
    Policy {
        base: true,
        ..Policy::new("final", "漏网之鱼", "🐟", outbound_tags::PROXY)
    },
];

/// The policy whose group tag is `tag` (`policy:ai`); None for anything
/// else.
pub fn policy_by_tag(tag: &str) -> Option<&'static Policy> {
    let id = tag.strip_prefix("policy:")?;
    POLICIES.iter().find(|p| p.id == id)
}

/// The catch-all policy (`policies.last`): where MATCH sends the rest.
pub fn final_policy() -> &'static Policy {
    &POLICIES[POLICIES.len() - 1]
}

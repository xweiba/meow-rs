//! The built-in business policies (Dart: `policies.dart`): one Clash-style
//! selector per kind of traffic the built-in split recognises ("⛔️ 广告拦截",
//! "🌐 国外网站", "🐟 漏网之鱼" …), in rule order.

use crate::dart::find_ignore_ascii_case;
use crate::plan::outbound_tags;

/// One alternative of a policy's alias pattern. Dart writes the aliases as
/// one case-insensitive regular expression; every alternative there is a
/// literal, a literal between ASCII word boundaries, or `ads?\b`, so they
/// are matched by hand (case folding is ASCII-only, `\b` is ASCII:
/// `[A-Za-z0-9_]` are the word characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasTerm {
    /// The text anywhere (`netflix`).
    Text(&'static str),
    /// `\bword\b`.
    Word(&'static str),
    /// `stem s?\b`: the stem anywhere, an optional `s`, then a word
    /// boundary (`ads?\b`).
    StemPlural(&'static str),
}

/// `[A-Za-z0-9_]`: a word character for a non-unicode `\b`.
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

impl AliasTerm {
    /// Whether the term matches somewhere in `name` (ASCII case ignored).
    pub fn matches(self, name: &str) -> bool {
        let b = name.as_bytes();
        let (word, lead) = match self {
            Self::Text(t) => return find_ignore_ascii_case(name, t, 0).is_some(),
            Self::Word(w) => (w, true),
            Self::StemPlural(w) => (w, false),
        };
        // Every word here starts and ends with a word character, so a
        // boundary at an edge only needs the other side to be a non-word.
        let edge = |p: usize| b.get(p).is_none_or(|c| !is_word_byte(*c));
        let mut from = 0;
        while let Some(i) = find_ignore_ascii_case(name, word, from) {
            let end = i + word.len();
            let before = !lead || i == 0 || !is_word_byte(b[i - 1]);
            let after = edge(end)
                || (matches!(self, Self::StemPlural(_))
                    && b.get(end).is_some_and(|c| c.eq_ignore_ascii_case(&b's'))
                    && edge(end + 1));
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
    /// The alias pattern as Dart writes it (case-insensitive regular
    /// expression), for reference; [`Policy::alias_terms`] is what matches.
    pub aliases: Option<&'static str>,
    /// [`Policy::aliases`] as hand-written alternatives.
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

    /// `aliasPattern?.hasMatch(name) ?? false`: a provider group named
    /// `name` means the same as this policy. False without aliases.
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

use AliasTerm::{StemPlural, Text, Word};

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
            Text("AdBlock"),
            StemPlural("ad"),
            Text("劫持"),
            Text("hijack"),
        ],
        ..Policy::new("ads", "广告拦截", "⛔️", outbound_tags::BLOCK)
    },
    // Before Google: geosite-google includes YouTube.
    Policy {
        rule_sets: &["geosite-youtube"],
        prefer_pick: Some(outbound_tags::FASTEST),
        block_quic: true,
        aliases: Some("youtube|油管"),
        alias_terms: &[Text("youtube"), Text("油管")],
        ..Policy::new("youtube", "YouTube", "📹", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-google-gemini", "geosite-google"],
        avoid_regions: &AVOID_CN_HK_MO_RU,
        aliases: Some("google|谷歌|gemini"),
        alias_terms: &[Text("google"), Text("谷歌"), Text("gemini")],
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
            Text("openai"),
            Text("chatgpt"),
            Text("claude"),
            Text("anthropic"),
            Word("ai"),
            Text("人工智能"),
            Text("copilot"),
            Text("grok"),
            Text("perplexity"),
        ],
        ..Policy::new("ai", "AI 服务", "🤖", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-telegram"],
        ip_cidrs: &TELEGRAM_IPS,
        aliases: Some(r"telegram|电报|\btg\b"),
        alias_terms: &[Text("telegram"), Text("电报"), Word("tg")],
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
            Text("twitter"),
            Text("推特"),
            Text("facebook"),
            Text("脸书"),
            Text("instagram"),
            Text("discord"),
            Text("社交"),
        ],
        ..Policy::new("social", "社交媒体", "💬", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-netflix"],
        aliases: Some("netflix|奈飞|网飞"),
        alias_terms: &[Text("netflix"), Text("奈飞"), Text("网飞")],
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
            Text("steam"),
            Text("游戏"),
            Text("game"),
            Text("epic"),
            Text("playstation"),
            Text("xbox"),
            Text("nintendo"),
            Text("switch"),
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
            Text("bilibili"),
            Text("爱奇艺"),
            Text("iqiyi"),
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
            Text("spotify"),
            Text("disney"),
            Text("hbo"),
            Text("tiktok"),
            Text("global media"),
            Text("globalmedia"),
            Text("streaming"),
        ],
        ..Policy::new("media", "国外媒体", "📺", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-github", "geosite-huggingface"],
        aliases: Some("github|开发"),
        alias_terms: &[Text("github"), Text("开发")],
        ..Policy::new("dev", "开发者服务", "💻", outbound_tags::PROXY)
    },
    Policy {
        rule_sets: &["geosite-microsoft", "geosite-onedrive", "geosite-bing"],
        aliases: Some("microsoft|微软|onedrive|bing|azure"),
        alias_terms: &[
            Text("microsoft"),
            Text("微软"),
            Text("onedrive"),
            Text("bing"),
            Text("azure"),
        ],
        ..Policy::new("microsoft", "微软服务", "Ⓜ️", outbound_tags::DIRECT)
    },
    Policy {
        rule_sets: &["geosite-apple"],
        aliases: Some("apple|苹果|icloud"),
        alias_terms: &[Text("apple"), Text("苹果"), Text("icloud")],
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

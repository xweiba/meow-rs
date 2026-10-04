//! Domains one company serves a signed-in session from: they must share an
//! exit, or the service sees one account hop between addresses
//! (re-verification, captchas, bans). Keys are registrable domains.

use std::collections::HashMap;
use std::sync::OnceLock;

const FAMILIES: &[(&str, &[&str])] = &[
    (
        "google",
        &[
            "google.com",
            "google.com.hk",
            "google.co.jp",
            "youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
            "ggpht.com",
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
            "gmail.com",
            "withgoogle.com",
            "gvt1.com",
            "gvt2.com",
            "blogger.com",
            "android.com",
            "googlesyndication.com",
        ],
    ),
    (
        "openai",
        &[
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "sora.com",
        ],
    ),
    (
        "anthropic",
        &[
            "anthropic.com",
            "claude.ai",
            "claude.com",
            "claudeusercontent.com",
        ],
    ),
    (
        "microsoft",
        &[
            "microsoft.com",
            "live.com",
            "microsoftonline.com",
            "office.com",
            "office.net",
            "bing.com",
            "msn.com",
            "outlook.com",
            "xbox.com",
            "skype.com",
            "copilot.microsoft.com",
            "msftauth.net",
            "msauth.net",
        ],
    ),
    (
        "github",
        &[
            "github.com",
            "githubusercontent.com",
            "githubassets.com",
            "github.io",
        ],
    ),
    (
        "meta",
        &[
            "facebook.com",
            "fbcdn.net",
            "instagram.com",
            "cdninstagram.com",
            "whatsapp.com",
            "whatsapp.net",
            "threads.net",
            "messenger.com",
        ],
    ),
    ("x", &["x.com", "twitter.com", "twimg.com", "t.co"]),
    (
        "netflix",
        &[
            "netflix.com",
            "nflxvideo.net",
            "nflximg.net",
            "nflxext.com",
            "nflxso.net",
        ],
    ),
    (
        "apple",
        &[
            "apple.com",
            "icloud.com",
            "mzstatic.com",
            "apple-cloudkit.com",
            "cdn-apple.com",
            "apple.news",
        ],
    ),
    (
        "amazon",
        &[
            "amazon.com",
            "primevideo.com",
            "media-amazon.com",
            "amazon.co.jp",
        ],
    ),
    (
        "telegram",
        &["telegram.org", "t.me", "telegram.me", "telesco.pe"],
    ),
    (
        "discord",
        &[
            "discord.com",
            "discord.gg",
            "discordapp.com",
            "discordapp.net",
        ],
    ),
    (
        "tiktok",
        &[
            "tiktok.com",
            "tiktokcdn.com",
            "tiktokv.com",
            "byteoversea.com",
            "ibytedtos.com",
        ],
    ),
    ("paypal", &["paypal.com", "paypalobjects.com"]),
    (
        "steam",
        &["steampowered.com", "steamcommunity.com", "steamstatic.com"],
    ),
    ("spotify", &["spotify.com", "scdn.co", "spotifycdn.com"]),
    (
        "disney",
        &[
            "disneyplus.com",
            "disney-plus.net",
            "bamgrid.com",
            "dssott.com",
        ],
    ),
];

fn table() -> &'static HashMap<&'static str, String> {
    static TABLE: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut out = HashMap::new();
        for (name, domains) in FAMILIES {
            for d in *domains {
                out.insert(*d, format!("family:{name}"));
            }
        }
        out
    })
}

/// The unit one exit is kept for: the company for well-known services,
/// otherwise the site itself.
pub fn family_key(site: &str) -> String {
    if let Some(f) = table().get(site) {
        return f.clone();
    }
    // copilot.microsoft.com-style entries name a host under a registrable
    // domain.
    if let Some((_, rest)) = site.split_once('.') {
        if let Some(f) = table().get(rest) {
            return f.clone();
        }
    }
    site.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_share_a_key() {
        assert_eq!(family_key("youtube.com"), family_key("google.com"));
        assert_eq!(family_key("chatgpt.com"), "family:openai");
        assert_eq!(family_key("example.com"), "example.com");
    }
}

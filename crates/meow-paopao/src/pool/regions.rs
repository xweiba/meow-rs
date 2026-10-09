//! Where a line exits, read from its name (Dart: `regions.dart`).
//!
//! Dart matches names with regular expressions; they are hand-written here
//! because their exact semantics matter: case folding is ASCII-only (a
//! non-unicode Dart regex never folds `ſ` to `s`), and "letters" around an
//! English word are `[A-Za-z]` only.

use std::borrow::Cow;

use crate::dart::{contains_ignore_ascii_case, find_ignore_ascii_case};
use crate::model::node::ProxyNode;

/// A place lines exit to, as people know it.
#[derive(Debug, Clone)]
pub struct Region {
    /// ISO 3166 alpha-2 code ("HK"); also the group tag suffix (`region:HK`).
    pub code: Cow<'static, str>,
    /// Chinese name ("香港"); the code itself for places made up from a code.
    pub name: Cow<'static, str>,
    /// Flag emoji ("🇭🇰").
    pub flag: Cow<'static, str>,
    /// Names, cities and codes seen in provider node names; empty for places
    /// made up from a code.
    pub words: &'static [&'static str],
}

impl Region {
    const fn known(
        code: &'static str,
        name: &'static str,
        flag: &'static str,
        words: &'static [&'static str],
    ) -> Self {
        Self {
            code: Cow::Borrowed(code),
            name: Cow::Borrowed(name),
            flag: Cow::Borrowed(flag),
            words,
        }
    }

    /// The group tag, `region:<code>`.
    pub fn tag(&self) -> String {
        format!("region:{}", self.code)
    }

    /// What the user sees, `<flag> <name>`.
    pub fn label(&self) -> String {
        format!("{} {}", self.flag, self.name)
    }
}

/// Regions are the same place when their codes are.
impl PartialEq for Region {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Eq for Region {}

/// The known places, in the order groups are shown (and names are matched:
/// the first region with a word in the name wins).
pub static REGIONS: [Region; 24] = [
    Region::known(
        "HK",
        "香港",
        "🇭🇰",
        &["香港", "HK", "Hong Kong", "HongKong", "港"],
    ),
    Region::known(
        "TW",
        "台湾",
        "🇹🇼",
        &["台湾", "台灣", "TW", "Taiwan", "台北", "新北"],
    ),
    Region::known(
        "JP",
        "日本",
        "🇯🇵",
        &[
            "日本", "JP", "Japan", "东京", "東京", "Tokyo", "大阪", "Osaka",
        ],
    ),
    Region::known("SG", "新加坡", "🇸🇬", &["新加坡", "SG", "Singapore", "狮城"]),
    Region::known(
        "US",
        "美国",
        "🇺🇸",
        &[
            "美国",
            "美國",
            "US",
            "USA",
            "United States",
            "America",
            "洛杉矶",
            "Los Angeles",
            "圣何塞",
            "San Jose",
            "California",
            "硅谷",
            "纽约",
            "New York",
            "西雅图",
            "Seattle",
            "芝加哥",
            "Chicago",
            "达拉斯",
            "Dallas",
            "凤凰城",
            "Phoenix",
        ],
    ),
    Region::known(
        "KR",
        "韩国",
        "🇰🇷",
        &["韩国", "韓國", "KR", "Korea", "首尔", "Seoul", "春川"],
    ),
    Region::known(
        "GB",
        "英国",
        "🇬🇧",
        &[
            "英国",
            "UK",
            "GB",
            "United Kingdom",
            "Britain",
            "伦敦",
            "London",
        ],
    ),
    Region::known(
        "DE",
        "德国",
        "🇩🇪",
        &["德国", "DE", "Germany", "法兰克福", "Frankfurt"],
    ),
    Region::known(
        "FR",
        "法国",
        "🇫🇷",
        &["法国", "FR", "France", "巴黎", "Paris"],
    ),
    Region::known(
        "NL",
        "荷兰",
        "🇳🇱",
        &["荷兰", "NL", "Netherlands", "阿姆斯特丹", "Amsterdam"],
    ),
    Region::known(
        "CA",
        "加拿大",
        "🇨🇦",
        &[
            "加拿大",
            "CA",
            "Canada",
            "多伦多",
            "Toronto",
            "温哥华",
            "Vancouver",
        ],
    ),
    Region::known(
        "AU",
        "澳大利亚",
        "🇦🇺",
        &["澳大利亚", "澳洲", "AU", "Australia", "悉尼", "Sydney"],
    ),
    Region::known(
        "IN",
        "印度",
        "🇮🇳",
        &["印度", "IN", "India", "孟买", "Mumbai"],
    ),
    Region::known(
        "MY",
        "马来西亚",
        "🇲🇾",
        &["马来西亚", "馬來西亞", "MY", "Malaysia", "吉隆坡"],
    ),
    Region::known("TH", "泰国", "🇹🇭", &["泰国", "TH", "Thailand", "曼谷"]),
    Region::known("VN", "越南", "🇻🇳", &["越南", "VN", "Vietnam"]),
    Region::known("PH", "菲律宾", "🇵🇭", &["菲律宾", "PH", "Philippines"]),
    Region::known(
        "ID",
        "印尼",
        "🇮🇩",
        &["印尼", "印度尼西亚", "Indonesia", "雅加达"],
    ),
    Region::known(
        "TR",
        "土耳其",
        "🇹🇷",
        &["土耳其", "TR", "Turkey", "Türkiye", "伊斯坦布尔"],
    ),
    Region::known("RU", "俄罗斯", "🇷🇺", &["俄罗斯", "RU", "Russia", "莫斯科"]),
    Region::known(
        "AE",
        "阿联酋",
        "🇦🇪",
        &["阿联酋", "UAE", "AE", "迪拜", "Dubai"],
    ),
    Region::known("IT", "意大利", "🇮🇹", &["意大利", "IT", "Italy", "米兰"]),
    Region::known("BR", "巴西", "🇧🇷", &["巴西", "BR", "Brazil"]),
    Region::known("AR", "阿根廷", "🇦🇷", &["阿根廷", "AR", "Argentina"]),
];

/// Text in names that marks an info entry, not a server ("剩余流量：…",
/// "套餐到期：…", "官网：…"); matched ignoring ASCII case.
const INFO_WORDS: [&str; 19] = [
    "剩余",
    "剩餘",
    "余量",
    "套餐",
    "到期",
    "过期",
    "過期",
    "订阅",
    "訂閱",
    "官网",
    "官網",
    "网址",
    "網址",
    "expire",
    "traffic",
    "官方",
    "客服",
    "telegram群",
    "频道",
];

/// Text marking a server the provider says is down; matched ignoring ASCII
/// case.
const FLAGGED_WORDS: [&str; 8] = [
    "故障",
    "维护",
    "維護",
    "恢复",
    "恢復",
    "停用",
    "失效",
    "maintenance",
];

/// Words inside brackets that make the bracket a transit note
/// ("越南A01 (香港中转)"); matched ignoring ASCII case.
const TRANSIT_WORDS: [&str; 7] = ["中转", "中轉", "转发", "專線", "专线", "relay", "transit"];

/// A real server, not an info row ("剩余流量：98.5 GB"); auto groups and the
/// pool take only these.
pub fn is_usable_node(n: &ProxyNode) -> bool {
    !INFO_WORDS
        .iter()
        .any(|w| contains_ignore_ascii_case(&n.name, w))
}

/// The provider marked this line as down (it may be back already: such
/// lines stay in the auto groups).
pub fn is_flagged_node(n: &ProxyNode) -> bool {
    FLAGGED_WORDS
        .iter()
        .any(|w| contains_ignore_ascii_case(&n.name, w))
}

/// The region a node exits in, from its name; None when the name says no
/// place.
///
/// A bracketed transit note doesn't count: "越南A01 (香港中转)" exits in
/// Vietnam. Chinese words match anywhere; English words must stand alone
/// ("HK 07" yes, "SHKO" no).
///
/// Dart parity: two-letter codes match in any case ("hk 01") while longer
/// English words are case-sensitive ("Tokyo" yes, "TOKYO" no) — the
/// reverse of what the Dart comment intends (`caseSensitive: w.length > 2`).
pub fn region_of(name: &str) -> Option<&'static Region> {
    let text = strip_transit(name);
    REGIONS
        .iter()
        .find(|r| r.words.iter().any(|w| word_hit(&text, w)))
}

/// Whether `w` occurs in `text` the way [`region_of`] counts it.
fn word_hit(text: &str, w: &str) -> bool {
    let ascii = !w.is_empty() && w.bytes().all(|b| b.is_ascii_alphabetic() || b == b' ');
    if !ascii {
        return text.contains(w);
    }
    // `(?<![A-Za-z])word(?![A-Za-z])`, case-sensitive when longer than 2.
    let case_sensitive = w.len() > 2;
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(i) = if case_sensitive {
        text.get(from..).and_then(|t| t.find(w)).map(|j| from + j)
    } else {
        find_ignore_ascii_case(text, w, from)
    } {
        let end = i + w.len();
        let before_ok = i == 0 || !bytes[i - 1].is_ascii_alphabetic();
        let after_ok = bytes.get(end).is_none_or(|b| !b.is_ascii_alphabetic());
        if before_ok && after_ok {
            return true;
        }
        from = i + 1;
    }
    false
}

/// `name.replaceAll(_transit, ' ')` with
/// `[（(][^）)]*(中转|中轉|转发|專線|专线|relay|transit)[^）)]*[）)]`
/// (case-insensitive): each opening bracket whose text up to the next
/// closing bracket holds a transit word is replaced, closing bracket
/// included, by one space.
fn strip_transit(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut rest = name;
    while let Some(open) = rest.find(['（', '(']) {
        let open_len = rest[open..].chars().next().map_or(1, char::len_utf8);
        let inner_start = open + open_len;
        let hit = rest[inner_start..].find(['）', ')']).and_then(|close| {
            let inner = &rest[inner_start..inner_start + close];
            let close_len = rest[inner_start + close..]
                .chars()
                .next()
                .map_or(1, char::len_utf8);
            TRANSIT_WORDS
                .iter()
                .any(|w| contains_ignore_ascii_case(inner, w))
                .then_some(inner_start + close + close_len)
        });
        match hit {
            Some(end) => {
                out.push_str(&rest[..open]);
                out.push(' ');
                rest = &rest[end..];
            }
            None => {
                out.push_str(&rest[..inner_start]);
                rest = &rest[inner_start..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A country by ISO code: a known region, or one made up on the spot (flag
/// from the code, name = code) for places providers rarely use. None unless
/// `code` is exactly two ASCII capitals.
pub fn region_for_code(code: Option<&str>) -> Option<Region> {
    let code = code?;
    if code.len() != 2 || !code.bytes().all(|b| b.is_ascii_uppercase()) {
        return None;
    }
    if let Some(r) = REGIONS.iter().find(|r| r.code == code) {
        return Some(r.clone());
    }
    // Regional indicator symbols: 🇦 = U+1F1E6 for 'A'.
    let flag: String = code
        .bytes()
        .filter_map(|c| char::from_u32(0x1F1E6 + u32::from(c - b'A')))
        .collect();
    Some(Region {
        code: Cow::Owned(code.to_owned()),
        name: Cow::Owned(code.to_owned()),
        flag: Cow::Owned(flag),
        words: &[],
    })
}

/// Where a node exits: its name first (the provider knows where its
/// machine is), else the measured exit country `exit` (ISO code).
pub fn region_of_node(n: &ProxyNode, exit: Option<&str>) -> Option<Region> {
    region_of(&n.name)
        .cloned()
        .or_else(|| region_for_code(exit))
}

/// Position of `r` in the usual group order: known regions by [`REGIONS`],
/// every other place after them.
pub(crate) fn rank(r: &Region) -> usize {
    REGIONS
        .iter()
        .position(|k| k.code == r.code)
        .unwrap_or(REGIONS.len())
}

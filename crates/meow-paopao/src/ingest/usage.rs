//! Traffic and expiry from a provider's info rows, for subscriptions without
//! a `subscription-userinfo` header (Dart: `usageFromNames` in `pool.dart`).
//!
//! Dart matches two case-insensitive regular expressions:
//!
//! ```text
//! (?:剩余|剩餘|余量|Remaining|Traffic)[^0-9]{0,12}([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?)i?B?
//! (?:到期|过期|過期|Expire)[^0-9]{0,12}(\d{4})[-/.年](\d{1,2})[-/.月](\d{1,2})
//! ```
//!
//! They are matched by hand here: the gap `[^0-9]{0,12}` counts UTF-16 code
//! units (an emoji takes two) and the case folding is ASCII-only, as in
//! Dart, and the gap can only be the whole run of non-digits after the
//! keyword, which makes the search a scan.

use crate::dart::is_regex_space;
use crate::model::usage::Usage;

const AMOUNT_KEYWORDS: [&str; 5] = ["剩余", "剩餘", "余量", "Remaining", "Traffic"];
const DATE_KEYWORDS: [&str; 4] = ["到期", "过期", "過期", "Expire"];

/// What a provider says about the account in node names ("剩余流量：98.5 GB",
/// "套餐到期：2026-11-06"). Remaining traffic becomes `total` (a bare number
/// is GB); a date expires at 23:59 UTC that day. None when the names say
/// nothing. The first name saying each wins.
pub fn usage_from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<Usage> {
    let mut left: Option<i64> = None;
    let mut expire: Option<i64> = None;
    for name in names {
        if left.is_none() {
            left = find(name, &AMOUNT_KEYWORDS, amount);
        }
        if expire.is_none() {
            expire = find(name, &DATE_KEYWORDS, date);
        }
    }
    if left.is_none() && expire.is_none() {
        return None;
    }
    Some(Usage {
        total: left.unwrap_or(0),
        expire,
        ..Usage::default()
    })
}

/// The leftmost keyword followed by a non-digit gap of at most 12 UTF-16
/// units and text `tail` accepts.
fn find(name: &str, keywords: &[&str], tail: fn(&str) -> Option<i64>) -> Option<i64> {
    name.char_indices().find_map(|(i, _)| {
        let rest = &name[i..];
        let kw = keywords
            .iter()
            .find(|k| starts_with_ignore_ascii_case(rest, k))?;
        let after = &rest[kw.len()..];
        let digit = after.find(|c: char| c.is_ascii_digit())?;
        if after[..digit].encode_utf16().count() > 12 {
            return None;
        }
        tail(&after[digit..])
    })
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len()
        && s.is_char_boundary(prefix.len())
        && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn leading_digits(s: &str) -> &str {
    &s[..s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len())]
}

/// `([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?)` → bytes (no unit = GB).
fn amount(s: &str) -> Option<i64> {
    let int = leading_digits(s);
    let mut number_len = int.len();
    if let Some(frac) = s[number_len..].strip_prefix('.') {
        let f = leading_digits(frac);
        if !f.is_empty() {
            number_len += 1 + f.len();
        }
    }
    let number: f64 = s[..number_len].parse().ok()?;
    let unit = s[number_len..]
        .trim_start_matches(is_regex_space)
        .chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .and_then(|c| "KMGTP".find(c))
        .map_or(3, |i| i + 1);
    let bytes = number * 1024f64.powi(i32::try_from(unit).ok()?);
    // Dart's `round()`: half away from zero, clamped to the int range.
    #[allow(clippy::cast_possible_truncation)]
    Some(bytes.round() as i64)
}

/// `(\d{4})[-/.年](\d{1,2})[-/.月](\d{1,2})` → that day 23:59 UTC, in Unix
/// milliseconds (`DateTime.utc` rolls over out-of-range months and days).
fn date(s: &str) -> Option<i64> {
    let year = s
        .get(..4)
        .filter(|y| y.bytes().all(|b| b.is_ascii_digit()))?;
    let rest = s[4..].strip_prefix(['-', '/', '.', '年'])?;
    // Month: two digits if a separator follows them, else one.
    let digits = leading_digits(rest);
    let (month, rest) = [2, 1].iter().find_map(|&n| {
        let m = digits.get(..n)?;
        let after = rest[n..].strip_prefix(['-', '/', '.', '月'])?;
        Some((m, after))
    })?;
    let day_digits = leading_digits(rest);
    let day = day_digits
        .get(..day_digits.len().min(2))
        .filter(|d| !d.is_empty())?;
    let (y, m, d): (i64, i64, i64) = (year.parse().ok()?, month.parse().ok()?, day.parse().ok()?);
    let months = y * 12 + (m - 1);
    let days = days_from_civil(months.div_euclid(12), months.rem_euclid(12) + 1) + (d - 1);
    Some(days * 86_400_000 + (23 * 60 + 59) * 60_000)
}

/// Days from 1970-01-01 to the first of `month` in `year` (proleptic
/// Gregorian; H. Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_roll_over_like_dart() {
        // DateTime.utc(2027, 13, 0, 23, 59) and (2027, 0, 99, 23, 59) in Dart.
        assert_eq!(date("2027-13-0"), Some(1_830_297_540_000));
        assert_eq!(date("2027-0-99"), Some(1_804_636_740_000));
        assert_eq!(date("2027年1月1日"), date("2027-01-01"));
        assert_eq!(date("2027-123-1"), None);
    }

    #[test]
    fn amounts() {
        let total = |n: &str| usage_from_names([n]).map(|u| u.total);
        assert_eq!(total("剩余流量：98.5 GB"), Some(105_763_569_664));
        assert_eq!(total("Remaining traffic: 1.5t"), Some(1_649_267_441_664));
        assert_eq!(total("TRAFFIC 100"), Some(107_374_182_400));
        assert_eq!(total("剩余 100 KB"), Some(102_400));
        // The gap counts UTF-16 units: six emoji are twelve.
        assert_eq!(total("剩余🚀🚀🚀🚀🚀🚀1 G"), Some(1_073_741_824));
        assert_eq!(total("剩余🚀🚀🚀🚀🚀🚀x1 G"), None);
        assert_eq!(total("no info 100 GB"), None);
    }
}

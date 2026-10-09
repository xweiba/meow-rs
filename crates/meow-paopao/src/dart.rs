//! Dart runtime semantics the port has to reproduce exactly.
//!
//! The Dart parser reads decoded JSON / YAML as untyped values and turns them
//! into strings with `'$v'`, compares them with `==`, trims with
//! `String.trim()` and parses numbers with `int.tryParse`. Each of those has
//! its own rules (`1.0` prints as `1.0`, `int.tryParse` accepts `0x1F`, `trim`
//! strips U+FEFF, ...); this module is the one place that knows them.

use serde_json::{Map, Number, Value};

/// A decoded JSON or YAML value as Dart sees it (`Object?`).
///
/// Maps keep their insertion order; YAML keys may be any value.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Dv {
    Null,
    Bool(bool),
    Int(i64),
    Double(f64),
    Str(String),
    List(Vec<Dv>),
    Map(Vec<(Dv, Dv)>),
}

/// What `m[key]` gives for a missing key.
pub(crate) static NULL: Dv = Dv::Null;

/// Dart threw something other than a `FormatException` (a failed `as` cast,
/// `toInt()` of NaN ...), which none of the parser's `try` blocks catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Crash(pub String);

impl Dv {
    /// `m[key]` with a String key: [`NULL`] when this is not a map or the key
    /// is missing.
    pub(crate) fn get(&self, key: &str) -> &Dv {
        match self {
            Dv::Map(entries) => entries
                .iter()
                .find(|(k, _)| matches!(k, Dv::Str(s) if s == key))
                .map_or(&NULL, |(_, v)| v),
            _ => &NULL,
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Dv::Null)
    }

    /// `a ?? b`.
    pub(crate) fn or<'a>(&'a self, other: &'a Dv) -> &'a Dv {
        if self.is_null() {
            other
        } else {
            self
        }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Dv::Str(s) => Some(s),
            _ => None,
        }
    }

    /// `'$v'`.
    pub(crate) fn dart_string(&self) -> String {
        let mut out = String::new();
        self.write_dart(&mut out);
        out
    }

    /// `'${v ?? ''}'`.
    pub(crate) fn dart_string_or_empty(&self) -> String {
        if self.is_null() {
            String::new()
        } else {
            self.dart_string()
        }
    }

    fn write_dart(&self, out: &mut String) {
        match self {
            Dv::Null => out.push_str("null"),
            Dv::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Dv::Int(i) => out.push_str(&i.to_string()),
            Dv::Double(d) => out.push_str(&double_to_string(*d)),
            Dv::Str(s) => out.push_str(s),
            Dv::List(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    v.write_dart(out);
                }
                out.push(']');
            }
            Dv::Map(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    k.write_dart(out);
                    out.push_str(": ");
                    v.write_dart(out);
                }
                out.push('}');
            }
        }
    }

    /// `v as String?`.
    pub(crate) fn as_str_opt(&self) -> Result<Option<&str>, Crash> {
        match self {
            Dv::Null => Ok(None),
            Dv::Str(s) => Ok(Some(s)),
            other => Err(Crash(format!("{other:?} is not a String?"))),
        }
    }

    /// `(v as num?)?.toInt()`.
    pub(crate) fn as_int_opt(&self) -> Result<Option<i64>, Crash> {
        match self {
            Dv::Null => Ok(None),
            Dv::Int(i) => Ok(Some(*i)),
            Dv::Double(d) => double_to_int(*d).map(Some),
            other => Err(Crash(format!("{other:?} is not a num?"))),
        }
    }

    /// Dart `==` against the int 1 (`1.0 == 1` holds in Dart).
    pub(crate) fn equals_one(&self) -> bool {
        match self {
            Dv::Int(i) => *i == 1,
            #[allow(clippy::float_cmp)]
            Dv::Double(d) => *d == 1.0,
            _ => false,
        }
    }

    /// From `jsonDecode`: integers beyond int64 become doubles, as in Dart.
    pub(crate) fn from_json(v: &Value) -> Dv {
        match v {
            Value::Null => Dv::Null,
            Value::Bool(b) => Dv::Bool(*b),
            Value::Number(n) => match n.as_i64() {
                Some(i) => Dv::Int(i),
                None => Dv::Double(n.as_f64().unwrap_or(f64::NAN)),
            },
            Value::String(s) => Dv::Str(s.clone()),
            Value::Array(a) => Dv::List(a.iter().map(Dv::from_json).collect()),
            Value::Object(o) => Dv::Map(
                o.iter()
                    .map(|(k, v)| (Dv::Str(k.clone()), Dv::from_json(v)))
                    .collect(),
            ),
        }
    }

    /// For `jsonEncode`. Non-string map keys are written as `'$key'` and
    /// NaN / infinity as null (Dart's `jsonEncode` throws on both).
    pub(crate) fn to_json(&self) -> Value {
        match self {
            Dv::Null => Value::Null,
            Dv::Bool(b) => Value::Bool(*b),
            Dv::Int(i) => Value::Number((*i).into()),
            Dv::Double(d) => Number::from_f64(*d).map_or(Value::Null, Value::Number),
            Dv::Str(s) => Value::String(s.clone()),
            Dv::List(items) => Value::Array(items.iter().map(Dv::to_json).collect()),
            Dv::Map(entries) => {
                let mut m = Map::new();
                for (k, v) in entries {
                    m.insert(k.dart_string(), v.to_json());
                }
                Value::Object(m)
            }
        }
    }
}

/// Dart `==` on decoded values, deep for lists and maps (YAML duplicate-key
/// detection uses `deepEquals`).
pub(crate) fn deep_equals(a: &Dv, b: &Dv) -> bool {
    match (a, b) {
        (Dv::Int(x), Dv::Double(y)) | (Dv::Double(y), Dv::Int(x)) => {
            #[allow(clippy::cast_precision_loss, clippy::float_cmp)]
            let same = (*x as f64) == *y;
            same
        }
        (Dv::List(x), Dv::List(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(a, b)| deep_equals(a, b))
        }
        (Dv::Map(x), Dv::Map(y)) => {
            x.len() == y.len()
                && x.iter().all(|(k, v)| {
                    y.iter()
                        .any(|(k2, v2)| deep_equals(k, k2) && deep_equals(v, v2))
                })
        }
        _ => a == b,
    }
}

/// `double.toInt()`: truncates, saturates at the int64 range, throws on
/// NaN / infinity.
pub(crate) fn double_to_int(d: f64) -> Result<i64, Crash> {
    if d.is_finite() {
        #[allow(clippy::cast_possible_truncation)]
        Ok(d.trunc() as i64)
    } else {
        Err(Crash(format!("{d} toInt")))
    }
}

/// `double.toString()`: JavaScript's number formatting, plus `.0` when the
/// result would otherwise read as an int (`1.0`, `1e+21`, `1.5e-7`).
pub(crate) fn double_to_string(d: f64) -> String {
    if d.is_nan() {
        return "NaN".into();
    }
    if d.is_infinite() {
        return if d > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if d == 0.0 {
        return if d.is_sign_negative() { "-0.0" } else { "0.0" }.into();
    }
    // Shortest round-trip digits and exponent: "1.2345e-7".
    let sci = format!("{:e}", d.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = i64::try_from(digits.len()).unwrap_or(i64::MAX);
    let n = exp.parse::<i64>().unwrap_or(0) + 1;
    let mut out = String::new();
    if d < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n(
            '0',
            usize::try_from(n - k).unwrap_or(0),
        ));
    } else if 0 < n && n <= 21 {
        let (a, b) = digits.split_at(usize::try_from(n).unwrap_or(0));
        out.push_str(a);
        out.push('.');
        out.push_str(b);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', usize::try_from(-n).unwrap_or(0)));
        out.push_str(&digits);
    } else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if n >= 1 { '+' } else { '-' });
        out.push_str(&(n - 1).abs().to_string());
    }
    if !out.contains(['.', 'e']) {
        out.push_str(".0");
    }
    out
}

/// Whitespace for Dart's `String.trim()` and `int.parse`: Unicode
/// White_Space plus the BOM.
pub(crate) fn is_dart_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// `String.trim()`.
pub(crate) fn trim(s: &str) -> &str {
    s.trim_matches(is_dart_space)
}

/// `\s` in a Dart (JavaScript-flavoured) regular expression: unlike Rust's
/// `\s` it includes U+FEFF and excludes U+0085.
pub(crate) fn is_regex_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// `int.tryParse(s)`: surrounding whitespace, an optional sign, then decimal
/// digits (null on int64 overflow) or `0x` hex digits (up to 64 bits,
/// wrapping like Dart's VM).
pub(crate) fn int_try_parse(s: &str) -> Option<i64> {
    let s = trim(s);
    let (negative, body) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if let Some(hex) = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let v = u64::from_str_radix(hex, 16).ok()?;
        #[allow(clippy::cast_possible_wrap)]
        let v = v as i64;
        return Some(if negative { v.wrapping_neg() } else { v });
    }
    int_try_parse_radix(s, 10)
}

/// `int.tryParse(s, radix: r)` for r = 8 or 10: no `0x` prefix.
pub(crate) fn int_try_parse_radix(s: &str, radix: u32) -> Option<i64> {
    let s = trim(s);
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    // Parse with the sign attached so i64::MIN fits.
    let signed = if negative {
        format!("-{digits}")
    } else {
        digits.to_owned()
    };
    i64::from_str_radix(&signed, radix).ok()
}

/// `utf8.decode(bytes)`: strict, and like Dart's decoder drops a leading BOM.
pub(crate) fn utf8_decode(bytes: Vec<u8>) -> Option<String> {
    let s = String::from_utf8(bytes).ok()?;
    Some(match s.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_owned(),
        None => s,
    })
}

/// `String.toLowerCase()` on the Dart VM: each character's simple lowercase
/// mapping, so `İ` becomes `i` (not `i̇`) and a final `Σ` becomes `σ` (no
/// final-sigma rule).
pub(crate) fn to_lower_case(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            // U+0130 is the one character whose full lowercase mapping (what
            // `char::to_lowercase` gives) differs from the simple one.
            let simple = if c == '\u{130}' { 'i' } else { c };
            simple.to_lowercase()
        })
        .collect()
}

/// `RegExp(word, caseSensitive: false).hasMatch(text)` for a literal
/// `word`: in a non-unicode Dart regular expression case folding never
/// maps a non-ASCII character to an ASCII one (`ſ` does not match `s`, the
/// Kelvin sign not `k`), so only ASCII letters fold.
///
/// Comparing UTF-8 bytes is exact: a multi-byte character's bytes are all
/// non-ASCII and compare as themselves.
pub(crate) fn contains_ignore_ascii_case(text: &str, word: &str) -> bool {
    find_ignore_ascii_case(text, word, 0).is_some()
}

/// Byte offset of the first `word` in `text` at or after `from`, ASCII
/// letters folded (see [`contains_ignore_ascii_case`]).
pub(crate) fn find_ignore_ascii_case(text: &str, word: &str, from: usize) -> Option<usize> {
    let (t, w) = (text.as_bytes(), word.as_bytes());
    if w.is_empty() {
        return Some(from.min(t.len()));
    }
    (from..=t.len().checked_sub(w.len())?).find(|&i| t[i..i + w.len()].eq_ignore_ascii_case(w))
}

/// What `InternetAddress.tryParse` makes of a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpKind {
    V4,
    V6,
}

/// `InternetAddress.tryParse(s)?.type` (dart:io on the VM): `inet_pton`,
/// i.e. strict dotted-quad IPv4 (no leading zeros, no spaces) or IPv6
/// (with an optional embedded IPv4 tail), no brackets.
///
/// A scope (`fe80::1%…`) is allowed on IPv6 only. Dart resolves a named
/// scope (`%eth0`) against the machine's interfaces, which a pure function
/// cannot see: here only numeric scopes are accepted.
pub(crate) fn internet_address_try_parse(s: &str) -> Option<IpKind> {
    let (addr, scope) = match s.find('%') {
        // Dart only splits at a `%` past the first character.
        Some(i) if i > 0 => (&s[..i], Some(&s[i + 1..])),
        _ => (s, None),
    };
    let kind = if addr.parse::<std::net::Ipv4Addr>().is_ok() {
        IpKind::V4
    } else if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        IpKind::V6
    } else {
        return None;
    };
    match scope {
        None => Some(kind),
        Some(id)
            if kind == IpKind::V6 && !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(kind)
        }
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_print_like_dart() {
        // Expected values printed by the Dart VM (3.47).
        for (d, s) in [
            (1.0, "1.0"),
            (100.0, "100.0"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000.0"),
            (1.5e-7, "1.5e-7"),
            (0.000_001, "0.000001"),
            (1e-7, "1e-7"),
            (-0.0, "-0.0"),
            (1.0 / 3.0, "0.3333333333333333"),
            (1e300, "1e+300"),
            (12345.678, "12345.678"),
            (5e-324, "5e-324"),
            (0.1 + 0.2, "0.30000000000000004"),
            (-2.5, "-2.5"),
        ] {
            assert_eq!(double_to_string(d), s, "{d}");
        }
        assert_eq!(double_to_string(f64::INFINITY), "Infinity");
        assert_eq!(double_to_string(f64::NAN), "NaN");
    }

    #[test]
    fn int_try_parse_like_dart() {
        for (s, v) in [
            (" 443", Some(443)),
            ("+443", Some(443)),
            ("-5", Some(-5)),
            ("0x1F", Some(31)),
            ("-0x1f", Some(-31)),
            ("0X10", Some(16)),
            ("1_000", None),
            ("９", None),
            ("9223372036854775807", Some(i64::MAX)),
            ("9223372036854775808", None),
            ("0xFFFFFFFFFFFFFFFF", Some(-1)),
            ("0x10000000000000000", None),
            ("", None),
            (" ", None),
            ("\u{feff}5", Some(5)),
            ("\u{85}5", Some(5)),
        ] {
            assert_eq!(int_try_parse(s), v, "{s:?}");
        }
    }

    #[test]
    fn collections_print_like_dart() {
        let v = Dv::Map(vec![
            (
                Dv::Str("a".into()),
                Dv::List(vec![
                    Dv::Int(1),
                    Dv::Double(2.0),
                    Dv::Null,
                    Dv::Bool(true),
                    Dv::Str("x".into()),
                ]),
            ),
            (Dv::Str("b".into()), Dv::Map(vec![])),
        ]);
        assert_eq!(v.dart_string(), "{a: [1, 2.0, null, true, x], b: {}}");
    }
}

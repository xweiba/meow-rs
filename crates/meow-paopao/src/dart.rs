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

/// `jsonEncode(v)`: compact, `/` and non-ASCII as they are, control
/// characters escaped, doubles printed as Dart prints them (`1.0`,
/// `1e+21`, which serde_json would write as `1` / `1e21`).
pub(crate) fn json_encode(v: &Dv) -> String {
    let mut out = String::new();
    write_json(v, &mut out);
    out
}

fn write_json(v: &Dv, out: &mut String) {
    match v {
        Dv::Null => out.push_str("null"),
        Dv::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Dv::Int(i) => out.push_str(&i.to_string()),
        // jsonEncode throws on NaN / infinity; JSON input never has them.
        Dv::Double(d) if !d.is_finite() => out.push_str("null"),
        Dv::Double(d) => out.push_str(&double_to_string(*d)),
        Dv::Str(s) => write_json_string(s, out),
        Dv::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Dv::Map(entries) => {
            out.push('{');
            for (i, (k, item)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(&k.dart_string(), out);
                out.push(':');
                write_json(item, out);
            }
            out.push('}');
        }
    }
}

/// Dart's JSON string escaping: `"` and `\`, `\b \t \n \f \r`, other
/// control characters as lowercase `\u00xx`.
fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let b = c as u32;
                out.push_str("\\u00");
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 0xf) as usize]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `Uri.tryParse(s)?.pathSegments.lastOrNull`: None when `s` is no URI by
/// Dart's parser or its path has no segments.
///
/// What Dart's `Uri.parse` does to the path is reproduced: `\` reads as
/// `/` (in the authority too), escapes of unreserved characters are decoded before dot segments
/// (`.`, `..`, also `%2E`) are removed — fully for a URI with a scheme, an
/// authority or an absolute path, else as a relative path keeps leading
/// `..` — and an authority (`file:` too) makes the path absolute.
/// Segments are percent-decoded.
///
/// Divergence: a segment whose escapes are not UTF-8 (`%FF`) makes Dart's
/// `pathSegments` throw; here it is decoded lossily.
pub(crate) fn uri_last_path_segment(s: &str) -> Option<String> {
    let mut segments = uri_path_segments(s)?;
    segments.pop()
}

/// `Uri.tryParse(s)?.pathSegments` (see [`uri_last_path_segment`]).
pub(crate) fn uri_path_segments(s: &str) -> Option<Vec<String>> {
    // Dart's scanner reads `\` as `/` everywhere (`\\h\a` has authority h).
    let s = s.replace('\\', "/");
    let s = s.as_str();
    // A scheme: everything before the first `:` when it comes before any
    // `/`, `?`, `#`; it must then be a valid one (an empty one too).
    let (scheme, rest) = match s.find([':', '/', '?', '#']) {
        Some(i) if s.as_bytes()[i] == b':' => {
            let scheme = &s[..i];
            if !is_uri_scheme(scheme) {
                return None;
            }
            (Some(scheme), &s[i + 1..])
        }
        _ => (None, s),
    };
    let hier = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
    let (has_authority, raw_path) = match hier.strip_prefix("//") {
        Some(a) => {
            let end = a.find('/').unwrap_or(a.len());
            if !is_uri_authority(&a[..end]) {
                return None;
            }
            (true, &a[end..])
        }
        None => (false, hier),
    };
    let mut path = decode_unreserved(raw_path);
    let is_file = scheme.is_some_and(|x| x.eq_ignore_ascii_case("file"));
    if path.is_empty() {
        if is_file {
            path.push('/');
        }
    } else if (is_file || has_authority) && !path.starts_with('/') {
        path.insert(0, '/');
    }
    let path = if scheme.is_none() && !has_authority && !path.starts_with('/') {
        normalize_relative_path(&path)
    } else {
        remove_dot_segments(&path)
    };
    let path = path.strip_prefix('/').unwrap_or(&path);
    if path.is_empty() {
        return Some(Vec::new());
    }
    Some(path.split('/').map(percent_decode_lossy).collect())
}

/// A letter, then letters, digits, `+`, `-`, `.`.
fn is_uri_scheme(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
}

/// `[userinfo@]host[:port]` as Dart accepts it: one `@` at most, a port of
/// digits only (empty allowed), brackets only around an IPv6 address (or
/// an `IPvFuture` `v…`, zone ids allowed).
fn is_uri_authority(a: &str) -> bool {
    let host_port = match a.split_once('@') {
        Some((_, hp)) if hp.contains('@') => return false,
        Some((_, hp)) => hp,
        None => a,
    };
    let port_ok = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    if let Some(inner) = host_port.strip_prefix('[') {
        let Some((ip, after)) = inner.split_once(']') else {
            return false;
        };
        let ip_ok = ip.starts_with(['v', 'V'])
            || ip
                .split('%')
                .next()
                .is_some_and(|x| x.parse::<std::net::Ipv6Addr>().is_ok());
        return ip_ok && (after.is_empty() || after.strip_prefix(':').is_some_and(port_ok));
    }
    let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
    !host.contains(['[', ']']) && port_ok(port)
}

/// Decodes `%XX` escapes of unreserved characters (`A-Z a-z 0-9 - . _ ~`),
/// as Dart's URI normalization does; other escapes are left alone.
fn decode_unreserved(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if b[i] == b'%' {
            if let Some(c) = hex_byte(b, i + 1) {
                if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~') {
                    out.push(char::from(c));
                    i += 3;
                    continue;
                }
            }
        }
        // Copy one character (s is valid UTF-8; `%` is one byte).
        let ch = s[i..].chars().next().unwrap_or_default();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The byte `%XX` at `b[i..i + 2]` stands for.
fn hex_byte(b: &[u8], i: usize) -> Option<u8> {
    let hi = char::from(*b.get(i)?).to_digit(16)?;
    let lo = char::from(*b.get(i + 1)?).to_digit(16)?;
    u8::try_from(hi * 16 + lo).ok()
}

/// `Uri.decodeComponent`, lossy where Dart throws (escapes that are not
/// UTF-8). A `%` without two hex digits stays as it is (Dart's parser has
/// escaped it as `%25` by then).
fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let mut bytes = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if let Some(c) = hex_byte(b, i + 1) {
                bytes.push(c);
                i += 3;
                continue;
            }
        }
        bytes.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Dart's `_mayContainDotSegments`.
fn may_contain_dot_segments(path: &str) -> bool {
    path.starts_with('.') || path.contains("/.")
}

/// Dart's `_removeDotSegments` (RFC 3986 5.2.4).
fn remove_dot_segments(path: &str) -> String {
    if !may_contain_dot_segments(path) {
        return path.to_owned();
    }
    let mut output: Vec<&str> = Vec::new();
    let mut append_slash = false;
    for segment in path.split('/') {
        append_slash = false;
        if segment == ".." {
            if output.pop().is_some() && output.is_empty() {
                output.push("");
            }
            append_slash = true;
        } else if segment == "." {
            append_slash = true;
        } else {
            output.push(segment);
        }
    }
    if append_slash {
        output.push("");
    }
    output.join("/")
}

/// Dart's `_normalizeRelativePath`: `.` dropped, `..` cancels the segment
/// before it, leading `..` kept.
fn normalize_relative_path(path: &str) -> String {
    if !may_contain_dot_segments(path) {
        return path.to_owned();
    }
    let mut output: Vec<&str> = Vec::new();
    let mut append_slash = false;
    for segment in path.split('/') {
        append_slash = false;
        if segment == ".." {
            if output.last().is_some_and(|l| *l != "..") {
                output.pop();
                append_slash = true;
            } else {
                output.push("..");
            }
        } else if segment == "." {
            append_slash = true;
        } else {
            output.push(segment);
        }
    }
    if output.is_empty() || (output.len() == 1 && output[0].is_empty()) {
        return "./".into();
    }
    if append_slash || output.last() == Some(&"..") {
        output.push("");
    }
    output.join("/")
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

    #[test]
    fn json_encodes_like_dart() {
        // Expected values printed by `jsonEncode` on the Dart VM (3.47).
        let v = Dv::from_json(&serde_json::json!({
            "n": 1.0, "big": 1e21, "small": 1.5e-7, "i": -3,
            "s": "\u{2028}\"\\/<\u{1}\u{8}\t\n\u{c}\r\u{1f}é",
            "l": [null, true, {}],
        }));
        assert_eq!(
            json_encode(&v),
            "{\"n\":1.0,\"big\":1e+21,\"small\":1.5e-7,\"i\":-3,\
             \"s\":\"\u{2028}\\\"\\\\/<\\u0001\\b\\t\\n\\f\\r\\u001fé\",\
             \"l\":[null,true,{}]}"
        );
    }

    #[test]
    fn uri_path_segments_like_dart() {
        // Expected values from `Uri.tryParse(s)?.pathSegments` on the
        // Dart VM (3.47); more in tests/fixtures/l4_helpers.json.
        let seg = |s: &str| uri_path_segments(s);
        let v = |x: &[&str]| Some(x.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_eq!(
            seg("https://h/a/b.sgmodule?x=/y#/z"),
            v(&["a", "b.sgmodule"])
        );
        assert_eq!(seg("https://h/a/b/"), v(&["a", "b", ""]));
        assert_eq!(seg("https://h"), v(&[]));
        assert_eq!(seg("https://h/a/./b/../c"), v(&["a", "c"]));
        assert_eq!(seg("https://h/a/%2E%2E"), v(&[]));
        assert_eq!(seg("https://h/a%2Fb/%252E"), v(&["a/b", "%2E"]));
        assert_eq!(seg("http://h\\a\\b"), v(&["a", "b"]));
        assert_eq!(seg("a\\b:c"), v(&["a", "b:c"]));
        assert_eq!(seg("https:\\\\h\\a"), v(&["a"]));
        assert_eq!(seg("a/../../b"), v(&["..", "b"]));
        assert_eq!(seg("."), v(&[".", ""]));
        assert_eq!(seg("file:"), v(&[]));
        assert_eq!(seg("https://[::1]:80/x"), v(&["x"]));
        assert_eq!(seg("https://h:/x"), v(&["x"]));
        assert_eq!(seg("https://h:8a/x"), None);
        assert_eq!(seg("https://a@b@c/x"), None);
        assert_eq!(seg("https://[zz]/x"), None);
        assert_eq!(seg("https://x]/y"), None);
        assert_eq!(seg("1http://x/y"), None);
        assert_eq!(seg(":x"), None);
        assert_eq!(
            uri_last_path_segment("https://h/%FF"),
            Some("\u{fffd}".into())
        );
    }
}

//! `{name}` references in a step's address, headers and body.
//!
//! A reference is `{` + a valid variable name + `}`. Anything else in
//! braces (JSON, `{}`, `{1}`) is ordinary text. Substitution is one pass:
//! a value is inserted as data and never scanned again, so a value holding
//! `{other}` (or its own `{name}`) stays that text.
//!
//! What is inserted depends on where:
//!
//! | where | value becomes |
//! |---|---|
//! | address (after the host) | percent-encoded, every byte outside `A-Z a-z 0-9 - . _ ~` |
//! | header value | as is; refused if it holds a control character (CR, LF, NUL…) |
//! | body, `application/json` | JSON string escapes (no quotes added) |
//! | body, `application/x-www-form-urlencoded` | percent-encoded like the address |
//! | body, anything else | as is |
//!
//! A reference in the scheme, host or port of an address is refused: a
//! value must not choose where the request goes.

use std::fmt::Write as _;

pub const NAME_MAX: usize = 40;

/// `^[A-Za-z][A-Za-z0-9_]{0,39}$`
pub fn is_valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= NAME_MAX
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// The reference starting at `text[at..]` (which starts with `{`): its
/// name and the length of `{name}`.
fn reference_at(text: &str, at: usize) -> Option<(&str, usize)> {
    let rest = &text[at + 1..];
    let end = rest.find('}')?;
    let name = &rest[..end];
    is_valid_name(name).then_some((name, end + 2))
}

/// Names referred to in `text`, in order, once each.
pub fn refs(text: &str) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    let mut i = 0;
    while let Some(off) = text[i..].find('{') {
        let at = i + off;
        if let Some((name, len)) = reference_at(text, at) {
            if !out.contains(&name) {
                out.push(name);
            }
            i = at + len;
        } else {
            i = at + 1;
        }
    }
    out
}

/// `text` with every `{from}` turned into `{to}`.
pub fn rename_refs(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(off) = text[i..].find('{') {
        let at = i + off;
        out.push_str(&text[i..at]);
        match reference_at(text, at) {
            Some((name, len)) => {
                out.push('{');
                out.push_str(if name == from { to } else { name });
                out.push('}');
                i = at + len;
            }
            None => {
                out.push('{');
                i = at + 1;
            }
        }
    }
    out.push_str(&text[i..]);
    out
}

/// How a value is written into the text around it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Escape {
    Url,
    Header,
    Json,
    Form,
    Raw,
}

impl Escape {
    /// For a text body of this content type.
    pub fn for_body(content_type: Option<&str>) -> Self {
        let ct = content_type
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if ct == "application/json" || ct.ends_with("+json") {
            Self::Json
        } else if ct == "application/x-www-form-urlencoded" {
            Self::Form
        } else {
            Self::Raw
        }
    }
}

/// What the task knows about a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Value(&'a str),
    /// A variable of the task without a value yet.
    Unfilled,
    /// Not a variable of the task: the braces are ordinary text.
    Undefined,
    /// A variable of the task that may not be used here (a cookie read for
    /// another site).
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VarError {
    /// A variable without a value.
    Unfilled(String),
    /// The value cannot be written here (control characters in a header).
    Unsafe(String),
    /// A reference where none is allowed (the host of an address).
    Misplaced(String),
    /// See [`Lookup::Refused`].
    Refused(String),
}

impl VarError {
    /// One sentence for the user.
    pub fn sentence(&self) -> String {
        match self {
            Self::Unfilled(n) => format!("变量 {n} 还没有值，先在应用里登录一次或填写它。"),
            Self::Unsafe(n) => format!("变量 {n} 的值里有换行等不能放进请求头的字符，没有发送。"),
            Self::Misplaced(n) => format!("变量 {n} 不能用在网址的域名部分。"),
            Self::Refused(n) => {
                format!("变量 {n} 是另一个网站的登录信息，不会发给这个地址。")
            }
        }
    }
}

fn percent_encode_into(out: &mut String, value: &str) {
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
}

fn json_escape_into(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Usable as (part of) a header value: no control character but TAB.
pub fn header_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// `text` with its references replaced, one pass.
pub fn substitute<'a>(
    text: &str,
    escape: Escape,
    lookup: &dyn Fn(&str) -> Lookup<'a>,
) -> Result<String, VarError> {
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(off) = text[i..].find('{') {
        let at = i + off;
        out.push_str(&text[i..at]);
        let Some((name, len)) = reference_at(text, at) else {
            out.push('{');
            i = at + 1;
            continue;
        };
        match lookup(name) {
            Lookup::Undefined => out.push_str(&text[at..at + len]),
            Lookup::Unfilled => return Err(VarError::Unfilled(name.to_string())),
            Lookup::Refused => return Err(VarError::Refused(name.to_string())),
            Lookup::Value(value) => match escape {
                Escape::Url | Escape::Form => percent_encode_into(&mut out, value),
                Escape::Json => json_escape_into(&mut out, value),
                Escape::Raw => out.push_str(value),
                Escape::Header => {
                    if !header_safe(value) {
                        return Err(VarError::Unsafe(name.to_string()));
                    }
                    out.push_str(value);
                }
            },
        }
        i = at + len;
    }
    out.push_str(&text[i..]);
    Ok(out)
}

/// Where the part of an address a value may appear in starts: after
/// `scheme://authority`.
fn authority_end(url: &str) -> usize {
    let after_scheme = url.find("://").map_or(0, |i| i + 3);
    url[after_scheme..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| after_scheme + i)
}

/// An address with its references replaced. Only the part after the host
/// may hold references that resolve to a variable.
pub fn substitute_url<'a>(
    url: &str,
    lookup: &dyn Fn(&str) -> Lookup<'a>,
) -> Result<String, VarError> {
    let split = authority_end(url);
    let (head, tail) = url.split_at(split);
    if let Some(name) = refs(head)
        .into_iter()
        .find(|n| !matches!(lookup(n), Lookup::Undefined))
    {
        return Err(VarError::Misplaced(name.to_string()));
    }
    let mut out = String::with_capacity(url.len());
    out.push_str(head);
    out.push_str(&substitute(tail, Escape::Url, lookup)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Lookup<'a> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map_or(Lookup::Undefined, |(_, v)| Lookup::Value(v))
        }
    }

    #[test]
    fn names() {
        assert!(is_valid_name("cookie"));
        assert!(is_valid_name("a_1"));
        assert!(is_valid_name(&"a".repeat(40)));
        assert!(!is_valid_name(&"a".repeat(41)));
        assert!(!is_valid_name("1a"));
        assert!(!is_valid_name("_a"));
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("a-b"));
        assert!(!is_valid_name("名"));
    }

    #[test]
    fn refs_skip_what_is_not_a_name() {
        assert_eq!(
            refs(r#"{"a":1,"b":"{uid}"} {} {1} {uid} {token} {"#),
            ["uid", "token"]
        );
        assert!(refs("no braces").is_empty());
        assert!(refs("{unclosed").is_empty());
    }

    #[test]
    fn json_text_is_sent_as_is() {
        let lookup = table(&[("uid", "7")]);
        let body = r#"{"a":1,"u":"{uid}","empty":{}}"#;
        assert_eq!(
            substitute(body, Escape::Json, &lookup).unwrap(),
            r#"{"a":1,"u":"7","empty":{}}"#
        );
    }

    #[test]
    fn a_value_is_never_scanned_again() {
        // `a` holds a reference to `b` and to itself: both stay text.
        let lookup = table(&[("a", "{b}{a}"), ("b", "SECRET")]);
        assert_eq!(
            substitute("x={a}", Escape::Raw, &lookup).unwrap(),
            "x={b}{a}"
        );
        assert_eq!(
            substitute("{a}{b}", Escape::Raw, &lookup).unwrap(),
            "{b}{a}SECRET"
        );
    }

    #[test]
    fn undefined_names_stay_text_and_unfilled_ones_refuse() {
        let lookup = |name: &str| match name {
            "known" => Lookup::Unfilled,
            _ => Lookup::Undefined,
        };
        assert_eq!(
            substitute("a {other} b", Escape::Raw, &lookup).unwrap(),
            "a {other} b"
        );
        assert_eq!(
            substitute("a {known} b", Escape::Raw, &lookup),
            Err(VarError::Unfilled("known".into()))
        );
    }

    #[test]
    fn header_values_refuse_control_characters() {
        for bad in ["a\r\nx-evil: 1", "a\nb", "a\rb", "a\0b", "a\x7fb"] {
            let pairs = [("v", bad)];
            let lookup = table(&pairs);
            assert_eq!(
                substitute("Bearer {v}", Escape::Header, &lookup),
                Err(VarError::Unsafe("v".into())),
                "{bad:?}"
            );
        }
        let lookup = table(&[("v", "sid=abc==; uid=7")]);
        assert_eq!(
            substitute("{v}", Escape::Header, &lookup).unwrap(),
            "sid=abc==; uid=7"
        );
    }

    #[test]
    fn address_values_cannot_leave_their_place() {
        let lookup = table(&[("v", "1&admin=1#/../x y"), ("h", "evil.example")]);
        assert_eq!(
            substitute_url("https://a.example/p/{v}?u={v}", &lookup).unwrap(),
            "https://a.example/p/1%26admin%3D1%23%2F..%2Fx%20y?u=1%26admin%3D1%23%2F..%2Fx%20y"
        );
        assert_eq!(
            substitute_url("https://{h}/p", &lookup),
            Err(VarError::Misplaced("h".into()))
        );
        assert_eq!(
            substitute_url("https://a.example:{h}/p", &lookup),
            Err(VarError::Misplaced("h".into()))
        );
        assert_eq!(
            substitute_url("{h}://a.example/p", &lookup),
            Err(VarError::Misplaced("h".into()))
        );
        // No path: everything is authority.
        assert_eq!(
            substitute_url("https://a.example{h}", &lookup),
            Err(VarError::Misplaced("h".into()))
        );
    }

    #[test]
    fn body_escaping_follows_the_content_type() {
        let lookup = table(&[("v", "a\"b\\c\n&d=1")]);
        assert_eq!(
            substitute(
                r#"{"k":"{v}"}"#,
                Escape::for_body(Some("application/json; charset=utf-8")),
                &lookup
            )
            .unwrap(),
            r#"{"k":"a\"b\\c\n&d=1"}"#
        );
        assert_eq!(
            substitute(
                "k={v}",
                Escape::for_body(Some("application/x-www-form-urlencoded")),
                &lookup
            )
            .unwrap(),
            "k=a%22b%5Cc%0A%26d%3D1"
        );
        assert_eq!(
            substitute("k={v}", Escape::for_body(None), &lookup).unwrap(),
            "k=a\"b\\c\n&d=1"
        );
    }

    #[test]
    fn renaming_rewrites_only_that_reference() {
        assert_eq!(
            rename_refs(r#"{"a":"{old}","b":"{older}"} {old}"#, "old", "new"),
            r#"{"a":"{new}","b":"{older}"} {new}"#
        );
    }
}

//! `loadYaml` from Dart's `yaml` package (3.1): the YAML 1.2 core schema
//! with that package's own scalar rules.
//!
//! Plain scalars resolve to null (`''`, `~`, `null`/`Null`/`NULL`), bool
//! (`true`/`True`/`TRUE`, `false`/…), int (`0x1F`, `0o17`, `0123` = 123,
//! `+5`) or float (`1e3`, `.5`, `.inf`, `.nan`); anything else, and every
//! quoted or block scalar, is a string. Duplicate keys, a second document,
//! unknown tags or aliases to an unfinished node are errors.

use std::collections::HashMap;

use yaml_rust2::parser::{Event, Parser, Tag};
use yaml_rust2::scanner::TScalarStyle;

use crate::dart::{deep_equals, int_try_parse, int_try_parse_radix, Dv};

/// The document is not YAML Dart accepts (`YamlException`).
#[derive(Debug)]
pub(crate) struct BadYaml;

enum Frame {
    Seq(Vec<Dv>, usize),
    Map(Vec<(Dv, Dv)>, Option<Dv>, usize),
}

/// Parses one YAML document; null for an empty stream.
#[cfg(test)]
pub(crate) fn load(text: &str) -> Result<Dv, BadYaml> {
    load_keeping_text(text, &[])
}

/// [`load`], except that a plain scalar under one of `keys` (in any
/// mapping) that would be a bool, int or float stays the string as
/// written (`password: 0123` → `"0123"`); null stays null.
pub(crate) fn load_keeping_text(text: &str, keys: &[&str]) -> Result<Dv, BadYaml> {
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<Frame> = Vec::new();
    let mut anchors: HashMap<usize, Dv> = HashMap::new();
    let mut root: Option<Dv> = None;
    let mut documents = 0;
    loop {
        let (event, _) = parser.next_token().map_err(|_| BadYaml)?;
        let value = match event {
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(BadYaml);
                }
                continue;
            }
            Event::Alias(id) => anchors.get(&id).cloned().ok_or(BadYaml)?,
            Event::Scalar(value, style, anchor, tag) => {
                let as_written = style == TScalarStyle::Plain
                    && tag.is_none()
                    && matches!(
                        stack.last(),
                        Some(Frame::Map(_, Some(Dv::Str(k)), _)) if keys.contains(&k.as_str())
                    );
                let raw = as_written.then(|| value.clone());
                let v = match (scalar(value, style, tag.as_ref())?, raw) {
                    (Dv::Bool(_) | Dv::Int(_) | Dv::Double(_), Some(raw)) => Dv::Str(raw),
                    (v, _) => v,
                };
                if anchor > 0 {
                    anchors.insert(anchor, v.clone());
                }
                v
            }
            Event::SequenceStart(anchor, tag) => {
                check_collection_tag(tag.as_ref(), "seq")?;
                stack.push(Frame::Seq(Vec::new(), anchor));
                continue;
            }
            Event::MappingStart(anchor, tag) => {
                check_collection_tag(tag.as_ref(), "map")?;
                stack.push(Frame::Map(Vec::new(), None, anchor));
                continue;
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let (v, anchor) = match stack.pop() {
                    Some(Frame::Seq(items, a)) => (Dv::List(items), a),
                    Some(Frame::Map(entries, _, a)) => (Dv::Map(entries), a),
                    None => return Err(BadYaml),
                };
                if anchor > 0 {
                    anchors.insert(anchor, v.clone());
                }
                v
            }
            _ => continue,
        };
        match stack.last_mut() {
            None => root = Some(value),
            Some(Frame::Seq(items, _)) => items.push(value),
            Some(Frame::Map(entries, key, _)) => match key.take() {
                None => *key = Some(value),
                Some(k) => {
                    if entries.iter().any(|(k2, _)| deep_equals(k2, &k)) {
                        return Err(BadYaml); // "Duplicate mapping key."
                    }
                    entries.push((k, value));
                }
            },
        }
    }
    Ok(root.unwrap_or(Dv::Null))
}

fn full_tag(tag: &Tag) -> String {
    format!("{}{}", tag.handle, tag.suffix)
}

fn check_collection_tag(tag: Option<&Tag>, kind: &str) -> Result<(), BadYaml> {
    match tag.map(full_tag) {
        None => Ok(()),
        Some(t) if t == "!" || t == format!("tag:yaml.org,2002:{kind}") => Ok(()),
        Some(_) => Err(BadYaml),
    }
}

fn scalar(value: String, style: TScalarStyle, tag: Option<&Tag>) -> Result<Dv, BadYaml> {
    let tag = tag.map(full_tag);
    match tag.as_deref() {
        // Quoted and block scalars carry the non-specific `!` tag in Dart.
        None if style != TScalarStyle::Plain => Ok(Dv::Str(value)),
        None => Ok(plain(&value).unwrap_or(Dv::Str(value))),
        Some("!") | Some("tag:yaml.org,2002:str") => Ok(Dv::Str(value)),
        Some("tag:yaml.org,2002:null") => null(&value).ok_or(BadYaml),
        Some("tag:yaml.org,2002:bool") => boolean(&value).ok_or(BadYaml),
        Some("tag:yaml.org,2002:int") => number(&value, true, false).ok_or(BadYaml),
        Some("tag:yaml.org,2002:float") => number(&value, false, true).ok_or(BadYaml),
        Some(_) => Err(BadYaml), // "Undefined tag"
    }
}

/// `_tryParseScalar`: None means "a string".
fn plain(v: &str) -> Option<Dv> {
    let len = v.chars().count();
    let Some(first) = v.as_bytes().first() else {
        return Some(Dv::Null);
    };
    match first {
        b'.' | b'+' | b'-' | b'0'..=b'9' => number(v, true, true),
        b'n' | b'N' if len == 4 => null(v),
        b't' | b'T' if len == 4 => boolean(v),
        b'f' | b'F' if len == 5 => boolean(v),
        b'~' if len == 1 => Some(Dv::Null),
        _ => None,
    }
}

fn null(v: &str) -> Option<Dv> {
    matches!(v, "" | "null" | "Null" | "NULL" | "~").then_some(Dv::Null)
}

fn boolean(v: &str) -> Option<Dv> {
    match v {
        "true" | "True" | "TRUE" => Some(Dv::Bool(true)),
        "false" | "False" | "FALSE" => Some(Dv::Bool(false)),
        _ => None,
    }
}

/// `_parseNumberValue`.
fn number(v: &str, allow_int: bool, allow_float: bool) -> Option<Dv> {
    let b = v.as_bytes();
    let first = *b.first()?;
    if allow_int && v.chars().count() == 1 {
        return first
            .is_ascii_digit()
            .then(|| Dv::Int(i64::from(first - b'0')));
    }
    let second = *b.get(1)?;
    if allow_int && first == b'0' {
        if second == b'x' {
            return int_try_parse(v).map(Dv::Int);
        }
        if second == b'o' {
            return int_try_parse_radix(&v[2..], 8).map(Dv::Int);
        }
    }
    let sign = matches!(first, b'+' | b'-');
    if first.is_ascii_digit() || (sign && second.is_ascii_digit()) {
        let int = if allow_int {
            int_try_parse_radix(v, 10).map(Dv::Int)
        } else {
            None
        };
        return int.or_else(|| {
            if allow_float {
                double_try_parse(v).map(Dv::Double)
            } else {
                None
            }
        });
    }
    if !allow_float {
        return None;
    }
    if (first == b'.' && second.is_ascii_digit()) || (sign && second == b'.') {
        match v {
            "+.inf" | "+.Inf" | "+.INF" => return Some(Dv::Double(f64::INFINITY)),
            "-.inf" | "-.Inf" | "-.INF" => return Some(Dv::Double(f64::NEG_INFINITY)),
            _ => {}
        }
        return double_try_parse(v).map(Dv::Double);
    }
    match v {
        ".inf" | ".Inf" | ".INF" => Some(Dv::Double(f64::INFINITY)),
        ".nan" | ".NaN" | ".NAN" => Some(Dv::Double(f64::NAN)),
        _ => None,
    }
}

/// `double.tryParse` for the decimal forms reaching it here (it also takes
/// `Infinity` / `NaN`, which never start with a digit, sign-digit or dot).
fn double_try_parse(v: &str) -> Option<f64> {
    let ok = v
        .bytes()
        .all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'));
    if ok {
        v.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_like_dart_yaml() {
        let doc = load(
            "a: 0123\nb: \"0123\"\nc: yes\nd: 0x1F\ne: 0o17\nf: 1e3\ng: .5\nh: ~\ni:\nj: TRUE\nk: +5\nl: 1.2.3\nm: '1'\nn: -.inf\n",
        )
        .unwrap();
        let get = |k: &str| doc.get(k).clone();
        assert_eq!(get("a"), Dv::Int(123));
        assert_eq!(get("b"), Dv::Str("0123".into()));
        assert_eq!(get("c"), Dv::Str("yes".into()));
        assert_eq!(get("d"), Dv::Int(31));
        assert_eq!(get("e"), Dv::Int(15));
        assert_eq!(get("f"), Dv::Double(1000.0));
        assert_eq!(get("g"), Dv::Double(0.5));
        assert_eq!(get("h"), Dv::Null);
        assert_eq!(get("i"), Dv::Null);
        assert_eq!(get("j"), Dv::Bool(true));
        assert_eq!(get("k"), Dv::Int(5));
        assert_eq!(get("l"), Dv::Str("1.2.3".into()));
        assert_eq!(get("m"), Dv::Str("1".into()));
        assert_eq!(get("n"), Dv::Double(f64::NEG_INFINITY));
    }

    #[test]
    fn errors_like_dart_yaml() {
        assert!(load("a: 1\na: 2\n").is_err());
        assert!(load("a: 1\n---\nb: 2\n").is_err());
        assert!(load("a: !foo 1\n").is_err());
        assert_eq!(
            load("x: &a [1]\ny: *a\n").unwrap().get("y"),
            &Dv::List(vec![Dv::Int(1)])
        );
    }
}

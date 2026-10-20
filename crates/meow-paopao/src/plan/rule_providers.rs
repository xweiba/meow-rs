//! Provider names belong to subscriptions; cache files belong to the local
//! core. Never reuse a downloaded config's HTTP cache path on this machine.

use base64::Engine;
use serde_json::{Map, Value};

/// Collision-free names, independent of priority and safe in Clash rule lines.
pub(crate) fn provider_tag(subscription: &str, name: &str) -> String {
    let encode = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
    format!("sub-provider:{}:{}", encode(subscription), encode(name))
}

/// Visit RULE-SET operands, including those inside AND/OR/NOT conditions.
/// Replacing only the operand retains original flags and parenthesis layout.
pub(crate) fn rewrite_references(line: &str, mut map: impl FnMut(&str) -> String) -> String {
    let mut result = String::new();
    let mut copied = 0;
    for (start, _) in line.char_indices() {
        if start < copied
            || !line[start..]
                .get(..8)
                .is_some_and(|s| s.eq_ignore_ascii_case("RULE-SET"))
        {
            continue;
        }
        let before = line[..start].trim_end();
        if !before.is_empty() && !before.ends_with('(') {
            continue;
        }
        let rest = &line[start + 8..];
        let Some(rest) = rest.trim_start().strip_prefix(',') else {
            continue;
        };
        let operand = rest.split([',', ')']).next().unwrap_or_default();
        let name = operand.trim();
        let offset = line.len() - rest.len();
        result.push_str(&line[copied..offset]);
        result.push_str(&map(name));
        copied = offset + operand.len();
    }
    result.push_str(&line[copied..]);
    result
}

/// Validate and emit only definitions used by the final rule list. This runs
/// after mode/priority/exclusion filtering, so disabled rules cause no downloads.
pub(crate) fn referenced_providers(
    rules: &[String],
    profile: &Map<String, Value>,
    imported: &Map<String, Value>,
    known_proxy: impl Fn(&str) -> bool,
) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    let mut error = None;
    for line in rules {
        let mut has_provider = false;
        rewrite_references(line, |name| {
            has_provider = true;
            if !out.contains_key(name) && error.is_none() {
                let definition = if name.starts_with("sub-provider:") {
                    imported.get(name)
                } else {
                    profile.get(name)
                };
                match definition {
                    None => {
                        error = Some(format!(
                            "RULE-SET references undefined rule provider: {}",
                            diagnostic_name(name)
                        ));
                    }
                    Some(value) => match local_definition(name, value, &known_proxy) {
                        Ok(value) => {
                            out.insert(name.to_owned(), value);
                        }
                        Err(reason) => {
                            error =
                                Some(format!("rule provider {}: {reason}", diagnostic_name(name)));
                        }
                    },
                }
            }
            name.to_owned()
        });
        if has_provider && error.is_none() {
            let target = crate::rules::rule_target(line);
            if !known_proxy(target) {
                error = Some(format!(
                    "RULE-SET rule target is undefined: {}",
                    diagnostic_name(target)
                ));
            }
        }
    }
    error.map_or(Ok(out), Err)
}

fn diagnostic_name(name: &str) -> String {
    let decoded = name.strip_prefix("sub-provider:").and_then(|name| {
        let (subscription, provider) = name.split_once(':')?;
        let decode = |s| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .ok()
                .and_then(|s| String::from_utf8(s).ok())
        };
        Some(format!(
            "{} (subscription {})",
            decode(provider)?,
            decode(subscription)?
        ))
    });
    decoded
        .as_deref()
        .unwrap_or(name)
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect()
}

/// Check native descriptor shapes without fetching payloads. Unknown metadata
/// remains intact for forward compatibility; errors never include URLs/headers.
pub(crate) fn validate_definition(value: &Value) -> Result<(), &'static str> {
    let definition = value.as_object().ok_or("definition must be an object")?;
    let behavior = definition
        .get("behavior")
        .and_then(Value::as_str)
        .ok_or("behavior is required")?
        .to_ascii_lowercase();
    if !matches!(
        behavior.as_str(),
        "domain" | "ipcidr" | "ip-cidr" | "classical"
    ) {
        return Err("unsupported behavior");
    }
    if let Some(format) = definition.get("format").filter(|v| !v.is_null()) {
        let format = format
            .as_str()
            .ok_or("format must be a string")?
            .to_ascii_lowercase();
        if !matches!(format.as_str(), "yaml" | "text" | "mrs" | "srs" | "json") {
            return Err("unsupported format");
        }
        if format == "mrs" && behavior == "classical" {
            return Err("MRS requires domain or ipcidr behavior");
        }
        if matches!(format.as_str(), "srs" | "json")
            && definition.get("type").and_then(Value::as_str) == Some("inline")
        {
            return Err("SRS/JSON requires an HTTP or file provider");
        }
    }
    if definition
        .get("background-fetch")
        .is_some_and(|v| !v.is_null() && !v.is_boolean())
    {
        return Err("background-fetch must be a boolean");
    }
    let interval = definition.get("interval").filter(|v| !v.is_null());
    if interval.is_some_and(|v| v.as_u64().is_none()) {
        return Err("interval must be a non-negative integer in seconds");
    }
    if let Some(proxy) = definition.get("proxy").filter(|v| !v.is_null()) {
        if !proxy
            .as_str()
            .is_some_and(|s| !s.is_empty() && !s.chars().any(char::is_control))
        {
            return Err("proxy must be a non-empty group/node name");
        }
    }
    if let Some(header) = definition.get("header").filter(|v| !v.is_null()) {
        let headers = header.as_object().ok_or("header must be an object")?;
        if headers.values().any(|v| {
            !v.is_string() && !v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
        }) {
            return Err("header values must be strings or lists of strings");
        }
    }
    if definition
        .get("url")
        .is_some_and(|v| !v.is_null() && !v.is_string())
    {
        return Err("url must be a string");
    }
    if let Some(payload) = definition.get("payload").filter(|v| !v.is_null()) {
        if !payload
            .as_array()
            .is_some_and(|a| a.iter().all(Value::is_string))
        {
            return Err("payload must be a list of rule strings");
        }
    }
    match definition.get("type").and_then(Value::as_str) {
        Some("http") => {
            let url = definition
                .get("url")
                .and_then(Value::as_str)
                .ok_or("HTTP url is required")?;
            let valid = url.split_once("://").is_some_and(|(scheme, rest)| {
                (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http"))
                    && !rest
                        .split(['/', '?', '#'])
                        .next()
                        .unwrap_or_default()
                        .is_empty()
            });
            if !valid || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err("HTTP url must use http:// or https:// with a host");
            }
        }
        Some("file") => {
            let path = definition
                .get("path")
                .and_then(Value::as_str)
                .ok_or("file path is required")?;
            // Check Windows and POSIX spelling on every platform. The native
            // loader additionally verifies symlink containment within core data.
            if path.is_empty()
                || path.starts_with('/')
                || path.contains(['\\', ':'])
                || path.chars().any(char::is_control)
                || path.split('/').any(|part| part == ".." || part.is_empty())
            {
                return Err("file path must be relative and cannot traverse directories");
            }
        }
        Some("inline") => {
            if interval.and_then(Value::as_u64).is_some_and(|i| i > 0) {
                return Err("inline providers cannot refresh");
            }
            if !definition
                .get("payload")
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().all(Value::is_string))
            {
                return Err("inline payload must be a list of rule strings");
            }
        }
        _ => return Err("unsupported provider type"),
    }
    Ok(())
}

fn local_definition(
    name: &str,
    value: &Value,
    known: &impl Fn(&str) -> bool,
) -> Result<Value, &'static str> {
    validate_definition(value)?;
    let mut definition = value
        .as_object()
        .cloned()
        .ok_or("definition must be an object")?;
    if let Some(proxy) = definition.get("proxy").filter(|v| !v.is_null()) {
        if !proxy.as_str().is_some_and(known) {
            return Err("download proxy/group is undefined");
        }
    }
    match definition.get("type").and_then(Value::as_str) {
        Some("http") => {
            let format = definition
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("yaml")
                .to_ascii_lowercase();
            // Stable FNV-1a digest bounds the filename even for long Unicode
            // names; neither remote URLs nor credentials enter the cache path.
            let digest = name.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
            });
            definition.insert(
                "path".into(),
                format!("rule-providers/paopao-{digest:016x}.{format}").into(),
            );
        }
        Some("file") => {}
        Some("inline") => {
            definition.remove("path");
        }
        _ => return Err("unsupported provider type"),
    }
    Ok(Value::Object(definition))
}

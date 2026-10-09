//! What the enabled rewrite modules add to the config (Dart:
//! `moduleConfig` in `script_module.dart`, with the parts of `ScriptModule`
//! / `ModuleSpec` it reads).
//!
//! Modules arrive as the app persists them (`ScriptModule.toJson`): parsing
//! module texts stays in the app.

use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::dart::{json_encode, uri_last_path_segment, Dv};
use crate::model::settings::{dart_str, list, str_or_empty};

/// The MITM proxy the scripts run in.
pub const MITM_PROXY_NAME: &str = "paopao-mitm";
/// The listener opened traffic re-enters the core by.
pub const MITM_RETURN_IN: &str = "mitm-return";
/// The proxy leading from the MITM proxy back to [`MITM_RETURN_IN`].
pub const MITM_RETURN_PROXY: &str = "paopao-mitm-return";
/// The script behind every rewrite, under the core's home.
pub const BUILTIN_SCRIPT_PATH: &str = "modules/builtin.js";
/// The scripts' persistent store (`$persistentStore`), under the core's home.
pub const MODULE_STORE_PATH: &str = "modules/store.json";
/// Where scripts' notifications are kept (one JSON object a line).
pub const MODULE_NOTIFICATIONS_PATH: &str = "modules/notifications.jsonl";

/// Where, under the core's home, script `index` of module `module_id` is
/// kept.
pub fn module_script_path(module_id: &str, index: usize) -> String {
    format!("modules/{module_id}/{index}.js")
}

/// A script of a module: run on matching requests / responses, or on a
/// schedule.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleScript {
    pub name: String,
    /// http-response (else http-request).
    pub response: bool,
    /// The URL pattern; empty for [`ModuleScript::cron`] scripts.
    pub pattern: String,
    /// A scheduled script: its cron expression.
    pub cron: Option<String>,
    /// [`ModuleScript::argument`] is a JSON object the script gets as one.
    pub argument_object: bool,
    pub argument: String,
    pub binary_body: bool,
    pub requires_body: bool,
    /// Seconds (default 10).
    pub timeout: i64,
}

impl ModuleScript {
    /// Dart `ModuleScript.fromJson`: None unless an object.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let at = |k: &str| o.get(k).unwrap_or(&Value::Null);
        Some(Self {
            name: dart_str(at("name")),
            response: at("response") == &Value::Bool(true),
            pattern: dart_str(at("pattern")),
            cron: at("cron").as_str().map(str::to_owned),
            argument_object: at("argObject") == &Value::Bool(true),
            argument: str_or_empty(o.get("argument")),
            binary_body: at("binary") == &Value::Bool(true),
            requires_body: at("body") == &Value::Bool(true),
            timeout: Dv::from_json(at("timeout"))
                .as_int_opt()
                .ok()
                .flatten()
                .unwrap_or(10),
        })
    }
}

/// A rewrite that needs no script of its own: run by the built-in script
/// with [`ModuleRewrite::action`] as its argument.
#[derive(Debug, Clone, PartialEq)]
pub struct ModuleRewrite {
    pub pattern: String,
    /// `{op, …}`: `reject`, `redirect`, `url`, `header`, `local`, `body`.
    pub action: Map<String, Value>,
    /// Applies to responses (else requests).
    pub response: bool,
    pub needs_body: bool,
}

impl ModuleRewrite {
    /// Dart `ModuleRewrite.fromJson`: None unless an object with an object
    /// `action`.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        Some(Self {
            action: o.get("action")?.as_object()?.clone(),
            pattern: dart_str(o.get("pattern").unwrap_or(&Value::Null)),
            response: o.get("response") == Some(&Value::Bool(true)),
            needs_body: o.get("body") == Some(&Value::Bool(true)),
        })
    }

    /// `'${action['op']}'`.
    pub fn op(&self) -> String {
        dart_str(self.action.get("op").unwrap_or(&Value::Null))
    }
}

/// What a module asks for, as far as the config is concerned.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ModuleSpec {
    /// Empty when the module has none (the URL's file name is shown).
    pub name: String,
    pub scripts: Vec<ModuleScript>,
    pub rewrites: Vec<ModuleRewrite>,
    /// Hosts to open (`*.example.com` wildcards allowed).
    pub hostnames: Vec<String>,
    /// `-host` entries: never opened, even when a wildcard covers them.
    pub excluded_hosts: Vec<String>,
    /// Rule lines, targets DIRECT / REJECT / PROXY.
    pub rules: Vec<String>,
}

impl ModuleSpec {
    /// Dart `ModuleSpec.fromJson`, the fields above; anything but an object
    /// is an empty spec. Old saves' `rejects` become reject rewrites.
    pub fn from_json(v: &Value) -> Self {
        let Some(o) = v.as_object() else {
            return Self::default();
        };
        let strings = |k: &str| -> Vec<String> { list(o.get(k)).iter().map(dart_str).collect() };
        let legacy = list(o.get("rejects")).iter().filter_map(|r| {
            let r = r.as_object()?;
            let s = |k: &str| dart_str(r.get(k).unwrap_or(&Value::Null));
            let mut action = Map::new();
            action.insert("op".into(), "reject".into());
            action.insert("kind".into(), s("kind").into());
            Some(ModuleRewrite {
                pattern: s("pattern"),
                action,
                response: false,
                needs_body: false,
            })
        });
        Self {
            name: str_or_empty(o.get("name")),
            scripts: list(o.get("scripts"))
                .iter()
                .filter_map(ModuleScript::from_json)
                .collect(),
            rewrites: list(o.get("rewrites"))
                .iter()
                .filter_map(ModuleRewrite::from_json)
                .chain(legacy)
                .collect(),
            hostnames: strings("hostnames"),
            excluded_hosts: strings("excluded"),
            rules: strings("rules"),
        }
    }
}

/// A rewrite module as the app keeps it (the parts the config needs).
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptModule {
    /// Names its scripts' directory ([`module_script_path`]).
    pub id: String,
    /// Where it was downloaded from.
    pub url: String,
    /// Switched on (default).
    pub enabled: bool,
    pub spec: ModuleSpec,
}

impl ScriptModule {
    /// Dart `ScriptModule.fromJson`: None unless an object with a non-null
    /// `id`.
    ///
    /// Dart parity: mistyped fields that make Dart's casts throw (a
    /// non-list `scripts`, a non-string `cron`, a non-numeric `timeout`)
    /// read as missing here.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let id = o.get("id").filter(|x| !x.is_null())?;
        Some(Self {
            id: dart_str(id),
            url: str_or_empty(o.get("url")),
            enabled: o.get("enabled") != Some(&Value::Bool(false)),
            spec: ModuleSpec::from_json(o.get("spec").unwrap_or(&Value::Null)),
        })
    }

    /// What it is called: the spec's name, else the URL's last path segment
    /// (possibly empty, as for `https://x/a/`), else the URL.
    pub fn name(&self) -> String {
        if self.spec.name.is_empty() {
            uri_last_path_segment(&self.url).unwrap_or_else(|| self.url.clone())
        } else {
            self.spec.name.clone()
        }
    }
}

impl<'de> Deserialize<'de> for ScriptModule {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Self::from_json(&v).ok_or_else(|| serde::de::Error::custom("not a module"))
    }
}

/// The rule condition matching `host`: `DOMAIN-SUFFIX` for `*.x.com`,
/// `DOMAIN-WILDCARD` for other `*` / `?` patterns, else `DOMAIN`.
pub fn host_condition(host: &str) -> String {
    if let Some(rest) = host.strip_prefix("*.") {
        format!("DOMAIN-SUFFIX,{rest}")
    } else if host.contains(['*', '?']) {
        format!("DOMAIN-WILDCARD,{host}")
    } else {
        format!("DOMAIN,{host}")
    }
}

/// What the enabled modules add to the config, see [`module_config`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ModuleConfig {
    /// The MITM proxy and the way back into the core; empty when nothing
    /// needs opening.
    pub proxies: Vec<Map<String, Value>>,
    /// The listener opened traffic re-enters by (with the MITM proxy).
    pub listener: Option<Map<String, Value>>,
    /// Rules: UDP to the opened hosts refused, the hosts to the MITM proxy,
    /// then the modules' own rules.
    pub rules: Vec<String>,
}

/// What the enabled `modules` add to a meow config (Dart: `moduleConfig`):
/// the MITM proxy running every script and rewrite and its way back in on
/// `return_port` (none when nothing needs opening: no scripts, no port, or
/// neither hosts nor cron scripts), and rules — UDP to the opened hosts
/// refused (QUIC would bypass the scripts), the hosts to the MITM proxy
/// (`-host` exclusions and traffic already back from it left alone), then
/// the modules' own rules with `PROXY` as `proxy_target`, duplicates once.
///
/// `utc_offset_minutes` is the local time zone's offset for cron scripts.
/// Dart parity: the app's config generation never passes it and Dart reads
/// the wall clock's offset; here it is an input.
pub fn module_config(
    modules: &[ScriptModule],
    proxy_target: &str,
    return_port: Option<i64>,
    utc_offset_minutes: i64,
) -> ModuleConfig {
    let mut scripts: Vec<Map<String, Value>> = Vec::new();
    let mut hosts: Vec<&str> = Vec::new();
    let mut excluded: Vec<&str> = Vec::new();
    let mut rules: Vec<String> = Vec::new();
    for m in modules.iter().filter(|m| m.enabled) {
        let name = m.name();
        for (i, s) in m.spec.scripts.iter().enumerate() {
            let mut e = Map::new();
            e.insert("name".into(), format!("{name}: {}", s.name).into());
            if let Some(c) = &s.cron {
                e.insert("type".into(), "cron".into());
                e.insert("cron".into(), c.clone().into());
            } else {
                let kind = if s.response {
                    "http-response"
                } else {
                    "http-request"
                };
                e.insert("type".into(), kind.into());
                e.insert("pattern".into(), s.pattern.clone().into());
            }
            e.insert("script-path".into(), module_script_path(&m.id, i).into());
            if !s.argument.is_empty() {
                e.insert("argument".into(), s.argument.clone().into());
            }
            if s.argument_object {
                e.insert("argument-object".into(), true.into());
            }
            e.insert("binary-body-mode".into(), s.binary_body.into());
            e.insert("requires-body".into(), s.requires_body.into());
            e.insert("timeout".into(), s.timeout.into());
            scripts.push(e);
        }
        for r in &m.spec.rewrites {
            let mut e = Map::new();
            e.insert("name".into(), format!("{name}: {}", r.op()).into());
            let kind = if r.response {
                "http-response"
            } else {
                "http-request"
            };
            e.insert("type".into(), kind.into());
            e.insert("pattern".into(), r.pattern.clone().into());
            e.insert("script-path".into(), BUILTIN_SCRIPT_PATH.into());
            let action = Dv::from_json(&Value::Object(r.action.clone()));
            e.insert("argument".into(), json_encode(&action).into());
            e.insert("requires-body".into(), r.needs_body.into());
            e.insert("timeout".into(), 5.into());
            scripts.push(e);
        }
        for h in &m.spec.hostnames {
            if !hosts.contains(&h.as_str()) {
                hosts.push(h);
            }
        }
        for h in &m.spec.excluded_hosts {
            if !excluded.contains(&h.as_str()) {
                excluded.push(h);
            }
        }
        for r in &m.spec.rules {
            let mut parts: Vec<&str> = r.split(',').collect();
            if parts.len() > 2 && parts[2] == "PROXY" {
                parts[2] = proxy_target;
            }
            let line = parts.join(",");
            if !rules.contains(&line) {
                rules.push(line);
            }
        }
    }
    // Scripts run in the MITM proxy, cron ones too (no host needed).
    let port = return_port.filter(|_| {
        !scripts.is_empty()
            && (!hosts.is_empty()
                || scripts
                    .iter()
                    .any(|s| s.get("type").and_then(Value::as_str) == Some("cron")))
    });
    let Some(port) = port else {
        return ModuleConfig {
            proxies: Vec::new(),
            listener: None,
            rules,
        };
    };
    let skip = std::iter::once(format!("(NOT,((IN-NAME,{MITM_RETURN_IN})))"))
        .chain(
            excluded
                .iter()
                .map(|x| format!("(NOT,(({})))", host_condition(x))),
        )
        .collect::<Vec<_>>()
        .join(",");

    let mut mitm = Map::new();
    mitm.insert("name".into(), MITM_PROXY_NAME.into());
    mitm.insert("type".into(), "mitm".into());
    mitm.insert("ca-cert".into(), "mitm-ca.pem".into());
    mitm.insert("ca-key".into(), "mitm-ca-key.pem".into());
    mitm.insert("store".into(), MODULE_STORE_PATH.into());
    mitm.insert("notifications".into(), MODULE_NOTIFICATIONS_PATH.into());
    mitm.insert("utc-offset".into(), utc_offset_minutes.into());
    mitm.insert("dialer-proxy".into(), MITM_RETURN_PROXY.into());
    mitm.insert(
        "scripts".into(),
        Value::Array(scripts.into_iter().map(Value::Object).collect()),
    );
    let mut back = Map::new();
    back.insert("name".into(), MITM_RETURN_PROXY.into());
    back.insert("type".into(), "socks5".into());
    back.insert("server".into(), "127.0.0.1".into());
    back.insert("port".into(), port.into());
    let mut listener = Map::new();
    listener.insert("name".into(), MITM_RETURN_IN.into());
    listener.insert("type".into(), "mixed".into());
    listener.insert("port".into(), port.into());
    listener.insert("listen".into(), "127.0.0.1".into());

    let mut all_rules = Vec::with_capacity(hosts.len() * 2 + rules.len());
    for h in hosts {
        let c = host_condition(h);
        all_rules.push(format!("AND,((NETWORK,UDP),({c})),REJECT"));
        all_rules.push(format!("AND,(({c}),{skip}),{MITM_PROXY_NAME}"));
    }
    all_rules.extend(rules);
    ModuleConfig {
        proxies: vec![mitm, back],
        listener: Some(listener),
        rules: all_rules,
    }
}

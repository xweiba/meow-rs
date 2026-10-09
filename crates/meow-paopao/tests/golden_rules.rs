//! L4 helpers against Dart.
//!
//! - `tests/fixtures/l4_helpers.json`: Dart's answers for many inputs
//!   (`clashProxyFor` over every parse-golden node plus edge cases, the
//!   `unique()` naming (now the pool's one tag scheme, B1),
//!   `clashSshProxies`, `paopaoHosts`, `moduleConfig`, `ScriptModule.name`), written once by a throwaway Dart script
//!   (`tests/fixtures/l4_helpers_dump.dart`, run from `paopao_proxy/test`).
//!   Where Dart threw (`{"throws": …}`), Rust's documented divergence is
//!   checked instead.
//! - `tests/golden/build/*.json`: the pieces must equal what the final
//!   config holds — node proxies, SSH proxies, module proxies / listener /
//!   rules, `paopao-hosts`, private-range and user rules.

mod common;

use meow_paopao::rules::{
    custom_rule_line, private_cidr_rules, rule_target_tag, ssh_proxies, ModuleConfig, SshProxy,
};
use meow_paopao::{
    build_pool, clash_proxy_for, effective_settings, module_config, paopao_hosts, NetworkInfo,
    PoolInput, PoolSource, ProxyNode, ProxySettings, ScriptModule, SshSecrets,
};
use serde_json::{Map, Value};

fn fixture() -> Value {
    common::read_json(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/l4_helpers.json"),
    )
}

fn node(v: &Value) -> ProxyNode {
    ProxyNode {
        name: match &v["name"] {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        },
        outbound: v["outbound"].as_object().cloned().unwrap_or_default(),
    }
}

fn objects(maps: Vec<Map<String, Value>>) -> Value {
    Value::Array(maps.into_iter().map(Value::Object).collect())
}

fn module_json(c: &ModuleConfig) -> Value {
    serde_json::json!({
        "proxies": objects(c.proxies.clone()),
        "listener": c.listener.clone().map_or(Value::Null, Value::Object),
        "rules": c.rules,
    })
}

fn report(what: &str, failures: &[String], total: usize) {
    assert!(
        failures.is_empty(),
        "{what}: {} of {total} differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("{what}: {total} passed");
}

#[test]
fn clash_proxy_for_matches_dart() {
    let f = fixture();
    let cases = f["clashProxyFor"].as_array().expect("cases");
    let mut failures = Vec::new();
    for c in cases {
        let n = node(&c["node"]);
        let got =
            clash_proxy_for(&n, &format!("tag:{}", n.name)).map_or(Value::Null, Value::Object);
        // Dart throws on mistyped fields; Rust does not convert the node.
        let want = c["got"].get("ok").cloned().unwrap_or(Value::Null);
        if let Some(d) = common::first_diff(&got, &want) {
            failures.push(format!("{}: {d}", n.name));
        }
    }
    report("clashProxyFor", &failures, cases.len());
}

/// Dart's `unique()` naming against the one tag scheme (B1): the same
/// names, the unconvertible nodes left out, except that a line no longer
/// takes a name our own outbounds use (`direct`, `block`, `speedtest`,
/// `auto~fastest` were free in the config).
#[test]
fn proxy_names_follow_dart_unique() {
    let f = fixture();
    let cases = f["unique"].as_array().expect("cases");
    let mut failures = Vec::new();
    for c in cases {
        let nodes: Vec<ProxyNode> = c["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .map(node)
            .collect();
        let input = PoolInput {
            subscriptions: vec![PoolSource {
                // Distinct servers: `unique()` saw no de-duplication.
                nodes: nodes
                    .iter()
                    .enumerate()
                    .map(|(i, n)| {
                        let mut n = n.clone();
                        n.outbound.insert("server_port".into(), (i + 1).into());
                        n
                    })
                    .collect(),
                usage: None,
            }],
            ..PoolInput::default()
        };
        let pool = build_pool(&input);
        let mut want = c["got"]["ok"].clone();
        for n in want["names"].as_array_mut().expect("names") {
            if let Some(s @ ("direct" | "block" | "speedtest" | "auto~fastest")) = n.as_str() {
                *n = format!("{s} 2").into();
            }
        }
        let got = serde_json::json!({"names": pool.tags, "unsupported": pool.unsupported});
        if let Some(d) = common::first_diff(&got, &want) {
            failures.push(format!("{}: {d}", c["nodes"]));
        }
    }
    report("unique()", &failures, cases.len());
}

#[test]
fn ssh_hosts_and_modules_match_dart() {
    let f = fixture();
    let mut failures = Vec::new();

    let secrets = SshSecrets::from_json(&f["ssh"]["secrets"]);
    let ssh = f["ssh"]["cases"].as_array().expect("ssh");
    for c in ssh {
        let chain = meow_paopao::model::settings::SshChain::from_json(&c["chain"]).expect("chain");
        let got = objects(
            ssh_proxies(&chain, &secrets)
                .into_iter()
                .map(SshProxy::into_map)
                .collect(),
        );
        if let Some(d) = common::first_diff(&got, &c["got"]["ok"]) {
            failures.push(format!("ssh {}: {d}", chain.id));
        }
    }

    let entries: Vec<_> = f["hosts"]["entries"]
        .as_array()
        .expect("hosts")
        .iter()
        .filter_map(meow_paopao::model::settings::HostEntry::from_json)
        .collect();
    let got = Value::Array(paopao_hosts(&entries));
    if let Some(d) = common::first_diff(&got, &f["hosts"]["got"]) {
        failures.push(format!("hosts: {d}"));
    }

    let modules = f["modules"].as_array().expect("modules");
    for (i, c) in modules.iter().enumerate() {
        let list: Vec<ScriptModule> = c["modules"]
            .as_array()
            .expect("list")
            .iter()
            .filter_map(ScriptModule::from_json)
            .collect();
        let got = module_json(&module_config(
            &list,
            "proxy",
            c["returnPort"].as_i64(),
            480,
        ));
        if let Some(d) = common::first_diff(&got, &c["got"]["ok"]) {
            failures.push(format!("modules #{i}: {d}"));
        }
    }

    let names = f["moduleNames"].as_array().expect("names");
    for c in names {
        let url = c["url"].as_str().expect("url");
        let m =
            ScriptModule::from_json(&serde_json::json!({"id": "x", "url": url})).expect("module");
        let got = m.name();
        match c["got"].get("ok") {
            Some(want) if want != &Value::String(got.clone()) => {
                failures.push(format!("name of {url:?}: got {got:?}, want {want}"));
            }
            Some(_) => {}
            // Dart throws on escapes that are not UTF-8; decoded lossily here.
            None => assert!(got.contains('\u{fffd}'), "{url:?}: {got:?}"),
        }
    }
    report(
        "ssh / hosts / modules / names",
        &failures,
        ssh.len() + 1 + modules.len() + names.len(),
    );
}

/// The pieces of each build golden's config L4 produces.
#[test]
fn pieces_match_build_goldens() {
    let files = common::golden_files("build");
    assert!(!files.is_empty(), "no build goldens");
    let mut failures = Vec::new();
    let (mut ssh_cases, mut module_cases, mut host_cases) = (0, 0, 0);
    for path in &files {
        let case = common::read_json(path);
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let input = &case["input"];
        let config = &case["expected"]["config"];
        let mut fail = |d: String| failures.push(format!("{name}: {d}"));
        let want_proxies = config["proxies"].as_array().expect("proxies");

        // Node proxies first.
        let pool_input: PoolInput = serde_json::from_value(input.clone()).expect("input");
        let pool = build_pool(&pool_input);
        let mut got: Vec<Value> = pool
            .nodes
            .iter()
            .zip(&pool.tags)
            .filter_map(|(n, t)| clash_proxy_for(&n.node, t))
            .map(Value::Object)
            .collect();

        // Then the SSH chains' (no device exits on the meow path).
        let settings: ProxySettings =
            serde_json::from_value(input["settings"].clone()).expect("settings");
        let secrets = SshSecrets::from_json(&input["sshSecrets"]);
        for c in &settings.ssh_chains {
            ssh_cases += 1;
            got.extend(
                ssh_proxies(c, &secrets)
                    .into_iter()
                    .map(|p| Value::Object(p.into_map())),
            );
        }

        // Then the modules'.
        let modules: Vec<ScriptModule> = input["modules"]
            .as_array()
            .map(|a| a.iter().filter_map(ScriptModule::from_json).collect())
            .unwrap_or_default();
        let mitm_port = input["runtime"]["mitmPort"].as_i64();
        // Dart read the dump machine's offset from the wall clock.
        let utc = want_proxies
            .iter()
            .find_map(|p| p.get("utc-offset").and_then(Value::as_i64))
            .unwrap_or(0);
        let mods = module_config(&modules, "proxy", mitm_port, utc);
        if !modules.is_empty() {
            module_cases += 1;
        }
        got.extend(mods.proxies.iter().cloned().map(Value::Object));
        let want_head = Value::Array(want_proxies[..got.len().min(want_proxies.len())].to_vec());
        if let Some(d) = common::first_diff(&Value::Array(got.clone()), &want_head) {
            fail(format!("proxies {d}"));
        }
        // Whatever follows is an interface outbound.
        if let Some(p) = want_proxies[got.len().min(want_proxies.len())..]
            .iter()
            .find(|p| p["type"] != "direct")
        {
            fail(format!("unexpected proxy after L4's: {p}"));
        }
        // The module listener is the last one.
        let listeners = config["listeners"].as_array().cloned().unwrap_or_default();
        if let Some(l) = &mods.listener {
            if listeners.last() != Some(&Value::Object(l.clone())) {
                fail(format!("listener: {listeners:?}"));
            }
        }

        // Hosts of the settings in effect.
        let network: NetworkInfo =
            serde_json::from_value(input["network"].clone()).expect("network");
        let effective = effective_settings(&settings, &network);
        let hosts = paopao_hosts(&effective.hosts);
        if !hosts.is_empty() {
            host_cases += 1;
        }
        match config.get("paopao-hosts") {
            Some(want) if !hosts.is_empty() => {
                if let Some(d) = common::first_diff(&Value::Array(hosts), want) {
                    fail(format!("paopao-hosts {d}"));
                }
            }
            None if hosts.is_empty() => {}
            other => fail(format!("paopao-hosts: {other:?}, got {hosts:?}")),
        }

        // Rules: private ranges, the user's, the modules'.
        let rules: Vec<&str> = config["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let private = private_cidr_rules();
        let Some(start) = rules.iter().position(|r| *r == private[0]) else {
            fail("no private rules".into());
            continue;
        };
        let mut at = start;
        for p in &private {
            if rules.get(at) != Some(&p.as_str()) {
                fail(format!("rules[{at}]: {:?}, want {p}", rules.get(at)));
            }
            at += 1;
        }
        // An app this version can't read makes no rule.
        for r in effective
            .rules
            .iter()
            .filter(|r| custom_rule_line(r, "x").is_some())
        {
            // The target as written, or REJECT when it no longer exists.
            let options = [
                custom_rule_line(r, &rule_target_tag(&r.target)).unwrap_or_default(),
                custom_rule_line(r, "REJECT").unwrap_or_default(),
            ];
            if !rules
                .get(at)
                .is_some_and(|x| options.iter().any(|o| o == x))
            {
                fail(format!(
                    "rules[{at}]: {:?}, want {options:?}",
                    rules.get(at)
                ));
            }
            at += 1;
        }
        for m in &mods.rules {
            if rules.get(at) != Some(&m.as_str()) {
                fail(format!(
                    "rules[{at}]: {:?}, want module rule {m}",
                    rules.get(at)
                ));
            }
            at += 1;
        }
    }
    assert!(
        ssh_cases > 0 && module_cases > 0 && host_cases > 0,
        "corpus lacks L4 cases"
    );
    report("build goldens (L4 pieces)", &failures, files.len());
}

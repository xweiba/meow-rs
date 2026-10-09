//! Unit tests ported from the Dart suite (`hosts_network_test.dart`,
//! `script_module_test.dart`, `module_features_test.dart`), plus the rule
//! helpers and secret redaction. Parity over many inputs is checked
//! against Dart's own answers in `tests/golden_rules.rs`.

use serde_json::{json, Value};

use super::*;
use crate::model::settings::{HostEntry, SshChain};

fn host(m: &str, pattern: &str, address: Option<&str>) -> HostEntry {
    HostEntry::from_json(&json!({"match": m, "pattern": pattern, "address": address}))
        .expect("entry")
}

#[test]
fn hosts_keep_order_and_pass_through() {
    // Dart: 'wildcard and pass-through: meow-rs gets the ordered list'.
    let weiba = [
        host("wildcard", "node*.weiba.pp.ua", None),
        host("exact", "pve.weiba.pp.ua", Some("192.168.186.215")),
        host("wildcard", "*.weiba.pp.ua", Some("192.168.186.230")),
    ];
    assert_eq!(
        Value::Array(paopao_hosts(&weiba)),
        json!([
            {"type": "wildcard", "value": "node*.weiba.pp.ua"},
            {"type": "exact", "value": "pve.weiba.pp.ua", "address": "192.168.186.215"},
            {"type": "wildcard", "value": "*.weiba.pp.ua", "address": "192.168.186.230"},
        ])
    );
    let types: Vec<Value> = paopao_hosts(&[
        host("domain", "a.example", Some("1.2.3.4")),
        host("keyword", "cdn", Some("1.2.3.5")),
        host("regex", r"^x\.", Some("::1")),
    ])
    .into_iter()
    .map(|e| e["type"].clone())
    .collect();
    assert_eq!(types, [json!("suffix"), json!("keyword"), json!("regex")]);
}

fn module(v: &Value) -> ScriptModule {
    ScriptModule::from_json(v).expect("module")
}

#[test]
fn opened_hosts_go_to_the_mitm_proxy_once_then_by_the_rules() {
    // Dart: 'config: opened hosts go to the MITM proxy once, then by the
    // rules', with the spec `parseModule(surge)` gives (in part).
    let on = module(&json!({"id": "m1", "url": "https://x/a", "spec": {
        "name": "Surge",
        "scripts": [{"name": "fix", "response": true, "pattern": "^https://a/", "url": "f.js"}],
        "rewrites": [{"pattern": "^https://ad/", "action": {"op": "reject", "kind": "dict"}}],
        "hostnames": ["gs-loc.apple.com", "*.example.com"],
        "excluded": ["skip.example.com"],
        "rules": ["DOMAIN-SUFFIX,tracker.example,REJECT", "DOMAIN,api.example.com,PROXY"],
    }}));
    let off = module(
        &json!({"id": "m2", "url": "https://x/b", "enabled": false, "spec": {
            "hostnames": ["off.example"], "rules": ["DOMAIN,off,REJECT"],
        }}),
    );
    let c = module_config(&[on, off], "proxy", Some(7999), 480);
    let mitm = &c.proxies[0];
    assert_eq!(mitm["type"], "mitm");
    assert_eq!(mitm["dialer-proxy"], MITM_RETURN_PROXY);
    let scripts = mitm["scripts"].as_array().expect("scripts");
    assert_eq!(scripts[0]["script-path"], "modules/m1/0.js");
    assert_eq!(scripts[1]["script-path"], BUILTIN_SCRIPT_PATH);
    assert_eq!(scripts[1]["argument"], r#"{"op":"reject","kind":"dict"}"#);
    assert_eq!(scripts[1]["name"], "Surge: reject");
    assert_eq!(c.proxies[1]["port"], 7999);
    assert_eq!(
        c.listener.as_ref().map(|l| l["name"].clone()),
        Some(json!(MITM_RETURN_IN))
    );
    assert_eq!(
        c.rules,
        [
            "AND,((NETWORK,UDP),(DOMAIN,gs-loc.apple.com)),REJECT",
            "AND,((DOMAIN,gs-loc.apple.com),(NOT,((IN-NAME,mitm-return))),(NOT,((DOMAIN,skip.example.com)))),paopao-mitm",
            "AND,((NETWORK,UDP),(DOMAIN-SUFFIX,example.com)),REJECT",
            "AND,((DOMAIN-SUFFIX,example.com),(NOT,((IN-NAME,mitm-return))),(NOT,((DOMAIN,skip.example.com)))),paopao-mitm",
            "DOMAIN-SUFFIX,tracker.example,REJECT",
            "DOMAIN,api.example.com,proxy",
        ]
    );

    // Nothing to open: no MITM, the rules still apply.
    let rules_only = module_config(
        &[module(
            &json!({"id": "r", "url": "u", "spec": {"rules": ["DOMAIN,a,REJECT"]}}),
        )],
        "proxy",
        Some(7999),
        480,
    );
    assert!(rules_only.proxies.is_empty());
    assert!(rules_only.listener.is_none());
    assert_eq!(rules_only.rules, ["DOMAIN,a,REJECT"]);
}

#[test]
fn cron_scripts_run_in_the_mitm_proxy_even_with_no_host() {
    // Dart: 'config: cron scripts run in the MITM proxy, even with no host'.
    let q = module(&json!({"id": "q", "url": "u", "spec": {"scripts": [
        {"name": "task", "pattern": "", "url": "https://example.com/qx-task.js", "cron": "0 9 * * *"},
    ]}}));
    let c = module_config(&[q], "proxy", Some(7999), 480);
    let mitm = &c.proxies[0];
    assert_eq!(mitm["utc-offset"], 480);
    assert_eq!(mitm["notifications"], MODULE_NOTIFICATIONS_PATH);
    let script = &mitm["scripts"][0];
    assert_eq!(script["type"], "cron");
    assert_eq!(script["cron"], "0 9 * * *");
    assert!(script.get("pattern").is_none());
    assert!(c.rules.is_empty(), "nothing to open");

    // Without a way back in, nothing runs.
    let none = module_config(
        &[module(
            &json!({"id": "q", "url": "u", "spec": {"scripts": [{"cron": "* * * * *"}]}}),
        )],
        "proxy",
        None,
        0,
    );
    assert_eq!(none, ModuleConfig::default());
}

#[test]
fn module_names_fall_back_to_the_url() {
    let named = |url: &str| module(&json!({"id": "x", "url": url})).name();
    assert_eq!(named("https://m.example/ad.sgmodule?x=1"), "ad.sgmodule");
    assert_eq!(named("https://m.example/%E5%8E%BB.plugin"), "去.plugin");
    assert_eq!(named("https://m.example/a/"), "");
    assert_eq!(named("https://m.example"), "https://m.example");
    assert_eq!(named("https://x:bad/y"), "https://x:bad/y");
    let spec = module(&json!({"id": "x", "url": "https://a/b", "spec": {"name": "N"}}));
    assert_eq!(spec.name(), "N");
}

#[test]
fn ssh_hops_chain_through_each_other() {
    let chain = SshChain::from_json(&json!({"id": "c", "name": "n", "hops": [
        {"host": "jump", "user": "me"},
        {"host": "10.0.0.5", "port": 2222, "user": "ops", "key": false, "host_key": "ssh-ed25519 K"},
    ]}))
    .expect("chain");
    let mut secrets = SshSecrets::new();
    secrets.insert(SshChain::secret_key("c", 0), "PRIVATE");
    secrets.insert(SshChain::secret_key("c", 1), "PASSWORD");
    let got: Vec<Value> = ssh_proxies(&chain, &secrets)
        .into_iter()
        .map(|p| Value::Object(p.into_map()))
        .collect();
    assert_eq!(
        got,
        [
            json!({"name": "ssh:c#0", "type": "ssh", "server": "jump", "port": 22, "username": "me", "private-key": "PRIVATE"}),
            json!({"name": "ssh:c", "type": "ssh", "server": "10.0.0.5", "port": 2222, "username": "ops", "password": "PASSWORD", "host-key": ["ssh-ed25519 K"], "dialer-proxy": "ssh:c#0"}),
        ]
    );
}

#[test]
fn secrets_never_show_in_debug_output() {
    let chain = SshChain::from_json(&json!({"id": "c", "hops": [
        {"host": "a"}, {"host": "b", "key": false},
    ]}))
    .expect("chain");
    let secrets = SshSecrets::from_json(&json!({"ssh/c/0": "PRIVATE", "ssh/c/1": "PASSWORD"}));
    let printed = format!("{secrets:?} {:?}", ssh_proxies(&chain, &secrets));
    assert!(
        !printed.contains("PRIVATE") && !printed.contains("PASSWORD"),
        "{printed}"
    );
    assert!(
        printed.contains("ssh/c/0") && printed.contains("ssh:c#0"),
        "{printed}"
    );

    let node = crate::model::node::ProxyNode {
        name: "n".into(),
        outbound: json!({"type": "socks", "server": "s", "server_port": 1, "password": "NODEPW"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    };
    let proxy = crate::pool::clash_proxy_for(&node, "n").expect("proxy");
    assert_eq!(proxy["password"], "NODEPW");
}

#[test]
fn rule_lines() {
    assert_eq!(
        private_cidr_rules()[0],
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
    );
    assert_eq!(
        private_cidr_rules()[8],
        "IP-CIDR6,::1/128,DIRECT,no-resolve"
    );
    let rule = |m: &str, v: &str, t: &str| {
        let r = crate::model::settings::CustomRule::from_json(
            &json!({"match": m, "value": v, "target": t}),
        )
        .expect("rule");
        custom_rule_line(&r, &rule_target_tag(&r.target)).expect("line")
    };
    assert_eq!(
        rule("domain", "a.com", "direct"),
        "DOMAIN-SUFFIX,a.com,DIRECT"
    );
    assert_eq!(rule("exact", "a.com", "block"), "DOMAIN,a.com,REJECT");
    assert_eq!(rule("keyword", "ads", "proxy"), "DOMAIN-KEYWORD,ads,proxy");
    assert_eq!(
        rule("ip", "8.8.8.8", "direct"),
        "IP-CIDR,8.8.8.8/32,DIRECT,no-resolve"
    );
    assert_eq!(
        rule("ip", "2001:db8::/32", "iface:utun6"),
        "IP-CIDR6,2001:db8::/32,iface:utun6,no-resolve"
    );
    assert_eq!(
        rule("ip", "::1", "device:d1"),
        "IP-CIDR6,::1/128,device:d1,no-resolve"
    );
    assert_eq!(
        rule("process", "chrome.exe", "line:policy:ai"),
        "PROCESS-NAME,chrome.exe,policy:ai"
    );
    // Apps: a macOS bundle by its folder (helpers inside included), a
    // program by its file name, an Android app by its package.
    assert_eq!(
        rule("app", "path:/Applications/Google Chrome.app", "direct"),
        "PROCESS-PATH,/Applications/Google Chrome.app,DIRECT"
    );
    assert_eq!(
        rule("app", "path:/Applications/X.app/", "proxy"),
        "PROCESS-PATH,/Applications/X.app,proxy"
    );
    assert_eq!(
        rule("app", "name:chrome.exe", "line:policy:ai"),
        "PROCESS-NAME,chrome.exe,policy:ai"
    );
    assert_eq!(
        rule("app", "name:firefox", "block"),
        "PROCESS-NAME,firefox,REJECT"
    );
    assert_eq!(
        rule("app", "pkg:com.tencent.mm", "direct"),
        "PROCESS-NAME,com.tencent.mm,DIRECT"
    );
    assert_eq!(
        rule("app", "path:/Applications/Teams (work).app", "direct"),
        "PROCESS-PATH,/Applications/Teams (work).app,DIRECT"
    );
    // What this version can't read (or a rule line can't carry) makes none.
    for v in ["bundle:com.x", "chrome.exe", "name:", "path:/", "name:a,b"] {
        let r = crate::model::settings::CustomRule::from_json(
            &json!({"match": "app", "value": v, "target": "direct"}),
        )
        .expect("kept");
        assert_eq!(custom_rule_line(&r, "DIRECT"), None, "{v}");
    }

    assert_eq!(geo_rule("geoip-cn", "DIRECT"), "GEOIP,cn,DIRECT");
    assert_eq!(
        geo_rule(PRIVATE_RULE_SET, "DIRECT"),
        "GEOSITE,private,DIRECT"
    );
    assert_eq!(
        rule_target("IP-CIDR,1.1.1.1/32,policy:x,no-resolve"),
        "policy:x"
    );
    assert_eq!(rule_target("SRC-IP-CIDR,1.1.1.1/32,DIRECT,src"), "DIRECT");
    assert_eq!(rule_target("no-resolve"), "");
    assert_eq!(rule_matcher("DOMAIN,a.com,proxy"), "DOMAIN,a.com");
    assert_eq!(rule_matcher("MATCH"), "MATCH");
    assert_eq!(host_condition("*.x.com"), "DOMAIN-SUFFIX,x.com");
    assert_eq!(host_condition("a*b"), "DOMAIN-WILDCARD,a*b");
    assert_eq!(host_condition("q?.x"), "DOMAIN-WILDCARD,q?.x");
    assert_eq!(host_condition("x.com"), "DOMAIN,x.com");
}

#[test]
fn sites_left_out_skip_a_rule() {
    // Dart: 'a site left out of a built-in policy skips all its rules'.
    let sites = |x: &[&str]| x.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        without_sites(
            "GEOSITE,x,p",
            &sites(&[
                "exact:www.a.com",
                "keyword:chat",
                "ip:10.0.0.0/8",
                "process:Chrome.exe",
                "::1"
            ])
        ),
        "AND,((GEOSITE,x),(NOT,((OR,((DOMAIN,www.a.com),(DOMAIN-KEYWORD,chat),\
         (IP-CIDR,10.0.0.0/8,no-resolve),(PROCESS-NAME,Chrome.exe),\
         (IP-CIDR6,::1/128,no-resolve)))))),p"
    );
    assert_eq!(
        without_sites("IP-CIDR,8.8.8.8/32,p,no-resolve", &sites(&["a.com"])),
        "AND,((IP-CIDR,8.8.8.8/32,no-resolve),(NOT,((DOMAIN-SUFFIX,a.com)))),p"
    );
    let skip = "(NOT,((OR,((DOMAIN-SUFFIX,music.youtube.com),(IP-CIDR,1.2.3.4/32,no-resolve)))))";
    let yt = sites(&["music.youtube.com", "1.2.3.4"]);
    assert_eq!(
        without_sites("GEOSITE,youtube,policy:youtube", &yt),
        format!("AND,((GEOSITE,youtube),{skip}),policy:youtube")
    );
    // QUIC refusal too: one more condition inside the AND.
    assert_eq!(
        without_sites(
            "AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,youtube)),REJECT",
            &yt
        ),
        format!("AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,youtube),{skip}),REJECT")
    );
    // Apps left out: by folder or by name; unreadable ones are ignored.
    assert_eq!(
        without_sites(
            "GEOSITE,x,p",
            &sites(&[
                "app:path:/Applications/X.app",
                "app:pkg:com.tencent.mm",
                "app:what:x"
            ])
        ),
        "AND,((GEOSITE,x),(NOT,((OR,((PROCESS-PATH,/Applications/X.app),\
         (PROCESS-NAME,com.tencent.mm)))))),p"
    );
    assert_eq!(
        without_sites("GEOSITE,x,p", &sites(&["app:what:x"])),
        "GEOSITE,x,p"
    );
    assert_eq!(
        without_sites("GEOSITE,x,p", &sites(&["app:path:/A (1).app"])),
        "GEOSITE,x,p"
    );
    // From the build goldens (regions--custom).
    assert_eq!(
        without_sites(
            "GEOSITE,openai,policy:ai",
            &sites(&["claude.ai", "1.2.3.4", "keyword:chat"])
        ),
        "AND,((GEOSITE,openai),(NOT,((OR,((DOMAIN-SUFFIX,claude.ai),\
         (IP-CIDR,1.2.3.4/32,no-resolve),(DOMAIN-KEYWORD,chat)))))),policy:ai"
    );
}

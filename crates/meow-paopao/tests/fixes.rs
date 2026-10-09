//! The behaviour fixes of the PaoPao task `10-09-config-rust`
//! (`research/decisions.md`), each with the bug's own example, checked on
//! the whole build.

use meow_paopao::{build, BuildInput, BuildOutput};
use serde_json::{json, Value};

/// A runnable vless line.
fn vless(name: &str, server: &str) -> Value {
    json!({"name": name, "outbound": {"type": "vless", "server": server, "server_port": 443, "uuid": "u"}})
}

/// A plain HTTP line (the core has no HTTP outbound).
fn http(name: &str, server: &str) -> Value {
    json!({"name": name, "outbound": {"type": "http", "server": server, "server_port": 80}})
}

/// One subscription with `nodes` and `split`, smart mode, the given
/// settings merged over the defaults.
fn input(nodes: &Value, split: &Value, settings: &Value) -> Value {
    let mut s = json!({"mode": "smart", "selected": "auto", "mixed_port": 7890, "rules": []});
    if let (Some(s), Some(extra)) = (s.as_object_mut(), settings.as_object()) {
        for (k, v) in extra {
            s.insert(k.clone(), v.clone());
        }
    }
    json!({
        "subscriptions": [{"id": "s", "url": "https://a.example", "name": "a", "nodes": nodes, "split": split}],
        "settings": s,
        "network": {"kind": "wifi", "ssid": "home", "addresses": []},
        "now": 1_791_563_444_034_i64,
        "runtime": {"controllerPort": 1, "secret": "x", "speedTestPort": 2},
    })
}

fn run(v: &Value) -> BuildOutput {
    build(&BuildInput::from_json(v))
}

fn config_rules(out: &BuildOutput) -> Vec<String> {
    out.config["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter_map(|r| r.as_str().map(str::to_owned))
        .collect()
}

fn proxy_names(out: &BuildOutput) -> Vec<String> {
    out.config["proxies"]
        .as_array()
        .expect("proxies")
        .iter()
        .filter_map(|p| p["name"].as_str().map(str::to_owned))
        .collect()
}

/// B1 / B4 / B31: an HTTP "HK" before a vless "HK". Dart's pool called the
/// vless line "HK 2", its config "HK"; the subscription's rule to "HK"
/// mapped to the pool's "HK 2", which the config did not know: dropped.
#[test]
fn b1_one_tag_scheme() {
    let v = input(
        &json!([http("HK", "h"), vless("HK", "a"), vless("JP", "b")]),
        &json!({
            "groups": [{"n": "🚀 节点选择", "t": "select", "m": ["HK", "JP"]}],
            "rules": ["DOMAIN,x.example,HK", "MATCH,🚀 节点选择"],
        }),
        &json!({}),
    );
    let out = run(&v);
    assert_eq!(out.pool.tags, ["HK", "JP"]);
    assert_eq!(out.pool.unsupported, 1);
    // The config's proxies are the pool's tags.
    assert_eq!(proxy_names(&out), out.pool.tags);
    // Every line member of every group (tree and config) is a pool tag.
    for g in &out.tree.groups {
        for m in &g.members {
            if !(m.contains(':')
                || m.contains('~')
                || ["DIRECT", "REJECT", "proxy", "auto"].contains(&m.as_str()))
            {
                assert!(out.pool.tags.contains(m), "{} has {m}", g.tag);
            }
        }
    }
    let hk = out.tree.by_tag("region:HK").expect("HK group");
    assert!(hk.members.contains(&"HK".to_owned()));
    // The subscription's rule survives.
    assert!(
        config_rules(&out).contains(&"DOMAIN,x.example,HK".to_owned()),
        "{:?}",
        config_rules(&out)
    );
    assert!(out.rules.contains(&"DOMAIN,x.example,HK".to_owned()));
}

/// B2: with 完全按订阅 (`group_mode = subscription`) in global mode, Dart's
/// screen showed our layers (no split outside smart mode) while the core
/// ran the provider's groups. Now one tree: the config's groups are the
/// tree's.
#[test]
fn b2_screen_tree_is_the_config_tree() {
    let v = input(
        &json!([vless("HK 01", "a"), vless("JP 01", "b")]),
        &json!({
            "groups": [
                {"n": "🚀 节点选择", "t": "select", "m": ["AUTO", "HK 01", "JP 01"]},
                {"n": "AUTO", "t": "url-test", "m": ["HK 01", "JP 01"]},
            ],
            "rules": ["MATCH,🚀 节点选择"],
        }),
        &json!({"mode": "global", "group_mode": "subscription"}),
    );
    let out = run(&v);
    let tags: Vec<&str> = out.tree.groups.iter().map(|g| g.tag.as_str()).collect();
    assert_eq!(tags, ["proxy", "sub:AUTO"]);
    assert_eq!(config_group_names(&out), tags);
}

fn config_group_names(out: &BuildOutput) -> Vec<&str> {
    out.config["proxy-groups"]
        .as_array()
        .expect("groups")
        .iter()
        .filter_map(|g| g["name"].as_str())
        .filter(|n| *n != "speedtest")
        .collect()
}

/// B3: the split follows the settings it is given (the ones in force), not
/// the input's saved ones: Dart's 分组默认 preview built the split from the
/// raw settings, so with built-in groups off in the preview a provider's
/// "🎥 Netflix" still merged into 🎥 NETFLIX.
#[test]
fn b3_split_reads_the_settings_in_force() {
    let v = input(
        &json!([vless("US 01", "a"), vless("JP 01", "b")]),
        &json!({
            "groups": [
                {"n": "🚀 节点选择", "t": "select", "m": ["US 01", "JP 01"]},
                {"n": "🎥 Netflix", "t": "select", "m": ["US 01"]},
            ],
            "rules": ["DOMAIN-SUFFIX,nflx.example,🎥 Netflix", "MATCH,🚀 节点选择"],
        }),
        &json!({}),
    );
    let input = BuildInput::from_json(&v);
    let pool = meow_paopao::build_pool(&input.pool_input());
    let mut s = input.effective();
    let on = meow_paopao::imported_split(&input, &pool, &s);
    assert_eq!(on.rules, ["DOMAIN-SUFFIX,nflx.example,policy:netflix"]);
    s.built_in_groups = false;
    let off = meow_paopao::imported_split(&input, &pool, &s);
    assert_eq!(off.rules, ["DOMAIN-SUFFIX,nflx.example,sub:🎥 Netflix"]);
}

/// B30: the route API's SSH policies come from the settings in force, like
/// the config's chains: every `ssh-…` policy targets a chain the config has.
#[test]
fn b30_route_policies_follow_the_config() {
    let v = input(
        &json!([vless("US 01", "a")]),
        &json!({}),
        &json!({"ssh": [{"id": "c1", "name": "jump", "hops": [{"host": "h", "user": "u"}]}]}),
    );
    let out = run(&v);
    let ssh: Vec<&str> = out
        .route_policies
        .iter()
        .filter(|p| p.kind == "ssh")
        .map(|p| p.target.as_str())
        .collect();
    assert_eq!(ssh, ["ssh:c1"]);
    assert!(proxy_names(&out).iter().any(|n| n.starts_with("ssh:c1")));
}

/// B28: the rule list (rules page, conflict check) is the config's, MITM
/// rules included. Dart built it with no MITM port: a module opening
/// `api.example.com` sent it to `paopao-mitm` in the core, but the rules
/// page did not show it.
#[test]
fn b28_rules_are_the_configs() {
    let mut v = input(&json!([vless("US 01", "a")]), &json!({}), &json!({}));
    v["modules"] = json!([{
        "id": "m", "url": "https://m.example/a.sgmodule", "enabled": true,
        "spec": {"name": "m", "scripts": [], "rewrites": [
            {"pattern": "^https://api\\.example\\.com/x", "action": {"op": "reject", "kind": "plain"}}
        ], "hostnames": ["api.example.com"], "rules": ["DOMAIN,ad.example.com,REJECT"]},
    }]);
    v["runtime"]["mitmPort"] = json!(3);
    v["runtime"]["route"] = json!({"key": "k"});
    let out = run(&v);
    let mitm = "AND,((DOMAIN,api.example.com),(NOT,((IN-NAME,mitm-return)))),paopao-mitm";
    assert!(out.rules.iter().any(|r| r == mitm), "{:?}", out.rules);
    assert!(out
        .rules
        .iter()
        .any(|r| r == "DOMAIN,ad.example.com,REJECT"));
    let want: Vec<String> = config_rules(&out)
        .into_iter()
        .filter(|r| !r.starts_with("IN-USER,") && !r.starts_with("IN-NAME,"))
        .collect();
    assert_eq!(out.rules, want);
}

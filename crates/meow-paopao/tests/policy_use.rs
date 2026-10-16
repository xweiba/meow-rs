//! A policy's own use of a shared group (`policy_use`) and its 固定出口
//! switch, on the whole build: the user's two examples (AI on 美国's line
//! 1, YouTube on 美国 速度最快) and AI's 固定出口 from before.

use meow_paopao::{build, BuildInput, BuildOutput};
use serde_json::{json, Value};

fn vless(name: &str, server: &str) -> Value {
    json!({"name": name, "outbound": {"type": "vless", "server": server, "server_port": 443, "uuid": "u"}})
}

/// 美国 with three lines, 日本 with two, 香港 with one; `settings` merged
/// over smart mode's defaults.
fn input(settings: &Value) -> Value {
    let nodes = json!([
        vless("美国 1", "u1"),
        vless("美国 2", "u2"),
        vless("美国 3", "u3"),
        vless("日本 1", "j1"),
        vless("日本 2", "j2"),
        vless("香港 1", "h1"),
    ]);
    let mut s = json!({"mode": "smart", "selected": "auto", "mixed_port": 7890, "rules": []});
    if let (Some(s), Some(extra)) = (s.as_object_mut(), settings.as_object()) {
        for (k, v) in extra {
            s.insert(k.clone(), v.clone());
        }
    }
    json!({
        "subscriptions": [{"id": "s", "url": "https://a.example", "name": "a", "nodes": nodes, "split": {}}],
        "settings": s,
        "network": {"kind": "wifi", "ssid": "home", "addresses": []},
        "now": 1_791_563_444_034_i64,
        "runtime": {"controllerPort": 1, "secret": "x", "speedTestPort": 2},
    })
}

fn run(settings: &Value) -> BuildOutput {
    build(&BuildInput::from_json(&input(settings)))
}

/// The config's `proxy-groups` entry named `name`.
fn group(out: &BuildOutput, name: &str) -> Value {
    out.config["proxy-groups"]
        .as_array()
        .expect("groups")
        .iter()
        .find(|g| g["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("no group {name}"))
}

fn has_group(out: &BuildOutput, name: &str) -> bool {
    out.config["proxy-groups"]
        .as_array()
        .expect("groups")
        .iter()
        .any(|g| g["name"] == name)
}

/// The tree's group `tag` as JSON.
fn tree(out: &BuildOutput, tag: &str) -> Value {
    out.tree
        .by_tag(tag)
        .unwrap_or_else(|| panic!("no tree group {tag}"))
        .to_json()
}

const US: &str = "region:US";

#[test]
fn the_users_two_examples() {
    let out = run(&json!({
        "policies": {"policy:ai": US, "policy:youtube": US},
        "policy_use": {
            "policy:ai": {"groups": {US: {"use": "line", "line": "美国 1"}}},
            "policy:youtube": {"groups": {US: {"use": "fastest"}}},
        },
    }));
    // AI: a selector of its own over 美国's members, on line 1.
    let ai = group(&out, "policy:ai");
    assert_eq!(ai["type"], "select");
    assert_eq!(ai["proxies"][0], "policy:ai@region:US");
    assert_eq!(
        group(&out, "policy:ai@region:US"),
        json!({"name": "policy:ai@region:US", "type": "select", "proxies": [
            "美国 1", "region:US~auto", "region:US~balance", "region:US~fastest", "美国 2", "美国 3"]})
    );
    // YouTube: 速度最快 of its own over 美国's lines.
    let yt = group(&out, "policy:youtube");
    assert_eq!(yt["proxies"][0], "policy:youtube@region:US~fastest");
    assert_eq!(
        group(&out, "policy:youtube@region:US~fastest"),
        json!({"name": "policy:youtube@region:US~fastest", "type": "smart",
            "proxies": ["美国 1", "美国 2", "美国 3"], "strategy": "throughput",
            "url": "https://www.gstatic.com/generate_204"})
    );
    // 美国 itself keeps its own default, and so does every other policy.
    assert_eq!(group(&out, US)["proxies"][0], "region:US~auto");
    let netflix = group(&out, "policy:netflix");
    assert!(netflix["proxies"].as_array().unwrap().contains(&json!(US)));
    // The tree says what each copy stands for, and names it so.
    assert_eq!(
        tree(&out, "policy:ai@region:US"),
        json!({"tag": "policy:ai@region:US", "label": "🇺🇸 美国 · 美国 1", "kind": "select",
            "members": ["region:US~auto", "region:US~balance", "region:US~fastest",
                "美国 1", "美国 2", "美国 3"],
            "pick": "美国 1", "card": false, "origin": US})
    );
    assert_eq!(
        tree(&out, "policy:youtube@region:US~fastest")["label"],
        "🇺🇸 美国 · 速度最快"
    );
    assert_eq!(out.tree.plain_members("policy:ai"), {
        let mut m = out.tree.by_tag("policy:ai").unwrap().members.clone();
        for x in &mut m {
            if x == "policy:ai@region:US" {
                *x = US.into();
            }
        }
        m
    });
}

#[test]
fn ai_keeps_its_sticky_exit_from_before_with_no_setting() {
    // Nothing saved: AI on 美国, 智能选择 there, 固定出口 on.
    let out = run(&json!({}));
    assert_eq!(
        group(&out, "policy:ai")["proxies"][0],
        "policy:ai@region:US~sticky"
    );
    assert_eq!(
        group(&out, "policy:ai@region:US~sticky"),
        json!({"name": "policy:ai@region:US~sticky", "type": "smart",
            "proxies": ["美国 1", "美国 2", "美国 3"], "strategy": "sticky",
            "url": "https://www.gstatic.com/generate_204"})
    );
    assert!(!has_group(&out, "policy:ai~sticky"));
    // 固定出口 picked by hand back when it was a member: the same.
    let old = run(&json!({"policies": {"policy:ai": "policy:ai~sticky"}}));
    assert_eq!(group(&old, "policy:ai"), group(&out, "policy:ai"));
    // Switched off: 美国 as it decides.
    let off = run(&json!({"policy_use": {"policy:ai": {"sticky": false}}}));
    assert_eq!(group(&off, "policy:ai")["proxies"][0], US);
    assert!(!has_group(&off, "policy:ai@region:US~sticky"));
}

#[test]
fn sticky_goes_with_the_mode_the_policy_uses() {
    // 速度最快 chosen with 固定出口 on: the sticky smart group over the
    // same lines (the core has no sticky 速度最快).
    let out = run(&json!({"policy_use": {"policy:ai": {"groups": {US: {"use": "fastest"}}}}}));
    assert_eq!(
        group(&out, "policy:ai")["proxies"][0],
        "policy:ai@region:US~sticky"
    );
    assert_eq!(
        group(&out, "policy:ai@region:US~sticky")["strategy"],
        "sticky"
    );
    assert_eq!(
        tree(&out, "policy:ai@region:US~sticky")["label"],
        "🇺🇸 美国 · 速度最快 · 固定出口"
    );
    // One line chosen: nothing for 固定出口 to choose.
    let out = run(&json!({"policy_use": {"policy:ai": {"sticky": true,
        "groups": {US: {"use": "line", "line": "美国 2"}}}}}));
    assert_eq!(
        group(&out, "policy:ai")["proxies"][0],
        "policy:ai@region:US"
    );
    assert_eq!(group(&out, "policy:ai@region:US")["proxies"][0], "美国 2");
    // 美国's own default is one line: AI follows it, no 固定出口 either.
    let out = run(&json!({"group_pick": {US: "美国 3"}}));
    assert_eq!(group(&out, "policy:ai")["proxies"][0], US);
    // YouTube on its built-in 速度最快 of every line, switched on.
    let out = run(&json!({"policy_use": {"policy:youtube": {"sticky": true}}}));
    let t = "policy:youtube@auto~fastest~sticky";
    assert_eq!(group(&out, "policy:youtube")["proxies"][0], t);
    assert_eq!(group(&out, t)["proxies"].as_array().unwrap().len(), 6);
    assert_eq!(tree(&out, t)["short"], "速度最快 · 固定出口");
    assert_eq!(tree(&out, t)["origin"], "auto~fastest");
}

#[test]
fn what_the_group_does_not_offer_is_its_default() {
    let out = run(&json!({
        "policies": {"policy:netflix": "region:HK"},
        "policy_use": {"policy:netflix": {"groups": {
            // One line: no modes.
            "region:HK": {"use": "balance"},
            // Not one of 日本's lines.
            "region:JP": {"use": "line", "line": "美国 1"},
        }}},
    }));
    assert_eq!(group(&out, "policy:netflix")["proxies"][0], "region:HK");
    assert!(!out
        .tree
        .groups
        .iter()
        .any(|g| g.tag.starts_with("policy:netflix@")));
}

#[test]
fn without_any_use_the_config_is_as_before() {
    let plain = run(&json!({"policy_use": {"policy:ai": {"sticky": false}}}));
    let same = run(&json!({"policies": {"policy:ai": US}}));
    assert_eq!(plain.config, same.config);
    assert!(!plain.tree.groups.iter().any(|g| g.origin.is_some()));
}

#[test]
fn the_users_own_group_takes_a_use_too() {
    let out = run(&json!({
        "custom_groups": [{"id": "g1", "name": "工作", "pick": "region:JP"}],
        "policy_use": {"group:g1": {"sticky": true, "groups": {"region:JP": {"use": "balance"}}}},
    }));
    assert_eq!(
        group(&out, "group:g1")["proxies"][0],
        "group:g1@region:JP~sticky"
    );
    let off = run(&json!({
        "custom_groups": [{"id": "g1", "name": "工作", "pick": "region:JP"}],
        "policy_use": {"group:g1": {"groups": {"region:JP": {"use": "balance"}}}},
    }));
    assert_eq!(
        group(&off, "group:g1")["proxies"][0],
        "group:g1@region:JP~balance"
    );
    assert_eq!(
        group(&off, "group:g1@region:JP~balance")["strategy"],
        "consistent-hashing"
    );
}

#[test]
fn sticky_follows_the_selectors_down_to_the_automatic_group_in_use() {
    // YouTube on 节点选择, which is on ♻️ 自动选择, on its 智能选择: the
    // sticky copy goes over 智能选择's lines.
    let out = run(&json!({
        "policies": {"policy:youtube": "proxy"},
        "policy_use": {"policy:youtube": {"sticky": true}},
    }));
    let t = "policy:youtube@proxy~sticky";
    assert_eq!(group(&out, "policy:youtube")["proxies"][0], t);
    assert_eq!(group(&out, t)["type"], "smart");
    assert_eq!(group(&out, t)["strategy"], "sticky");
    assert_eq!(
        group(&out, t)["proxies"],
        group(&out, "auto~smart")["proxies"]
    );
    assert_eq!(group(&out, t)["proxies"].as_array().unwrap().len(), 6);
    assert_eq!(tree(&out, t)["origin"], "proxy");
    assert_eq!(
        tree(&out, t)["label"],
        "🚀 节点选择 · ♻️ 自动选择 · 智能选择 · 固定出口"
    );
    // 节点选择 and every other policy as they were.
    assert_eq!(
        out.tree.by_tag("proxy").unwrap().pick.as_deref(),
        Some("auto")
    );
    assert!(group(&out, "policy:netflix")["proxies"]
        .as_array()
        .unwrap()
        .contains(&json!("proxy")));

    // 节点选择 on 美国, whose default is 速度最快: over 美国's lines.
    let out = run(&json!({
        "selected": US,
        "group_pick": {US: "region:US~fastest"},
        "policies": {"policy:youtube": "proxy"},
        "policy_use": {"policy:youtube": {"sticky": true}},
    }));
    assert_eq!(group(&out, "policy:youtube")["proxies"][0], t);
    assert_eq!(
        group(&out, t)["proxies"],
        json!(["美国 1", "美国 2", "美国 3"])
    );
    assert_eq!(group(&out, t)["strategy"], "sticky");
    assert_eq!(
        tree(&out, t)["label"],
        "🚀 节点选择 · 🇺🇸 美国 · 速度最快 · 固定出口"
    );
}

#[test]
fn sticky_has_nothing_to_keep_on_one_line_or_direct() {
    for (settings, why) in [
        (json!({"selected": "美国 2"}), "节点选择 on one line"),
        (json!({"selected": "DIRECT"}), "节点选择 直连"),
        (
            json!({"group_pick": {"auto": "region:HK"}}),
            "自动选择 on 香港's one line",
        ),
    ] {
        let mut s = settings;
        s["policies"] = json!({"policy:youtube": "proxy"});
        s["policy_use"] = json!({"policy:youtube": {"sticky": true}});
        let out = run(&s);
        assert_eq!(
            group(&out, "policy:youtube")["proxies"][0],
            "proxy",
            "{why}"
        );
        assert!(
            !out.tree
                .groups
                .iter()
                .any(|g| g.tag.starts_with("policy:youtube@")),
            "{why}"
        );
    }
}

#[test]
fn the_users_own_group_follows_the_selectors_too() {
    let on = json!({
        "custom_groups": [{"id": "g1", "name": "工作", "pick": "proxy"}],
        "policy_use": {"group:g1": {"sticky": true}},
    });
    let out = run(&on);
    let t = "group:g1@proxy~sticky";
    assert_eq!(group(&out, "group:g1")["proxies"][0], t);
    assert_eq!(group(&out, t)["proxies"].as_array().unwrap().len(), 6);
    assert_eq!(group(&out, t)["strategy"], "sticky");
    // On one line: none.
    let mut one = on;
    one["selected"] = json!("日本 1");
    let out = run(&one);
    assert_eq!(group(&out, "group:g1")["proxies"][0], "proxy");
    assert!(!has_group(&out, t));
}

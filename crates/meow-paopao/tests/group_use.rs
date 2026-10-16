//! A 策略组's own use of a shared group among its members (`group_use`)
//! and a policy's 固定出口 switch, on the whole build: the user's two
//! examples (AI on 美国's line 1, YouTube on 美国 速度最快), AI's 固定出口
//! from before, and 自动选择 / 节点选择 using 香港 their own way.

use meow_paopao::{build, BuildInput, BuildOutput};
use serde_json::{json, Value};

fn vless(name: &str, server: &str) -> Value {
    json!({"name": name, "outbound": {"type": "vless", "server": server, "server_port": 443, "uuid": "u"}})
}

/// 美国 with three lines, 日本 with two, 香港 with one; `settings` merged
/// over smart mode's defaults.
fn input(settings: &Value) -> Value {
    input_over(&[], settings)
}

/// [`input`] with `more` lines too.
fn input_over(more: &[(&str, &str)], settings: &Value) -> Value {
    let mut nodes = vec![
        vless("美国 1", "u1"),
        vless("美国 2", "u2"),
        vless("美国 3", "u3"),
        vless("日本 1", "j1"),
        vless("日本 2", "j2"),
        vless("香港 1", "h1"),
    ];
    nodes.extend(more.iter().map(|(n, h)| vless(n, h)));
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

/// [`run`] with 香港 on two lines.
fn run_hk2(settings: &Value) -> BuildOutput {
    build(&BuildInput::from_json(&input_over(
        &[("香港 2", "h2")],
        settings,
    )))
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
        "group_use": {
            "policy:ai": {"members": {US: {"use": "line", "line": "美国 1"}}},
            "policy:youtube": {"members": {US: {"use": "fastest"}}},
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
            "members": ["美国 1", "美国 2", "美国 3"],
            "modes": ["region:US~auto", "region:US~balance", "region:US~fastest"],
            "pick": "美国 1", "card": false, "origin": US})
    );
    assert_eq!(
        tree(&out, "policy:youtube@region:US~fastest")["label"],
        "🇺🇸 美国 · 速度最快"
    );
    // AI's own 自动选择 (without 香港, in 其他地区 here) shows as 自动选择.
    assert_eq!(
        out.tree.by_tag("policy:ai").unwrap().members,
        [
            "DIRECT",
            "REJECT",
            "policy:ai@auto~auto",
            "region:JP",
            "policy:ai@region:US"
        ]
    );
    assert_eq!(
        out.tree.plain_members("policy:ai"),
        ["DIRECT", "REJECT", "auto", "region:JP", US]
    );
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
    let off = run(&json!({"group_use": {"policy:ai": {"sticky": false}}}));
    assert_eq!(group(&off, "policy:ai")["proxies"][0], US);
    assert!(!has_group(&off, "policy:ai@region:US~sticky"));
}

#[test]
fn sticky_goes_with_the_mode_the_group_uses() {
    // 速度最快 chosen with 固定出口 on: the sticky smart group over the
    // same lines (the core has no sticky 速度最快).
    let out = run(&json!({"group_use": {"policy:ai": {"members": {US: {"use": "fastest"}}}}}));
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
        "🇺🇸 美国 · 速度最快 · 固定节点"
    );
    // One line chosen: nothing for 固定出口 to choose.
    let out = run(&json!({"group_use": {"policy:ai": {"sticky": true,
        "members": {US: {"use": "line", "line": "美国 2"}}}}}));
    assert_eq!(
        group(&out, "policy:ai")["proxies"][0],
        "policy:ai@region:US"
    );
    assert_eq!(group(&out, "policy:ai@region:US")["proxies"][0], "美国 2");
    // 美国's own default is one line: AI follows it, no 固定出口 either.
    let out = run(&json!({"group_pick": {US: "美国 3"}}));
    assert_eq!(group(&out, "policy:ai")["proxies"][0], US);
    // YouTube on 自动选择, its built-in 速度最快 there, switched on.
    let out = run(&json!({"group_use": {"policy:youtube": {"sticky": true}}}));
    let t = "policy:youtube@auto~sticky";
    assert_eq!(group(&out, "policy:youtube")["proxies"][0], t);
    assert_eq!(group(&out, t)["proxies"].as_array().unwrap().len(), 6);
    assert_eq!(tree(&out, t)["label"], "♻️ 自动选择 · 速度最快 · 固定节点");
    assert_eq!(tree(&out, t)["origin"], "auto");
    assert!(!has_group(&out, "policy:youtube@auto~fastest"));
}

#[test]
fn what_the_group_does_not_offer_is_its_default() {
    let out = run(&json!({
        "policies": {"policy:netflix": "region:other"},
        "group_use": {"policy:netflix": {"members": {
            // One line (香港's, in 其他地区): no modes.
            "region:other": {"use": "balance"},
            // Not one of 日本's lines.
            "region:JP": {"use": "line", "line": "美国 1"},
        }}},
    }));
    assert_eq!(group(&out, "policy:netflix")["proxies"][0], "region:other");
    assert!(!out
        .tree
        .groups
        .iter()
        .any(|g| g.tag.starts_with("policy:netflix@")));
}

#[test]
fn without_any_use_the_config_is_as_before() {
    let plain = run(&json!({"group_use": {"policy:ai": {"sticky": false}}}));
    let same = run(&json!({"policies": {"policy:ai": US}}));
    assert_eq!(plain.config, same.config);
    // Only the built-in copies: YouTube's 自动选择 on 速度最快, AI's and
    // Google's own 自动选择 without 香港.
    let mut copies: Vec<&str> = plain
        .tree
        .groups
        .iter()
        .filter(|g| g.origin.is_some())
        .map(|g| g.tag.as_str())
        .collect();
    copies.sort_unstable();
    assert_eq!(
        copies,
        [
            "policy:ai@auto~auto",
            "policy:google@auto~auto",
            "policy:youtube@auto~fastest"
        ]
    );
}

#[test]
fn the_users_own_group_takes_a_use_too() {
    let out = run(&json!({
        "custom_groups": [{"id": "g1", "name": "工作", "pick": "region:JP"}],
        "group_use": {"group:g1": {"sticky": true, "members": {"region:JP": {"use": "balance"}}}},
    }));
    assert_eq!(
        group(&out, "group:g1")["proxies"][0],
        "group:g1@region:JP~sticky"
    );
    let off = run(&json!({
        "custom_groups": [{"id": "g1", "name": "工作", "pick": "region:JP"}],
        "group_use": {"group:g1": {"members": {"region:JP": {"use": "balance"}}}},
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
        "group_use": {"policy:youtube": {"sticky": true}},
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
        "🚀 节点选择 · ♻️ 自动选择 · 智能选择 · 固定节点"
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
        "group_use": {"policy:youtube": {"sticky": true}},
    }));
    assert_eq!(group(&out, "policy:youtube")["proxies"][0], t);
    assert_eq!(
        group(&out, t)["proxies"],
        json!(["美国 1", "美国 2", "美国 3"])
    );
    assert_eq!(group(&out, t)["strategy"], "sticky");
    assert_eq!(
        tree(&out, t)["label"],
        "🚀 节点选择 · 🇺🇸 美国 · 速度最快 · 固定节点"
    );
}

#[test]
fn sticky_has_nothing_to_keep_on_one_line_or_direct() {
    for (settings, why) in [(json!({"selected": "美国 2"}), "节点选择 on one line")] {
        let mut s = settings;
        s["policies"] = json!({"policy:youtube": "proxy"});
        s["group_use"] = json!({"policy:youtube": {"sticky": true}});
        let out = run(&s);
        assert_eq!(
            group(&out, "policy:youtube")["proxies"][0],
            "proxy",
            "{why}"
        );
        assert!(!has_group(&out, "policy:youtube@proxy~sticky"), "{why}");
    }
}

#[test]
fn the_users_own_group_follows_the_selectors_too() {
    let on = json!({
        "custom_groups": [{"id": "g1", "name": "工作", "pick": "proxy"}],
        "group_use": {"group:g1": {"sticky": true}},
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

const HK: &str = "region:HK";

#[test]
fn auto_offers_its_modes_only_never_a_region_or_a_line() {
    // A region picked and used on one line, saved by hand: neither is read.
    let out = run_hk2(&json!({
        "group_pick": {"auto": HK},
        "group_use": {"auto": {"members": {HK: {"use": "line", "line": "香港 2"}}}},
    }));
    assert_eq!(
        group(&out, "auto")["proxies"],
        json!(["auto~smart", "auto~balance", "auto~fastest"])
    );
    assert!(!out.tree.groups.iter().any(|g| g.tag.starts_with("auto@")));
    // Its mode is its one choice.
    let out = run_hk2(&json!({"group_pick": {"auto": "auto~fastest"}}));
    assert_eq!(group(&out, "auto")["proxies"][0], "auto~fastest");
    // 香港 itself, 节点选择 and the policies keep 香港 as it decides.
    assert_eq!(group(&out, HK)["proxies"][0], "region:HK~auto");
    assert!(group(&out, "proxy")["proxies"]
        .as_array()
        .unwrap()
        .contains(&json!(HK)));
}

#[test]
fn proxy_uses_its_members_its_own_way_too() {
    let out = run_hk2(&json!({
        "selected": HK,
        "group_use": {"proxy": {"members": {
            HK: {"use": "balance"},
            "auto": {"use": "fastest"},
        }}},
    }));
    let proxy = group(&out, "proxy");
    assert_eq!(proxy["proxies"][0], "proxy@region:HK~balance");
    assert!(proxy["proxies"]
        .as_array()
        .unwrap()
        .contains(&json!("proxy@auto~fastest")));
    assert_eq!(
        group(&out, "proxy@auto~fastest")["proxies"],
        group(&out, "auto~fastest")["proxies"]
    );
    assert_eq!(
        tree(&out, "proxy@auto~fastest")["label"],
        "♻️ 自动选择 · 速度最快"
    );
    assert_eq!(
        group(&out, "proxy@region:HK~balance")["strategy"],
        "consistent-hashing"
    );
    // 节点选择's pick is its copy of the member picked.
    assert_eq!(
        out.tree.by_tag("proxy").unwrap().pick.as_deref(),
        Some("proxy@region:HK~balance")
    );
    // 节点选择 never gets a 固定出口 of its own.
    let on = run_hk2(&json!({"group_use": {"proxy": {"sticky": true}}}));
    assert!(!on.tree.groups.iter().any(|g| g.tag.starts_with("proxy@")));
}

#[test]
fn nested_uses_each_see_what_the_member_really_uses() {
    // 节点选择 on 自动选择 (速度最快), 香港 used its own way there; YouTube
    // on 节点选择 with 固定出口; Netflix on 自动选择's 速度最快 of its own.
    let settings = json!({
        "selected": "auto",
        "group_pick": {"auto": "auto~smart"},
        "policies": {"policy:youtube": "proxy", "policy:netflix": "auto"},
        "group_use": {
            "proxy": {"members": {HK: {"use": "fastest"}}},
            "policy:youtube": {"sticky": true},
            "policy:netflix": {"members": {"auto": {"use": "fastest"}}},
        },
    });
    let out = run_hk2(&settings);
    // Each user its own copy, none of another's.
    assert_eq!(group(&out, "auto")["proxies"][0], "auto~smart");
    assert!(group(&out, "proxy")["proxies"]
        .as_array()
        .unwrap()
        .contains(&json!("proxy@region:HK~fastest")));
    assert_eq!(group(&out, "proxy")["proxies"][0], "auto");
    // YouTube follows 节点选择 → 自动选择 → 智能选择: 固定出口 over every line.
    let t = "policy:youtube@proxy~sticky";
    assert_eq!(group(&out, "policy:youtube")["proxies"][0], t);
    assert_eq!(group(&out, t)["strategy"], "sticky");
    assert_eq!(group(&out, t)["proxies"].as_array().unwrap().len(), 7);
    // Netflix: 自动选择's 速度最快, over every line.
    assert_eq!(
        group(&out, "policy:netflix")["proxies"][0],
        "policy:netflix@auto~fastest"
    );
    assert_eq!(
        group(&out, "policy:netflix@auto~fastest")["proxies"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    // The same settings, the same config; every copy a known group, and
    // no loop cut.
    assert_eq!(run_hk2(&settings).config, out.config);
    assert!(out.tree.loops.is_empty());
    for g in out.tree.groups.iter().filter(|g| g.origin.is_some()) {
        for m in &g.members {
            assert!(!m.starts_with(&g.tag), "{} in {}", m, g.tag);
        }
    }
}

#[test]
fn a_subscription_group_uses_its_sub_groups() {
    let split = json!({"groups": [
        {"n": "Main", "t": "select", "m": ["Pick", "日本 1"]},
        {"n": "Pick", "t": "select", "m": ["美国 1", "美国 2"]},
    ], "rules": ["DOMAIN-SUFFIX,x.example,Main", "MATCH,DIRECT"]});
    let settings = |uses: Value| {
        let mut i = input(&json!({"group_use": uses}));
        i["subscriptions"][0]["split"] = split.clone();
        build(&BuildInput::from_json(&i))
    };
    let plain = settings(json!({}));
    let main = plain
        .tree
        .groups
        .iter()
        .find(|g| g.label == "Main")
        .expect("Main")
        .tag
        .clone();
    let pick = plain
        .tree
        .groups
        .iter()
        .find(|g| g.label == "Pick")
        .expect("Pick")
        .tag
        .clone();
    let out = settings(json!({&main: {"members": {&pick: {"use": "line", "line": "美国 2"}}}}));
    let copy = format!("{main}@{pick}");
    assert!(group(&out, &main)["proxies"]
        .as_array()
        .unwrap()
        .contains(&json!(copy)));
    assert_eq!(group(&out, &copy)["proxies"][0], "美国 2");
    assert_eq!(tree(&out, &copy)["origin"], json!(pick));
}

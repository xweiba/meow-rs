//! Unit tests for the plan layer: ported from `group_tree_test.dart`,
//! `custom_groups_test.dart` and `sub_rules_test.dart`, plus matcher
//! tables whose expectations were printed by the Dart code (VM 3.x).

use indexmap::IndexMap;

use super::custom_groups::{exclude_entry, exclude_match, split_sites};
use super::group_defaults::group_default_choices_in;
use super::group_tree::{group_child, BADGE_BUILT_IN, BADGE_CUSTOM, OTHER_REGION_TAG};
use super::*;
use crate::model::settings::{
    is_extra_outlet, CustomGroup, GroupDefault, GroupDefaultKind, GroupEdit, GroupStrategy,
    RuleMatch,
};
use crate::model::subscription::{SubGroup, SubRules};
use crate::parse_subscription;
use crate::pool::NodeGroup;

fn s(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|x| (*x).to_owned()).collect()
}

fn map(kv: &[(&str, &str)]) -> IndexMap<String, String> {
    kv.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

// ------------------------------------------------------------- matchers

/// Our policy for a provider group name, as `_ourGroupFor`'s alias step.
fn alias_of(name: &str) -> Option<String> {
    POLICIES
        .iter()
        .find(|p| !p.base && p.alias_matches(name))
        .map(Policy::tag)
}

/// `policies.where(!base && aliases match).first?.tag`. Rows marked B20 /
/// B21 differ from Dart on purpose: English aliases are whole words now.
#[test]
fn aliases_match_whole_words() {
    let ads = Some("policy:ads");
    let ai = Some("policy:ai");
    let tg = Some("policy:telegram");
    let media = Some("policy:media");
    let table: &[(&str, Option<&str>)] = &[
        ("🛑 广告拦截", ads),
        ("AdBlock", ads),
        ("Ads", ads),
        ("ads", ads),
        ("ad", ads),
        ("AD 屏蔽", ads),
        ("📢 Ads-Block", ads),
        // B20: Dart's `ads?\b` had no leading boundary.
        ("Download", None),
        ("Downloads", None),
        ("iPad Pro", None),
        ("Trinidad", None),
        ("roads", None),
        ("adsl", None),
        ("Ad_s", None),
        ("ADS!", ads),
        ("🤖 AI", ai),
        ("AI服务", ai),
        ("ai-tools", ai),
        ("OpenAI", ai),
        ("Mail", None),
        ("AIR", None),
        ("x_ai", None),
        ("ai2", None),
        ("🌐 Ai 平台", ai),
        ("Claude", ai),
        ("Grok", ai),
        ("tg", tg),
        ("TG频道", tg),
        ("stg", None),
        ("tg_bot", None),
        ("TG-1", tg),
        ("TG电报", tg),
        ("📲 Telegram", tg),
        // B21: a letter of another alphabet is part of the word.
        ("ſtg", None),
        ("tgé", None),
        ("Телеграм TG", tg),
        ("Global Media", media),
        ("globalmedia", media),
        ("Global  Media", None),
        ("GLOBAL MEDIA", media),
        ("Streaming", media),
        ("Bing", Some("policy:microsoft")),
        ("必应 Bing", Some("policy:microsoft")),
        // B21: aliases were substrings.
        ("Harbing", None),
        ("Switch", Some("policy:games")),
        ("Nintendo Switch", Some("policy:games")),
        ("Switcher", None),
        ("🎮 Game", Some("policy:games")),
        ("🎮 Games", Some("policy:games")),
        ("Endgame", None),
        ("Epic", Some("policy:games")),
        ("Epicure", None),
        ("Apple", Some("policy:apple")),
        ("iCloud", Some("policy:apple")),
        ("HBO", media),
        ("HBO Max", media),
        ("Ashbourne", None),
        ("YouTube", Some("policy:youtube")),
        ("油管", Some("policy:youtube")),
        ("Netflix", Some("policy:netflix")),
        ("🎥 NETFLIX", Some("policy:netflix")),
        ("🎥 奈飞视频", Some("policy:netflix")),
        ("网飞", Some("policy:netflix")),
        ("国内媒体", Some("policy:cnmedia")),
        ("GitHub", Some("policy:dev")),
        ("开发者", Some("policy:dev")),
        ("其他", None),
        ("🇭🇰 香港", None),
        ("🚀 节点选择", None),
        ("Proxy", None),
        ("K", None),
        ("ﬀ", None),
        ("ĳ", None),
    ];
    for (name, want) in table {
        assert_eq!(alias_of(name).as_deref(), *want, "{name:?}");
    }
}

#[test]
fn select_and_other_names_like_dart() {
    let select = [
        "🚀 节点选择",
        "Proxy",
        "PROXIES",
        "🚀 Proxy",
        " proxy ",
        "Proxies!!",
        "手动切换",
    ];
    let not_select = [
        "proxy1",
        "my proxy",
        "_proxy_",
        "proxyies",
        "Others",
        "♻️ HK",
        "JP节点",
    ];
    for n in select {
        assert!(is_select_name(n), "{n:?}");
    }
    for n in not_select {
        assert!(!is_select_name(n), "{n:?}");
    }
    let on = ProxySettings::default();
    for n in ["其他", "Others", "OTHER"] {
        assert_eq!(
            our_group_for(n, &on, &[]).as_deref(),
            Some(OTHER_REGION_TAG),
            "{n:?}"
        );
    }
    // A region only when the pool has a group there.
    let hk = [NodeGroup {
        tag: "region:HK".into(),
        label: "🇭🇰 香港".into(),
        members: s(&["HK 1"]),
    }];
    assert_eq!(
        our_group_for("香港自动", &on, &hk).as_deref(),
        Some("region:HK")
    );
    assert_eq!(our_group_for("香港自动", &on, &[]), None);
    // Built-in groups off: no aliases.
    let off = ProxySettings {
        built_in_groups: false,
        ..ProxySettings::default()
    };
    assert_eq!(our_group_for("Netflix", &off, &[]), None);
    assert_eq!(
        our_group_for("Netflix", &on, &[]).as_deref(),
        Some("policy:netflix")
    );
}

#[test]
fn sites_and_excludes_like_dart() {
    for (text, want) in [
        ("a.com b.com", s(&["a.com", "b.com"])),
        (
            "a.com,b.com，c.com、d.com;e.com；f.com",
            s(&["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"]),
        ),
        ("  a.com \n\n a.com\tb.com ", s(&["a.com", "b.com"])),
        ("", vec![]),
        (" , ,", vec![]),
        (
            "x.com\u{3000}y.com\u{a0}z.com\u{feff}w.com",
            s(&["x.com", "y.com", "z.com", "w.com"]),
        ),
    ] {
        assert_eq!(split_sites(text), want, "{text:?}");
    }
    for (entry, m, v) in [
        ("example.com", RuleMatch::Domain, "example.com"),
        ("1.2.3.4", RuleMatch::Ip, "1.2.3.4"),
        ("::1", RuleMatch::Ip, "::1"),
        ("exact:a.com", RuleMatch::Exact, "a.com"),
        ("keyword:chat", RuleMatch::Keyword, "chat"),
        ("ip:10.0.0.0/8", RuleMatch::Ip, "10.0.0.0/8"),
        ("process:Telegram", RuleMatch::Process, "Telegram"),
        (
            "app:path:/Applications/X.app",
            RuleMatch::App,
            "path:/Applications/X.app",
        ),
        ("domain:x", RuleMatch::Domain, "domain:x"),
        ("exactly.com", RuleMatch::Domain, "exactly.com"),
        ("ip:", RuleMatch::Ip, ""),
        ("1.2.3.4/8", RuleMatch::Domain, "1.2.3.4/8"),
        ("fe80::1%1", RuleMatch::Ip, "fe80::1%1"),
    ] {
        assert_eq!(exclude_match(entry), (m, v.to_owned()), "{entry:?}");
    }
    assert_eq!(exclude_entry(RuleMatch::Domain, "a.com"), "a.com");
    assert_eq!(exclude_entry(RuleMatch::Ip, "1.2.3.4"), "1.2.3.4");
    assert_eq!(exclude_entry(RuleMatch::Ip, "10.0.0.0/8"), "ip:10.0.0.0/8");
    assert_eq!(exclude_entry(RuleMatch::Process, "QQ"), "process:QQ");
    assert_eq!(
        exclude_entry(RuleMatch::App, "name:QQ.exe"),
        "app:name:QQ.exe"
    );
}

#[test]
fn rule_lines_parse_like_dart() {
    let rules = SubRules {
        groups: vec![SubGroup {
            name: "G".into(),
            kind: "select".into(),
            members: s(&["n1", "n2"]),
        }],
        rules: s(&[
            " DOMAIN-SUFFIX , a.com , G ",
            "domain,b.com,G,no-resolve",
            "IP-CIDR,1.2.3.0/24,G,No-Resolve,src",
            "AND,((DOMAIN,quic.example),(NETWORK,UDP)),G",
            "# comment,x,G",
            "",
            "DOMAIN,c.com",
            "GEOIP,CN,DIRECT",
            "DOMAIN,d.com,REJECT-DROP",
            "DOMAIN,e.com,PASS",
            "DOMAIN,f.com,nope",
            "FINAL,G",
            "RULE-SET,x,G",
            "DOMAIN-SUFFIX,a.com,DIRECT",
            "src,no-resolve",
            "DOMAIN,g.com,G,src,no-resolve,src",
        ]),
    };
    let line_of = map(&[
        ("n1", "L1"),
        ("n2", "L2"),
        ("n3", "L3"),
        ("n4", "L4"),
        ("n5", "L5"),
    ]);
    let merged = merge_subscription_splits(
        &[SubSplit {
            rules: &rules,
            line_of: &line_of,
        }],
        targets(),
        None,
        false,
    );
    // G is the MATCH (FINAL) target: our 漏网之鱼.
    assert_eq!(
        merged.rules,
        s(&[
            "DOMAIN-SUFFIX,a.com,policy:final",
            "DOMAIN,b.com,policy:final,no-resolve",
            "IP-CIDR,1.2.3.0/24,policy:final,No-Resolve,src",
            "AND,((DOMAIN,quic.example),(NETWORK,UDP)),policy:final",
            "GEOIP,CN,DIRECT",
            "DOMAIN,d.com,REJECT",
            "DOMAIN,e.com,DIRECT",
            "DOMAIN,g.com,policy:final,src,no-resolve,src",
        ])
    );
    assert!(merged.groups.is_empty());
}

// ----------------------------------------------------------- group tree

fn base() -> Vec<NodeGroup> {
    let g = |tag: &str, label: &str, members: &[&str]| NodeGroup {
        tag: tag.into(),
        label: label.into(),
        members: s(members),
    };
    vec![
        g("region:HK", "🇭🇰 香港", &["HK 1", "HK 2"]),
        g("region:US", "🇺🇸 美国", &["US 1", "US 2"]),
        g("region:JP", "🇯🇵 日本", &["JP 1"]),
        g("kind:relay", "🔀 中转", &["HK 2", "US 2"]),
    ]
}

fn lines() -> Vec<String> {
    s(&["HK 1", "HK 2", "US 1", "US 2", "JP 1", "X 1"])
}

fn build(settings: &ProxySettings, split: &ImportedSplit) -> GroupTree {
    let lines = lines();
    let base = base();
    build_group_tree(&TreeInput {
        lines: &lines,
        base: &base,
        settings,
        split,
        extras: &[],
        smart_mode: true,
    })
}

fn build_with(settings: &ProxySettings) -> GroupTree {
    build(settings, &ImportedSplit::default())
}

fn g<'a>(t: &'a GroupTree, tag: &str) -> &'a GroupSpec {
    t.by_tag(tag).unwrap_or_else(|| panic!("no group {tag}"))
}

fn pick(t: &GroupTree, tag: &str) -> String {
    g(t, tag).pick.clone().unwrap_or_default()
}

fn defaults(kv: &[(&str, GroupDefault)]) -> IndexMap<String, GroupDefault> {
    kv.iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

#[test]
fn a_line_switched_off_stays_listed_but_not_automatic() {
    let t = build_with(&ProxySettings {
        disabled_lines: s(&["HK 2"]),
        ..ProxySettings::default()
    });
    let hk = g(&t, "region:HK");
    assert!(hk.members.contains(&"HK 2".into()), "picked by hand here");
    assert!(!hk.members.iter().any(|m| group_child::is_child(m)));
    for x in t.groups.iter().filter(|x| x.kind != GroupKind::Select) {
        assert!(!x.members.contains(&"HK 2".into()), "{}", x.tag);
    }
    let smart = g(&t, outbound_tags::SMART);
    for l in ["HK 1", "US 1", "US 2", "JP 1"] {
        assert!(smart.members.contains(&l.into()));
    }
    let all = build_with(&ProxySettings::default());
    assert!(g(&all, "region:HK")
        .members
        .iter()
        .any(|m| group_child::is_child(m)));
    assert!(g(&all, outbound_tags::SMART)
        .members
        .contains(&"HK 2".into()));
}

#[test]
fn a_user_policy_is_generated_like_the_built_in_ones() {
    let company = CustomGroup {
        id: "co".into(),
        name: "公司".into(),
        extras: s(&["iface:utun6", "ssh:gone"]),
        pick: Some("iface:utun6".into()),
    };
    let t = build_with(&ProxySettings {
        custom_groups: vec![company],
        ..ProxySettings::default()
    });
    let co = g(&t, "group:co");
    let ai = g(&t, "policy:ai");
    assert_eq!(co.label, "公司");
    assert_eq!(co.badge, Some(BADGE_CUSTOM));
    assert_eq!(co.members[..3], s(&["DIRECT", "REJECT", "proxy"]));
    for m in ["region:HK", "region:US", "auto"] {
        assert!(co.members.contains(&m.into()));
    }
    assert_eq!(co.members.last().map(String::as_str), Some("iface:utun6"));
    assert!(!co.members.contains(&"ssh:gone".into()));
    assert!(ai.members.iter().any(|m| co.members.contains(m)));
    assert_eq!(co.pick.as_deref(), Some("iface:utun6"));
    let plain = CustomGroup {
        id: "p".into(),
        name: "普通".into(),
        extras: vec![],
        pick: None,
    };
    let t = build_with(&ProxySettings {
        custom_groups: vec![plain.clone()],
        group_picks: map(&[("group:p", "region:US")]),
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "group:p"), "region:US");
    let t = build_with(&ProxySettings {
        custom_groups: vec![plain],
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "group:p"), "proxy");
}

#[test]
fn no_lines_yet_still_has_the_users_policies() {
    let settings = ProxySettings {
        custom_groups: vec![CustomGroup {
            id: "co".into(),
            name: "公司".into(),
            extras: s(&["iface:en0"]),
            pick: None,
        }],
        ..ProxySettings::default()
    };
    let t = build_group_tree(&TreeInput {
        lines: &[],
        base: &[],
        settings: &settings,
        split: &ImportedSplit::default(),
        extras: &[],
        smart_mode: true,
    });
    assert_eq!(
        g(&t, "group:co").members,
        s(&["DIRECT", "REJECT", "proxy", "iface:en0"])
    );
    assert_eq!(g(&t, "proxy").members, s(&["DIRECT"]));
    assert_eq!(pick(&t, "proxy"), "DIRECT");
}

#[test]
fn an_edited_built_in_policy_gets_outlets_and_is_marked() {
    let t = build_with(&ProxySettings {
        group_edits: [(
            "policy:ai".to_owned(),
            GroupEdit {
                extras: s(&["iface:en1", "ssh:gone"]),
                exclude: s(&["example.com"]),
            },
        )]
        .into_iter()
        .collect(),
        policies: map(&[("policy:ai", "iface:en1")]),
        ..ProxySettings::default()
    });
    let ai = g(&t, "policy:ai");
    assert!(ai.members.contains(&"REJECT".into()));
    assert_eq!(ai.members.last().map(String::as_str), Some("iface:en1"));
    assert!(!ai.members.contains(&"ssh:gone".into()));
    assert_eq!(ai.pick.as_deref(), Some("iface:en1"));
    assert!(ai.edited);
    assert!(!g(&t, "policy:youtube").edited);
}

#[test]
fn layers_lines_regions_auto_services() {
    let t = build_with(&ProxySettings::default());
    assert_eq!(
        g(&t, "region:HK").members,
        s(&[
            "region:HK~auto",
            "region:HK~balance",
            "region:HK~fastest",
            "HK 1",
            "HK 2"
        ])
    );
    assert_eq!(pick(&t, "region:HK"), "region:HK~auto");
    assert_eq!(g(&t, OTHER_REGION_TAG).members, s(&["X 1"]));
    assert_eq!(g(&t, "region:JP").members, s(&["JP 1"]));
    assert_eq!(g(&t, "region:HK~balance").kind, GroupKind::Balance);
    assert_eq!(g(&t, "region:HK~fastest").kind, GroupKind::Fastest);

    let regions = ["region:HK", "region:US", "region:JP", OTHER_REGION_TAG];
    let mut want = s(&[
        outbound_tags::SMART,
        outbound_tags::BALANCE,
        outbound_tags::FASTEST,
    ]);
    want.extend(s(&regions));
    assert_eq!(g(&t, "auto").members, want);
    assert_eq!(g(&t, outbound_tags::SMART).members, lines());
    assert_eq!(g(&t, outbound_tags::SMART).kind, GroupKind::Smart);

    let select = g(&t, "proxy");
    assert_eq!(select.pick.as_deref(), Some("auto"));
    assert_eq!(select.members[0], "DIRECT");
    assert!(!select.members.iter().any(|m| lines().contains(m)));
    let netflix = g(&t, "policy:netflix");
    assert_eq!(
        netflix.members[..6],
        s(&[
            "DIRECT",
            "REJECT",
            "proxy",
            "auto",
            outbound_tags::BALANCE,
            outbound_tags::FASTEST
        ])
    );
    for m in regions.iter().chain(&["kind:relay"]) {
        assert!(netflix.members.contains(&(*m).to_owned()));
    }
    assert_eq!(netflix.pick.as_deref(), Some("proxy"));
    assert!(t.by_tag("policy:netflix~auto").is_none());
    assert_eq!(g(&t, "policy:ads").members, s(&["REJECT", "DIRECT"]));
    assert_eq!(g(&t, "policy:ads").badge, Some(BADGE_BUILT_IN));

    assert!(!t.cards().any(|c| group_child::is_child(&c.tag)));
    let mut leaves = t.leaves("proxy");
    leaves.sort();
    let mut all = lines();
    all.sort();
    assert_eq!(leaves, all);
}

#[test]
fn ai_leaves_out_regions_it_does_not_serve() {
    let t = build_with(&ProxySettings::default());
    let ai = g(&t, "policy:ai");
    assert!(!ai.members.contains(&"region:HK".into()));
    assert_eq!(
        ai.members[..6],
        s(&[
            "DIRECT",
            "REJECT",
            "policy:ai~sticky",
            "policy:ai~auto",
            "policy:ai~balance",
            "policy:ai~fastest"
        ])
    );
    assert_eq!(
        g(&t, "policy:ai~auto").members,
        s(&["US 1", "US 2", "JP 1", "X 1"])
    );
    let sticky = g(&t, "policy:ai~sticky");
    assert_eq!(sticky.kind, GroupKind::Sticky);
    assert_eq!(sticky.members, s(&["US 1", "US 2"]));
    assert_eq!(ai.pick.as_deref(), Some("policy:ai~sticky"));
}

#[test]
fn group_defaults_precedence_own_pick_then_default_then_built_in() {
    let t = build_with(&ProxySettings::default());
    assert_eq!(pick(&t, "policy:netflix"), "proxy");
    assert_eq!(pick(&t, "policy:youtube"), outbound_tags::FASTEST);
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[
            ("policy:netflix", GroupDefault::region("JP")),
            ("policy:youtube", GroupDefault::of(GroupDefaultKind::Auto)),
            ("policy:cnmedia", GroupDefault::of(GroupDefaultKind::Select)),
            ("policy:ads", GroupDefault::of(GroupDefaultKind::Direct)),
        ]),
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "policy:netflix"), "region:JP");
    assert_eq!(pick(&t, "policy:youtube"), "auto");
    assert_eq!(pick(&t, "policy:cnmedia"), "proxy");
    assert_eq!(pick(&t, "policy:ads"), "DIRECT");
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[("policy:netflix", GroupDefault::region("JP"))]),
        policies: map(&[("policy:netflix", "region:US")]),
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "policy:netflix"), "region:US");
    // An own pick the group no longer offers: the default, not 直连.
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[("policy:netflix", GroupDefault::region("JP"))]),
        policies: map(&[("policy:netflix", "region:SG")]),
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "policy:netflix"), "region:JP");
}

#[test]
fn ai_default_region_moves_the_sticky_exit() {
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[("policy:ai", GroupDefault::region("JP"))]),
        ..ProxySettings::default()
    });
    assert_eq!(g(&t, "policy:ai~sticky").members, s(&["JP 1"]));
    assert_eq!(pick(&t, "policy:ai"), "policy:ai~sticky");
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[("policy:ai", GroupDefault::of(GroupDefaultKind::Fastest))]),
        ..ProxySettings::default()
    });
    assert_eq!(g(&t, "policy:ai~sticky").members, s(&["US 1", "US 2"]));
    assert_eq!(pick(&t, "policy:ai"), "policy:ai~fastest");
}

#[test]
fn a_refused_region_or_one_without_lines_keeps_the_built_in_default() {
    let ai = policy_by_tag("policy:ai").expect("ai");
    assert!(!GroupDefault::region("HK").allowed_for(ai));
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[("policy:ai", GroupDefault::region("HK"))]),
        ..ProxySettings::default()
    });
    assert_eq!(g(&t, "policy:ai~sticky").members, s(&["US 1", "US 2"]));
    assert_eq!(pick(&t, "policy:ai"), "policy:ai~sticky");
    let t = build_with(&ProxySettings {
        group_defaults: defaults(&[
            ("policy:ai", GroupDefault::region("SG")),
            ("policy:youtube", GroupDefault::region("SG")),
        ]),
        ..ProxySettings::default()
    });
    assert_eq!(g(&t, "policy:ai~sticky").members, s(&["US 1", "US 2"]));
    assert_eq!(pick(&t, "policy:ai"), "policy:ai~sticky");
    assert_eq!(pick(&t, "policy:youtube"), outbound_tags::FASTEST);
}

#[test]
fn group_default_choices_regions_first() {
    let t = build_with(&ProxySettings::default());
    let choices = |tag: &str| -> Vec<String> {
        let p = policy_by_tag(tag).expect("policy");
        group_default_choices_in(p, &g(&t, tag).members)
            .iter()
            .map(|d| d.name_for(p))
            .collect()
    };
    assert_eq!(
        choices("policy:ai"),
        s(&[
            "固定出口 · 美国",
            "固定出口 · 日本",
            "速度最快",
            "自动选择",
            "负载均衡",
            "节点选择",
            "直连",
            "拦截"
        ])
    );
    assert_eq!(
        choices("policy:netflix"),
        s(&[
            "🇭🇰 香港",
            "🇺🇸 美国",
            "🇯🇵 日本",
            "速度最快",
            "自动选择",
            "负载均衡",
            "节点选择",
            "直连",
            "拦截"
        ])
    );
    assert_eq!(choices("policy:ads"), s(&["直连", "拦截"]));
}

#[test]
fn group_defaults_decode_drops_refused_entries() {
    let s = ProxySettings::from_json(&serde_json::json!({
        "group_defaults": {
            "policy:ai": "region:HK",
            "policy:ads": "fastest",
            "policy:nope": "direct",
            "policy:netflix": "region:usa",
            "policy:dev": "select",
        }
    }));
    assert_eq!(
        s.group_defaults,
        defaults(&[("policy:dev", GroupDefault::of(GroupDefaultKind::Select))])
    );
}

#[test]
fn picks_per_group_legacy_strategies_and_a_line_chosen_before() {
    let t = build_with(&ProxySettings {
        group_picks: map(&[("region:HK", "HK 2"), ("region:US", "nope")]),
        group_strategies: [("region:US".to_owned(), GroupStrategy::Fastest)]
            .into_iter()
            .collect(),
        policies: map(&[("policy:netflix", "region:US")]),
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "region:HK"), "HK 2");
    assert_eq!(pick(&t, "region:US"), "region:US~fastest");
    assert_eq!(pick(&t, "policy:netflix"), "region:US");
    let t = build_with(&ProxySettings {
        selected: "US 1".into(),
        ..ProxySettings::default()
    });
    assert_eq!(pick(&t, "proxy"), "region:US");
    assert_eq!(pick(&t, "region:US"), "US 1");
}

fn targets() -> MergeTargets<'static> {
    MergeTargets {
        select: outbound_tags::PROXY,
        auto: outbound_tags::AUTO,
        fallback: "policy:final",
    }
}

fn sub_group(name: &str, kind: &str, members: &[&str]) -> SubGroup {
    SubGroup {
        name: name.into(),
        kind: kind.into(),
        members: s(members),
    }
}

#[test]
fn subscription_groups_kept_same_names_merged_conflicts_merged() {
    let line_of = map(&[
        ("a-hk", "HK 1"),
        ("a-us", "US 1"),
        ("b-hk", "HK 2"),
        ("b-us", "US 2"),
    ]);
    let a = SubRules {
        groups: vec![
            sub_group("🚀 节点选择", "select", &["a-hk", "a-us", "b-hk"]),
            sub_group("🎥 NETFLIX", "select", &["a-hk", "a-us"]),
            sub_group("🎬 流媒体", "select", &["a-us"]),
        ],
        rules: s(&[
            "DOMAIN-SUFFIX,netflix.com,🎥 NETFLIX",
            "DOMAIN-SUFFIX,hbo.com,🎬 流媒体",
        ]),
    };
    let b = SubRules {
        groups: vec![
            sub_group("🚀 节点选择", "select", &["b-hk", "b-us", "a-us"]),
            sub_group("🎥 NETFLIX", "select", &["b-hk"]),
            sub_group("📺 视频", "select", &["b-us", "b-hk"]),
        ],
        rules: s(&[
            "DOMAIN-SUFFIX,netflix.com,🎥 NETFLIX",
            "DOMAIN-SUFFIX,hbo.com,📺 视频",
            "DOMAIN-SUFFIX,disney.com,📺 视频",
        ]),
    };
    let split = merge_subscription_splits(
        &[
            SubSplit {
                rules: &a,
                line_of: &line_of,
            },
            SubSplit {
                rules: &b,
                line_of: &line_of,
            },
        ],
        targets(),
        None,
        false,
    );
    let by = |tag: &str| {
        split
            .groups
            .iter()
            .find(|x| x.tag == tag)
            .unwrap_or_else(|| panic!("{tag}"))
            .members
            .clone()
    };
    assert_eq!(by("sub:🎥 NETFLIX"), s(&["HK 1", "US 1", "HK 2"]));
    assert_eq!(by("sub:🎬 流媒体"), s(&["US 1", "US 2", "HK 2"]));
    assert_eq!(
        split.rules,
        s(&[
            "DOMAIN-SUFFIX,netflix.com,sub:🎥 NETFLIX",
            "DOMAIN-SUFFIX,hbo.com,sub:🎬 流媒体",
            "DOMAIN-SUFFIX,disney.com,sub:📺 视频",
        ])
    );
    let t = build(&ProxySettings::default(), &split);
    let nf = g(&t, "sub:🎥 NETFLIX");
    assert_eq!(
        nf.members[..3],
        s(&[
            "sub:🎥 NETFLIX~auto",
            "sub:🎥 NETFLIX~balance",
            "sub:🎥 NETFLIX~fastest"
        ])
    );
    assert_eq!(nf.pick.as_deref(), Some("HK 1"));
}

#[test]
fn no_loops_a_member_leading_back_is_dropped() {
    let split = ImportedSplit {
        groups: vec![
            ImportedGroup::new("sub:A", "A", &["sub:B", "HK 1"]),
            ImportedGroup::new("sub:B", "B", &["sub:A", "US 1"]),
        ],
        rules: vec![],
        final_target: None,
    };
    let t = build(&ProxySettings::default(), &split);
    let a = &g(&t, "sub:A").members;
    let b = &g(&t, "sub:B").members;
    assert!(!(a.contains(&"sub:B".into()) && b.contains(&"sub:A".into())));
    assert!(a.contains(&"HK 1".into()));
    assert!(b.contains(&"US 1".into()));
    assert_eq!(t.loops, [("sub:B".to_owned(), "sub:A".to_owned())]);
}

// -------------------------------------------------------- custom groups

#[test]
fn an_edit_adds_outlets_after_the_generated_members() {
    let e = GroupEdit {
        extras: s(&["iface:en1", "DIRECT", "iface:en1"]),
        exclude: vec![],
    };
    assert_eq!(
        e.apply(&s(&["DIRECT", "proxy"])),
        s(&["DIRECT", "proxy", "iface:en1"])
    );
    assert!(is_extra_outlet("ssh:abc"));
    assert!(!is_extra_outlet("region:HK"));
    assert!(CustomGroup::is_custom("group:abc"));
    assert!(!CustomGroup::is_custom("policy:ai"));
}

// ------------------------------------------------------------ sub rules

/// An ACL4SSR-style subscription, trimmed (sub_rules_test.dart).
const ACL: &str = r#"
proxies:
  - {name: "香港 01", type: trojan, server: hk1.example, port: 443, password: a}
  - {name: "日本 01", type: trojan, server: jp1.example, port: 443, password: a}
  - {name: "剩余流量：10 GB", type: trojan, server: info.example, port: 443, password: a}
proxy-groups:
  - {name: "🔰 节点选择", type: select, proxies: ["♻️ 自动选择", DIRECT, "香港 01", "日本 01"]}
  - {name: "♻️ 自动选择", type: url-test, proxies: ["香港 01", "日本 01"]}
  - {name: "🎥 NETFLIX", type: select, proxies: ["🔰 节点选择", "♻️ 自动选择", "🎯 全球直连", "香港 01", "日本 01"]}
  - {name: "🎯 全球直连", type: select, proxies: [DIRECT, "🔰 节点选择"]}
  - {name: "🛑 全球拦截", type: select, proxies: [REJECT, DIRECT]}
  - {name: "🐟 漏网之鱼", type: select, proxies: ["🔰 节点选择", DIRECT]}
rules:
  - DOMAIN-SUFFIX,netflix.com,🎥 NETFLIX
  - DOMAIN-SUFFIX,ad.example,🛑 全球拦截
  - DOMAIN-KEYWORD,baidu,🎯 全球直连
  - IP-CIDR,10.9.0.0/16,🎯 全球直连,no-resolve
  - AND,((DOMAIN,quic.example),(NETWORK,UDP)),🛑 全球拦截
  - RULE-SET,someprovider,🎥 NETFLIX
  - DOMAIN-SUFFIX,unknown.example,🚫 不存在的组
  - MATCH,🐟 漏网之鱼
"#;

/// A second provider with overlapping names and matchers.
const OTHER: &str = r#"
proxies:
  - {name: "HK-A", type: trojan, server: hk1.example, port: 443, password: b}
proxy-groups:
  - {name: "🚀 Proxy", type: select, proxies: ["HK-A"]}
  - {name: "🎥 NETFLIX", type: select, proxies: [DIRECT]}
  - {name: "🎮 Steam", type: select, proxies: ["🚀 Proxy", DIRECT]}
rules:
  - DOMAIN-SUFFIX,netflix.com,DIRECT
  - DOMAIN-SUFFIX,steampowered.com,🎮 Steam
  - DOMAIN-SUFFIX,fast.com,🎥 NETFLIX
  - MATCH,🚀 Proxy
"#;

#[test]
fn merge_maps_groups_onto_ours_by_priority() {
    let a = parse_subscription(ACL).expect("acl").split;
    let b = parse_subscription(OTHER).expect("other").split;
    let la = map(&[("香港 01", "香港 01"), ("日本 01", "日本 01")]);
    let lb = map(&[("HK-A", "香港 01")]);
    let merged = merge_subscription_splits(
        &[
            SubSplit {
                rules: &a,
                line_of: &la,
            },
            SubSplit {
                rules: &b,
                line_of: &lb,
            },
        ],
        targets(),
        None,
        false,
    );
    let names: Vec<&str> = merged.groups.iter().map(|x| x.name.as_str()).collect();
    assert_eq!(names, ["🎥 NETFLIX", "🎮 Steam"]);
    assert_eq!(merged.groups[0].tag, "sub:🎥 NETFLIX");
    assert_eq!(
        merged.groups[0].members,
        s(&["proxy", "auto", "DIRECT", "香港 01", "日本 01"])
    );
    assert_eq!(
        merged.rules,
        s(&[
            "DOMAIN-SUFFIX,netflix.com,sub:🎥 NETFLIX",
            "DOMAIN-SUFFIX,ad.example,REJECT",
            "DOMAIN-KEYWORD,baidu,DIRECT",
            "IP-CIDR,10.9.0.0/16,DIRECT,no-resolve",
            "AND,((DOMAIN,quic.example),(NETWORK,UDP)),REJECT",
            "DOMAIN-SUFFIX,steampowered.com,sub:🎮 Steam",
            "DOMAIN-SUFFIX,fast.com,sub:🎥 NETFLIX",
        ])
    );
    assert_eq!(merged.groups[1].members, s(&["proxy", "DIRECT"]));
}

#[test]
fn merge_with_built_in_groups_supplements_ours() {
    let a = parse_subscription(ACL).expect("acl").split;
    let la = map(&[("香港 01", "香港 01"), ("日本 01", "日本 01")]);
    let built_in = |name: &str| alias_of(name);
    let split = merge_subscription_splits(
        &[SubSplit {
            rules: &a,
            line_of: &la,
        }],
        targets(),
        Some(&built_in),
        false,
    );
    assert!(!split.groups.iter().any(|x| x.name == "🎥 NETFLIX"));
    assert!(split
        .rules
        .contains(&"DOMAIN-SUFFIX,netflix.com,policy:netflix".to_owned()));
}

#[test]
fn merge_raw_keeps_groups_as_written() {
    let a = parse_subscription(ACL).expect("acl").split;
    let la = map(&[("香港 01", "香港 01"), ("日本 01", "日本 01")]);
    let split = merge_subscription_splits(
        &[SubSplit {
            rules: &a,
            line_of: &la,
        }],
        targets(),
        None,
        true,
    );
    assert_eq!(split.final_target.as_deref(), Some("sub:🐟 漏网之鱼"));
    let auto = split
        .groups
        .iter()
        .find(|x| x.tag == "sub:♻️ 自动选择")
        .expect("auto");
    assert_eq!(auto.kind, "url-test");
    assert!(split.groups.iter().any(|x| x.tag == "proxy"));
    assert!(split
        .rules
        .contains(&"DOMAIN-KEYWORD,baidu,sub:🎯 全球直连".to_owned()));

    // In the tree (完全按订阅): the provider's groups with their own types.
    let settings = ProxySettings {
        group_mode: crate::model::settings::GroupMode::Subscription,
        ..ProxySettings::default()
    };
    let t = build(&settings, &split);
    let auto = g(&t, "sub:♻️ 自动选择");
    assert_eq!(auto.kind, GroupKind::Fastest);
    assert_eq!(auto.raw_type.as_deref(), Some("url-test"));
    assert_eq!(auto.pick, None);
    assert!(t.by_tag("policy:ai").is_none());
}

// ---------------------------------------------- behaviour fixes (B23–B25)

/// B23: 完全按订阅, "B" offers only "A", and A only B: the loop is cut at
/// B, which picked A. Dart kept that pick (`copyWith(pick: null)` keeps
/// it), so the config listed A in B again: the loop was back. Now B goes
/// DIRECT, the core's only way out of a group with nothing left.
#[test]
fn b23_a_cut_pick_is_cleared() {
    let split = ImportedSplit {
        groups: vec![
            ImportedGroup::new("proxy", "🚀 节点选择", &["sub:A", "HK 1"]),
            ImportedGroup::new("sub:A", "A", &["sub:B"]),
            ImportedGroup::new("sub:B", "B", &["sub:A"]),
        ],
        rules: vec![],
        final_target: None,
    };
    let settings = ProxySettings {
        group_mode: crate::model::settings::GroupMode::Subscription,
        ..ProxySettings::default()
    };
    let t = build(&settings, &split);
    assert_eq!(t.loops, [("sub:B".to_owned(), "sub:A".to_owned())]);
    assert_eq!(g(&t, "sub:B").members, s(&["DIRECT"]));
    assert_eq!(pick(&t, "sub:B"), "DIRECT");
    // A keeps B; nothing names a cut member any more.
    assert_eq!(pick(&t, "sub:A"), "sub:B");
    for x in &t.groups {
        assert!(
            x.pick.as_ref().is_none_or(|p| x.members.contains(p)),
            "{}",
            x.tag
        );
    }
}

/// B24: two subscriptions followed exactly, each with its own 节点选择:
/// Dart's second replaced the first's members; now both are in it.
#[test]
fn b24_both_subscriptions_select_groups_merge() {
    let one = SubRules {
        groups: vec![sub_group("🚀 节点选择", "select", &["HK 01", "JP 01"])],
        rules: s(&["MATCH,🚀 节点选择"]),
    };
    let two = SubRules {
        groups: vec![sub_group("🚀 Proxy", "select", &["US 01"])],
        rules: s(&["DOMAIN,x.example,🚀 Proxy", "MATCH,🚀 Proxy"]),
    };
    let l1 = map(&[("HK 01", "HK 01"), ("JP 01", "JP 01")]);
    let l2 = map(&[("US 01", "US 01")]);
    let split = merge_subscription_splits(
        &[
            SubSplit {
                rules: &one,
                line_of: &l1,
            },
            SubSplit {
                rules: &two,
                line_of: &l2,
            },
        ],
        targets(),
        None,
        true,
    );
    let proxy = split
        .groups
        .iter()
        .find(|x| x.tag == "proxy")
        .expect("proxy");
    assert_eq!(proxy.members, s(&["HK 01", "JP 01", "US 01"]));
    assert_eq!(proxy.name, "🚀 节点选择");
}

/// B24: a group with no members is left out of the tree (Dart threw on
/// `members.first`), in smart mode and followed exactly.
#[test]
fn b24_empty_groups_are_skipped() {
    let split = ImportedSplit {
        groups: vec![
            ImportedGroup::new("proxy", "🚀 节点选择", &["HK 1"]),
            ImportedGroup::new("sub:Empty", "Empty", &[]),
        ],
        rules: vec![],
        final_target: None,
    };
    let t = build(&ProxySettings::default(), &split);
    assert!(t.by_tag("sub:Empty").is_none());
    let settings = ProxySettings {
        group_mode: crate::model::settings::GroupMode::Subscription,
        ..ProxySettings::default()
    };
    let t = build(&settings, &split);
    assert!(t.by_tag("sub:Empty").is_none());
    assert!(t.by_tag("proxy").is_some());
}

/// B25: edits apply only to groups that take them (Dart `canEdit`): an
/// edit saved for a region group is ignored; outlets come once.
#[test]
fn b25_edits_only_on_editable_groups_outlets_once() {
    let edit = |extras: &[&str]| GroupEdit {
        extras: s(extras),
        exclude: vec![],
    };
    let settings = ProxySettings {
        group_edits: [
            ("region:HK".to_owned(), edit(&["iface:en0"])),
            ("policy:ads".to_owned(), edit(&["iface:en0"])),
            ("policy:ai".to_owned(), edit(&["iface:en0", "iface:en0"])),
        ]
        .into_iter()
        .collect(),
        custom_groups: vec![CustomGroup {
            id: "co".into(),
            name: "Co".into(),
            extras: s(&["iface:en1", "iface:en1"]),
            pick: None,
        }],
        ..ProxySettings::default()
    };
    let t = build_with(&settings);
    assert!(!g(&t, "region:HK").edited);
    assert!(!g(&t, "region:HK").members.contains(&"iface:en0".into()));
    assert!(!g(&t, "policy:ads").edited);
    let ai = g(&t, "policy:ai");
    assert!(ai.edited);
    assert_eq!(ai.members.iter().filter(|m| *m == "iface:en0").count(), 1);
    let co = g(&t, "group:co");
    assert_eq!(co.members.iter().filter(|m| *m == "iface:en1").count(), 1);
    assert!(GroupEdit::editable("group:co"));
    assert!(GroupEdit::editable("policy:netflix"));
    assert!(!GroupEdit::editable("policy:foreign"));
    assert!(!GroupEdit::editable("policy:ads"));
    assert!(!GroupEdit::editable("region:HK"));
}

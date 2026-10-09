//! Expected values printed by the Dart VM (Dart 3.13, paopao_proxy) for
//! names and servers the golden corpus does not cover; rows marked with a
//! fix (B17 …) differ from Dart on purpose.

use super::*;
use crate::dart::{internet_address_try_parse, to_lower_case, IpKind};
use serde_json::json;

const REGION_OF: &[(&str, Option<&str>)] = &[
    ("", None),
    ("HK", Some("HK")),
    // B17: Dart had Some("HK").
    ("hk 01", None),
    ("HK01", Some("HK")),
    ("01HK", Some("HK")),
    ("HKG 01", None),
    ("SHKO", None),
    ("HK_01", Some("HK")),
    ("HK-IPv6", Some("HK")),
    ("🇭🇰 Hong Kong 01", Some("HK")),
    ("HK🇭🇰", Some("HK")),
    ("🇺🇸US", Some("US")),
    // B17: Dart had None.
    ("Hongkong", Some("HK")),
    // B17: Dart had None.
    ("HONG KONG", Some("HK")),
    ("hong  kong", None),
    // B17: Dart had None.
    ("hong kong", Some("HK")),
    ("USA-01", Some("US")),
    ("US01", Some("US")),
    ("aUS", None),
    ("Plus", None),
    // B17: Dart had None.
    ("RUSSIA", Some("RU")),
    // B17: Dart had Some("RU").
    ("Ru\u{17f}sia", None),
    ("JPN", None),
    ("Japan", Some("JP")),
    ("japanese", None),
    // B17: Dart had None.
    ("TOKYO", Some("JP")),
    // B17: Dart had None.
    ("tokyo", Some("JP")),
    ("IN 01", Some("IN")),
    ("India", Some("IN")),
    ("Indonesia", Some("ID")),
    ("IT 01", Some("IT")),
    ("IT之家", Some("IT")),
    // B17: Dart had None.
    ("ITALY", Some("IT")),
    ("Italy", Some("IT")),
    ("香港中转 日本", Some("HK")),
    ("日本 (香港中转)", Some("JP")),
    ("(香港中转) 日本", Some("JP")),
    ("日本（香港 IEPL 专线）", Some("JP")),
    ("香港（日本Relay）", Some("HK")),
    ("HK (Relay)", Some("HK")),
    ("(HK relay) Node", None),
    ("日本 (a (香港 中转) b)", Some("JP")),
    ("日本 (香港中转", Some("HK")),
    ("香港) 日本 (中转", Some("HK")),
    ("(TRANSIT 香港)日本", Some("JP")),
    ("(香港 tran\u{17f}it) 日本", Some("HK")),
    ("Türkiye", Some("TR")),
    ("TÜRKIYE", None),
    // B17: Dart had None.
    ("turkey", Some("TR")),
    ("UAE-01", Some("AE")),
    ("Dubai", Some("AE")),
    ("United States", Some("US")),
    // B17: Dart had None.
    ("united states", Some("US")),
    ("UnitedStates", None),
    ("San Jose", Some("US")),
    ("SanJose", None),
    ("DE 01", Some("DE")),
    ("Deutschland", None),
    // B17: Dart had Some("DE").
    ("de 01", None),
    ("CA 01", Some("CA")),
    ("California CA", Some("US")),
    ("SG-HK", Some("HK")),
    ("GB", Some("GB")),
    ("UK 01", Some("GB")),
    // B17: Dart had Some("GB").
    ("uk", None),
    ("台北", Some("TW")),
    ("新北", Some("TW")),
    ("Los Angeles", Some("US")),
    ("LosAngeles", None),
    // B17: Dart had None.
    ("los angeles", Some("US")),
    ("ＨＫ", None),
    ("HK", Some("HK")),
    // B17: Dart had None.
    ("NEW YORK", Some("US")),
    ("Newyork", None),
    ("A Series - HK 07 (IPv6)", Some("HK")),
    ("Z 越南A01 (香港中转)", Some("VN")),
    ("California (美国) A05", Some("US")),
    ("US-LA-02", Some("US")),
    ("Relay 01", None),
    ("Plus Plan node", None),
    ("Seoul", Some("KR")),
    ("KR", Some("KR")),
    ("韓國", Some("KR")),
    ("澳洲", Some("AU")),
    ("AU", Some("AU")),
    ("Australia", Some("AU")),
    ("Sydney", Some("AU")),
    ("BR", Some("BR")),
    // B17: Dart had None.
    ("brazil", Some("BR")),
    ("AR", Some("AR")),
    ("Argentina", Some("AR")),
    ("Moscow", None),
    ("RU", Some("RU")),
    ("PH", Some("PH")),
    ("Philippines", Some("PH")),
    ("VN", Some("VN")),
    ("Vietnam", Some("VN")),
    ("TH", Some("TH")),
    ("Thailand", Some("TH")),
    ("MY", Some("MY")),
    ("Malaysia", Some("MY")),
    ("ID", None),
    ("TR", Some("TR")),
    ("AE", Some("AE")),
    ("IT", Some("IT")),
    ("Milan", None),
    ("NL", Some("NL")),
    ("Amsterdam", Some("NL")),
    ("Netherlands", Some("NL")),
    ("FR", Some("FR")),
    ("Paris", Some("FR")),
    ("France", Some("FR")),
    ("Frankfurt", Some("DE")),
    ("Germany", Some("DE")),
    ("Britain", Some("GB")),
    ("London", Some("GB")),
    ("England", None),
    ("Korea", Some("KR")),
    ("Taiwan", Some("TW")),
    ("Singapore", Some("SG")),
    ("America", Some("US")),
    ("Phoenix", Some("US")),
    ("Dallas", Some("US")),
    ("Chicago", Some("US")),
    ("Seattle", Some("US")),
    ("Silicon", None),
    ("Osaka", Some("JP")),
    ("Toronto", Some("CA")),
    ("Vancouver", Some("CA")),
    ("Mumbai", Some("IN")),
    ("HK\u{a0}Node", Some("HK")),
    ("Hong\u{a0}Kong", None),
    ("Hong\u{9}Kong", None),
    ("x(中转)HK", Some("HK")),
    ("（relay）US（transit）JP", Some("JP")),
    ("K\u{212a}HK", Some("HK")),
    ("ıT", None),
    ("IT", Some("IT")),
];

const LOWER: &[(&str, &str)] = &[
    ("İ", "i"),
    ("ΣΑΣ", "σασ"),
    ("HK.EXAMPLE", "hk.example"),
    ("ẞ", "ß"),
    ("ǅ", "ǆ"),
    ("Ω", "ω"),
    ("K", "k"),
    ("ﬃ", "ﬃ"),
];

const KINDS: &[(&str, &[&str])] = &[
    ("IPV6", &["ipv6"]),
    ("v6", &["ipv6"]),
    ("V6", &["ipv6"]),
    ("v6x", &[]),
    ("xv6", &[]),
    ("v60", &[]),
    ("Hv6", &[]),
    ("6v6", &["ipv6"]),
    ("ipv6", &["ipv6"]),
    ("IPv6x", &["ipv6"]),
    ("_v6_", &["ipv6"]),
    ("0.5x", &["lowrate"]),
    ("0.5 ×", &["lowrate"]),
    ("0.5倍", &["lowrate"]),
    ("x0.5", &["lowrate"]),
    ("× 0.3", &["lowrate"]),
    ("X0.1", &["lowrate"]),
    ("0.x", &[]),
    ("1.5x", &[]),
    ("10.5x", &["lowrate"]),
    ("0.5\u{3000}x", &["lowrate"]),
    ("0.5\u{85}x", &[]),
    ("0.5\u{feff}x", &["lowrate"]),
    ("0.5X", &["lowrate"]),
    ("0.5", &[]),
    ("x 0.", &[]),
    ("低倍率", &["lowrate"]),
    ("IEPL", &["dedicated"]),
    ("iepl", &["dedicated"]),
    ("Relay", &["relay"]),
    ("TRANSIT", &["relay"]),
    ("转发", &["relay"]),
    ("專線", &["dedicated"]),
    ("iplc", &["dedicated"]),
    ("relaY", &["relay"]),
    ("v6é", &["ipv6"]),
    ("év6", &["ipv6"]),
    ("ﬀv6", &["ipv6"]),
];

/// (name, usable, flagged)
const INFO: &[(&str, bool, bool)] = &[
    ("Expire", false, false),
    ("EXPIRE", false, false),
    ("Telegram群", false, false),
    ("TELEGRAM群", false, false),
    ("telegram 群", true, false),
    ("官网", false, false),
    ("traffic", false, false),
    ("TRAFFIC 1", false, false),
    ("维护", true, true),
    ("Maintenance", true, true),
    ("恢復", true, true),
    ("香港 01", true, false),
    ("订阅", false, false),
    ("expıre", true, false),
];

/// (server, InternetAddress.tryParse type, needsIpv6 for a node named "x")
const SERVERS: &[(&str, Option<&str>, bool)] = &[
    ("2001:db8::1", Some("IPv6"), true),
    ("[2001:db8::1]", None, true),
    ("2001:DB8::1", Some("IPv6"), true),
    ("::ffff:1.2.3.4", Some("IPv6"), true),
    ("1.2.3.4", Some("IPv4"), false),
    ("01.2.3.4", None, false),
    ("1.2.3", None, false),
    ("256.1.1.1", None, false),
    ("fe80::1%eth0", None, false),
    ("fe80::1%1", Some("IPv6"), true),
    ("fe80::1%lo", Some("IPv6"), true),
    ("fe80::1%", None, false),
    ("1.2.3.4%1", None, false),
    ("::", Some("IPv6"), true),
    ("1::2:3:4:5:6:7", Some("IPv6"), true),
    ("1:2:3:4:5:6:7:8:9", None, false),
    (" 1.2.3.4", None, false),
    ("1.2.3.4 ", None, false),
    ("", None, false),
    ("[1.2.3.4]", None, false),
    ("::1.2.3.04", None, false),
    ("1:2:3:4:5:6:1.2.3.4", Some("IPv6"), true),
    ("hk.example", None, false),
    ("0x1.2.3.4", None, false),
    ("1.2.3.4.", None, false),
    ("::1:", None, false),
    (":1::", None, false),
    ("1:2:3:4:5:6:7::", Some("IPv6"), true),
    ("::2:3:4:5:6:7:8", Some("IPv6"), true),
    ("00001::", None, false),
    ("1::1.2.3.4", Some("IPv6"), true),
    ("%1", None, false),
    ("[::1", None, true),
    ("1.2.3.4]", None, false),
];

const TAG_NAMES: &[&str] = &[
    "",
    "  ",
    "proxy",
    "proxy",
    "auto",
    "region:HK",
    " region:x",
    "a",
    "a",
    "a 2",
    "\u{feff}a",
    "direct",
    "block",
    "speedtest",
    "auto~fastest",
    "node",
    "node 2",
    "kind:x",
    "\u{85}b",
    "b",
];

const TAGS: &[&str] = &[
    "node",
    "node 2",
    "proxy 2",
    "proxy 3",
    "auto 2",
    " region:HK",
    " region:x",
    "a",
    "a 2",
    "a 2 2",
    "a 3",
    "direct 2",
    "block 2",
    "speedtest 2",
    "auto~fastest 2",
    "node 3",
    "node 2 2",
    " kind:x",
    "b",
    "b 2",
];

fn node(name: &str, server: &str) -> ProxyNode {
    node_with(name, server, "a", 443)
}

fn node_with(name: &str, server: &str, password: &str, port: i64) -> ProxyNode {
    ProxyNode::from_json(&json!({
        "name": name,
        "outbound": {"type": "trojan", "server": server, "server_port": port, "password": password},
    }))
    .expect("node")
}

const GB: i64 = 1 << 30;

#[test]
fn region_of_like_dart() {
    for (name, code) in REGION_OF {
        assert_eq!(region_of(name).map(|r| &*r.code), *code, "{name:?}");
    }
}

#[test]
fn lower_case_like_dart() {
    for (s, want) in LOWER {
        assert_eq!(to_lower_case(s), *want, "{s:?}");
    }
}

#[test]
fn line_kinds_like_dart() {
    for (name, want) in KINDS {
        let got: Vec<&str> = LINE_KINDS
            .iter()
            .filter(|k| k.matches(name))
            .map(|k| k.id)
            .collect();
        assert_eq!(&got, want, "{name:?}");
    }
}

#[test]
fn info_and_flagged_like_dart() {
    for (name, usable, flagged) in INFO {
        let n = node(name, "s.example.com");
        assert_eq!(is_usable_node(&n), *usable, "usable {name:?}");
        assert_eq!(is_flagged_node(&n), *flagged, "flagged {name:?}");
    }
}

#[test]
fn addresses_like_dart() {
    for (server, kind, v6) in SERVERS {
        // Dart resolves a named scope against this machine's interfaces
        // (`%lo` exists, `%eth0` not); only numeric scopes are accepted here.
        if server.split_once('%').is_some_and(|(a, s)| {
            !a.is_empty() && !s.is_empty() && !s.bytes().all(|b| b.is_ascii_digit())
        }) {
            assert_eq!(internet_address_try_parse(server), None, "{server:?}");
            continue;
        }
        let got = internet_address_try_parse(server).map(|k| match k {
            IpKind::V4 => "IPv4",
            IpKind::V6 => "IPv6",
        });
        assert_eq!(got, *kind, "{server:?}");
        assert_eq!(needs_ipv6(&node("x", server)), *v6, "needs_ipv6 {server:?}");
    }
    assert!(needs_ipv6(&node("香港 01 IPv6", "hk.example")));
}

#[test]
fn tags_like_dart() {
    // Names as given (`from_json` would put the server in a blank one).
    let nodes: Vec<ProxyNode> = TAG_NAMES
        .iter()
        .map(|n| ProxyNode {
            name: (*n).to_owned(),
            ..node("x", "s")
        })
        .collect();
    let refs: Vec<&ProxyNode> = nodes.iter().collect();
    assert_eq!(node_tags_for(&refs), TAGS);
}

/// B1 / B4: one tag per runnable line, and it is the line's proxy name.
/// Dart named a plain-HTTP "HK" and a vless "HK" `HK` / `HK 2` in the pool
/// but left the HTTP one out of the config, where the vless one was `HK`.
#[test]
fn only_runnable_lines_get_tags() {
    let http = ProxyNode::from_json(&json!({
        "name": "HK",
        "outbound": {"type": "http", "server": "h", "server_port": 80},
    }))
    .expect("http");
    let h2_trojan = ProxyNode::from_json(&json!({
        "name": "JP",
        "outbound": {"type": "trojan", "server": "j", "server_port": 1, "password": "p",
                     "transport": {"type": "http"}},
    }))
    .expect("trojan");
    let vless = |name: &str, server: &str| {
        ProxyNode::from_json(&json!({
            "name": name,
            "outbound": {"type": "vless", "server": server, "server_port": 443, "uuid": "u"},
        }))
        .expect("vless")
    };
    let input = PoolInput {
        subscriptions: vec![PoolSource {
            nodes: vec![
                http,
                vless("HK", "a"),
                h2_trojan,
                vless("JP", "b"),
                vless("DIRECT", "c"),
                vless("REJECT", "d"),
                vless("paopao-mitm", "e"),
                vless("auto~smart", "f"),
            ],
            usage: None,
        }],
        ..PoolInput::default()
    };
    let pool = build_pool(&input);
    assert_eq!(
        pool.tags,
        [
            "HK",
            "JP",
            "DIRECT 2",
            "REJECT 2",
            "paopao-mitm 2",
            "auto~smart 2"
        ]
    );
    assert_eq!(pool.unsupported, 2);
    assert_eq!(pool.nodes.len(), pool.tags.len());
    // Groups list only those tags.
    let hk = pool
        .groups
        .iter()
        .find(|g| g.tag == "region:HK")
        .expect("HK");
    assert_eq!(hk.members, ["HK"]);
    let jp = pool
        .groups
        .iter()
        .find(|g| g.tag == "region:JP")
        .expect("JP");
    assert_eq!(jp.members, ["JP"]);
    for (n, t) in pool.nodes.iter().zip(&pool.tags) {
        assert_eq!(clash_proxy_for(&n.node, t).expect("runnable")["name"], *t);
    }
}

/// A server whose first entry can't run is served by a later one that can.
#[test]
fn unrunnable_entry_does_not_hide_its_server() {
    let trojan = |name: &str, transport: Option<&str>| {
        let mut o = json!({"type": "trojan", "server": "s", "server_port": 1, "password": "p"});
        if let Some(t) = transport {
            o["transport"] = json!({"type": t});
        }
        ProxyNode::from_json(&json!({"name": name, "outbound": o})).expect("node")
    };
    let sources = [PoolSource {
        nodes: vec![trojan("bad", Some("http")), trojan("good", None)],
        usage: None,
    }];
    let names: Vec<&str> = pool_nodes(&sources, 0)
        .iter()
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(names, ["good"]);
}

// Ported from paopao_proxy test/pool_test.dart.

#[test]
fn one_line_per_server_higher_priority_serves() {
    let small = PoolSource {
        nodes: vec![
            node_with("香港 01", "hk.example", "small", 443),
            node_with("日本 01", "jp.example", "small", 443),
        ],
        usage: Some(Usage {
            total: 100 * GB,
            download: 90 * GB,
            ..Usage::default()
        }),
    };
    let big = PoolSource {
        nodes: vec![
            node_with("HK-01", "HK.example", "big", 443),
            node_with("美国 01", "us.example", "big", 443),
        ],
        usage: Some(Usage {
            total: 100 * GB,
            download: 10 * GB,
            ..Usage::default()
        }),
    };
    let sources = [big.clone(), small.clone()];
    let pool = pool_nodes(&sources, 0);
    let names: Vec<&str> = pool.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["HK-01", "美国 01", "日本 01"]);
    assert_eq!(pool[0].outbound["password"], "big");
    let sources = [small, big];
    assert_eq!(pool_nodes(&sources, 0)[0].outbound["password"], "small");
}

#[test]
fn used_up_accounts_only_when_nothing_else() {
    // 2026-10-04 and 2026-09-01, UTC.
    let now = 1_791_072_000_000;
    let gone = PoolSource {
        nodes: vec![node_with("香港 01", "hk.example", "old", 443)],
        usage: Some(Usage {
            total: 50 * GB,
            expire: Some(1_788_220_800_000),
            ..Usage::default()
        }),
    };
    let empty = PoolSource {
        nodes: vec![node("日本 01", "jp.example")],
        usage: Some(Usage {
            total: 10 * GB,
            download: 10 * GB,
            ..Usage::default()
        }),
    };
    let unknown = PoolSource {
        nodes: vec![node("新加坡 01", "sg.example")],
        usage: None,
    };
    let names = |s: &[PoolSource]| -> Vec<String> {
        pool_nodes(s, now).iter().map(|n| n.name.clone()).collect()
    };
    assert_eq!(
        names(&[gone.clone(), empty.clone(), unknown]),
        ["新加坡 01"]
    );
    assert_eq!(names(&[gone, empty]), ["香港 01", "日本 01"]);
    assert_eq!(
        remaining_of(
            Some(&Usage {
                total: 10,
                download: 4,
                ..Usage::default()
            }),
            0
        ),
        Some(6)
    );
    assert_eq!(remaining_of(None, 0), None);
}

#[test]
fn info_rows_and_duplicates_leave_the_pool() {
    let sources = [PoolSource {
        nodes: vec![
            node("剩余流量：98.5 GB", "info.example"),
            node("香港 01", "hk.example"),
            node_with("香港 01 备用账号", "hk.example", "b", 443),
            node_with("香港 02", "hk.example", "a", 8443),
        ],
        usage: None,
    }];
    let names: Vec<&str> = pool_nodes(&sources, 0)
        .iter()
        .map(|n| n.name.as_str())
        .collect();
    assert_eq!(names, ["香港 01", "香港 02"]);
}

#[test]
fn places_by_code() {
    assert_eq!(
        region_for_code(Some("JP")).map(|r| r.code),
        Some("JP".into())
    );
    let pl = region_for_code(Some("PL")).expect("PL");
    assert_eq!(pl.flag, "🇵🇱");
    assert_eq!(pl.tag(), "region:PL");
    assert!(region_for_code(Some("pl")).is_none());
    assert!(region_for_code(None).is_none());
    let code =
        |name: &str, exit: Option<&str>| region_of_node(&node(name, "x"), exit).map(|r| r.code);
    assert_eq!(code("香港 01", Some("US")), Some("HK".into()));
    assert_eq!(code("A Series - HK 07", Some("US")), Some("HK".into()));
    assert_eq!(
        code("Z 新加坡A02 (香港中转)", Some("HK")),
        Some("SG".into())
    );
    assert_eq!(code("Node 7", Some("SG")), Some("SG".into()));
}

#[test]
fn measured_exits_make_groups() {
    let nodes = [
        (node("香港 01", "a"), None),
        (node("Node 7", "b"), Some("HK")),
        (node("Node 8", "c"), Some("PL")),
        (node("Node 9", "d"), Some("PL")),
        (node("Node 10", "e"), None),
    ];
    let with_exit: Vec<(&ProxyNode, Option<&str>)> = nodes.iter().map(|(n, e)| (n, *e)).collect();
    let tags: Vec<String> = nodes.iter().map(|(n, _)| n.name.clone()).collect();
    let groups = classify(&with_exit, &tags);
    let gt: Vec<&str> = groups.iter().map(|g| g.tag.as_str()).collect();
    assert_eq!(gt, ["region:HK", "region:PL"]);
    assert_eq!(groups[0].members, ["香港 01", "Node 7"]);
    assert_eq!(groups[1].label, "🇵🇱 PL");
}

#[test]
fn kind_groups_need_two_lines() {
    let nodes = [
        node("香港 01 中转", "a"),
        node("日本 relay", "b"),
        node("美国 v6", "c"),
        node("新加坡 0.5x", "d"),
        node("韩国 x0.2", "e"),
        node("剩余流量 中转", "f"),
    ];
    let with_exit: Vec<(&ProxyNode, Option<&str>)> = nodes.iter().map(|n| (n, None)).collect();
    let tags: Vec<String> = nodes.iter().map(|n| n.name.clone()).collect();
    let kinds: Vec<(String, Vec<String>)> = classify(&with_exit, &tags)
        .into_iter()
        .filter(|g| g.tag.starts_with("kind:"))
        .map(|g| (g.tag, g.members))
        .collect();
    assert_eq!(
        kinds,
        [
            (
                "kind:relay".to_owned(),
                vec!["香港 01 中转".to_owned(), "日本 relay".to_owned()]
            ),
            (
                "kind:lowrate".to_owned(),
                vec!["新加坡 0.5x".to_owned(), "韩国 x0.2".to_owned()]
            ),
        ]
    );
}

#[test]
fn exits_by_address_resolved_domains_and_ipv6_filter() {
    let input = PoolInput::from_json(&json!({
        "subscriptions": [{"id": "s", "url": "u", "nodes": [
            {"name": "Node A", "outbound": {"type": "trojan", "server": "A.example", "server_port": 1, "password": "p"}},
            {"name": "Node B", "outbound": {"type": "trojan", "server": "2001:DB8::1", "server_port": 2, "password": "p"}},
            {"name": "Node C", "outbound": {"type": "trojan", "server": "1.2.3.4", "server_port": 3, "password": "p"}},
            {"name": "Node D IPv6", "outbound": {"type": "trojan", "server": "d.example", "server_port": 4, "password": "p"}},
        ]}],
        "exits": {"5.6.7.8:1": "PL", "[2001:db8::1]:2": "JP", "1.2.3.4:3": "US"},
        "resolved": {"a.example": "5.6.7.8"},
        "ipv6": true,
        "now": 0,
    }));
    let pool = build_pool(&input);
    let exits: Vec<Option<&str>> = pool.nodes.iter().map(|n| n.exit.as_deref()).collect();
    assert_eq!(exits, [Some("PL"), Some("JP"), Some("US"), None]);
    assert_eq!(
        pool.region_by_tag["Node A"].as_ref().map(Region::label),
        Some("🇵🇱 PL".into())
    );
    assert_eq!(pool.region_by_tag["Node D IPv6"], None);

    let pool = build_pool(&PoolInput {
        ipv6: false,
        ..input
    });
    assert_eq!(pool.tags, ["Node A", "Node C"]);
}

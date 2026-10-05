use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use super::*;

const T0: i64 = 1_800_000_000;

fn store() -> (Store, Arc<AtomicI64>) {
    let clock = Arc::new(AtomicI64::new(T0));
    let c = Arc::clone(&clock);
    (
        Store::with_clock(move || c.load(Ordering::Relaxed), 7),
        clock,
    )
}

fn lines(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

fn ok(ms: f64) -> Outcome {
    Outcome {
        first_ms: ms,
        connect_ms: ms / 2.0,
        ..Outcome::default()
    }
}

fn fail() -> Outcome {
    Outcome {
        failed: true,
        ..Outcome::default()
    }
}

#[test]
fn site_keys() {
    assert_eq!(site_key("video.Example.com."), "example.com");
    assert_eq!(site_key("a.b.example.co.uk"), "example.co.uk");
    assert_eq!(site_key("1.2.3.4"), "1.2.3.0/24");
    assert_eq!(site_key("2001:db8:1:2::5"), "2001:db8:1::/48");
    assert_eq!(site_key(""), "");
}

#[test]
fn unknown_site_races_the_best_overall() {
    let (s, _) = store();
    s.report("", "a", &ok(400.0));
    s.report("", "b", &ok(100.0));
    s.report("", "c", &ok(200.0));
    s.report("", "d", &fail());
    let p = s.plan("new.com", &lines(&["a", "b", "c", "d"]));
    assert_eq!(p.race, 3);
    assert!(!p.known);
    assert_eq!(&p.lines[..3], &lines(&["b", "c", "a"])[..]);
}

#[test]
fn known_good_site_uses_its_own_best() {
    let (s, _) = store();
    for _ in 0..3 {
        s.report("x.com", "slow-overall-but-good-here", &ok(80.0));
        s.report("", "fast-overall", &ok(50.0));
    }
    // Over many plans: almost always alone on its line, sometimes a
    // challenger (exploration).
    let mut alone = 0;
    for _ in 0..200 {
        let p = s.plan(
            "x.com",
            &lines(&["fast-overall", "slow-overall-but-good-here"]),
        );
        assert!(p.known);
        assert_eq!(p.lines[0], "slow-overall-but-good-here");
        if p.race == 1 {
            alone += 1;
        }
    }
    assert!(alone > 170, "explores too often: {alone}/200");
}

#[test]
fn failures_move_the_site_away() {
    let (s, _) = store();
    s.report("x.com", "a", &ok(100.0));
    s.report("x.com", "b", &ok(300.0));
    for _ in 0..4 {
        s.report("x.com", "a", &fail());
    }
    s.report("", "a", &ok(10.0)); // don't ban: one success overall
    let p = s.plan("y.x.com", &lines(&["a", "b"]));
    let p2 = s.plan("x.com", &lines(&["a", "b"]));
    assert_eq!(p2.lines[0], "b", "{p2:?}");
    assert!(!p.lines.is_empty());
}

#[test]
fn old_failures_fade() {
    let (s, clock) = store();
    for _ in 0..5 {
        s.report("x.com", "a", &fail());
    }
    s.report("", "a", &ok(1.0)); // out of the ban box
    let fresh = s.snapshot("x.com")["a"].cost();
    clock.store(T0 + 30 * 24 * 3600, Ordering::Relaxed);
    s.report("x.com", "a", &ok(100.0));
    let later = s.snapshot("x.com")["a"].cost();
    assert!(later < fresh / 3.0, "{later} vs {fresh}");
}

#[test]
fn throughput_counts_for_downloads() {
    let mut fast = Record::default();
    let mut slow = Record::default();
    for _ in 0..3 {
        fast.add(
            &Outcome {
                first_ms: 300.0,
                bytes: 50 << 20,
                duration_ms: 2000.0,
                ..Outcome::default()
            },
            T0,
        );
        slow.add(
            &Outcome {
                first_ms: 300.0,
                bytes: 5 << 20,
                duration_ms: 5000.0,
                ..Outcome::default()
            },
            T0,
        );
    }
    assert!(fast.cost() < slow.cost());
}

#[test]
fn save_and_load() {
    let dir = std::env::temp_dir().join(format!("meow-smart-{}", std::process::id()));
    let path = dir.join("smart-auto.json");
    let s = Store::new(Some(path.clone()));
    s.report("x.com", "a", &ok(120.0));
    s.set_exit(
        "a",
        Exit {
            ip: "1.2.3.4".into(),
            country: "JP".into(),
        },
    );
    s.use_line("x.com", "a");
    s.save().unwrap();
    let again = Store::new(Some(path));
    assert_eq!(again.snapshot("x.com").len(), 1);
    assert_eq!(again.exit_of("a").unwrap().country, "JP");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn families_share_one_exit() {
    let (s, _) = store();
    for l in ["a", "b", "c"] {
        s.report("", l, &ok(100.0));
    }
    s.use_line("youtube.com", "c");
    let p = s.plan("googlevideo.com", &lines(&["a", "b", "c"]));
    assert!(p.pinned);
    assert_eq!(p.race, 1);
    assert_eq!(p.lines[0], "c");
}

#[test]
fn pinned_failover_prefers_same_exit_then_country() {
    let (s, _) = store();
    for l in ["pin", "same-ip", "same-cc", "other"] {
        s.report("", l, &ok(100.0));
    }
    s.set_exit(
        "pin",
        Exit {
            ip: "9.9.9.9".into(),
            country: "JP".into(),
        },
    );
    s.set_exit(
        "same-ip",
        Exit {
            ip: "9.9.9.9".into(),
            country: "JP".into(),
        },
    );
    s.set_exit(
        "same-cc",
        Exit {
            ip: "8.8.8.8".into(),
            country: "JP".into(),
        },
    );
    s.set_exit(
        "other",
        Exit {
            ip: "7.7.7.7".into(),
            country: "US".into(),
        },
    );
    s.use_line("x.com", "pin");
    let p = s.plan("x.com", &lines(&["other", "same-cc", "same-ip", "pin"]));
    assert_eq!(p.lines, lines(&["pin", "same-ip", "same-cc", "other"]));
}

#[test]
fn pin_expires_when_unused() {
    let (s, clock) = store();
    s.report("", "a", &ok(500.0));
    s.report("", "b", &ok(50.0));
    s.use_line("x.com", "a");
    assert_eq!(s.plan("x.com", &lines(&["a", "b"])).lines[0], "a");
    clock.store(T0 + 3 * 3600, Ordering::Relaxed);
    assert!(!s.plan("x.com", &lines(&["a", "b"])).pinned);
}

#[test]
fn balance_spreads_sites_and_keeps_each_on_one_line() {
    let (s, _) = store();
    s.set_balance(true);
    let all = lines(&["a", "b", "c", "d"]);
    for l in &all {
        s.report("", l, &ok(100.0));
    }
    let mut used = std::collections::HashSet::new();
    for i in 0..40 {
        let site = format!("site{i}.com");
        let first = s.plan(&site, &all).lines[0].clone();
        assert_eq!(s.plan(&site, &all).lines[0], first, "stable per site");
        used.insert(first);
    }
    assert!(used.len() >= 3, "spread over lines: {used:?}");
}

#[test]
fn ban_sits_out_then_a_probe_lets_it_out() {
    let (s, clock) = store();
    let all = lines(&["a", "b", "c"]);
    s.report("x.com", "a", &fail());
    s.report("y.com", "a", &fail());
    assert_eq!(s.free(&all).len(), 3, "two failures: still in");
    s.report("z.com", "a", &fail());
    s.report("x.com", "b", &ok(50.0));
    assert_eq!(s.free(&all), lines(&["b", "c"]));
    assert!(s.banned("a"));
    // One failed probe alone doesn't ban (the probe target may be down).
    s.report("", "c", &fail());
    assert!(!s.banned("c"));
    // Time up: due for a probe, still out until it passes.
    clock.store(T0 + BAN_SECS + 1, Ordering::Relaxed);
    assert_eq!(s.due(&all), lines(&["a"]));
    assert_eq!(s.free(&all), lines(&["b", "c"]));
    s.report("", "a", &ok(80.0));
    assert_eq!(s.free(&all), all);
    // A banned line failing its re-check probe stays out.
    for site in ["p.com", "q.com", "r.com"] {
        s.report(site, "b", &fail());
    }
    clock.store(T0 + 2 * BAN_SECS + 2, Ordering::Relaxed);
    s.report("", "b", &fail());
    assert!(s.banned("b"));
}

#[test]
fn refresh_candidates_recent_then_best() {
    let (s, clock) = store();
    for (i, l) in ["a", "b", "c", "d", "e"].iter().enumerate() {
        clock.store(T0 + i as i64, Ordering::Relaxed);
        s.report("", l, &ok(100.0 * (5 - i) as f64));
    }
    let c = s.refresh_candidates(&lines(&["a", "b", "c", "d", "e"]), 4);
    assert_eq!(c.len(), 4);
    assert_eq!(&c[..2], &lines(&["e", "d"])[..]);
}

#[test]
fn cold_start_races_wider() {
    let (s, _) = store();
    let all = lines(&["a", "b", "c", "d", "e", "f", "g"]);
    assert_eq!(s.plan("x.com", &all).race, 6, "nothing known yet");
    s.report("", "c", &ok(100.0));
    assert_eq!(s.plan("x.com", &all).race, 3, "probes have answered");
}

fn exit(ip: &str, cc: &str) -> Exit {
    Exit {
        ip: ip.into(),
        country: cc.into(),
    }
}

const MB: f64 = (1u64 << 20) as f64;

#[test]
fn a_busy_exit_lends_new_connections_to_a_roomier_line_of_its_country() {
    let (s, _) = store();
    for l in ["a", "b", "far"] {
        s.report("", l, &ok(100.0));
        s.report("dl.example", l, &ok(100.0));
    }
    s.set_exit("a", exit("1.1.1.1", "JP"));
    s.set_exit("b", exit("2.2.2.2", "JP"));
    s.set_exit("far", exit("3.3.3.3", "US"));
    s.use_line("dl.example", "a");
    let all = lines(&["a", "b", "far"]);
    // Quiet: the exit's line.
    let p = s.plan_with("dl.example", &all, &LoadView::new());
    assert_eq!(p.lines[0], "a");
    assert!(p.keep_pin.is_none());
    // Downloading at 3 MB/s of its 3.5: b (same country, idle) takes the
    // new connection; the family stays on a; never the other country.
    let load: LoadView = [
        ("a".to_string(), (3.0 * MB, 3.5 * MB)),
        ("b".to_string(), (0.0, 3.0 * MB)),
        ("far".to_string(), (0.0, 50.0 * MB)),
    ]
    .into();
    let p = s.plan_with("dl.example", &all, &load);
    assert_eq!(p.lines[0], "b");
    assert_eq!(p.keep_pin.as_deref(), Some("a"));
    // Sites whose accounts watch the address never spread.
    for l in ["a", "b"] {
        s.report("google.com", l, &ok(100.0));
    }
    s.use_line("google.com", "a");
    assert_eq!(s.plan_with("google.com", &all, &load).lines[0], "a");
}

#[test]
fn fastest_goes_by_measured_download_speed_and_never_pins() {
    let (s, _) = store();
    for l in ["slow", "quick", "new"] {
        s.report("", l, &ok(if l == "slow" { 50.0 } else { 300.0 }));
    }
    s.set_fastest(true);
    let load: LoadView = [
        ("slow".to_string(), (0.0, 1.0 * MB)),
        ("quick".to_string(), (0.0, 9.0 * MB)),
    ]
    .into();
    let all = lines(&["slow", "quick", "new"]);
    let mut first = std::collections::HashMap::new();
    for _ in 0..300 {
        let p = s.plan_with("x.com", &all, &load);
        assert!(p.no_pin);
        *first.entry(p.lines[0].clone()).or_insert(0) += 1;
    }
    // Lower latency doesn't win; the unmeasured one is tried now and then.
    assert!(first["quick"] > 230, "{first:?}");
    assert!(first.get("new").copied().unwrap_or(0) > 5, "{first:?}");
    assert!(!first.contains_key("slow"), "{first:?}");
}

#[test]
fn a_slow_mark_moves_only_that_site_and_expires() {
    let (s, clock) = store();
    let all = lines(&["a", "b", "c"]);
    for site in ["googlevideo.com", "example.com"] {
        s.report(site, "a", &ok(50.0));
        s.report(site, "b", &ok(200.0));
        s.report(site, "c", &ok(300.0));
    }
    s.use_line("googlevideo.com", "a");
    assert_eq!(s.plan("youtube.com", &all).lines[0], "a", "family pinned");
    assert!(s.mark_slow("googlevideo.com", "a"));
    assert!(!s.mark_slow("googlevideo.com", "a"), "already marked");
    // The family's pin on a is gone; a goes last for every Google site.
    for site in ["googlevideo.com", "youtube.com"] {
        let p = s.plan(site, &all);
        assert!(!p.pinned, "{site}: {p:?}");
        assert_eq!(p.lines.last().unwrap(), "a", "{site}: {p:?}");
    }
    assert_eq!(s.plan("googlevideo.com", &all).lines[0], "b");
    // Other sites keep their best line.
    for _ in 0..20 {
        assert_eq!(s.plan("example.com", &all).lines[0], "a");
    }
    assert!(s.slow("youtube.com").contains_key("a"));
    clock.store(T0 + SLOW_SECS + 1, Ordering::Relaxed);
    assert!(s.slow("youtube.com").is_empty());
    assert_eq!(s.plan("googlevideo.com", &all).lines[0], "a", "expired");
}

#[test]
fn a_slow_mark_keeps_a_pin_on_another_line() {
    let (s, _) = store();
    let all = lines(&["a", "b"]);
    for l in ["a", "b"] {
        s.report("x.com", l, &ok(100.0));
    }
    s.use_line("x.com", "b");
    s.mark_slow("x.com", "a");
    let p = s.plan("x.com", &all);
    assert!(p.pinned);
    assert_eq!(p.lines, all.iter().rev().cloned().collect::<Vec<_>>());
}

#[test]
fn speed_tests_cool_down_per_family() {
    let (s, clock) = store();
    assert!(s.speed_probe_due("googlevideo.com"));
    assert!(!s.speed_probe_due("googlevideo.com"));
    assert!(!s.speed_probe_due("youtube.com"), "same family");
    assert!(s.speed_probe_due("example.com"), "another site");
    clock.store(T0 + SPEED_PROBE_COOLDOWN, Ordering::Relaxed);
    assert!(s.speed_probe_due("youtube.com"));
}

#[test]
fn balance_moves_a_site_off_its_slow_line_and_keeps_the_others() {
    let (s, _) = store();
    s.set_balance(true);
    let all = lines(&["a", "b", "c", "d"]);
    for l in &all {
        s.report("", l, &ok(100.0));
    }
    let sites: Vec<String> = (0..30).map(|i| format!("site{i}.com")).collect();
    let before: Vec<String> = sites
        .iter()
        .map(|site| {
            let line = s.plan(site, &all).lines[0].clone();
            s.use_line(site, &line);
            s.report(site, &line, &ok(100.0));
            line
        })
        .collect();
    let (moved, slow_line) = (&sites[0], before[0].clone());
    s.mark_slow(moved, &slow_line);
    let p = s.plan(moved, &all);
    assert_ne!(p.lines[0], slow_line);
    assert_eq!(p.lines.last(), Some(&slow_line));
    // The next line of its ring: what it would get without the slow line.
    let rest: Vec<String> = all.iter().filter(|l| **l != slow_line).cloned().collect();
    let fresh = Store::with_clock(|| T0, 7);
    fresh.set_balance(true);
    for l in &all {
        fresh.report("", l, &ok(100.0));
    }
    assert_eq!(p.lines[0], fresh.plan(moved, &rest).lines[0]);
    for (site, line) in sites.iter().zip(&before).skip(1) {
        assert_eq!(&s.plan(site, &all).lines[0], line, "{site} kept its line");
    }
}

#[test]
fn fastest_puts_a_slow_line_last_for_that_site() {
    let (s, _) = store();
    s.set_fastest(true);
    for l in ["quick", "other"] {
        s.report("", l, &ok(100.0));
    }
    let load: LoadView = [
        ("quick".to_string(), (0.0, 9.0 * MB)),
        ("other".to_string(), (0.0, 1.0 * MB)),
    ]
    .into();
    let all = lines(&["quick", "other"]);
    s.mark_slow("x.com", "quick");
    for _ in 0..50 {
        assert_eq!(s.plan_with("x.com", &all, &load).lines[0], "other");
        assert_eq!(s.plan_with("y.com", &all, &load).lines[0], "quick");
    }
}

#[test]
fn samples_update_speed_without_counting_a_connection() {
    let (s, _) = store();
    s.report("x.com", "a", &ok(100.0));
    s.sample("x.com", "a", 6 << 20, 3000.0);
    let rec = s.snapshot("x.com")["a"];
    assert_eq!(rec.success, 1.0);
    assert!((rec.throughput - 2.0 * MB).abs() < 1.0, "{rec:?}");
    // A site never seen gains no record from a sample.
    s.sample("new.com", "a", 6 << 20, 3000.0);
    assert!(s.snapshot("new.com").is_empty());
}

#[test]
fn sites_by_the_public_suffix_list() {
    for (host, site) in [
        ("api.weiba.pp.ua", "weiba.pp.ua"),
        ("x.user.github.io", "user.github.io"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("www.example.com.cn", "example.com.cn"),
        ("Video.CDN.Example.com.", "example.com"),
        ("pp.ua", "pp.ua"),
        ("203.0.113.5", "203.0.113.5"),
        ("[2001:db8::1]", "[2001:db8::1]"),
    ] {
        assert_eq!(site_of_host(host), site, "{host}");
    }
    let json: serde_json::Value = serde_json::from_str(&sites_json(&["api.weiba.pp.ua"])).unwrap();
    assert_eq!(json["api.weiba.pp.ua"], "weiba.pp.ua");
}

#[test]
fn a_lines_best_speed_is_kept_fades_over_days_and_stays_in_the_group() {
    let (s, clock) = store();
    // 10 MB/s in a speed test, then 2 MB/s: the best stays 10.
    s.sample("googlevideo.com", "h01", 10 << 20, 1000.0);
    s.sample("googlevideo.com", "h01", 2 << 20, 1000.0);
    s.sample("googlevideo.com", "tw", 1 << 20, 1000.0);
    let p = s.peaks(&lines(&["h01", "tw", "never"]));
    assert_eq!(p["h01"], ((10 << 20) as f64, T0));
    assert!(!p.contains_key("never"), "never measured");
    // Only the lines asked for (the group's own members).
    assert_eq!(s.peaks(&lines(&["tw"])).len(), 1);
    // Three days on it counts half; a faster speed then takes over.
    clock.store(T0 + PEAK_HALF_LIFE as i64, Ordering::Relaxed);
    let half = s.peaks(&lines(&["h01"]))["h01"].0;
    assert!((half - (5 << 20) as f64).abs() < 1.0, "{half}");
    s.sample("googlevideo.com", "h01", 6 << 20, 1000.0);
    assert_eq!(s.peaks(&lines(&["h01"]))["h01"].0, (6 << 20) as f64);
}

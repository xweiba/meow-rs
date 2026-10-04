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

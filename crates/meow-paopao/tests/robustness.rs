//! D15: the release profile is `panic = "abort"`, so a panic inside the
//! library would end the app (no `catch_unwind` across the FFI then).
//! Every golden input, randomly broken (keys dropped, values of the wrong
//! type, huge numbers, odd strings), must build, explain and parse without
//! a panic. Seeded: a failure names its case and seed, and repeats.

// Only the corpus readers are used here.
#[allow(dead_code)]
mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use serde_json::{json, Value};

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        // n is small: the modulo bias does not matter here.
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap_or(0)
    }
}

/// Values of the wrong type, out of range or odd.
fn odd_value(rng: &mut Rng) -> Value {
    let long = "x".repeat(10_000);
    let deep = (0..64).fold(json!(1), |v, _| json!([v]));
    let pick: [Value; 30] = [
        Value::Null,
        json!(true),
        json!(false),
        json!(0),
        json!(-1),
        json!(i64::MAX),
        json!(i64::MIN),
        json!(u64::MAX),
        json!(1e308),
        json!(-1e308),
        json!(0.5),
        json!(-0.0),
        json!(""),
        json!(" "),
        json!("\u{0}"),
        json!("\u{feff}"),
        json!("💥🇭🇰"),
        json!("%FF%"),
        json!("0x1BB"),
        json!("+443"),
        json!("region:"),
        json!("a~b~c"),
        json!("AND,((,x"),
        json!("[::1]:"),
        json!("ſtg Ünïcödé 香港 01"),
        json!(long),
        json!([]),
        json!({}),
        json!([null, 1, "a", {}]),
        deep,
    ];
    pick[rng.below(pick.len())].clone()
}

/// Every place in `v` (as a path of keys / indexes).
fn paths(v: &Value, at: &mut Vec<Step>, out: &mut Vec<Vec<Step>>) {
    out.push(at.clone());
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                at.push(Step::Key(k.clone()));
                paths(x, at, out);
                at.pop();
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                at.push(Step::Index(i));
                paths(x, at, out);
                at.pop();
            }
        }
        _ => {}
    }
}

#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

fn get_mut<'a>(v: &'a mut Value, path: &[Step]) -> Option<&'a mut Value> {
    path.iter().try_fold(v, |v, s| match s {
        Step::Key(k) => v.get_mut(k.as_str()),
        Step::Index(i) => v.get_mut(*i),
    })
}

/// One random change somewhere in `v`.
fn mutate(v: &mut Value, rng: &mut Rng) {
    let mut all = Vec::new();
    paths(v, &mut Vec::new(), &mut all);
    let path = all[rng.below(all.len())].clone();
    match rng.below(4) {
        // Drop it (from its object or list).
        0 if !path.is_empty() => {
            let (last, parent) = path.split_last().unwrap_or((&Step::Index(0), &[]));
            if let Some(p) = get_mut(v, parent) {
                match (p, last) {
                    (Value::Object(m), Step::Key(k)) => {
                        m.shift_remove(k);
                    }
                    (Value::Array(a), Step::Index(i)) if *i < a.len() => {
                        a.remove(*i);
                    }
                    _ => {}
                }
            }
        }
        // Repeat a list's item.
        1 => {
            if let Some(Value::Array(a)) = get_mut(v, &path) {
                if let Some(x) = a.first().cloned() {
                    a.push(x);
                }
            }
        }
        // Anything else: an odd value in its place.
        _ => {
            if let Some(x) = get_mut(v, &path) {
                *x = odd_value(rng);
            }
        }
    }
}

/// Hosts to explain on the broken inputs.
const HOSTS: [&str; 6] = [
    "example.com",
    "10.1.2.3",
    "[::1]",
    "",
    "AND,((",
    "很长的.名字.example",
];

#[test]
fn broken_build_inputs_never_panic() {
    let files = common::golden_files("build");
    let rounds: u64 = std::env::var("ROBUST_ROUNDS")
        .ok()
        .and_then(|r| r.parse().ok())
        .unwrap_or(12);
    let mut failures = Vec::new();
    let mut runs = 0;
    for (n, path) in files.iter().enumerate() {
        let case = common::read_json(path);
        for round in 0..rounds {
            let seed = (n as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (round + 1);
            let mut rng = Rng(seed | 1);
            let mut input = case["input"].clone();
            for _ in 0..=rng.below(4) {
                mutate(&mut input, &mut rng);
            }
            let text = input.to_string();
            let host = HOSTS[rng.below(HOSTS.len())];
            let query = json!({"host": host, "port": rng.below(70_000), "process": "WeChat"});
            runs += 1;
            let ok = catch_unwind(AssertUnwindSafe(|| {
                let _ = meow_paopao::build_json(&text);
                if round % 3 == 0 {
                    let _ = meow_paopao::explain_json(&text, &query.to_string());
                }
            }));
            if ok.is_err() {
                failures.push(format!("{}: seed {seed:#x}", path.display()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {runs} broken inputs panicked:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("broken build inputs: {runs} without a panic");
}

/// Bodies cut, spliced with odd text, digits swapped.
#[test]
fn broken_subscription_bodies_never_panic() {
    let files = common::golden_files("parse");
    let odd = [
        "\u{0}",
        "%",
        "%F",
        "%FF",
        "#",
        "@",
        ":",
        "://",
        "\n",
        "\r",
        "{",
        "[",
        "- ",
        ": ",
        "0x1BB",
        "💥",
        "\u{feff}",
        "&",
        "=",
        "?",
        "!!binary ",
        "*a",
        "&a ",
    ];
    let mut failures = Vec::new();
    let mut runs = 0;
    for (n, path) in files.iter().enumerate() {
        let case = common::read_json(path);
        let body = case["body"].as_str().unwrap_or_default().to_owned();
        let chars: Vec<char> = body.chars().collect();
        for round in 0..40u64 {
            let seed = (n as u64 + 7).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (round + 1);
            let mut rng = Rng(seed | 1);
            let mut c = chars.clone();
            for _ in 0..=rng.below(5) {
                let at = rng.below(c.len() + 1);
                match rng.below(3) {
                    0 => c.truncate(at),
                    1 => {
                        let s: Vec<char> = odd[rng.below(odd.len())].chars().collect();
                        c.splice(at..at, s);
                    }
                    _ => {
                        if let Some(x) = c.get_mut(at) {
                            if x.is_ascii_digit() {
                                *x = '9';
                            }
                        }
                    }
                }
            }
            let text: String = c.into_iter().collect();
            runs += 1;
            if catch_unwind(|| meow_paopao::parse_json(&text)).is_err() {
                failures.push(format!("{}: seed {seed:#x}", path.display()));
            }
            // Links and bodies also go through the base64 path.
            let b64 = base64_encode(&text);
            if catch_unwind(|| meow_paopao::parse_json(&b64)).is_err() {
                failures.push(format!("{} (base64): seed {seed:#x}", path.display()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {runs} broken bodies panicked:\n{}",
        failures.len(),
        failures.join("\n")
    );
    eprintln!("broken bodies: {runs} without a panic");
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s)
}

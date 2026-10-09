//! Parse goldens: every `tests/golden/parse/*.json` body must parse to what
//! the Dart parser produced, and every `usage.json` header likewise.

mod common;

use meow_paopao::{parse_subscription, usage_from_names, Usage};
use serde_json::{json, Value};

#[test]
fn parse_goldens() {
    let files = common::golden_files("parse");
    assert!(!files.is_empty(), "no parse goldens");
    let mut failures = Vec::new();
    for path in &files {
        let case = common::read_json(path);
        let name = case["name"].as_str().unwrap_or_default();
        let body = case["body"].as_str().expect("body");
        let got = match parse_subscription(body) {
            Ok(r) => {
                let usage = usage_from_names(r.nodes.iter().map(|n| n.name.as_str()));
                json!({
                    "nodes": r.nodes,
                    "skipped": r.skipped,
                    "split": r.split,
                    "usage": usage,
                })
            }
            Err(e) => json!({ "error": e.message }),
        };
        if let Some(d) = common::first_diff(&got, &case["expected"]) {
            failures.push(format!("{name}: {d}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} parse goldens differ:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
    eprintln!("parse goldens: {} passed", files.len());
}

#[test]
fn usage_goldens() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/usage.json");
    let cases = common::read_json(&path);
    let cases = cases.as_array().expect("usage.json is a list");
    let mut failures = Vec::new();
    for case in cases {
        let header = case["header"].as_str().expect("header");
        let got = Usage::parse(header).map_or(Value::Null, |u| u.to_json());
        if let Some(d) = common::first_diff(&got, &case["expected"]) {
            failures.push(format!("{header:?}: {d}"));
        }
    }
    assert!(
        failures.is_empty(),
        "usage goldens differ:\n{}",
        failures.join("\n")
    );
    eprintln!("usage goldens: {} passed", cases.len());
}

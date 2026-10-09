//! Pool layer: for every `tests/golden/build/*.json`, the pool built from
//! the case's input must equal `expected.pool` (tags, nodes with exits,
//! groups), key order included.

mod common;

use meow_paopao::{build_pool, PoolInput};

#[test]
fn pool_matches_dart() {
    let files = common::golden_files("build");
    assert!(!files.is_empty(), "no build goldens");
    let mut failures = Vec::new();
    for path in &files {
        let case = common::read_json(path);
        let input: PoolInput = serde_json::from_value(case["input"].clone()).expect("input");
        let got = build_pool(&input).to_json();
        if let Some(d) = common::first_diff(&got, &case["expected"]["pool"]) {
            failures.push(format!("{}: {d}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "pool differs in {} of {} cases:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
    eprintln!("pool: {} passed", files.len());
}

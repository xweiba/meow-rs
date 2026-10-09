//! Plan layer: for every `tests/golden/build/*.json`, the group tree built
//! from the case's input (pool first) must equal `expected.tree.groups`,
//! key order included.

mod common;

use meow_paopao::{build_pool, build_tree, BuildInput};

#[test]
fn tree_matches_dart() {
    let files = common::golden_files("build");
    assert!(!files.is_empty(), "no build goldens");
    let mut failures = Vec::new();
    for path in &files {
        let case = common::read_json(path);
        let input: BuildInput = serde_json::from_value(case["input"].clone()).expect("input");
        let pool = build_pool(&input.pool_input());
        let got = build_tree(&input, &pool).to_json();
        if let Some(d) = common::first_diff(&got["groups"], &case["expected"]["tree"]["groups"]) {
            failures.push(format!("{}: {d}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "tree differs in {} of {} cases:\n{}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
    eprintln!("tree: {} passed", files.len());
}

//! Settings round trip: the settings of every `tests/golden/build/*.json`
//! (as Dart saved them) must decode and encode back to the same JSON, key
//! order included.

mod common;

use meow_paopao::ProxySettings;

#[test]
fn settings_round_trip() {
    let files = common::golden_files("build");
    assert!(!files.is_empty(), "no build goldens");
    let mut failures = Vec::new();
    for path in &files {
        let case = common::read_json(path);
        let want = &case["input"]["settings"];
        let settings: ProxySettings = serde_json::from_value(want.clone()).expect("settings");
        let got = serde_json::to_value(&settings).expect("encode");
        if let Some(d) = common::first_diff(&got, want) {
            failures.push(format!("{}: {d}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "settings round trip differs:\n{}",
        failures.join("\n")
    );
    eprintln!("settings round trip: {} passed", files.len());
}

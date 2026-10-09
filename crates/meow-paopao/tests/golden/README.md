# Golden corpus

`parse/`, `build/` and `usage.json` were first exported from the Dart
implementation in PaoPao (`paopao_proxy` `test/golden_dump_test.dart`), so
the Rust port could be compared with it case by case.

Config generation now exists only here: the Dart generator and its dump
test are gone, and these files are owned by this crate. When the Rust
output changes on purpose (the behaviour fixes listed in the PaoPao task
`10-09-config-rust`, `research/decisions.md`), update the expected files
here together with the code change.

To regenerate the expected parts from the current output (only for a
deliberate change; review `git diff tests/golden` and make sure every
change is explained before keeping it):

    UPDATE_GOLDEN=1 cargo test -p meow-paopao --test golden_config --test golden_parse

`tests/robustness.rs` builds every input here with random breakage and
must never panic (the release profile aborts on a panic, which would end
the app); `ROBUST_ROUNDS=200` runs a longer sweep.

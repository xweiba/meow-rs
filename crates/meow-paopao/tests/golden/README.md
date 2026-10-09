# Golden corpus

`parse/`, `build/` and `usage.json` were first exported from the Dart
implementation in PaoPao (`paopao_proxy` `test/golden_dump_test.dart`), so
the Rust port could be compared with it case by case.

Config generation now exists only here: the Dart generator and its dump
test are gone, and these files are owned by this crate. When the Rust
output changes on purpose (the behaviour fixes listed in the PaoPao task
`10-09-config-rust`, `research/decisions.md`), update the expected files
here together with the code change.

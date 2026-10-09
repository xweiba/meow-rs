//! Shared by the golden tests: reading the corpus and reporting the first
//! difference between two JSON values.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// `tests/golden/<dir>/*.json`, sorted.
pub fn golden_files(dir: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(dir);
    let mut files: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("{}: {e}", root.display()))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    files
}

/// `UPDATE_GOLDEN=1`: the golden tests rewrite the expected parts of their
/// files from the current output instead of comparing (for a deliberate
/// behaviour change; review `git diff tests/golden` before keeping it). Run
/// only the tests that own the files, one binary at a time:
/// `UPDATE_GOLDEN=1 cargo test -p meow-paopao --test golden_config --test golden_parse`.
#[allow(dead_code)] // not every golden test binary rewrites files
pub fn updating() -> bool {
    std::env::var_os("UPDATE_GOLDEN").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Writes `v` as the corpus is formatted: two-space indent, UTF-8 as is,
/// a final newline.
#[allow(dead_code)]
pub fn write_json(path: &Path, v: &Value) {
    let mut text = serde_json::to_string_pretty(v).expect("encode");
    text.push('\n');
    std::fs::write(path, text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

pub fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The first place `got` and `want` differ, as `path: got … want …`; None
/// when equal. Object key order counts.
pub fn first_diff(got: &Value, want: &Value) -> Option<String> {
    diff_at("$", got, want)
}

fn diff_at(path: &str, got: &Value, want: &Value) -> Option<String> {
    match (got, want) {
        (Value::Object(g), Value::Object(w)) => {
            let gk: Vec<&String> = g.keys().collect();
            let wk: Vec<&String> = w.keys().collect();
            for (k, wv) in w {
                let Some(gv) = g.get(k) else {
                    return Some(format!("{path}.{k}: missing, want {wv}"));
                };
                if let Some(d) = diff_at(&format!("{path}.{k}"), gv, wv) {
                    return Some(d);
                }
            }
            if let Some(extra) = gk.iter().find(|k| !w.contains_key(k.as_str())) {
                return Some(format!("{path}.{extra}: unexpected {}", g[extra.as_str()]));
            }
            (gk != wk).then(|| format!("{path}: key order {gk:?}, want {wk:?}"))
        }
        (Value::Array(g), Value::Array(w)) => {
            for (i, (gv, wv)) in g.iter().zip(w).enumerate() {
                if let Some(d) = diff_at(&format!("{path}[{i}]"), gv, wv) {
                    return Some(d);
                }
            }
            (g.len() != w.len()).then(|| format!("{path}: length {}, want {}", g.len(), w.len()))
        }
        _ => (got != want).then(|| format!("{path}: got {got}, want {want}")),
    }
}

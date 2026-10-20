//! File saves are observed by the core, including while Flutter is closed.
//! Metadata is only a change hint: bounded bytes are compared before a
//! rebuild, and two equal observations debounce non-atomic editor saves.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::Value;
use tokio::io::AsyncReadExt as _;

use super::Service;

#[derive(Default)]
struct Watch {
    input: Option<(u64, Option<SystemTime>)>,
    path: Option<PathBuf>,
    pending: Option<Vec<u8>>,
    applied: Option<Vec<u8>>,
}

impl Watch {
    async fn once(&mut self, svc: &Service) {
        let input = svc.store().input();
        let Ok(meta) = tokio::fs::metadata(&input).await else {
            return;
        };
        let stamp = (meta.len(), meta.modified().ok());
        if self.input != Some(stamp) {
            let Ok(bytes) = tokio::fs::read(input).await else {
                return;
            };
            let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
                return;
            };
            let path = value
                .pointer("/runtime/rulesFile")
                .and_then(Value::as_str)
                .map(PathBuf::from);
            if self.path != path {
                self.path = path;
                self.pending = None;
                self.applied = None;
            }
            self.input = Some(stamp);
        }
        let Some(path) = &self.path else {
            return;
        };
        // Editor renames and missing files retain the last good config.
        let Ok(file) = tokio::fs::File::open(path).await else {
            return;
        };
        let mut bytes = Vec::new();
        if file
            .take(512 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .is_err()
        {
            return;
        }
        if self.applied.as_ref() == Some(&bytes) {
            return;
        }
        if self.pending.as_ref() != Some(&bytes) {
            self.pending = Some(bytes);
            return;
        }
        // Retain the bytes attempted even on refusal; an invalid file is
        // retried on its next edit rather than spawning a child every poll.
        match svc.apply_rules().await {
            Ok(report) => {
                self.applied = Some(bytes);
                if report.error.is_some() {
                    tracing::warn!("paopao: edited routing rules refused; current config retained");
                }
            }
            Err(super::JobError::Unavailable) => self.applied = Some(bytes),
            Err(_) => {}
        }
    }
}

/// A native task independent of the panel and subscription schedule.
pub async fn run_rules_watch(svc: Arc<Service>) {
    let mut watch = Watch::default();
    loop {
        watch.once(&svc).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::{Reload, Runner};
    use super::*;
    use meow_config::raw::RawConfig;
    use parking_lot::RwLock;

    #[tokio::test]
    async fn saves_are_debounced_and_native_rebuild_refusal_keeps_watching() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("routing-rules.json");
        let log = dir.path().join("calls");
        // This stand-in records native rebuilds, including refused ones;
        // profile parsing and actual reload are exercised in integration.
        let runner = Runner::new("sh").with_prefix(["-c".into(), format!(
            "cat >/dev/null; printf x >> '{}'; echo '{{\"error\":\"invalid saved profile\"}}'; exit 2", log.display()
        ), "sh".into()]);
        let reload: Reload =
            Arc::new(|_| Box::pin(async { panic!("a refused build must never reload") }));
        let svc = Service::new(
            Some(Arc::new(runner)),
            Arc::new(RwLock::new(RawConfig::default())),
            dir.path(),
            None,
            reload,
        );
        std::fs::create_dir_all(svc.store().dir()).unwrap();
        std::fs::write(
            svc.store().input(),
            serde_json::json!({"runtime":{"rulesFile":profile}}).to_string(),
        )
        .unwrap();
        let mut watch = Watch::default();
        std::fs::write(&profile, "partial").unwrap();
        watch.once(&svc).await;
        assert!(!log.exists());
        // An intervening write never applies the partial save.
        std::fs::write(&profile, "invalid but settled").unwrap();
        watch.once(&svc).await;
        assert!(!log.exists());
        watch.once(&svc).await;
        assert_eq!(std::fs::read(&log).unwrap(), b"x");
        watch.once(&svc).await;
        assert_eq!(std::fs::read(&log).unwrap(), b"x");
        std::fs::write(&profile, "corrected").unwrap();
        watch.once(&svc).await;
        watch.once(&svc).await;
        assert_eq!(std::fs::read(&log).unwrap(), b"xx");
        // Removal by an editor does not reset the effective profile.
        std::fs::remove_file(&profile).unwrap();
        watch.once(&svc).await;
        assert_eq!(std::fs::read(&log).unwrap(), b"xx");
    }
}

//! meow-rs inside an app (Android / iOS VPN): start with a config and the
//! platform's TUN fd, stop on demand — the binary's own startup path,
//! minus process concerns (signals, CLI).

use std::sync::OnceLock;

use anyhow::Context as _;
use base64::Engine as _;
use clap::Parser as _;
use parking_lot::Mutex;

use crate::app_main::{run_application, Args, LogTarget, ShutdownSignal};

static STOP: OnceLock<Mutex<Option<tokio::sync::oneshot::Sender<()>>>> = OnceLock::new();

fn stop_slot() -> &'static Mutex<Option<tokio::sync::oneshot::Sender<()>>> {
    STOP.get_or_init(|| Mutex::new(None))
}

/// The config with the platform's TUN fd: `tun.enable`, `file-descriptor`
/// and DNS hijack set, routes left to the platform.
pub fn with_tun_fd(config_yaml: &str, fd: i32) -> anyhow::Result<String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(config_yaml).context("config is not YAML")?;
    let map = doc
        .as_mapping_mut()
        .context("config must be a mapping")?;
    let tun = map
        .entry("tun".into())
        .or_insert_with(|| serde_yaml::Value::Mapping(Default::default()));
    if !tun.is_mapping() {
        *tun = serde_yaml::Value::Mapping(Default::default());
    }
    let t = tun.as_mapping_mut().expect("just made a mapping");
    t.insert("enable".into(), true.into());
    t.insert("file-descriptor".into(), i64::from(fd).into());
    t.insert("auto-route".into(), false.into());
    t.entry("dns-hijack".into())
        .or_insert_with(|| serde_yaml::Value::Sequence(vec!["any:53".into()]));
    Ok(serde_yaml::to_string(&doc)?)
}

/// Runs the core until [`stop`] (blocks the calling thread: call it from a
/// thread of its own). `home` holds caches, geodata and learnt records.
/// `fd` < 0: no TUN (local proxy port only).
pub fn run(home: &str, config_yaml: &str, fd: i32) -> anyhow::Result<()> {
    let config = if fd >= 0 {
        with_tun_fd(config_yaml, fd)?
    } else {
        config_yaml.to_string()
    };
    let encoded = base64::engine::general_purpose::STANDARD.encode(config.as_bytes());
    let args = Args::try_parse_from(["meow", "-d", home, "--config-string", &encoded])
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    *stop_slot().lock() = Some(tx);
    let result = run_application(args, &LogTarget::Console, ShutdownSignal::Embedded(rx), None);
    *stop_slot().lock() = None;
    result
}

/// Asks a running core to stop; true when one was running.
pub fn stop() -> bool {
    stop_slot().lock().take().is_some_and(|tx| tx.send(()).is_ok())
}

/// Whether a core runs now.
pub fn running() -> bool {
    stop_slot().lock().is_some()
}

#[cfg(test)]
mod tests {
    #[test]
    fn tun_fd_goes_into_the_config() {
        let out = super::with_tun_fd("mixed-port: 7890\ntun:\n  stack: system\n", 42).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(v["tun"]["file-descriptor"], 42);
        assert_eq!(v["tun"]["enable"], true);
        assert_eq!(v["tun"]["auto-route"], false);
        assert_eq!(v["tun"]["stack"], "system");
        assert_eq!(v["mixed-port"], 7890);
        assert_eq!(v["tun"]["dns-hijack"][0], "any:53");
    }
}

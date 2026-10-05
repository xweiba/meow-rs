//! meow-rs inside an app (Android / iOS VPN): start with a config and the
//! platform's TUN fd, stop on demand — the binary's own startup path,
//! minus process concerns (signals, CLI).

use std::sync::OnceLock;

use anyhow::Context as _;
use base64::Engine as _;
use clap::Parser as _;
use parking_lot::Mutex;

use crate::app_main::{run_application, Args, LogTarget, ShutdownSignal};

/// The cores of this process: the newest run's stop switch, and how many
/// runs have not returned yet. A run that ends clears only its own switch
/// (a restart's new core must not lose its switch to the old one ending),
/// and [`running`] stays true until the last run has really returned (a
/// restart waits for the old core to let go of the TUN and ports).
#[derive(Default)]
struct Cores {
    newest: u64,
    stop: Option<(u64, tokio::sync::oneshot::Sender<()>)>,
    live: usize,
}

static CORES: OnceLock<Mutex<Cores>> = OnceLock::new();

fn cores() -> &'static Mutex<Cores> {
    CORES.get_or_init(|| Mutex::new(Cores::default()))
}

/// The config with the platform's TUN fd: `tun.enable`, `file-descriptor`
/// and DNS hijack set, routes left to the platform.
pub fn with_tun_fd(config_yaml: &str, fd: i32) -> anyhow::Result<String> {
    let mut doc: serde_yaml::Value =
        serde_yaml::from_str(config_yaml).context("config is not YAML")?;
    let map = doc.as_mapping_mut().context("config must be a mapping")?;
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
    let me = {
        let mut c = cores().lock();
        c.newest += 1;
        c.stop = Some((c.newest, tx));
        c.live += 1;
        c.newest
    };
    let result = run_application(
        args,
        &LogTarget::Console,
        ShutdownSignal::Embedded(rx),
        None,
    );
    let mut c = cores().lock();
    if c.stop.as_ref().is_some_and(|(id, _)| *id == me) {
        c.stop = None;
    }
    c.live -= 1;
    result
}

/// Asks the running core to stop; true when one was running.
pub fn stop() -> bool {
    cores()
        .lock()
        .stop
        .take()
        .is_some_and(|(_, tx)| tx.send(()).is_ok())
}

/// Whether a core runs now: also while a stopped one is still winding
/// down (its TUN and ports not yet released).
pub fn running() -> bool {
    cores().lock().live > 0
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_restart_keeps_the_new_cores_switch_and_waits_for_the_old() {
        use super::cores;
        // Two runs bookkept as `run` does: the old one ends after the new
        // one started.
        let open = |c: &mut super::Cores| {
            let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
            c.newest += 1;
            c.stop = Some((c.newest, tx));
            c.live += 1;
            c.newest
        };
        let close = |c: &mut super::Cores, me: u64| {
            if c.stop.as_ref().is_some_and(|(id, _)| *id == me) {
                c.stop = None;
            }
            c.live -= 1;
        };
        let mut c = cores().lock();
        let base = c.live;
        let old = open(&mut c);
        assert!(c.stop.take().is_some(), "stop() takes the old switch");
        assert_eq!(c.live, base + 1, "still running until the old run returns");
        let new = open(&mut c);
        close(&mut c, old);
        assert_eq!(c.stop.as_ref().map(|(id, _)| *id), Some(new), "kept");
        assert_eq!(c.live, base + 1);
        close(&mut c, new);
        assert_eq!(c.live, base);
    }

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

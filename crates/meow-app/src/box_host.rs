//! `meow box`: meow-box's [`CoreHost`] on this crate's embedded core
//! ([`crate::embed`], the phones' path: config + TUN fd, in-process) and
//! the core's own direct HTTP client for subscriptions.
//!
//! The box lives in its own crate (Linux-only raw sockets, smoltcp, the
//! config page); this module is the whole of meow-app's part, behind the
//! `box` feature.

use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use meow_box::{CoreHost, HostFuture, Options};

/// The embedded core.
struct EmbeddedCore;

impl CoreHost for EmbeddedCore {
    fn start(&self, home: &Path, config: &str, tun_fd: i32) -> anyhow::Result<()> {
        let home = home.to_string_lossy().into_owned();
        let config = config.to_owned();
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("meow-core".into())
            .spawn(move || {
                let r = crate::embed::run(&home, &config, tun_fd);
                let _ = tx.send(r);
            })?;
        // A bad config ends the run at once; a healthy core keeps running.
        match rx.recv_timeout(Duration::from_millis(1500)) {
            Ok(Err(e)) => Err(e),
            Ok(Ok(())) => anyhow::bail!("the core stopped right away"),
            Err(_) => Ok(()),
        }
    }

    fn stop(&self) {
        crate::embed::stop();
        for _ in 0..200 {
            if !crate::embed::running() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn fetch(&self, url: &str) -> HostFuture<Vec<u8>> {
        let url = url.to_owned();
        Box::pin(async move { meow_config::internal_http::fetch_direct(&url).await })
    }
}

/// Runs `meow box` until Ctrl-C / SIGTERM.
pub fn run(opts: &Options) -> anyhow::Result<()> {
    meow_box::run(opts, Arc::new(EmbeddedCore))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use meow_box::config::{core_config, Runtime};
    use serde_json::{json, Value};

    fn golden_subscriptions() -> Vec<Value> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../meow-paopao/tests/golden/build/regions--default--v4.json"
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        v["input"]["subscriptions"].as_array().unwrap().clone()
    }

    /// The box's config is one the core reads: its TUN section and the
    /// whole document parse.
    #[test]
    fn the_box_config_parses_in_the_core() {
        let rt = Runtime {
            controller: "127.0.0.1:41000".parse().unwrap(),
            secret: "x".into(),
            dns: "127.0.0.1:41001".parse().unwrap(),
            socks: "127.0.0.1:41002".parse().unwrap(),
            tun_fd: 9,
            addr: Some("192.168.1.50".parse().unwrap()),
        };
        for (settings, subs) in [
            (json!({}), Vec::new()),
            (json!({}), golden_subscriptions()),
            (json!({"mode": "global"}), golden_subscriptions()),
        ] {
            let c = core_config(&settings, &subs, &rt, 0, 480).unwrap();
            let raw = meow_config::parse_raw_yaml(&c.yaml).unwrap();
            let tun = meow_config::parse_tun_config(raw.tun.as_ref(), raw.max_connections).unwrap();
            assert!(tun.enable);
            assert_eq!(tun.file_descriptor, Some(9));
            assert!(!tun.auto_route);
            assert_eq!(
                raw.dns.as_ref().and_then(|d| d.listen.as_deref()),
                Some("127.0.0.1:41001")
            );
            // The DNS front's way through a line: SOCKS on the loopback.
            let listeners = meow_config::resolve_named_listeners(&raw).unwrap();
            assert!(
                listeners
                    .iter()
                    .any(|l| l.port == 41002 && l.listen == "127.0.0.1"),
                "socks listener on 127.0.0.1:41002"
            );
        }
    }
}

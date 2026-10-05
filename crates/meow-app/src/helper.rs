//! The privileged helper an app installs once (macOS: a launchd daemon run
//! as root) so the core can open a TUN device without asking for a
//! password every time.
//!
//! `meow service --socket PATH --uid UID` listens on a Unix socket and
//! serves only that user (checked with the peer's credentials): one JSON
//! line in, one JSON line out —
//!
//! - `{"op":"start","config":"/abs/config.json","dir":"/abs/dir"}` runs
//!   this binary as the core (`-f config -d dir`), replacing a running one;
//! - `{"op":"stop"}`; `{"op":"status"}` (`running`);
//! - `{"op":"relocate"}` (macOS): restarts `locationd`, so the system asks
//!   for its location again (virtual location takes effect at once);
//! - `{"op":"wifi"}` (macOS): the current Wi-Fi network name, read as root
//!   with `wdutil info` (recent macOS redacts it for apps without Location
//!   permission) — `{"ok":true,"ssid":"Name"}`, or `"ssid":null` when not
//!   on Wi-Fi / not found; `{"ok":false}` on other systems.
//!
//! `meow service-call --socket PATH --op start --config … --dir …` is the
//! client: prints the reply, exits non-zero only when the helper can't be
//! reached.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// The connecting process's user id.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let fd = stream.as_raw_fd();
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
        // SAFETY: fd is a connected Unix socket owned by `stream`; uid / gid
        // are valid out-pointers.
        let r = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
        (r == 0).then_some(uid)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
        // SAFETY: fd is a connected Unix socket; cred / len describe a
        // buffer of the size SO_PEERCRED writes.
        let r = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &raw mut len,
            )
        };
        (r == 0).then_some(cred.uid)
    }
}

/// Log lines without terminal colors.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

struct Core {
    child: Option<Child>,
}

impl Core {
    fn running(&mut self) -> bool {
        match &mut self.child {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            #[allow(clippy::cast_possible_wrap, reason = "pids fit in pid_t")]
            let pid = c.id() as libc::pid_t;
            // SAFETY: plain kill(2) on our own child.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if !matches!(c.try_wait(), Ok(None)) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn start(&mut self, config: &str, dir: &str) -> Value {
        if !Path::new(config).is_absolute() || !Path::new(dir).is_absolute() {
            return json!({"ok": false, "error": "config and dir must be absolute paths"});
        }
        self.stop();
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => return json!({"ok": false, "error": e.to_string()}),
        };
        let log_path = Path::new(dir).join("core.log");
        let log = match std::fs::File::create(&log_path) {
            Ok(f) => f,
            Err(e) => return json!({"ok": false, "error": format!("{}: {e}", log_path.display())}),
        };
        let err = log.try_clone().ok();
        let child = Command::new(exe)
            .args(["-f", config, "-d", dir])
            .stdin(Stdio::null())
            .stdout(log)
            .stderr(err.map_or_else(Stdio::null, Stdio::from))
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => return json!({"ok": false, "error": e.to_string()}),
        };
        // A config the core refuses ends it at once: say why.
        std::thread::sleep(Duration::from_millis(600));
        if let Ok(Some(status)) = child.try_wait() {
            let mut tail = String::new();
            let _ = std::fs::File::open(&log_path).and_then(|mut f| f.read_to_string(&mut tail));
            let tail = strip_ansi(&tail);
            let lines: Vec<&str> = tail.lines().collect();
            let tail = lines[lines.len().saturating_sub(8)..].join("\n");
            return json!({"ok": false, "error": format!("core exited ({status})"), "log": tail});
        }
        self.child = Some(child);
        json!({"ok": true})
    }
}

fn handle(core: &mut Core, stream: UnixStream, uid: u32) -> Result<()> {
    if peer_uid(&stream) != Some(uid) && peer_uid(&stream) != Some(0) {
        let mut s = stream;
        writeln!(s, "{}", json!({"ok": false, "error": "not allowed"}))?;
        return Ok(());
    }
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line)?;
    let req: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
    let text = |k: &str| {
        req.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let reply = match text("op").as_str() {
        "start" => core.start(&text("config"), &text("dir")),
        "stop" => {
            core.stop();
            json!({"ok": true})
        }
        "status" => json!({"ok": true, "running": core.running()}),
        "relocate" => relocate(),
        "wifi" => wifi(),
        other => json!({"ok": false, "error": format!("unknown op '{other}'")}),
    };
    let mut s = stream;
    writeln!(s, "{reply}")?;
    Ok(())
}

/// macOS: `locationd` restarted (launchd brings it back); it then looks up
/// where it is again instead of using what it had.
fn relocate() -> Value {
    if !cfg!(target_os = "macos") {
        return json!({"ok": false, "error": "macOS only"});
    }
    match Command::new("/usr/bin/killall").arg("locationd").status() {
        Ok(s) if s.success() => json!({"ok": true}),
        Ok(s) => json!({"ok": false, "error": format!("killall locationd: {s}")}),
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    }
}

/// macOS: the current Wi-Fi SSID from `wdutil info` (needs root, which the
/// helper is). Never fails the service: anything unexpected is `null`.
fn wifi() -> Value {
    #[cfg(target_os = "macos")]
    {
        let ssid = Command::new("/usr/bin/wdutil")
            .arg("info")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()
            .and_then(|o| parse_wdutil_ssid(&String::from_utf8_lossy(&o.stdout)));
        json!({"ok": true, "ssid": ssid})
    }
    #[cfg(not(target_os = "macos"))]
    {
        json!({"ok": false, "error": "macOS only"})
    }
}

/// The `SSID : <name>` line of the `WIFI` section of `wdutil info`. `None`
/// when there is no such section/line, or the value says there is no
/// network (`None`, empty) or is redacted (`<redacted>`).
#[cfg_attr(
    not(any(target_os = "macos", test)),
    allow(dead_code, reason = "only the macOS wifi op calls it")
)]
fn parse_wdutil_ssid(text: &str) -> Option<String> {
    let mut in_wifi = false;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let Some((key, value)) = t.split_once(':') else {
            // A section title (`WIFI`, `BLUETOOTH`, …) or a rule line made
            // of dashes: only titles switch sections.
            if t.chars().any(char::is_alphabetic) {
                in_wifi = t.eq_ignore_ascii_case("WIFI") || t.eq_ignore_ascii_case("WI-FI");
            }
            continue;
        };
        if in_wifi && key.trim() == "SSID" {
            let v = value.trim();
            return match v {
                "" | "None" | "<redacted>" | "<SSID Redacted>" => None,
                v => Some(v.to_owned()),
            };
        }
    }
    None
}

/// `meow service`: serves [`uid`] on [`socket`] until killed.
pub fn serve(socket: &str, uid: u32) -> Result<()> {
    let path = Path::new(socket);
    if path.exists() {
        std::fs::remove_file(path).with_context(|| format!("removing stale {socket}"))?;
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("binding {socket}"))?;
    // Anyone may connect; only `uid` (and root) are answered.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let mut core = Core { child: None };
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(&mut core, s, uid) {
                    eprintln!("service: {e:#}");
                }
            }
            Err(e) => eprintln!("service: accept: {e}"),
        }
    }
    core.stop();
    Ok(())
}

/// `meow service-call`.
pub fn call(socket: &str, op: &str, config: Option<&str>, dir: Option<&str>) -> Result<()> {
    let mut s = UnixStream::connect(socket).with_context(|| format!("connecting {socket}"))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut req = json!({"op": op});
    if let Some(c) = config {
        req["config"] = json!(c);
    }
    if let Some(d) = dir {
        req["dir"] = json!(d);
    }
    writeln!(s, "{req}")?;
    let mut reply = String::new();
    BufReader::new(&s).read_line(&mut reply)?;
    print!("{reply}");
    std::io::stdout().flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_are_dropped_from_the_log() {
        assert_eq!(
            strip_ansi("\u{1b}[2mtime\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m x"),
            "time  INFO x"
        );
    }

    const WDUTIL_SAMPLE: &str = "\
————————————————————————————————————————————————————————————————————————
NETWORK
————————————————————————————————————————————————————————————————————————
    Primary IPv4         : en0 (Wi-Fi / 0F3A9B2C-1D2E-4F50-8A6B-7C8D9E0F1A2B)
                         : 192.168.186.42
    DNS                  : 192.168.186.1
————————————————————————————————————————————————————————————————————————
WIFI
————————————————————————————————————————————————————————————————————————
    MAC Address          : 3c:22:fb:00:11:22 (hw=3c:22:fb:00:11:22)
    Interface Name       : en0
    Power                : On [On]
    Op Mode              : STA
    SSID                 : Home Net: 5G
    BSSID                : a0:b1:c2:d3:e4:f5
    RSSI                 : -51 dBm
    Noise                : -94 dBm
    Tx Rate              : 866.0 Mbps
    Security             : WPA2 Personal
    Channel              : 5g149/80
————————————————————————————————————————————————————————————————————————
BLUETOOTH
————————————————————————————————————————————————————————————————————————
    Power                : On
    SSID                 : not-wifi
";

    #[test]
    fn wdutil_ssid_is_read_from_the_wifi_section() {
        assert_eq!(
            parse_wdutil_ssid(WDUTIL_SAMPLE).as_deref(),
            Some("Home Net: 5G")
        );
        let off = WDUTIL_SAMPLE.replace(
            "SSID                 : Home Net: 5G",
            "SSID                 : None",
        );
        assert_eq!(parse_wdutil_ssid(&off), None, "not associated");
        let redacted = WDUTIL_SAMPLE.replace("Home Net: 5G", "<redacted>");
        assert_eq!(parse_wdutil_ssid(&redacted), None);
        // No WIFI section: the BLUETOOTH `SSID` line is not taken.
        let no_wifi = WDUTIL_SAMPLE.replace("\nWIFI\n", "\nOTHER\n");
        assert_eq!(parse_wdutil_ssid(&no_wifi), None);
        assert_eq!(parse_wdutil_ssid(""), None);
        assert_eq!(parse_wdutil_ssid("garbage\n:::\n"), None);
    }

    #[test]
    fn serves_the_owner_and_answers_each_op() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("h.sock");
        let s = sock.to_str().unwrap().to_string();
        // SAFETY: getuid(2) has no preconditions.
        let me = unsafe { libc::getuid() };
        let server = s.clone();
        std::thread::spawn(move || serve(&server, me));
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let ask = |req: &str| {
            let mut c = UnixStream::connect(&s).unwrap();
            writeln!(c, "{req}").unwrap();
            let mut line = String::new();
            BufReader::new(&c).read_line(&mut line).unwrap();
            serde_json::from_str::<Value>(&line).unwrap()
        };
        assert_eq!(
            ask(r#"{"op":"status"}"#),
            json!({"ok": true, "running": false})
        );
        assert_eq!(
            ask(r#"{"op":"start","config":"rel.json","dir":"/tmp"}"#)["ok"],
            json!(false),
            "relative paths refused"
        );
        assert_eq!(ask(r#"{"op":"nope"}"#)["ok"], json!(false));
        let wifi = ask(r#"{"op":"wifi"}"#);
        if cfg!(target_os = "macos") {
            assert_eq!(wifi["ok"], json!(true));
            assert!(wifi["ssid"].is_null() || wifi["ssid"].is_string());
        } else {
            assert_eq!(wifi["ok"], json!(false));
        }
        assert_eq!(ask(r#"{"op":"stop"}"#), json!({"ok": true}));
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }
}

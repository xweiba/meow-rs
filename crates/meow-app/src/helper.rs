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
//! - `{"op":"stop"}`; `{"op":"status"}` (`running`).
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
        other => json!({"ok": false, "error": format!("unknown op '{other}'")}),
    };
    let mut s = stream;
    writeln!(s, "{reply}")?;
    Ok(())
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
        assert_eq!(ask(r#"{"op":"stop"}"#), json!({"ok": true}));
        assert_eq!(
            std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
            0o666
        );
    }
}

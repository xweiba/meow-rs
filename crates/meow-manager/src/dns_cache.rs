//! Bounded native system DNS cache invalidation after interception ends.
//! Std-only so both the standalone desktop manager and core share exactly
//! the same platform commands. Resolver settings and applications are never
//! changed; applications may still retain their own addresses/connections.

use std::io;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Flush the platform resolver caches. `false` means no supported cache
/// service/tool is installed; errors identify failed commands, never claim
/// that application-local caches were invalidated.
pub fn flush() -> io::Result<bool> {
    flush_with(std::env::consts::OS, &mut run)
}

fn run(program: &str, args: &[&str]) -> io::Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn()?;
    wait(&mut child, Duration::from_secs(2))
}

fn wait(child: &mut std::process::Child, timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("exit status {status}")))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS cache command timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn flush_with(os: &str, run: &mut impl FnMut(&str, &[&str]) -> io::Result<()>) -> io::Result<bool> {
    // Try equivalent tool paths only on ENOENT. A refused/failed operation
    // is reported rather than hidden behind a different command.
    let mut group = |paths: &[&str], args: &[&str]| -> io::Result<bool> {
        for path in paths {
            match run(path, args) {
                Ok(()) => return Ok(true),
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io::Error::new(e.kind(), format!("{path}: {e}"))),
            }
        }
        Ok(false)
    };
    match os {
        "linux" => {
            // Prefer resolved's D-Bus operation: no auth prompt and no
            // privileged shell. Absence of a running daemon is normal.
            let resolved = group(
                &["/usr/bin/resolvectl", "/bin/resolvectl"],
                &["--no-ask-password", "flush-caches"],
            );
            let resolved = match resolved {
                Ok(false) => group(
                    &["/usr/bin/systemd-resolve", "/bin/systemd-resolve"],
                    &["--flush-caches"],
                ),
                result => result,
            };
            // resolved and nscd can coexist. Invalidate hosts only, never
            // restart a resolver/service or touch DNS configuration.
            let nscd = group(&["/usr/sbin/nscd", "/sbin/nscd"], &["--invalidate=hosts"]);
            match (resolved, nscd) {
                (Ok(a), Ok(b)) => Ok(a || b),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
        "macos" => {
            let cache = group(&["/usr/bin/dscacheutil"], &["-flushcache"]);
            // Still notify mDNSResponder if DirectoryService flushing
            // failed. The privileged TUN core has the needed permission.
            let mdns = group(&["/usr/bin/killall"], &["-HUP", "mDNSResponder"]);
            match (cache, mdns) {
                (Ok(a), Ok(b)) => Ok(a || b),
                (Err(e), _) | (_, Err(e)) => Err(e),
            }
        }
        "windows" => group(&["ipconfig.exe"], &["/flushdns"]),
        _ => Ok(false),
    }
}

/// Called only after the owner's interception or core has stopped.
pub fn flush_after_capture() {
    match flush() {
        Ok(true) => tracing::info!("system DNS cache flushed after DNS capture stopped"),
        Ok(false) => tracing::debug!("no supported system DNS cache tool installed"),
        Err(e) => tracing::warn!("system DNS cache flush failed after DNS capture stopped: {e}"),
    }
}

/// Last field of a native TUN owner: its routes and device must be dropped
/// before this guard, so cache refill uses the restored network path.
pub struct FlushOnDrop(bool);

impl FlushOnDrop {
    /// Enable only for a desktop TUN that intercepted DNS.
    pub fn new(enabled: bool) -> Self {
        Self(enabled)
    }
}

impl Drop for FlushOnDrop {
    fn drop(&mut self) {
        if self.0 {
            flush_after_capture();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_commands_invalidate_caches_without_changing_dns() {
        for (os, expected) in [
            (
                "linux",
                vec![
                    (
                        "/usr/bin/resolvectl",
                        vec!["--no-ask-password", "flush-caches"],
                    ),
                    ("/usr/sbin/nscd", vec!["--invalidate=hosts"]),
                ],
            ),
            (
                "macos",
                vec![
                    ("/usr/bin/dscacheutil", vec!["-flushcache"]),
                    ("/usr/bin/killall", vec!["-HUP", "mDNSResponder"]),
                ],
            ),
            ("windows", vec![("ipconfig.exe", vec!["/flushdns"])]),
        ] {
            let mut calls = Vec::new();
            assert!(flush_with(os, &mut |p, a| {
                calls.push((
                    p.to_owned(),
                    a.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                ));
                Ok(())
            })
            .unwrap());
            assert_eq!(
                calls,
                expected
                    .into_iter()
                    .map(|(p, a)| (p.to_owned(), a.into_iter().map(str::to_owned).collect()))
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn unavailable_tools_and_failures_are_distinguished() {
        let missing = &mut |_: &str, _: &[&str]| Err(io::Error::from(io::ErrorKind::NotFound));
        assert!(!flush_with("linux", missing).unwrap());
        let mut calls = Vec::new();
        let err = flush_with("macos", &mut |p, _| {
            calls.push(p.to_owned());
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn hung_cache_command_is_killed_and_reaped() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        assert_eq!(
            wait(&mut child, Duration::from_millis(20))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(child.try_wait().unwrap().is_some());
    }
}

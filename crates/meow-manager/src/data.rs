//! The app's data directory (subscriptions, settings, the manager's state
//! and API file, the core's run directories), the one place every part of
//! PaoPao Proxy gets it from: the tray (paopao-tray), PaoPao Menu (through
//! meow-manager-ffi) and the app (meow-paopao's `paopao_data_dir`, which
//! compiles this same file). Only `std`: meow-paopao includes it by path.
//!
//! - Windows: `%APPDATA%\PaoPao`;
//! - macOS: `~/Library/Application Support/PaoPao`;
//! - Linux and others: `$XDG_DATA_HOME/paopao-proxy`, else
//!   `~/.local/share/paopao-proxy`.
//!
//! `PAOPAO_PROXY_DATA` overrides it, as does a directory passed in
//! (`--data`). Until 0.1.0 every desktop used `~/.local/share/paopao-proxy`:
//! that one, found where the standard one is not yet, is moved over once
//! ([`resolve`]); a `--data` naming it (a login item registered then) means
//! the standard one. What runs on the old one is stopped first
//! ([`stop_what_runs`]: an older tray or PaoPao Menu, its core, the
//! privileged helper's core), so nothing writes there after the move; the
//! next start brings the core back on the new one.

use std::path::{Path, PathBuf};

/// The override's environment variable.
pub const OVERRIDE: &str = "PAOPAO_PROXY_DATA";

/// What the directory is found from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    /// `std::env::consts::OS`.
    pub os: String,
    /// `HOME`, else `USERPROFILE`.
    pub home: PathBuf,
    /// `APPDATA` (Windows).
    pub appdata: Option<PathBuf>,
    /// `XDG_DATA_HOME`.
    pub xdg_data_home: Option<PathBuf>,
    /// [`OVERRIDE`].
    pub data_override: Option<PathBuf>,
}

impl Env {
    /// This process's.
    pub fn current() -> Env {
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Env {
            os: std::env::consts::OS.to_owned(),
            home: var("HOME")
                .or_else(|| var("USERPROFILE"))
                .unwrap_or_else(|| PathBuf::from(".")),
            appdata: var("APPDATA"),
            xdg_data_home: var("XDG_DATA_HOME"),
            data_override: var(OVERRIDE),
        }
    }
}

/// The platform's place for it (no override).
pub fn standard(env: &Env) -> PathBuf {
    match env.os.as_str() {
        "windows" => env
            .appdata
            .clone()
            .unwrap_or_else(|| env.home.join("AppData").join("Roaming"))
            .join("PaoPao"),
        "macos" => env
            .home
            .join("Library")
            .join("Application Support")
            .join("PaoPao"),
        _ => env
            .xdg_data_home
            .clone()
            .filter(|d| d.is_absolute())
            .unwrap_or_else(|| env.home.join(".local").join("share"))
            .join("paopao-proxy"),
    }
}

/// Where every desktop kept it before.
pub fn legacy(env: &Env) -> PathBuf {
    env.home.join(".local").join("share").join("paopao-proxy")
}

/// The directory, and what happened finding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub dir: PathBuf,
    /// The old directory moved here just now.
    pub moved_from: Option<PathBuf>,
    /// The move failed (`dir` is then the old directory, used as it is
    /// until the next start tries again).
    pub problem: Option<String>,
}

/// The data directory: [`Env::data_override`] or `given` as they are (a
/// `given` naming the [`legacy`] directory means the standard one), else
/// [`standard`]; the legacy directory moved there first when only it
/// exists. Call it before anything reads the directory.
pub fn resolve(env: &Env, given: Option<&Path>) -> Resolved {
    resolve_with(env, given, stop_what_runs)
}

/// [`resolve`], with `stop` called on the old directory right before it
/// moves (only then).
pub fn resolve_with(env: &Env, given: Option<&Path>, stop: impl FnOnce(&Path)) -> Resolved {
    let old = legacy(env);
    let new = standard(env);
    let as_is = |dir: PathBuf| Resolved {
        dir,
        moved_from: None,
        problem: None,
    };
    match given.filter(|g| !g.as_os_str().is_empty()) {
        Some(g) if g != old.as_path() || old == new => return as_is(g.to_owned()),
        Some(_) => {}
        None => {
            if let Some(o) = &env.data_override {
                return as_is(o.clone());
            }
        }
    }
    if old == new || new.exists() || !old.is_dir() {
        return as_is(new);
    }
    stop(&old);
    match move_dir(&old, &new) {
        Ok(()) => Resolved {
            dir: new,
            moved_from: Some(old),
            problem: None,
        },
        Err(e) => Resolved {
            dir: old,
            moved_from: None,
            problem: Some(e),
        },
    }
}

/// `from` renamed to `to`, else copied and then removed (another volume;
/// a file of it still open). The copy is made beside `to` and renamed to
/// it once whole, so a second process starting meanwhile (the tray and the
/// app start together) never takes a half copy; one that fails is taken
/// back.
fn move_dir(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let mut staged = to.as_os_str().to_owned();
    staged.push(format!(".moving-{}", std::process::id()));
    let staged = PathBuf::from(staged);
    let copied = copy_dir(from, &staged)
        .and_then(|()| std::fs::rename(&staged, to).map_err(|e| format!("{}: {e}", to.display())));
    if let Err(e) = copied {
        let _ = std::fs::remove_dir_all(&staged);
        // Another process moved it meanwhile: theirs is the directory.
        return if to.is_dir() { Ok(()) } else { Err(e) };
    }
    // What stays (a file in use) is left; the copy is the directory now.
    let _ = std::fs::remove_dir_all(from);
    Ok(())
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let entries = std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", from.display()))?;
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", src.display()))?;
        if kind.is_dir() {
            copy_dir(&src, &dst)?;
        } else if kind.is_file() {
            std::fs::copy(&src, &dst).map_err(|e| format!("{}: {e}", src.display()))?;
        }
        // Sockets and links (a core's control socket): not data.
    }
    Ok(())
}

/// Before the old directory moves: what runs on it stopped — an older
/// tray or PaoPao Menu hosting the manager there (`manager-api.json`'s
/// pid), the core it ran (`meow/core.pid`), and the privileged helper's
/// core (macOS, Windows: its run directory was there, nothing else could
/// have started one yet). Each pid is checked to be that program first.
pub fn stop_what_runs(old: &Path) {
    let me = std::process::id();
    let host = std::fs::read_to_string(old.join("manager-api.json"))
        .ok()
        .and_then(|t| pid_in(&t));
    if let Some(pid) = host.filter(|&p| p != me) {
        if process_name(pid).is_some_and(|n| is_named(&n, &["paopao-tray", "PaoPao Menu"])) {
            end(pid);
        }
    }
    helper_stop();
    let core = std::fs::read_to_string(old.join("meow").join("core.pid"))
        .ok()
        .and_then(|t| t.trim().parse::<u32>().ok());
    if let Some(pid) = core.filter(|&p| p != me) {
        if process_name(pid).is_some_and(|n| is_named(&n, &["meow"])) {
            end(pid);
        }
    }
}

/// The `"pid": n` of the manager's API file.
fn pid_in(text: &str) -> Option<u32> {
    let rest = &text[text.find("\"pid\"")? + 5..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// A process name (`ps`'s path, `tasklist`'s image) is one of `names`.
fn is_named(name: &str, names: &[&str]) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    names.iter().any(|n| base.eq_ignore_ascii_case(n))
}

fn quiet(exe: &str) -> std::process::Command {
    let mut c = std::process::Command::new(exe);
    c.stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c
}

/// The program `pid` runs; None when there is no such process.
fn process_name(pid: u32) -> Option<String> {
    if cfg!(windows) {
        let out = quiet("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().find(|l| l.contains(&format!("\"{pid}\"")))?;
        return line
            .split(',')
            .next()
            .map(|n| n.trim_matches('"').to_owned());
    }
    let out = quiet("/bin/ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let name = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (out.status.success() && !name.is_empty()).then_some(name)
}

/// `pid` ended (asked to first on Unix; Windows: with what it started),
/// waited for a few seconds.
fn end(pid: u32) {
    let id = pid.to_string();
    if cfg!(windows) {
        let _ = quiet("taskkill").args(["/PID", &id, "/T", "/F"]).output();
    } else {
        let _ = quiet("/bin/kill").args(["-TERM", &id]).output();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while process_name(pid).is_some() {
        if std::time::Instant::now() > deadline {
            if !cfg!(windows) {
                let _ = quiet("/bin/kill").args(["-KILL", &id]).output();
            }
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The privileged helper's core stopped, when one runs (`{"op":"status"}`,
/// then `{"op":"stop"}`); nothing without a helper.
fn helper_stop() {
    let ask = |op: &str, secs: u64| helper_call(&format!("{{\"op\":\"{op}\"}}"), secs);
    if ask("status", 3).is_some_and(|r| r.replace(' ', "").contains("\"running\":true")) {
        let _ = ask("stop", 15);
    }
}

#[cfg(target_os = "macos")]
fn helper_call(line: &str, secs: u64) -> Option<String> {
    use std::io::{BufRead as _, Write as _};
    let mut s = std::os::unix::net::UnixStream::connect("/var/run/paopao-core.sock").ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(secs)))
        .ok()?;
    writeln!(s, "{line}").ok()?;
    let mut reply = String::new();
    std::io::BufReader::new(&s).read_line(&mut reply).ok()?;
    Some(reply)
}

#[cfg(windows)]
fn helper_call(line: &str, secs: u64) -> Option<String> {
    use std::io::{BufRead as _, Write as _};
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(r"\\.\pipe\paopao-core")
        .ok()?;
    let line = format!("{line}\n");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if f.write_all(line.as_bytes()).is_err() {
            return;
        }
        let mut reply = String::new();
        if std::io::BufReader::new(&f).read_line(&mut reply).is_ok() {
            let _ = tx.send(reply);
        }
    });
    rx.recv_timeout(std::time::Duration::from_secs(secs)).ok()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn helper_call(_line: &str, _secs: u64) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, empty directory of its own under the system's temp.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("paopao-data-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Nothing runs on the old directory (the real [`stop_what_runs`] is
    /// never called by a test: it would reach this machine's helper).
    fn never(_: &Path) {}

    fn env(os: &str, home: &Path) -> Env {
        Env {
            os: os.into(),
            home: home.to_owned(),
            appdata: None,
            xdg_data_home: None,
            data_override: None,
        }
    }

    #[test]
    fn each_platform_has_its_place() {
        let home = Path::new("/home/u");
        let mut w = env("windows", Path::new(r"C:\Users\u"));
        w.appdata = Some(r"C:\Users\u\AppData\Roaming".into());
        assert_eq!(
            standard(&w),
            Path::new(r"C:\Users\u\AppData\Roaming").join("PaoPao")
        );
        assert_eq!(
            standard(&env("macos", Path::new("/Users/u"))),
            Path::new("/Users/u/Library/Application Support/PaoPao")
        );
        let mut l = env("linux", home);
        assert_eq!(standard(&l), Path::new("/home/u/.local/share/paopao-proxy"));
        // Absolute on the host running the test (\data is not on Windows).
        let xdg = std::env::temp_dir().join("data-u");
        l.xdg_data_home = Some(xdg.clone());
        assert_eq!(standard(&l), xdg.join("paopao-proxy"));
        // Relative: not a base directory (the XDG spec says ignore it).
        l.xdg_data_home = Some("data".into());
        assert_eq!(standard(&l), Path::new("/home/u/.local/share/paopao-proxy"));
    }

    #[test]
    fn the_old_directory_moves_over_once() {
        let home = scratch("move");
        let e = env("macos", &home);
        let old = legacy(&e);
        std::fs::create_dir_all(old.join("core-service")).unwrap();
        std::fs::write(old.join("proxy.json"), "{\"subscriptions\":[]}").unwrap();
        std::fs::write(old.join("core-service").join("config.json"), "{}").unwrap();

        let r = resolve_with(&e, None, never);
        let new = home.join("Library/Application Support/PaoPao");
        assert_eq!(r.dir, new);
        assert_eq!(r.moved_from.as_deref(), Some(old.as_path()));
        assert_eq!(r.problem, None);
        assert_eq!(
            std::fs::read_to_string(new.join("proxy.json")).unwrap(),
            "{\"subscriptions\":[]}"
        );
        assert!(new.join("core-service/config.json").is_file());
        assert!(!old.exists());

        // Both there (an old build ran since): the standard one wins,
        // nothing moves.
        std::fs::create_dir_all(&old).unwrap();
        let again = resolve_with(&e, None, never);
        assert_eq!(again.dir, new);
        assert_eq!(again.moved_from, None);
        assert!(old.exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_login_item_naming_the_old_one_gets_the_new_one() {
        let home = scratch("given");
        let e = env("windows", &home);
        std::fs::create_dir_all(legacy(&e)).unwrap();
        std::fs::write(legacy(&e).join("proxy.json"), "{}").unwrap();
        let r = resolve_with(&e, Some(&legacy(&e)), never);
        assert_eq!(r.dir, home.join("AppData").join("Roaming").join("PaoPao"));
        assert!(r.dir.join("proxy.json").is_file());
        // Any other directory passed in is used as it is.
        let other = home.join("elsewhere");
        assert_eq!(resolve_with(&e, Some(&other), never).dir, other);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn the_override_is_used_as_it_is() {
        let home = scratch("override");
        let mut e = env("macos", &home);
        std::fs::create_dir_all(legacy(&e)).unwrap();
        e.data_override = Some(home.join("mine"));
        let r = resolve_with(&e, None, never);
        assert_eq!(r.dir, home.join("mine"));
        assert_eq!(r.moved_from, None);
        // Nothing moved for it.
        assert!(legacy(&e).is_dir());
        // Passed in, it still wins over the override.
        let given = home.join("given");
        assert_eq!(resolve_with(&e, Some(&given), never).dir, given);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn linux_stays_where_it_was() {
        let home = scratch("linux");
        let e = env("linux", &home);
        std::fs::create_dir_all(legacy(&e)).unwrap();
        let r = resolve_with(&e, None, never);
        assert_eq!(r.dir, legacy(&e));
        assert_eq!(r.moved_from, None);
        assert_eq!(resolve_with(&e, Some(&legacy(&e)), never).dir, legacy(&e));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_copy_is_whole_before_it_is_the_directory() {
        let home = scratch("copy");
        let (from, to) = (home.join("from"), home.join("to"));
        std::fs::create_dir_all(from.join("a/b")).unwrap();
        std::fs::write(from.join("a/b/c.json"), "c").unwrap();
        std::fs::write(from.join("proxy.json"), "p").unwrap();
        copy_dir(&from, &to).unwrap();
        assert_eq!(std::fs::read_to_string(to.join("a/b/c.json")).unwrap(), "c");
        assert_eq!(std::fs::read_to_string(to.join("proxy.json")).unwrap(), "p");
        // Moved where it is already there (another process won): fine,
        // nothing staged left.
        std::fs::create_dir_all(home.join("from2")).unwrap();
        assert_eq!(move_dir(&home.join("from2"), &to), Ok(()));
        let left: Vec<_> = std::fs::read_dir(&home)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".moving-"))
            .collect();
        assert!(left.is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_first_start_moves_nothing() {
        let home = scratch("fresh");
        let e = env("windows", &home);
        let r = resolve_with(&e, None, never);
        assert_eq!(r.dir, standard(&e));
        assert_eq!(r.moved_from, None);
        assert_eq!(r.problem, None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn what_runs_on_the_old_one_is_stopped_before_it_moves() {
        let home = scratch("stop");
        let e = env("windows", &home);
        let old = legacy(&e);
        std::fs::create_dir_all(old.join("meow")).unwrap();
        std::fs::write(old.join("meow").join("core.pid"), "4242").unwrap();
        let mut seen = Vec::new();
        let r = resolve_with(&e, None, |dir| {
            // Still there, as it was, when asked.
            assert!(dir.join("meow").join("core.pid").is_file());
            seen.push(dir.to_owned());
        });
        assert_eq!(seen, std::slice::from_ref(&old));
        assert_eq!(r.moved_from.as_deref(), Some(old.as_path()));
        // Nothing to move: nothing stopped.
        let again = resolve_with(&e, None, |_| panic!("nothing moves"));
        assert_eq!(again.dir, r.dir);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn the_programs_on_it_are_told_by_name() {
        assert_eq!(pid_in(r#"{"port":1234,"token":"t","pid": 987}"#), Some(987));
        assert_eq!(pid_in(r#"{"port":1234}"#), None);
        assert!(is_named("paopao-tray.exe", &["paopao-tray"]));
        assert!(is_named(
            "/Applications/PaoPao Proxy.app/Contents/Library/PaoPao Menu.app/Contents/MacOS/PaoPao Menu",
            &["paopao-tray", "PaoPao Menu"]
        ));
        assert!(is_named("meow.exe", &["meow"]));
        assert!(is_named(
            "/Applications/PaoPao Proxy.app/Contents/MacOS/meow",
            &["meow"]
        ));
        // Not another program given the pid since.
        assert!(!is_named(
            "paopao-device-agent",
            &["paopao-tray", "PaoPao Menu"]
        ));
        assert!(!is_named("PaoPao Proxy", &["paopao-tray", "PaoPao Menu"]));
        assert!(!is_named("meowx", &["meow"]));
        // No such process.
        assert_eq!(process_name(u32::MAX - 1), None);
    }
}

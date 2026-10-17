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
//! the standard one.

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

        let r = resolve(&e, None);
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
        let again = resolve(&e, None);
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
        let r = resolve(&e, Some(&legacy(&e)));
        assert_eq!(r.dir, home.join("AppData").join("Roaming").join("PaoPao"));
        assert!(r.dir.join("proxy.json").is_file());
        // Any other directory passed in is used as it is.
        let other = home.join("elsewhere");
        assert_eq!(resolve(&e, Some(&other)).dir, other);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn the_override_is_used_as_it_is() {
        let home = scratch("override");
        let mut e = env("macos", &home);
        std::fs::create_dir_all(legacy(&e)).unwrap();
        e.data_override = Some(home.join("mine"));
        let r = resolve(&e, None);
        assert_eq!(r.dir, home.join("mine"));
        assert_eq!(r.moved_from, None);
        // Nothing moved for it.
        assert!(legacy(&e).is_dir());
        // Passed in, it still wins over the override.
        let given = home.join("given");
        assert_eq!(resolve(&e, Some(&given)).dir, given);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn linux_stays_where_it_was() {
        let home = scratch("linux");
        let e = env("linux", &home);
        std::fs::create_dir_all(legacy(&e)).unwrap();
        let r = resolve(&e, None);
        assert_eq!(r.dir, legacy(&e));
        assert_eq!(r.moved_from, None);
        assert_eq!(resolve(&e, Some(&legacy(&e))).dir, legacy(&e));
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
        let r = resolve(&e, None);
        assert_eq!(r.dir, standard(&e));
        assert_eq!(r.moved_from, None);
        assert_eq!(r.problem, None);
        let _ = std::fs::remove_dir_all(&home);
    }
}

//! 开机自启: the login item that starts the tray program (PaoPao Menu,
//! paopao-tray) when the user logs in; the tray starts the manager, and the
//! manager brings the core up ([`crate::Manager::boot`]). All user-level:
//!
//! - macOS: `~/Library/LaunchAgents/app.paopao.proxy.login.plist`, running
//!   `/usr/bin/open -g -a <PaoPao Menu.app> --args <args…>` at load (not
//!   loaded now: it would run at once);
//! - Linux: `$XDG_CONFIG_HOME/autostart/paopao-proxy.desktop` (else
//!   `~/.config/autostart`), `Exec=<tray> <args…>`;
//! - Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value
//!   `PaoPao Proxy` = `"<tray>" <args…>` (through `reg`: [`Commands`]).
//!
//! Whether it is there is read back each time: removed by the user (System
//! Settings' login items, a desktop's autostart page), it is off.

use crate::proxy::{Commands, Os};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const MAC_LABEL: &str = "app.paopao.proxy.login";
pub const LINUX_FILE: &str = "paopao-proxy.desktop";
pub const WINDOWS_RUN: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
pub const WINDOWS_VALUE: &str = "PaoPao Proxy";

/// What starts at login: the tray program (macOS: its .app bundle) and
/// its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<String>,
}

pub struct OsLogin {
    os: Os,
    launch: Launch,
    /// The user's home.
    home: PathBuf,
    /// `XDG_CONFIG_HOME` when set.
    xdg_config: Option<PathBuf>,
    run: Arc<dyn Commands>,
}

impl OsLogin {
    pub fn new(
        os: Os,
        launch: Launch,
        home: PathBuf,
        xdg_config: Option<PathBuf>,
        run: Arc<dyn Commands>,
    ) -> OsLogin {
        OsLogin {
            os,
            launch,
            home,
            xdg_config,
            run,
        }
    }

    /// The file it is (macOS, Linux).
    pub fn file(&self) -> Option<PathBuf> {
        match self.os {
            Os::MacOs => Some(
                self.home
                    .join("Library/LaunchAgents")
                    .join(format!("{MAC_LABEL}.plist")),
            ),
            Os::Linux => Some(
                self.xdg_config
                    .clone()
                    .unwrap_or_else(|| self.home.join(".config"))
                    .join("autostart")
                    .join(LINUX_FILE),
            ),
            Os::Windows | Os::Other => None,
        }
    }

    pub fn plist(&self) -> String {
        let mut args = vec![
            "/usr/bin/open".to_owned(),
            "-g".to_owned(),
            "-a".to_owned(),
            self.launch.program.display().to_string(),
        ];
        if !self.launch.args.is_empty() {
            args.push("--args".to_owned());
            args.extend(self.launch.args.iter().cloned());
        }
        let strings: String = args
            .iter()
            .map(|a| format!("\t\t<string>{}</string>\n", xml(a)))
            .collect();
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>Label</key><string>{MAC_LABEL}</string>\n\
\t<key>ProgramArguments</key>\n\t<array>\n{strings}\t</array>\n\
\t<key>RunAtLoad</key><true/>\n\
</dict>\n</plist>\n"
        )
    }

    pub fn desktop_entry(&self) -> String {
        let exec: Vec<String> = std::iter::once(self.launch.program.display().to_string())
            .chain(self.launch.args.iter().cloned())
            .map(|a| exec_arg(&a))
            .collect();
        format!(
            "[Desktop Entry]\nType=Application\nName=PaoPao Proxy\n\
Exec={}\nIcon=app.paopao.proxy\nTerminal=false\nNoDisplay=true\n\
X-GNOME-Autostart-enabled=true\n",
            exec.join(" ")
        )
    }

    /// `"<tray>" <args…>`, as Windows runs it.
    pub fn command_line(&self) -> String {
        std::iter::once(format!("\"{}\"", self.launch.program.display()))
            .chain(self.launch.args.iter().map(|a| {
                if a.contains(' ') {
                    format!("\"{a}\"")
                } else {
                    a.clone()
                }
            }))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn write(path: &Path, text: &str) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

impl crate::LoginItem for OsLogin {
    fn registered(&self) -> bool {
        match self.os {
            Os::MacOs => self.file().is_some_and(|f| f.exists()),
            Os::Linux => self.file().is_some_and(|f| {
                std::fs::read_to_string(f).is_ok_and(|t| {
                    !t.lines().any(|l| {
                        let l = l.trim();
                        l == "Hidden=true" || l == "X-GNOME-Autostart-enabled=false"
                    })
                })
            }),
            Os::Windows => self
                .run
                .out("reg", &["query", WINDOWS_RUN, "/v", WINDOWS_VALUE])
                .is_some(),
            Os::Other => false,
        }
    }

    fn set(&self, on: bool) -> Result<(), String> {
        match (self.os, self.file()) {
            (Os::MacOs | Os::Linux, Some(file)) => {
                if !on {
                    return match std::fs::remove_file(&file) {
                        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                            Err(format!("{}: {e}", file.display()))
                        }
                        _ => Ok(()),
                    };
                }
                let text = if self.os == Os::MacOs {
                    self.plist()
                } else {
                    self.desktop_entry()
                };
                Self::write(&file, &text)
            }
            (Os::Windows, _) => {
                let done = if on {
                    let line = self.command_line();
                    self.run.ok(
                        "reg",
                        &[
                            "add",
                            WINDOWS_RUN,
                            "/v",
                            WINDOWS_VALUE,
                            "/t",
                            "REG_SZ",
                            "/d",
                            &line,
                            "/f",
                        ],
                    )
                } else {
                    // Gone already counts.
                    self.run
                        .ok("reg", &["delete", WINDOWS_RUN, "/v", WINDOWS_VALUE, "/f"])
                        || !self.registered()
                };
                if done {
                    Ok(())
                } else {
                    Err("the login item could not be changed".into())
                }
            }
            _ => Err("no login items here".into()),
        }
    }
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One argument of a desktop entry's `Exec`: quoted when it needs to be,
/// `"`, `` ` ``, `$` and `\` escaped inside the quotes, then the
/// backslashes doubled for the file's own string escaping.
fn exec_arg(a: &str) -> String {
    let plain = !a.is_empty()
        && a.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c));
    if plain {
        return a.to_owned();
    }
    let mut q = String::from("\"");
    for c in a.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            q.push('\\');
        }
        q.push(c);
    }
    q.push('"');
    q.replace('\\', "\\\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tests::FakeCommands;
    use crate::LoginItem as _;

    fn login(os: Os, home: &Path, program: &str) -> (Arc<FakeCommands>, OsLogin) {
        let run = Arc::new(FakeCommands::default());
        let l = OsLogin::new(
            os,
            Launch {
                program: program.into(),
                args: vec!["--data".into(), "/home/u/.local/share/paopao-proxy".into()],
            },
            home.to_owned(),
            None,
            Arc::clone(&run) as _,
        );
        (run, l)
    }

    #[test]
    fn macos_launch_agent() {
        let home = tempfile::tempdir().unwrap();
        let (_, l) = login(
            Os::MacOs,
            home.path(),
            "/Applications/PaoPao Proxy.app/Contents/Library/PaoPao Menu.app",
        );
        assert!(!l.registered());
        l.set(true).unwrap();
        let file = home
            .path()
            .join("Library/LaunchAgents/app.paopao.proxy.login.plist");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("<string>/usr/bin/open</string>"));
        assert!(text.contains("<string>-g</string>"));
        assert!(text.contains(
            "<string>/Applications/PaoPao Proxy.app/Contents/Library/PaoPao Menu.app</string>"
        ));
        assert!(text.contains("<string>--args</string>\n\t\t<string>--data</string>"));
        assert!(text.contains("<key>RunAtLoad</key><true/>"));
        assert!(l.registered());
        l.set(false).unwrap();
        assert!(!file.exists());
        assert!(!l.registered());
        // Off twice: fine.
        l.set(false).unwrap();
    }

    #[test]
    fn linux_autostart_entry() {
        let home = tempfile::tempdir().unwrap();
        let (_, l) = login(Os::Linux, home.path(), "/opt/PaoPao Proxy/paopao-tray");
        l.set(true).unwrap();
        let file = home.path().join(".config/autostart/paopao-proxy.desktop");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains(
            "Exec=\"/opt/PaoPao Proxy/paopao-tray\" --data /home/u/.local/share/paopao-proxy\n"
        ));
        assert!(text.contains("X-GNOME-Autostart-enabled=true"));
        assert!(l.registered());
        // Switched off on the desktop's autostart page.
        std::fs::write(&file, text.replace("enabled=true", "enabled=false")).unwrap();
        assert!(!l.registered());
        l.set(false).unwrap();
        assert!(!file.exists());
        // XDG_CONFIG_HOME is followed.
        let xdg = home.path().join("xdg");
        let l = OsLogin::new(
            Os::Linux,
            Launch {
                program: "/t".into(),
                args: vec![],
            },
            home.path().to_owned(),
            Some(xdg.clone()),
            Arc::new(FakeCommands::default()),
        );
        l.set(true).unwrap();
        assert!(xdg.join("autostart/paopao-proxy.desktop").exists());
        assert_eq!(exec_arg(r#"a "b"$"#), r#""a \\"b\\"\\$""#);
    }

    #[test]
    fn windows_run_value() {
        let home = tempfile::tempdir().unwrap();
        let (run, l) = login(
            Os::Windows,
            home.path(),
            r"C:\Program Files\PaoPao\paopao-tray.exe",
        );
        assert!(!l.registered());
        l.set(true).unwrap();
        let calls = run.take();
        assert_eq!(
            calls.last().unwrap(),
            &format!(
                r#"reg add {WINDOWS_RUN} /v PaoPao Proxy /t REG_SZ /d "C:\Program Files\PaoPao\paopao-tray.exe" --data /home/u/.local/share/paopao-proxy /f"#
            )
        );
        run.answer(
            &format!("reg query {WINDOWS_RUN} /v PaoPao Proxy"),
            "PaoPao Proxy    REG_SZ    x",
        );
        assert!(l.registered());
        l.set(false).unwrap();
        assert_eq!(
            run.take().last().unwrap(),
            &format!("reg delete {WINDOWS_RUN} /v PaoPao Proxy /f")
        );
    }
}

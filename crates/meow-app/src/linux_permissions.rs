//! One-time desktop authorization: network capabilities and only the
//! resolver's cache-flush operation. Never changes resolver configuration.
use anyhow::{bail, Context, Result};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::Command;

const RULE_DIR: &str = "/usr/share/polkit-1/rules.d";
const CAPS: &str = "cap_net_admin,cap_net_raw,cap_net_bind_service+ep";

fn account(uid: u32) -> Result<String> {
    let out = Command::new("/usr/bin/id")
        .args(["-nu", &uid.to_string()])
        .output()?;
    if !out.status.success() {
        bail!("unknown authorization user");
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

fn rule(user: &str) -> String {
    format!("// PaoPao: cache invalidation only; no resolver configuration rights.\npolkit.addRule(function(action, subject) {{\n    if (action.id === \"org.freedesktop.resolve1.flush-caches\" && subject.user === {})\n        return polkit.Result.YES;\n}});\n", serde_json::to_string(user).unwrap())
}

fn rule_path(uid: u32) -> PathBuf {
    PathBuf::from(RULE_DIR).join(format!("49-paopao-dns-cache-{uid}.rules"))
}

/// Check/install/remove this user's narrow permission through the normal
/// OS authorization dialog. Install/remove must run under pkexec as root.
pub fn run(action: &str) -> Result<()> {
    let root = unsafe { libc::geteuid() } == 0;
    let uid = if root {
        std::env::var("PKEXEC_UID")
            .context("must be invoked through pkexec")?
            .parse::<u32>()?
    } else {
        unsafe { libc::getuid() }
    };
    if uid == 0 {
        bail!("desktop user must not be root");
    }
    let path = rule_path(uid);
    let expected = rule(&account(uid)?);
    match action {
        "check" => {
            let m = std::fs::symlink_metadata(&path)?;
            if !m.is_file()
                || m.uid() != 0
                || m.permissions().mode() & 0o022 != 0
                || std::fs::read_to_string(path)? != expected
            {
                bail!("DNS cache permission not installed");
            }
        }
        "install" | "remove" if root => {
            let exe = std::env::current_exe()?;
            if action == "install" {
                // Publish a complete root-owned rule atomically. Polkit
                // ignores the temporary extension; create_new rejects links.
                let next = path.with_extension(format!("{}.tmp", std::process::id()));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(&next)?;
                use std::io::Write as _;
                file.write_all(expected.as_bytes())?;
                file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
                file.sync_all()?;
                std::fs::rename(&next, &path)?;
                if !Command::new("setcap")
                    .arg(CAPS)
                    .arg(exe)
                    .status()?
                    .success()
                {
                    let _ = std::fs::remove_file(path);
                    bail!("network capability authorization failed");
                }
            } else {
                match std::fs::remove_file(path) {
                    Ok(()) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
                let caps = Command::new("getcap").arg(&exe).output()?;
                if !caps.status.success() {
                    bail!("cannot inspect network capabilities");
                }
                if !caps.stdout.is_empty()
                    && !Command::new("setcap")
                        .arg("-r")
                        .arg(exe)
                        .status()?
                        .success()
                {
                    bail!("network capability removal failed");
                }
            }
        }
        _ => bail!("invalid action or missing administrator authorization"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn permission_is_limited_to_one_user_and_cache_flush() {
        let text = super::rule("test\"user");
        assert!(text.contains("subject.user === \"test\\\"user\""));
        assert!(text.contains("action.id === \"org.freedesktop.resolve1.flush-caches\""));
        assert!(!text.contains("set-dns"));
        assert_eq!(
            super::rule_path(1234).file_name().unwrap(),
            "49-paopao-dns-cache-1234.rules"
        );
    }
}

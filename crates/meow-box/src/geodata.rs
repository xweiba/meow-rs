//! The rule data in the core's home: GeoIP (`Country.mmdb`, for
//! `GEOIP,CN`) and GeoSite (`geosite.dat`, for `GEOSITE,…` and the DNS
//! front's domestic list).
//!
//! The core only fetches the data its config uses when it starts; the box
//! starts it before there is a subscription (no `GEOIP` rule yet) and later
//! hot-reloads, so the core alone would never fetch the GeoIP data. The box
//! makes sure both files arrive: direct downloads over a few mirrors,
//! retried with backoff until they are here, then a reload so the rules
//! use them.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use meow_rules::geosite::GeositeDB;

use crate::dns::DOMESTIC_CATEGORY;

/// GeoIP file name in the core's home (the core's default path).
pub const MMDB: &str = "Country.mmdb";
/// GeoSite file name in the core's home (the core's default path).
pub const GEOSITE: &str = "geosite.dat";
/// First wait after a round of failed downloads; doubles up to
/// [`RETRY_MAX`].
pub const RETRY_FIRST: Duration = Duration::from_secs(5);
/// Longest wait between download rounds.
pub const RETRY_MAX: Duration = Duration::from_secs(600);
/// Smaller than any real file (both are several MB): an error page.
const MIN_BYTES: usize = 64 * 1024;
/// The MaxMind DB metadata marker every `.mmdb` file carries.
const MMDB_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
/// The MetaCubeX rule data repository (the app's default source).
const REPO: &str = "MetaCubeX/meta-rules-dat";

/// The links to try for `url`, in order: `url` itself, the other jsDelivr
/// CDNs for the same release file, and the GitHub release (all reachable
/// directly from China when last checked, at different speeds).
pub fn mirrors(url: &str) -> Vec<String> {
    let mut out = vec![url.to_owned()];
    let file = url.rsplit('/').next().unwrap_or_default();
    if url.contains(&format!("jsdelivr.net/gh/{REPO}@release/")) {
        for host in ["testingcf", "fastly", "cdn"] {
            out.push(format!(
                "https://{host}.jsdelivr.net/gh/{REPO}@release/{file}"
            ));
        }
    }
    if matches!(file, "country.mmdb" | "geosite.dat") {
        out.push(format!(
            "https://github.com/{REPO}/releases/download/latest/{file}"
        ));
    }
    let mut seen = HashSet::new();
    out.retain(|u| seen.insert(u.clone()));
    out
}

/// Whether `bytes` is a usable GeoIP file.
pub fn mmdb_ok(bytes: &[u8]) -> bool {
    bytes.len() >= MIN_BYTES && bytes.windows(MMDB_MARKER.len()).any(|w| w == MMDB_MARKER)
}

/// The domestic list out of GeoSite data: only its `cn` category is kept;
/// None when the data is unusable or has no such category.
pub fn domestic_list(bytes: &[u8]) -> Option<GeositeDB> {
    if bytes.len() < MIN_BYTES {
        return None;
    }
    let only: HashSet<String> = [DOMESTIC_CATEGORY.to_owned()].into();
    let db = GeositeDB::from_bytes(bytes, Some(&only)).ok()?;
    db.domain_count(DOMESTIC_CATEGORY)
        .is_some_and(|n| n > 0)
        .then_some(db)
}

/// The domestic list from the GeoSite file at `path` (read off the async
/// threads); None when absent or unusable.
pub async fn load_domestic(path: &Path) -> Option<Arc<GeositeDB>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::read(path).ok().and_then(|b| domestic_list(&b)))
        .await
        .ok()
        .flatten()
        .map(Arc::new)
}

/// Writes `bytes` as `home/file` through a temporary name (the core never
/// sees half a file).
pub fn save(home: &Path, file: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = home.join(format!(".{file}.box-download"));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, home.join(file)).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}

/// The next wait after `wait`.
pub fn backoff(wait: Duration) -> Duration {
    (wait * 2).min(RETRY_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_start_with_the_configs_link() {
        let u = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb";
        let m = mirrors(u);
        assert_eq!(m[0], u);
        assert_eq!(m.len(), 4, "{m:?}");
        assert!(m.contains(
            &"https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb".into()
        ));
        assert_eq!(
            m.last().unwrap(),
            "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
        );
        // A link of the user's own: kept, nothing guessed for it.
        assert_eq!(
            mirrors("https://example.com/x/rules.dat"),
            vec!["https://example.com/x/rules.dat".to_owned()]
        );
    }

    #[test]
    fn unusable_downloads_are_refused() {
        assert!(!mmdb_ok(b"<html>404</html>"));
        let mut big = vec![0u8; MIN_BYTES];
        assert!(!mmdb_ok(&big));
        big.extend_from_slice(MMDB_MARKER);
        assert!(mmdb_ok(&big));
        assert!(domestic_list(&vec![7u8; MIN_BYTES]).is_none());
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        assert_eq!(backoff(RETRY_FIRST), Duration::from_secs(10));
        assert_eq!(backoff(Duration::from_secs(500)), RETRY_MAX);
    }

    #[test]
    fn save_replaces_in_one_step() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(MMDB), b"old").unwrap();
        save(d.path(), MMDB, b"new").unwrap();
        assert_eq!(std::fs::read(d.path().join(MMDB)).unwrap(), b"new");
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no leftovers"
        );
    }
}

use crate::internal_http;
use crate::raw::RawGeoDataConfig;
use anyhow::anyhow;
use meow_common::adapter::Proxy;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

const DEFAULT_MMDB_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb";
const DEFAULT_ASN_URL: &str =
    "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb";
const DEFAULT_GEOSITE_URL: &str =
    "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.dat";

/// Validated `geodata:` config, produced by [`parse_geodata`].
#[derive(Debug, Clone)]
pub struct GeoDataConfig {
    pub mmdb_path: Option<PathBuf>,
    pub asn_path: Option<PathBuf>,
    pub geosite_path: Option<PathBuf>,
    pub auto_update: bool,
    /// Hours between update checks (≥1).
    pub auto_update_interval: u32,
    pub mmdb_url: String,
    pub asn_url: String,
    pub geosite_url: String,
    /// `geodata.background-fetch`: missing DBs never block startup.
    pub background_fetch: bool,
    /// Explicit download exit; no direct fallback when a proxy is named.
    pub proxy: Option<String>,
    /// Additional source URLs keyed by mmdb, asn or geosite.
    pub sources: std::collections::HashMap<String, Vec<String>>,
    /// Public GitHub mirror URL templates containing `{url}`.
    pub mirrors: Vec<String>,
}

impl Default for GeoDataConfig {
    fn default() -> Self {
        Self {
            mmdb_path: None,
            asn_path: None,
            geosite_path: None,
            auto_update: false,
            auto_update_interval: 24,
            mmdb_url: DEFAULT_MMDB_URL.to_string(),
            asn_url: DEFAULT_ASN_URL.to_string(),
            geosite_url: DEFAULT_GEOSITE_URL.to_string(),
            background_fetch: false,
            proxy: None,
            sources: Default::default(),
            mirrors: Vec::new(),
        }
    }
}

/// Parse and validate the raw `geodata:` block. Returns `GeoDataConfig::default()`
/// when the block is absent.
pub fn parse_geodata(raw: Option<&RawGeoDataConfig>) -> Result<GeoDataConfig, anyhow::Error> {
    let Some(r) = raw else {
        return Ok(GeoDataConfig::default());
    };

    // Warn on upstream-only fields (Class B per ADR-0002 §geodata-subsection.md).
    for (name, val) in [
        ("geodata-mode", &r.geodata_mode),
        ("geodata-loader", &r.geodata_loader),
        ("geoip-matcher", &r.geoip_matcher),
    ] {
        if val.is_some() {
            warn!(
                "geodata.{}: field is not supported in meow-rs and will be ignored \
                (upstream: config.go); remove it to suppress this warning",
                name
            );
        }
    }

    let interval = r.auto_update_interval.unwrap_or(24);
    if interval == 0 {
        return Err(anyhow!(
            "geodata.auto-update-interval must be at least 1 hour (got 0)"
        ));
    }
    // Same ceiling as the rule-provider refresh supervisor
    // (`MAX_REFRESH_INTERVAL_SECS`, ~10 years): `Instant + Duration`
    // overflows — and `tokio::time::interval` panics — on absurd values.
    const MAX_AUTO_UPDATE_INTERVAL_HOURS: u32 = 10 * 365 * 24;
    let interval = interval.min(MAX_AUTO_UPDATE_INTERVAL_HOURS);
    if interval != r.auto_update_interval.unwrap_or(24) {
        warn!(
            "geodata.auto-update-interval {}h exceeds the {}h ceiling; clamped",
            r.auto_update_interval.unwrap_or(24),
            MAX_AUTO_UPDATE_INTERVAL_HOURS
        );
    }

    let urls = r.url.as_ref();
    for (id, links) in &r.sources {
        if !matches!(id.as_str(), "mmdb" | "asn" | "geosite") || links.len() > 8 {
            return Err(anyhow!("invalid geodata.sources resource or too many URLs"));
        }
        for link in links {
            validate_url(link)?;
        }
    }
    if r.mirrors.len() > 8 {
        return Err(anyhow!("at most 8 geodata mirrors are allowed"));
    }
    for template in &r.mirrors {
        if template.matches("{url}").count() != 1 {
            return Err(anyhow!("geodata mirror must contain exactly one {{url}}"));
        }
        validate_url(&template.replace("{url}", "https://github.com/example/data"))?;
    }
    if let Some(urls) = urls {
        for link in [&urls.mmdb, &urls.asn, &urls.geosite].into_iter().flatten() {
            validate_url(link)?;
        }
    }
    Ok(GeoDataConfig {
        mmdb_path: r.mmdb_path.as_deref().map(PathBuf::from),
        asn_path: r.asn_path.as_deref().map(PathBuf::from),
        geosite_path: r.geosite_path.as_deref().map(PathBuf::from),
        auto_update: r.auto_update,
        auto_update_interval: interval,
        mmdb_url: urls
            .and_then(|u| u.mmdb.clone())
            .unwrap_or_else(|| DEFAULT_MMDB_URL.to_string()),
        asn_url: urls
            .and_then(|u| u.asn.clone())
            .unwrap_or_else(|| DEFAULT_ASN_URL.to_string()),
        geosite_url: urls
            .and_then(|u| u.geosite.clone())
            .unwrap_or_else(|| DEFAULT_GEOSITE_URL.to_string()),
        background_fetch: r.background_fetch,
        proxy: r.proxy.clone().filter(|s| !s.trim().is_empty()),
        sources: r.sources.clone(),
        mirrors: r.mirrors.clone(),
    })
}

fn validate_url(link: &str) -> Result<(), anyhow::Error> {
    let url = url::Url::parse(link).map_err(|_| anyhow!("invalid geodata URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(anyhow!("geodata URL must use HTTP or HTTPS"));
    }
    Ok(())
}

/// Sources are data, not routing code. Mirrors receive only public GitHub
/// URLs; private subscription credentials are never copied to a third party.
pub fn configured_links(geo: &GeoDataConfig, id: &str, primary: &str) -> Vec<String> {
    let mut links = vec![primary.to_owned()];
    if let Some(extra) = geo.sources.get(id) {
        links.extend(extra.iter().cloned());
    }
    let originals = links.clone();
    for link in originals {
        let public = url::Url::parse(&link).ok().is_some_and(|u| {
            matches!(
                u.host_str(),
                Some("github.com" | "raw.githubusercontent.com")
            ) && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none()
        });
        if public {
            links.extend(geo.mirrors.iter().map(|m| m.replace("{url}", &link)));
        }
    }
    let mut seen = std::collections::HashSet::new();
    links.retain(|link| seen.insert(link.clone()));
    // Explicit sources have priority; bound the generated cross-product.
    links.truncate(16);
    links
}

/// Download `url` and atomically replace `dest` via a `.tmp` sibling.
///
/// When `proxy` is `Some`, the HTTP fetch is tunneled through that proxy
/// adapter (used so GFW-blocked CDNs stay reachable on background refresh);
/// otherwise the OS handles connectivity directly.
///
/// Returns `Ok(())` on success. On failure the temp file is removed (best-
/// effort) and the original `dest` is untouched.
pub async fn download_and_replace(
    url: &str,
    dest: &Path,
    proxy: Option<&Arc<dyn Proxy>>,
) -> Result<(), anyhow::Error> {
    // Unique scratch, not `with_extension("tmp")` — same-stem targets
    // (`Country.mmdb`/`Country.yaml` → `Country.tmp`) and concurrent
    // downloaders (auto-update vs rebuild-time `ensure_geodata`) must not
    // share it (issue #543 review). Sweep scratch a crashed downloader
    // orphaned (issue #621) — on the blocking pool, off the async worker.
    {
        let sweep_target = dest.to_path_buf();
        let _ = crate::spawn_blocking_with_current_dispatcher(move || {
            meow_common::fs_util::sweep_scratch_siblings(
                &sweep_target,
                meow_common::fs_util::SCRATCH_STALE_AGE,
            );
            // The pre-#543 scratch was `with_extension("tmp")`
            // (`Country.mmdb` → `Country.tmp`) — it does not match the
            // `{base}.{pid}.{n}.tmp` sweep shape; remove it only when old
            // (a young file could be a user's own).
            let legacy = sweep_target.with_extension("tmp");
            if legacy != sweep_target {
                let old = std::fs::metadata(&legacy)
                    .and_then(|m| m.modified())
                    .is_ok_and(|t| {
                        SystemTime::now().duration_since(t).unwrap_or_default()
                            > meow_common::fs_util::SCRATCH_STALE_AGE
                    });
                if old {
                    let _ = std::fs::remove_file(&legacy);
                }
            }
        })
        .await;
    }
    let tmp = crate::unique_scratch_path(dest);

    if let Some(p) = proxy {
        info!(
            "auto-update: downloading {} from {} via proxy '{}'",
            dest.display(),
            url,
            p.name()
        );
    } else {
        info!("auto-update: downloading {} from {}", dest.display(), url);
    }

    let bytes = internal_http::fetch(url, proxy, &[])
        .await
        .map_err(|e| anyhow!("fetching {url}: {e}"))?;
    write_atomically(dest, &tmp, bytes, None).await
}

/// Which rule data a download is — decides how it is checked before it
/// replaces anything on disk ([`usable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoKind {
    /// A MaxMind DB (`Country.mmdb`, `GeoLite2-ASN.mmdb`).
    Mmdb,
    /// Country-record MMDB, sing-box GeoIP MMDB or V2Ray GeoIP DAT.
    Country,
    /// ASN MMDB with actual autonomous_system_number records.
    Asn,
    /// GeoSite data (`geosite.dat` protobuf or MetaCubeX `.mrs`).
    Geosite,
}

/// One rule-data file the running config needs and does not have yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoDownload {
    /// The link from the config (`geodata.url.*`, or the default).
    pub url: String,
    /// Where the file goes.
    pub dest: PathBuf,
    pub kind: GeoKind,
}

/// The MetaCubeX rule data repository (where the default links point).
const METACUBEX_REPO: &str = "MetaCubeX/meta-rules-dat";

/// The links to try for `url`, in order: `url` itself; then, when it is a
/// MetaCubeX rule-data file (a jsDelivr `@release` link or a GitHub release
/// link), the same file on the testingcf / fastly / cdn jsDelivr hosts and
/// finally the GitHub release. Any other link is tried alone — nothing is
/// guessed for a user's own source.
///
/// Overlaps `meow_box::geodata::mirrors`, which the box keeps for its own
/// download of the same files (it also checks the domestic list).
pub fn mirrors(url: &str) -> Vec<String> {
    let mut out = vec![url.to_owned()];
    let file = url.rsplit('/').next().unwrap_or_default();
    let jsdelivr = url.contains(".jsdelivr.net/gh/") && url.contains(&format!("{METACUBEX_REPO}@"));
    let github = url.starts_with(&format!("https://github.com/{METACUBEX_REPO}/releases/"));
    if !file.is_empty() && (jsdelivr || github) {
        for host in ["testingcf", "fastly", "cdn"] {
            out.push(format!(
                "https://{host}.jsdelivr.net/gh/{METACUBEX_REPO}@release/{file}"
            ));
        }
        out.push(format!(
            "https://github.com/{METACUBEX_REPO}/releases/download/latest/{file}"
        ));
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|u| seen.insert(u.clone()));
    out
}

/// Whether `bytes` is rule data of `kind` the core can load: an MMDB must
/// open (its metadata — behind the MaxMind marker — parses), GeoSite data
/// must parse as `.mrs` or `.dat`. Rejects error pages, captive-portal
/// answers and cut-off downloads before they replace anything.
pub fn usable(kind: GeoKind, bytes: &[u8]) -> bool {
    match kind {
        GeoKind::Mmdb => maxminddb::Reader::from_source(bytes).is_ok(),
        GeoKind::Country => meow_rules::geodata_format::validate_country(bytes).is_ok(),
        GeoKind::Asn => meow_rules::geodata_format::validate_asn(bytes).is_ok(),
        GeoKind::Geosite => {
            // No category kept: the parse walks (and so checks) the whole
            // file without building any matcher.
            let none = std::collections::HashSet::new();
            !bytes.is_empty()
                && meow_rules::geosite::GeositeDB::from_bytes(bytes, Some(&none)).is_ok()
        }
    }
}

/// Downloads `d` into place: each of [`mirrors`] in turn, every link
/// fetched through `proxies` and directly at once (the first body that is
/// [`usable`] wins), the file replaced atomically. Returns the link that
/// delivered; an error when no link gave usable data (`d.dest` untouched).
pub async fn download_checked(
    d: &GeoDownload,
    proxies: &[Arc<dyn Proxy>],
) -> Result<String, anyhow::Error> {
    download_checked_from(&mirrors(&d.url), d, proxies).await
}

/// [`download_checked`] over an explicit list of links (tests).
pub async fn download_checked_from(
    links: &[String],
    d: &GeoDownload,
    proxies: &[Arc<dyn Proxy>],
) -> Result<String, anyhow::Error> {
    download_checked_via(links, d, proxies, true).await
}

/// Small state for the UI. Payloads remain in the native loaders/on disk.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadStatus {
    pub updating: bool,
    pub checked_at: Option<u64>,
    pub last_error: Option<String>,
}

static DOWNLOADS: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<PathBuf, DownloadStatus>>,
> = std::sync::LazyLock::new(Default::default);
// One bounded data buffer process-wide, including background/manual jobs.
static DOWNLOAD_SLOT: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));
const GEO_DOWNLOAD_MAX: usize = 64 * 1024 * 1024;

pub fn download_status(path: &Path) -> DownloadStatus {
    DOWNLOADS.lock().get(path).cloned().unwrap_or_default()
}

/// Explicit proxy requests fail closed, never retry via the physical NIC.
/// Attempts are sequential and bodies capped, avoiding four database-sized
/// racing response buffers and validation copies during a refresh.
pub async fn download_checked_via(
    links: &[String],
    d: &GeoDownload,
    proxies: &[Arc<dyn Proxy>],
    direct: bool,
) -> Result<String, anyhow::Error> {
    let permit = Arc::new(
        Arc::clone(&DOWNLOAD_SLOT)
            .acquire_owned()
            .await
            .map_err(|_| anyhow!("data updater stopped"))?,
    );
    let status = DownloadStatus {
        updating: true,
        checked_at: None,
        last_error: None,
    };
    DOWNLOADS.lock().insert(d.dest.clone(), status);
    struct Finish(PathBuf);
    impl Drop for Finish {
        fn drop(&mut self) {
            if let Some(s) = DOWNLOADS.lock().get_mut(&self.0) {
                s.updating = false;
            }
        }
    }
    let _finish = Finish(d.dest.clone());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut errors = Vec::new();
    for link in links {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        info!("geodata: downloading {}", d.dest.display());
        let attempts = proxies.iter().map(Some).chain(direct.then_some(None));
        for proxy in attempts {
            let attempt = async {
                let bytes = tokio::time::timeout_at(
                    deadline,
                    internal_http::fetch_capped(link, proxy, &[], GEO_DOWNLOAD_MAX),
                )
                .await
                .map_err(|_| anyhow!("data download deadline exceeded"))?
                .map_err(|e| anyhow!("{e}"))?;
                // Full MMDB/DAT validation is CPU work. Keep it off the
                // socket workers and keep its download permit alive even if
                // the async caller is cancelled while parsing continues.
                let kind = d.kind;
                let validation_permit = Arc::clone(&permit);
                let (bytes, valid) = crate::spawn_blocking_with_current_dispatcher(move || {
                    let _permit = validation_permit;
                    let valid = usable(kind, &bytes);
                    meow_common::memory::release_free_memory();
                    (bytes, valid)
                })
                .await
                .map_err(|_| anyhow!("data validation worker failed"))?;
                if valid {
                    Ok(bytes)
                } else {
                    Err(anyhow!(
                        "not usable {:?} data ({} bytes)",
                        d.kind,
                        bytes.len()
                    ))
                }
            }
            .await;
            match attempt {
                Ok(bytes) => {
                    let tmp = crate::unique_scratch_path(&d.dest);
                    write_atomically(&d.dest, &tmp, bytes, Some(Arc::clone(&permit))).await?;
                    if let Some(s) = DOWNLOADS.lock().get_mut(&d.dest) {
                        s.checked_at = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .ok()
                            .map(|d| d.as_secs());
                        s.last_error = None;
                    }
                    return Ok(link.clone());
                }
                Err(e) => {
                    // URLs may carry credentials. Keep diagnostics useful without
                    // copying arbitrary URL/token text into status or logs.
                    warn!("geodata: download or validation failed for {:?}", d.kind);
                    errors.push(e);
                }
            }
        }
    }
    let message = format!(
        "no usable data after {} attempts; previous file retained",
        errors.len()
    );
    if let Some(s) = DOWNLOADS.lock().get_mut(&d.dest) {
        s.last_error = Some(message.clone());
    }
    Err(anyhow!(message))
}

async fn write_atomically(
    dest: &Path,
    tmp: &Path,
    bytes: Vec<u8>,
    hold: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
) -> Result<(), anyhow::Error> {
    let size = bytes.len();
    let destination = dest.to_path_buf();
    let scratch = tmp.to_path_buf();
    // tokio::fs::write on a borrowed slice copies the whole database.
    // Move the existing buffer to the file worker, retaining the same
    // permit if cancellation detaches this bounded write from its caller.
    crate::spawn_blocking_with_current_dispatcher(move || {
        use std::io::Write as _;
        let _hold = hold;
        let result = (|| -> Result<(), anyhow::Error> {
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                // Cache data remains readable when switching between the
                // privileged service and the same user's ordinary core.
                options.mode(0o644);
            }
            // A collision/symlink is not our scratch and must not be
            // followed, truncated or removed during error cleanup.
            let mut file = options.open(&scratch)?;
            let written = (|| -> Result<(), anyhow::Error> {
                file.write_all(&bytes)?;
                file.sync_all()?;
                std::fs::rename(&scratch, &destination)?;
                Ok(())
            })();
            drop(file);
            if written.is_err() {
                let _ = std::fs::remove_file(&scratch);
            }
            written
        })();
        drop(bytes);
        meow_common::memory::release_free_memory();
        result
    })
    .await??;
    info!("auto-update: {} updated ({} bytes)", dest.display(), size);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{RawGeoDataConfig, RawGeoDataUrls};

    #[tokio::test]
    async fn atomic_writer_keeps_last_good_and_does_not_touch_reserved_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("country.mmdb");
        let reserved = dir.path().join("reserved.tmp");
        std::fs::write(&dest, b"last-good").unwrap();
        std::fs::write(&reserved, b"other-owner").unwrap();
        assert!(write_atomically(&dest, &reserved, b"new".to_vec(), None)
            .await
            .is_err());
        assert_eq!(std::fs::read(&dest).unwrap(), b"last-good");
        assert_eq!(std::fs::read(&reserved).unwrap(), b"other-owner");
        let scratch = dir.path().join("owned.tmp");
        write_atomically(&dest, &scratch, b"new".to_vec(), None)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert!(!scratch.exists());
        #[cfg(unix)]
        {
            let link = dir.path().join("link.tmp");
            std::os::unix::fs::symlink(&reserved, &link).unwrap();
            assert!(write_atomically(&dest, &link, b"bad".to_vec(), None)
                .await
                .is_err());
            assert_eq!(std::fs::read(&reserved).unwrap(), b"other-owner");
            assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        }
    }

    /// A minimal IPv4 MaxMind DB: `0.0.0.0/1` → `{country: {iso_code}}`,
    /// the other half without data.
    fn tiny_mmdb(code: &str) -> Vec<u8> {
        fn s(out: &mut Vec<u8>, v: &str) {
            out.push(0x40 | v.len() as u8);
            out.extend_from_slice(v.as_bytes());
        }
        // One node, 24-bit records: left → data offset 0 (node_count + 16),
        // right → no data (node_count).
        let mut db = vec![0, 0, 17, 0, 0, 1];
        db.extend_from_slice(&[0u8; 16]);
        db.push(0xE1);
        s(&mut db, "country");
        db.push(0xE1);
        s(&mut db, "iso_code");
        s(&mut db, code);
        db.extend_from_slice(b"\xab\xcd\xefMaxMind.com");
        db.push(0xE9);
        s(&mut db, "node_count");
        db.extend_from_slice(&[0xC1, 1]);
        s(&mut db, "record_size");
        db.extend_from_slice(&[0xA1, 24]);
        s(&mut db, "ip_version");
        db.extend_from_slice(&[0xA1, 4]);
        s(&mut db, "database_type");
        s(&mut db, "Test");
        s(&mut db, "languages");
        db.extend_from_slice(&[0x00, 0x04]);
        s(&mut db, "binary_format_major_version");
        db.extend_from_slice(&[0xA1, 2]);
        s(&mut db, "binary_format_minor_version");
        db.push(0xA0);
        s(&mut db, "build_epoch");
        db.extend_from_slice(&[0x01, 0x02, 1]);
        s(&mut db, "description");
        db.push(0xE0);
        db
    }

    fn tiny_geosite() -> Vec<u8> {
        meow_rules::mrs_parser::write_geosite_mrs(&meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
        })
        .unwrap()
    }

    /// Serves `routes` (path → body; anything else 404) on 127.0.0.1.
    async fn origin(routes: Vec<(&'static str, Vec<u8>)>) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes = Arc::new(routes);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let routes = Arc::clone(&routes);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let req = String::from_utf8_lossy(&buf);
                    let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                    let body = routes.iter().find(|(p, _)| *p == path).map(|(_, b)| b);
                    let status = if body.is_some() {
                        "200 OK"
                    } else {
                        "404 Not Found"
                    };
                    let body: &[u8] = body.map_or(b"", Vec::as_slice);
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    #[test]
    fn mirrors_follow_the_configs_link_for_metacubex_files() {
        let u = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb";
        assert_eq!(
            mirrors(u),
            vec![
                u.to_owned(),
                "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
                    .to_owned(),
                "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
                    .to_owned(),
                "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country.mmdb"
                    .to_owned(),
            ]
        );
        // The core's default (a GitHub link) gets the CDNs after it.
        let m = mirrors(DEFAULT_GEOSITE_URL);
        assert_eq!(m[0], DEFAULT_GEOSITE_URL);
        assert_eq!(
            m[1],
            "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
        );
        assert_eq!(m.len(), 5, "{m:?}");
        // A user's own source: tried alone.
        assert_eq!(
            mirrors("https://example.com/x/rules.dat"),
            vec!["https://example.com/x/rules.dat".to_owned()]
        );
        assert_eq!(mirrors(DEFAULT_ASN_URL), vec![DEFAULT_ASN_URL.to_owned()]);
    }

    #[test]
    fn configured_mirrors_never_receive_private_urls() {
        let geo = GeoDataConfig {
            mirrors: vec!["https://mirror.example/{url}".into()],
            sources: std::collections::HashMap::from([(
                "mmdb".into(),
                vec!["https://backup.example/country.mmdb".into()],
            )]),
            ..GeoDataConfig::default()
        };
        let public = "https://github.com/example/data/releases/latest/download/country.mmdb";
        assert_eq!(
            configured_links(&geo, "mmdb", public),
            vec![
                public.to_owned(),
                "https://backup.example/country.mmdb".into(),
                format!("https://mirror.example/{public}")
            ]
        );
        for private in [
            "https://github.com/example/data?token=test",
            "https://test:synthetic@github.com/example/data",
        ] {
            let links = configured_links(&geo, "asn", private);
            assert_eq!(links, vec![private.to_owned()]);
        }
        let mut raw = RawGeoDataConfig {
            mirrors: vec!["https://mirror.example/no-placeholder".into()],
            ..RawGeoDataConfig::default()
        };
        assert!(parse_geodata(Some(&raw)).is_err());
        raw.mirrors.clear();
        raw.sources.insert("typo".into(), vec![]);
        assert!(parse_geodata(Some(&raw)).is_err());
    }

    #[test]
    fn only_loadable_data_is_usable() {
        assert!(usable(GeoKind::Mmdb, &tiny_mmdb("XX")));
        assert!(!usable(GeoKind::Mmdb, b"<html>404</html>"));
        let mmdb = tiny_mmdb("XX");
        assert!(!usable(GeoKind::Mmdb, &mmdb[..mmdb.len() - 20]), "cut off");
        assert!(usable(GeoKind::Geosite, &tiny_geosite()));
        assert!(!usable(GeoKind::Geosite, b""));
        assert!(!usable(
            GeoKind::Geosite,
            b"<html><body>blocked</body></html>"
        ));
        assert!(!usable(GeoKind::Geosite, &tiny_mmdb("XX")));
    }

    /// Links are tried in order: a 404 and an error page are skipped (the
    /// file stays absent meanwhile), the first usable body is saved.
    #[tokio::test]
    async fn download_checked_skips_bad_links_and_keeps_the_first_usable() {
        let addr = origin(vec![
            ("/page.mmdb", b"<html>captive portal</html>".to_vec()),
            ("/good.mmdb", tiny_mmdb("XX")),
        ])
        .await;
        let dir = tempfile::tempdir().unwrap();
        let d = GeoDownload {
            url: format!("http://{addr}/missing.mmdb"),
            dest: dir.path().join("Country.mmdb"),
            kind: GeoKind::Mmdb,
        };
        let links = vec![
            d.url.clone(),
            format!("http://{addr}/page.mmdb"),
            format!("http://{addr}/good.mmdb"),
        ];
        let used = download_checked_from(&links, &d, &[]).await.unwrap();
        assert_eq!(used, links[2]);
        assert_eq!(std::fs::read(&d.dest).unwrap(), tiny_mmdb("XX"));

        // Nothing usable anywhere: an error, and an existing file is kept.
        std::fs::write(&d.dest, b"old").unwrap();
        assert!(download_checked_from(&links[..2], &d, &[]).await.is_err());
        assert_eq!(std::fs::read(&d.dest).unwrap(), b"old");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no scratch files left"
        );
    }

    fn raw_defaults() -> RawGeoDataConfig {
        RawGeoDataConfig::default()
    }

    #[test]
    fn background_fetch_is_parsed() {
        let raw: RawGeoDataConfig = serde_yaml::from_str("background-fetch: true").unwrap();
        assert!(parse_geodata(Some(&raw)).unwrap().background_fetch);
        assert!(!parse_geodata(None).unwrap().background_fetch);
    }

    #[test]
    fn absent_block_returns_defaults() {
        let cfg = parse_geodata(None).unwrap();
        assert!(!cfg.auto_update);
        assert_eq!(cfg.auto_update_interval, 24);
        assert!(cfg.mmdb_path.is_none());
        assert!(cfg.asn_path.is_none());
        assert!(cfg.geosite_path.is_none());
        assert!(cfg.mmdb_url.contains("country.mmdb"));
        assert!(cfg.asn_url.contains("GeoLite2-ASN"));
        assert!(cfg.geosite_url.contains("geosite.dat"));
    }

    #[test]
    fn explicit_paths_override_discovery() {
        let raw = RawGeoDataConfig {
            mmdb_path: Some("/custom/Country.mmdb".to_string()),
            asn_path: Some("/custom/ASN.mmdb".to_string()),
            geosite_path: Some("/custom/geosite.mrs".to_string()),
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(
            cfg.mmdb_path.unwrap().to_str().unwrap(),
            "/custom/Country.mmdb"
        );
        assert_eq!(cfg.asn_path.unwrap().to_str().unwrap(), "/custom/ASN.mmdb");
        assert_eq!(
            cfg.geosite_path.unwrap().to_str().unwrap(),
            "/custom/geosite.mrs"
        );
    }

    #[test]
    fn url_overrides_replace_defaults() {
        let raw = RawGeoDataConfig {
            url: Some(RawGeoDataUrls {
                mmdb: Some("https://example.com/country.mmdb".to_string()),
                asn: None,
                geosite: Some("https://example.com/geosite.mrs".to_string()),
            }),
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(cfg.mmdb_url, "https://example.com/country.mmdb");
        assert!(cfg.asn_url.contains("GeoLite2-ASN")); // default preserved
        assert_eq!(cfg.geosite_url, "https://example.com/geosite.mrs");
    }

    #[test]
    fn interval_zero_is_hard_error() {
        let raw = RawGeoDataConfig {
            auto_update_interval: Some(0),
            ..raw_defaults()
        };
        let err = parse_geodata(Some(&raw)).unwrap_err();
        assert!(
            err.to_string().contains("at least 1 hour"),
            "error should mention minimum interval: {err}"
        );
    }

    #[test]
    fn absent_interval_defaults_to_24() {
        let raw = RawGeoDataConfig {
            auto_update: true,
            auto_update_interval: None,
            ..raw_defaults()
        };
        let cfg = parse_geodata(Some(&raw)).unwrap();
        assert_eq!(cfg.auto_update_interval, 24);
    }

    #[test]
    fn upstream_only_fields_do_not_error() {
        // geodata-mode, geodata-loader, geoip-matcher accepted without error.
        let raw = RawGeoDataConfig {
            geodata_mode: Some(serde_yaml::Value::String("memconservative".to_string())),
            geodata_loader: Some(serde_yaml::Value::String("standard".to_string())),
            geoip_matcher: Some(serde_yaml::Value::String("succinct".to_string())),
            ..raw_defaults()
        };
        // Must not error — warn-only (Class B per ADR-0002).
        parse_geodata(Some(&raw)).unwrap();
    }
}

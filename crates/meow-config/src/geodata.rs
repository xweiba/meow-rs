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
    })
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
    write_atomically(dest, &tmp, &bytes).await
}

/// Which rule data a download is — decides how it is checked before it
/// replaces anything on disk ([`usable`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoKind {
    /// A MaxMind DB (`Country.mmdb`, `GeoLite2-ASN.mmdb`).
    Mmdb,
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
    let mut errors = Vec::new();
    for link in links {
        info!("geodata: downloading {} from {link}", d.dest.display());
        let direct = std::iter::once(None);
        let attempts = direct.chain(proxies.iter().map(Some)).map(|p| {
            Box::pin(async move {
                let bytes = internal_http::fetch(link, p, &[])
                    .await
                    .map_err(|e| anyhow!("{e}"))?;
                if usable(d.kind, &bytes) {
                    Ok(bytes)
                } else {
                    Err(anyhow!(
                        "not usable {:?} data ({} bytes)",
                        d.kind,
                        bytes.len()
                    ))
                }
            })
        });
        match futures::future::select_ok(attempts).await {
            Ok((bytes, _)) => {
                let tmp = crate::unique_scratch_path(&d.dest);
                write_atomically(&d.dest, &tmp, &bytes).await?;
                return Ok(link.clone());
            }
            Err(e) => {
                warn!("geodata: {link}: {e:#}");
                errors.push(format!("{link}: {e:#}"));
            }
        }
    }
    Err(anyhow!("no usable download: {}", errors.join("; ")))
}

async fn write_atomically(dest: &Path, tmp: &Path, bytes: &[u8]) -> Result<(), anyhow::Error> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(tmp, bytes).await?;

    if let Err(e) = tokio::fs::rename(tmp, dest).await {
        let _ = tokio::fs::remove_file(tmp).await;
        return Err(anyhow!(
            "atomic rename {} → {}: {}",
            tmp.display(),
            dest.display(),
            e
        ));
    }

    info!(
        "auto-update: {} updated ({} bytes)",
        dest.display(),
        bytes.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::{RawGeoDataConfig, RawGeoDataUrls};

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

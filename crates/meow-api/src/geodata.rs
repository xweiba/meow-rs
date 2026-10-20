//! Shared native geodata orchestration — startup-fetch (run unconditionally
//! when a target file is missing) and auto-update loop (periodic refresh
//! when `geodata.auto-update: true`).
//!
//! Both entry points are `pub` so downstream FFI callers that build a
//! `Tunnel` directly — bypassing `main.rs` — can wire the same behavior in
//! without reimplementing it.

use meow_common::adapter::Proxy;
use meow_config::geodata::{configured_links, download_checked_via, GeoDownload, GeoKind};
use meow_config::proxy_provider::ProxyProvider;
use meow_config::raw::RawConfig;
use meow_config::rule_provider::RuleProvider;
use meow_config::GeoDataConfig;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Lightweight status endpoint: stat each resource, never deserialize a DB.
pub async fn get_status(
    axum::extract::State(state): axum::extract::State<Arc<crate::routes::AppState>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Status polling must not clone thousands of rules and all node
    // credentials merely to render three resource rows.
    let (parsed, formats) = {
        let raw = state.raw_config.read();
        let formats: std::collections::HashMap<_, _> = raw
            .rule_providers
            .as_ref()
            .into_iter()
            .flat_map(|all| all.iter())
            .map(|(name, p)| {
                (
                    name.clone(),
                    p.format.clone().unwrap_or_else(|| "yaml".into()),
                )
            })
            .collect();
        (
            meow_config::geodata::parse_geodata(raw.geodata.as_ref()),
            formats,
        )
    };
    let Ok(geo) = parsed else {
        return (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            axum::Json(serde_json::json!({"error":"invalid geodata configuration"})),
        )
            .into_response();
    };
    let mut resources = Vec::new();
    for (id, target) in ["mmdb", "asn", "geosite"]
        .into_iter()
        .zip(compute_targets(&geo))
    {
        let meta = tokio::fs::metadata(&target.path).await.ok();
        let updated = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let status = meow_config::geodata::download_status(&target.path);
        resources.push(serde_json::json!({"id":id, "url":target.url,
            "format":if id == "geosite" { "dat/mrs" } else { "mmdb" },
            "available":meta.as_ref().is_some_and(std::fs::Metadata::is_file),
            "bytes":meta.as_ref().map_or(0, std::fs::Metadata::len), "updatedAt":updated,
            // The scheduler uses a monotonic per-process clock; file mtime
            // plus interval is not its deadline after restart/manual update.
            // Omit an exact time until the scheduler publishes one itself.
            "nextUpdate":serde_json::Value::Null,
            "updating":status.updating, "lastError":status.last_error}));
    }
    let providers: Vec<_> = state.rule_providers.read().iter().map(|(name, p)| {
        let format = formats.get(name).map_or("yaml", String::as_str);
        serde_json::json!({"name":name,"behavior":p.behavior.to_string(),
            "format":format,"ruleCount":p.rule_count(),"updatedAt":if p.updated_at_secs()==0 {None} else {crate::routes::unix_rfc3339(p.updated_at_secs())},
            "lastError":p.last_error()})
    }).collect();
    axum::Json(serde_json::json!({"geodata":{"autoUpdate":geo.auto_update,
        "intervalHours":geo.auto_update_interval,"proxy":geo.proxy,"mirrors":geo.mirrors,
        "resources":resources},"providers":providers}))
    .into_response()
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRequest {
    pub id: Option<String>,
}

static MANUAL_UPDATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Reclaim allocator-retained validation/rebuild buffers after every exit
/// path. The guard must outlive temporary parser contexts and old indexes.
struct ReleaseTemporaryMemory;
impl Drop for ReleaseTemporaryMemory {
    fn drop(&mut self) {
        meow_common::memory::release_free_memory();
    }
}

/// The owned task continues if Flutter closes the request or its process.
/// A second update is rejected, rather than retaining another DB-sized job.
pub async fn update(
    axum::extract::State(state): axum::extract::State<Arc<crate::routes::AppState>>,
    axum::Json(request): axum::Json<UpdateRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if request
        .id
        .as_deref()
        .is_some_and(|s| !matches!(s, "mmdb" | "asn" | "geosite"))
    {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error":"unknown data resource"})),
        )
            .into_response();
    }
    let Ok(permit) = MANUAL_UPDATE.try_lock() else {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(serde_json::json!({"error":"a data update is running"})),
        )
            .into_response();
    };
    let job = tokio::spawn(async move {
        let _memory = ReleaseTemporaryMemory;
        let _permit = permit;
        let raw = state.raw_config.read().clone();
        let geo = meow_config::geodata::parse_geodata(raw.geodata.as_ref())
            .map_err(|_| "invalid data configuration")?;
        let mut report = refresh_targets(&geo, &raw, &state.tunnel, request.id.as_deref()).await;
        if !report.updated.is_empty() {
            let cache_dir = state
                .config_path
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(meow_config::resource_cache_dir_for_config_path);
            if !reload_rules_with_new_data(
                &state.tunnel,
                &state.raw_config,
                &state.rule_providers,
                &state.proxy_providers,
                &state.dns_server,
                cache_dir.as_deref(),
                "manual data update",
            )
            .await
            {
                report.errors.insert(
                    "reload".into(),
                    "data downloaded but native rule reload failed".into(),
                );
            }
        }
        Ok::<_, &str>(report)
    });
    match job.await {
        Ok(Ok(report)) => axum::Json(report).into_response(),
        _ => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error":"data update failed; previous data retained"})),
        )
            .into_response(),
    }
}

/// One geodata DB to consider on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoTarget {
    pub label: &'static str,
    pub path: PathBuf,
    pub url: String,
}

/// Resolve the three geodata target paths (mmdb / asn / geosite) from `geo`,
/// applying the project-wide defaults when an explicit path was not set.
pub fn compute_targets(geo: &GeoDataConfig) -> [GeoTarget; 3] {
    let mmdb = geo
        .mmdb_path
        .clone()
        .unwrap_or_else(meow_config::default_geoip_path);
    let asn = geo
        .asn_path
        .clone()
        .unwrap_or_else(meow_config::default_asn_path);
    let geosite = geo
        .geosite_path
        .clone()
        .unwrap_or_else(meow_config::default_geosite_path);
    [
        GeoTarget {
            label: "GeoIP MMDB",
            path: mmdb,
            url: geo.mmdb_url.clone(),
        },
        GeoTarget {
            label: "ASN MMDB",
            path: asn,
            url: geo.asn_url.clone(),
        },
        GeoTarget {
            label: "geosite",
            path: geosite,
            url: geo.geosite_url.clone(),
        },
    ]
}

/// Resolve download policy against the live registry. Explicit policy
/// failure never changes a request to a direct download.
fn download_routes(
    raw: &RawConfig,
    geo: &GeoDataConfig,
    tunnel: &Tunnel,
) -> Result<(Vec<Arc<dyn Proxy>>, bool), String> {
    let route = tunnel.route_snapshot();
    match geo.proxy.as_deref() {
        Some("DIRECT") => Ok((Vec::new(), true)),
        Some(name) => route
            .proxies
            .get(name)
            .cloned()
            .map(|p| (vec![p], false))
            .ok_or_else(|| "configured data download exit is unavailable".into()),
        None => Ok((
            meow_config::internal_http::first_named_proxies(
                raw.proxies.as_deref(),
                &route.proxies,
                3,
            ),
            true,
        )),
    }
}

#[derive(Default, serde::Serialize)]
pub struct UpdateReport {
    pub updated: Vec<String>,
    pub errors: std::collections::BTreeMap<String, String>,
}

/// Downloads and validates all selected files, retaining each previous
/// file independently on failure. No database payload survives this call.
async fn refresh_targets(
    geo: &GeoDataConfig,
    raw: &RawConfig,
    tunnel: &Tunnel,
    only: Option<&str>,
) -> UpdateReport {
    let mut report = UpdateReport::default();
    let routes = download_routes(raw, geo, tunnel);
    for (id, target) in ["mmdb", "asn", "geosite"]
        .into_iter()
        .zip(compute_targets(geo))
    {
        if only.is_some_and(|wanted| wanted != id) {
            continue;
        }
        let (proxies, direct) = match &routes {
            Ok(routes) => routes,
            Err(error) => {
                report.errors.insert(id.into(), error.clone());
                continue;
            }
        };
        let d = GeoDownload {
            url: target.url.clone(),
            dest: target.path,
            kind: if id == "geosite" {
                GeoKind::Geosite
            } else if id == "asn" {
                GeoKind::Asn
            } else {
                GeoKind::Country
            },
        };
        match download_checked_via(
            &configured_links(geo, id, &target.url),
            &d,
            proxies,
            *direct,
        )
        .await
        {
            Ok(_) => report.updated.push(id.into()),
            Err(_) => {
                report.errors.insert(
                    id.into(),
                    "download or validation failed; previous file retained".into(),
                );
            }
        }
    }
    report
}

/// Download each target whose `path` does not yet exist. Returns the list of
/// labels that were successfully fetched (empty if nothing was missing or
/// every fetch failed). Each target is attempted independently — one failure
/// does not skip the others.
pub async fn fetch_missing(
    targets: &[GeoTarget],
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> Vec<&'static str> {
    let mut downloaded = Vec::new();
    for t in targets {
        if t.path.exists() {
            continue;
        }
        info!(
            "geodata startup-fetch: {} missing at {}, downloading",
            t.label,
            t.path.display()
        );
        let d = GeoDownload {
            url: t.url.clone(),
            dest: t.path.clone(),
            kind: if t.label == "geosite" {
                GeoKind::Geosite
            } else if t.label == "ASN MMDB" {
                GeoKind::Asn
            } else {
                GeoKind::Country
            },
        };
        let proxies: Vec<_> = download_proxy.cloned().into_iter().collect();
        match download_checked_via(
            std::slice::from_ref(&d.url),
            &d,
            &proxies,
            download_proxy.is_none(),
        )
        .await
        {
            Ok(_) => downloaded.push(t.label),
            Err(e) => warn!(
                "geodata startup-fetch: {} download failed: {:#}",
                t.label, e
            ),
        }
    }
    downloaded
}

/// Reparse + republish the resolver after the geo DB files changed. The
/// raw config is unchanged, so `reconcile_dns_config`'s
/// old-vs-candidate gate would call this a no-op for `geosite:`-only
/// policies — parse and publish directly. The DNS rebuild borrows the
/// same routing rebuild's provider map (the live registry generation
/// these rules bind); no payload snapshot exists to forward — a shared
/// rebuild never prefetches (issue #543). A parse failure warns and
/// keeps the running resolver — the rules commit proceeds regardless.
///
/// `#name` upstreams bind the LIVE route's proxies and dialer registry,
/// not `rebuild`'s: a rules-only rebuild publishes into a transient
/// `ProxyRegistry` cell that `update_rules` never installs, so adapters
/// captured from `rebuild.proxies` would hold a dangling
/// `Weak<RegistryCell>` (and groups a stateless duplicate) once
/// `rebuild` drops.
///
/// The parse runs on a spawned task so a panic unwinds into a
/// `JoinError` we can warn-and-continue on — a panic inside the loop
/// task would silently kill auto-update until restart.
///
/// Ordering is the point of the signature taking `rules`: the DNS parse
/// is the only await before the commits, and it runs FIRST — a
/// cancellation during it leaves nothing committed (the next trigger
/// retries the whole refresh). After the parse resolves, `update_rules`
/// and `publish_dns`'s synchronous resolver swap run back to back with
/// no await between, so the two commits cannot be split (issue #621).
/// Parse inputs are invariant under `update_rules` (`route.proxies` /
/// `dialer_registry` are unchanged by it; `prior` is just the old
/// resolver), so computing them before the rules commit is equivalent.
async fn republish_dns_for_geo_dbs(
    raw: &RawConfig,
    cache_dir: Option<&std::path::Path>,
    rule_providers: &std::collections::HashMap<String, Arc<RuleProvider>>,
    rules: Vec<Box<dyn meow_common::rule::Rule>>,
    tunnel: &Tunnel,
    dns_server: &RwLock<Option<crate::routes::DnsServerHandle>>,
    label: &str,
) -> bool {
    debug_assert!(
        crate::routes::CONFIG_MUTATION.try_lock().is_err(),
        "{label}: republish outside the CONFIG_MUTATION lane"
    );
    let raw = raw.clone();
    let cache_dir = cache_dir.map(std::path::Path::to_path_buf);
    let providers = rule_providers.clone();
    let prior = tunnel.resolver();
    let route = tunnel.route_snapshot();
    let parse = tokio::spawn(async move {
        meow_config::parse_dns_from_raw(
            &raw,
            cache_dir.as_deref(),
            &route.proxies,
            Some(&providers),
            None,
            Some(prior.as_ref()),
            Some(&route.dialer_registry),
        )
        .await
    });
    // Abort the parse if this future is cancelled while awaiting it —
    // a dropped JoinHandle would detach the task and keep the cloned
    // inputs alive until it finishes anyway.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _abort_guard = AbortOnDrop(parse.abort_handle());
    let parsed = parse.await;
    // Commits — synchronous, adjacent, no await between.
    match parsed {
        Ok(Ok(dns)) => {
            tunnel.update_rules(rules);
            crate::routes::publish_dns(tunnel, dns_server, &dns).await;
            true
        }
        Ok(Err(e)) => {
            warn!("{label}: dns republish refused; previous generation retained: {e:#}");
            false
        }
        Err(e) => {
            warn!("{label}: dns republish task failed: {e}");
            false
        }
    }
}

/// Startup-fetch entry point: download any geodata DB whose target file does
/// not yet exist, then rebuild rules so the freshly-downloaded DBs take
/// effect without a restart. Independent of `geodata.auto-update` — the goal
/// is "if the file is missing when meow boots, fetch it so rules work on
/// first run." Safe to spawn as a background task.
///
/// `rule_providers` must be the same shared registry `ApiServer` holds —
/// a private `RwLock` would fork the API-visible provider set. The
/// rebuild binds those live provider objects rather than replacing the
/// registry, so no supervisor reconcile is needed here. `dns_server` is
/// the shared DNS-server handle — after a DB download the resolver is
/// reparsed and republished so `geosite:`/`rule-set:` policy matchers
/// bind the new DB generation (issue #543).
///
/// `cache_dir` feeds only the post-download rebuild context (provider
/// `path:` containment, fake-IP store base) — pass the same value startup
/// used so a republish cannot admit paths `-t` would have rejected.
/// Download targets come from `compute_targets` and are unaffected.
pub async fn run_on_startup(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    // Live proxy providers — group `use:` names resolve against them;
    // an empty map fails every `use:` group under `strict: true`.
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>>,
    cache_dir: Option<std::path::PathBuf>,
) {
    let route = tunnel.route_snapshot();
    let proxies = &route.proxies;
    let downloaded = if geo.background_fetch {
        // Only what the config uses (startup never waited for it).
        let raw = raw_config.read().clone();
        let got = fetch_needed(&raw, &geo, &tunnel).await.downloaded;
        vec!["geodata"; got]
    } else {
        let targets = compute_targets(&geo);
        let download_proxy = meow_config::internal_http::first_named_proxy(
            raw_config.read().proxies.as_deref(),
            proxies,
        );
        fetch_missing(&targets, download_proxy.as_ref()).await
    };
    if downloaded.is_empty() {
        return;
    }
    reload_rules_with_new_data(
        &tunnel,
        &raw_config,
        &rule_providers,
        &proxy_providers,
        &dns_server,
        cache_dir.as_deref(),
        "geodata startup-fetch",
    )
    .await;
}

/// Rebuilds the rules (and republishes the resolver) after rule data
/// arrived on disk, so GEOIP / GEOSITE / `geosite:` policies match without
/// another reload. The raw is read inside the config lane: a download that
/// finishes after a PUT must not revert rules to the pre-PUT config
/// (issue #514).
#[allow(clippy::too_many_arguments)]
async fn reload_rules_with_new_data(
    tunnel: &Tunnel,
    raw_config: &RwLock<RawConfig>,
    rule_providers: &Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    proxy_providers: &dashmap::DashMap<String, Arc<ProxyProvider>>,
    dns_server: &RwLock<Option<crate::routes::DnsServerHandle>>,
    cache_dir: Option<&std::path::Path>,
    label: &str,
) -> bool {
    let _memory = ReleaseTemporaryMemory;
    // Serialize against config commits and rebuild from the raw committed
    // *inside* the lane — otherwise a download finishing after a PUT could
    // revert rules to a set built from the pre-PUT config (issue #514).
    let _lane = crate::routes::CONFIG_MUTATION.lock().await;
    let raw = raw_config.read().clone();
    // Share the tunnel's resolver slot so the rebuilt DIRECT adapter
    // tracks later `set_resolver` swaps (issue #514).
    let resolver = tunnel.resolver_slot();
    let rebuild = tokio::task::spawn_blocking({
        let cache_dir = cache_dir.map(std::path::Path::to_path_buf);
        let raw = raw.clone();
        let rule_providers = Arc::clone(rule_providers);
        let proxy_providers: std::collections::HashMap<_, _> = proxy_providers
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();
        move || {
            meow_config::rebuild_from_raw_with_resolver(
                &raw,
                Some(&resolver),
                cache_dir.as_deref(),
                &proxy_providers,
                // Rules-only refresh — bind the rebuilt RULE-SET rules to
                // the LIVE provider objects so the rebuild sees each
                // provider's current (possibly refreshed) content rather
                // than a fresh declaration (issue #533 review). Refreshes
                // landing after this rebuild stay visible too: the
                // matchers hold the same Arc<RuleProvider> objects the
                // refresh tasks mutate (issue #553).
                Some(rule_providers.read().clone()),
            )
        }
    })
    .await;
    match rebuild {
        Ok(Ok(rebuild)) => {
            // The republish owns the commit order: DNS parse first
            // (cancel = nothing committed), then `update_rules` and the
            // synchronous resolver swap back to back (issue #621). The
            // DNS parse borrows the rebuild's (live) provider map
            // (issue #543).
            let published = republish_dns_for_geo_dbs(
                &raw,
                cache_dir,
                &rebuild.rule_providers,
                rebuild.rules,
                tunnel,
                dns_server,
                label,
            )
            .await;
            // No registry swap or supervisor reconcile: the rebuild bound
            // the live provider objects, so the map is unchanged and every
            // interval task is already supervised. Known limitation:
            // provider payloads embed geo entries parsed against the
            // provider's load-time ctx — a DB arriving via this fetch only
            // reaches them at the next full config commit.
            info!("{label}: rules reloaded with downloaded DBs");
            published
        }
        Ok(Err(e)) => {
            warn!("{label}: rule rebuild failed after download: {e:#}");
            false
        }
        Err(e) => {
            warn!("{label}: rule rebuild task failed after download: {e}");
            false
        }
    }
}

/// What one [`fetch_needed`] pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchPass {
    /// Files downloaded (checked and in place).
    pub downloaded: usize,
    /// Files still missing (every link failed or gave unusable data).
    pub missing: usize,
}

/// Downloads the rule data `raw` references and lacks
/// ([`meow_config::missing_geodata_for`]): mirrors, checked before they
/// replace anything, raced through up to three of the config's lines (as
/// published on `tunnel`) and directly
/// ([`meow_config::geodata::download_checked`]).
pub async fn fetch_needed(raw: &RawConfig, geo: &GeoDataConfig, tunnel: &Tunnel) -> FetchPass {
    let wanted = meow_config::missing_geodata_for(raw, geo);
    if wanted.is_empty() {
        return FetchPass::default();
    }
    let (racers, direct) = match download_routes(raw, geo, tunnel) {
        Ok(routes) => routes,
        Err(e) => {
            warn!("geodata: {e}");
            return FetchPass {
                downloaded: 0,
                missing: wanted.len(),
            };
        }
    };
    let mut pass = FetchPass::default();
    for d in &wanted {
        let id = if d.kind == GeoKind::Geosite {
            "geosite"
        } else if d.dest
            == geo
                .asn_path
                .clone()
                .unwrap_or_else(meow_config::default_asn_path)
        {
            "asn"
        } else {
            "mmdb"
        };
        let links = configured_links(geo, id, &d.url);
        match download_checked_via(&links, d, &racers, direct).await {
            Ok(link) => {
                info!("geodata: {} downloaded from {link}", d.dest.display());
                pass.downloaded += 1;
            }
            Err(e) => {
                warn!("geodata: {}: {e:#}", d.dest.display());
                pass.missing += 1;
            }
        }
    }
    pass
}

/// Pacing of [`run_background_fetch`]'s retries after a failed pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    /// Wait after the first failed pass; doubles after each further one.
    pub first: std::time::Duration,
    /// Longest wait between passes.
    pub max: std::time::Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            first: std::time::Duration::from_secs(5),
            max: std::time::Duration::from_secs(600),
        }
    }
}

/// Keeps the rule data the running config needs on disk: a pass
/// ([`fetch_needed`]) at start when `initial` (the startup fetch of
/// `geodata.background-fetch`), and one after every committed config change
/// (`commits`, bumped by the API's commit path) — a reload that adds
/// `GEOIP` / `GEOSITE` rules or `geosite:` DNS policies gets its files
/// without a restart. A pass that downloaded something rebuilds the rules
/// and republishes the resolver ([`reload_rules_with_new_data`]); a pass
/// that left files missing is retried with backoff ([`Retry`]), sooner when
/// another commit lands.
///
/// The geodata settings (links, paths) are read from the committed raw on
/// every pass, so a reload that changes them is followed too. Ends when the
/// tunnel is dropped or every commit sender is gone. Spawn it as a
/// background task.
///
/// `meow box` downloads the same two files itself as well
/// (`meow_box::App::ensure_rule_data`, which also loads the box DNS
/// front's domestic list); both replace files atomically, so whichever
/// lands first wins and the other finds nothing missing.
#[allow(clippy::too_many_arguments)]
pub async fn run_background_fetch(
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>>,
    cache_dir: Option<std::path::PathBuf>,
    mut commits: tokio::sync::watch::Receiver<u64>,
    retry: Retry,
    initial: bool,
) {
    // Weak between passes: an embedder dropping every `Tunnel` handle ends
    // this task instead of keeping `TunnelInner` alive (issue #514).
    let weak = tunnel.weak_inner();
    drop(tunnel);
    let mut wait = retry.first;
    let mut run_pass = initial;
    loop {
        let mut pending = false;
        if run_pass {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let tunnel = Tunnel::from_inner(inner);
            let raw = raw_config.read().clone();
            let geo = match meow_config::geodata::parse_geodata(raw.geodata.as_ref()) {
                Ok(g) => g,
                Err(e) => {
                    warn!("geodata: {e:#}");
                    GeoDataConfig::default()
                }
            };
            let pass = fetch_needed(&raw, &geo, &tunnel).await;
            if pass.downloaded > 0 {
                reload_rules_with_new_data(
                    &tunnel,
                    &raw_config,
                    &rule_providers,
                    &proxy_providers,
                    &dns_server,
                    cache_dir.as_deref(),
                    "geodata fetch",
                )
                .await;
            }
            pending = pass.missing > 0;
        }
        if pending {
            warn!("geodata: retrying in {}s", wait.as_secs());
            tokio::select! {
                changed = commits.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    wait = retry.first;
                }
                () = tokio::time::sleep(wait) => {
                    wait = (wait * 2).min(retry.max);
                }
            }
        } else {
            wait = retry.first;
            if commits.changed().await.is_err() {
                return;
            }
        }
        run_pass = true;
    }
}

/// Background task that periodically re-downloads all enabled geodata DBs
/// when `geodata.auto-update: true`. After each successful download the DB
/// file is atomically replaced on disk, then rules are rebuilt and the DNS
/// resolver republished (same helper as `run_on_startup`) — all without
/// restart. Runs forever; spawn as a background task.
///
/// Country MMDB, ASN and GeoSite use the same checked atomic replacement.
///
/// The tunnel is captured weakly (issue #514): an embedder that drops
/// every `Tunnel` handle stops this loop at the next tick instead of
/// pinning `TunnelInner` forever.
///
/// See [`run_on_startup`] for the `rule_providers` / `proxy_providers` /
/// `dns_server` sharing contract — and for `cache_dir`, which feeds only
/// the post-download rebuild context (download targets resolve via
/// `compute_targets` independently).
pub async fn auto_update_loop(
    geo: GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    // Same contract as `run_on_startup` — the live provider registry.
    proxy_providers: Arc<dashmap::DashMap<String, Arc<ProxyProvider>>>,
    dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>>,
    cache_dir: Option<std::path::PathBuf>,
) {
    let weak = tunnel.weak_inner();
    drop(tunnel);
    let mut geo = geo;
    loop {
        // A reload may change the source, exit, interval or enabled flag.
        // Wake at most once a minute to observe it without a busy poll.
        let since = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if weak.strong_count() == 0 {
                return;
            }
            let raw = raw_config.read().clone();
            if let Ok(current) = meow_config::geodata::parse_geodata(raw.geodata.as_ref()) {
                geo = current;
            }
            if geo.auto_update
                && since.elapsed().as_secs() >= geo.auto_update_interval as u64 * 3600
            {
                break;
            }
        }

        let Some(inner) = weak.upgrade() else {
            info!("tunnel dropped; stopping geodata auto-update loop");
            return;
        };
        let tunnel = Tunnel::from_inner(inner);

        let asn_target = geo
            .asn_path
            .clone()
            .unwrap_or_else(meow_config::default_asn_path);
        let geosite_target = geo
            .geosite_path
            .clone()
            .unwrap_or_else(meow_config::default_geosite_path);
        auto_update_tick(
            &geo,
            &tunnel,
            &raw_config,
            Arc::clone(&rule_providers),
            &proxy_providers,
            &dns_server,
            cache_dir.as_deref(),
            &asn_target,
            &geosite_target,
        )
        .await;
    }
}

/// One auto-update round: download all DBs (each failure is logged and
/// skipped — a partial update still commits), then serialize through the
/// config lane to rebuild rules and republish the resolver. Split out of
/// `auto_update_loop` so the orchestration is directly testable without
/// driving the ticker (issue #543 review).
#[allow(clippy::too_many_arguments)]
async fn auto_update_tick(
    geo: &GeoDataConfig,
    tunnel: &Tunnel,
    raw_config: &RwLock<RawConfig>,
    rule_providers: Arc<RwLock<std::collections::HashMap<String, Arc<RuleProvider>>>>,
    proxy_providers: &dashmap::DashMap<String, Arc<ProxyProvider>>,
    dns_server: &RwLock<Option<crate::routes::DnsServerHandle>>,
    cache_dir: Option<&std::path::Path>,
    asn_target: &std::path::Path,
    geosite_target: &std::path::Path,
) {
    let _memory = ReleaseTemporaryMemory;
    let mut geo = geo.clone();
    geo.asn_path = Some(asn_target.to_owned());
    geo.geosite_path = Some(geosite_target.to_owned());
    let raw = raw_config.read().clone();
    let report = refresh_targets(&geo, &raw, tunnel, None).await;
    if report.updated.is_empty() {
        warn!("geodata auto-update: all downloads failed; rules not reloaded");
        return;
    }

    // Serialize against config commits and rebuild from the raw
    // committed *inside* the lane — otherwise this rebuild could
    // revert rules committed by a concurrent PUT (issue #514).
    let _lane = crate::routes::CONFIG_MUTATION.lock().await;
    let raw = raw_config.read().clone();
    // Share the tunnel's resolver slot so the rebuilt DIRECT adapter
    // tracks later `set_resolver` swaps (issue #514).
    let resolver = tunnel.resolver_slot();
    let rebuild = tokio::task::spawn_blocking({
        let cache_dir = cache_dir.map(std::path::Path::to_path_buf);
        let raw = raw.clone();
        let rule_providers = Arc::clone(&rule_providers);
        let proxy_providers: std::collections::HashMap<_, _> = proxy_providers
            .iter()
            .map(|e| (e.key().clone(), Arc::clone(e.value())))
            .collect();
        move || {
            meow_config::rebuild_from_raw_with_resolver(
                &raw,
                Some(&resolver),
                cache_dir.as_deref(),
                &proxy_providers,
                // Rules-only refresh — bind the rebuilt RULE-SET rules
                // to the LIVE provider set so API/provider refreshes
                // keep reaching them (issue #533 review).
                Some(rule_providers.read().clone()),
            )
        }
    })
    .await;
    match rebuild {
        Ok(Ok(rebuild)) => {
            // Same ordering as the startup path — the republish parses
            // DNS first (cancel = nothing committed), then commits rules
            // and the resolver swap back to back (issue #621). No
            // registry write or reconcile: the rebuild bound the live
            // provider objects (issue #543).
            republish_dns_for_geo_dbs(
                &raw,
                cache_dir,
                &rebuild.rule_providers,
                rebuild.rules,
                tunnel,
                dns_server,
                "geodata auto-update",
            )
            .await;
            info!("geodata auto-update: rules reloaded with updated DBs");
        }
        Ok(Err(e)) => {
            warn!(
                "geodata auto-update: rule rebuild failed after DB download: {:#}",
                e
            );
        }
        Err(e) => {
            warn!(
                "geodata auto-update: rule rebuild task failed after DB download: {}",
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg_with_paths(
        mmdb: Option<&str>,
        asn: Option<&str>,
        geosite: Option<&str>,
    ) -> GeoDataConfig {
        GeoDataConfig {
            mmdb_path: mmdb.map(PathBuf::from),
            asn_path: asn.map(PathBuf::from),
            geosite_path: geosite.map(PathBuf::from),
            mmdb_url: "https://example.test/country.mmdb".into(),
            asn_url: "https://example.test/asn.mmdb".into(),
            geosite_url: "https://example.test/geosite.mrs".into(),
            ..GeoDataConfig::default()
        }
    }

    #[test]
    fn compute_targets_uses_explicit_paths_when_set() {
        let cfg = cfg_with_paths(
            Some("/tmp/explicit/country.mmdb"),
            Some("/tmp/explicit/asn.mmdb"),
            Some("/tmp/explicit/geosite.mrs"),
        );
        let t = compute_targets(&cfg);
        assert_eq!(t[0].label, "GeoIP MMDB");
        assert_eq!(t[0].path, PathBuf::from("/tmp/explicit/country.mmdb"));
        assert_eq!(t[1].label, "ASN MMDB");
        assert_eq!(t[1].path, PathBuf::from("/tmp/explicit/asn.mmdb"));
        assert_eq!(t[2].label, "geosite");
        assert_eq!(t[2].path, PathBuf::from("/tmp/explicit/geosite.mrs"));
    }

    #[test]
    fn compute_targets_falls_back_to_defaults_when_unset() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        // Defaults are project-defined; we just assert non-empty + matching
        // file basenames so the test isn't tied to the user's home dir.
        assert_eq!(t[0].path, meow_config::default_geoip_path());
        assert_eq!(t[1].path, meow_config::default_asn_path());
        assert_eq!(t[2].path, meow_config::default_geosite_path());
    }

    #[test]
    fn compute_targets_carries_urls() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        assert_eq!(t[0].url, "https://example.test/country.mmdb");
        assert_eq!(t[1].url, "https://example.test/asn.mmdb");
        assert_eq!(t[2].url, "https://example.test/geosite.mrs");
    }

    #[tokio::test]
    async fn fetch_missing_skips_existing_files() {
        // All three targets point at files that already exist → returns empty
        // and never touches the network (the URLs are unreachable).
        let dir = tempfile::tempdir().unwrap();
        let mmdb = dir.path().join("country.mmdb");
        let asn = dir.path().join("asn.mmdb");
        let geosite = dir.path().join("geosite.mrs");
        std::fs::write(&mmdb, b"existing-mmdb").unwrap();
        std::fs::write(&asn, b"existing-asn").unwrap();
        std::fs::write(&geosite, b"existing-geosite").unwrap();

        let cfg = cfg_with_paths(
            Some(mmdb.to_str().unwrap()),
            Some(asn.to_str().unwrap()),
            Some(geosite.to_str().unwrap()),
        );
        let targets = compute_targets(&cfg);
        let downloaded = fetch_missing(&targets, None).await;
        assert!(
            downloaded.is_empty(),
            "no file is missing → no download attempt"
        );
        // Files are unchanged.
        assert_eq!(std::fs::read(&mmdb).unwrap(), b"existing-mmdb");
    }

    /// Issue #543 — after the geo DB files change, the resolver must be
    /// republished even though the raw config is unchanged
    /// (`dns_inputs_equal` would call it a no-op). Observable as a new
    /// resolver generation on the tunnel.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_swaps_resolver_generation() {
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let before = tunnel.resolver();
        let dir = tempfile::tempdir().unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = crate::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            Some(dir.path()),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(
            !Arc::ptr_eq(&before, &tunnel.resolver()),
            "a geo-DB refresh must republish the resolver generation"
        );
        // `publish_dns` installs the process-global host resolver for an
        // enabled `dns:` section — clear it so sibling tests observe a
        // clean global.
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — the republish must reach a RUNNING standalone DNS
    /// server: `publish_dns` writes the rebuilt resolver into the
    /// handle's shared slot so the live `dns.listen` socket serves the
    /// new generation without a rebind.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_swaps_live_server_slot() {
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  listen: 127.0.0.1:0\n  nameserver:\n    - 127.0.0.1\nrules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let dir = tempfile::tempdir().unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();

        let stale = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let slot = meow_dns::new_resolver_slot(Arc::clone(&stale));
        // A live (never-finished) serve task keeps `publish_dns` on the
        // in-place slot-swap path rather than a rebind.
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(Some(crate::routes::DnsServerHandle {
                listen: "127.0.0.1:0".parse().unwrap(),
                task: tokio::spawn(std::future::pending::<()>()),
                resolver_slot: Arc::clone(&slot),
            })));

        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = crate::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            Some(dir.path()),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(
            !Arc::ptr_eq(&stale, &slot.read()),
            "the running server's slot must leave the stale generation"
        );
        assert!(
            Arc::ptr_eq(&slot.read(), &tunnel.resolver()),
            "server slot and tunnel must hold the same rebuilt resolver"
        );
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — the republished resolver must bind the NEW geosite DB,
    /// not merely be a fresh `Arc`. A `geosite:` nameserver-policy that
    /// missed under the old DB generation must start routing to its
    /// policy upstream once the DB containing the domain is in place.
    /// `rcode://` upstreams answer a fixed rcode with no I/O and record
    /// their label as the cache entry's `source`, which makes the tier
    /// that answered observable through `dns_results`.
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_binds_new_geosite_generation() {
        let dir = tempfile::tempdir().unwrap();
        let geosite_path = dir.path().join("geosite.mrs");
        // v1: the category exists but does not contain the probe domain —
        // the policy matcher is built yet never fires, the exact shape a
        // stale generation leaves behind.
        let v1 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["other.example".to_string()])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v1).unwrap(),
        )
        .unwrap();

        let raw: RawConfig = serde_yaml::from_str(&format!(
            "geodata:\n  geosite-path: '{}'\n\
             dns:\n  enable: true\n  nameserver:\n    - rcode://success\n  \
             nameserver-policy:\n    \"geosite:testcat\": rcode://name_error\n\
             rules:\n  - MATCH,DIRECT\n",
            geosite_path.display()
        ))
        .unwrap();

        // The "before" generation is bound to v1 via the same parse path.
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &HashMap::new(),
            Some(&HashMap::new()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        let before = tunnel.resolver();

        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        let source = results.first().and_then(|e| e.source.as_deref());
        assert_eq!(
            source,
            Some("rcode:NoError"),
            "v1 lacks the probe domain → the main upstream must answer"
        );

        // The refresh lands: v2 contains the probe domain.
        let v2 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v2).unwrap(),
        )
        .unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));
        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = crate::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            Some(dir.path()),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(!Arc::ptr_eq(&before, &tunnel.resolver()));
        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        let source = results.first().and_then(|e| e.source.as_deref());
        assert_eq!(
            source,
            Some("rcode:NXDomain"),
            "the republished resolver must bind the v2 geosite generation"
        );
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — a DNS parse failure warns and keeps the running
    /// resolver; the routing commit above is not rolled back
    /// (`rule-set:gone` has no declared provider → deterministic `Err`).
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_parse_failure_keeps_resolver() {
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - rcode://success\n  \
             nameserver-policy:\n    \"rule-set:gone\": rcode://success\n\
             rules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["127.0.0.1:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        let tunnel = Tunnel::new(resolver);
        let before = tunnel.resolver();
        let dir = tempfile::tempdir().unwrap();
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = crate::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            Some(dir.path()),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        assert!(
            Arc::ptr_eq(&before, &tunnel.resolver()),
            "a failed DNS rebuild must keep the running resolver"
        );
    }

    /// Issue #543 — `prior_resolver` carries the fake-IP pool across the
    /// republish so clients holding `host → fake-ip` answers keep valid
    /// reverse mappings (a `None` regression would silently strand them).
    #[tokio::test]
    async fn republish_dns_for_geo_dbs_preserves_fake_ip_pool() {
        let dir = tempfile::tempdir().unwrap();
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  \
             fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - rcode://success\n\
             rules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &HashMap::new(),
            Some(&HashMap::new()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        let before = tunnel.resolver();
        let net = before
            .fake_ip_v4_net()
            .expect("fake-ip mode gives a v4 net");
        let pool = before
            .fakeip_pool_over(net)
            .expect("fake-ip resolver holds a pool");

        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));
        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = crate::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            Some(dir.path()),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;

        let after = tunnel.resolver();
        assert!(
            Arc::ptr_eq(&pool, &after.fakeip_pool_over(net).unwrap()),
            "the republished resolver must reuse the prior fake-IP pool"
        );
        meow_common::clear_host_resolver();
    }

    /// `#name` upstreams must bind the LIVE route's proxies — a rules-only
    /// rebuild publishes into a transient `ProxyRegistry` that
    /// `update_rules` never installs, so adapters captured from
    /// `rebuild.proxies` would hold a dangling `Weak<RegistryCell>` once
    /// `rebuild` drops (issue #543 review).
    #[tokio::test]
    async fn republish_dns_binds_live_registry_cell_not_transient_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        // Both proxies are `type: direct` so the chained dial completes a
        // real loopback TCP connection when the front hop resolves.
        let raw: RawConfig = serde_yaml::from_str(
            "dns:\n  enable: true\n  nameserver:\n    - \"tcp://127.0.0.1:9#chained\"\n\
             proxies:\n  - {name: hop, type: direct}\n  \
             - {name: chained, type: direct, dialer-proxy: hop}\n\
             rules:\n  - MATCH,DIRECT\n",
        )
        .unwrap();

        // The committed generation: installed on the route table, which
        // retains its registry cell for the route's lifetime.
        let committed = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            None,
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &committed.proxies,
            Some(&committed.rule_providers),
            Some(&committed.prefetched_payloads),
            None,
            Some(&committed.dialer_registry),
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        tunnel.update_routing(
            committed.proxies,
            committed.rules,
            committed.dialer_registry,
        );

        // The geodata rebuild — its proxy map and dialer-registry cell are
        // transient: `update_rules` never installs them.
        let rebuild = meow_config::rebuild_from_raw_with_resolver(
            &raw,
            Some(&tunnel.resolver_slot()),
            Some(dir.path()),
            &HashMap::new(),
            None,
        )
        .unwrap();
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));
        // Production callers hold the lane; the debug_assert in
        // `publish_dns` enforces that contract here too.
        let _lane = crate::routes::CONFIG_MUTATION.lock().await;
        republish_dns_for_geo_dbs(
            &raw,
            Some(dir.path()),
            &rebuild.rule_providers,
            rebuild.rules,
            &tunnel,
            &dns_server,
            "test",
        )
        .await;
        // `rebuild.rules` moved into the republish; drop the remaining
        // transient halves (proxy map + dialer-registry cell) so a
        // dangling Weak would be caught below.
        drop(rebuild.proxies);
        drop(rebuild.dialer_registry);
        drop(rebuild.rule_providers);

        // A dial through the captured `#chained` upstream resolves `hop`
        // via the live route's retained cell. A dead cell would fail with
        // "registry generation dropped"; a live one reaches the listener.
        let resolver = tunnel.resolver();
        let proxy = resolver
            .main_nameservers()
            .iter()
            .find_map(|c| c.proxy().cloned())
            .expect("the #chained upstream must be proxied");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let meta = meow_common::Metadata {
            host: "127.0.0.1".into(),
            dst_port: port,
            ..Default::default()
        };
        proxy
            .dial_tcp(&meta)
            .await
            .expect("the republished resolver's #chained adapter must resolve its front hop");
        meow_common::clear_host_resolver();
    }

    /// Issue #543 — the periodic tick itself (not just the startup path)
    /// must republish the resolver: `auto_update_loop`'s per-tick body is
    /// `auto_update_tick`, exercised here directly so no ticker timing is
    /// involved. A stale geosite generation misses the probe domain
    /// before the tick and answers it afterwards.
    #[tokio::test]
    async fn auto_update_tick_republishes_resolver_with_new_geosite() {
        // Origin serving the v2 geosite containing the probe domain.
        let v2 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["hit.example".to_string()])],
        };
        let body = meow_rules::mrs_parser::write_geosite_mrs(&v2).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                use std::io::{Read, Write};
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while !stop.load(std::sync::atomic::Ordering::SeqCst)
                    && std::time::Instant::now() < deadline
                {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ =
                                stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                            let mut buf = [0_u8; 2048];
                            let _ = stream.read(&mut buf);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(&body);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let geosite_path = dir.path().join("geosite.mrs");
        // v1 on disk: the category exists but misses the probe domain.
        let v1 = meow_rules::mrs_parser::GeositePayload {
            categories: vec![("testcat".to_string(), vec!["other.example".to_string()])],
        };
        std::fs::write(
            &geosite_path,
            meow_rules::mrs_parser::write_geosite_mrs(&v1).unwrap(),
        )
        .unwrap();
        let asn_target = dir.path().join("asn.mmdb");

        let raw: RawConfig = serde_yaml::from_str(&format!(
            "geodata:\n  geosite-path: '{}'\n\
             dns:\n  enable: true\n  nameserver:\n    - rcode://success\n  \
             nameserver-policy:\n    \"geosite:testcat\": rcode://name_error\n\
             rules:\n  - MATCH,DIRECT\n",
            geosite_path.display()
        ))
        .unwrap();

        // Bind the "before" generation to v1 through the real parse path.
        let before_dns = meow_config::parse_dns_from_raw(
            &raw,
            Some(dir.path()),
            &HashMap::new(),
            Some(&HashMap::new()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let tunnel = Tunnel::new(Arc::clone(&before_dns.resolver));
        let before = tunnel.resolver();

        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        assert_eq!(
            results.first().and_then(|e| e.source.as_deref()),
            Some("rcode:NoError"),
            "v1 does not contain the probe domain — the main upstream must answer"
        );

        let geo = GeoDataConfig {
            geosite_url: format!("http://{addr}/geosite.mrs"),
            mmdb_url: "http://127.0.0.1:1/country.mmdb".into(),
            // Unreachable — tolerated: a partial update still commits.
            asn_url: "http://127.0.0.1:1/asn.mmdb".to_string(),
            ..GeoDataConfig::default()
        };
        let dns_server: Arc<RwLock<Option<crate::routes::DnsServerHandle>>> =
            Arc::new(RwLock::new(None));

        auto_update_tick(
            &geo,
            &tunnel,
            &RwLock::new(raw),
            Arc::new(RwLock::new(HashMap::new())),
            &dashmap::DashMap::new(),
            &dns_server,
            Some(dir.path()),
            &asn_target,
            &geosite_path,
        )
        .await;

        assert!(
            geosite_path.exists(),
            "the tick must have written the downloaded DB"
        );
        assert!(
            !Arc::ptr_eq(&before, &tunnel.resolver()),
            "the periodic tick must republish the resolver generation"
        );
        tunnel.resolver().lookup_ipv4("hit.example").await;
        let results = tunnel.resolver().dns_results(Some("hit.example"), 1);
        assert_eq!(
            results.first().and_then(|e| e.source.as_deref()),
            Some("rcode:NXDomain"),
            "after the tick the geosite policy must answer via its upstream"
        );
        meow_common::clear_host_resolver();
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

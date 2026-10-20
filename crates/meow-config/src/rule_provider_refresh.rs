//! Interval-refresh supervision for HTTP rule-providers.
//!
//! One background task per HTTP provider keeps calling
//! [`RuleProvider::refresh`]. [`RefreshSupervisor::reconcile`] is invoked on
//! every successful config commit — after the rebuilt provider map has been
//! swapped into the registry — so providers added, removed, or re-
//! `interval`ed by a reload gain/lose their task without a restart (issue
//! #543). Before this supervisor existed the tasks were spawned once at
//! startup, so reloads could only ever refresh startup-era providers.
//! Opted-in providers without usable cached data fetch immediately. Failures
//! retry with bounded exponential backoff; success returns to the configured
//! interval, or ends a one-shot (`interval: 0`) initial acquisition.

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::rule_provider::{ProviderType, RuleProvider};

/// Largest interval the supervisor will spawn a loop for (~10 years).
/// `RawRuleProvider.interval` is an unchecked `u64`: an absurd value
/// would overflow `Instant + Duration` inside `tokio::time::sleep`
/// and panic the task on every reconcile — an over-ceiling provider is
/// treated as non-refreshable instead (issue #543 review).
const MAX_REFRESH_INTERVAL_SECS: u64 = meow_common::MAX_DURATION_SECS;
/// Failed acquisitions retry promptly without hammering an offline source.
const INITIAL_RETRY_SECS: u64 = 5;
const MAX_RETRY_SECS: u64 = 600;

struct RefreshTask {
    interval: u64,
    background_fetch: bool,
    /// Only weak identity is retained between fetches. Rebinding an empty
    /// provider must not inherit the retired generation's daily countdown.
    provider: Weak<RuleProvider>,
    initially_missing: bool,
    task: JoinHandle<()>,
}

fn needs_initial_fetch(provider: &RuleProvider) -> bool {
    provider.background_fetch() && provider.updated_at_secs() == 0
}

/// Tracks the live refresh task per provider name. Cheap to share via
/// `Arc`; all mutation goes through [`reconcile`](Self::reconcile), which
/// diffs the wanted set against the running set — spawn what's missing,
/// abort what's gone or whose interval changed.
#[derive(Default)]
pub struct RefreshSupervisor {
    tasks: Mutex<HashMap<String, RefreshTask>>,
}

impl RefreshSupervisor {
    /// Diff the registry's refreshable providers against running tasks.
    ///
    /// Must be called from a tokio runtime context — it `tokio::spawn`s the
    /// per-provider loops — and under the same exclusion that serialised
    /// the registry swap (`CONFIG_MUTATION` in-tree): `wanted` is
    /// snapshotted before the task map lock, so a concurrent registry write
    /// could otherwise be missed until the next reconcile.
    ///
    /// Each spawned loop resolves its provider **by name** on every tick
    /// rather than pinning a `Arc<RuleProvider>`: commits swap the registry
    /// map, and a detached startup-era `Arc` would refresh content no live
    /// matcher sees (issue #514 review).
    ///
    /// Every call must pass the **same** registry `Arc` — spawned loops
    /// capture a weak reference to that allocation, so an embedder that
    /// replaces the whole `Arc<RwLock<…>>` (rather than the map inside it)
    /// strands its loops on a dead registry. In-tree the `Arc` is created
    /// once at startup and only its contents are swapped.
    ///
    /// Reaping runs only inside `reconcile`, i.e. on commits: a task that
    /// dies between commits stays dead until the next one (same semantics
    /// as the health-check supervisor).
    ///
    /// Callers must not hold the registry's write guard — `reconcile`
    /// takes `registry.read()` and `parking_lot` locks are not reentrant.
    /// Commits that swap the map should prefer
    /// [`commit_registry`](Self::commit_registry), which performs the swap
    /// and this call in the only safe order.
    pub fn reconcile(&self, registry: &Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>) {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_ok(),
            "RefreshSupervisor::reconcile must run inside a tokio runtime"
        );
        let wanted: HashMap<String, Arc<RuleProvider>> = registry
            .read()
            .iter()
            .filter(|(_, p)| {
                if p.interval > MAX_REFRESH_INTERVAL_SECS {
                    warn!(
                        provider = %p.name,
                        interval = p.interval,
                        "rule-provider interval exceeds the maximum; not auto-refreshing"
                    );
                    return false;
                }
                p.provider_type == ProviderType::Http && (p.interval > 0 || needs_initial_fetch(p))
            })
            .map(|(name, p)| (name.clone(), Arc::clone(p)))
            .collect();

        let mut tasks = self.tasks.lock();
        tasks.retain(|name, job| {
            let keep = wanted.get(name).is_some_and(|provider| {
                let rebound = !job.provider.ptr_eq(&Arc::downgrade(provider));
                provider.interval == job.interval
                    && provider.background_fetch() == job.background_fetch
                    && !job.task.is_finished()
                    && !(rebound && (needs_initial_fetch(provider) || job.initially_missing))
            });
            if !keep {
                job.task.abort();
            } else if let Some(provider) = wanted.get(name) {
                job.provider = Arc::downgrade(provider);
                job.initially_missing = needs_initial_fetch(provider);
            }
            keep
        });
        for (name, provider) in wanted {
            if tasks.contains_key(&name) {
                continue;
            }
            let task = tokio::spawn(refresh_loop(
                name.clone(),
                provider.interval,
                Arc::downgrade(registry),
            ));
            tasks.insert(
                name,
                RefreshTask {
                    interval: provider.interval,
                    background_fetch: provider.background_fetch(),
                    provider: Arc::downgrade(&provider),
                    initially_missing: needs_initial_fetch(&provider),
                    task,
                },
            );
        }
    }

    /// Install a rebuilt provider map and reconcile refresh tasks — the
    /// two steps every registry-mutating commit performs, in the only
    /// safe order (publish first, then supervise). Call under the same
    /// exclusion that serialised the rebuild (`CONFIG_MUTATION` in-tree).
    pub fn commit_registry(
        &self,
        registry: &Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        map: HashMap<String, Arc<RuleProvider>>,
    ) {
        *registry.write() = map;
        self.reconcile(registry);
    }

    /// Number of running refresh tasks (test introspection).
    #[cfg(test)]
    fn task_count(&self) -> usize {
        self.tasks.lock().len()
    }

    /// Interval a running task was spawned with (test introspection).
    #[cfg(test)]
    fn task_interval(&self, name: &str) -> Option<u64> {
        self.tasks.lock().get(name).map(|job| job.interval)
    }

    /// Identity of a running task's `JoinHandle` (test introspection) —
    /// distinguishes a respawned task from a kept one.
    #[cfg(test)]
    fn task_id(&self, name: &str) -> Option<tokio::task::Id> {
        self.tasks.lock().get(name).map(|job| job.task.id())
    }

    /// Insert an already-finished task — exercises the reap-and-respawn
    /// branch without racing a real panic. The spawned future is awaited
    /// to completion first, so `is_finished()` is genuinely true on a
    /// current-thread runtime (a bare `tokio::spawn` is never polled).
    #[cfg(test)]
    async fn insert_dead_task(&self, name: &str, interval: u64) {
        let mut task = tokio::spawn(async {});
        (&mut task).await.unwrap();
        debug_assert!(task.is_finished());
        self.tasks.lock().insert(
            name.to_string(),
            RefreshTask {
                interval,
                background_fetch: false,
                provider: Weak::new(),
                initially_missing: false,
                task,
            },
        );
    }
}

impl Drop for RefreshSupervisor {
    /// Abort every supervised task — otherwise the `JoinHandle`s detach on
    /// drop and, while the registry is still alive, the loops keep
    /// refreshing providers nobody supervises.
    fn drop(&mut self) {
        for (_, job) in self.tasks.get_mut().drain() {
            job.task.abort();
        }
    }
}

async fn refresh_loop(
    name: String,
    interval_secs: u64,
    registry: Weak<RwLock<HashMap<String, Arc<RuleProvider>>>>,
) {
    let Some(provider) = current_provider(&registry, &name) else {
        return;
    };
    let mut binding = Arc::downgrade(&provider);
    let mut delay = if needs_initial_fetch(&provider) {
        0
    } else {
        interval_secs
    };
    // An interval-zero legacy provider is never a supervised acquisition.
    if delay == 0 && !needs_initial_fetch(&provider) {
        return;
    }
    drop(provider);
    let mut retry = INITIAL_RETRY_SECS;
    let mut recovering = false;
    loop {
        // Nothing strong crosses this sleep: old provider generations and
        // the registry may be collected even with a 24-hour interval.
        tokio::time::sleep(Duration::from_secs(delay)).await;
        let Some(provider) = current_provider(&registry, &name) else {
            return;
        };
        if !binding.ptr_eq(&Arc::downgrade(&provider)) {
            binding = Arc::downgrade(&provider);
            retry = INITIAL_RETRY_SECS;
            // A valid replacement must not inherit an old failure's short
            // retry schedule. Normal interval ticks still follow swaps.
            if recovering && !needs_initial_fetch(&provider) {
                recovering = false;
                if interval_secs == 0 {
                    return;
                }
                delay = interval_secs;
                drop(provider);
                continue;
            }
        }
        if interval_secs == 0 && !needs_initial_fetch(&provider) {
            return;
        }
        // The provider re-parses the payload in its own load-time
        // ParserContext and declared format, so geo-dependent entries
        // survive refreshes (issue #533 review).
        match provider.refresh().await {
            Ok(()) => {
                if interval_secs == 0 {
                    return;
                }
                delay = interval_secs;
                retry = INITIAL_RETRY_SECS;
                recovering = false;
            }
            Err(e) => {
                delay = retry.min(MAX_RETRY_SECS);
                if interval_secs > 0 {
                    delay = delay.min(interval_secs);
                }
                retry = retry.saturating_mul(2).min(MAX_RETRY_SECS);
                recovering = true;
                error!(provider = %provider.name, retry_secs = delay, "background refresh failed: {:#}", e);
            }
        }
    }
}

fn current_provider(
    registry: &Weak<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    name: &str,
) -> Option<Arc<RuleProvider>> {
    let registry = registry.upgrade()?;
    let provider = registry.read().get(name).cloned();
    if provider.is_none() {
        debug!(provider = %name, "rule-provider gone; refresh task exiting");
    }
    provider
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_provider::test_provider;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct AbortOnDrop(tokio::task::AbortHandle);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Keep a paused clock from auto-advancing while real local HTTP and
    /// blocking parse workers are making progress; tests advance it explicitly.
    fn hold_clock() -> AbortOnDrop {
        let task = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        AbortOnDrop(task.abort_handle())
    }

    struct HttpSource {
        url: String,
        requests: Arc<AtomicUsize>,
        status: Arc<AtomicUsize>,
        body: Arc<Mutex<&'static str>>,
        blocked: Arc<AtomicUsize>,
        _task: AbortOnDrop,
    }

    async fn http_source() -> HttpSource {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/rules", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let status = Arc::new(AtomicUsize::new(200));
        let body = Arc::new(Mutex::new("payload:\n  - 'live.example'\n"));
        let blocked = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let requests = Arc::clone(&requests);
            let status = Arc::clone(&status);
            let body = Arc::clone(&body);
            let blocked = Arc::clone(&blocked);
            async move {
                let mut children = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut socket, _) = accepted.unwrap();
                            let requests = Arc::clone(&requests);
                            let status = Arc::clone(&status);
                            let body = Arc::clone(&body);
                            let blocked = Arc::clone(&blocked);
                            children.spawn(async move {
                                let mut request = Vec::new();
                                let mut buf = [0; 1024];
                                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                                    let n = socket.read(&mut buf).await.unwrap();
                                    if n == 0 { return; }
                                    request.extend_from_slice(&buf[..n]);
                                }
                                requests.fetch_add(1, Ordering::SeqCst);
                                if blocked.load(Ordering::SeqCst) != 0 {
                                    // Wait for cancellation to drop the HTTP
                                    // socket, so teardown is observable too.
                                    while socket.read(&mut buf).await.is_ok_and(|n| n > 0) {}
                                    return;
                                }
                                let status = status.load(Ordering::SeqCst);
                                let body = *body.lock();
                                let response = format!("HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                                let _ = socket.write_all(response.as_bytes()).await;
                            });
                        }
                        Some(done) = children.join_next(), if !children.is_empty() => done.unwrap(),
                    }
                }
            }
        });
        HttpSource {
            url,
            requests,
            status,
            body,
            blocked,
            _task: AbortOnDrop(task.abort_handle()),
        }
    }

    fn background_provider(
        source: &HttpSource,
        dir: &std::path::Path,
        interval: u64,
        behavior: &str,
        cache: Option<&str>,
    ) -> Arc<RuleProvider> {
        if let Some(cache) = cache {
            std::fs::write(dir.join("rules.yaml"), cache).unwrap();
        }
        let raw = crate::raw::RawRuleProvider {
            provider_type: "http".into(),
            behavior: behavior.into(),
            format: Some("yaml".into()),
            url: Some(source.url.clone()),
            path: Some("rules.yaml".into()),
            interval: Some(interval),
            background_fetch: true,
            sources: vec![],
            mirrors: vec![],
            proxy: None,
            header: None,
            payload: None,
        };
        crate::rule_provider::load_providers(
            &HashMap::from([("p".into(), raw)]),
            Some(dir),
            &meow_rules::ParserContext::empty(),
            None,
            true,
        )
        .unwrap()
        .remove("p")
        .unwrap()
    }

    async fn wait_until(mut ready: impl FnMut() -> bool) {
        let end = std::time::Instant::now() + Duration::from_secs(5);
        while !ready() {
            assert!(
                std::time::Instant::now() < end,
                "background HTTP work did not settle"
            );
            tokio::task::yield_now().await;
        }
        // Let the refresh loop leave refresh() and arm its next sleep.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    async fn advance(seconds: u64) {
        tokio::time::advance(Duration::from_secs(seconds)).await;
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn missing_background_providers_start_without_http_and_fetch_immediately() {
        let _clock = hold_clock();
        for behavior in ["domain", "ipcidr"] {
            let source = http_source().await;
            if behavior == "ipcidr" {
                *source.body.lock() = "payload:\n  - '198.51.100.0/24'\n";
            }
            let dir = tempfile::tempdir().unwrap();
            let provider = background_provider(&source, dir.path(), 86400, behavior, None);
            assert!(provider.background_fetch());
            assert_eq!(provider.updated_at_secs(), 0);
            assert_eq!(source.requests.load(Ordering::SeqCst), 0);
            let live = crate::rule_provider::live_ruleset_map(&HashMap::from([(
                "p".into(),
                Arc::clone(&provider),
            )]));
            assert_eq!(live["p"].len(), 0);
            let reg = Arc::new(RwLock::new(HashMap::from([(
                "p".into(),
                Arc::clone(&provider),
            )])));
            let sup = RefreshSupervisor::default();
            sup.reconcile(&reg);
            wait_until(|| provider.updated_at_secs() > 0 && Arc::strong_count(&provider) == 3)
                .await;
            assert_eq!(
                live["p"].len(),
                1,
                "native matcher must see the installed data without Flutter"
            );
            assert_eq!(source.requests.load(Ordering::SeqCst), 1);
            advance(86399).await;
            assert_eq!(source.requests.load(Ordering::SeqCst), 1);
            advance(1).await;
            wait_until(|| {
                source.requests.load(Ordering::SeqCst) == 2 && Arc::strong_count(&provider) == 3
            })
            .await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_initial_fetch_retries_exponentially_then_resumes_normal_interval() {
        let _clock = hold_clock();
        let source = http_source().await;
        source.status.store(503, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let provider = background_provider(&source, dir.path(), 86400, "domain", None);
        let reg = Arc::new(RwLock::new(HashMap::from([(
            "p".into(),
            Arc::clone(&provider),
        )])));
        let sup = RefreshSupervisor::default();
        sup.reconcile(&reg);
        wait_until(|| {
            provider
                .last_error()
                .is_some_and(|e| e.contains("refresh failed"))
                && Arc::strong_count(&provider) == 2
        })
        .await;
        assert_eq!(source.requests.load(Ordering::SeqCst), 1);
        for (i, delay) in [5, 10, 20, 40, 80, 160, 320, 600, 600]
            .into_iter()
            .enumerate()
        {
            advance(delay - 1).await;
            assert_eq!(source.requests.load(Ordering::SeqCst), i + 1);
            advance(1).await;
            wait_until(|| {
                source.requests.load(Ordering::SeqCst) == i + 2 && Arc::strong_count(&provider) == 2
            })
            .await;
        }
        source.status.store(200, Ordering::SeqCst);
        advance(600).await;
        wait_until(|| provider.updated_at_secs() > 0 && Arc::strong_count(&provider) == 2).await;
        let successful = source.requests.load(Ordering::SeqCst);
        assert!(provider.last_error().is_none());
        advance(86399).await;
        assert_eq!(source.requests.load(Ordering::SeqCst), successful);
        advance(1).await;
        wait_until(|| {
            source.requests.load(Ordering::SeqCst) == successful + 1
                && Arc::strong_count(&provider) == 2
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn retry_delay_never_exceeds_a_short_configured_interval() {
        let _clock = hold_clock();
        let source = http_source().await;
        source.status.store(503, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let provider = background_provider(&source, dir.path(), 3, "domain", None);
        let reg = Arc::new(RwLock::new(HashMap::from([(
            "p".into(),
            Arc::clone(&provider),
        )])));
        let sup = RefreshSupervisor::default();
        sup.reconcile(&reg);
        wait_until(|| {
            provider
                .last_error()
                .is_some_and(|e| e.contains("refresh failed"))
                && Arc::strong_count(&provider) == 2
        })
        .await;
        for count in 1..4 {
            advance(2).await;
            assert_eq!(source.requests.load(Ordering::SeqCst), count);
            advance(1).await;
            wait_until(|| {
                source.requests.load(Ordering::SeqCst) == count + 1
                    && Arc::strong_count(&provider) == 2
            })
            .await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn interval_zero_fetches_until_success_then_exits_and_legacy_stays_disabled() {
        let _clock = hold_clock();
        let source = http_source().await;
        source.status.store(503, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let provider = background_provider(&source, dir.path(), 0, "domain", None);
        let reg = Arc::new(RwLock::new(HashMap::from([
            ("p".into(), Arc::clone(&provider)),
            (
                "legacy".into(),
                test_provider("legacy", ProviderType::Http, 0),
            ),
        ])));
        let sup = RefreshSupervisor::default();
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 1);
        wait_until(|| {
            provider
                .last_error()
                .is_some_and(|e| e.contains("refresh failed"))
                && Arc::strong_count(&provider) == 2
        })
        .await;
        source.status.store(200, Ordering::SeqCst);
        advance(5).await;
        wait_until(|| provider.updated_at_secs() > 0 && sup.tasks.lock()["p"].task.is_finished())
            .await;
        assert_eq!(source.requests.load(Ordering::SeqCst), 2);
        advance(86400).await;
        assert_eq!(source.requests.load(Ordering::SeqCst), 2);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn valid_cache_waits_for_interval_and_zero_cache_spawns_no_job() {
        let _clock = hold_clock();
        for interval in [0, 60] {
            let source = http_source().await;
            let dir = tempfile::tempdir().unwrap();
            let provider = background_provider(
                &source,
                dir.path(),
                interval,
                "domain",
                Some("payload:\n  - 'cached.example'\n"),
            );
            assert!(provider.updated_at_secs() > 0);
            assert_eq!(provider.rule_count(), 1);
            let reg = Arc::new(RwLock::new(HashMap::from([("p".into(), provider)])));
            let sup = RefreshSupervisor::default();
            sup.reconcile(&reg);
            assert_eq!(sup.task_count(), usize::from(interval != 0));
            advance(0).await;
            advance(59).await;
            assert_eq!(source.requests.load(Ordering::SeqCst), 0);
            advance(1).await;
            if interval != 0 {
                wait_until(|| source.requests.load(Ordering::SeqCst) == 1).await;
            } else {
                assert_eq!(source.requests.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn sleeping_tasks_hold_neither_provider_nor_registry_alive() {
        let _clock = hold_clock();
        for empty in [false, true] {
            let source = http_source().await;
            source.status.store(503, Ordering::SeqCst);
            let dir = tempfile::tempdir().unwrap();
            let cache = (!empty).then_some("payload:\n  - 'cached.example'\n");
            let provider = background_provider(&source, dir.path(), 86400, "domain", cache);
            let weak_provider = Arc::downgrade(&provider);
            let reg = Arc::new(RwLock::new(HashMap::from([(
                "p".into(),
                Arc::clone(&provider),
            )])));
            let weak_registry = Arc::downgrade(&reg);
            let sup = RefreshSupervisor::default();
            sup.reconcile(&reg);
            if empty {
                wait_until(|| {
                    provider
                        .last_error()
                        .is_some_and(|e| e.contains("refresh failed"))
                        && Arc::strong_count(&provider) == 2
                })
                .await;
            } else {
                advance(0).await;
            }
            reg.write().clear();
            drop(provider);
            wait_until(|| weak_provider.upgrade().is_none()).await;
            drop(reg);
            assert!(weak_registry.upgrade().is_none());
            advance(86400).await;
            wait_until(|| sup.tasks.lock()["p"].task.is_finished()).await;
            assert_eq!(source.requests.load(Ordering::SeqCst), usize::from(empty));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rebind_empty_provider_cancels_old_fetch_and_starts_new_generation_immediately() {
        let _clock = hold_clock();
        let old_source = http_source().await;
        old_source.blocked.store(1, Ordering::SeqCst);
        let old_dir = tempfile::tempdir().unwrap();
        let old = background_provider(&old_source, old_dir.path(), 86400, "domain", None);
        let old_weak = Arc::downgrade(&old);
        let reg = Arc::new(RwLock::new(HashMap::from([("p".into(), old)])));
        let sup = RefreshSupervisor::default();
        sup.reconcile(&reg);
        let old_task = sup.task_id("p");
        wait_until(|| old_source.requests.load(Ordering::SeqCst) == 1).await;
        let new_source = http_source().await;
        let new_dir = tempfile::tempdir().unwrap();
        let new = background_provider(&new_source, new_dir.path(), 86400, "domain", None);
        sup.commit_registry(&reg, HashMap::from([("p".into(), Arc::clone(&new))]));
        assert_ne!(sup.task_id("p"), old_task);
        wait_until(|| {
            new.updated_at_secs() > 0
                && Arc::strong_count(&new) == 2
                && old_weak.upgrade().is_none()
        })
        .await;
        assert_eq!(new_source.requests.load(Ordering::SeqCst), 1);
        advance(86400).await;
        wait_until(|| {
            new_source.requests.load(Ordering::SeqCst) == 2 && Arc::strong_count(&new) == 2
        })
        .await;
        assert_eq!(old_source.requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn valid_replacement_does_not_inherit_the_retired_providers_retry() {
        let _clock = hold_clock();
        let old_source = http_source().await;
        old_source.status.store(503, Ordering::SeqCst);
        let old_dir = tempfile::tempdir().unwrap();
        let old = background_provider(&old_source, old_dir.path(), 86400, "domain", None);
        let reg = Arc::new(RwLock::new(HashMap::from([("p".into(), Arc::clone(&old))])));
        let sup = RefreshSupervisor::default();
        sup.reconcile(&reg);
        wait_until(|| {
            old.last_error()
                .is_some_and(|e| e.contains("refresh failed"))
                && Arc::strong_count(&old) == 2
        })
        .await;
        let new_source = http_source().await;
        let new_dir = tempfile::tempdir().unwrap();
        let new = background_provider(
            &new_source,
            new_dir.path(),
            86400,
            "domain",
            Some("payload:\n  - 'cached.example'\n"),
        );
        sup.commit_registry(&reg, HashMap::from([("p".into(), Arc::clone(&new))]));
        advance(0).await;
        advance(86399).await;
        assert_eq!(new_source.requests.load(Ordering::SeqCst), 0);
        assert_eq!(old_source.requests.load(Ordering::SeqCst), 1);
        advance(1).await;
        wait_until(|| {
            new_source.requests.load(Ordering::SeqCst) == 1 && Arc::strong_count(&new) == 2
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_supervisor_or_removing_provider_cancels_pending_fetch() {
        let _clock = hold_clock();
        for remove in [false, true] {
            let source = http_source().await;
            source.blocked.store(1, Ordering::SeqCst);
            let dir = tempfile::tempdir().unwrap();
            let provider = background_provider(&source, dir.path(), 86400, "domain", None);
            let reg = Arc::new(RwLock::new(HashMap::from([(
                "p".into(),
                Arc::clone(&provider),
            )])));
            let sup = RefreshSupervisor::default();
            sup.reconcile(&reg);
            wait_until(|| source.requests.load(Ordering::SeqCst) == 1).await;
            if remove {
                sup.commit_registry(&reg, HashMap::new());
                assert_eq!(sup.task_count(), 0);
                wait_until(|| Arc::strong_count(&provider) == 1).await;
            } else {
                drop(sup);
                wait_until(|| Arc::strong_count(&provider) == 2).await;
            }
            advance(86400).await;
            assert_eq!(provider.updated_at_secs(), 0);
            assert_eq!(source.requests.load(Ordering::SeqCst), 1);
        }
    }

    fn registry_map(entries: &[(&str, ProviderType, u64)]) -> HashMap<String, Arc<RuleProvider>> {
        entries
            .iter()
            .map(|(name, ty, iv)| (name.to_string(), test_provider(name, *ty, *iv)))
            .collect()
    }

    fn registry(
        entries: &[(&str, ProviderType, u64)],
    ) -> Arc<RwLock<HashMap<String, Arc<RuleProvider>>>> {
        Arc::new(RwLock::new(registry_map(entries)))
    }

    #[tokio::test]
    async fn reconcile_spawns_per_refreshable_provider() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[
            ("http-a", ProviderType::Http, 3600),
            ("http-b", ProviderType::Http, 60),
            ("no-interval", ProviderType::Http, 0),
            ("file", ProviderType::File, 3600),
            ("inline", ProviderType::Inline, 3600),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 2, "only http providers with interval > 0");
        assert_eq!(sup.task_interval("http-a"), Some(3600));
        assert_eq!(sup.task_interval("http-b"), Some(60));
        assert_eq!(sup.task_interval("file"), None);
        assert_eq!(sup.task_interval("inline"), None);
        assert_eq!(sup.task_interval("no-interval"), None);
    }

    #[tokio::test]
    async fn reconcile_aborts_removed_and_respawns_changed_interval() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[
            ("a", ProviderType::Http, 3600),
            ("b", ProviderType::Http, 60),
            ("c", ProviderType::Http, 300),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 3);
        let kept_id = sup.task_id("c").unwrap();
        let old_a = sup.task_id("a").unwrap();

        // "b" removed, "a" interval changed → both tasks re-dispatched.
        *reg.write() = registry_map(&[
            ("a", ProviderType::Http, 120),
            ("c", ProviderType::Http, 300),
        ]);
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 2);
        assert_eq!(
            sup.task_interval("a"),
            Some(120),
            "the interval change must respawn the task with the new tick"
        );
        assert_ne!(
            sup.task_id("a"),
            Some(old_a),
            "the interval change must spawn a *new* task, not rewrite the old one"
        );
        assert_eq!(
            sup.task_id("c"),
            Some(kept_id),
            "an unchanged provider must keep its task — churn would restart \
             the interval countdown on every commit"
        );
    }

    #[tokio::test]
    async fn reconcile_reaps_and_respawns_dead_tasks() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[("a", ProviderType::Http, 3600)]);
        sup.insert_dead_task("a", 3600).await;
        let dead_id = sup.task_id("a").unwrap();
        // The dead task matches the wanted interval but is finished — the
        // supervisor must reap it and spawn a live replacement.
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 1);
        assert_eq!(sup.task_interval("a"), Some(3600));
        assert_ne!(
            sup.task_id("a"),
            Some(dead_id),
            "the finished task must be replaced, not kept"
        );
    }

    #[tokio::test]
    async fn reconcile_empty_registry_aborts_all() {
        let sup = RefreshSupervisor::default();
        let reg = registry(&[("a", ProviderType::Http, 3600)]);
        sup.reconcile(&reg);
        *reg.write() = HashMap::new();
        sup.reconcile(&reg);
        assert_eq!(sup.task_count(), 0);
    }

    /// The loop itself: ticks resolve the provider *by name* so a registry
    /// swap is followed without a respawn, and `abort()` actually stops
    /// further refreshes. Driven with real temp files through a `File`
    /// provider (the loop does not check `provider_type` — only
    /// `reconcile`'s wanted set does).
    #[tokio::test]
    async fn refresh_loop_follows_swaps_and_stops_on_abort() {
        use crate::rule_provider::test_provider_with_vehicle;

        let dir = tempfile::tempdir().unwrap();
        let path1 = dir.path().join("one.yaml");
        let path2 = dir.path().join("two.yaml");
        std::fs::write(&path1, "payload:\n  - 'a.example'\n").unwrap();
        std::fs::write(&path2, "payload:\n  - 'b.example'\n  - 'c.example'\n").unwrap();

        let p1 =
            test_provider_with_vehicle("p", ProviderType::File, 0, path1.display().to_string());
        let reg = registry(&[]);
        *reg.write() = HashMap::from([("p".to_string(), p1)]);

        let mut task = tokio::spawn(refresh_loop("p".to_string(), 1, Arc::downgrade(&reg)));
        // First real tick lands one interval after spawn.
        wait_rule_count(&reg, "p", 1).await;

        // Swap a new provider object in under the same name — the running
        // task must refresh *it*, not the retired generation.
        let p2 =
            test_provider_with_vehicle("p", ProviderType::File, 0, path2.display().to_string());
        let p1 = Arc::clone(&reg.read()["p"]);
        *reg.write() = HashMap::from([("p".to_string(), Arc::clone(&p2))]);
        for _ in 0..40 {
            if p2.rule_count() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(p2.rule_count(), 2, "name resolution must follow the swap");
        assert_eq!(
            p1.rule_count(),
            1,
            "the retired provider must not be refreshed again"
        );

        // Abort: no further refresh even though the payload file changed.
        std::fs::write(
            &path2,
            "payload:\n  - 'b.example'\n  - 'c.example'\n  - 'd.example'\n",
        )
        .unwrap();
        task.abort();
        assert!(
            (&mut task).await.unwrap_err().is_cancelled(),
            "the aborted task must actually terminate"
        );
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(p2.rule_count(), 2);
    }

    async fn wait_rule_count(
        reg: &RwLock<HashMap<String, Arc<RuleProvider>>>,
        name: &str,
        want: usize,
    ) {
        for _ in 0..40 {
            if reg.read()[name].rule_count() == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            reg.read()[name].rule_count(),
            want,
            "the tick must have refreshed the file provider"
        );
    }
}

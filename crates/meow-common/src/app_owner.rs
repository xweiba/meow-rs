//! Android: which app owns a connection that came in through the VPN.
//!
//! Android gives a VPN app no socket tables to scan (`/proc/net` is closed
//! to apps since Android 10). The one way is
//! `ConnectivityManager.getConnectionOwnerUid` (Android 10+, only for the
//! active VPN app), which needs the protocol and **both** ends of the
//! connection, then `PackageManager.getPackagesForUid` for the package
//! name. The host app answers both through an [`AppOwnerLookup`] it
//! installs (meow-mobile: JNI into the VPN service).
//!
//! Rules see the connection only after the fake-IP rewrite cleared or
//! changed its destination, so the TUN listener notes each new flow's
//! original destination here first ([`note_flow`]); [`find`] then asks
//! the host with it — only when a rule needs the app (lazily, like the
//! desktop scans). The flow's entry also keeps the answer for
//! [`FLOW_TTL`]; a new flow from the same source address replaces it.
//! UID → package answers are kept for [`PACKAGE_TTL`].
//!
//! The package name becomes `ProcessInfo::name` (so `PROCESS-NAME,<pkg>`
//! rules match); the path stays empty.

use crate::network::Network;
use crate::process_lookup::ProcessInfo;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What the host app answers. Called from the core's blocking-pool
/// threads (never a Tokio worker); may block for a system call.
pub trait AppOwnerLookup: Send + Sync {
    /// The UID owning the socket `local` → `remote` (`network` = TCP or
    /// UDP); `None` when unknown (old Android, no such socket, refused).
    fn owner_uid(&self, network: Network, local: SocketAddr, remote: SocketAddr) -> Option<u32>;

    /// The package of `uid` (one stable pick when several share it);
    /// `None` when there is none the app may see.
    fn package_of(&self, uid: u32) -> Option<String>;
}

/// How long a flow's noted destination and owner are kept. Rules run
/// within moments of the flow's start (after the sniff window and maybe a
/// DNS lookup); a new flow from the same source replaces the entry anyway.
pub const FLOW_TTL: Duration = Duration::from_secs(30);
/// How long a UID → package answer is kept (UIDs change only when an app
/// is reinstalled).
pub const PACKAGE_TTL: Duration = Duration::from_secs(600);
/// Past this many flows, expired ones are dropped; still past it, all.
const FLOW_CAP: usize = 4096;
const PACKAGE_CAP: usize = 1024;

struct Flow {
    at: Instant,
    remote: SocketAddr,
    /// `None` = not asked yet; `Some(None)` = asked, no owner.
    owner: Option<Option<u32>>,
}

/// uid → (answered at, package; `None` = no package the app may see).
type PackageCache = HashMap<u32, (Instant, Option<Arc<str>>)>;

/// The flow and package caches in front of one [`AppOwnerLookup`].
pub struct AppOwners {
    lookup: Arc<dyn AppOwnerLookup>,
    flows: Mutex<HashMap<(Network, SocketAddr), Flow>>,
    packages: Mutex<PackageCache>,
}

impl AppOwners {
    pub fn new(lookup: Arc<dyn AppOwnerLookup>) -> Self {
        Self {
            lookup,
            flows: Mutex::new(HashMap::new()),
            packages: Mutex::new(HashMap::new()),
        }
    }

    /// A new flow `local` → `remote` (its original destination, before
    /// any fake-IP rewrite); forgets an earlier flow's answer.
    pub fn note_flow(&self, network: Network, local: SocketAddr, remote: SocketAddr) {
        self.note_flow_at(network, local, remote, Instant::now());
    }

    fn note_flow_at(&self, network: Network, local: SocketAddr, remote: SocketAddr, now: Instant) {
        let mut flows = self.flows.lock();
        if flows.len() >= FLOW_CAP {
            flows.retain(|_, f| now.duration_since(f.at) < FLOW_TTL);
            if flows.len() >= FLOW_CAP {
                flows.clear();
            }
        }
        flows.insert(
            (network, local),
            Flow {
                at: now,
                remote,
                owner: None,
            },
        );
    }

    /// The app owning the noted flow from `local`; `None` for a flow
    /// never noted (or long gone) or with no known owner.
    pub fn find(&self, network: Network, local: SocketAddr) -> Option<ProcessInfo> {
        self.find_at(network, local, Instant::now())
    }

    fn find_at(&self, network: Network, local: SocketAddr, now: Instant) -> Option<ProcessInfo> {
        let key = (network, local);
        let remote = {
            let flows = self.flows.lock();
            let flow = flows.get(&key)?;
            if now.duration_since(flow.at) >= FLOW_TTL {
                return None;
            }
            match flow.owner {
                Some(owner) => return owner.map(|uid| self.info(uid, now)),
                None => flow.remote,
            }
        };
        // The host call (a system call) runs without the lock held.
        let owner = self.lookup.owner_uid(network, local, remote);
        if let Some(flow) = self.flows.lock().get_mut(&key) {
            // Unless a new flow took the address meanwhile.
            if flow.remote == remote && flow.owner.is_none() {
                flow.owner = Some(owner);
            }
        }
        owner.map(|uid| self.info(uid, now))
    }

    /// `uid` with its package (cached) as the process name.
    fn info(&self, uid: u32, now: Instant) -> ProcessInfo {
        let cached = self
            .packages
            .lock()
            .get(&uid)
            .filter(|(at, _)| now.duration_since(*at) < PACKAGE_TTL)
            .map(|(_, p)| p.clone());
        let package = match cached {
            Some(p) => p,
            None => {
                let p: Option<Arc<str>> = self.lookup.package_of(uid).map(Into::into);
                let mut packages = self.packages.lock();
                if packages.len() >= PACKAGE_CAP {
                    packages.clear();
                }
                packages.insert(uid, (now, p.clone()));
                p
            }
        };
        ProcessInfo {
            name: package.map(|p| p.to_string()).unwrap_or_default(),
            path: String::new(),
            uid: Some(uid),
        }
    }
}

static OWNERS: RwLock<Option<Arc<AppOwners>>> = RwLock::new(None);

/// Installs the host's lookup (meow-mobile at core start); replaces an
/// earlier one and its caches.
pub fn set_app_owner_lookup(lookup: Arc<dyn AppOwnerLookup>) {
    *OWNERS.write() = Some(Arc::new(AppOwners::new(lookup)));
}

/// Removes it (core stop): lookups answer `None` again.
pub fn clear_app_owner_lookup() {
    *OWNERS.write() = None;
}

fn owners() -> Option<Arc<AppOwners>> {
    OWNERS.read().clone()
}

/// [`AppOwners::note_flow`] on the installed lookup; nothing without one.
pub fn note_flow(network: Network, local: SocketAddr, remote: SocketAddr) {
    if let Some(o) = owners() {
        o.note_flow(network, local, remote);
    }
}

/// [`AppOwners::find`] on the installed lookup; `None` without one.
pub fn find(network: Network, local: SocketAddr) -> Option<ProcessInfo> {
    owners()?.find(network, local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers uid 10086 for remote port 443, none otherwise; packages
    /// from a fixed table. Counts the calls.
    #[derive(Default)]
    struct Fake {
        uid_calls: AtomicUsize,
        package_calls: AtomicUsize,
        seen_remote: Mutex<Option<SocketAddr>>,
    }

    impl AppOwnerLookup for Fake {
        fn owner_uid(&self, _: Network, _: SocketAddr, remote: SocketAddr) -> Option<u32> {
            self.uid_calls.fetch_add(1, Ordering::Relaxed);
            *self.seen_remote.lock() = Some(remote);
            (remote.port() == 443).then_some(10086)
        }

        fn package_of(&self, uid: u32) -> Option<String> {
            self.package_calls.fetch_add(1, Ordering::Relaxed);
            (uid == 10086).then(|| "com.tencent.mm".to_string())
        }
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn owners() -> (Arc<Fake>, AppOwners) {
        let fake = Arc::new(Fake::default());
        (Arc::clone(&fake), AppOwners::new(fake))
    }

    #[test]
    fn asks_with_the_noted_destination_and_caches() {
        let (fake, o) = owners();
        let t = Instant::now();
        let local = addr("172.19.0.1:40000");
        // The fake IP the app's socket connected to.
        o.note_flow_at(Network::Tcp, local, addr("198.18.0.7:443"), t);
        let info = o.find_at(Network::Tcp, local, t).unwrap();
        assert_eq!(info.name, "com.tencent.mm");
        assert_eq!(info.path, "");
        assert_eq!(info.uid, Some(10086));
        assert_eq!(*fake.seen_remote.lock(), Some(addr("198.18.0.7:443")));
        // Cached: no second host call for the flow or the package.
        let again = o.find_at(Network::Tcp, local, t + Duration::from_secs(1));
        assert_eq!(again.unwrap().name, "com.tencent.mm");
        assert_eq!(fake.uid_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fake.package_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn unnoted_or_expired_flows_are_not_asked() {
        let (fake, o) = owners();
        let t = Instant::now();
        let local = addr("172.19.0.1:40001");
        assert!(o.find_at(Network::Tcp, local, t).is_none());
        o.note_flow_at(Network::Tcp, local, addr("1.1.1.1:443"), t);
        // Another protocol is another flow.
        assert!(o.find_at(Network::Udp, local, t).is_none());
        assert!(o.find_at(Network::Tcp, local, t + FLOW_TTL).is_none());
        assert_eq!(fake.uid_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn no_owner_is_cached_and_a_new_flow_asks_again() {
        let (fake, o) = owners();
        let t = Instant::now();
        let local = addr("[fdfe:dcba:9876::1]:5353");
        o.note_flow_at(Network::Udp, local, addr("[2001:db8::1]:53"), t);
        assert!(o.find_at(Network::Udp, local, t).is_none());
        assert!(o.find_at(Network::Udp, local, t).is_none());
        assert_eq!(fake.uid_calls.load(Ordering::Relaxed), 1);
        // The port reused for another destination: asked afresh.
        o.note_flow_at(Network::Udp, local, addr("[2001:db8::1]:443"), t);
        assert_eq!(o.find_at(Network::Udp, local, t).unwrap().uid, Some(10086));
        assert_eq!(fake.uid_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn package_answers_expire_and_unknown_uid_keeps_the_uid() {
        let (fake, o) = owners();
        let t = Instant::now();
        assert_eq!(o.info(10086, t).name, "com.tencent.mm");
        assert_eq!(o.info(10086, t + PACKAGE_TTL).name, "com.tencent.mm");
        assert_eq!(fake.package_calls.load(Ordering::Relaxed), 2);
        let unknown = o.info(1000, t);
        assert_eq!(unknown.name, "");
        assert_eq!(unknown.uid, Some(1000));
    }

    #[test]
    fn flow_table_stays_bounded() {
        let (_, o) = owners();
        let t = Instant::now();
        for port in 0..(FLOW_CAP as u16 + 10) {
            o.note_flow_at(
                Network::Tcp,
                SocketAddr::new([172, 19, 0, 1].into(), port),
                addr("1.1.1.1:443"),
                t,
            );
        }
        assert!(o.flows.lock().len() <= FLOW_CAP);
    }

    #[test]
    fn global_install_and_clear() {
        // The only test touching the process-wide slot.
        let local = addr("172.19.0.1:40002");
        note_flow(Network::Tcp, local, addr("1.1.1.1:443"));
        assert!(find(Network::Tcp, local).is_none());
        set_app_owner_lookup(Arc::new(Fake::default()));
        note_flow(Network::Tcp, local, addr("1.1.1.1:443"));
        assert_eq!(find(Network::Tcp, local).unwrap().name, "com.tencent.mm");
        clear_app_owner_lookup();
        assert!(find(Network::Tcp, local).is_none());
    }
}

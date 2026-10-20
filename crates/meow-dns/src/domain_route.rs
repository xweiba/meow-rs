//! Rule selection supplied by the tunnel without a reverse dependency.
use futures::future::BoxFuture;
use std::{io, sync::Arc};
pub type RouteFuture<'a> = BoxFuture<'a, io::Result<DomainRoute>>;

/// A DNS view selected for a domain. Proxy generations stay alive across
/// the query so dialer-proxy chains cannot race a routing reload.
pub enum DomainRoute {
    Direct {
        interface: Option<Arc<str>>,
    },
    Reject,
    Proxy {
        proxy: Arc<dyn meow_common::Proxy>,
        generation: Arc<dyn Send + Sync>,
    },
}

pub trait DomainRouter: Send + Sync {
    fn route<'a>(&'a self, domain: &'a str) -> RouteFuture<'a>;
}

tokio::task_local! { static CLASSIFYING: (); }

/// IP rules need an initial address to choose an egress. Nested lookups
/// use the configured nameserver/policy pipeline without re-entering
/// domain routing; the final answer uses the selected egress. A proxy
/// bound to that pipeline protects otherwise unclassified domain names.
pub async fn classify<T>(future: impl std::future::Future<Output = T>) -> T {
    CLASSIFYING.scope((), future).await
}

pub fn classifying() -> bool {
    CLASSIFYING.try_with(|_| ()).is_ok()
}

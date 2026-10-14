use crate::http_proxy;
use crate::sniffer::SnifferRuntime;
use crate::socks5;
use crate::{Inbound, MetadataStamp};
use meow_common::AuthConfig;
use meow_tunnel::Tunnel;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default cap on in-flight inbound connections per listener.
/// `0` explicitly disables the cap. Set a positive value (via the
/// `max-connections` config key, top-level or per-listener) to back-pressure
/// the TCP listen queue and bound RSS under burst load: each live
/// VLESS+WS+TLS+ECH tunnel costs ~90 KB of userland memory, so a cap of 256
/// holds RSS to ~50 MB on top of an ~18 MB idle baseline.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

pub struct MixedListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
    auth: Option<Arc<AuthConfig>>,
    max_connections: usize,
    stamp: Option<MetadataStamp>,
    loopback_only: bool,
}

impl MixedListener {
    pub fn new(tunnel: Tunnel, listen_addr: SocketAddr, name: String) -> Self {
        Self {
            tunnel,
            listen_addr,
            sniffer: None,
            name,
            auth: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            stamp: None,
            loopback_only: false,
        }
    }

    /// Stamp every connection before it is routed (see [`MetadataStamp`]).
    /// A stamped listener serves TCP only: SOCKS5 UDP ASSOCIATE is refused.
    pub fn with_stamp(mut self, stamp: MetadataStamp) -> Self {
        self.stamp = Some(stamp);
        self
    }

    /// Serve this machine only: [`Self::run_on`] refuses a socket that is
    /// not bound to a loopback address, and a peer that is not loopback is
    /// dropped unanswered. For a listener that asks for no credentials.
    pub fn loopback_only(mut self) -> Self {
        self.loopback_only = true;
        self
    }

    /// Override the cap on in-flight inbound connections (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    pub fn with_sniffer(mut self, sniffer: Arc<SnifferRuntime>) -> Self {
        if sniffer.is_enabled() {
            self.sniffer = Some(sniffer);
        }
        self
    }

    pub fn with_auth(mut self, auth: Arc<AuthConfig>) -> Self {
        if !auth.credentials.is_empty() {
            self.auth = Some(auth);
        }
        self
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.run_on(listener).await
    }

    /// Serve on an already-bound socket. Lets the caller bind first (e.g. to
    /// resolve a `port: 0` ephemeral listener to its OS-assigned port before
    /// the API snapshot is taken) and hand the socket over.
    pub async fn run_on(
        &self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound_addr = listener.local_addr().unwrap_or(self.listen_addr);
        if self.loopback_only && !bound_addr.ip().is_loopback() {
            return Err(format!(
                "listener '{}' is loopback-only and will not serve {bound_addr}",
                self.name
            )
            .into());
        }
        if self.max_connections == 0 {
            info!(
                "Mixed listener '{}' on {} (max_connections=unlimited)",
                self.name, bound_addr
            );
        } else {
            info!(
                "Mixed listener '{}' on {} (max_connections={})",
                self.name, bound_addr, self.max_connections
            );
        }

        // Bound the number of in-flight connection-handler tasks so RSS stays
        // capped under burst load. The semaphore is None when max=0
        // (cap disabled).
        let conn_limit: Option<Arc<Semaphore>> = if self.max_connections > 0 {
            Some(Arc::new(Semaphore::new(self.max_connections)))
        } else {
            None
        };
        let mut warned_saturated = false;
        // A persistent accept failure (fd exhaustion) must not spin the loop
        // or flood the log; a transient one must not be delayed meaningfully.
        let mut accept_backoff = meow_common::ErrorBackoff::new();

        loop {
            // Acquire a slot before accepting — back-pressures the TCP listen
            // queue when the cap is reached rather than spawning unbounded
            // tasks and bloating RSS.
            let permit = if let Some(sem) = &conn_limit {
                let sem = Arc::clone(sem);
                if sem.available_permits() == 0 && !warned_saturated {
                    warn!(
                        "Mixed listener '{}' saturated at {} concurrent connections; new clients will queue",
                        self.name, self.max_connections
                    );
                    warned_saturated = true;
                }
                match sem.acquire_owned().await {
                    Ok(p) => {
                        if warned_saturated {
                            debug!("Mixed listener '{}' has free capacity again", self.name);
                            warned_saturated = false;
                        }
                        Some(p)
                    }
                    Err(_) => return Ok(()), // semaphore closed → shutdown
                }
            } else {
                None
            };

            let (stream, src_addr) = match listener.accept().await {
                Ok(v) => {
                    accept_backoff.succeeded();
                    v
                }
                Err(e) => {
                    drop(permit);
                    // Loud only when the backoff engaged — per-connection
                    // errors (a reset embryo, a pending network error) are
                    // queue progress and stay at debug!.
                    if accept_backoff.failed(&e).await {
                        error!("Mixed listener '{}' accept error: {}", self.name, e);
                    } else {
                        debug!("Mixed listener '{}' accept error: {}", self.name, e);
                    }
                    continue;
                }
            };

            if self.loopback_only && !src_addr.ip().is_loopback() {
                debug!(
                    "Mixed listener '{}' dropped non-loopback peer {src_addr}",
                    self.name
                );
                continue;
            }

            let tunnel = self.tunnel.clone();
            let sniffer = self.sniffer.clone();
            let name = self.name.clone();
            let port = bound_addr.port();
            let auth = self.auth.clone();
            let stamp = self.stamp.clone();
            tokio::spawn(async move {
                let inbound = Inbound {
                    name: &name,
                    port,
                    stamp: stamp.as_ref(),
                };
                handle_connection(tunnel, stream, src_addr, sniffer, auth, inbound).await;
                drop(permit);
            });
        }
    }
}

async fn handle_connection(
    tunnel: Tunnel,
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    auth: Option<Arc<AuthConfig>>,
    inbound: Inbound<'_>,
) {
    // Peek the first byte to determine protocol
    let mut peek = [0u8; 1];
    match tokio::time::timeout(crate::DEFAULT_HANDSHAKE_TIMEOUT, stream.peek(&mut peek)).await {
        Err(_) => {
            debug!("Protocol detection timed out for {src_addr}");
            return;
        }
        Ok(Ok(0)) => return,
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            debug!("Peek error: {}", e);
            return;
        }
    }

    if peek[0] == 0x05 {
        // SOCKS5
        socks5::handle_socks5_from(
            &tunnel,
            stream,
            src_addr,
            sniffer.as_deref(),
            auth.as_deref(),
            inbound,
        )
        .await;
    } else {
        // HTTP proxy
        http_proxy::handle_http_from(
            &tunnel,
            stream,
            src_addr,
            sniffer.as_deref(),
            auth.as_deref(),
            inbound,
        )
        .await;
    }
}

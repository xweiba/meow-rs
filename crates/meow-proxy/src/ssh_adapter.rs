//! SSH outbound (`type: ssh`, mihomo-compatible): each connection is a
//! `direct-tcpip` channel over one SSH session kept per proxy. Chain hops
//! with `dialer-proxy` (the SSH TCP itself goes through the previous hop)
//! for multi-hop jumps.
//!
//! Host keys: with `host-key` set the server must present one of them;
//! without, any key is accepted (as in mihomo).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    Result,
};
use russh::client::{self, Handle};
use russh::keys::{PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use smol_str::SmolStr;
use tokio::sync::Mutex;
use tracing::debug;

use crate::stream_conn::StreamConn;

/// How the SSH user signs in.
#[derive(Clone)]
pub enum SshAuth {
    Password(String),
    /// OpenSSH / PEM private key text, with its passphrase if any.
    Key {
        pem: String,
        passphrase: Option<String>,
    },
}

pub struct SshAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    user: String,
    auth: SshAuth,
    host_keys: Arc<Vec<PublicKey>>,
    dialer: Arc<dyn crate::dialer::TcpDialer>,
    session: Mutex<Option<Arc<Handle<Client>>>>,
    health: ProxyHealth,
}

/// Checks the server's host key against the pinned ones.
struct Client {
    host_keys: Arc<Vec<PublicKey>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if self.host_keys.is_empty() {
            return Ok(true);
        }
        let presented = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.key_data().clone(),
            PublicKeyOrCertificate::Certificate(c) => c.public_key().clone(),
        };
        Ok(self.host_keys.iter().any(|k| *k.key_data() == presented))
    }
}

fn err(e: impl std::fmt::Display) -> MeowError {
    MeowError::Proxy(format!("ssh: {e}"))
}

/// Parses `host-key` entries ("ssh-ed25519 AAAA… [comment]").
pub fn parse_host_keys(keys: &[String]) -> std::result::Result<Vec<PublicKey>, String> {
    keys.iter()
        .map(|k| {
            PublicKey::from_openssh(k.trim()).map_err(|e| format!("ssh host-key '{k}': {e}"))
        })
        .collect()
}

impl SshAdapter {
    #[allow(clippy::too_many_arguments, reason = "mirrors the config fields")]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        user: &str,
        auth: SshAuth,
        host_keys: Vec<PublicKey>,
        dialer: Arc<dyn crate::dialer::TcpDialer>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            user: user.to_string(),
            auth,
            host_keys: Arc::new(host_keys),
            dialer,
            session: Mutex::new(None),
            health: ProxyHealth::new(),
        }
    }

    /// A signed-in session over `stream` (already at the SSH server).
    async fn handshake(
        &self,
        stream: Box<dyn meow_transport::Stream>,
    ) -> Result<Handle<Client>> {
        let config = Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            ..Default::default()
        });
        let handler = Client {
            host_keys: Arc::clone(&self.host_keys),
        };
        let mut handle = client::connect_stream(config, StreamConn(stream), handler)
            .await
            .map_err(err)?;
        let ok = match &self.auth {
            SshAuth::Password(p) => handle
                .authenticate_password(&self.user, p)
                .await
                .map_err(err)?
                .success(),
            SshAuth::Key { pem, passphrase } => {
                let key = russh::keys::decode_secret_key(pem, passphrase.as_deref())
                    .map_err(|e| err(format!("private key: {e}")))?;
                let hash = handle.best_supported_rsa_hash().await.map_err(err)?.flatten();
                handle
                    .authenticate_publickey(
                        &self.user,
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await
                    .map_err(err)?
                    .success()
            }
        };
        if !ok {
            return Err(err(format!("{}@{}: sign-in refused", self.user, self.addr_str)));
        }
        Ok(handle)
    }

    /// The kept session, or a new one (also after the old one closed).
    async fn session(&self, internal: bool) -> Result<Arc<Handle<Client>>> {
        let mut slot = self.session.lock().await;
        if let Some(s) = slot.as_ref().filter(|s| !s.is_closed()) {
            return Ok(Arc::clone(s));
        }
        let tcp = self
            .dialer
            .dial(&self.server, self.port, internal)
            .await
            .map_err(MeowError::Io)?;
        let s = Arc::new(self.handshake(tcp).await?);
        *slot = Some(Arc::clone(&s));
        Ok(s)
    }

    async fn open(
        &self,
        session: &Handle<Client>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let host = if metadata.host.is_empty() {
            metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default()
        } else {
            metadata.host.to_string()
        };
        let ch = session
            .channel_open_direct_tcpip(host, u32::from(metadata.dst_port), "127.0.0.1", 0)
            .await
            .map_err(err)?;
        Ok(Box::new(StreamConn(Box::new(ch.into_stream()))))
    }
}

#[async_trait]
impl ProxyAdapter for SshAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Ssh
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let session = self.session(metadata.is_internal()).await?;
        match self.open(&session, metadata).await {
            Ok(c) => Ok(c),
            Err(e) => {
                // The session may have died quietly: once more on a new one.
                debug!("{}: channel failed ({e}); new session", self.name);
                *self.session.lock().await = None;
                let session = self.session(metadata.is_internal()).await?;
                self.open(&session, metadata).await
            }
        }
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported("ssh: UDP not supported".into()))
    }

    /// One-off session over `stream` (a relay chain's previous hop).
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        let session = self.handshake(Box::new(StreamConn(Box::new(stream)))).await?;
        let conn = self.open(&session, metadata).await?;
        // The channel keeps the session's connection alive while it lives.
        Ok(Box::new(Keep { conn, _session: session }))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

/// A channel plus the session it rides on (relay hops own their session).
struct Keep {
    conn: Box<dyn ProxyConn>,
    _session: Handle<Client>,
}

impl tokio::io::AsyncRead for Keep {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Keep {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.conn).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

impl ProxyConn for Keep {}

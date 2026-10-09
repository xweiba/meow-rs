//! SSH chains as meow proxies (Dart: `clashSshProxies` in `ssh.dart`).
//!
//! Private keys and passwords pass through here: neither [`SshSecrets`]
//! nor [`SshProxy`] ever prints them.

use std::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::model::settings::SshChain;

/// The chains' credentials: [`SshChain::secret_key`] (`ssh/<chain>/<hop>`)
/// → the hop's private key (PEM) or password. Held in memory only, never
/// logged: `Debug` shows the keys, not the values.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SshSecrets(IndexMap<String, String>);

impl SshSecrets {
    /// No credentials: every hop is written without one.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the credential under `key` (`ssh/<chain>/<hop>`).
    pub fn insert(&mut self, key: impl Into<String>, secret: impl Into<String>) {
        self.0.insert(key.into(), secret.into());
    }

    /// Hop `hop` of chain `chain_id`'s credential.
    pub fn get(&self, chain_id: &str, hop: usize) -> Option<&str> {
        self.0
            .get(&SshChain::secret_key(chain_id, hop))
            .map(String::as_str)
    }

    /// From the build input's `sshSecrets` object; non-string values are
    /// left out.
    pub fn from_json(v: &Value) -> Self {
        Self(
            v.as_object()
                .into_iter()
                .flatten()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                .collect(),
        )
    }
}

impl fmt::Debug for SshSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, "<redacted>")))
            .finish()
    }
}

impl<'de> Deserialize<'de> for SshSecrets {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from_json(&Value::deserialize(d)?))
    }
}

/// One `proxies:` entry of an SSH chain. It may carry a private key or a
/// password: `Debug` redacts them; [`SshProxy::into_map`] gives the entry
/// for the config.
#[derive(Clone, PartialEq)]
pub struct SshProxy(Map<String, Value>);

impl SshProxy {
    /// The entry's `name`: `ssh:<id>#<i>` for a hop, `ssh:<id>` for the
    /// last.
    pub fn name(&self) -> &str {
        self.0
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The entry as written into the config.
    pub fn into_map(self) -> Map<String, Value> {
        self.0
    }
}

/// Keys whose values are credentials.
const SECRET_KEYS: [&str; 2] = ["private-key", "password"];

impl fmt::Debug for SshProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.iter().map(|(k, v)| {
                let shown: &dyn fmt::Debug = if SECRET_KEYS.contains(&k.as_str()) {
                    &"<redacted>"
                } else {
                    v
                };
                (k, shown)
            }))
            .finish()
    }
}

/// meow `proxies:` entries for `chain`: one `ssh` per hop, each dialing
/// through the previous one (`dialer-proxy`); the last carries the chain's
/// tag (`ssh:<id>`), the others `ssh:<id>#<i>`.
///
/// A hop's credential from `secrets` is its `private-key` (key hops) or
/// `password`; without one the hop is written without it. Pinned host keys
/// go to `host-key`.
pub fn ssh_proxies(chain: &SshChain, secrets: &SshSecrets) -> Vec<SshProxy> {
    let tag = chain.tag();
    let last = chain.hops.len().saturating_sub(1);
    chain
        .hops
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let mut m = Map::new();
            let name = if i == last {
                tag.clone()
            } else {
                format!("{tag}#{i}")
            };
            m.insert("name".into(), name.into());
            m.insert("type".into(), "ssh".into());
            m.insert("server".into(), h.host.clone().into());
            m.insert("port".into(), h.port.into());
            m.insert("username".into(), h.user.clone().into());
            if let Some(secret) = secrets.get(&chain.id, i) {
                let key = if h.use_key { "private-key" } else { "password" };
                m.insert(key.into(), secret.into());
            }
            if let Some(k) = &h.host_key {
                m.insert("host-key".into(), Value::Array(vec![k.clone().into()]));
            }
            if i > 0 {
                m.insert("dialer-proxy".into(), format!("{tag}#{}", i - 1).into());
            }
            SshProxy(m)
        })
        .collect()
}

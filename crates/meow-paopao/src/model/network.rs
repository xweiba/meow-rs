//! The network the device is on, conditions naming networks, and what the
//! settings mean on one (Dart: `network.dart`, data and `effectiveSettings`).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::dart::{int_try_parse, trim};
use crate::model::settings::{dart_str, string_field, ProxyMode, ProxySettings};

/// What kind of link the device is on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkKind {
    Wifi,
    Ethernet,
    Cellular,
    None,
    /// The OS didn't tell.
    #[default]
    Unknown,
}

/// The network the device is on now. JSON: `{kind, ssid?, addresses}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub kind: NetworkKind,
    /// Wi-Fi name, when the OS lets the app read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// This device's own addresses on the network (for subnet conditions).
    #[serde(default)]
    pub addresses: Vec<String>,
}

/// Which network something applies on: the Wi-Fi name contains `name`
/// (case-insensitive) and/or this device is in `subnet`; every part given
/// must hold.
///
/// A wired network has no name: off Wi-Fi (ethernet, or a kind the OS
/// didn't tell) a condition with a subnet is decided by the subnet alone. A
/// name-only condition never matches off Wi-Fi.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct NetworkCondition {
    /// Text the Wi-Fi name must contain.
    pub name: Option<String>,
    /// `192.168.1.0/24`, `fd00::/8`.
    pub subnet: Option<String>,
}

impl NetworkCondition {
    /// Neither part says anything: blank (only spaces) counts as unset.
    /// Dart let a blank name through, and it then matched every network,
    /// wired ones included (B13).
    pub fn is_empty(&self) -> bool {
        trim(self.name.as_deref().unwrap_or_default()).is_empty()
            && trim(self.subnet.as_deref().unwrap_or_default()).is_empty()
    }

    pub fn matches(&self, n: &NetworkInfo) -> bool {
        if self.is_empty() {
            return false;
        }
        let want = self
            .name
            .as_deref()
            .map(|s| trim(s).to_lowercase())
            .unwrap_or_default();
        let net = self.subnet.as_deref().map(trim).unwrap_or_default();
        let wired = matches!(n.kind, NetworkKind::Ethernet | NetworkKind::Unknown);
        if !want.is_empty()
            && !(wired && !net.is_empty())
            && !(n.kind == NetworkKind::Wifi
                && n.ssid
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(&want)))
        {
            return false;
        }
        net.is_empty() || on_network(net, n)
    }

    /// `{"name"?, "subnet"?}`.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        if let Some(n) = &self.name {
            m.insert("name".into(), n.clone().into());
        }
        if let Some(s) = &self.subnet {
            m.insert("subnet".into(), s.clone().into());
        }
        Value::Object(m)
    }

    /// Also reads the earlier single string (a Wi-Fi name or a subnet).
    /// None when empty.
    pub fn from_json(v: &Value) -> Option<Self> {
        if let Some(s) = v.as_str() {
            if trim(s).is_empty() {
                return None;
            }
            return Some(if is_subnet(s) {
                Self {
                    name: None,
                    subnet: Some(s.into()),
                }
            } else {
                Self {
                    name: Some(s.into()),
                    subnet: None,
                }
            });
        }
        let o = v.as_object()?;
        let c = Self {
            name: string_field(o.get("name")),
            subnet: string_field(o.get("subnet")),
        };
        (!c.is_empty()).then_some(c)
    }
}

/// A network the user named once ("家里"). Entries refer to it by `id`.
/// JSON: `{id, name, on}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamedNetwork {
    /// Stable; what entries store.
    pub id: String,
    /// What the user calls it (家里, 公司); never empty.
    pub name: String,
    pub condition: NetworkCondition,
}

impl NamedNetwork {
    pub fn matches(&self, n: &NetworkInfo) -> bool {
        self.condition.matches(n)
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), self.id.clone().into());
        m.insert("name".into(), self.name.clone().into());
        m.insert("on".into(), self.condition.to_json());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let id = o.get("id")?.as_str().filter(|s| !s.is_empty())?.to_owned();
        let condition = NetworkCondition::from_json(o.get("on")?)?;
        let name = match o.get("name") {
            Some(n) if !n.is_null() => trim(&dart_str(n)).to_owned(),
            _ => String::new(),
        };
        Some(Self {
            name: if name.is_empty() { id.clone() } else { name },
            id,
            condition,
        })
    }
}

/// "On this network, use that mode". Checked in order; the first match wins.
/// JSON: `{network, mode}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WifiProfile {
    /// A [`NamedNetwork::id`]; one that no longer exists never matches.
    pub network: String,
    pub mode: ProxyMode,
}

impl WifiProfile {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("network".into(), self.network.clone().into());
        m.insert("mode".into(), self.mode.name().into());
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let network = o.get("network")?.as_str().filter(|s| !s.is_empty())?;
        let mode = ProxyMode::from_name(o.get("mode")?.as_str()?)?;
        Some(Self {
            network: network.into(),
            mode,
        })
    }
}

/// Whether `condition` — a Wi-Fi name, or a subnet like `192.168.1.0/24` —
/// describes `network`.
pub fn on_network(condition: &str, network: &NetworkInfo) -> bool {
    let Some((base, bits)) = parse_cidr(condition) else {
        return network.kind == NetworkKind::Wifi && network.ssid.as_deref() == Some(condition);
    };
    network.addresses.iter().any(|a| {
        a.parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| same_prefix(ip, base, bits))
    })
}

/// Is `s` a subnet (rather than a Wi-Fi name)?
pub fn is_subnet(s: &str) -> bool {
    parse_cidr(s).is_some()
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u32)> {
    let parts: Vec<&str> = trim(s).split('/').collect();
    let [ip, bits] = parts[..] else {
        return None;
    };
    let ip: IpAddr = ip.parse().ok()?;
    let bits = int_try_parse(bits)?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    u32::try_from(bits)
        .ok()
        .filter(|b| *b <= max)
        .map(|b| (ip, b))
}

/// The first `bits` bits of `a` and `b` agree (false across families).
fn same_prefix(a: IpAddr, b: IpAddr, bits: u32) -> bool {
    let (a, b): (Vec<u8>, Vec<u8>) = match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.octets().into(), b.octets().into()),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.octets().into(), b.octets().into()),
        _ => return false,
    };
    (0..bits as usize).all(|i| {
        let mask = 0x80 >> (i % 8);
        a[i / 8] & mask == b[i / 8] & mask
    })
}

/// What the settings mean on `network`: the mode of the first matching Wi-Fi
/// profile, and only the rules and hosts that apply there. Entries name a
/// network by id; an id that no longer exists never applies.
pub fn effective_settings(s: &ProxySettings, network: &NetworkInfo) -> ProxySettings {
    // A repeated id: the last one counts (Dart map literal).
    let here = |id: &str| {
        s.networks
            .iter()
            .rev()
            .find(|n| n.id == id)
            .is_some_and(|n| n.matches(network))
    };
    let applies = |only_on: Option<&String>| only_on.is_none_or(|id| here(id));
    let profile = s.wifi_profiles.iter().find(|p| here(&p.network));
    ProxySettings {
        mode: profile.map_or(s.mode, |p| p.mode),
        rules: s
            .rules
            .iter()
            .filter(|r| applies(r.network.as_ref()))
            .cloned()
            .collect(),
        hosts: s
            .hosts
            .iter()
            .filter(|h| applies(h.network.as_ref()))
            .cloned()
            .collect(),
        ..s.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::settings::{CustomRule, RuleMatch, RuleTarget};

    fn net(id: &str, name: Option<&str>, subnet: Option<&str>) -> NamedNetwork {
        NamedNetwork {
            id: id.into(),
            name: id.into(),
            condition: NetworkCondition {
                name: name.map(Into::into),
                subnet: subnet.map(Into::into),
            },
        }
    }

    fn info(kind: NetworkKind, ssid: Option<&str>, addresses: &[&str]) -> NetworkInfo {
        NetworkInfo {
            kind,
            ssid: ssid.map(Into::into),
            addresses: addresses.iter().map(|a| (*a).into()).collect(),
        }
    }

    #[test]
    fn conditions_match_like_dart() {
        let wifi = info(
            NetworkKind::Wifi,
            Some("Weiba-5G"),
            &["192.168.186.23", "fe80::1"],
        );
        let wired = info(NetworkKind::Ethernet, None, &["10.1.2.5", "240e:3b0:1::5"]);
        let name = net("a", Some(" weiba "), None).condition;
        let both = net("b", Some("weiba"), Some("192.168.186.0/24")).condition;
        let office = net("c", Some("corp"), Some("10.1.0.0/16")).condition;
        let v6 = net("d", None, Some("240e:3b0::/32")).condition;
        // Wi-Fi name contains, case-insensitive and trimmed.
        assert!(name.matches(&wifi));
        assert!(!name.matches(&wired));
        assert!(both.matches(&wifi));
        // Wired: a subnet decides alone, the name is not required.
        assert!(office.matches(&wired));
        assert!(!office.matches(&wifi));
        assert!(v6.matches(&wired));
        assert!(!NetworkCondition::default().matches(&wifi));
        // B13: a whitespace-only name is unset (Dart: it matched every
        // network, wired too).
        let blank = net("e", Some("  "), None).condition;
        assert!(blank.is_empty());
        assert!(!blank.matches(&wired));
        assert!(!blank.matches(&wifi));
        assert_eq!(NetworkCondition::from_json(&serde_json::json!(" ")), None);
        assert_eq!(
            NetworkCondition::from_json(&serde_json::json!({"name": "  "})),
            None
        );
    }

    #[test]
    fn effective_settings_filter_by_network() {
        let rule = |v: &str, network: Option<&str>| CustomRule {
            matches: RuleMatch::Domain,
            value: v.into(),
            target: RuleTarget::Direct,
            network: network.map(Into::into),
        };
        let s = ProxySettings {
            networks: vec![
                net("home", Some("home"), None),
                net("office", None, Some("10.1.0.0/16")),
            ],
            rules: vec![
                rule("all.example", None),
                rule("home.example", Some("home")),
                rule("office.example", Some("office")),
                rule("gone.example", Some("deleted")),
            ],
            wifi_profiles: vec![
                WifiProfile {
                    network: "deleted".into(),
                    mode: ProxyMode::Global,
                },
                WifiProfile {
                    network: "office".into(),
                    mode: ProxyMode::Direct,
                },
            ],
            ..ProxySettings::default()
        };
        let values =
            |e: &ProxySettings| e.rules.iter().map(|r| r.value.clone()).collect::<Vec<_>>();

        let wired = info(NetworkKind::Ethernet, None, &["10.1.2.5"]);
        let e = effective_settings(&s, &wired);
        assert_eq!(e.mode, ProxyMode::Direct);
        assert_eq!(values(&e), ["all.example", "office.example"]);

        let home = info(NetworkKind::Wifi, Some("my HOME net"), &["192.168.1.5"]);
        let e = effective_settings(&s, &home);
        assert_eq!(e.mode, ProxyMode::Smart);
        assert_eq!(values(&e), ["all.example", "home.example"]);
    }
}

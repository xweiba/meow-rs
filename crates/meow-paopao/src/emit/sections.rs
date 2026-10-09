//! The config's fixed sections (Dart: the literals in `buildClashConfig`):
//! profile, rule data, DNS, sniffer and the virtual adapter.

use serde_json::{json, Value};

/// MetaCubeX's rule data (the cores' defaults) through jsDelivr.
const GEODATA_BASE: &str = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release";

/// Names that keep their real address under fake-ip (as the community lists
/// do): the local network, time sync, the OS's "am I online" checks
/// (captive portals), QQ's local helpers. Plain and `+.` entries also match
/// subdomains.
///
/// A real address loses the name: what is not sniffable (time sync over
/// UDP) is then routed by address and may leave directly. So only vendors
/// whose traffic goes out directly anyway are listed; Apple's and
/// Microsoft's only while their group's pick is direct
/// ([`FAKE_IP_FILTER_IF_DIRECT`]).
pub const FAKE_IP_FILTER: [&str; 17] = [
    "*.lan",
    "*.local",
    "*.localdomain",
    "*.home.arpa",
    "localhost",
    // Time (no accounts behind these).
    "+.pool.ntp.org",
    "+.ntp.org",
    "time.cloudflare.com",
    "ntp.aliyun.com",
    "ntp.tencent.com",
    "ntp.ntsc.ac.cn",
    // Connectivity checks of phones sold here (direct anyway).
    "connect.rom.miui.com",
    "wifi.vivo.com.cn",
    "connectivitycheck.platform.hicloud.com",
    // Local helpers that resolve to 127.0.0.1.
    "localhost.ptlogin2.qq.com",
    "localhost.sec.qq.com",
    "localhost.work.weixin.qq.com",
];

/// Vendors' names kept real only while their group (tag) goes out directly.
pub const FAKE_IP_FILTER_IF_DIRECT: [(&str, &[&str]); 2] = [
    (
        "policy:apple",
        &[
            "time.apple.com",
            "time-ios.apple.com",
            "time-macos.apple.com",
            "captive.apple.com",
        ],
    ),
    (
        "policy:microsoft",
        &[
            "time.windows.com",
            "+.msftconnecttest.com",
            "+.msftncsi.com",
        ],
    ),
];

/// `{"store-selected": true}`: the core keeps the selectors' picks.
pub fn profile() -> Value {
    json!({ "store-selected": true })
}

/// Rule data fetched in the background (a missing file never holds the
/// start), from a CDN reachable in China; until then geosite / geoip rules
/// match nothing.
pub fn geodata() -> Value {
    json!({
        "background-fetch": true,
        "auto-update": true,
        "url": {
            "mmdb": format!("{GEODATA_BASE}/country.mmdb"),
            "geosite": format!("{GEODATA_BASE}/geosite.dat"),
        },
    })
}

/// DNS: Chinese DoH; with the virtual adapter (`tun`) names are answered
/// with fake addresses so rules see the site, except [`FAKE_IP_FILTER`] and
/// the vendors of [`FAKE_IP_FILTER_IF_DIRECT`] whose group `direct_pick`
/// says goes out directly.
pub fn dns(ipv6: bool, tun: bool, direct_pick: impl Fn(&str) -> bool) -> Value {
    let mut d = json!({
        "enable": true,
        "ipv6": ipv6,
        "nameserver": ["https://223.5.5.5/dns-query", "223.5.5.5"],
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    });
    if tun {
        let mut filter: Vec<&str> = FAKE_IP_FILTER.to_vec();
        for (group, names) in FAKE_IP_FILTER_IF_DIRECT {
            if direct_pick(group) {
                filter.extend_from_slice(names);
            }
        }
        if let Some(o) = d.as_object_mut() {
            o.insert("enhanced-mode".into(), "fake-ip".into());
            o.insert("fake-ip-range".into(), "198.18.0.1/16".into());
            o.insert("fake-ip-filter".into(), filter.into());
        }
    }
    d
}

/// The site from the first bytes (TLS SNI, HTTP Host) for programs that
/// connect by address; a line is then asked for that name (D16). Apple
/// push is skipped (its own long-lived TLS, nothing to learn).
pub fn sniffer() -> Value {
    json!({
        "enable": true,
        "parse-pure-ip": true,
        // Lines get the site name, not an address the device resolved
        // itself (possibly poisoned): the line resolves it where it is.
        "override-destination": true,
        "sniff": {
            "TLS": { "ports": ["443", "8443"] },
            "HTTP": { "ports": ["80", "8080-8880"] },
        },
        "skip-domain": ["+.push.apple.com"],
    })
}

/// The virtual adapter (desktop): every program's traffic into the device,
/// DNS answered inside. IPv6 into it too while the network reaches IPv6;
/// direct traffic leaves by `outbound_interface` when the user chose one,
/// else the core picks a physical uplink.
pub fn tun(ipv6: bool, outbound_interface: Option<&str>) -> Value {
    let mut t = serde_json::Map::new();
    t.insert("enable".into(), true.into());
    t.insert("auto-route".into(), "global".into());
    if ipv6 {
        t.insert("inet6-address".into(), json!(["fdfe:dcba:9876::1/126"]));
    }
    t.insert("auto-detect-interface".into(), true.into());
    if let Some(i) = outbound_interface {
        t.insert("outbound-interface".into(), i.into());
    }
    t.insert("dns-hijack".into(), json!(["any:53"]));
    Value::Object(t)
}

//! A connection that names its own proxy or group (`Metadata::special_proxy`)
//! gets that one whatever the mode and the rules say — upstream
//! `resolveMetadata`'s `SpecialProxy` arm. A name the registry does not
//! hold refuses the connection: it is never handed to the rules instead.

use meow_common::{AdapterType, DnsMode, Metadata, Network, Rule, TunnelMode};
use meow_dns::Resolver;
use meow_rules::final_rule::FinalRule;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::sync::Arc;

/// Rule mode, the built-in registry (DIRECT / REJECT / REJECT-DROP), and
/// one rule sending everything to `fallback`.
fn tunnel(fallback: &str) -> Tunnel {
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let res = meow_config::rebuild_from_raw(&meow_config::raw::RawConfig::default())
        .expect("an empty config must build its built-in registry");
    tunnel.update_proxies(res.proxies, res.dialer_registry);
    tunnel.set_mode(TunnelMode::Rule);
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new(fallback))];
    tunnel.update_rules(rules);
    tunnel
}

fn metadata(special: &str) -> Metadata {
    Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        special_proxy: special.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn the_named_proxy_wins_over_the_rules() {
    let tunnel = tunnel("DIRECT");
    for lazy in [false, true] {
        let mut m = metadata("REJECT");
        let target = if lazy {
            tunnel.inner().resolve_proxy_lazy(&mut m).await
        } else {
            tunnel.inner().resolve_proxy(&m).await
        }
        .expect("a known name resolves");
        assert_eq!(target.adapter.adapter_type(), AdapterType::Reject);
        assert_eq!(target.rule_name, "SpecialProxy");
        assert_eq!(target.rule_payload, "REJECT");
    }
    assert!(
        tunnel.statistics().rule_match.snapshot().is_empty(),
        "no rule was asked"
    );
}

#[tokio::test]
async fn the_named_proxy_wins_in_every_mode() {
    let tunnel = tunnel("REJECT");
    for mode in [TunnelMode::Rule, TunnelMode::Global, TunnelMode::Direct] {
        tunnel.set_mode(mode);
        for (name, kind) in [
            ("DIRECT", AdapterType::Direct),
            ("REJECT", AdapterType::Reject),
        ] {
            let mut m = metadata(name);
            let eager = tunnel.inner().resolve_proxy(&m).await.unwrap();
            assert_eq!(eager.adapter.adapter_type(), kind, "{mode:?} {name}");
            let lazy = tunnel.inner().resolve_proxy_lazy(&mut m).await.unwrap();
            assert_eq!(lazy.adapter.adapter_type(), kind, "{mode:?} {name}");
        }
    }
}

#[tokio::test]
async fn an_unknown_name_refuses_instead_of_asking_the_rules() {
    // The rules would let it out directly.
    let tunnel = tunnel("DIRECT");
    for mode in [TunnelMode::Rule, TunnelMode::Global, TunnelMode::Direct] {
        tunnel.set_mode(mode);
        let mut m = metadata("ghost-group");
        assert!(tunnel.inner().resolve_proxy(&m).await.is_none(), "{mode:?}");
        assert!(
            tunnel.inner().resolve_proxy_lazy(&mut m).await.is_none(),
            "{mode:?}"
        );
    }
    assert!(!tunnel.inner().has_proxy("ghost-group"));
    assert!(tunnel.inner().has_proxy("REJECT"));
    assert!(tunnel.inner().has_proxy("DIRECT"));
}

#[tokio::test]
async fn no_name_is_the_rules_as_before() {
    let tunnel = tunnel("REJECT");
    let mut m = metadata("");
    let eager = tunnel.inner().resolve_proxy(&m).await.unwrap();
    assert_eq!(eager.adapter.adapter_type(), AdapterType::Reject);
    assert_eq!(eager.rule_name, "MATCH");
    let lazy = tunnel.inner().resolve_proxy_lazy(&mut m).await.unwrap();
    assert_eq!(lazy.adapter.adapter_type(), AdapterType::Reject);
}

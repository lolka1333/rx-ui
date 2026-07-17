//! Build xray's `router.Config` protobuf — the full ordered rule set — for the
//! `RoutingService.AddRule` hot-apply path, so a routing change takes effect on
//! a live xray with NO restart.
//!
//! This mirrors the routing block of `config_gen::build_bootstrap_config`
//! exactly: same evaluation order (`ordered_rule_tokens`), same system rules
//! (api pin, bittorrent, block-domains/ips, ipv4-force), same custom-rule
//! mapping — only it emits proto instead of JSON. The two paths MUST agree, so
//! the shared order lives in `config_gen` and both call it.
//!
//! `AddRule(shouldAppend=false)` atomically replaces the WHOLE rule set under
//! the router's lock (`app/router/router.go` `ReloadRules`), so the pushed set
//! must be complete — including the api pin, or the control channel that just
//! issued the call falls through to `direct`.

use crate::models::RoutingRule;
use crate::xray::config_gen::{
    API_TAG, BootstrapSettings, SYSTEM_TOKENS, TAG_BLOCKED, TAG_DIRECT_IPV4, ordered_rule_tokens,
};
use crate::xray::orchestrator::{build_domain_rules, build_ip_rules};
use crate::xray::proto::xray::app::router::{
    Config as RouterConfig, RoutingRule as PbRule, routing_rule::TargetTag,
};
use crate::xray::proto::xray::common::net::{Network, PortList, PortRange};
use std::collections::HashMap;

/// The full ordered rule set as a `router.Config`, ready to encode into a
/// `TypedMessage` and push via `AddRule(shouldAppend=false)`.
pub fn build_router_config(s: &BootstrapSettings) -> anyhow::Result<RouterConfig> {
    let custom_by_id: HashMap<&str, &RoutingRule> =
        s.custom_rules.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut rules = Vec::new();
    for tok in ordered_rule_tokens(s) {
        if SYSTEM_TOKENS.contains(&tok.as_str()) {
            if let Some(r) = system_rule_proto(&tok, s)? {
                rules.push(r);
            }
        } else if let Some(r) = custom_by_id.get(tok.as_str()).filter(|r| r.enabled) {
            rules.push(custom_rule_proto(r)?);
        }
    }

    Ok(RouterConfig {
        // `ReloadRules` ignores domain_strategy (it only swaps rules +
        // balancers); the routing-level strategy is bound once at Router.Init
        // and stays restart-only. Left at AsIs (0) since it's a no-op here.
        domain_strategy: 0,
        rule: rules,
        balancing_rule: Vec::new(),
    })
}

fn tag(target: &str) -> TargetTag {
    TargetTag::Tag(target.to_owned())
}

/// The xray routing rule for a system token, or `None` when inactive — mirrors
/// `config_gen::system_rule` field-for-field.
fn system_rule_proto(token: &str, s: &BootstrapSettings) -> anyhow::Result<Option<PbRule>> {
    let rule = match token {
        t if t == API_TAG => PbRule {
            inbound_tag: vec![API_TAG.to_owned()],
            target_tag: Some(tag(API_TAG)),
            ..PbRule::default()
        },
        "bittorrent" if s.block_bittorrent => PbRule {
            protocol: vec!["bittorrent".to_owned()],
            target_tag: Some(tag(TAG_BLOCKED)),
            ..PbRule::default()
        },
        "blocked_domains" if !s.blocked_domains.is_empty() => PbRule {
            domain: build_domain_rules(&s.blocked_domains, true)?,
            target_tag: Some(tag(TAG_BLOCKED)),
            ..PbRule::default()
        },
        "blocked_ips" if !s.blocked_ips.is_empty() => PbRule {
            ip: build_ip_rules(&s.blocked_ips, true)?,
            target_tag: Some(tag(TAG_BLOCKED)),
            ..PbRule::default()
        },
        "ipv4" if !s.ipv4_domains.is_empty() => PbRule {
            domain: build_domain_rules(&s.ipv4_domains, true)?,
            target_tag: Some(tag(TAG_DIRECT_IPV4)),
            ..PbRule::default()
        },
        _ => return Ok(None),
    };
    Ok(Some(rule))
}

/// One operator rule as an xray routing rule — mirrors `config_gen::custom_rule`
/// (empty matchers omitted). `rule_tag` carries the panel id so a future
/// single-rule `RemoveRule` can target it.
fn custom_rule_proto(r: &RoutingRule) -> anyhow::Result<PbRule> {
    Ok(PbRule {
        rule_tag: r.id.clone(),
        domain: build_domain_rules(&r.domain, true)?,
        ip: build_ip_rules(&r.ip, true)?,
        source_ip: build_ip_rules(&r.source_ip, true)?,
        port_list: parse_port_list(&r.port)?,
        source_port_list: parse_port_list(&r.source_port)?,
        networks: parse_networks(&r.network),
        protocol: r.protocol.clone(),
        inbound_tag: r.inbound_tag.clone(),
        user_email: r.user.clone(),
        target_tag: Some(tag(&r.outbound_tag)),
        ..PbRule::default()
    })
}

/// Parse an xray port spec (`"443"`, `"1000-2000"`, `"80,443,8080-8090"`) into
/// a `PortList`. `None` for an empty spec so the matcher is omitted.
fn parse_port_list(spec: &str) -> anyhow::Result<Option<PortList>> {
    let mut ranges = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (from, to) = if let Some((a, b)) = part.split_once('-') {
            (parse_port(a)?, parse_port(b)?)
        } else {
            let p = parse_port(part)?;
            (p, p)
        };
        anyhow::ensure!(from <= to, "invalid port range (from > to): {part}");
        ranges.push(PortRange { from, to });
    }
    Ok((!ranges.is_empty()).then_some(PortList { range: ranges }))
}

fn parse_port(s: &str) -> anyhow::Result<u32> {
    let p: u32 = s
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port: {s}"))?;
    anyhow::ensure!((1..=65535).contains(&p), "port out of range: {p}");
    Ok(p)
}

/// Map network names to xray's `Network` enum ints; unknown names are dropped
/// (the panel UI only offers tcp/udp).
fn parse_networks(nets: &[String]) -> Vec<i32> {
    nets.iter()
        .filter_map(|n| match n.trim().to_lowercase().as_str() {
            "tcp" => Some(Network::Tcp as i32),
            "udp" => Some(Network::Udp as i32),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::proto::xray::common::geodata::{domain_rule, ip_rule};

    fn settings(custom: Vec<RoutingRule>, order: &[&str]) -> BootstrapSettings {
        BootstrapSettings {
            freedom_strategy: "AsIs".into(),
            routing_strategy: "AsIs".into(),
            block_bittorrent: false,
            blocked_ips: Vec::new(),
            blocked_domains: Vec::new(),
            ipv4_domains: Vec::new(),
            has_reverse_bridge: false,
            custom_rules: custom,
            rule_order: order.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    fn rule(id: &str, target: &str) -> RoutingRule {
        RoutingRule {
            id: id.to_owned(),
            enabled: true,
            name: id.to_owned(),
            domain: Vec::new(),
            ip: Vec::new(),
            source_ip: Vec::new(),
            port: String::new(),
            source_port: String::new(),
            network: Vec::new(),
            protocol: Vec::new(),
            inbound_tag: Vec::new(),
            user: Vec::new(),
            outbound_tag: target.to_owned(),
        }
    }

    fn find<'a>(cfg: &'a RouterConfig, tag: &str) -> &'a PbRule {
        cfg.rule
            .iter()
            .find(|r| r.rule_tag == tag)
            .expect("rule present")
    }

    // A full-replace AddRule wipes everything, so the api pin MUST lead or the
    // control channel that issued the call falls through to `direct`.
    #[test]
    fn api_pin_is_always_first() {
        let cfg = build_router_config(&settings(Vec::new(), &[])).unwrap();
        let first = &cfg.rule[0];
        assert_eq!(first.inbound_tag, vec!["api"]);
        assert_eq!(first.target_tag, Some(TargetTag::Tag("api".to_owned())));
    }

    #[test]
    fn geosite_and_geoip_become_references() {
        let mut r = rule("r1", "blocked");
        r.domain = vec!["geosite:category-ads-all".to_owned()];
        r.ip = vec!["geoip:ru".to_owned(), "!geoip:private".to_owned()];
        let cfg = build_router_config(&settings(vec![r], &["api", "r1"])).unwrap();
        let cr = find(&cfg, "r1");
        let Some(domain_rule::Value::Geosite(g)) = &cr.domain[0].value else {
            panic!("expected geosite reference");
        };
        assert_eq!(g.file, "geosite.dat");
        assert_eq!(g.code, "CATEGORY-ADS-ALL"); // upper-cased like xray
        let Some(ip_rule::Value::Geoip(gi)) = &cr.ip[0].value else {
            panic!("expected geoip reference");
        };
        assert_eq!((gi.code.as_str(), gi.reverse_match), ("RU", false));
        let Some(ip_rule::Value::Geoip(gi2)) = &cr.ip[1].value else {
            panic!("expected geoip reference");
        };
        assert_eq!((gi2.code.as_str(), gi2.reverse_match), ("PRIVATE", true));
    }

    #[test]
    fn ports_networks_user_and_target_map_through() {
        let mut r = rule("r1", "de-out");
        r.port = "443,8080-8090".to_owned();
        r.network = vec!["tcp".to_owned(), "udp".to_owned()];
        r.user = vec!["a@b".to_owned()];
        r.inbound_tag = vec!["RU-XHTTP".to_owned()];
        let cfg = build_router_config(&settings(vec![r], &["api", "r1"])).unwrap();
        let cr = find(&cfg, "r1");
        let pl = cr.port_list.as_ref().unwrap();
        assert_eq!(pl.range.len(), 2);
        assert_eq!((pl.range[0].from, pl.range[0].to), (443, 443));
        assert_eq!((pl.range[1].from, pl.range[1].to), (8080, 8090));
        assert_eq!(cr.networks, vec![Network::Tcp as i32, Network::Udp as i32]);
        assert_eq!(cr.user_email, vec!["a@b"]);
        assert_eq!(cr.inbound_tag, vec!["RU-XHTTP"]);
        assert_eq!(cr.target_tag, Some(TargetTag::Tag("de-out".to_owned())));
    }

    #[test]
    fn disabled_custom_rule_is_skipped() {
        let mut r = rule("r1", "blocked");
        r.enabled = false;
        let cfg = build_router_config(&settings(vec![r], &["api", "r1"])).unwrap();
        assert!(cfg.rule.iter().all(|x| x.rule_tag != "r1"));
    }

    // Empty matchers must be omitted (an empty port_list would be a no-op but an
    // empty geoip/domain rule would reject or misbehave).
    #[test]
    fn empty_matchers_are_omitted() {
        let cfg =
            build_router_config(&settings(vec![rule("r1", "direct")], &["api", "r1"])).unwrap();
        let cr = find(&cfg, "r1");
        assert!(cr.domain.is_empty());
        assert!(cr.ip.is_empty());
        assert!(cr.port_list.is_none());
        assert!(cr.networks.is_empty());
    }
}

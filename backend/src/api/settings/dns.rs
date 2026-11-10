//! The core's own resolver (the `dns` section). A `dns` block xray refuses
//! takes the whole config down with it — every inbound, over a typo in one
//! resolver — so each server, host and match list goes through the rules the
//! core applies before it is stored.

use super::routing::validate_list_entries;
use crate::{
    error::{AppError, AppResult},
    models::{DnsHost, DnsServer, PanelSettingsUpdate},
    xray::orchestrator::{check_domain_matcher, check_ip_matcher},
};

/// `dns.queryStrategy` values the core understands. It maps anything it does
/// not recognise to `UseIP` silently, so an unchecked field would look applied
/// and behave as the default — hence the allowlist.
const DNS_QUERY_STRATEGIES: &[&str] = &["UseIP", "UseIPv4", "UseIPv6", "UseSystem"];

/// URL schemes `app/dns/nameserver.go` builds a server from. The `+local`
/// variants resolve straight from the node; the plain ones send their queries
/// back through routing and outbounds, which on a relay means the upstream
/// resolver is reached through the tunnel.
const DNS_SCHEMES: &[&str] = &[
    "https",
    "https+local",
    "h2c",
    "h2c+local",
    "quic+local",
    "tcp",
    "tcp+local",
];

/// A resolver list longer than this is a mistake, not a strategy: xray walks it
/// in order on a miss, so every extra entry is added latency on failure.
const MAX_DNS_SERVERS: usize = 8;

/// The core's resolver settings, validated and ready to bind. The switches are
/// already `i64` because that is what the columns take, and the two lists are
/// already JSON strings for the same reason.
pub(super) struct XrayDns {
    pub(super) servers: String,
    pub(super) hosts: String,
    pub(super) query_strategy: String,
    pub(super) client_ip: String,
    pub(super) tag: String,
    pub(super) flags: DnsFlags,
    pub(super) serve_expired_ttl: i64,
}

/// The section's on/off switches. Grouped because six bare `i64`s bound
/// positionally into an UPDATE is a swap the compiler cannot catch.
pub(super) struct DnsFlags {
    pub(super) disable_cache: i64,
    pub(super) disable_fallback: i64,
    pub(super) disable_fallback_if_match: i64,
    pub(super) parallel_query: i64,
    pub(super) use_system_hosts: i64,
    pub(super) serve_stale: i64,
}

/// Sanity ceilings, not xray limits: a resolver allowed a five-minute timeout
/// hangs every connection that waits on it.
const MAX_DNS_TIMEOUT_MS: u32 = 60_000;
const MAX_SERVE_EXPIRED_TTL: u32 = 86_400;
const MAX_DNS_HOSTS: usize = 128;

pub(super) fn validate_xray_dns(body: &PanelSettingsUpdate) -> AppResult<XrayDns> {
    // Read first: every server below is checked against it.
    let query_strategy =
        validate_dns_strategy(&body.xray_dns_query_strategy, "xray_dns_query_strategy")?
            .unwrap_or_else(|| "UseIP".to_owned());
    // Keep the operator's order — xray walks the list — while dropping repeats
    // of a plain address. A server carrying per-server rules is never a
    // duplicate: two entries with the same address and different `domains` are
    // the whole point of split-horizon DNS.
    let mut servers: Vec<DnsServer> = Vec::new();
    for raw in &body.xray_dns_servers {
        let Some(address) = validate_dns_server(&raw.address)? else {
            continue;
        };
        let server = validate_dns_server_fields(raw, address, &query_strategy)?;
        let is_dup = is_plain_server(&server)
            && servers
                .iter()
                .any(|s| s.address == server.address && is_plain_server(s));
        if !is_dup {
            servers.push(server);
        }
    }
    // Counted on what will actually be stored: the editor keeps a blank row on
    // screen while it is being filled in and those rows are dropped above, so
    // counting the raw list would refuse a save over rows that are not servers.
    if servers.len() > MAX_DNS_SERVERS {
        return Err(AppError::BadRequest(format!(
            "xray_dns_servers has too many entries (max {MAX_DNS_SERVERS})"
        )));
    }

    let hosts = validate_dns_hosts(&body.xray_dns_hosts)?;
    let client_ip = validate_optional_ip(&body.xray_dns_client_ip, "xray_dns_client_ip")?;
    let tag = validate_dns_tag(&body.xray_dns_tag)?;

    if body.xray_dns_serve_expired_ttl > MAX_SERVE_EXPIRED_TTL {
        return Err(AppError::BadRequest(format!(
            "xray_dns_serve_expired_ttl must be at most {MAX_SERVE_EXPIRED_TTL} seconds"
        )));
    }

    Ok(XrayDns {
        servers: serde_json::to_string(&servers)
            .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?,
        hosts: serde_json::to_string(&hosts).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?,
        query_strategy,
        client_ip,
        tag,
        flags: DnsFlags {
            disable_cache: i64::from(body.xray_dns_disable_cache),
            disable_fallback: i64::from(body.xray_dns_disable_fallback),
            disable_fallback_if_match: i64::from(body.xray_dns_disable_fallback_if_match),
            parallel_query: i64::from(body.xray_dns_parallel_query),
            use_system_hosts: i64::from(body.xray_dns_use_system_hosts),
            serve_stale: i64::from(body.xray_dns_serve_stale),
        },
        serve_expired_ttl: i64::from(body.xray_dns_serve_expired_ttl),
    })
}

/// Whether this server is "just an address" — the form emitted as a bare string
/// and the only form deduplication may collapse.
const fn is_plain_server(s: &DnsServer) -> bool {
    s.port == 0
        && s.domains.is_empty()
        && s.expect_ips.is_empty()
        && s.unexpected_ips.is_empty()
        && !s.skip_fallback
        && !s.final_query
        && s.timeout_ms == 0
        && s.client_ip.is_empty()
        && s.query_strategy.is_empty()
}

/// The per-server fields, cleaned and checked against the section they will
/// live in.
fn validate_dns_server_fields(
    raw: &DnsServer,
    address: String,
    section_strategy: &str,
) -> AppResult<DnsServer> {
    if raw.port > 65535 {
        return Err(AppError::BadRequest(format!(
            "dns server port out of range: {}",
            raw.port
        )));
    }
    // A `scheme://` address carries its own port. The core reads the object's
    // `port` only for the plain forms, so keeping one here would show a setting
    // that is silently ignored, and an operator debugging a resolver on a
    // non-standard port would have nothing to go on.
    if raw.port != 0 && address.contains("://") {
        return Err(AppError::BadRequest(format!(
            "dns server port is ignored for a url address, put it in the url: {address}"
        )));
    }
    if raw.timeout_ms > MAX_DNS_TIMEOUT_MS {
        return Err(AppError::BadRequest(format!(
            "dns server timeout must be at most {MAX_DNS_TIMEOUT_MS} ms"
        )));
    }
    let query_strategy = validate_dns_strategy(&raw.query_strategy, "dns server query_strategy")?
        .unwrap_or_default();
    check_strategy_pair(section_strategy, &query_strategy, &address)?;
    Ok(DnsServer {
        address,
        port: raw.port,
        domains: clean_dns_matchers("dns server domains", &raw.domains, check_domain_matcher)?,
        expect_ips: clean_dns_matchers("dns server expect_ips", &raw.expect_ips, check_ip_matcher)?,
        unexpected_ips: clean_dns_matchers(
            "dns server unexpected_ips",
            &raw.unexpected_ips,
            check_ip_matcher,
        )?,
        skip_fallback: raw.skip_fallback,
        final_query: raw.final_query,
        timeout_ms: raw.timeout_ms,
        client_ip: validate_optional_ip(&raw.client_ip, "dns server client_ip")?,
        query_strategy,
    })
}

/// A per-server strategy does not replace the section-wide one, it narrows it:
/// `ResolveIpOptionOverride` (`app/dns/nameserver.go`) intersects the two. Ask
/// for one family at the top and the other at a server and nothing is left, so
/// the core refuses to build — `no QueryStrategy available` — and refuses the
/// *whole* config with it. That would be a panel answering 200 and an xray that
/// never comes back on the next start, so the pair dies here instead.
fn check_strategy_pair(section: &str, server: &str, address: &str) -> AppResult<()> {
    if matches!(
        (section, server),
        ("UseIPv4", "UseIPv6") | ("UseIPv6", "UseIPv4")
    ) {
        return Err(AppError::BadRequest(format!(
            "dns server {address} asks for {server} while the section asks for {section}: no address family would be left to query"
        )));
    }
    Ok(())
}

/// One per-server match list, cleaned and put through the core's own parser.
///
/// Length and shape alone are not enough here: `expect_ips: ["cloudflare"]` is
/// an ordinary-looking string that `ParseIPRules` rejects, and the core reports
/// that by refusing the config rather than the rule — so the panel would store
/// a setting that quietly costs every inbound at the next start.
///
/// `*` is not a matcher — `infra/conf/dns.go` lifts it out as the "prioritise"
/// flag before parsing — so it is kept exactly as written.
fn clean_dns_matchers(
    field: &str,
    list: &[String],
    check: fn(&str) -> anyhow::Result<()>,
) -> AppResult<Vec<String>> {
    validate_list_entries(field, list)?;
    let mut out = Vec::new();
    for raw in list {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if entry != "*" {
            check(entry).map_err(|e| AppError::BadRequest(format!("{field}: {e}")))?;
        }
        out.push(entry.to_owned());
    }
    Ok(out)
}

/// `hosts`: a matcher and the addresses it answers with.
fn validate_dns_hosts(list: &[DnsHost]) -> AppResult<Vec<DnsHost>> {
    if list.len() > MAX_DNS_HOSTS {
        return Err(AppError::BadRequest(format!(
            "xray_dns_hosts has too many entries (max {MAX_DNS_HOSTS})"
        )));
    }
    let mut out = Vec::new();
    for h in list {
        let domain = h.domain.trim();
        if domain.is_empty() {
            continue;
        }
        if domain.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(AppError::BadRequest(format!(
                "hosts entry must not contain spaces: {domain}"
            )));
        }
        // `hosts` is written as a JSON object and read back into a map, so a
        // repeated key is not two answers but one: the last written wins and
        // the other vanishes without a word, while the editor still shows both
        // rows as if they were live.
        if out.iter().any(|e: &DnsHost| e.domain == domain) {
            return Err(AppError::BadRequest(format!(
                "duplicate hosts entry: {domain}"
            )));
        }
        check_domain_matcher(domain)
            .map_err(|e| AppError::BadRequest(format!("hosts entry: {e}")))?;
        validate_list_entries("hosts values", &h.values)?;
        let values: Vec<String> = h
            .values
            .iter()
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .collect();
        if values.is_empty() {
            return Err(AppError::BadRequest(format!(
                "hosts entry needs at least one address: {domain}"
            )));
        }
        // `newHostMapping` keeps either a list of addresses or one proxied
        // domain: a single name anywhere in the list turns the whole entry into
        // an alias and every address beside it is dropped on the floor.
        if values.len() > 1
            && values
                .iter()
                .any(|v| v.parse::<std::net::IpAddr>().is_err())
        {
            return Err(AppError::BadRequest(format!(
                "hosts entry {domain} mixes a name with addresses, the core would keep only the name"
            )));
        }
        out.push(DnsHost {
            domain: domain.to_owned(),
            values,
        });
    }
    Ok(out)
}

/// Empty stays empty (the field is simply not emitted); anything else has to be
/// a value the core maps to a real strategy rather than silently to `UseIP`.
fn validate_dns_strategy(raw: &str, field: &str) -> AppResult<Option<String>> {
    let v = raw.trim();
    if v.is_empty() {
        return Ok(None);
    }
    if !DNS_QUERY_STRATEGIES.contains(&v) {
        return Err(AppError::BadRequest(format!(
            "{field} must be one of: {}",
            DNS_QUERY_STRATEGIES.join(", ")
        )));
    }
    Ok(Some(v.to_owned()))
}

/// The routing tag stamped on the resolver's own queries.
fn validate_dns_tag(raw: &str) -> AppResult<String> {
    let tag = raw.trim();
    if tag.is_empty() {
        return Ok(String::new());
    }
    if tag.len() > 32 {
        return Err(AppError::BadRequest(
            "xray_dns_tag must be a short name".to_owned(),
        ));
    }
    // The resolver's tag lands in the same namespace the emitter's own tags
    // live in, and colliding with one would hand the resolver's queries to that
    // rule. Checked through the emitter's own validator so the reserved list
    // cannot drift away from what is actually emitted.
    crate::xray::config_gen::validate_routable_tag(tag)
        .map_err(|e| AppError::BadRequest(format!("xray_dns_tag: {e}")))?;
    Ok(tag.to_owned())
}

/// An optional bare IP (EDNS client subnet). Rejected early because the core
/// refuses to build the whole `dns` section over one bad address.
fn validate_optional_ip(raw: &str, field: &str) -> AppResult<String> {
    let v = raw.trim();
    if v.is_empty() {
        return Ok(String::new());
    }
    if v.parse::<std::net::IpAddr>().is_err() {
        return Err(AppError::BadRequest(format!("{field} must be an IP: {v}")));
    }
    Ok(v.to_owned())
}

/// One name server, in any spelling `NewServer` accepts: `localhost`, a bare
/// IP, a hostname, or a `scheme://` URL. Returns `None` for a blank entry.
///
/// Checked here rather than left to the core because a rejected `dns` block
/// takes the whole config down with it — the operator would lose every inbound
/// over a typo in a resolver address.
fn validate_dns_server(raw: &str) -> AppResult<Option<String>> {
    let entry = raw.trim();
    if entry.is_empty() {
        return Ok(None);
    }
    let bad = |why: &str| Err(AppError::BadRequest(format!("{why}: {entry}")));

    if entry.eq_ignore_ascii_case("localhost") {
        return Ok(Some("localhost".to_owned()));
    }
    // `fakedns` builds only when a fakedns section exists, which the panel does
    // not emit — accepting it here would produce a config xray refuses to load.
    if entry.eq_ignore_ascii_case("fakedns") {
        return bad("fakedns needs a fakedns section, which this panel does not write");
    }
    if let Some((scheme, rest)) = entry.split_once("://") {
        if !DNS_SCHEMES.contains(&scheme.to_ascii_lowercase().as_str()) {
            return bad(&format!(
                "dns server scheme must be one of: {}",
                DNS_SCHEMES.join(", ")
            ));
        }
        let host = rest.split(['/', ':']).next().unwrap_or("");
        if host.is_empty() {
            return bad("dns server url has no host");
        }
        return Ok(Some(entry.to_owned()));
    }
    if entry.parse::<std::net::IpAddr>().is_ok() {
        return Ok(Some(entry.to_owned()));
    }
    // A bare host is queried over plain UDP on 53. Ports belong to the object
    // form of a name server, which this field does not carry, so `1.1.1.1:5353`
    // would be read as a hostname and fail at resolve time instead of here.
    // The message names the field that does take a port, so it does not read as
    // "the panel cannot set a port".
    if entry.contains(':') {
        return bad("put the port in the Port field beside the address, not in the address");
    }
    if entry
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        && entry.contains('.')
    {
        return Ok(Some(entry.to_owned()));
    }
    bad("not a name server: expected an IP, a hostname, localhost or scheme://host")
}

#[cfg(test)]
mod tests {
    use super::{
        DnsHost, DnsServer, check_strategy_pair, clean_dns_matchers, validate_dns_hosts,
        validate_dns_server, validate_dns_server_fields,
    };
    use crate::xray::orchestrator::{check_domain_matcher, check_ip_matcher};

    fn server(json: serde_json::Value) -> DnsServer {
        serde_json::from_value(json).expect("test fixture")
    }

    fn host(domain: &str, values: &[&str]) -> DnsHost {
        DnsHost {
            domain: domain.to_owned(),
            values: values.iter().map(|v| (*v).to_owned()).collect(),
        }
    }

    /// Every spelling `app/dns/nameserver.go` can build a server from has to
    /// survive this validator, and everything else has to die here rather than
    /// in the core: a `dns` block xray refuses takes the whole config with it,
    /// so a typo in a resolver would cost the operator every inbound.
    #[test]
    fn dns_server_accepts_what_the_core_accepts() {
        for good in [
            "1.1.1.1",
            "2606:4700:4700::1111",
            "localhost",
            "LocalHost",
            "dns.google",
            "https://dns.google/dns-query",
            "https+local://1.1.1.1/dns-query",
            "h2c://10.0.0.1/dns-query",
            "quic+local://dns.adguard.com",
            "tcp://9.9.9.9",
            "tcp+local://9.9.9.9",
        ] {
            assert!(
                validate_dns_server(good).is_ok(),
                "{good} should be accepted"
            );
        }
        assert_eq!(validate_dns_server("  ").unwrap(), None);
        assert_eq!(
            validate_dns_server(" LOCALHOST ").unwrap(),
            Some("localhost".to_owned())
        );
    }

    /// A per-server strategy narrows the section-wide one instead of replacing
    /// it, so asking for one family at the top and the other at a server leaves
    /// the core with none. Checked against the real binary: that config dies
    /// with `no QueryStrategy available` — and it takes every inbound with it,
    /// because the core refuses the config as a whole rather than the server.
    #[test]
    fn dns_server_strategy_may_not_fight_the_section() {
        for (section, per_server) in [("UseIPv4", "UseIPv6"), ("UseIPv6", "UseIPv4")] {
            let err = validate_dns_server_fields(
                &server(serde_json::json!({ "address": "1.1.1.1", "query_strategy": per_server })),
                "1.1.1.1".to_owned(),
                section,
            )
            .unwrap_err()
            .to_string();
            assert!(
                err.contains(section) && err.contains(per_server),
                "{section} + {per_server} must be refused, got: {err}"
            );
        }
        // Everything else survives: neither `UseIP` nor `UseSystem` drops a
        // family, and an empty per-server value means "whatever the section
        // says".
        for (section, per_server) in [
            ("UseIP", "UseIPv6"),
            ("UseIPv4", "UseIPv4"),
            ("UseIPv4", ""),
            ("UseIPv6", "UseSystem"),
            ("UseIPv4", "UseIP"),
        ] {
            assert!(
                check_strategy_pair(section, per_server, "1.1.1.1").is_ok(),
                "{section} + {per_server} should be accepted"
            );
        }
    }

    /// The match lists reach the core as rules, not strings: a plausible-looking
    /// `cloudflare` in `expect_ips` is refused by `ParseIPRules`, and the core
    /// reports it by refusing the whole config at load. Anything the parser
    /// would choke on has to be refused here, where the operator is looking.
    #[test]
    fn dns_match_lists_are_checked_by_the_cores_parser() {
        for bad in ["cloudflare", "1.1.1.1/33", "geoip:", "ext:", "300.1.1.1"] {
            assert!(
                clean_dns_matchers("expect_ips", &[bad.to_owned()], check_ip_matcher).is_err(),
                "{bad} should be refused as an ip rule"
            );
        }
        let good = [
            "1.1.1.1",
            "10.0.0.0/8",
            "!192.168.0.0/16",
            "2606:4700::/32",
            "geoip:ru",
            // Not a rule at all — the core lifts it out as the "prioritise"
            // flag before parsing, so it has to pass through untouched.
            "*",
        ];
        let kept = clean_dns_matchers("expect_ips", &good.map(str::to_owned), check_ip_matcher)
            .expect("valid ip rules");
        assert_eq!(kept, good);

        for bad in ["geosite:cn@", "geosite:", "ext-domain:"] {
            assert!(
                clean_dns_matchers("domains", &[bad.to_owned()], check_domain_matcher).is_err(),
                "{bad} should be refused as a domain rule"
            );
        }
        assert!(
            clean_dns_matchers(
                "domains",
                &["domain:example.com".to_owned(), "geosite:cn".to_owned()],
                check_domain_matcher,
            )
            .is_ok()
        );
        // Blank rows are dropped, not refused: the editor keeps one around
        // while it is being filled in.
        assert!(
            clean_dns_matchers("domains", &["  ".to_owned()], check_domain_matcher)
                .expect("blank rows are dropped")
                .is_empty()
        );
    }

    /// `hosts` is a map on both sides of the wire, and `newHostMapping` keeps
    /// either addresses or one alias. Both shapes that lose data silently are
    /// refused here rather than half-applied.
    #[test]
    fn dns_hosts_refuse_what_the_map_would_swallow() {
        let dup = validate_dns_hosts(&[
            host("ads.example.com", &["127.0.0.1"]),
            host("ads.example.com", &["0.0.0.0"]),
        ])
        .unwrap_err()
        .to_string();
        assert!(dup.contains("ads.example.com"), "got: {dup}");

        let mixed = validate_dns_hosts(&[host("a.example.com", &["1.1.1.1", "b.example.com"])])
            .unwrap_err()
            .to_string();
        assert!(mixed.contains("a.example.com"), "got: {mixed}");

        // A key is a matcher, so it gets the same parser as a routing domain.
        assert!(validate_dns_hosts(&[host("geosite:cn@", &["127.0.0.1"])]).is_err());

        // What the core really does keep: several addresses, or one alias.
        assert!(
            validate_dns_hosts(&[
                host("geosite:category-ads-all", &["127.0.0.1"]),
                host("a.example.com", &["1.1.1.1", "2606:4700::1111"]),
                host("b.example.com", &["c.example.com"]),
            ])
            .is_ok()
        );
    }

    /// The object's `port` is read only for the plain address forms, so a port
    /// beside a url is a setting that does nothing — and an operator whose
    /// resolver listens on 5353 would never learn why it is not being used.
    #[test]
    fn dns_server_port_belongs_in_the_url() {
        assert!(
            validate_dns_server_fields(
                &server(serde_json::json!({ "address": "x", "port": 5353 })),
                "https://dns.google/dns-query".to_owned(),
                "UseIP",
            )
            .is_err()
        );
        assert!(
            validate_dns_server_fields(
                &server(serde_json::json!({ "address": "x", "port": 5353 })),
                "1.1.1.1".to_owned(),
                "UseIP",
            )
            .is_ok()
        );
    }

    #[test]
    fn dns_server_rejects_what_would_break_the_config() {
        for bad in [
            // Scheme the core has no branch for: it would fall through to a
            // classic UDP server pointed at a hostname with a colon in it.
            "udp://1.1.1.1",
            "ftp://1.1.1.1",
            // The port belongs to the object form, which this field cannot
            // carry — as a string it is read as a hostname.
            "1.1.1.1:5353",
            // Builds only with a fakedns section, which the panel never writes.
            "fakedns",
            "https://",
            "not a server",
        ] {
            assert!(validate_dns_server(bad).is_err(), "{bad} should be refused");
        }
    }
}

//! The routing half of a settings save: the basic match lists and the
//! operator's custom rules. Both emitters — proto on the hot-apply path, JSON
//! on the restart path — read what is stored here, so a rule is stored in the
//! one normalised form both agree on.

use super::store::StoredPanel;
use crate::{
    error::{AppError, AppResult},
    models::{PanelSettingsUpdate, RoutingRule},
};

/// The routing match lists, validated and serialised. A struct because six
/// positional values of which five are `String` is a swap waiting to happen,
/// and the compiler would not catch it.
pub(super) struct XrayRouting {
    pub(super) block_bittorrent: bool,
    pub(super) blocked_ips: String,
    pub(super) blocked_domains: String,
    pub(super) direct_ips: String,
    pub(super) direct_domains: String,
    pub(super) ipv4_domains: String,
}

/// Validate the routing block (the "basic connections" lists + bittorrent
/// toggle). Returns the toggle plus the match lists, each cleaned and
/// serialized as a JSON array string ready to bind into the UPDATE.
pub(super) fn validate_xray_routing(body: &PanelSettingsUpdate) -> AppResult<XrayRouting> {
    Ok(XrayRouting {
        block_bittorrent: body.xray_block_bittorrent,
        blocked_ips: validate_match_list(&body.xray_blocked_ips, "xray_blocked_ips")?,
        blocked_domains: validate_match_list(&body.xray_blocked_domains, "xray_blocked_domains")?,
        direct_ips: validate_match_list(&body.xray_direct_ips, "xray_direct_ips")?,
        direct_domains: validate_match_list(&body.xray_direct_domains, "xray_direct_domains")?,
        ipv4_domains: validate_match_list(&body.xray_ipv4_domains, "xray_ipv4_domains")?,
    })
}

/// Caps shared by every routing match list (the basic block-lists and the
/// custom-rule matchers): max entries per list, max chars per entry.
const MAX_LIST_ENTRIES: usize = 500;
const MAX_ENTRY_LEN: usize = 256;

/// Per-entry sanity for a routing match list, shared by `validate_match_list`
/// (basic block-lists) and the custom-rule matchers: cap count + length and
/// reject control chars / internal whitespace — matcher tokens (domains,
/// CIDRs, `geoip:`/`geosite:` labels, ports) never contain spaces. Blank
/// entries are tolerated (callers drop them). The real syntax check is the
/// router-config builder on the hot-apply path, or `xray run -test` on the
/// restart path.
pub(super) fn validate_list_entries(field: &str, list: &[String]) -> AppResult<()> {
    if list.len() > MAX_LIST_ENTRIES {
        return Err(AppError::BadRequest(format!(
            "{field} has too many entries (max {MAX_LIST_ENTRIES})"
        )));
    }
    for entry in list {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if e.len() > MAX_ENTRY_LEN {
            return Err(AppError::BadRequest(format!(
                "{field} entry too long (max {MAX_ENTRY_LEN} chars): {e}"
            )));
        }
        if e.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(AppError::BadRequest(format!(
                "{field} entry must not contain spaces or control characters: {e}"
            )));
        }
    }
    Ok(())
}

/// Clean one basic-block match list: validate its entries, then return the
/// trimmed non-blank survivors serialized as a JSON array string ready to bind
/// into the UPDATE.
pub(super) fn validate_match_list(list: &[String], field: &str) -> AppResult<String> {
    validate_list_entries(field, list)?;
    let cleaned: Vec<&str> = list
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    serde_json::to_string(&cleaned).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))
}

/// The set of outbound tags a custom rule may target right now: the built-in
/// outbounds (`crate::xray::config_gen::BUILTIN_OUTBOUND_TAGS`) ∪ every enabled
/// custom outbound's tag. Anything else would dangle (no such outbound), so
/// it's rejected at save time.
pub(super) async fn valid_rule_targets(
    db: &crate::db::DbPool,
) -> AppResult<std::collections::HashSet<String>> {
    let mut set: std::collections::HashSet<String> = crate::xray::config_gen::BUILTIN_OUTBOUND_TAGS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for ob in crate::api::outbounds::load_custom_outbounds(db).await? {
        // A reverse BRIDGE outbound (VLESS carrying a reverse_tag) can't be a
        // routing target: the portal rejects any non-reverse command from that
        // account, so traffic routed to a bridge's tag dead-ends on every
        // connection. Its tag is an inbound source, not a destination — skip it.
        let is_bridge = matches!(
            &ob.protocol,
            crate::models::OutboundProtocolConfig::Vless(v) if !v.reverse_tag.trim().is_empty()
        );
        if ob.enabled && !is_bridge {
            set.insert(ob.tag);
        }
    }
    // A client's reverse_tag (VLESS Reverse Proxy portal): when a bridge dials
    // in as that user, xray registers its tunnel as an outbound under the tag on
    // THIS server, so a routing rule may legally target it. Bridge-side tags
    // (custom outbound reverse_tag) are inbound sources, not targets — omitted.
    let reverse_tags = sqlx::query_scalar!(
        r#"SELECT DISTINCT reverse_tag AS "reverse_tag!: String"
           FROM clients
           WHERE reverse_tag IS NOT NULL AND reverse_tag <> ''"#
    )
    .fetch_all(db)
    .await?;
    set.extend(reverse_tags);
    Ok(set)
}

/// What the database already holds about the rules being re-saved. Grouped so
/// a new grandfathering dimension does not change the validator's signature —
/// and, more to the point, so every call site keeps passing ONE thing that
/// means "what was already true".
#[derive(Default)]
pub(super) struct StoredRules {
    /// `(rule id, outbound tag)` — a target that has since disappeared.
    targets: std::collections::HashSet<(String, String)>,
    /// `(rule id, lowercased network)` — a network the panel no longer offers.
    networks: std::collections::HashSet<(String, String)>,
}

impl StoredRules {
    pub(super) fn from_row(stored: &StoredPanel) -> Self {
        Self {
            targets: stored_rule_targets(stored),
            networks: stored_rule_networks(stored),
        }
    }
}

/// `(rule id, outbound tag)` for every rule already persisted.
///
/// A rule's target is checked against what exists *now*, but a target can
/// disappear after the rule was stored — delete the custom outbound, or clear
/// the client whose `reverse_tag` the rule pointed at, and the stored rule is
/// suddenly "invalid". Re-rejecting it on every save would wedge the whole
/// settings page: an unrelated edit (a brand name, the egress-test URL) would
/// be refused because of a rule the operator is not touching, and the only way
/// out would be to find and fix that rule first — with nothing in the UI saying
/// so. Rules that arrive unchanged are therefore grandfathered; creating or
/// re-pointing one still requires a live target.
fn stored_rule_targets(stored: &StoredPanel) -> std::collections::HashSet<(String, String)> {
    // Parsed from the snapshot the rest of the save already holds. A malformed
    // column means "no grandfathered rules", which is the safe reading: every
    // incoming rule then has to point at a live target.
    serde_json::from_str::<Vec<RoutingRule>>(&stored.custom_rules)
        .unwrap_or_default()
        .into_iter()
        .map(|r| (r.id, r.outbound_tag))
        .collect()
}

/// The `(rule id, network)` pairs already in the database. Same idea as
/// `stored_rule_targets`: a value that is already stored is already live, so
/// refusing to re-save it protects nothing and would hold every unrelated
/// setting hostage — see `check_rule_networks` for the case it covers.
fn stored_rule_networks(stored: &StoredPanel) -> std::collections::HashSet<(String, String)> {
    serde_json::from_str::<Vec<RoutingRule>>(&stored.custom_rules)
        .unwrap_or_default()
        .into_iter()
        .flat_map(|r| {
            r.network
                .into_iter()
                .map(move |n| (r.id.clone(), n.trim().to_ascii_lowercase()))
        })
        .collect()
}

/// Trim entries and drop blanks from a matcher list. Both rule emitters must
/// see identical tokens: a blank entry is a match-everything `Substr("")` to
/// xray's JSON parser but a hard error to the proto builder.
fn clean_entries(v: &[String]) -> Vec<String> {
    v.iter()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parse a port spec and return it CANONICALISED ("443", "1024-65535", joined by
/// commas) plus whether it yields any range at all. Storing the canonical form
/// keeps the JSON bootstrap and proto hot-apply paths byte-identical: xray's own
/// JSON parser does not trim around a range dash, so "1024 - 65535" would parse
/// here and be rejected by xray, silently blocking every later config write.
fn canonical_port_spec(field: &str, spec: &str, rule_name: &str) -> AppResult<(String, bool)> {
    let list = crate::xray::router_rules::parse_port_list(spec).map_err(|e| {
        AppError::BadRequest(format!(
            "custom rule '{rule_name}': invalid {field} '{spec}' ({e})"
        ))
    })?;
    let Some(list) = list else {
        return Ok((String::new(), false));
    };
    let text = list
        .range
        .iter()
        .map(|r| {
            if r.from == r.to {
                r.from.to_string()
            } else {
                format!("{}-{}", r.from, r.to)
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    Ok((text, true))
}

/// Only tcp/udp may reach the router. Anything else means the OPPOSITE thing
/// on the two config paths — the JSON emitter hands the token to xray while the
/// proto builder drops it, and a rule left with no network condition matches
/// EVERYTHING — so a new one is refused outright.
///
/// A value ALREADY in the database is kept instead, exactly like a target whose
/// outbound has since vanished: it is already live, both emitters now agree on
/// what it means (`router_rules::parse_networks` maps `unix` rather than
/// dropping it), and refusing it would only stop the operator from changing
/// anything ELSE. That is not hypothetical — an older build offered `unix` in
/// the UI, and the resulting rules blocked saving the Subscription and HTTPS
/// tabs with an error naming a routing rule the operator was not editing.
fn check_rule_networks(rule: &RoutingRule, id: &str, stored: &StoredRules) -> AppResult<()> {
    for n in &rule.network {
        let lower = n.to_ascii_lowercase();
        if matches!(lower.as_str(), "tcp" | "udp") {
            continue;
        }
        if stored.networks.contains(&(id.to_owned(), lower.clone())) {
            tracing::warn!(
                rule = %id,
                network = %lower,
                "routing rule uses a network the panel no longer offers; kept as-is"
            );
            continue;
        }
        return Err(AppError::BadRequest(format!(
            // One line on purpose: a `\`-continued literal keeps the indentation
            // of the following lines in the message text.
            "custom rule '{}': unsupported network '{n}' — use tcp or udp (fix it under Settings -> Xray -> Routing)",
            rule.name
        )));
    }
    Ok(())
}

/// Validate one operator rule and return it normalised (entries trimmed, blanks
/// dropped, ports canonicalised) — the form both emitters serialise and read, so
/// the JSON bootstrap and proto hot-apply paths always see identical tokens.
fn validate_and_clean_rule(
    r: &RoutingRule,
    valid_targets: &std::collections::HashSet<String>,
    stored: &StoredRules,
) -> AppResult<RoutingRule> {
    let id = r.id.trim();
    if id.is_empty() {
        return Err(AppError::BadRequest(
            "custom rule id must not be empty".to_owned(),
        ));
    }
    // Rule ids share the `rule_order` namespace with the system tokens, and
    // both emitters match the system arm first — an id like "ipv4" would make
    // the operator's rule silently vanish. Same size/control guard the order
    // tokens get; the id also ships as the proto rule_tag.
    if crate::xray::config_gen::SYSTEM_TOKENS.contains(&id) {
        return Err(AppError::BadRequest(format!(
            "custom rule id '{id}' is reserved"
        )));
    }
    if id.len() > 128 || id.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "invalid custom rule id '{id}'"
        )));
    }
    if !valid_targets.contains(&r.outbound_tag) {
        // Already stored with this exact target: its outbound vanished after the
        // fact. Warn and carry on — the rule is already dead at runtime, so
        // refusing the save protects nothing and would hold every other setting
        // hostage. Everything below still runs, so a grandfathered rule is
        // normalised exactly like any other.
        if stored
            .targets
            .contains(&(id.to_owned(), r.outbound_tag.clone()))
        {
            tracing::warn!(
                rule = %id,
                target = %r.outbound_tag,
                "routing rule points at an outbound that no longer exists; kept as-is"
            );
        } else {
            let mut known: Vec<&str> = valid_targets.iter().map(String::as_str).collect();
            known.sort_unstable();
            return Err(AppError::BadRequest(format!(
                "custom rule '{}' targets '{}', which is not a known outbound (valid: {})",
                r.name.trim(),
                r.outbound_tag,
                known.join(", ")
            )));
        }
    }
    if r.name.chars().count() > 80 {
        return Err(AppError::BadRequest(
            "custom rule name too long (max 80 chars)".to_owned(),
        ));
    }
    validate_list_entries("domain", &r.domain)?;
    validate_list_entries("ip", &r.ip)?;
    validate_list_entries("source_ip", &r.source_ip)?;
    validate_list_entries("network", &r.network)?;
    validate_list_entries("protocol", &r.protocol)?;
    validate_list_entries("inbound_tag", &r.inbound_tag)?;
    validate_list_entries("user", &r.user)?;
    check_port_field("port", &r.port)?;
    check_port_field("source_port", &r.source_port)?;
    // Normalise matcher lists (trim, drop blanks) before anything else sees
    // them: a blank entry means "match everything" to xray's JSON parser but
    // is a hard error to the proto builder, so leaving it in would make the
    // restart and hot-apply paths behave differently.
    // Ports are stored CANONICALISED (rebuilt from the parse result), not as
    // typed. The two emitters disagree on whitespace: parse_port_list trims
    // both sides of a range, xray's JSON parser trims only around commas and
    // hands " 65535" straight to ParseUint, which rejects it. Storing the
    // canonical form makes both serialise the identical, xray-parsable spec.
    let (port, port_has_range) = canonical_port_spec("port", &r.port, &r.name)?;
    let (source_port, source_port_has_range) =
        canonical_port_spec("source_port", &r.source_port, &r.name)?;
    let has_port_matcher = port_has_range || source_port_has_range;
    let cleaned_rule = crate::models::RoutingRule {
        id: r.id.clone(),
        enabled: r.enabled,
        name: r.name.clone(),
        domain: clean_entries(&r.domain),
        ip: clean_entries(&r.ip),
        source_ip: clean_entries(&r.source_ip),
        port,
        source_port,
        network: clean_entries(&r.network),
        protocol: clean_entries(&r.protocol),
        inbound_tag: clean_entries(&r.inbound_tag),
        user: clean_entries(&r.user),
        local_os: clean_entries(&r.local_os),
        outbound_tag: r.outbound_tag.clone(),
    };
    // tcp/udp only — see `check_rule_networks`. Its error names where to fix the
    // rule because the operator usually meets it while saving an unrelated tab.
    check_rule_networks(&cleaned_rule, id, stored)?;
    // A rule with no matcher (only an outbound_tag) is rejected by xray at
    // router build ("this rule has no effective fields"), which fails the
    // config `-test` and bricks the next restart. Checked on the CLEANED
    // rule so a matcher that was only blank entries counts as absent.
    let has_matcher = !cleaned_rule.domain.is_empty()
        || !cleaned_rule.ip.is_empty()
        || !cleaned_rule.source_ip.is_empty()
        || !cleaned_rule.network.is_empty()
        || !cleaned_rule.protocol.is_empty()
        || !cleaned_rule.inbound_tag.is_empty()
        || !cleaned_rule.user.is_empty()
        || has_port_matcher;
    if !has_matcher {
        return Err(AppError::BadRequest(format!(
            "custom rule '{}' has no match conditions — add at least one \
             (e.g. a network or domain); xray rejects a condition-less rule",
            cleaned_rule.name
        )));
    }
    Ok(cleaned_rule)
}

/// Validate the operator's custom routing rules + order tokens, returning the
/// pair of JSON strings ready to bind into the UPDATE (rules normalised via
/// `validate_and_clean_rule`). Light validation only — the router-config builder
/// (hot-apply) or `xray run -test` (restart) is the real syntax check; this
/// stops obviously-broken input (bad target, control chars, runaway sizes).
pub(super) fn validate_custom_routing(
    body: &PanelSettingsUpdate,
    valid_targets: &std::collections::HashSet<String>,
    stored: &StoredRules,
) -> AppResult<(String, String)> {
    if body.xray_custom_rules.len() > 200 {
        return Err(AppError::BadRequest(
            "too many custom rules (max 200)".to_owned(),
        ));
    }
    let mut cleaned: Vec<crate::models::RoutingRule> =
        Vec::with_capacity(body.xray_custom_rules.len());
    for r in &body.xray_custom_rules {
        cleaned.push(validate_and_clean_rule(r, valid_targets, stored)?);
    }
    // Ids key the evaluation order, and that order is de-duplicated — a repeated
    // id would silently drop one of the rules instead of applying both.
    let mut ids = std::collections::HashSet::with_capacity(cleaned.len());
    for r in &cleaned {
        if !ids.insert(r.id.as_str()) {
            return Err(AppError::BadRequest(format!(
                "duplicate custom rule id '{}'",
                r.id
            )));
        }
    }

    if body.xray_rule_order.len() > 1000 {
        return Err(AppError::BadRequest("rule order is too long".to_owned()));
    }
    for tok in &body.xray_rule_order {
        if tok.len() > 128 || tok.chars().any(char::is_control) {
            return Err(AppError::BadRequest("invalid rule order token".to_owned()));
        }
    }

    let custom =
        serde_json::to_string(&cleaned).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    let order = serde_json::to_string(&body.xray_rule_order)
        .map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    Ok((custom, order))
}

/// A port / sourcePort field: free-form ("443", "1024-65535", "80, 443") — a
/// size + control-char guard only. `canonical_port_spec` is the syntax
/// authority and rewrites the value into its canonical form. Empty means
/// "any port".
fn check_port_field(field: &str, value: &str) -> AppResult<()> {
    let t = value.trim();
    if t.is_empty() {
        return Ok(());
    }
    if t.len() > 128 {
        return Err(AppError::BadRequest(format!("{field} is too long")));
    }
    if t.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "{field} must not contain control characters: {t}"
        )));
    }
    // Interior spaces are fine — the port input's own placeholder shows
    // "443, 1024-65535", and both consumers trim each part. `parse_port_list`
    // (called on the cleaned rule) is the actual syntax authority.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(names: &[&str]) -> std::collections::HashSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    /// No rule is already persisted, so nothing is grandfathered and every
    /// guard below is exercised at full strength.
    fn nothing_stored() -> StoredRules {
        StoredRules::default()
    }

    fn rule(id: &str) -> RoutingRule {
        RoutingRule {
            id: id.to_string(),
            enabled: true,
            name: String::new(),
            domain: vec![],
            ip: vec![],
            source_ip: vec![],
            port: String::new(),
            source_port: String::new(),
            network: vec!["tcp".to_string()],
            protocol: vec![],
            inbound_tag: vec![],
            user: vec![],
            local_os: vec![],
            outbound_tag: "direct".to_string(),
        }
    }

    /// This is the only gate between operator input and BOTH emitters (proto on
    /// the hot path, JSON on the restart path), and each guard below exists
    /// because the two disagree about the input it rejects. A rule that slips
    /// through here does not fail loudly — it either silently never matches, or
    /// it fails to build inside xray, which wipes the whole live rule set.
    #[test]
    fn rule_validation_rejects_what_the_emitters_disagree_on() {
        let ok = targets(&["direct", "blocked", "relay-jp"]);

        // A system token as an id is matched by the SYSTEM_TOKENS arm first in
        // both emitters, so the operator's rule would silently vanish.
        for reserved in crate::xray::config_gen::SYSTEM_TOKENS {
            let mut r = rule(reserved);
            r.outbound_tag = "direct".to_string();
            assert!(
                validate_and_clean_rule(&r, &ok, &nothing_stored()).is_err(),
                "reserved id '{reserved}' must be rejected"
            );
        }

        // Rejected for two different reasons, both worth keeping. `quic` and
        // `TCP,udp` are unknown to xray's parser and become Network_Unknown —
        // a rule that never fires. `unix` IS known to xray (Network_UNIX), but
        // no traffic through a panel inbound is ever a unix socket, so the rule
        // could not match anything either. Both would be no-ops the operator
        // believes in, so neither is allowed to be stored.
        for bad in ["quic", "unix", "TCP,udp"] {
            let mut r = rule("r1");
            r.network = vec![bad.to_string()];
            assert!(
                validate_and_clean_rule(&r, &ok, &nothing_stored()).is_err(),
                "network '{bad}' must be rejected"
            );
        }

        // Already in the database: kept, warned about, and — crucially — NOT
        // allowed to block the save. An older build offered `unix` in the UI,
        // so operators have such rules stored; refusing them here meant the
        // Subscription and HTTPS tabs could not be saved either, with an error
        // naming a routing rule the operator was not editing.
        let mut r = rule("r-unix");
        r.network = vec!["unix".to_string()];
        let stored = StoredRules {
            networks: std::collections::HashSet::from([("r-unix".to_string(), "unix".to_string())]),
            ..StoredRules::default()
        };
        let kept = validate_and_clean_rule(&r, &ok, &stored)
            .expect("a stored network must not block the save");
        assert_eq!(kept.network, vec!["unix".to_string()]);
        // The same value on a DIFFERENT rule id is still new, so still refused.
        let mut other = rule("r-new");
        other.network = vec!["unix".to_string()];
        assert!(
            validate_and_clean_rule(&other, &ok, &stored).is_err(),
            "a network that is not already stored must still be rejected"
        );

        // A blank entry is a match-everything Substr to xray's JSON parser and
        // a hard error on the proto path.
        let mut r = rule("r1");
        r.domain = vec!["  ".to_string(), String::new()];
        r.network = vec![];
        assert!(
            validate_and_clean_rule(&r, &ok, &nothing_stored()).is_err(),
            "a rule whose only matcher is blank has no conditions"
        );

        // Blanks are stripped rather than forwarded, and surviving entries trimmed.
        let mut r = rule("r1");
        r.domain = vec![" a.com ".to_string(), String::new(), "b.com".to_string()];
        let cleaned = validate_and_clean_rule(&r, &ok, &nothing_stored()).unwrap();
        assert_eq!(
            cleaned.domain,
            vec!["a.com".to_string(), "b.com".to_string()]
        );

        // Ports are stored canonicalised, so the JSON emitter never sees the
        // interior whitespace it would reject.
        let mut r = rule("r1");
        r.port = " 443, 1024 - 65535 ".to_string();
        assert_eq!(
            validate_and_clean_rule(&r, &ok, &nothing_stored())
                .unwrap()
                .port,
            "443,1024-65535"
        );

        // An outbound that isn't there would dangle in the pushed rule set.
        let mut r = rule("r1");
        r.outbound_tag = "relay-de".to_string();
        assert!(validate_and_clean_rule(&r, &ok, &nothing_stored()).is_err());
        r.outbound_tag = "relay-jp".to_string();
        assert!(validate_and_clean_rule(&r, &ok, &nothing_stored()).is_ok());
    }

    /// A target can vanish after its rule was stored — the custom outbound is
    /// deleted, or the client whose `reverse_tag` the rule pointed at loses it.
    /// Re-rejecting the stored rule would wedge the entire settings page: an
    /// unrelated edit elsewhere in the form would be refused because of a rule
    /// the operator never touched.
    #[test]
    fn stored_rule_with_a_vanished_target_does_not_block_unrelated_saves() {
        let ok = targets(&["direct", "blocked"]);
        let mut r = rule("r1");
        r.outbound_tag = "my_user_1_pc".to_string();

        // Never stored → this is the operator pointing a rule at nothing.
        assert!(validate_and_clean_rule(&r, &ok, &nothing_stored()).is_err());

        // Stored with this exact target → grandfathered, and still normalised
        // like any other rule rather than passed through raw.
        let stored = StoredRules {
            targets: std::collections::HashSet::from([(
                "r1".to_string(),
                "my_user_1_pc".to_string(),
            )]),
            ..StoredRules::default()
        };
        r.port = " 1024 - 2048 ".to_string();
        let cleaned = validate_and_clean_rule(&r, &ok, &stored).expect("stored rule is kept");
        assert_eq!(cleaned.outbound_tag, "my_user_1_pc");
        assert_eq!(
            cleaned.port, "1024-2048",
            "grandfathered rules are still cleaned"
        );

        // Re-pointing a stored rule at another dead tag is a fresh mistake.
        r.outbound_tag = "some_other_ghost".to_string();
        assert!(validate_and_clean_rule(&r, &ok, &stored).is_err());
    }

    /// Ports are stored canonicalised because the two emitters disagree on
    /// whitespace: xray's own JSON parser does NOT trim around a range dash and
    /// would reject " 65535", which would then block every later config write
    /// (and stop xray from starting on a cold boot).
    #[test]
    fn port_specs_are_canonicalised_for_both_emitters() {
        let (spec, has_range) = canonical_port_spec("port", " 1024 - 65535 ", "r").unwrap();
        assert_eq!(spec, "1024-65535");
        assert!(has_range);

        let (spec, _) = canonical_port_spec("port", "443, 8080 - 8090", "r").unwrap();
        assert_eq!(spec, "443,8080-8090");

        // No ranges at all: not a matcher, and stored empty.
        let (spec, has_range) = canonical_port_spec("port", ",,", "r").unwrap();
        assert_eq!(spec, "");
        assert!(!has_range);

        assert!(canonical_port_spec("port", "70000", "r").is_err());
        assert!(canonical_port_spec("port", "abc", "r").is_err());
    }
}

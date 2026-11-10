//! Checks for the panel, subscription and engine fields, and the resolution of
//! the two TLS pairs. Every bound here is a mistake the OS, xray or a share
//! link would otherwise trip over later — after the row is already stored.

use super::{
    dns::{XrayDns, validate_xray_dns},
    routing::{XrayRouting, validate_match_list, validate_xray_routing},
    store::StoredPanel,
};
use crate::{
    error::{AppError, AppResult},
    models::PanelSettingsUpdate,
};
use axum_server::tls_rustls::RustlsConfig;

/// Validated + normalised form of a `PanelSettingsUpdate`. Owns its
/// strings so the caller can bind them straight into the UPDATE.
pub(super) struct NormalizedPanel {
    pub(super) new_port: u16,
    pub(super) base_path: String,
    pub(super) sub_host: String,
    pub(super) sub_link_host: String,
    pub(super) sub_brand: String,
    pub(super) sub_service_url: String,
    /// The engine settings that only reach xray through the config file:
    /// both `domainStrategy` values, the test URL, and the private-range
    /// allow-list. Grouped rather than left as four loose strings — they are
    /// validated together and bound consecutively, and four positional
    /// `String`s is a swap the compiler cannot catch.
    pub(super) engine: XrayEngine,
    /// The routing switch and its match lists, cleaned + serialised as JSON
    /// arrays. Kept as one field rather than six flat ones: they travel
    /// together into the UPDATE and into the change check, and six positional
    /// strings is a swap the compiler cannot catch.
    pub(super) routing: XrayRouting,
    /// The core's own resolver. Not part of `XrayRouting`: routing fields are
    /// pushed into the running xray, while a name server only exists in the
    /// config file and needs a restart to take effect.
    pub(super) dns: XrayDns,
}

/// Canonicalise the panel base path: empty OR leading-slash + no trailing
/// slash, restricted to URL-safe chars. Single "/" collapses to "" so two
/// stored values can't mean the same mount point.
fn normalize_base_path(raw: &str) -> AppResult<String> {
    let prefix_raw = raw.trim();
    if prefix_raw.is_empty() || prefix_raw == "/" {
        return Ok(String::new());
    }
    let trimmed = prefix_raw.trim_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '/')
    {
        return Err(AppError::BadRequest(
            "panel_base_path may only contain letters, digits, '-', '_', '/'".to_owned(),
        ));
    }
    // The panel is nested UNDER this prefix while three paths stay mounted at
    // the root beside it (`main::build_router`). Taking one of their names is
    // not a routing curiosity: `healthz` makes axum panic on the duplicate
    // route, and with `panic = "abort"` in the release profile that kills the
    // process — after the new prefix is already committed, so the panel would
    // abort again on every boot until someone edited the row by hand. `sub` and
    // `assets` do not panic; they shadow the public subscription endpoint and
    // the asset files, which is its own kind of unrecoverable.
    let head = trimmed.split('/').next().unwrap_or(trimmed);
    if ROOT_MOUNTED_PATHS.contains(&head) {
        return Err(AppError::BadRequest(format!(
            "panel_base_path may not start with '{head}': that path is served at the root ({})",
            ROOT_MOUNTED_PATHS.join(", ")
        )));
    }
    Ok(format!("/{trimmed}"))
}

/// Paths `main::build_router` mounts at the root, outside the panel's prefix.
/// A prefix may not begin with any of them — see `normalize_base_path`.
const ROOT_MOUNTED_PATHS: &[&str] = &["healthz", "sub", "assets"];

/// Validate and normalise an incoming panel-settings PATCH. Pure (no DB,
/// no listener state) — every bound here is an operator mistake the OS or
/// the share-link builder would otherwise choke on.
pub(super) fn validate_panel_update(body: &PanelSettingsUpdate) -> AppResult<NormalizedPanel> {
    // Port must fit a real TCP port. Anything outside [1, 65535] is a
    // definite operator mistake the OS would refuse to bind anyway — fail
    // loud here so the operator sees it in the form, not in tomorrow's log.
    if !(1..=65535).contains(&body.panel_port) {
        return Err(AppError::BadRequest(
            "panel_port must be between 1 and 65535".to_owned(),
        ));
    }
    let new_port = u16::try_from(body.panel_port).expect("range-checked above");

    let base_path = normalize_base_path(&body.panel_base_path)?;

    // Two subscription hosts, same shape (bare hostname / IPv4 / bracketed
    // IPv6, no scheme/path/spaces): `sub_host_override` is the server address
    // spliced into each config as an `@host:port` chunk; `sub_link_host` is
    // the host of the subscription URL itself. A stray `https://` or `/foo`
    // in either breaks the link, so both are validated the same way.
    let sub_host = validate_optional_host(&body.sub_host_override, "sub_host_override")?;
    let sub_link_host = validate_optional_host(&body.sub_link_host, "sub_link_host")?;

    // Update interval: <1h hammers the panel; >1week stalls config
    // rotation. Bounds mirror what v2rayN / Hiddify actually honour.
    if !(1..=168).contains(&body.sub_update_interval_hours) {
        return Err(AppError::BadRequest(
            "sub_update_interval_hours must be between 1 and 168 (one week)".to_owned(),
        ));
    }

    // Brand name: strip control chars, cap at 60. Empty = "no override".
    // The strict filter keeps it safe to embed in both a response header
    // and the React hero text without per-site escaping.
    let sub_brand = body
        .sub_brand_name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>();
    if sub_brand.chars().count() > 60 {
        return Err(AppError::BadRequest(
            "sub_brand_name is too long (max 60 chars)".to_owned(),
        ));
    }

    // Service URL: empty OR `http(s)://` + content. Restricting the scheme
    // blocks `javascript:` / `data:` payloads from the landing page's `<a href>`.
    let sub_service_url = validate_optional_http_url(&body.sub_service_url, "sub_service_url")?;

    // Sub-port: 0 = disabled OR valid TCP port, and must differ from the
    // panel port (binding the same port twice conflicts AND lets the full
    // API listener shadow the sub-only router — the opposite of intent).
    if body.sub_port != 0 && !(1..=65535).contains(&body.sub_port) {
        return Err(AppError::BadRequest(
            "sub_port must be 0 (disabled) or a valid TCP port (1..=65535)".to_owned(),
        ));
    }
    if body.sub_port != 0 && body.sub_port == body.panel_port {
        return Err(AppError::BadRequest(
            "sub_port must differ from panel_port".to_owned(),
        ));
    }

    let engine = validate_xray_settings(body)?;
    let routing = validate_xray_routing(body)?;
    let dns = validate_xray_dns(body)?;

    Ok(NormalizedPanel {
        new_port,
        base_path,
        sub_host,
        sub_link_host,
        sub_brand,
        sub_service_url,
        engine,
        routing,
        dns,
    })
}

/// xray freedom-outbound `domainStrategy` values the panel accepts. xray
/// would reject anything else at config-validate time anyway; checking here
/// turns a would-be failed restart into a clean 400 at save time.
const FREEDOM_STRATEGIES: &[&str] = &[
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv6v4",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv6v4",
];
/// xray routing-block `domainStrategy` values.
const ROUTING_STRATEGIES: &[&str] = &["AsIs", "IPIfNonMatch", "IPOnDemand"];

/// The engine half of the panel settings: the two `domainStrategy` values,
/// the outbound test URL, and the freedom private-range allow-list, all
/// trimmed and ready to bind. `allow_private` is already a JSON array string,
/// like every other stored match list.
pub(super) struct XrayEngine {
    pub(super) freedom_strategy: String,
    pub(super) routing_strategy: String,
    pub(super) test_url: String,
    pub(super) allow_private: String,
    pub(super) block_delay: String,
}

/// Validate the xray engine settings (Freedom/routing `domainStrategy`, test
/// URL, private allow-list). Split out of `validate_panel_update` to keep that
/// function under the line cap.
fn validate_xray_settings(body: &PanelSettingsUpdate) -> AppResult<XrayEngine> {
    // Freedom / routing domainStrategy: only values xray accepts, else the
    // next restart's config-validate fails and leaves the engine down.
    let freedom = body.xray_freedom_strategy.trim();
    if !FREEDOM_STRATEGIES.contains(&freedom) {
        return Err(AppError::BadRequest(format!(
            "xray_freedom_strategy must be one of: {}",
            FREEDOM_STRATEGIES.join(", ")
        )));
    }
    let routing = body.xray_routing_strategy.trim();
    if !ROUTING_STRATEGIES.contains(&routing) {
        return Err(AppError::BadRequest(format!(
            "xray_routing_strategy must be one of: {}",
            ROUTING_STRATEGIES.join(", ")
        )));
    }

    // Test URL: empty OR `http(s)://` + content (same rule the test endpoint
    // enforces on use). Scheme restriction blocks file:// and the like.
    let test_url = validate_optional_http_url(&body.xray_test_url, "xray_test_url")?;

    // Same matcher syntax as every other IP list, so the same entry rules
    // apply. What it MEANS is different: entries here reopen destinations the
    // core blocks on purpose, so the operator is widening reach, not narrowing
    // it. Nothing is special-cased — a list of one `/32` and a list containing
    // `0.0.0.0/0` are both exactly what was asked for.
    let allow_private = validate_match_list(
        &body.xray_freedom_allow_private,
        "xray_freedom_allow_private",
    )?;

    Ok(XrayEngine {
        freedom_strategy: freedom.to_owned(),
        routing_strategy: routing.to_owned(),
        test_url,
        allow_private,
        block_delay: validate_block_delay(&body.xray_freedom_block_delay)?,
    })
}

/// Longest stall the panel will ask the core to hold a doomed connection for.
/// Not an xray limit: a block delay is a socket kept open on purpose, and one
/// measured in hours is a resource leak wearing a censorship-resistance hat.
const MAX_BLOCK_DELAY_SECS: u32 = 600;

/// `blockDelay` as xray's `Int32Range` spells it: a number of seconds, or
/// `"min-max"`. Returned canonicalised to `"min-max"` so the emitted JSON is
/// unambiguous whichever form the operator typed.
///
/// Empty stays empty, and the emitter then omits the key entirely — which is
/// what leaves the core on its own 30~90 seconds. Writing `"0-0"` instead would
/// mean "block instantly", the opposite of the default.
fn validate_block_delay(value: &str) -> AppResult<String> {
    let v = value.trim();
    if v.is_empty() {
        return Ok(String::new());
    }
    let bad = || {
        AppError::BadRequest(format!(
            "xray_freedom_block_delay must be seconds or a range like 30-90, got '{v}'"
        ))
    };
    let secs = |s: &str| s.trim().parse::<u32>().map_err(|_| bad());
    let (from, to) = if let Some((a, b)) = v.split_once('-') {
        (secs(a)?, secs(b)?)
    } else {
        let n = secs(v)?;
        (n, n)
    };
    if from > to {
        return Err(AppError::BadRequest(format!(
            "xray_freedom_block_delay range runs backwards: '{v}'"
        )));
    }
    if to > MAX_BLOCK_DELAY_SECS {
        return Err(AppError::BadRequest(format!(
            "xray_freedom_block_delay must be at most {MAX_BLOCK_DELAY_SECS} seconds"
        )));
    }
    Ok(format!("{from}-{to}"))
}

/// Validate an optional bare-host field (hostname / IPv4 / bracketed IPv6):
/// empty is allowed; otherwise no scheme, path, query, or spaces, capped at
/// the DNS FQDN limit (253). Shared by both subscription host fields
/// (`sub_host_override`, `sub_link_host`). Returns the trimmed value ready to
/// store; `field` is spliced into the error so the messages name the culprit.
fn validate_optional_host(value: &str, field: &str) -> AppResult<String> {
    let host = value.trim();
    if !host.is_empty() {
        if host.contains("://") || host.contains('/') || host.contains('?') || host.contains(' ') {
            return Err(AppError::BadRequest(format!(
                "{field} must be a bare hostname or IP — no scheme, path, or spaces"
            )));
        }
        if host.len() > 253 {
            return Err(AppError::BadRequest(format!(
                "{field} is too long (max 253 chars)"
            )));
        }
    }
    Ok(host.to_owned())
}

/// Validate an optional `http(s)://` URL field. Empty is allowed; otherwise the
/// value must contain no control characters, start with `http://` or
/// `https://`, be at most 2048 chars, and parse as a URL with a non-empty host.
/// Returns the trimmed value ready to store. `field` is spliced into the error
/// messages so the sub-service and xray-test URL validators share one
/// implementation.
pub fn validate_optional_http_url(value: &str, field: &str) -> AppResult<String> {
    let url = value.trim();
    if !url.is_empty() {
        if url.chars().any(char::is_control) {
            return Err(AppError::BadRequest(format!(
                "{field} contains control characters"
            )));
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(format!(
                "{field} must start with http:// or https://"
            )));
        }
        if url.len() > 2048 {
            return Err(AppError::BadRequest(format!(
                "{field} is too long (max 2048 chars)"
            )));
        }
        // Full parse, not just the prefix: a value like `http://` (no host) or
        // `http://a b` (space) passes the checks above but fails reqwest at
        // request time, where the outbound test would surface it as a
        // misattributed "no egress". Reject it here as a clear config error.
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| AppError::BadRequest(format!("{field} is not a valid URL: {e}")))?;
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(AppError::BadRequest(format!("{field} has no host")));
        }
    }
    Ok(url.to_owned())
}

/// Resolve + validate the panel TLS fields for a settings write. An empty
/// incoming key keeps the stored one (so saving any other section can't wipe
/// it); enabling HTTPS requires both halves and that they form a usable pair.
/// Returns `(enabled_flag, cert_pem, key_pem)` ready to bind into the UPDATE.
pub(super) async fn resolve_panel_tls(
    stored: &StoredPanel,
    body: &PanelSettingsUpdate,
) -> AppResult<(i64, String, String)> {
    let stored_key = stored.panel_tls_key.clone();
    let cert = body.panel_tls_cert.trim().to_owned();
    let key = if body.panel_tls_key.trim().is_empty() {
        stored_key
    } else {
        body.panel_tls_key.trim().to_owned()
    };
    if body.panel_tls_enabled {
        if cert.is_empty() || key.is_empty() {
            return Err(AppError::BadRequest(
                "HTTPS requires both a certificate and a private key".to_owned(),
            ));
        }
        RustlsConfig::from_pem(cert.clone().into_bytes(), key.clone().into_bytes())
            .await
            .map_err(|e| {
                AppError::BadRequest(format!("invalid TLS certificate or private key: {e}"))
            })?;
    }
    Ok((i64::from(body.panel_tls_enabled), cert, key))
}

/// Resolve + validate the subscription TLS fields. Mode is normalised to
/// `inherit` | `off` | `custom` (anything else ≡ `inherit`). An empty incoming
/// cert OR key keeps the stored one — the custom-cert form fields are unmounted
/// outside `custom` mode (so a save from another section, or in inherit/off,
/// sends them empty and must not wipe a stored pair). `custom` requires both
/// halves and a usable pair. Returns `(mode, cert_pem, key_pem, changed)`, where
/// `changed` (any of mode/cert/key differs from stored) drives the live
/// force-rebind of the sub listener.
pub(super) async fn resolve_sub_tls(
    stored: &StoredPanel,
    body: &PanelSettingsUpdate,
) -> AppResult<(String, String, String, bool)> {
    let mode = match body.sub_tls_mode.trim() {
        "off" => "off",
        "custom" => "custom",
        _ => "inherit",
    }
    .to_owned();
    let cert = if body.sub_cert_pem.trim().is_empty() {
        stored.sub_cert_pem.clone()
    } else {
        body.sub_cert_pem.trim().to_owned()
    };
    let key = if body.sub_key_pem.trim().is_empty() {
        stored.sub_key_pem.clone()
    } else {
        body.sub_key_pem.trim().to_owned()
    };
    if mode == "custom" {
        if cert.is_empty() || key.is_empty() {
            return Err(AppError::BadRequest(
                "custom subscription TLS requires both a certificate and a private key".to_owned(),
            ));
        }
        RustlsConfig::from_pem(cert.clone().into_bytes(), key.clone().into_bytes())
            .await
            .map_err(|e| {
                AppError::BadRequest(format!(
                    "invalid subscription certificate or private key: {e}"
                ))
            })?;
    }
    // The sub listener binds its TLS once at spawn, so any change here needs a
    // live rebind even when the port is unchanged — signal it to the caller.
    let changed =
        mode != stored.sub_tls_mode || cert != stored.sub_cert_pem || key != stored.sub_key_pem;
    Ok((mode, cert, key, changed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prefix that shadows one of the root mounts is refused at the door.
    /// `healthz` is the fatal one — axum panics on the duplicate route, and the
    /// release profile aborts on panic, after the value is already stored. The
    /// second half of this test is the proof of that: the router shape
    /// `build_router` produces really does panic, so the validator above is the
    /// only thing standing between an operator and a panel that cannot boot.
    #[test]
    fn base_path_may_not_shadow_a_root_mount() {
        for taken in ROOT_MOUNTED_PATHS {
            let err = normalize_base_path(taken).unwrap_err().to_string();
            assert!(err.contains(taken), "{taken} must be refused, got: {err}");
            let nested = normalize_base_path(&format!("{taken}/panel")).unwrap_err();
            assert!(
                nested.to_string().contains(taken),
                "{taken}/panel must be refused"
            );
        }
        // A name that merely CONTAINS a reserved word is fine.
        assert_eq!(normalize_base_path("healthzone").unwrap(), "/healthzone");
        assert_eq!(normalize_base_path("my/sub").unwrap(), "/my/sub");
    }

    /// The panic the rule above exists to prevent, demonstrated on the same
    /// router shape `main::build_router` assembles.
    #[test]
    fn nesting_under_healthz_would_panic_the_router() {
        let build = || {
            let inner = axum::Router::<()>::new().route("/", axum::routing::get(|| async { "" }));
            axum::Router::<()>::new()
                .nest("/healthz", inner)
                .route("/healthz", axum::routing::get(|| async { "ok" }))
        };
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(build)).is_err();
        assert!(panicked, "axum accepted the overlapping /healthz route");
    }
}

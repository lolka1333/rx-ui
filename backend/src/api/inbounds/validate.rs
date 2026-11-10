//! The gate every inbound create and update passes before anything is
//! written. xray refuses most of these combinations itself, but only at
//! `AddInbound` — after the row is committed — and a few it accepts and then
//! panics on, or builds and never applies. Refusing them here keeps what the
//! panel stores and what the core runs from drifting apart.
//!
//! `validate_finalmask` is shared with `api::outbounds`: both write paths feed
//! the same xray process, so a combination that is inert or fatal on one side
//! is inert or fatal on the other.

use crate::{
    error::{AppError, AppResult},
    protocols::{
        ProtocolConfig,
        vless::{VlessEncryptionMode, VlessFlow},
    },
    security::SecurityConfig,
    transports::{
        TransportConfig,
        finalmask::{FinalMask, FinalMaskScope},
        xhttp::XhttpMode,
    },
    xray::keygen,
};

#[cfg(test)]
mod tests;

/// Whether this host can SERVE XICMP. The panel and the xray it drives share a
/// machine, so the panel's own target is the answer. A named constant rather
/// than an inline `cfg!`, so the check below stays an ordinary expression on
/// every target instead of folding into a literal on one of them.
const HOST_SERVES_XICMP: bool = cfg!(target_os = "linux");

/// An XICMP server has to RECEIVE Echo Requests, and only Linux passes those
/// up to a program. Windows and the BSDs answer them in the kernel and never
/// hand them on — measured on Windows: a second raw ICMP socket sees the
/// kernel's Echo Reply and never the request. xray reflects the same split:
/// the server that reads requests is `finalmask/xicmp/server_oob.go`, built
/// for Linux only. Off Linux the inbound would save, start, and never see a
/// packet, which is the silence `validate_finalmask` refuses for a mask on the
/// wrong registry — so it follows the same `check_matrix` rule.
///
/// Inbound only. The client side works everywhere: replies ARE delivered to
/// a raw socket, Windows included.
fn validate_xicmp_host(finalmask: &FinalMask, check: bool) -> AppResult<()> {
    if check && !HOST_SERVES_XICMP && matches!(finalmask, FinalMask::Xicmp(_)) {
        return Err(AppError::BadRequest(
            "XICMP inbounds need a Linux server: this OS answers pings in the kernel and \
             never passes the requests on to xray"
                .to_owned(),
        ));
    }
    Ok(())
}

/// `FinalMask` cross-checks against the transport and the security layer.
/// Split out of `validate_layers` to keep that function readable, and shared
/// with `api::outbounds`: both write paths feed the SAME xray process, so a
/// combination that is inert or fatal on one side is inert or fatal on the
/// other. The caller supplies its own error prefix.
pub fn validate_finalmask(
    transport: &TransportConfig,
    security: &SecurityConfig,
    finalmask: &FinalMask,
    check_matrix: bool,
) -> AppResult<()> {
    // A mask outside the matrix is not an error in xray — it builds, the
    // inbound starts, and the mask never runs, because the transport only ever
    // consults the other registry. Refusing it here is the difference between
    // "obfuscation you don't have" and "obfuscation you think you have".
    //
    // `check_matrix` is off when the caller is carrying a stored mask forward
    // untouched. Rows predating this rule exist (the form used to offer all
    // five masks on every transport), and refusing them unconditionally would
    // mean a PATCH of `{enabled: false}` gets a 400 about a mask the operator
    // can no longer even see in the dropdown — an inbound that is live and
    // unmanageable. A mask that silently does nothing is cosmetic; a mask the
    // operator is actively choosing is not, and that is the case this guards.
    // The gates below are NOT conditional: they cover crashes, not cosmetics.
    //
    // Judged by `is_configured`, not `is_active`: XMC's keys are derived after
    // this runs on the create path, so `is_active` is false there for every
    // freshly submitted XMC mask and the whole check would be dead for it.
    if check_matrix && finalmask.is_configured() {
        let allowed = crate::transports::finalmask::supported_kinds(
            transport.as_transport().kind(),
            security.as_security().kind(),
        );
        if !allowed.contains(&finalmask.kind()) {
            return Err(AppError::BadRequest(format!(
                "FinalMask '{}' does not work with transport '{}' and security \
                 '{}' — xray would build it and never apply it. Supported here: {}.",
                finalmask.kind(),
                transport.as_transport().kind().as_db_str(),
                security.as_security().kind().as_db_str(),
                if allowed.is_empty() {
                    "none".to_owned()
                } else {
                    allowed.join(", ")
                },
            )));
        }
    }

    // Same trap one level down. XHTTP negotiating HTTP/3 is QUIC underneath:
    // the listener gates the wrapper on `!l.isH3` (`splithttp/hub.go:540`) and
    // the dialer goes through `http3.Transport`, which never calls the
    // masking dialer at all. `isH3` is decided by ALPN being exactly `h3` —
    // compared the same way the core compares it, so `["h3","h3"]` (which the
    // core runs over HTTP/2) is not falsely rejected here.
    //
    // Gated by scope rather than by variant: this catches every mask that
    // lives only in the TCP registry — XMC and Fragment today. Sudoku is
    // registered in the UDP one as well and keeps masking over h3. Same
    // severity as the matrix above (silently inert, not fatal), so it carries
    // the same `check_matrix` escape for stored values.
    if check_matrix
        && finalmask.is_configured()
        && matches!(
            finalmask.scope(),
            FinalMaskScope::Tcp | FinalMaskScope::TcpClientOnly
        )
        && matches!(transport, TransportConfig::Xhttp(_))
        && let SecurityConfig::Tls(tls) = security
        && tls.alpn.as_deref().is_some_and(|a| a == ["h3"])
    {
        return Err(AppError::BadRequest(format!(
            "FinalMask '{}' cannot be used with XHTTP over HTTP/3: with ALPN \
             set to h3 only, xray runs the QUIC path and skips TCP masks on \
             both ends. Add h2 / http1.1 to ALPN, or choose another transport.",
            finalmask.kind(),
        )));
    }

    validate_finalmask_security(security, finalmask)
}

fn validate_finalmask_security(security: &SecurityConfig, finalmask: &FinalMask) -> AppResult<()> {
    // Reality wraps the raw TCP socket and type-asserts the underlying conn to
    // `CloseWriteConn` WITHOUT checking (xtls/reality `tls.go:186`), so a
    // server-side mask that lacks `CloseWrite` panics the accept goroutine —
    // which `tcp/hub.go:116` starts with no recover, taking the whole xray
    // process down on the first connection.
    //
    // `xmc.serverConn` has Read/Write/Close/addrs/deadlines and nothing else.
    // Verified rather than reasoned: a vless+reality inbound carrying an XMC
    // mask, one TCP connection, and xray was gone —
    //   panic: interface conversion: *xmc.serverConn is not
    //          reality.CloseWriteConn: missing method CloseWrite
    //
    // Sudoku is not refused: `sudoku.wrappedConn` does implement `CloseWrite`,
    // and the same experiment (reality + sudoku, four connections) left the
    // process running with a clean log.
    //
    // Fragment never runs server-side at all (client-only, via `fm=` — see the
    // orchestrator), and Noise is UDP-only, so neither ever meets Reality.
    if matches!(security, SecurityConfig::Reality(_)) && matches!(finalmask, FinalMask::Xmc(_)) {
        return Err(AppError::BadRequest(
            "Reality is incompatible with XMC FinalMask: XMC must run \
             server-side and Reality can't wrap its socket (xray-core panics). \
             Switch security to TLS / none, or pick another mask."
                .to_owned(),
        ));
    }

    // A sudoku table is a byte layout, not free text: `normalizeCustomTable`
    // (transport/internet/finalmask/sudoku/table.go) wants exactly eight
    // characters over the byte's bits — two `x` (the marker bits), two `p`
    // (the group's high bits) and four `v` (the value nibble). Anything else
    // fails when the mask is built, which on this path means the inbound is
    // already committed and `AddInbound` is the thing that says no.
    if let FinalMask::Sudoku(p) = finalmask {
        let tables = if p.custom_tables.is_empty() {
            std::slice::from_ref(&p.custom_table)
        } else {
            p.custom_tables.as_slice()
        };
        for raw in tables {
            let cleaned: String = raw
                .trim()
                .to_ascii_lowercase()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if cleaned.is_empty() {
                continue;
            }
            let bad = |why: &str| {
                Err(AppError::BadRequest(format!(
                    concat!(
                        "sudoku table '{}' {} — it must be 8 characters made of ",
                        "exactly two 'x', two 'p' and four 'v', one per bit of the byte."
                    ),
                    raw, why,
                )))
            };
            if cleaned.chars().count() != 8 {
                return bad("is not 8 characters long");
            }
            if cleaned.chars().any(|c| !matches!(c, 'x' | 'p' | 'v')) {
                return bad("has a character other than x, p or v");
            }
            let count = |want: char| cleaned.chars().filter(|c| *c == want).count();
            if count('x') != 2 || count('p') != 2 || count('v') != 4 {
                return bad("does not have exactly two 'x', two 'p' and four 'v'");
            }
        }
    }

    // xray's FragmentMask.Build rejects a final `lengths` entry whose min is
    // 0 ("last lengths entry min can't be 0"). An active Fragment mask whose
    // last length range starts at 0 ships a config the client's xray refuses,
    // so the user simply can't connect — reject it at the panel instead.
    if let FinalMask::Fragment(p) = finalmask
        && finalmask.is_active()
    {
        if p.lengths_min.last().copied().unwrap_or(0) < 1 {
            return Err(AppError::BadRequest(
                "Fragment FinalMask needs a chunk length of at least 1 byte — \
                 xray rejects a zero min on the last length range. Set the last \
                 length min to 1 or more."
                    .to_owned(),
            ));
        }
        // The share-link zips the min/max lists into "min-max" pairs, so lists
        // of different lengths would silently drop ranges; an inverted min > max
        // range is a config error too. The form guarantees neither, but a direct
        // API call could send them — reject both here.
        if p.lengths_min.len() != p.lengths_max.len() || p.delays_min.len() != p.delays_max.len() {
            return Err(AppError::BadRequest(
                "Fragment length/delay ranges are malformed — each range needs \
                 both a min and a max."
                    .to_owned(),
            ));
        }
        if p.lengths_min
            .iter()
            .zip(&p.lengths_max)
            .any(|(mn, mx)| mn > mx)
            || p.delays_min
                .iter()
                .zip(&p.delays_max)
                .any(|(mn, mx)| mn > mx)
        {
            return Err(AppError::BadRequest(
                "Fragment range min must be ≤ max.".to_owned(),
            ));
        }
    }

    // Noise per-item invariants (literal-XOR-rand, decodable literal, bounded
    // rand/delay/reset). Shared with the outbound write path so the same xray
    // process can't be crashed from either — see `FinalMask::validate_noise`.
    finalmask.validate_noise().map_err(AppError::BadRequest)?;

    // XICMP address lists: the server parses them with `MustParseAddr`, so a
    // typo would not be a 400 from xray but a crashed process.
    finalmask.validate_xicmp().map_err(AppError::BadRequest)?;

    // XMC profile/password invariants, mirrored from xray's own conf parser so
    // the operator gets a field-level message instead of an inbound that comes
    // up and then drops every connection.
    if let FinalMask::Xmc(p) = finalmask {
        p.validate().map_err(AppError::BadRequest)?;
    }

    Ok(())
}

/// Reject the XHTTP uplink knobs xray's JSON conf permits only in packet-up
/// mode (cookie/header uplink-data placement, a GET uplink method). The panel
/// builds the server via proto, which skips that check, so the inbound would
/// "work" while any client — which parses the share link through infra/conf —
/// refuses to start. Reject the invalid combo at the source instead.
fn validate_xhttp_mode(transport: &TransportConfig) -> AppResult<()> {
    let TransportConfig::Xhttp(x) = transport else {
        return Ok(());
    };
    if x.mode == Some(XhttpMode::PacketUp) {
        return Ok(());
    }
    if matches!(
        x.uplink_data_placement.as_deref().map(str::trim),
        Some("cookie" | "header")
    ) {
        return Err(AppError::BadRequest(
            "XHTTP uplink-data placement 'cookie'/'header' requires packet-up mode".to_owned(),
        ));
    }
    if x.uplink_http_method
        .as_deref()
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("GET"))
    {
        return Err(AppError::BadRequest(
            "XHTTP uplinkHTTPMethod 'GET' requires packet-up mode".to_owned(),
        ));
    }
    Ok(())
}

/// The mask rule for a `WireGuard` inbound, which is its own rule.
///
/// A `WireGuard` peer is not ours: whatever wraps the inbound's socket, the far
/// end is a stock `WireGuard` client, and the config the panel hands out has no
/// field that could tell it to speak the same wrapping. Only the masks that
/// survive that asymmetry are allowed — `wireguard_supported_kinds` says which
/// and why.
///
/// The transport/security matrix deliberately gets no say here. It judges a
/// mask by the layers underneath it, and this inbound has none: the `tcp` it
/// stores is a placeholder the layer validator wants, not a socket anything
/// runs on. Judged by it, the one mask that does work would be refused for
/// sitting on the wrong registry.
///
/// `check` is off only when the caller is carrying a stored mask forward
/// untouched, so a `{enabled: false}` PATCH on a row that predates this rule
/// stays possible.
fn validate_wireguard_finalmask(finalmask: &FinalMask, check: bool) -> AppResult<()> {
    if !check || !finalmask.is_configured() {
        return Ok(());
    }
    let allowed = crate::transports::finalmask::wireguard_supported_kinds();
    if allowed.contains(&finalmask.kind()) {
        return Ok(());
    }
    Err(AppError::BadRequest(format!(
        concat!(
            "FinalMask '{}' cannot be used on a WireGuard inbound: a stock ",
            "WireGuard client has no way to speak it, so the tunnel would stop ",
            "completing its handshake. Supported here: {}."
        ),
        finalmask.kind(),
        allowed.join(", "),
    )))
}

/// Cross-layer compatibility checks. xray would reject most of these at
/// `AddInbound` time anyway; doing them up front keeps the panel and xray from
/// drifting if the gRPC call fails between the commit and `AddInbound`.
///
/// `check_matrix` decides whether the transport×mask matrix applies. See
/// `validate_finalmask` — it is off when a stored mask is being carried
/// forward untouched, so a legacy row stays editable.
pub(super) fn validate_layers(
    protocol: &ProtocolConfig,
    transport: &TransportConfig,
    security: &SecurityConfig,
    finalmask: &FinalMask,
    check_matrix: bool,
    // True when this call carries a protocol choice being made now — a create,
    // or a PATCH whose body names a protocol.
    check_protocol_mask: bool,
) -> AppResult<()> {
    // Cross-layer protocol/transport/security compatibility — declared
    // per protocol in `ProtocolConfig::compat`. The validator just
    // checks set membership; rules grow by editing the per-protocol
    // compat block, not by adding branches here.
    let compat = protocol.compat();
    let transport_kind = transport.as_transport().kind();
    let security_kind = security.as_security().kind();
    if !compat.allowed_transports.contains(&transport_kind) {
        return Err(AppError::BadRequest(format!(
            "{} does not support transport '{}'",
            protocol.display_name(),
            transport_kind.as_db_str(),
        )));
    }
    if !compat.allowed_securities.contains(&security_kind) {
        return Err(AppError::BadRequest(format!(
            "{} does not support security '{}'",
            protocol.display_name(),
            security_kind.as_db_str(),
        )));
    }

    // VLESS Vision is TCP-only. Reject any flow=vision combined with
    // non-TCP transports up front. Skipped for non-VLESS protocols.
    if let ProtocolConfig::Vless(vless) = protocol
        && vless.flow == VlessFlow::XtlsRprxVision
        && !matches!(transport, TransportConfig::Tcp(_))
    {
        return Err(AppError::BadRequest(
            "xtls-rprx-vision is only supported on raw TCP, not XHTTP or WebSocket".to_owned(),
        ));
    }

    // Reality + WebSocket is unsupported by xray.
    if matches!(security, SecurityConfig::Reality(_)) && matches!(transport, TransportConfig::Ws(_))
    {
        return Err(AppError::BadRequest(
            "Reality is not supported over WebSocket — use TCP or XHTTP transport \
             (or switch security to TLS for WebSocket)"
                .to_owned(),
        ));
    }

    // XHTTP uplink knobs xray's JSON conf accepts only in packet-up mode; the
    // proto build path skips that check, so guard it here (grouped in the
    // helper to keep this function readable).
    validate_xhttp_mode(transport)?;

    // A WireGuard peer is not ours: whatever wraps the inbound's socket, the
    // far end is a stock WireGuard client, and the config the panel hands out
    // has no field that could tell it to speak the same wrapping. Only the
    // masks that survive that asymmetry are allowed — see
    // `wireguard_supported_kinds` for which and why. Keyed on its own flag as
    // well as `check_matrix`: a PATCH that switches an inbound TO WireGuard
    // carries no transport/security/finalmask block, so the matrix flag is off
    // and the stored mask would ride along unchecked. A PATCH that touches
    // neither still passes, so `{enabled: false}` on such a row stays possible.
    if matches!(protocol, ProtocolConfig::Wireguard(_)) {
        validate_wireguard_finalmask(finalmask, check_matrix || check_protocol_mask)?;
    } else {
        // FinalMask compatibility with the transport and the security layer
        // (Reality panics on Sudoku/XMC; XMC needs a TCP path; zero-length
        // fragment) — grouped in `validate_finalmask`.
        validate_finalmask(transport, security, finalmask, check_matrix)?;
        validate_xicmp_host(finalmask, check_matrix)?;
    }

    // VLESS fallbacks — xray-core rejects two combos at startup:
    //   * `fallbacks` + `decryption != "none"` (VLESS Encryption) — they
    //     write to the same protocol header bytes and xray bails out at
    //     `infra/conf/vless.go:157` with "fallbacks can not be used
    //     together with decryption".
    //   * `fallbacks` on anything other than TCP — fallbacks fire on the
    //     raw post-TLS stream, which only the TCP transport produces.
    //     WebSocket / XHTTP wrap traffic in their own framing and the
    //     fallback code path never gets called.
    if let ProtocolConfig::Vless(vless) = protocol
        && !vless.fallbacks.is_empty()
    {
        if !matches!(vless.encryption_mode, VlessEncryptionMode::None) {
            return Err(AppError::BadRequest(
                "VLESS fallbacks are incompatible with VLESS Encryption \
                 (xray-core rejects the combo). Disable encryption \
                 or remove the fallbacks."
                    .to_owned(),
            ));
        }
        if !matches!(transport, TransportConfig::Tcp(_)) {
            return Err(AppError::BadRequest(
                "VLESS fallbacks only work on the TCP transport — \
                 WebSocket / XHTTP frame traffic before xray sees it."
                    .to_owned(),
            ));
        }
        for fb in &vless.fallbacks {
            if fb.dest.trim().is_empty() {
                return Err(AppError::BadRequest(
                    "VLESS fallback `dest` is required".to_owned(),
                ));
            }
            if !fb.path.is_empty() && !fb.path.starts_with('/') {
                return Err(AppError::BadRequest(
                    "VLESS fallback `path` must be empty or start with '/'".to_owned(),
                ));
            }
            if fb.xver > 2 {
                return Err(AppError::BadRequest(
                    "VLESS fallback `xver` only accepts 0, 1, or 2".to_owned(),
                ));
            }
        }
    }

    // Reality needs a real dest and at least one serverName.
    if let SecurityConfig::Reality(r) = security {
        if r.dest.trim().is_empty() {
            return Err(AppError::BadRequest("reality dest is required".to_owned()));
        }
        if r.server_names.is_empty() {
            return Err(AppError::BadRequest(
                "reality server_names must have at least one entry".to_owned(),
            ));
        }
        for s in &r.short_ids {
            keygen::decode_short_id(s).map_err(|e| AppError::BadRequest(e.to_string()))?;
        }
    }

    Ok(())
}

/// Reject inbound tags that collide with reserved internal tags. The only
/// reserved inbound tag is the gRPC control channel's (`API_TAG`): a user
/// inbound claiming it fails xray's duplicate-tag check and, worse, a later
/// remove/re-add tears down the panel's own control inbound. Mirrors the
/// reserved-tag guard `api::outbounds` runs for outbound tags, and makes the
/// per-inbound traffic poller's `api`-skip invariant actually hold.
pub(super) fn validate_inbound_tag(tag: &str) -> AppResult<()> {
    if tag == crate::xray::config_gen::API_TAG {
        return Err(AppError::BadRequest(format!(
            "inbound tag '{tag}' is reserved for the internal control channel"
        )));
    }
    Ok(())
}

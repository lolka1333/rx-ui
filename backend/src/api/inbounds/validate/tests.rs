//! Truth table for `validate_layers`, the create/edit gate that keeps xray
//! from ever seeing an invalid flow×transport×security combo.
use super::*;
use crate::protocols::vless::{VlessEncryptionMode, VlessFlow, VlessProtocol};
use crate::security::NoneSecurity;
use crate::security::reality::RealitySecurity;
use crate::security::tls::TlsSecurity;
use crate::transports::finalmask::{
    FragmentParams, NoiseItem, NoiseParams, SudokuParams, XmcParams,
};
use crate::transports::tcp::TcpTransport;
use crate::transports::ws::WsTransport;
use crate::transports::xhttp::{XhttpMode, XhttpTransport};

/// `validate_layers` with no mask and every check on, for the tests that
/// don't care about either — a new parameter is then a one-line edit here.
fn vl(p: &ProtocolConfig, t: &TransportConfig, s: &SecurityConfig) -> AppResult<()> {
    validate_layers(p, t, s, &FinalMask::None, true, true)
}

fn vless(flow: VlessFlow) -> ProtocolConfig {
    ProtocolConfig::Vless(VlessProtocol {
        flow,
        encryption_mode: VlessEncryptionMode::None,
        ..VlessProtocol::default()
    })
}

fn reality_ok() -> SecurityConfig {
    SecurityConfig::Reality(RealitySecurity {
        dest: "www.cloudflare.com:443".into(),
        server_names: vec!["www.cloudflare.com".into()],
        short_ids: vec!["aabb1122".into()],
        fingerprint: "chrome".into(),
        ..RealitySecurity::default()
    })
}

#[test]
fn tcp_none_none_ok() {
    vl(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap();
}

#[test]
fn tcp_vision_reality_ok_canonical_combo() {
    vl(
        &vless(VlessFlow::XtlsRprxVision),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
    )
    .unwrap();
}

fn noise(items: Vec<NoiseItem>) -> FinalMask {
    FinalMask::Noise(NoiseParams {
        items,
        ..NoiseParams::default()
    })
}

#[test]
fn noise_negative_rand_rejected() {
    // Reachable only via a direct API body (the UI pins min=0); a negative
    // rand would panic xray at runtime (`make([]byte, RandBetween(neg))`).
    let err = validate_finalmask_security(
        &SecurityConfig::None(NoneSecurity {}),
        &noise(vec![NoiseItem {
            rand_min: Some(-5),
            rand_max: Some(8),
            ..NoiseItem::default()
        }]),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("random length must be between"), "got: {err}");
}

#[test]
fn noise_oversized_rand_rejected() {
    let err = validate_finalmask_security(
        &SecurityConfig::None(NoneSecurity {}),
        &noise(vec![NoiseItem {
            rand_max: Some(5_000_000_000),
            ..NoiseItem::default()
        }]),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("random length must be between"), "got: {err}");
}

#[test]
fn noise_literal_plus_rand_accepted_packet_wins() {
    // A literal + a stray rand is NOT rejected — it's the old UI's normal
    // output and the default literal flow. "Packet wins" is applied at
    // build time (rand zeroed), matching the tooltip; a hard 400 here would
    // block editing legacy inbounds and the default literal flow.
    validate_finalmask_security(
        &SecurityConfig::None(NoneSecurity {}),
        &noise(vec![NoiseItem {
            packet_hex: "dead".into(),
            rand_min: Some(5),
            rand_max: Some(10),
            ..NoiseItem::default()
        }]),
    )
    .unwrap();
}

#[test]
fn noise_undecodable_literal_rejected() {
    // Odd-length / separator-only literals decode to junk or empty — the
    // operator gets an error, not a silent no-op mask.
    for bad in ["abc", "a", ",", "zz"] {
        let err = validate_finalmask_security(
            &SecurityConfig::None(NoneSecurity {}),
            &noise(vec![NoiseItem {
                packet_hex: bad.into(),
                ..NoiseItem::default()
            }]),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("literal packet"), "input {bad:?} got: {err}");
    }
}

#[test]
fn noise_in_range_ok() {
    validate_finalmask_security(
        &SecurityConfig::None(NoneSecurity {}),
        &noise(vec![NoiseItem {
            rand_min: Some(5),
            rand_max: Some(10),
            delay_min: Some(0),
            delay_max: Some(65_535),
            ..NoiseItem::default()
        }]),
    )
    .unwrap();
    // A clean literal with separators is accepted.
    validate_finalmask_security(
        &SecurityConfig::None(NoneSecurity {}),
        &noise(vec![NoiseItem {
            packet_hex: "de:ad be,ef".into(),
            ..NoiseItem::default()
        }]),
    )
    .unwrap();
}

#[test]
fn xhttp_vision_err_vision_is_tcp_only() {
    let err = vl(
        &vless(VlessFlow::XtlsRprxVision),
        &TransportConfig::Xhttp(XhttpTransport::default()),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("xtls-rprx-vision"), "got: {err}");
    assert!(err.contains("TCP"), "got: {err}");
}

#[test]
fn xhttp_get_method_outside_packet_up_err() {
    // Case-insensitive: xray uppercases before the check.
    let err = vl(
        &vless(VlessFlow::None),
        &TransportConfig::Xhttp(XhttpTransport {
            uplink_http_method: Some("get".into()),
            ..XhttpTransport::default()
        }),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("uplinkHTTPMethod"), "got: {err}");
    assert!(err.contains("packet-up"), "got: {err}");
}

#[test]
fn xhttp_cookie_uplink_outside_packet_up_err() {
    let err = vl(
        &vless(VlessFlow::None),
        &TransportConfig::Xhttp(XhttpTransport {
            uplink_data_placement: Some("cookie".into()),
            ..XhttpTransport::default()
        }),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("uplink-data placement"), "got: {err}");
}

#[test]
fn xhttp_packet_up_allows_uplink_knobs() {
    vl(
        &vless(VlessFlow::None),
        &TransportConfig::Xhttp(XhttpTransport {
            mode: Some(XhttpMode::PacketUp),
            uplink_http_method: Some("GET".into()),
            uplink_data_placement: Some("cookie".into()),
            ..XhttpTransport::default()
        }),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap();
}

#[test]
fn xhttp_post_body_ok_in_any_mode() {
    // POST + body/auto placement carry no mode restriction.
    vl(
        &vless(VlessFlow::None),
        &TransportConfig::Xhttp(XhttpTransport {
            mode: Some(XhttpMode::StreamUp),
            uplink_http_method: Some("POST".into()),
            uplink_data_placement: Some("body".into()),
            ..XhttpTransport::default()
        }),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap();
}

#[test]
fn ws_reality_err_reality_no_ws() {
    let err = vl(
        &vless(VlessFlow::None),
        &TransportConfig::Ws(WsTransport::default()),
        &reality_ok(),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("Reality"), "got: {err}");
    assert!(err.contains("WebSocket"), "got: {err}");
}

#[test]
fn ws_tls_ok_typical_cdn_combo() {
    vl(
        &vless(VlessFlow::None),
        &TransportConfig::Ws(WsTransport::default()),
        &SecurityConfig::Tls(TlsSecurity::default()),
    )
    .unwrap();
}

#[test]
fn reality_empty_dest_err() {
    let mut r = reality_ok();
    if let SecurityConfig::Reality(ref mut inner) = r {
        inner.dest = String::new();
    }
    let err = vl(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &r,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("dest"), "got: {err}");
}

#[test]
fn reality_empty_server_names_err() {
    let mut r = reality_ok();
    if let SecurityConfig::Reality(ref mut inner) = r {
        inner.server_names.clear();
    }
    let err = vl(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &r,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("server_names"), "got: {err}");
}

/// Reality + XMC is the combination that really does kill xray: reality
/// type-asserts the conn to `CloseWriteConn` unchecked and `xmc.serverConn`
/// has no `CloseWrite`, so the accept goroutine panics with no recover.
/// Confirmed by running it — one connection and the process was gone.
#[test]
fn reality_with_xmc_err_kills_xray() {
    let err = validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::Xmc(XmcParams::default()),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("Reality"), "got: {err}");
    assert!(err.contains("XMC"), "got: {err}");
}

/// A `WireGuard` inbound's clients are the standard `WireGuard` apps, and the
/// config the panel hands them has no field that could carry a mask. The
/// server socket DOES get wrapped, so accepting one would mean a tunnel
/// that stops completing handshakes with nothing in the log to explain it.
#[test]
fn wireguard_with_a_mask_is_refused() {
    let wg = crate::protocols::ProtocolConfig::Wireguard(
        crate::protocols::wireguard::WireguardProtocol::default(),
    );
    let err = validate_layers(
        &wg,
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(crate::security::NoneSecurity {}),
        &FinalMask::Sudoku(crate::transports::finalmask::SudokuParams {
            // A mask only counts as chosen once it carries a secret —
            // `is_configured` is what the guard keys on.
            password: "not-a-secret".to_owned(),
            ..crate::transports::finalmask::SudokuParams::default()
        }),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("WireGuard"), "got: {err}");
}

/// Switching an existing inbound TO `WireGuard` is where the mask does its
/// damage: the PATCH carries only a protocol, so the transport/security
/// matrix flag is off, and without its own trigger the stored mask would
/// ride along onto a socket no `WireGuard` client can talk to.
#[test]
fn switching_to_wireguard_refuses_a_stored_mask() {
    let wg = crate::protocols::ProtocolConfig::Wireguard(
        crate::protocols::wireguard::WireguardProtocol::default(),
    );
    let err = validate_layers(
        &wg,
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(crate::security::NoneSecurity {}),
        &FinalMask::Sudoku(crate::transports::finalmask::SudokuParams {
            password: "not-a-secret".to_owned(),
            ..crate::transports::finalmask::SudokuParams::default()
        }),
        // The matrix flag is off: this PATCH touches none of the three.
        false,
        // But it does name a protocol.
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("WireGuard"), "got: {err}");
}

/// The one mask a stock `WireGuard` client survives: its server side only
/// injects extra datagrams and never rewrites a packet, so the client drops
/// the junk and reads the rest unchanged. Refusing it would be refusing
/// obfuscation that actually works here.
#[test]
fn wireguard_accepts_the_mask_a_stock_client_survives() {
    let wg = crate::protocols::ProtocolConfig::Wireguard(
        crate::protocols::wireguard::WireguardProtocol::default(),
    );
    validate_layers(
        &wg,
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(crate::security::NoneSecurity {}),
        &FinalMask::Noise(crate::transports::finalmask::NoiseParams {
            items: vec![crate::transports::finalmask::NoiseItem {
                packet_hex: String::new(),
                rand_min: Some(5),
                rand_max: Some(10),
                delay_min: None,
                delay_max: None,
            }],
            ..crate::transports::finalmask::NoiseParams::default()
        }),
        true,
        true,
    )
    .unwrap();
}

/// Same inbound without a mask stays valid — the guard must not turn into
/// "`WireGuard` inbounds cannot be saved".
#[test]
fn wireguard_without_a_mask_is_accepted() {
    let wg = crate::protocols::ProtocolConfig::Wireguard(
        crate::protocols::wireguard::WireguardProtocol::default(),
    );
    validate_layers(
        &wg,
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(crate::security::NoneSecurity {}),
        &FinalMask::None,
        true,
        true,
    )
    .unwrap();
}

/// Fragment is asymmetric — the panel ships it to the client via `fm=` and
/// never wraps the server socket with it (orchestrator skips its tcpmask),
/// so it no longer panics under Reality and must be ACCEPTED. This is the
/// combo that used to be rejected here.
#[test]
fn reality_with_fragment_ok() {
    validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::Fragment(FragmentParams {
            packets_from: Some(0),
            packets_to: Some(1),
            lengths_min: vec![40],
            lengths_max: vec![80],
            ..FragmentParams::default()
        }),
        true,
        true,
    )
    .expect("Fragment + Reality must be allowed (Fragment is client-only)");
}

/// xray rejects `LengthMin` == 0; the panel must reject an active Fragment
/// mask with a zero/empty min length before it ships a broken fm=.
#[test]
fn fragment_zero_length_rejected() {
    let err = validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::Fragment(FragmentParams {
            packets_from: Some(0),
            packets_to: Some(1),
            // last length min is 0, max set → the mask is active but
            // ships lengths ["0-80"], which xray would reject.
            lengths_min: vec![0],
            lengths_max: vec![80],
            ..FragmentParams::default()
        }),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("length"), "got: {err}");
}

/// A range whose min exceeds its max ("200-100") is a config error; the
/// panel rejects it instead of shipping an inverted range to xray.
#[test]
fn fragment_inverted_range_rejected() {
    let err = validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::Fragment(FragmentParams {
            packets_from: Some(0),
            packets_to: Some(1),
            lengths_min: vec![200],
            lengths_max: vec![100],
            ..FragmentParams::default()
        }),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("min must be"), "got: {err}");
}

/// Mismatched min/max list lengths would silently truncate via the
/// share-link zip; the panel rejects the malformed config up front.
#[test]
fn fragment_mismatched_range_lists_rejected() {
    let err = validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::Fragment(FragmentParams {
            packets_from: Some(0),
            packets_to: Some(1),
            lengths_min: vec![40, 90],
            lengths_max: vec![80],
            ..FragmentParams::default()
        }),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("malformed"), "got: {err}");
}

// ---- VLESS fallbacks validation -------------------------------------
//
// Mirrors what `infra/conf/vless.go` enforces server-side. We catch
// these at the panel boundary so the operator sees a clean 400 instead
// of xray refusing to start with a cryptic Go error on the next reload.

use crate::protocols::vless::{VlessFallback, VlessFallbackType};

fn vless_with_fallbacks(fallbacks: Vec<VlessFallback>) -> ProtocolConfig {
    ProtocolConfig::Vless(VlessProtocol {
        flow: VlessFlow::None,
        encryption_mode: VlessEncryptionMode::None,
        fallbacks,
        ..VlessProtocol::default()
    })
}

fn fb_minimal() -> VlessFallback {
    VlessFallback {
        dest: "127.0.0.1:8080".into(),
        kind: VlessFallbackType::Tcp,
        ..VlessFallback::default()
    }
}

#[test]
fn fallbacks_with_encryption_err_xray_mutual_exclusion() {
    let mut p = vless_with_fallbacks(vec![fb_minimal()]);
    if let ProtocolConfig::Vless(v) = &mut p {
        v.encryption_mode = VlessEncryptionMode::Mlkem768x25519Plus;
    }
    let err = vl(
        &p,
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("fallbacks"), "got: {err}");
    assert!(err.contains("Encryption"), "got: {err}");
}

#[test]
fn fallbacks_on_ws_err_tcp_only() {
    let err = vl(
        &vless_with_fallbacks(vec![fb_minimal()]),
        &TransportConfig::Ws(WsTransport::default()),
        &SecurityConfig::Tls(TlsSecurity::default()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("fallbacks"), "got: {err}");
    assert!(err.contains("TCP"), "got: {err}");
}

#[test]
fn fallbacks_empty_dest_err() {
    let mut fb = fb_minimal();
    fb.dest = "   ".into();
    let err = vl(
        &vless_with_fallbacks(vec![fb]),
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("dest"), "got: {err}");
}

#[test]
fn fallbacks_path_without_leading_slash_err() {
    let mut fb = fb_minimal();
    fb.path = "fallback".into();
    let err = vl(
        &vless_with_fallbacks(vec![fb]),
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("path"), "got: {err}");
}

#[test]
fn fallbacks_xver_above_2_err() {
    let mut fb = fb_minimal();
    fb.xver = 3;
    let err = vl(
        &vless_with_fallbacks(vec![fb]),
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("xver"), "got: {err}");
}

#[test]
fn fallbacks_tcp_no_encryption_ok() {
    let mut fb = fb_minimal();
    fb.path = "/fallback".into();
    fb.xver = 2;
    vl(
        &vless_with_fallbacks(vec![fb]),
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::Tls(TlsSecurity::default()),
    )
    .unwrap();
}

#[test]
/// Sudoku under Reality used to be refused on the grounds that it panics
/// xray. It does not: `sudoku.wrappedConn` implements `CloseWrite`, and a
/// live reality+sudoku inbound took repeated connections with a clean log.
/// The combination is allowed, and this test is here so the old rule does
/// not come back on the strength of the story rather than the measurement.
fn reality_with_sudoku_ok() {
    validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::Sudoku(SudokuParams {
            password: "probe".to_owned(),
            ..SudokuParams::default()
        }),
        true,
        true,
    )
    .unwrap();
}

fn tls_ok() -> SecurityConfig {
    SecurityConfig::Tls(TlsSecurity::default())
}

fn tls_alpn(alpn: &[&str]) -> SecurityConfig {
    SecurityConfig::Tls(TlsSecurity {
        alpn: Some(alpn.iter().map(|s| (*s).to_owned()).collect()),
        ..TlsSecurity::default()
    })
}

/// A profile the matrix tests can hand around without caring about it.
fn xmc_profile() -> crate::transports::finalmask::XmcProfile {
    crate::transports::finalmask::XmcProfile {
        username: "Notch".to_owned(),
        uuid: "069a79f4-44e9-4726-a5be-fca90e38aaf5".to_owned(),
        textures_value: "dmFsdWU=".to_owned(),
        textures_signature: "c2ln".to_owned(),
    }
}

/// As the form sends it: password and profiles, no derived keys.
fn xmc_from_form() -> FinalMask {
    FinalMask::Xmc(XmcParams {
        password: "probe".to_owned(),
        profiles: vec![xmc_profile()],
        ..XmcParams::default()
    })
}

/// The matrix has to judge a mask the way the form sends it — without the
/// RSA keys, which are derived after validation on the create path. Gating
/// on `is_active` instead left this check dead for every new XMC inbound,
/// so hysteria2 + XMC returned 201 and quietly listened without the mask.
#[test]
fn xmc_on_hysteria_rejected_without_derived_keys() {
    let err = validate_layers(
        &hysteria2(),
        &hysteria_transport(),
        &tls_ok(),
        &xmc_from_form(),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("xmc"), "got: {err}");
}

/// The mirror of the case above: on TCP the same mask is in the matrix.
#[test]
fn xmc_on_tcp_tls_ok() {
    validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &tls_ok(),
        &xmc_from_form(),
        true,
        true,
    )
    .unwrap();
}

/// A stored mask carried forward untouched skips the matrix: rows created
/// before the rule existed must stay editable, or a `{enabled: false}`
/// PATCH 400s about a mask the dropdown no longer even offers.
#[test]
fn legacy_out_of_matrix_mask_survives_an_untouched_update() {
    validate_layers(
        &hysteria2(),
        &hysteria_transport(),
        &tls_ok(),
        &xmc_from_form(),
        false,
        false,
    )
    .unwrap();
}

/// A blank draft (kind chosen, nothing filled in) is not a mask yet, so
/// the matrix stays quiet about it — gating on "kind != none" instead
/// would turn every half-open form section into a 400. Fragment shows this
/// on its own; a blank XMC draft is stopped one step earlier, by its own
/// field validation ("XMC needs a password").
#[test]
fn empty_fragment_draft_on_hysteria_passes() {
    validate_layers(
        &hysteria2(),
        &hysteria_transport(),
        &tls_ok(),
        &FinalMask::Fragment(FragmentParams::default()),
        true,
        true,
    )
    .unwrap();
}

/// XHTTP with ALPN exactly `h3` runs the QUIC path, where TCP-registry
/// masks are never consulted. Fragment lives only in that registry, so it
/// is refused there just like XMC — the gate is on the scope, not on one
/// variant.
#[test]
fn fragment_on_xhttp_h3_rejected() {
    let err = validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Xhttp(XhttpTransport {
            mode: Some(XhttpMode::Auto),
            ..XhttpTransport::default()
        }),
        &tls_alpn(&["h3"]),
        &FinalMask::Fragment(FragmentParams {
            packets_from: Some(0),
            packets_to: Some(1),
            lengths_min: vec![40],
            lengths_max: vec![80],
            ..FragmentParams::default()
        }),
        true,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("HTTP/3"), "got: {err}");
}

/// `["h3","h3"]` is not `["h3"]` to the core — it takes the HTTP/2 path,
/// where the mask does run. Refusing it would be a false negative.
#[test]
fn duplicate_h3_alpn_is_not_h3_only() {
    validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Xhttp(XhttpTransport {
            mode: Some(XhttpMode::Auto),
            ..XhttpTransport::default()
        }),
        &tls_alpn(&["h3", "h3"]),
        &xmc_from_form(),
        true,
        true,
    )
    .unwrap();
}

#[test]
fn reality_with_none_finalmask_ok() {
    validate_layers(
        &vless(VlessFlow::None),
        &TransportConfig::Tcp(TcpTransport {}),
        &reality_ok(),
        &FinalMask::None,
        true,
        true,
    )
    .unwrap();
}

// Hysteria 2 cross-layer rules. Force-paired with hysteria transport,
// TLS-only — every other combo must 4xx at the validator.
use crate::protocols::hysteria::HysteriaProtocol;
use crate::transports::hysteria::{HysteriaMasquerade, HysteriaTransport};

fn hysteria2() -> ProtocolConfig {
    ProtocolConfig::Hysteria2(HysteriaProtocol {})
}
fn hysteria_transport() -> TransportConfig {
    TransportConfig::Hysteria(HysteriaTransport {
        auth: None,
        udp_idle_timeout: None,
        masquerade: HysteriaMasquerade::NotFound,
        quic_params: None,
    })
}

#[test]
fn hysteria_with_tls_ok() {
    vl(
        &hysteria2(),
        &hysteria_transport(),
        &SecurityConfig::Tls(TlsSecurity::default()),
    )
    .unwrap();
}

#[test]
fn hysteria_proto_with_tcp_transport_err() {
    let err = vl(
        &hysteria2(),
        &TransportConfig::Tcp(TcpTransport {}),
        &SecurityConfig::Tls(TlsSecurity::default()),
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("Hysteria"), "got: {err}");
}

#[test]
fn vless_proto_with_hysteria_transport_err() {
    let err = vl(
        &vless(VlessFlow::None),
        &hysteria_transport(),
        &SecurityConfig::Tls(TlsSecurity::default()),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("VLESS") && err.contains("hysteria"),
        "got: {err}"
    );
}

#[test]
fn hysteria_with_reality_err() {
    let err = vl(&hysteria2(), &hysteria_transport(), &reality_ok())
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("Hysteria 2") && err.contains("reality"),
        "got: {err}"
    );
}

#[test]
fn hysteria_with_none_security_err() {
    let err = vl(
        &hysteria2(),
        &hysteria_transport(),
        &SecurityConfig::None(NoneSecurity {}),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("Hysteria 2") && err.contains("none"),
        "got: {err}"
    );
}

/// Serving XICMP is a property of the host, not of the form: refused off
/// Linux, allowed on it. `check = false` (a stored row carried forward
/// untouched) never refuses, so such a row stays manageable.
#[test]
fn xicmp_inbounds_are_refused_where_the_kernel_swallows_pings() {
    use crate::transports::finalmask::XicmpParams;
    let xicmp = FinalMask::Xicmp(XicmpParams::default());

    assert_eq!(
        validate_xicmp_host(&xicmp, true).is_err(),
        !cfg!(target_os = "linux"),
        "xicmp must be refused exactly where the kernel answers pings itself"
    );
    assert!(validate_xicmp_host(&xicmp, false).is_ok());
    assert!(validate_xicmp_host(&FinalMask::None, true).is_ok());
}

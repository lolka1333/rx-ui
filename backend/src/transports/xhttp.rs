//! XHTTP (splithttp) transport — the modern HTTP/2-and-H/3 over single
//! TCP-replacement xray-core ships. Operator surface is wide (30+ knobs
//! for padding obfuscation, multiplexing, session tokens, anti-DPI), but
//! every field has a sensible default — leaving `None` everywhere
//! produces a working `mode=auto` inbound that handles the common case.

use super::quic::QuicParams;
use super::{Transport, TransportKind};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::QuicParams as XrayQuicParams;
use crate::xray::proto::xray::transport::internet::splithttp::{
    Config as XraySplitHttpConfig, RangeConfig, XmuxConfig,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ts_rs::TS;

const TYPE_SPLITHTTP_CONFIG: &str = "xray.transport.internet.splithttp.Config";

/// XHTTP mode — see xray-core `infra/conf/transport_internet.go::SplitHTTPConfig.Build`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub enum XhttpMode {
    #[default]
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

impl XhttpMode {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PacketUp => "packet-up",
            Self::StreamUp => "stream-up",
            Self::StreamOne => "stream-one",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct XhttpTransport {
    pub path: Option<String>,
    pub host: Option<String>,
    pub mode: Option<XhttpMode>,
    pub headers: Option<BTreeMap<String, String>>,
    // Padding range fields — operator types "100" or "100-1000".
    pub x_padding_bytes: Option<String>,
    pub no_grpc_header: Option<bool>,
    pub no_sse_header: Option<bool>,
    pub sc_max_each_post_bytes: Option<String>,
    pub sc_min_posts_interval_ms: Option<String>,
    #[ts(type = "number | null")]
    pub sc_max_buffered_posts: Option<i64>,
    pub sc_stream_up_server_secs: Option<String>,
    pub xmux_max_concurrency: Option<String>,
    pub xmux_max_connections: Option<String>,
    pub xmux_c_max_reuse_times: Option<String>,
    pub xmux_h_max_request_times: Option<String>,
    pub xmux_h_max_reusable_secs: Option<String>,
    #[ts(type = "number | null")]
    pub xmux_h_keep_alive_period: Option<i64>,
    pub x_padding_obfs_mode: Option<bool>,
    pub x_padding_key: Option<String>,
    pub x_padding_header: Option<String>,
    pub x_padding_placement: Option<String>,
    pub x_padding_method: Option<String>,
    pub uplink_http_method: Option<String>,
    // xray-core v26.6.22 (#6258) renamed `session*` → `sessionID*` (proto
    // field numbers 20/21 unchanged) and added a custom session-ID table +
    // length. These session knobs are optional; the panel re-serializes them
    // under the new keys, so the rename needs no DB migration.
    pub session_id_placement: Option<String>,
    pub session_id_key: Option<String>,
    /// Predefined table name (ALPHABET/Alphabet/BASE36/Base62/HEX/alphabet/
    /// base36/hex/number) or a custom ASCII alphabet for the session ID.
    pub session_id_table: Option<String>,
    /// Session-ID length range ("8" or "8-16"). Empty ≡ xray default.
    pub session_id_length: Option<String>,
    pub seq_placement: Option<String>,
    pub seq_key: Option<String>,
    pub uplink_data_placement: Option<String>,
    pub uplink_data_key: Option<String>,
    pub uplink_chunk_size: Option<String>,
    #[ts(type = "number | null")]
    pub server_max_header_bytes: Option<i64>,
    /// Raw JSON applied to the XHTTP listener's `net/http.HTTP2Config`
    /// (xray-core v26.10.31, `splithttp/hub.go`). Server-side only — the
    /// dialing client never reads it, so it stays out of the share link.
    ///
    /// Written in operator-friendly form and normalised on the way out by
    /// [`XhttpTransport::build_h2_params`]: durations are typed as Go
    /// duration strings (`"30s"`) and converted to the integer nanoseconds
    /// `encoding/json` actually requires.
    pub h2_params: Option<String>,
    /// Stream-level QUIC tuning. xray's splithttp reads this off
    /// `StreamConfig.quic_params` when running in H3 mode
    /// (`ALPN=["h3"]`); ignored for the TCP / H2 modes. Routed
    /// through `Transport::quic_params_proto`.
    pub quic_params: Option<QuicParams>,
}

impl XhttpTransport {
    /// Build `xmux` proto sub-message, or `None` when every xmux field
    /// is unset (lets xray use its default multiplexing policy).
    fn build_xmux(&self) -> anyhow::Result<Option<XmuxConfig>> {
        let any_set = self.xmux_max_concurrency.is_some()
            || self.xmux_max_connections.is_some()
            || self.xmux_c_max_reuse_times.is_some()
            || self.xmux_h_max_request_times.is_some()
            || self.xmux_h_max_reusable_secs.is_some()
            || self.xmux_h_keep_alive_period.is_some();
        if !any_set {
            return Ok(None);
        }
        Ok(Some(XmuxConfig {
            max_concurrency: parse_range(self.xmux_max_concurrency.as_deref())?,
            max_connections: parse_range(self.xmux_max_connections.as_deref())?,
            c_max_reuse_times: parse_range(self.xmux_c_max_reuse_times.as_deref())?,
            h_max_request_times: parse_range(self.xmux_h_max_request_times.as_deref())?,
            h_max_reusable_secs: parse_range(self.xmux_h_max_reusable_secs.as_deref())?,
            h_keep_alive_period: self.xmux_h_keep_alive_period.unwrap_or(0),
        }))
    }

    /// Validate and normalise [`Self::h2_params`] into the bytes xray hands
    /// to `json.Unmarshal`.
    ///
    /// Three traps live in that call, all verified against the Go stdlib:
    ///
    ///   * `time.Duration` has no JSON unmarshaller, so `"30s"` is a hard
    ///     error and a bare `30` means thirty *nanoseconds*. Durations are
    ///     taken as strings here and emitted as integer nanoseconds.
    ///   * an unrecognised key is dropped without a word, so a typo would
    ///     silently do nothing. Keys are matched against the real struct.
    ///   * `encoding/json` matches field names case-insensitively, so the
    ///     match here is too, and the canonical spelling is what we emit.
    ///
    /// Empty / absent input yields no bytes at all, which leaves the proto
    /// field unset and xray on its own defaults.
    fn build_h2_params(&self) -> anyhow::Result<Vec<u8>> {
        let Some(raw) = self
            .h2_params
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(Vec::new());
        };
        let parsed: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("h2Params is not valid JSON: {e}"))?;
        let Some(obj) = parsed.as_object() else {
            return Err(anyhow::anyhow!(
                "h2Params must be a JSON object, for example {{\"SendPingTimeout\": \"30s\"}}"
            ));
        };
        let mut out = serde_json::Map::new();
        for (key, value) in obj {
            let (canonical, kind) = canonical_h2_key(key)?;
            let normalised = match kind {
                H2Kind::Duration => {
                    let Some(text) = value.as_str() else {
                        return Err(anyhow::anyhow!(
                            "h2Params '{canonical}' must be a duration string such as \"30s\" — a bare number is read as nanoseconds by the core"
                        ));
                    };
                    serde_json::Value::from(parse_go_duration_nanos(canonical, text)?)
                }
                H2Kind::Integer => {
                    let Some(n) = value.as_i64().filter(|n| *n >= 0) else {
                        return Err(anyhow::anyhow!(
                            "h2Params '{canonical}' must be a non-negative whole number"
                        ));
                    };
                    serde_json::Value::from(n)
                }
                H2Kind::Boolean => {
                    let Some(b) = value.as_bool() else {
                        return Err(anyhow::anyhow!(
                            "h2Params '{canonical}' must be true or false"
                        ));
                    };
                    serde_json::Value::Bool(b)
                }
            };
            if out.insert(canonical.to_owned(), normalised).is_some() {
                return Err(anyhow::anyhow!(
                    "h2Params names '{canonical}' twice (the core matches keys ignoring case)"
                ));
            }
        }
        Ok(serde_json::Value::Object(out).to_string().into_bytes())
    }
}

impl Transport for XhttpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Xhttp
    }
    fn xray_protocol_name(&self) -> &'static str {
        "splithttp"
    }
    fn share_link_params(&self) -> Vec<(String, String)> {
        let mut params = vec![("type".to_owned(), "xhttp".to_owned())];
        if let Some(p) = &self.path
            && !p.is_empty()
        {
            params.push(("path".to_owned(), p.clone()));
        }
        if let Some(h) = &self.host
            && !h.is_empty()
        {
            params.push(("host".to_owned(), h.clone()));
        }
        if let Some(m) = self.mode {
            params.push(("mode".to_owned(), m.as_db_str().to_owned()));
        }
        // Advanced xhttpSettings the client must mirror travel in xray's
        // `extra` param — a JSON the client merges into its own xhttpSettings
        // (key names match xray's conf). Every symmetric knob rides here:
        //   * padding obfuscation — the server pads every request, so a client
        //     that doesn't pad identically can't connect (only when obfs on).
        //   * session-ID + seq + uplink-data placement/key — the client encodes
        //     each at this location/key and the server reads it there to pair and
        //     reassemble the up/down streams, so any mismatch breaks the
        //     connection. `uplinkHTTPMethod` is the verb the client posts with,
        //     which the server matches on; table/length shape the id generated
        //     client-side.
        //   * noGRPCHeader / noSSEHeader — downlink framing the client must parse
        //     the same way the server writes it.
        // Built lazily: only non-default fields are inserted, so a plain inbound
        // keeps a clean link with no `extra=` at all.
        let mut extra = serde_json::Map::new();
        if self.x_padding_obfs_mode.unwrap_or(false) {
            extra.insert("xPaddingObfsMode".to_owned(), serde_json::Value::Bool(true));
            for (key, val) in [
                ("xPaddingKey", self.x_padding_key.as_deref()),
                ("xPaddingHeader", self.x_padding_header.as_deref()),
                ("xPaddingPlacement", self.x_padding_placement.as_deref()),
                ("xPaddingMethod", self.x_padding_method.as_deref()),
            ] {
                if let Some(v) = val.filter(|s| !s.is_empty()) {
                    extra.insert(key.to_owned(), serde_json::Value::String(v.to_owned()));
                }
            }
        }
        for (key, val) in [
            ("sessionIDPlacement", self.session_id_placement.as_deref()),
            ("sessionIDKey", self.session_id_key.as_deref()),
            ("sessionIDTable", self.session_id_table.as_deref()),
            ("sessionIDLength", self.session_id_length.as_deref()),
            ("seqPlacement", self.seq_placement.as_deref()),
            ("seqKey", self.seq_key.as_deref()),
        ] {
            if let Some(v) = val.filter(|s| !s.is_empty()) {
                extra.insert(key.to_owned(), serde_json::Value::String(v.to_owned()));
            }
        }
        // uplink-data placement/key and uplinkHTTPMethod are packet-up-only in
        // xray's JSON conf: cookie/header placement and a `GET` method are
        // rejected outside packet-up mode. The panel builds the server via proto
        // (which skips that check), so a non-packet-up inbound can carry stale
        // values harmlessly — but the client parses the link through infra/conf
        // and would refuse to start. In other modes uplink is a single stream and
        // these knobs don't apply, so only advertise them under packet-up.
        if self.mode == Some(XhttpMode::PacketUp) {
            for (key, val) in [
                ("uplinkDataPlacement", self.uplink_data_placement.as_deref()),
                ("uplinkDataKey", self.uplink_data_key.as_deref()),
                ("uplinkHTTPMethod", self.uplink_http_method.as_deref()),
            ] {
                if let Some(v) = val.filter(|s| !s.is_empty()) {
                    extra.insert(key.to_owned(), serde_json::Value::String(v.to_owned()));
                }
            }
        }
        for (key, val) in [
            ("noGRPCHeader", self.no_grpc_header),
            ("noSSEHeader", self.no_sse_header),
        ] {
            if val.unwrap_or(false) {
                extra.insert(key.to_owned(), serde_json::Value::Bool(true));
            }
        }
        if !extra.is_empty() {
            params.push((
                "extra".to_owned(),
                serde_json::Value::Object(extra).to_string(),
            ));
        }
        params
    }
    fn build_settings(&self) -> anyhow::Result<TypedMessage> {
        let xmux = self.build_xmux()?;
        let headers: std::collections::HashMap<String, String> = self
            .headers
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        // Clamp the i64 column into the proto's int32 field. Upper bound
        // is lifted into i64 via the infallible `i64::from`; the clamped
        // result is in [0, i32::MAX] so the final `as i32` is exact.
        #[allow(clippy::cast_possible_truncation)]
        let server_max_header_bytes = self
            .server_max_header_bytes
            .map_or(0, |v| v.clamp(0, i64::from(i32::MAX)) as i32);
        let cfg = XraySplitHttpConfig {
            host: self.host.clone().unwrap_or_default(),
            path: self.path.clone().unwrap_or_default(),
            mode: self.mode.unwrap_or(XhttpMode::Auto).as_db_str().to_owned(),
            headers,
            x_padding_bytes: parse_range(self.x_padding_bytes.as_deref())?,
            no_grpc_header: self.no_grpc_header.unwrap_or(false),
            no_sse_header: self.no_sse_header.unwrap_or(false),
            sc_max_each_post_bytes: parse_range(self.sc_max_each_post_bytes.as_deref())?,
            sc_min_posts_interval_ms: parse_range(self.sc_min_posts_interval_ms.as_deref())?,
            sc_max_buffered_posts: self.sc_max_buffered_posts.unwrap_or(0),
            sc_stream_up_server_secs: parse_range(self.sc_stream_up_server_secs.as_deref())?,
            xmux,
            x_padding_obfs_mode: self.x_padding_obfs_mode.unwrap_or(false),
            x_padding_key: self.x_padding_key.clone().unwrap_or_default(),
            x_padding_header: self.x_padding_header.clone().unwrap_or_default(),
            x_padding_placement: self.x_padding_placement.clone().unwrap_or_default(),
            x_padding_method: self.x_padding_method.clone().unwrap_or_default(),
            uplink_http_method: self.uplink_http_method.clone().unwrap_or_default(),
            session_id_placement: self.session_id_placement.clone().unwrap_or_default(),
            session_id_key: self.session_id_key.clone().unwrap_or_default(),
            session_id_table: self.session_id_table.clone().unwrap_or_default(),
            session_id_length: parse_range(self.session_id_length.as_deref())?,
            seq_placement: self.seq_placement.clone().unwrap_or_default(),
            seq_key: self.seq_key.clone().unwrap_or_default(),
            uplink_data_placement: self.uplink_data_placement.clone().unwrap_or_default(),
            uplink_data_key: self.uplink_data_key.clone().unwrap_or_default(),
            uplink_chunk_size: parse_range(self.uplink_chunk_size.as_deref())?,
            server_max_header_bytes,
            h2_params: self.build_h2_params()?,
            ..XraySplitHttpConfig::default()
        };
        Ok(TypedMessage {
            r#type: TYPE_SPLITHTTP_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }
    fn quic_params_proto(&self) -> Option<XrayQuicParams> {
        self.quic_params.as_ref().map(QuicParams::to_proto)
    }
}

/// Parse "100" or "100-1000" into `RangeConfig`. Empty/None → None.
/// Accepts a single number (degenerate range with `from==to`) or a
/// dashed pair. Whitespace around the tokens is tolerated; everything
/// else is a hard error so the operator notices instead of silently
/// sending zero ranges to xray.
fn parse_range(input: Option<&str>) -> anyhow::Result<Option<RangeConfig>> {
    let Some(raw) = input else { return Ok(None) };
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if let Some((a, b)) = s.split_once('-') {
        let from: i32 = a
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("range '{raw}': cannot parse 'from' as i32: {e}"))?;
        let to: i32 = b
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("range '{raw}': cannot parse 'to' as i32: {e}"))?;
        return Ok(Some(RangeConfig { from, to }));
    }
    let n: i32 = s
        .parse()
        .map_err(|e| anyhow::anyhow!("range '{raw}': cannot parse as i32: {e}"))?;
    Ok(Some(RangeConfig { from: n, to: n }))
}

/// How `encoding/json` decodes each settable field of Go's
/// `net/http.HTTP2Config`. `CountError` is a func field with no JSON
/// representation, so it is deliberately absent.
#[derive(Clone, Copy)]
enum H2Kind {
    Duration,
    Integer,
    Boolean,
}

const H2_FIELDS: [(&str, H2Kind); 11] = [
    ("MaxConcurrentStreams", H2Kind::Integer),
    ("StrictMaxConcurrentRequests", H2Kind::Boolean),
    ("MaxDecoderHeaderTableSize", H2Kind::Integer),
    ("MaxEncoderHeaderTableSize", H2Kind::Integer),
    ("MaxReadFrameSize", H2Kind::Integer),
    ("MaxReceiveBufferPerConnection", H2Kind::Integer),
    ("MaxReceiveBufferPerStream", H2Kind::Integer),
    ("SendPingTimeout", H2Kind::Duration),
    ("PingTimeout", H2Kind::Duration),
    ("WriteByteTimeout", H2Kind::Duration),
    ("PermitProhibitedCipherSuites", H2Kind::Boolean),
];

/// Resolve an operator-typed key to its canonical spelling. Matching is
/// case-insensitive because `encoding/json` is, and an unknown key is an
/// error here precisely because it would *not* be one in the core.
fn canonical_h2_key(key: &str) -> anyhow::Result<(&'static str, H2Kind)> {
    H2_FIELDS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .map(|(name, kind)| (*name, *kind))
        .ok_or_else(|| {
            let known = H2_FIELDS.map(|(name, _)| name).join(", ");
            anyhow::anyhow!(
                "h2Params: unknown key '{key}' — the core would drop it without a word. Known keys: {known}"
            )
        })
}

/// Parse a single-unit Go duration (`"30s"`, `"500ms"`, `"2m"`) into whole
/// nanoseconds. Fractions and multi-part forms like `"1h30m"` are refused on
/// purpose: the error names a spelling that works instead of rounding behind
/// the operator's back.
fn parse_go_duration_nanos(field: &str, raw: &str) -> anyhow::Result<i64> {
    // Two-character units first, so "ms" is never read as "s".
    const UNITS: [(&str, i64); 6] = [
        ("ns", 1),
        ("us", 1_000),
        ("ms", 1_000_000),
        ("s", 1_000_000_000),
        ("m", 60_000_000_000),
        ("h", 3_600_000_000_000),
    ];
    let text = raw.trim();
    for (suffix, scale) in UNITS {
        let Some(number) = text.strip_suffix(suffix) else {
            continue;
        };
        let number = number.trim();
        let value: i64 = number.parse().map_err(|_| {
            anyhow::anyhow!(
                "h2Params '{field}': cannot read '{raw}' as a whole number of {suffix} (write 1500ms rather than 1.5s)"
            )
        })?;
        if value < 0 {
            return Err(anyhow::anyhow!("h2Params '{field}': '{raw}' is negative"));
        }
        return value
            .checked_mul(scale)
            .ok_or_else(|| anyhow::anyhow!("h2Params '{field}': '{raw}' overflows nanoseconds"));
    }
    Err(anyhow::anyhow!(
        "h2Params '{field}': '{raw}' needs a unit — one of ns, us, ms, s, m, h (for example \"30s\")"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_h2(raw: &str) -> XhttpTransport {
        XhttpTransport {
            h2_params: Some(raw.to_owned()),
            ..XhttpTransport::default()
        }
    }

    fn emitted(raw: &str) -> serde_json::Value {
        let bytes = with_h2(raw).build_h2_params().expect("accepted");
        serde_json::from_slice(&bytes).expect("emits JSON")
    }

    fn refused(raw: &str) -> String {
        with_h2(raw)
            .build_h2_params()
            .expect_err("should be refused")
            .to_string()
    }

    /// xray hands these bytes to plain `encoding/json`, which has no
    /// unmarshaller for `time.Duration`. Verified against the Go stdlib:
    /// `"30s"` is a hard error there and a bare `30` is thirty *nanoseconds*.
    /// Converting here is the only place the operator's intent survives.
    #[test]
    fn duration_strings_become_whole_nanoseconds() {
        let v = emitted(r#"{"SendPingTimeout":"30s","PingTimeout":"10s"}"#);
        assert_eq!(v["SendPingTimeout"], 30_000_000_000_i64);
        assert_eq!(v["PingTimeout"], 10_000_000_000_i64);
    }

    /// The presets are pretty-printed, and an operator may well paste a
    /// formatted document too. Whitespace is JSON's business; what reaches
    /// xray is the same compact object either way.
    #[test]
    fn pretty_printed_json_is_accepted_and_sent_compact() {
        let raw = "{\n  \"SendPingTimeout\": \"30s\",\n  \"WriteByteTimeout\": \"30s\"\n}";
        let bytes = with_h2(raw).build_h2_params().expect("accepted");
        let text = String::from_utf8(bytes).expect("utf-8");
        assert!(!text.contains('\n') && !text.contains(' '), "{text}");
        let v: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(v["SendPingTimeout"], 30_000_000_000_i64);
        assert_eq!(v["WriteByteTimeout"], 30_000_000_000_i64);
    }

    #[test]
    fn every_unit_scales() {
        for (text, nanos) in [
            ("5ns", 5_i64),
            ("250us", 250_000),
            ("500ms", 500_000_000),
            ("30s", 30_000_000_000),
            ("2m", 120_000_000_000),
            ("1h", 3_600_000_000_000),
        ] {
            let v = emitted(&format!(r#"{{"WriteByteTimeout":"{text}"}}"#));
            assert_eq!(v["WriteByteTimeout"], nanos, "unit {text}");
        }
    }

    /// The trap that would hurt most: `30` reaches the core as 30ns and it
    /// pings in a tight loop. Nothing downstream would complain.
    #[test]
    fn a_bare_number_duration_is_refused() {
        let err = refused(r#"{"SendPingTimeout":30}"#);
        assert!(err.contains("duration string"), "{err}");
        assert!(err.contains("nanoseconds"), "{err}");
    }

    /// Go accepts "1.5s"; `encoding/json` into `time.Duration` does not. Say
    /// so, and name a spelling that works.
    #[test]
    fn a_fraction_is_refused_and_names_the_fix() {
        let err = refused(r#"{"PingTimeout":"1.5s"}"#);
        assert!(err.contains("1500ms"), "{err}");
    }

    #[test]
    fn a_duration_without_a_unit_is_refused() {
        let err = refused(r#"{"PingTimeout":"10"}"#);
        assert!(err.contains("needs a unit"), "{err}");
    }

    #[test]
    fn a_negative_duration_is_refused() {
        assert!(refused(r#"{"PingTimeout":"-5s"}"#).contains("negative"));
    }

    /// `encoding/json` drops keys it doesn't recognise without a word, so a
    /// typo would silently configure nothing at all on the listener.
    #[test]
    fn an_unknown_key_is_refused() {
        let err = refused(r#"{"SendPingInterval":"30s"}"#);
        assert!(err.contains("unknown key"), "{err}");
        assert!(
            err.contains("SendPingTimeout"),
            "the error lists the real keys: {err}"
        );
    }

    /// ...but the keys it *does* know are matched ignoring case, so the panel
    /// has to accept the same spellings and emit the canonical one.
    #[test]
    fn keys_match_ignoring_case_and_come_out_canonical() {
        let v = emitted(r#"{"sendpingtimeout":"30s"}"#);
        assert_eq!(v["SendPingTimeout"], 30_000_000_000_i64);
        assert!(v.get("sendpingtimeout").is_none());
    }

    /// Two spellings of one field would silently collapse in the core, last
    /// one winning. Better to say which key is doubled.
    #[test]
    fn the_same_key_twice_in_two_cases_is_refused() {
        let err = refused(r#"{"PingTimeout":"1s","pingtimeout":"2s"}"#);
        assert!(err.contains("twice"), "{err}");
    }

    #[test]
    fn integers_and_booleans_keep_their_shape() {
        let v =
            emitted(r#"{"MaxReceiveBufferPerStream":4194304,"PermitProhibitedCipherSuites":true}"#);
        assert_eq!(v["MaxReceiveBufferPerStream"], 4_194_304_i64);
        assert_eq!(v["PermitProhibitedCipherSuites"], true);
    }

    #[test]
    fn a_wrongly_typed_value_is_refused() {
        assert!(refused(r#"{"MaxReadFrameSize":"big"}"#).contains("whole number"));
        assert!(refused(r#"{"StrictMaxConcurrentRequests":1}"#).contains("true or false"));
        assert!(refused(r#"{"MaxReadFrameSize":-1}"#).contains("non-negative"));
    }

    #[test]
    fn blank_input_emits_no_bytes() {
        for raw in ["", "   "] {
            assert!(
                with_h2(raw)
                    .build_h2_params()
                    .expect("blank is fine")
                    .is_empty()
            );
        }
        assert!(
            XhttpTransport::default()
                .build_h2_params()
                .expect("absent is fine")
                .is_empty()
        );
    }

    #[test]
    fn malformed_input_is_refused() {
        assert!(refused("not json").contains("not valid JSON"));
        assert!(refused("[1,2]").contains("must be a JSON object"));
    }

    /// `h2Params` configures the *listener*. A client that merged it into its
    /// own xhttpSettings would be configuring nothing, so it must never ride
    /// the share link the way the symmetric knobs do.
    #[test]
    fn h2_params_stay_out_of_the_share_link() {
        let link = with_h2(r#"{"SendPingTimeout":"30s"}"#).share_link_params();
        assert!(
            link.iter()
                .all(|(k, v)| !k.contains("h2") && !v.contains("SendPingTimeout")),
            "{link:?}"
        );
    }

    /// Wiring: the normalised bytes have to reach proto field 30, not just
    /// validate cleanly on their own.
    #[test]
    fn the_bytes_reach_the_proto_field() {
        let msg = with_h2(r#"{"SendPingTimeout":"30s"}"#)
            .build_settings()
            .expect("builds");
        let cfg = XraySplitHttpConfig::decode(msg.value.as_slice()).expect("decodes");
        assert_eq!(
            cfg.h2_params,
            br#"{"SendPingTimeout":30000000000}"#.to_vec()
        );
    }

    /// An inbound that never touches the field must encode byte-identically
    /// to one from before it existed, or every stored inbound changes shape.
    #[test]
    fn an_untouched_inbound_leaves_the_field_empty() {
        let msg = XhttpTransport::default().build_settings().expect("builds");
        let cfg = XraySplitHttpConfig::decode(msg.value.as_slice()).expect("decodes");
        assert!(cfg.h2_params.is_empty());
    }
}

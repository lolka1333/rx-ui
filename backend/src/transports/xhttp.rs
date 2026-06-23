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
    // length. The serde aliases keep configs stored under the old keys
    // readable so nothing in the DB needs migrating.
    #[serde(alias = "session_placement")]
    pub session_id_placement: Option<String>,
    #[serde(alias = "session_key")]
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
        // Padding-obfuscation is a *symmetric* wire feature: the server pads
        // every request, so a client that doesn't pad identically can't
        // connect. xray carries the advanced xhttpSettings in the
        // share-link's `extra` param — a JSON the client merges into its own
        // xhttpSettings (field names match xray's conf: xPaddingObfsMode,
        // xPaddingKey, …). Only emitted when obfs is actually on, so plain
        // inbounds keep a clean link.
        if self.x_padding_obfs_mode.unwrap_or(false) {
            let mut extra = serde_json::Map::new();
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

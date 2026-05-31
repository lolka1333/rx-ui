//! WebSocket transport. xray-core marks WS as `PrintNonRemovalDeprecatedFeatureWarning`
//! ("deprecated but not going away"), so we keep it for CDN-fronted setups
//! where WS is the only viable upgrade mechanism. Defaults match the
//! operator-friendly path: `/` for path, empty host (use client SNI), no
//! headers, no PROXY-protocol, no heartbeat.

use super::{Transport, TransportKind};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::websocket::Config as XrayWsConfig;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ts_rs::TS;

const TYPE_WS_CONFIG: &str = "xray.transport.internet.websocket.Config";

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct WsTransport {
    /// URL path for the WS upgrade handshake. Defaults to "/". Behind a
    /// CDN this is the route the CDN forwards on.
    pub path: Option<String>,
    /// Override for the upstream Host header. Empty = use whatever the
    /// client sent. Used when CDN's incoming host differs from xray's
    /// expected vhost.
    pub host: Option<String>,
    /// Custom HTTP headers. `BTreeMap` for stable JSON serialization in
    /// the panel's persisted blob; converted to `HashMap` when feeding
    /// the prost-generated proto.
    pub headers: Option<BTreeMap<String, String>>,
    /// PROXY-protocol acceptance. When `true`, expects the front-end
    /// (nginx/HAProxy) to prepend PROXY headers so xray can see the
    /// real client IP.
    pub accept_proxy_protocol: Option<bool>,
    /// WS Ping interval in seconds. `0` (or `None`) = disabled. Useful
    /// behind CDNs that kill idle connections after N seconds.
    #[ts(type = "number | null")]
    pub heartbeat_period: Option<i64>,
}

impl Transport for WsTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Ws
    }
    fn xray_protocol_name(&self) -> &'static str {
        "websocket"
    }
    fn share_link_params(&self) -> Vec<(String, String)> {
        // WS clients (esp. older v2rayN) treat missing `path` as a
        // parse error, so always emit at least "/" as the default.
        let path = self
            .path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_owned();
        let mut params = vec![
            ("type".to_owned(), "ws".to_owned()),
            ("path".to_owned(), path),
        ];
        if let Some(h) = &self.host
            && !h.is_empty()
        {
            params.push(("host".to_owned(), h.clone()));
        }
        params
    }
    fn build_settings(&self) -> anyhow::Result<TypedMessage> {
        // BTreeMap → HashMap conversion: prost wants HashMap<String,String>;
        // we keep BTreeMap in panel state so the persisted JSON is byte-
        // stable across saves (HashMap iteration order is randomized).
        let header: std::collections::HashMap<String, String> = self
            .headers
            .as_ref()
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        // heartbeat_period is uint32 in the proto. Saturating-clamp the
        // i64 down so a wild operator value can't wrap silently. The
        // upper bound is `u32::MAX` lifted into i64 via the infallible
        // `i64::from`; the clamped value is in [0, u32::MAX] by
        // construction, so the final `as u32` truncation is exact.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let heartbeat_period = self
            .heartbeat_period
            .map_or(0, |v| v.clamp(0, i64::from(u32::MAX)) as u32);
        let cfg = XrayWsConfig {
            host: self.host.clone().unwrap_or_default(),
            path: self.path.clone().unwrap_or_default(),
            header,
            accept_proxy_protocol: self.accept_proxy_protocol.unwrap_or(false),
            // `ed` (early data) is parsed by xray from the path query
            // string (e.g. `/ws?ed=2048`) — operator types it into the
            // path field directly, no separate column needed.
            ed: 0,
            heartbeat_period,
        };
        Ok(TypedMessage {
            r#type: TYPE_WS_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }
}

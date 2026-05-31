//! Plain TCP transport. No headers, no path, no host — just raw TCP.
//! xray's default `TcpConfig` with `header_settings=None` and
//! `accept_proxy_protocol=false` is exactly what we want; there's nothing
//! operator-configurable here. The struct is empty for forward-compatibility
//! (if xray adds TCP-level knobs later we'll add fields without breaking
//! the public JSON shape).

use super::{Transport, TransportKind};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::tcp::Config as XrayTcpConfig;
use prost::Message;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

const TYPE_TCP_CONFIG: &str = "xray.transport.internet.tcp.Config";

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct TcpTransport {
    // intentionally empty — xray's TCP transport has nothing operator-tunable
}

impl Transport for TcpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tcp
    }
    fn xray_protocol_name(&self) -> &'static str {
        "tcp"
    }
    fn build_settings(&self) -> anyhow::Result<TypedMessage> {
        let cfg = XrayTcpConfig {
            header_settings: None,
            accept_proxy_protocol: false,
        };
        Ok(TypedMessage {
            r#type: TYPE_TCP_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }
}

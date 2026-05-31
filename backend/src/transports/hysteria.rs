//! Hysteria 2 QUIC transport. Tightly bound to the `protocols::hysteria`
//! proxy — the two are always wired together. TLS is mandatory (the
//! upstream hub bails with "tls config is nil" otherwise); cross-layer
//! validation lives in the inbound API handler so the operator sees a
//! 4xx at save time, not a cryptic runtime failure.

use super::quic::QuicParams;
use super::{Transport, TransportKind};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::QuicParams as XrayQuicParams;
use crate::xray::proto::xray::transport::internet::hysteria::Config as XrayHysteriaConfig;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use ts_rs::TS;

const TYPE_HYSTERIA_CONFIG: &str = "xray.transport.internet.hysteria.Config";
// `version` field selects hysteria 1 vs 2; the panel only exposes 2.
const HYSTERIA_VERSION_2: i32 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub enum HysteriaMasquerade {
    #[default]
    NotFound,
    File {
        root: String,
    },
    Proxy {
        url: String,
        rewrite_host: bool,
        insecure: bool,
    },
    String {
        content: String,
        headers: BTreeMap<String, String>,
        status_code: i32,
    },
}

impl HysteriaMasquerade {
    /// Wire value of upstream's `masq_type` switch in
    /// `transport/internet/hysteria/hub.go`.
    const fn proto_tag(&self) -> &'static str {
        match self {
            Self::NotFound => "404",
            Self::File { .. } => "file",
            Self::Proxy { .. } => "proxy",
            Self::String { .. } => "string",
        }
    }

    /// Write the active variant's fields into `cfg`. Inactive variants
    /// leave their `masq_*` siblings at zero — the upstream switch only
    /// reads the active arm's fields, so the rest stay defaulted.
    fn apply(&self, cfg: &mut XrayHysteriaConfig) {
        self.proto_tag().clone_into(&mut cfg.masq_type);
        match self {
            Self::NotFound => {}
            Self::File { root } => {
                cfg.masq_file.clone_from(root);
            }
            Self::Proxy {
                url,
                rewrite_host,
                insecure,
            } => {
                cfg.masq_url.clone_from(url);
                cfg.masq_url_rewrite_host = *rewrite_host;
                cfg.masq_url_insecure = *insecure;
            }
            Self::String {
                content,
                headers,
                status_code,
            } => {
                cfg.masq_string.clone_from(content);
                cfg.masq_string_headers = headers
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                cfg.masq_string_status_code = *status_code;
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct HysteriaTransport {
    /// Server-wide auth fallback. Used only when `users[]` is empty on
    /// the protocol side; the panel prefers per-user auth (Client.auth)
    /// and leaves this empty.
    pub auth: Option<String>,
    /// UDP session idle timeout in seconds. `None` ≡ upstream default (60s).
    #[ts(type = "number | null")]
    pub udp_idle_timeout: Option<i64>,
    #[serde(default)]
    pub masquerade: HysteriaMasquerade,
    /// Stream-level QUIC tuning. xray reads this off
    /// `StreamConfig.quic_params`, not the hysteria proto itself, so
    /// the orchestrator routes it via the shared `Transport::quic_params_proto`
    /// trait method. `None` leaves all QUIC knobs at xray defaults.
    pub quic_params: Option<QuicParams>,
}

impl Transport for HysteriaTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Hysteria
    }
    fn xray_protocol_name(&self) -> &'static str {
        "hysteria"
    }
    fn build_settings(&self) -> anyhow::Result<TypedMessage> {
        let mut cfg = XrayHysteriaConfig {
            version: HYSTERIA_VERSION_2,
            auth: self.auth.clone().unwrap_or_default(),
            udp_idle_timeout: self.udp_idle_timeout.unwrap_or(0),
            ..XrayHysteriaConfig::default()
        };
        self.masquerade.apply(&mut cfg);
        Ok(TypedMessage {
            r#type: TYPE_HYSTERIA_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }
    fn quic_params_proto(&self) -> Option<XrayQuicParams> {
        self.quic_params.as_ref().map(QuicParams::to_proto)
    }
    // share_link_params: default impl returns `[("type", "hysteria")]`,
    // never consulted because hysteria builds its own `hysteria2://` URL.
}

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
// Field 1 used to be `version`, selecting hysteria 1 vs 2; the panel only ever
// sent 2. xray v26.9.8 reserved the number and dropped hysteria 1 with it, so
// there is nothing left to select.

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
        /// Add `X-Forwarded-For/-Host/-Proto` so the site behind the proxy
        /// sees the visitor rather than the server. Absent in older rows.
        #[serde(default)]
        x_forwarded: bool,
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
                x_forwarded,
            } => {
                cfg.masq_url.clone_from(url);
                cfg.masq_url_rewrite_host = *rewrite_host;
                cfg.masq_url_insecure = *insecure;
                cfg.masq_url_x_forwarded = *x_forwarded;
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
    /// The connection password.
    ///
    /// On an INBOUND it is a server-wide fallback, used only when `users[]` is
    /// empty on the protocol side — the panel prefers per-user auth
    /// (`Client.auth`) and leaves it empty. On an OUTBOUND it is required and
    /// is where the dialer reads the upstream's password from
    /// (`orchestrator::outbound_to_handler_config`), which is why the outbound
    /// validator rejects an empty one.
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
    /// Port hopping — client side only (see `transports::udphop`). On an
    /// inbound it is never pushed to xray: it reaches clients through the
    /// share link. On an outbound it is pushed as the last UDP mask.
    #[serde(default)]
    pub udp_hop: Option<super::udphop::UdpHop>,
}

/// The core's limits for `udpIdleTimeout` (`HysteriaConfig.Build`).
const UDP_IDLE_TIMEOUT_SECS: std::ops::RangeInclusive<i64> = 2..=600;

impl HysteriaTransport {
    /// What xray's own loader would refuse — the panel pushes over gRPC, which
    /// skips it — plus hopping next to XICMP, which the core only refuses when
    /// the first connection is dialled. `finalmask` is the mask this transport
    /// runs under.
    pub fn validate(&self, finalmask: &super::finalmask::FinalMask) -> Result<(), String> {
        if let Some(t) = self
            .udp_idle_timeout
            .filter(|t| *t != 0 && !UDP_IDLE_TIMEOUT_SECS.contains(t))
        {
            return Err(format!(
                "UDP idle timeout must be {}-{} s, got {t}",
                UDP_IDLE_TIMEOUT_SECS.start(),
                UDP_IDLE_TIMEOUT_SECS.end()
            ));
        }
        if let Some(q) = &self.quic_params {
            q.validate()?;
        }
        if let Some(hop) = self.udp_hop.as_ref().filter(|h| h.is_active()) {
            hop.validate()?;
            if matches!(finalmask, super::finalmask::FinalMask::Xicmp(_)) {
                return Err(
                    "port hopping cannot run with XICMP: both open their own socket, \
                            and the core allows only one of them"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::finalmask::{FinalMask, XicmpParams};
    use crate::transports::udphop::{UdpHop, UdpHopRemote};

    fn hopping() -> HysteriaTransport {
        HysteriaTransport {
            udp_hop: Some(UdpHop {
                local: true,
                ..UdpHop::default()
            }),
            ..HysteriaTransport::default()
        }
    }

    #[test]
    fn hopping_and_xicmp_cannot_share_the_socket() {
        let xicmp = FinalMask::Xicmp(XicmpParams {
            allowed_client_ips: vec![],
            server_ips: vec!["203.0.113.9".into()],
            dgram: false,
        });
        let err = hopping().validate(&xicmp).unwrap_err();
        assert!(err.contains("XICMP"), "got: {err}");
        assert_eq!(hopping().validate(&FinalMask::None), Ok(()));
        // An inactive hopping block is no hopping: XICMP stays allowed.
        let idle = HysteriaTransport {
            udp_hop: Some(UdpHop {
                remote: UdpHopRemote::Off,
                ..UdpHop::default()
            }),
            ..HysteriaTransport::default()
        };
        assert_eq!(idle.validate(&xicmp), Ok(()));
    }

    #[test]
    fn udp_idle_timeout_follows_the_core_limits() {
        for (t, ok) in [(0, true), (2, true), (600, true), (1, false), (601, false)] {
            let tr = HysteriaTransport {
                udp_idle_timeout: Some(t),
                ..HysteriaTransport::default()
            };
            assert_eq!(tr.validate(&FinalMask::None).is_ok(), ok, "timeout {t}");
        }
    }

    #[test]
    fn proxy_masquerade_carries_x_forwarded() {
        let tr = HysteriaTransport {
            masquerade: HysteriaMasquerade::Proxy {
                url: "https://example.com".into(),
                rewrite_host: true,
                insecure: false,
                x_forwarded: true,
            },
            ..HysteriaTransport::default()
        };
        let msg = tr.build_settings().unwrap();
        let cfg = XrayHysteriaConfig::decode(msg.value.as_slice()).unwrap();
        assert_eq!(cfg.masq_type, "proxy");
        assert!(cfg.masq_url_rewrite_host && cfg.masq_url_x_forwarded);
        // Rows saved before the field existed still load, with it off.
        let old: HysteriaMasquerade = serde_json::from_str(
            r#"{"kind":"proxy","url":"https://example.com","rewrite_host":false,"insecure":false}"#,
        )
        .unwrap();
        assert!(matches!(
            old,
            HysteriaMasquerade::Proxy {
                x_forwarded: false,
                ..
            }
        ));
    }
}

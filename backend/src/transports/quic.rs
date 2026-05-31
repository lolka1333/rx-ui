//! Stream-level QUIC parameters. Lives outside any single transport
//! because xray exposes them on `StreamConfig.quic_params` and shares
//! them across QUIC-based transports (Hysteria 2 today, H3-XHTTP if
//! we ever surface it). The Hysteria transport carries an
//! `Option<QuicParams>` field; the orchestrator pulls it out via the
//! `Transport::quic_params_proto` trait method when assembling the
//! `StreamConfig` proto.
//!
//! Every field is operator-tunable but optional — leaving them
//! `None` defers to xray's hard-coded defaults (which are sensible
//! for most deployments).

use crate::xray::proto::xray::transport::internet::{
    QuicParams as XrayQuicParams, UdpHop as XrayUdpHop,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Congestion-control algorithm. xray's hysteria hub maps these
/// strings 1:1 — see `hub.go` switch over `quicParams.Congestion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub enum QuicCongestion {
    /// CUBIC-like classic TCP. Rare in QUIC deployments.
    Reno,
    /// Google's Bottleneck Bandwidth and RTT — adaptive, no fixed cap.
    Bbr,
    /// Brutal — operator-set fixed bandwidth, ignores congestion signals.
    /// Falls back to BBR if `brutal_up`/`brutal_down` are unset.
    Brutal,
    /// Brutal but never falls back — even with no caps it stays in
    /// Brutal mode (effectively a no-op). Useful only for tests.
    #[serde(rename = "force-brutal")]
    ForceBrutal,
}

impl QuicCongestion {
    /// Wire value sent to xray. Matches the kebab-case JSON form.
    pub const fn as_xray_str(self) -> &'static str {
        match self {
            Self::Reno => "reno",
            Self::Bbr => "bbr",
            Self::Brutal => "brutal",
            Self::ForceBrutal => "force-brutal",
        }
    }
}

/// UDP port-hopping — defeats simple port-based blocking by rotating
/// the listening port from the `ports` set every `interval_min..max`
/// seconds.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct UdpHop {
    /// Ports to rotate through. Must contain at least one entry.
    pub ports: Vec<u32>,
    /// Lower bound of the random hop interval, in seconds.
    #[ts(type = "number")]
    pub interval_min: i64,
    /// Upper bound. `min == max` produces a fixed cadence.
    #[ts(type = "number")]
    pub interval_max: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct QuicParams {
    pub congestion: Option<QuicCongestion>,
    /// BBR sub-profile (e.g. "standard", "fastpath"). Only consulted
    /// when `congestion == Bbr` or Brutal-fallback hits BBR.
    pub bbr_profile: Option<String>,
    /// Brutal-mode upstream cap, **megabits/sec** in xray's wire
    /// format. Required when `congestion == Brutal` for the cap to
    /// have effect (else falls back to BBR).
    #[ts(type = "number | null")]
    pub brutal_up_mbps: Option<u64>,
    /// Brutal-mode downstream cap, megabits/sec.
    #[ts(type = "number | null")]
    pub brutal_down_mbps: Option<u64>,
    pub udp_hop: Option<UdpHop>,
    /// Initial QUIC stream receive window, in bytes.
    #[ts(type = "number | null")]
    pub init_stream_receive_window: Option<u64>,
    #[ts(type = "number | null")]
    pub max_stream_receive_window: Option<u64>,
    #[ts(type = "number | null")]
    pub init_conn_receive_window: Option<u64>,
    #[ts(type = "number | null")]
    pub max_conn_receive_window: Option<u64>,
    /// Connection idle timeout, seconds. 0 / `None` ≡ xray default.
    #[ts(type = "number | null")]
    pub max_idle_timeout_secs: Option<i64>,
    /// QUIC keepalive period, seconds. 0 disables.
    #[ts(type = "number | null")]
    pub keep_alive_period_secs: Option<i64>,
    /// Skip the QUIC Path MTU discovery probe. Set for misbehaving
    /// middleboxes that drop the probe packets.
    pub disable_path_mtu_discovery: bool,
    /// Max concurrent inbound streams per connection. 0 ≡ default.
    #[ts(type = "number | null")]
    pub max_incoming_streams: Option<i64>,
}

impl QuicParams {
    /// Convert into the xray proto message. Empty / `None` fields
    /// become zero values, which xray interprets as "use my default".
    pub fn to_proto(&self) -> XrayQuicParams {
        XrayQuicParams {
            congestion: self
                .congestion
                .map_or_else(String::new, |c| c.as_xray_str().to_owned()),
            bbr_profile: self.bbr_profile.clone().unwrap_or_default(),
            brutal_up: self.brutal_up_mbps.unwrap_or(0),
            brutal_down: self.brutal_down_mbps.unwrap_or(0),
            udp_hop: self.udp_hop.as_ref().map(|h| XrayUdpHop {
                ports: h.ports.clone(),
                interval_min: h.interval_min,
                interval_max: h.interval_max,
            }),
            init_stream_receive_window: self.init_stream_receive_window.unwrap_or(0),
            max_stream_receive_window: self.max_stream_receive_window.unwrap_or(0),
            init_conn_receive_window: self.init_conn_receive_window.unwrap_or(0),
            max_conn_receive_window: self.max_conn_receive_window.unwrap_or(0),
            max_idle_timeout: self.max_idle_timeout_secs.unwrap_or(0),
            keep_alive_period: self.keep_alive_period_secs.unwrap_or(0),
            disable_path_mtu_discovery: self.disable_path_mtu_discovery,
            max_incoming_streams: self.max_incoming_streams.unwrap_or(0),
        }
    }
}

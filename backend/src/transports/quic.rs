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

use crate::xray::proto::xray::transport::internet::QuicParams as XrayQuicParams;
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
    /// Client side only: stop the Hysteria dialer from imitating Chrome's QUIC
    /// handshake. The imitation pins Chrome's numbers (6 MiB stream and 15 MiB
    /// connection starting windows, 30 s idle) over whatever is set above, so
    /// the windows reach a client only with this on. The server never reads it.
    /// Absent in rows saved before the field existed, hence the default.
    #[serde(default)]
    pub disable_chrome_parrot: bool,
}

/// Limits xray's JSON loader enforces on `quicParams` (`QuicParamsConfig.Build`).
/// The panel pushes over gRPC, which skips that loader, and share links hand
/// these values to client apps that DO run it — one value out of range there
/// rejects the client's whole config. So they are checked here, once, for both.
const MIN_RECEIVE_WINDOW: u64 = 16_384;
const IDLE_TIMEOUT_SECS: std::ops::RangeInclusive<i64> = 4..=120;
const KEEP_ALIVE_SECS: std::ops::RangeInclusive<i64> = 2..=60;
const MIN_INCOMING_STREAMS: i64 = 8;
const BBR_PROFILES: [&str; 3] = ["conservative", "standard", "aggressive"];

impl QuicParams {
    /// Values xray's own loader would refuse (see the limits above). Zero or
    /// unset means "core default" and always passes.
    pub fn validate(&self) -> Result<(), String> {
        let windows = [
            (
                "initial stream receive window",
                self.init_stream_receive_window,
            ),
            ("max stream receive window", self.max_stream_receive_window),
            (
                "initial connection receive window",
                self.init_conn_receive_window,
            ),
            (
                "max connection receive window",
                self.max_conn_receive_window,
            ),
        ];
        for (name, value) in windows {
            if let Some(v) = value.filter(|&v| v != 0 && v < MIN_RECEIVE_WINDOW) {
                return Err(format!(
                    "QUIC {name} must be at least {MIN_RECEIVE_WINDOW} bytes, got {v}"
                ));
            }
        }
        let outside = |v: Option<i64>, range: &std::ops::RangeInclusive<i64>| {
            v.filter(|v| *v != 0 && !range.contains(v))
        };
        if let Some(v) = outside(self.max_idle_timeout_secs, &IDLE_TIMEOUT_SECS) {
            return Err(format!(
                "QUIC idle timeout must be {}-{} s, got {v}",
                IDLE_TIMEOUT_SECS.start(),
                IDLE_TIMEOUT_SECS.end()
            ));
        }
        if let Some(v) = outside(self.keep_alive_period_secs, &KEEP_ALIVE_SECS) {
            return Err(format!(
                "QUIC keepalive must be {}-{} s, got {v}",
                KEEP_ALIVE_SECS.start(),
                KEEP_ALIVE_SECS.end()
            ));
        }
        if let Some(v) = self
            .max_incoming_streams
            .filter(|v| *v != 0 && *v < MIN_INCOMING_STREAMS)
        {
            return Err(format!(
                "QUIC max incoming streams must be at least {MIN_INCOMING_STREAMS}, got {v}"
            ));
        }
        // Sent to the core verbatim: the gRPC path does not lower-case it the
        // way the JSON loader does, so only the exact spellings are let through.
        if let Some(p) = self.bbr_profile.as_deref().filter(|p| !p.is_empty())
            && !BBR_PROFILES.contains(&p)
        {
            return Err(format!(
                "BBR profile must be one of {}, got {p:?}",
                BBR_PROFILES.join(", ")
            ));
        }
        Ok(())
    }

    /// The part of this tuning a Hysteria CLIENT runs with, in xray's
    /// `finalmask.quicParams` JSON shape — what a share link carries inside
    /// `fm`. Only the client's own knobs: keepalive (the server never pings, so
    /// an idle tunnel dies at 30 s without it), the receive windows (a client's
    /// windows are what bound its downloads) and the Chrome switch. Congestion,
    /// idle timeout and stream limits stay server-side. `None` when none is set.
    pub fn client_share_json(&self) -> Option<serde_json::Value> {
        let mut out = serde_json::Map::new();
        if let Some(v) = self.keep_alive_period_secs.filter(|v| *v > 0) {
            out.insert("keepAlivePeriod".to_owned(), v.into());
        }
        let windows = [
            ("initStreamReceiveWindow", self.init_stream_receive_window),
            ("maxStreamReceiveWindow", self.max_stream_receive_window),
            ("initConnectionReceiveWindow", self.init_conn_receive_window),
            ("maxConnectionReceiveWindow", self.max_conn_receive_window),
        ];
        for (key, value) in windows {
            if let Some(v) = value.filter(|v| *v > 0) {
                out.insert(key.to_owned(), v.into());
            }
        }
        if self.disable_chrome_parrot {
            out.insert("disableChromeParrot".to_owned(), true.into());
        }
        (!out.is_empty()).then_some(serde_json::Value::Object(out))
    }

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
            disable_chrome_parrot: self.disable_chrome_parrot,
            // Three switches xray v26.9.8 added to this message. The panel does
            // not model them yet, and `false` is the core's own default for
            // every one of them, so the emitted config is unchanged — they are
            // named rather than left to `..default()` because this struct is
            // exhaustively initialised on purpose: the compiler is what caught
            // both the v26.9.8 and the v26.9.9 renumbering, and it can only do
            // that while every field is spelled out.
            brutal_disable_loss_compensation: false,
            disable_gso: false,
            disable_stateless_reset: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_and_zero_values_pass() {
        assert_eq!(QuicParams::default().validate(), Ok(()));
        let zeros = QuicParams {
            init_stream_receive_window: Some(0),
            max_idle_timeout_secs: Some(0),
            keep_alive_period_secs: Some(0),
            max_incoming_streams: Some(0),
            bbr_profile: Some(String::new()),
            ..QuicParams::default()
        };
        assert_eq!(zeros.validate(), Ok(()));
    }

    #[test]
    fn limits_match_the_core_loader() {
        let bad = [
            QuicParams {
                max_conn_receive_window: Some(16_383),
                ..QuicParams::default()
            },
            QuicParams {
                max_idle_timeout_secs: Some(3),
                ..QuicParams::default()
            },
            QuicParams {
                max_idle_timeout_secs: Some(121),
                ..QuicParams::default()
            },
            QuicParams {
                keep_alive_period_secs: Some(1),
                ..QuicParams::default()
            },
            QuicParams {
                keep_alive_period_secs: Some(61),
                ..QuicParams::default()
            },
            QuicParams {
                keep_alive_period_secs: Some(-1),
                ..QuicParams::default()
            },
            QuicParams {
                max_incoming_streams: Some(7),
                ..QuicParams::default()
            },
            QuicParams {
                bbr_profile: Some("Standard".to_owned()),
                ..QuicParams::default()
            },
        ];
        for q in bad {
            assert!(q.validate().is_err(), "accepted {q:?}");
        }
        let edges = QuicParams {
            init_stream_receive_window: Some(16_384),
            max_idle_timeout_secs: Some(120),
            keep_alive_period_secs: Some(2),
            max_incoming_streams: Some(8),
            bbr_profile: Some("conservative".to_owned()),
            ..QuicParams::default()
        };
        assert_eq!(edges.validate(), Ok(()));
    }

    #[test]
    fn client_share_json_carries_only_client_knobs() {
        assert_eq!(QuicParams::default().client_share_json(), None);
        let q = QuicParams {
            congestion: Some(QuicCongestion::Bbr),
            max_idle_timeout_secs: Some(60),
            max_incoming_streams: Some(64),
            keep_alive_period_secs: Some(10),
            init_stream_receive_window: Some(1_048_576),
            max_stream_receive_window: Some(1_048_576),
            init_conn_receive_window: Some(67_108_864),
            max_conn_receive_window: Some(67_108_864),
            disable_chrome_parrot: true,
            ..QuicParams::default()
        };
        assert_eq!(
            q.client_share_json(),
            Some(serde_json::json!({
                "keepAlivePeriod": 10,
                "initStreamReceiveWindow": 1_048_576,
                "maxStreamReceiveWindow": 1_048_576,
                "initConnectionReceiveWindow": 67_108_864,
                "maxConnectionReceiveWindow": 67_108_864,
                "disableChromeParrot": true,
            }))
        );
    }

    #[test]
    fn rows_saved_before_the_switch_still_load() {
        let old = r#"{"congestion":null,"bbr_profile":null,"brutal_up_mbps":null,
            "brutal_down_mbps":null,"init_stream_receive_window":null,
            "max_stream_receive_window":null,"init_conn_receive_window":null,
            "max_conn_receive_window":null,"max_idle_timeout_secs":null,
            "keep_alive_period_secs":10,"disable_path_mtu_discovery":false,
            "max_incoming_streams":null}"#;
        let q: QuicParams = serde_json::from_str(old).expect("legacy row");
        assert!(!q.disable_chrome_parrot);
        assert!(!q.to_proto().disable_chrome_parrot);
        let on = QuicParams {
            disable_chrome_parrot: true,
            ..QuicParams::default()
        };
        assert!(on.to_proto().disable_chrome_parrot);
    }
}

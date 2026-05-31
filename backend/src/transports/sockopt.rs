//! Per-inbound socket options (`streamSettings.sockopt`).
//!
//! Only the knobs that matter for an inbound listener are surfaced. Xray's
//! full `SocketConfig` has ~20 operator-settable fields, but most are
//! Linux-only routing knobs (mark, interface, tproxy, congestion, …) or
//! only affect *outbound* dialing (domainStrategy, dialerProxy,
//! happyEyeballs, …) — neither is useful for a panel that manages inbounds.
//! We expose the security-, compatibility- and stability-relevant subset:
//!
//!   * `trusted_x_forwarded_for` — REQUIRED-soon for XHTTP/WS/HU inbounds.
//!     xray-core #6159 (commit ab69985f) now warns when an XHTTP/WS/
//!     `HttpUpgrade` inbound has no `sockopt.trustedXForwardedFor`, because
//!     it otherwise trusts the `X-Forwarded-For` header IMPLICITLY — a
//!     client can spoof its source IP, poisoning per-IP stats and any
//!     IP-based routing. The release note says it becomes mandatory in a
//!     future version. Set it to the CIDR(s) of whatever sits in front of
//!     xray (your CDN / reverse proxy), or leave empty for a directly
//!     exposed inbound where no proxy is trusted.
//!   * `tcp_keep_alive_interval` / `tcp_keep_alive_idle` — OS keepalive so
//!     dead peers get reaped instead of hanging (helps the "connection
//!     periodically stalls" class of problems on mobile / NAT).
//!   * `tcp_mptcp` — multipath TCP when both ends support it.
//!   * `accept_proxy_protocol` — believe a PROXY-protocol (v1/v2) header
//!     from a trusted upstream TCP load-balancer / proxy, so xray sees the
//!     real client IP instead of the balancer's. Enable ONLY when the thing
//!     in front actually speaks PROXY protocol, else the first bytes of
//!     every connection get misparsed.
//!   * `tcp_fast_open` — TFO on the listening socket (saves a round-trip on
//!     connection setup). `None`/0 ≡ leave the OS default, a positive value
//!     enables it with that pending-accept queue length (256 is the usual
//!     "on"), a negative value force-disables it.
//!   * `v6only` — `IPV6_V6ONLY` on a `[::]` listener. Off ≡ dual-stack (also
//!     accepts IPv4-mapped addresses); only meaningful on an IPv6 listen IP.
//!
//! Struct-level `#[serde(default)]` means a stored `{}` blob (the DB
//! column default) deserializes to an all-empty, inactive `SocketOpt`,
//! so every pre-existing inbound emits no sockopt block and its wire
//! output is byte-identical to before this field existed. The same default
//! covers rows written before a field was added, so growing this struct
//! never needs a migration — the JSON blob just gains keys.

use crate::xray::proto::xray::transport::internet::SocketConfig as XraySocketConfig;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Operator-facing socket options. Every field is optional; an instance
/// where nothing is set is inactive and contributes no `socket_settings`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(default)]
#[ts(export, export_to = "../../frontend/src/api/types/inbound.ts")]
pub struct SocketOpt {
    /// CIDRs / IPs of trusted upstream proxies whose `X-Forwarded-For`
    /// header xray may believe. Empty = trust nothing (the safe default
    /// for a directly-exposed inbound). xray-core #6159 warns when this
    /// is unset on XHTTP / WS / `HttpUpgrade` inbounds.
    pub trusted_x_forwarded_for: Vec<String>,
    /// TCP keepalive probe interval (seconds). 0 / unset ≡ xray default.
    #[ts(type = "number | null")]
    pub tcp_keep_alive_interval: Option<i64>,
    /// Idle time before the first keepalive probe (seconds). 0 / unset ≡
    /// xray default.
    #[ts(type = "number | null")]
    pub tcp_keep_alive_idle: Option<i64>,
    /// Enable multipath TCP (both peers must support it).
    pub tcp_mptcp: bool,
    /// Accept a PROXY-protocol header from a trusted upstream LB / proxy so
    /// xray recovers the real client IP. Enable only when something in
    /// front actually prepends one.
    pub accept_proxy_protocol: bool,
    /// TCP Fast Open. Maps straight to xray's `tfo`: `None`/0 leaves the OS
    /// default, a positive value enables TFO with that queue length (256 =
    /// typical "on"), a negative value force-disables it. The UI offers
    /// Default / Enabled (256) / Disabled (-1).
    #[ts(type = "number | null")]
    pub tcp_fast_open: Option<i32>,
    /// Listen IPv6-only on a `[::]` socket (`IPV6_V6ONLY`). Off ≡ dual-stack.
    pub v6only: bool,
}

impl SocketOpt {
    /// True when at least one knob is set — i.e. xray should receive a
    /// `socket_settings` block. An all-default instance returns false so
    /// the orchestrator omits it and the wire output is unchanged.
    pub fn is_active(&self) -> bool {
        !self.trusted_x_forwarded_for.is_empty()
            || self.tcp_keep_alive_interval.is_some_and(|v| v != 0)
            || self.tcp_keep_alive_idle.is_some_and(|v| v != 0)
            || self.tcp_mptcp
            || self.accept_proxy_protocol
            || self.tcp_fast_open.is_some_and(|v| v != 0)
            || self.v6only
    }

    /// Build the xray `SocketConfig` proto, or `None` when inactive.
    /// Only the exposed fields are set; everything else stays at the
    /// proto default (zero), which xray treats as "unset". The keepalive
    /// values are cast to the proto's i32 width (operator inputs are far
    /// below `i32::MAX` seconds, so the cast is lossless in practice).
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_proto(&self) -> Option<XraySocketConfig> {
        if !self.is_active() {
            return None;
        }
        Some(XraySocketConfig {
            trusted_x_forwarded_for: self.trusted_x_forwarded_for.clone(),
            tcp_keep_alive_interval: self.tcp_keep_alive_interval.unwrap_or(0) as i32,
            tcp_keep_alive_idle: self.tcp_keep_alive_idle.unwrap_or(0) as i32,
            tcp_mptcp: self.tcp_mptcp,
            accept_proxy_protocol: self.accept_proxy_protocol,
            tfo: self.tcp_fast_open.unwrap_or(0),
            v6only: self.v6only,
            ..XraySocketConfig::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_inactive_and_emits_no_proto() {
        let s = SocketOpt::default();
        assert!(!s.is_active());
        assert!(s.to_proto().is_none());
    }

    #[test]
    fn zero_keepalive_and_unset_tfo_stay_inactive() {
        // 0 / None are "leave xray default", not an active override.
        let s = SocketOpt {
            tcp_keep_alive_interval: Some(0),
            tcp_keep_alive_idle: Some(0),
            tcp_fast_open: Some(0),
            ..SocketOpt::default()
        };
        assert!(!s.is_active());
        assert!(s.to_proto().is_none());
    }

    #[test]
    fn each_new_field_activates_on_its_own() {
        assert!(
            SocketOpt {
                accept_proxy_protocol: true,
                ..SocketOpt::default()
            }
            .is_active()
        );
        assert!(
            SocketOpt {
                tcp_fast_open: Some(256),
                ..SocketOpt::default()
            }
            .is_active()
        );
        // negative TFO (force-disable) is still an active override
        assert!(
            SocketOpt {
                tcp_fast_open: Some(-1),
                ..SocketOpt::default()
            }
            .is_active()
        );
        assert!(
            SocketOpt {
                v6only: true,
                ..SocketOpt::default()
            }
            .is_active()
        );
    }

    #[test]
    fn proto_carries_every_exposed_field() {
        let s = SocketOpt {
            trusted_x_forwarded_for: vec!["10.0.0.0/8".into()],
            tcp_keep_alive_interval: Some(15),
            tcp_keep_alive_idle: Some(30),
            tcp_mptcp: true,
            accept_proxy_protocol: true,
            tcp_fast_open: Some(256),
            v6only: true,
        };
        let p = s.to_proto().expect("active");
        assert_eq!(p.trusted_x_forwarded_for, vec!["10.0.0.0/8".to_string()]);
        assert_eq!(p.tcp_keep_alive_interval, 15);
        assert_eq!(p.tcp_keep_alive_idle, 30);
        assert!(p.tcp_mptcp);
        assert!(p.accept_proxy_protocol);
        assert_eq!(p.tfo, 256);
        assert!(p.v6only);
    }
}

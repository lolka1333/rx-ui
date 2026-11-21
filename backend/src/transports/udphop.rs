//! Port hopping for Hysteria 2 — xray's `udphop` finalmask.
//!
//! It is a CLIENT-side layer only: the core's server half refuses it
//! (`udphop: client only`). So on an inbound it is never pushed to xray; it
//! rides to clients in the share link, and on an outbound it is pushed as the
//! last UDP mask. Two independent things can hop:
//!
//! * the client's own source port (`local`) — every interval the client opens
//!   a new socket and QUIC migrates onto it. Nothing to set up on the server,
//!   and to a middlebox each period looks like a new flow;
//! * the server port (`remote`), picked from `ports`. The server must accept
//!   on every one of them, which xray does not do by itself: the operator
//!   redirects the range to the inbound's port (iptables `REDIRECT`).
//!
//! Like XICMP it opens its own socket, and the core accepts only one such mask,
//! as the last of the list — the validators refuse hopping next to XICMP.

use crate::xray::proto::xray::common::serial::TypedMessage;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

const TYPE_UDPHOP_CONFIG: &str = "xray.transport.internet.finalmask.udphop.Config";
/// The core's floor for the hop interval (`NewUDPHopConn`, `UDPHop.Build`).
const MIN_INTERVAL_SECS: i64 = 5;
/// The core's default when no interval is given (`UDPHop.Build`).
const DEFAULT_INTERVAL_SECS: i64 = 30;

/// How the server port is chosen from [`UdpHop::ports`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub enum UdpHopRemote {
    /// Always the port the client dials.
    #[default]
    Off,
    /// A random one of `ports` for each connection, kept for its lifetime
    /// (core mode `perConnRemote`).
    PerConnection,
    /// A random one at the start and a new one every interval
    /// (core mode `intervalRemote`).
    Interval,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/transport.ts")]
pub struct UdpHop {
    /// Move to a new source port every interval (core mode `intervalLocal`).
    #[serde(default)]
    pub local: bool,
    #[serde(default)]
    pub remote: UdpHopRemote,
    /// Server ports to hop across, in the core's port-list syntax:
    /// `20000-30000` or `443,8443,20000-20100`. Used only when `remote` is on.
    #[serde(default)]
    pub ports: String,
    /// Seconds between hops, picked at random in `[min, max]` each time.
    /// Empty means the core's 30 s.
    #[ts(type = "number | null")]
    pub interval_min: Option<i64>,
    #[ts(type = "number | null")]
    pub interval_max: Option<i64>,
}

impl UdpHop {
    /// Whether anything hops at all. A stored block with both halves off is
    /// treated as no hopping.
    pub fn is_active(&self) -> bool {
        self.local || self.remote != UdpHopRemote::Off
    }

    /// `[min, max]` with the core's default filled in and the order fixed the
    /// way the core fixes it.
    fn interval(&self) -> (i64, i64) {
        let (a, b) = match (self.interval_min, self.interval_max) {
            (None, None) => (DEFAULT_INTERVAL_SECS, DEFAULT_INTERVAL_SECS),
            (Some(a), None) => (a, a),
            (None, Some(b)) => (b, b),
            (Some(a), Some(b)) => (a, b),
        };
        (a.min(b), a.max(b))
    }

    /// Parse [`Self::ports`] into `(from, to)` pairs, the same syntax the
    /// core's `PortList` reads. Unlike the core, a reversed range is refused
    /// rather than silently yielding no ports.
    pub fn port_ranges(&self) -> Result<Vec<(u16, u16)>, String> {
        let mut out = Vec::new();
        for item in self
            .ports
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let port = |s: &str| {
                s.trim()
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or_else(|| format!("port hopping: {s:?} is not a port (1-65535)"))
            };
            let (a, b) = item.split_once('-').unwrap_or((item, item));
            let range = (port(a)?, port(b)?);
            if range.0 > range.1 {
                return Err(format!("port hopping: range {item} runs backwards"));
            }
            out.push(range);
        }
        Ok(out)
    }

    /// Checks the core would apply at config load (and some it would only
    /// trip over at runtime). Inactive hopping always passes.
    pub fn validate(&self) -> Result<(), String> {
        if !self.is_active() {
            return Ok(());
        }
        for v in [self.interval_min, self.interval_max].into_iter().flatten() {
            if v < MIN_INTERVAL_SECS {
                return Err(format!(
                    "port hopping interval must be at least {MIN_INTERVAL_SECS} s, got {v}"
                ));
            }
        }
        let ranges = self.port_ranges()?;
        if self.remote != UdpHopRemote::Off && ranges.is_empty() {
            return Err("port hopping on the server port needs a list of ports".to_owned());
        }
        Ok(())
    }

    /// The core's `mode` string.
    fn mode(&self) -> String {
        let mut modes = Vec::new();
        if self.local {
            modes.push("intervalLocal");
        }
        match self.remote {
            UdpHopRemote::Off => {}
            UdpHopRemote::PerConnection => modes.push("perConnRemote"),
            UdpHopRemote::Interval => modes.push("intervalRemote"),
        }
        modes.join(",")
    }

    /// The `udphop` layer in xray's `finalmask.udp` JSON — what a share link
    /// puts in `fm`. `None` when nothing hops.
    pub fn share_json(&self) -> Option<serde_json::Value> {
        if !self.is_active() {
            return None;
        }
        let (min, max) = self.interval();
        let mut settings = serde_json::json!({
            "mode": self.mode(),
            "interval": format!("{min}-{max}"),
        });
        if self.remote != UdpHopRemote::Off {
            settings["remotePorts"] = self.ports.trim().into();
        }
        Some(serde_json::json!({ "type": "udphop", "settings": settings }))
    }

    /// The port list a standard `mport=` parameter carries — what clients
    /// that don't read `fm` (and v2rayN when there is no `fm`) hop across.
    /// `None` unless the server port hops.
    pub fn share_mport(&self) -> Option<String> {
        (self.is_active() && self.remote != UdpHopRemote::Off)
            .then(|| self.ports.split_whitespace().collect::<String>())
    }

    /// The `udphop` mask for a client's `StreamConfig.udpmasks`, appended
    /// LAST (the core reverses the list and wants the socket-owning mask
    /// first). `None` when nothing hops. The port list is expanded, as the
    /// core's own loader does (`PortList.Build().Ports()`).
    pub fn to_typed_message(&self) -> Option<TypedMessage> {
        use crate::xray::proto::xray::transport::internet::finalmask::udphop::Config;
        use prost::Message as _;
        if !self.is_active() {
            return None;
        }
        let (interval_min, interval_max) = self.interval();
        let remote_ports = if self.remote == UdpHopRemote::Off {
            Vec::new()
        } else {
            self.port_ranges()
                .unwrap_or_default()
                .into_iter()
                .flat_map(|(a, b)| u32::from(a)..=u32::from(b))
                .collect()
        };
        let cfg = Config {
            local: self.local,
            remote: self.remote == UdpHopRemote::Interval,
            remote_once: self.remote == UdpHopRemote::PerConnection,
            interval_min,
            interval_max,
            remote_i_ps: Vec::new(),
            remote_ports,
        };
        Some(TypedMessage {
            r#type: TYPE_UDPHOP_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(local: bool, remote: UdpHopRemote, ports: &str) -> UdpHop {
        UdpHop {
            local,
            remote,
            ports: ports.to_owned(),
            ..UdpHop::default()
        }
    }

    #[test]
    fn inactive_hopping_emits_nothing_and_passes() {
        let off = hop(false, UdpHopRemote::Off, "garbage");
        assert!(!off.is_active());
        assert_eq!(off.validate(), Ok(()));
        assert_eq!(off.share_json(), None);
        assert_eq!(off.share_mport(), None);
        assert!(off.to_typed_message().is_none());
    }

    #[test]
    fn port_list_parses_like_the_core() {
        let h = hop(false, UdpHopRemote::Interval, " 443, 20000-20002 ,8443");
        assert_eq!(
            h.port_ranges(),
            Ok(vec![(443, 443), (20000, 20002), (8443, 8443)])
        );
        for bad in ["0", "70000", "30000-20000", "abc", "1-"] {
            assert!(
                hop(false, UdpHopRemote::Interval, bad).validate().is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn remote_hopping_needs_ports_and_a_sane_interval() {
        assert!(
            hop(false, UdpHopRemote::PerConnection, "")
                .validate()
                .is_err()
        );
        assert_eq!(hop(true, UdpHopRemote::Off, "").validate(), Ok(()));
        let fast = UdpHop {
            interval_min: Some(4),
            ..hop(true, UdpHopRemote::Off, "")
        };
        assert!(fast.validate().is_err());
    }

    #[test]
    fn share_json_matches_the_core_loader_shape() {
        let h = UdpHop {
            interval_min: Some(40),
            interval_max: Some(20),
            ..hop(true, UdpHopRemote::Interval, "20000-30000")
        };
        assert_eq!(
            h.share_json(),
            Some(serde_json::json!({
                "type": "udphop",
                "settings": {
                    "mode": "intervalLocal,intervalRemote",
                    "interval": "20-40",
                    "remotePorts": "20000-30000",
                }
            }))
        );
        assert_eq!(h.share_mport().as_deref(), Some("20000-30000"));
        // Local-only hopping: no server ports to advertise.
        let local = hop(true, UdpHopRemote::Off, "20000-30000");
        assert_eq!(
            local.share_json().unwrap()["settings"],
            serde_json::json!({ "mode": "intervalLocal", "interval": "30-30" })
        );
        assert_eq!(local.share_mport(), None);
    }

    #[test]
    fn proto_expands_ports_and_maps_modes() {
        use crate::xray::proto::xray::transport::internet::finalmask::udphop::Config;
        use prost::Message as _;
        let msg = hop(false, UdpHopRemote::PerConnection, "443,20000-20002")
            .to_typed_message()
            .unwrap();
        assert_eq!(msg.r#type, TYPE_UDPHOP_CONFIG);
        let cfg = Config::decode(msg.value.as_slice()).unwrap();
        assert!(!cfg.local && !cfg.remote && cfg.remote_once);
        assert_eq!(cfg.remote_ports, vec![443, 20000, 20001, 20002]);
        assert_eq!((cfg.interval_min, cfg.interval_max), (30, 30));
    }
}

//! `WireGuard` inbound: the panel as a `WireGuard` server.
//!
//! The core's server half is the same `DeviceConfig` the outbound uses with
//! `is_client` off: the peers become `users`, and a connection is attributed to
//! one of them by the SOURCE ADDRESS INSIDE THE TUNNEL — `GetUserByAddr` in
//! `proxy/wireguard/server.go` walks each peer's `allowed_ips` looking for the
//! address that just spoke. Two consequences run through everything here:
//!
//!   * every client needs its own address out of the inbound's subnet, and it
//!     must be unique — two clients sharing one address are one user to xray,
//!     and their traffic lands on whichever peer is found first;
//!   * the address is the identity, so it is what per-client traffic accounting
//!     hangs off. Peers do get counted, unlike in most `WireGuard` servers.
//!
//! The device itself takes the subnet's first usable address.

use crate::models::Client;
use crate::protocols::Protocol;
use crate::xray::keygen::parse_wireguard_key;
use crate::xray::proto::xray::common::protocol::User;
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::proxy::wireguard::{DeviceConfig, PeerConfig};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use ts_rs::TS;

const TYPE_WIREGUARD_SERVER_CONFIG: &str = "xray.proxy.wireguard.DeviceConfig";
const TYPE_WIREGUARD_ACCOUNT: &str = "xray.proxy.wireguard.PeerConfig";

/// The core's own default, spelled out because the panel writes the config a
/// client will use and a blank MTU there is not the same as an absent one.
pub const DEFAULT_MTU: i32 = 1420;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub struct WireguardProtocol {
    /// The server device's private key, as `WireGuard` writes keys (base64).
    /// Generated when an inbound is created without one.
    pub secret_key: String,
    /// Derived from `secret_key`. Stored rather than derived on demand because
    /// every client config carries it, and a share link is built far from here.
    pub public_key: String,
    /// The tunnel network. The device takes the first usable address and every
    /// client gets one of the rest.
    pub subnet: String,
    /// 0 ≡ the core's default.
    #[serde(default)]
    pub mtu: i32,
    /// What a client's config should use for DNS. The core never reads it —
    /// it exists because a config without a resolver leaves the client with
    /// the network's own, which is usually the thing being avoided.
    #[serde(default)]
    pub dns: String,
    /// What goes on the client's `AllowedIPs` line: the traffic it sends into
    /// the tunnel. `0.0.0.0/0` is everything; narrowing it is split tunnelling.
    ///
    /// Client-side only — the core never sees this. The peer's own
    /// `allowed_ips` stays a `/32` no matter what is written here, because on
    /// the server side that field is the peer's identity.
    ///
    /// Deliberately not `::/0` by default: the tunnel is IPv4-only, so a client
    /// promised a v6 default route hands its IPv6 traffic to a device that has
    /// no v6 address and no v6 route — a black hole rather than a tunnel.
    // Defaulted through functions, not `Default::default()`: a row stored
    // before these fields existed has neither key in its JSON, and falling
    // back to ""/0 there would quietly drop the full-tunnel route and the
    // keepalive that inbound has been handing out all along.
    #[serde(default = "default_client_allowed_ips")]
    pub client_allowed_ips: String,
    /// Seconds between keepalives in the client's config. 0 omits the line.
    /// 25 is the usual choice: often enough to hold a NAT binding open, rare
    /// enough not to matter for a phone's battery.
    #[serde(default = "default_client_keepalive")]
    pub client_keepalive: i32,
    /// Whether a peer added to this inbound gets a pre-shared key.
    ///
    /// `WireGuard` itself treats one as optional — an extra symmetric secret
    /// mixed into a handshake that is already public-key — so this is the
    /// operator's call, not the panel's. Left on by default: the panel writes
    /// both sides of every config it hands out, so the key costs nothing and
    /// every implementation understands it.
    ///
    /// Turning it off changes nothing for peers that already have one; their
    /// configs keep working. It only decides what the next peer is issued.
    #[serde(default = "default_true")]
    pub issue_preshared_key: bool,
}

/// `AllowedIPs` for a client that should send everything through the tunnel.
pub const DEFAULT_CLIENT_ALLOWED_IPS: &str = "0.0.0.0/0";

/// Seconds between keepalives written into a client config.
pub const DEFAULT_CLIENT_KEEPALIVE: i32 = 25;

fn default_client_allowed_ips() -> String {
    DEFAULT_CLIENT_ALLOWED_IPS.to_owned()
}

const fn default_client_keepalive() -> i32 {
    DEFAULT_CLIENT_KEEPALIVE
}

const fn default_true() -> bool {
    true
}

impl Default for WireguardProtocol {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            public_key: String::new(),
            subnet: "10.66.66.0/24".to_owned(),
            mtu: DEFAULT_MTU,
            dns: "1.1.1.1".to_owned(),
            client_allowed_ips: DEFAULT_CLIENT_ALLOWED_IPS.to_owned(),
            client_keepalive: DEFAULT_CLIENT_KEEPALIVE,
            issue_preshared_key: true,
        }
    }
}

impl WireguardProtocol {
    /// The address the server device answers on — the first usable one in the
    /// subnet (`10.66.66.1` for `10.66.66.0/24`).
    pub fn device_address(&self) -> anyhow::Result<Ipv4Addr> {
        let (base, _) = parse_subnet(&self.subnet)?;
        Ok(Ipv4Addr::from(u32::from(base) + 1))
    }

    /// Every address a client may be given: the subnet minus the network
    /// address, the device's own, and the broadcast address.
    pub fn client_addresses(&self) -> anyhow::Result<impl Iterator<Item = Ipv4Addr>> {
        let (base, prefix) = parse_subnet(&self.subnet)?;
        let size = 1u32 << (32 - u32::from(prefix));
        let first = u32::from(base) + 2;
        let last = u32::from(base) + size - 2;
        Ok((first..=last).map(Ipv4Addr::from))
    }
}

/// `10.66.66.0/24` → the network address and its prefix.
///
/// IPv4 only, and deliberately: a `WireGuard` inbound hands out addresses, and
/// a v6 pool would double every address-assignment path for a tunnel whose
/// clients reach the internet through the node's own egress either way.
pub fn parse_subnet(subnet: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = subnet
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("subnet needs a prefix, e.g. 10.66.66.0/24"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("subnet is not an IPv4 network: {subnet}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| anyhow::anyhow!("subnet prefix is not a number: {subnet}"))?;
    // /30 leaves the device and exactly one client; anything wider than /8 is a
    // pool no panel needs and a mask that swallows the host's own network.
    anyhow::ensure!(
        (8..=30).contains(&prefix),
        "subnet prefix must be between 8 and 30: {subnet}"
    );
    // The network address itself, so that "first usable" is unambiguous.
    let mask = u32::MAX << (32 - u32::from(prefix));
    anyhow::ensure!(
        u32::from(addr) & mask == u32::from(addr),
        "{subnet} is a host address, not a network: try {}/{prefix}",
        Ipv4Addr::from(u32::from(addr) & mask)
    );
    Ok((addr, prefix))
}

impl Protocol for WireguardProtocol {
    fn build_proxy_settings(&self, users: Vec<User>) -> anyhow::Result<TypedMessage> {
        let cfg = DeviceConfig {
            secret_key: parse_wireguard_key(&self.secret_key)
                .map_err(|e| anyhow::anyhow!("wireguard private key: {e}"))?,
            endpoint: vec![self.device_address()?.to_string()],
            users,
            mtu: if self.mtu == 0 { DEFAULT_MTU } else { self.mtu },
            is_client: false,
            // `no_kernel_tun`, `reserved` and `domain_strategy` are deliberately
            // left at their proto defaults: the server path reads none of them.
            // It always builds a userspace gVisor TUN (`CreateNetTUN(..., false)`
            // in proxy/wireguard/server.go), and the other two are only ever
            // consulted by the client half.
            ..DeviceConfig::default()
        };
        Ok(TypedMessage {
            r#type: TYPE_WIREGUARD_SERVER_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }

    fn build_user(&self, client: &Client) -> anyhow::Result<User> {
        let public_key = client
            .wg_public_key
            .as_deref()
            .filter(|k| !k.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("client '{}' has no wireguard key", client.email))?;
        let address = client
            .wg_address
            .as_deref()
            .filter(|a| !a.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("client '{}' has no tunnel address", client.email))?;
        let account = PeerConfig {
            public_key: parse_wireguard_key(public_key)
                .map_err(|e| anyhow::anyhow!("client '{}': {e}", client.email))?,
            // The address IS the identity here: a /32 so this peer matches its
            // own traffic and nobody else's.
            allowed_ips: vec![format!("{}/32", address.trim())],
            // Optional second secret, shared by this peer and the server only.
            // The core writes it straight into the UAPI config, which speaks
            // hex — same conversion the public key goes through. Empty ≡ no
            // pre-shared key, which is what every row created before this
            // carries and what the core reads as "skip the line".
            pre_shared_key: match client.wg_preshared_key.as_deref() {
                Some(psk) if !psk.trim().is_empty() => parse_wireguard_key(psk)
                    .map_err(|e| anyhow::anyhow!("client '{}' preshared key: {e}", client.email))?,
                _ => String::new(),
            },
            ..PeerConfig::default()
        };
        Ok(User {
            level: 0,
            email: client.email.clone(),
            account: Some(TypedMessage {
                r#type: TYPE_WIREGUARD_ACCOUNT.to_owned(),
                value: account.encode_to_vec(),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_subnet_yields_a_device_address_and_a_pool() {
        let wg = WireguardProtocol {
            subnet: "10.66.66.0/24".to_owned(),
            ..WireguardProtocol::default()
        };
        assert_eq!(wg.device_address().unwrap().to_string(), "10.66.66.1");
        let pool: Vec<String> = wg
            .client_addresses()
            .unwrap()
            .map(|a| a.to_string())
            .collect();
        // The device's own address is not on offer, and neither is the
        // broadcast address at the end.
        assert_eq!(pool.first().unwrap(), "10.66.66.2");
        assert_eq!(pool.last().unwrap(), "10.66.66.254");
        assert_eq!(pool.len(), 253);
    }

    /// A /30 is the smallest subnet that still means something: the device and
    /// exactly one client.
    #[test]
    fn the_smallest_useful_subnet_holds_one_client() {
        let wg = WireguardProtocol {
            subnet: "192.168.9.0/30".to_owned(),
            ..WireguardProtocol::default()
        };
        assert_eq!(wg.device_address().unwrap().to_string(), "192.168.9.1");
        let pool: Vec<Ipv4Addr> = wg.client_addresses().unwrap().collect();
        assert_eq!(pool, [Ipv4Addr::new(192, 168, 9, 2)]);
    }

    #[test]
    fn a_subnet_that_would_confuse_the_pool_is_refused() {
        for bad in [
            "10.66.66.0",       // no prefix
            "10.66.66.0/24/24", // not a prefix
            "10.66.66.0/31",    // no room for a client
            "10.66.66.0/4",     // swallows the host's own network
            "10.66.66.5/24",    // a host, not a network — "first usable" would lie
            "fd00::/64",        // v6 pools are deliberately out of scope
        ] {
            assert!(parse_subnet(bad).is_err(), "{bad} should be refused");
        }
    }
}

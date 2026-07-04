//! `FinalMask` — xray's last-stage wire-level obfuscation that wraps
//! socket bytes AFTER the TLS/Reality handshake completes. The chosen
//! variant lands in `StreamConfig.tcpmasks` and/or `.udpmasks`; the
//! orchestrator picks slots from `to_typed_message`'s returned scope.
//!
//! **Symmetric configuration is mandatory.** The variants do a stateful
//! handshake (sudoku derives lookup tables from the password; mismatch
//! → server drops the connection). The matching settings ship to the
//! client via the share-link's `fm=` parameter so v2rayN / Hiddify /
//! sing-box pick them up automatically when importing a subscription.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::xray::proto::xray::common::serial::TypedMessage;

/// Tagged-enum operator-facing `FinalMask` configuration. `None` is the
/// "no obfuscation" default — the column is non-nullable but its
/// default JSON blob always decodes to `Self::None`.
///
/// Per-variant transport scope (xray dispatches on the actual socket
/// type at handshake time):
///   * `Sudoku`   — both TCP and UDP. Same Config goes into both
///     `tcpmasks` and `udpmasks`.
///   * `Fragment` — TCP, but CLIENT-ONLY. It's asymmetric (the client
///     fragments its own `ClientHello`; the server just reassembles over
///     TCP), so the orchestrator deliberately does NOT add it to the
///     server's `tcpmasks` — it only rides the share-link's `fm=`. A
///     server-side fragment wrapper would be pointless and, under Reality,
///     panics xray (`fragmentConn is not reality.CloseWriteConn`).
///   * `Noise`    — UDP only. Populates only `udpmasks`; ignored for
///     vless/reality TCP inbounds. Most useful for QUIC/Hysteria
///     where a noise prefix breaks fingerprinting.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub enum FinalMask {
    /// No obfuscation — `streamSettings.finalmask` is omitted in the
    /// xray config and the share-link gets no `fm=` parameter.
    #[default]
    None,
    /// Sudoku finalmask (`xray.transport.internet.finalmask.sudoku`).
    /// Derives a lookup table from `password` and obfuscates payload
    /// with optional ASCII-entropy preference + variable padding.
    Sudoku(SudokuParams),
    /// Fragment finalmask (`xray.transport.internet.finalmask.fragment`).
    /// Splits TCP payloads into random-sized chunks with small inter-
    /// chunk delays — defeats simple SNI-watching DPI that needs the
    /// whole `ClientHello` in one segment to match a rule.
    Fragment(FragmentParams),
    /// Noise finalmask (`xray.transport.internet.finalmask.noise`).
    /// Prepends short random byte sequences to UDP datagrams — masks
    /// QUIC fingerprints (well-known long-header byte patterns) as a
    /// cheap pass over surface DPI.
    Noise(NoiseParams),
    /// Salamander finalmask (`xray.transport.internet.finalmask.salamander`) —
    /// Hysteria 2's native password-keyed UDP obfuscation. UDP-only, so it
    /// applies to Hysteria/QUIC inbounds. Unlike the others it rides the
    /// hysteria2 share-link as the STANDARD `obfs=salamander&obfs-password=…`
    /// (not `fm=`), so non-xray clients (sing-box, `NekoBox`, official hysteria)
    /// pick it up too.
    Salamander(SalamanderParams),
}

/// Knobs surfaced to the operator. Mirrors the upstream proto field
/// names (`snake_case` Rust ↔ camelCase JSON) so the JSON round-trips
/// cleanly into xray's parser when we build the share-link payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct SudokuParams {
    /// Shared secret. Required; empty string is treated as "disabled"
    /// downstream by the orchestrator (we just don't emit the mask).
    pub password: String,
    /// `prefer_entropy` (default) or `prefer_ascii`. Empty ≡ default.
    pub ascii: String,
    /// Optional custom lookup table override (advanced — leave empty
    /// for the built-in default).
    pub custom_table: String,
    /// Min padding bytes per packet. Empty ≡ xray default.
    #[ts(type = "number | null")]
    pub padding_min: Option<u32>,
    /// Max padding bytes per packet. Empty ≡ xray default.
    #[ts(type = "number | null")]
    pub padding_max: Option<u32>,
    /// Optional list of additional lookup tables (advanced).
    pub custom_tables: Vec<String>,
}

/// Fragment finalmask knobs (xray-core v26.6.22 #6334). `lengths`/`delays`
/// are PER-SEGMENT parallel arrays: segment `i` is `lengths_min[i]..
/// lengths_max[i]` bytes long and is followed by a `delays_min[i]..
/// delays_max[i]` ms pause; the last entry repeats for all further segments.
/// `packets` selects which packets to fragment (0/1 ≡ the `tlshello`
/// shortcut). Empty arrays ≡ "use xray's default". xray rejects a final
/// `lengths` entry whose min is 0, so the active form keeps a positive last
/// min.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[serde(default)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct FragmentParams {
    #[ts(type = "number | null")]
    pub packets_from: Option<i64>,
    #[ts(type = "number | null")]
    pub packets_to: Option<i64>,
    /// Per-segment chunk-length range, min side. Paired index-for-index with
    /// `lengths_max`.
    #[ts(type = "number[]")]
    pub lengths_min: Vec<i64>,
    #[ts(type = "number[]")]
    pub lengths_max: Vec<i64>,
    /// Per-segment inter-chunk delay range in ms, min side. Paired with
    /// `delays_max`.
    #[ts(type = "number[]")]
    pub delays_min: Vec<i64>,
    #[ts(type = "number[]")]
    pub delays_max: Vec<i64>,
    #[ts(type = "number | null")]
    pub max_split_min: Option<i64>,
    #[ts(type = "number | null")]
    pub max_split_max: Option<i64>,
}

/// Noise finalmask knobs. xray's wire shape is a list of `Item`s plus
/// a reset interval (rotates which item is used between datagrams).
/// `Item.packet` is the literal byte prefix; `rand_min/max` adds N
/// random bytes after the literal, and `rand_range_min/max` picks the
/// byte value range for those random bytes. For v1 we expose a
/// single item built from a hex-encoded `packet` plus the random
/// length pair — covers the common "10 random bytes per datagram"
/// pattern people use to mask QUIC long-header detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct NoiseParams {
    /// Hex-encoded literal prefix bytes. Empty = no literal, only
    /// random bytes used.
    pub packet_hex: String,
    /// Random byte count appended to the literal prefix.
    #[ts(type = "number | null")]
    pub rand_min: Option<i64>,
    #[ts(type = "number | null")]
    pub rand_max: Option<i64>,
    /// Datagram count after which xray rotates noise state. `0..0` =
    /// xray default.
    #[ts(type = "number | null")]
    pub reset_min: Option<i64>,
    #[ts(type = "number | null")]
    pub reset_max: Option<i64>,
}

/// Salamander finalmask knobs. Hysteria 2's obfs is a single shared
/// password; the packet-size window (Gecko variant) is left at xray's
/// default for v1.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct SalamanderParams {
    /// Shared obfuscation password. Required; empty ≡ disabled (the
    /// orchestrator emits no mask, and the share-link omits `obfs=`).
    pub password: String,
}

/// Which socket-side(s) a variant applies to. `Sudoku` works on both;
/// `Fragment` only on TCP; `Noise` / `Salamander` only on UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalMaskScope {
    Tcp,
    Udp,
    Both,
}

impl FinalMask {
    /// Stable variant tag used both as the `kind` discriminator
    /// (serde tag, share-link JSON `"type"`) and as the leaf of the
    /// xray proto type-URL (`xray.transport.internet.finalmask.<kind>.Config`).
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sudoku(_) => "sudoku",
            Self::Fragment(_) => "fragment",
            Self::Noise(_) => "noise",
            Self::Salamander(_) => "salamander",
        }
    }

    /// True when this variant should be wired into xray's stream config.
    /// `None` is always skipped; parameterised variants check their
    /// "required" field so an empty draft form doesn't break xray startup.
    pub fn is_active(&self) -> bool {
        match self {
            Self::None => false,
            Self::Sudoku(p) => !p.password.trim().is_empty(),
            // Fragment is active once a positive chunk length is configured;
            // a packets-only form has no chunk size to split to and xray
            // rejects a zero final length anyway.
            Self::Fragment(p) => p.lengths_min.iter().chain(&p.lengths_max).any(|&v| v > 0),
            // Noise is active when there's either a literal packet
            // prefix or a non-zero random byte count.
            Self::Noise(p) => {
                !p.packet_hex.trim().is_empty()
                    || p.rand_min.is_some_and(|v| v > 0)
                    || p.rand_max.is_some_and(|v| v > 0)
            }
            // Salamander is active once a password is set.
            Self::Salamander(p) => !p.password.trim().is_empty(),
        }
    }

    /// Wire-level `TypedMessage` for `StreamConfig.tcpmasks` / `.udpmasks`
    /// paired with the scope the orchestrator should route it to.
    /// Returns `None` for inactive variants — the caller drops both slots.
    pub fn to_typed_message(&self) -> Option<(TypedMessage, FinalMaskScope)> {
        use crate::xray::proto::xray::transport::internet::finalmask as fm;
        use prost::Message as _;
        if !self.is_active() {
            return None;
        }
        // `is_active` filtered out `Self::None` and the blank-form variants,
        // so by here we have a populated Sudoku / Fragment / Noise.
        let (bytes, scope) = match self {
            Self::Sudoku(p) => {
                let proto = fm::sudoku::Config {
                    password: p.password.clone(),
                    ascii: p.ascii.clone(),
                    custom_table: p.custom_table.clone(),
                    padding_min: p.padding_min.unwrap_or(0),
                    padding_max: p.padding_max.unwrap_or(0),
                    custom_tables: p.custom_tables.clone(),
                };
                (proto.encode_to_vec(), FinalMaskScope::Both)
            }
            Self::Fragment(p) => {
                let proto = fm::fragment::Config {
                    packets_from: p.packets_from.unwrap_or(0),
                    packets_to: p.packets_to.unwrap_or(0),
                    lengths_min: p.lengths_min.clone(),
                    lengths_max: p.lengths_max.clone(),
                    delays_min: p.delays_min.clone(),
                    delays_max: p.delays_max.clone(),
                    max_split_min: p.max_split_min.unwrap_or(0),
                    max_split_max: p.max_split_max.unwrap_or(0),
                };
                (proto.encode_to_vec(), FinalMaskScope::Tcp)
            }
            Self::Noise(p) => {
                // Invalid hex collapses to empty bytes — validation runs at
                // form-submit time, not here, so we never bury errors inside
                // a 200 response.
                let item = fm::noise::Item {
                    rand_min: p.rand_min.unwrap_or(0),
                    rand_max: p.rand_max.unwrap_or(0),
                    // Byte-value range for the random prefix. Mirror xray's
                    // conf default (`randRange` → 0..255); the proto default
                    // (0..0) would make the server emit an all-zero "random"
                    // prefix — itself a fingerprint, and asymmetric with the
                    // client, whose `fm=` conf defaults to 0..255.
                    rand_range_min: 0,
                    rand_range_max: 255,
                    packet: decode_hex_relaxed(&p.packet_hex),
                    ..Default::default()
                };
                let proto = fm::noise::Config {
                    reset_min: p.reset_min.unwrap_or(0),
                    reset_max: p.reset_max.unwrap_or(0),
                    items: vec![item],
                };
                (proto.encode_to_vec(), FinalMaskScope::Udp)
            }
            Self::Salamander(p) => {
                let proto = fm::salamander::Config {
                    password: p.password.clone(),
                };
                (proto.encode_to_vec(), FinalMaskScope::Udp)
            }
            Self::None => unreachable!("filtered by is_active above"),
        };
        Some((
            TypedMessage {
                r#type: format!("xray.transport.internet.finalmask.{}.Config", self.kind()),
                value: bytes,
            },
            scope,
        ))
    }

    /// Resolve into the `(tcpmasks, udpmasks)` pair a `StreamConfig` carries.
    /// `client_side` flips the asymmetric Fragment scope:
    ///
    /// * Sudoku (Both) is symmetric — fills both slots either way.
    /// * Noise (Udp) → the UDP slot.
    /// * Fragment (Tcp) → the TCP slot ON THE CLIENT (the dialer fragments its
    ///   own `ClientHello`), but NEITHER slot on the server: a server-side
    ///   fragment wrapper is pointless and, under Reality, panics
    ///   (`*fragment.fragmentConn is not reality.CloseWriteConn`).
    pub fn masks(&self, client_side: bool) -> (Vec<TypedMessage>, Vec<TypedMessage>) {
        match self.to_typed_message() {
            Some((m, FinalMaskScope::Both)) => (vec![m.clone()], vec![m]),
            Some((m, FinalMaskScope::Udp)) => (Vec::new(), vec![m]),
            Some((m, FinalMaskScope::Tcp)) if client_side => (vec![m], Vec::new()),
            Some((_, FinalMaskScope::Tcp)) | None => (Vec::new(), Vec::new()),
        }
    }
}

/// Loose hex-decoder for the noise `packet_hex` operator input. Strips
/// whitespace, `:` / `,` separators, and a leading `0x`; trailing odd
/// nibbles are silently dropped. Returns empty Vec on any invalid nibble
/// so the orchestrator stays infallible.
fn decode_hex_relaxed(s: &str) -> Vec<u8> {
    const fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let mut nibbles = trimmed
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':' && *b != b',');
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    while let (Some(hi), Some(lo)) = (nibbles.next(), nibbles.next()) {
        let (Some(h), Some(l)) = (nibble(hi), nibble(lo)) else {
            return Vec::new();
        };
        out.push((h << 4) | l);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xray::proto::xray::transport::internet::finalmask as fm;
    use prost::Message as _;

    /// The server-side noise proto must carry the full 0..255 byte-value
    /// range (xray's conf default), not the proto's 0..0 — otherwise the
    /// server's "random" prefix is all zeros, which is both a fingerprint
    /// and asymmetric with the client (whose `fm=` conf defaults to 0..255).
    #[test]
    fn noise_server_uses_full_rand_range() {
        let (msg, scope) = FinalMask::Noise(NoiseParams {
            rand_min: Some(1),
            rand_max: Some(10),
            ..NoiseParams::default()
        })
        .to_typed_message()
        .expect("noise with a non-zero rand count is active");
        assert_eq!(scope, FinalMaskScope::Udp);
        let cfg = fm::noise::Config::decode(msg.value.as_slice()).expect("decode noise config");
        assert_eq!(cfg.items.len(), 1);
        assert_eq!(cfg.items[0].rand_range_min, 0);
        assert_eq!(cfg.items[0].rand_range_max, 255);
    }
}

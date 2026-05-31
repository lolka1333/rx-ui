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
///   * `Fragment` — TCP only. Populates only `tcpmasks`; xray ignores
///     it for QUIC/Hysteria inbounds.
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

/// Fragment finalmask knobs. Each field is `[min, max]` — xray picks
/// a uniform-random value in that range per fragment. `0` on a field
/// means "use xray's built-in default" (typical: packets 1..1, length
/// 100..200, delay 0..0, `max_split` 0..0). For the operator the most
/// impactful pair is `length_min/max` — the chunk size distribution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct FragmentParams {
    #[ts(type = "number | null")]
    pub packets_from: Option<i64>,
    #[ts(type = "number | null")]
    pub packets_to: Option<i64>,
    #[ts(type = "number | null")]
    pub length_min: Option<i64>,
    #[ts(type = "number | null")]
    pub length_max: Option<i64>,
    /// Inter-chunk delay in milliseconds.
    #[ts(type = "number | null")]
    pub delay_min: Option<i64>,
    #[ts(type = "number | null")]
    pub delay_max: Option<i64>,
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

/// Which socket-side(s) a variant applies to. `Sudoku` works on both;
/// `Fragment` only on TCP; `Noise` only on UDP.
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
        }
    }

    /// True when this variant should be wired into xray's stream config.
    /// `None` is always skipped; parameterised variants check their
    /// "required" field so an empty draft form doesn't break xray startup.
    pub fn is_active(&self) -> bool {
        match self {
            Self::None => false,
            Self::Sudoku(p) => !p.password.trim().is_empty(),
            // Fragment is active when ANY of the length / packets knobs
            // is set above 0 — otherwise the wrapper is a no-op.
            Self::Fragment(p) => p
                .length_min
                .or(p.length_max)
                .or(p.packets_from)
                .or(p.packets_to)
                .is_some_and(|v| v > 0),
            // Noise is active when there's either a literal packet
            // prefix or a non-zero random byte count.
            Self::Noise(p) => {
                !p.packet_hex.trim().is_empty()
                    || p.rand_min.is_some_and(|v| v > 0)
                    || p.rand_max.is_some_and(|v| v > 0)
            }
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
                    length_min: p.length_min.unwrap_or(0),
                    length_max: p.length_max.unwrap_or(0),
                    delay_min: p.delay_min.unwrap_or(0),
                    delay_max: p.delay_max.unwrap_or(0),
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

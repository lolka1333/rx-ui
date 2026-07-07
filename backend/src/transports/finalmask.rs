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

/// One noise item. xray builds a datagram prefix from EITHER a literal
/// `packet` (hex) OR `rand_min..rand_max` random bytes — never both on the
/// same item (xray's conf parser errors on `len(packet) > 0 && rand.To > 0`).
/// `rand_range_min/max` (the byte-value range) is pinned to xray's 0..255
/// conf default at build time. `delay_min..delay_max` is an optional per-item
/// pause (ms) before the item is emitted; `0..0` ≡ no delay.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct NoiseItem {
    /// Hex-encoded literal prefix bytes. Empty ≡ random-bytes mode.
    #[serde(default)]
    pub packet_hex: String,
    /// Random byte count appended when there's no literal prefix.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub rand_min: Option<i64>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub rand_max: Option<i64>,
    /// Per-item send delay (ms). `0..0` ≡ no delay.
    #[serde(default)]
    #[ts(type = "number | null")]
    pub delay_min: Option<i64>,
    #[serde(default)]
    #[ts(type = "number | null")]
    pub delay_max: Option<i64>,
}

impl NoiseItem {
    /// True when the item contributes a prefix — a literal packet or a
    /// positive random count. Blank rows (empty packet, no/zero rand) are
    /// dropped at build time so an unfinished UI row is a no-op.
    pub(crate) fn is_active(&self) -> bool {
        !self.packet_hex.trim().is_empty()
            || self.rand_min.is_some_and(|v| v > 0)
            || self.rand_max.is_some_and(|v| v > 0)
    }

    /// A literal packet and a random count are mutually exclusive; the
    /// literal wins so server (proto) and client (`fm=` conf) agree.
    pub(crate) fn has_literal(&self) -> bool {
        !self.packet_hex.trim().is_empty()
    }

    /// Random-length range `(lo, hi)`, clamped to `0..=NOISE_MAX_BYTES` and
    /// sorted. A literal item contributes no random bytes → `(0, 0)`.
    ///
    /// The clamp is the build-time safety net: `validate_noise` rejects
    /// out-of-range values on write, but a legacy row hand-crafted BEFORE that
    /// validation existed is rebuilt on every reconcile without re-validation —
    /// clamping here means such residue can never reach xray as a negative
    /// length (`make([]byte, RandBetween(neg))` panics the shared process) or a
    /// multi-GB allocation. The sort mirrors xray's client `Int32Range`
    /// `ensureOrder` so a partially-filled pair yields the SAME range on the
    /// server proto and in the client `fm=`. (`crypto.RandBetween` itself swaps
    /// inverted bounds, so the sort is for symmetry, not to avoid a panic.)
    pub(crate) fn rand_range(&self) -> (i64, i64) {
        if self.has_literal() {
            return (0, 0);
        }
        clamped_range(self.rand_min, self.rand_max, NOISE_MAX_BYTES)
    }

    /// Per-item send-delay range `(lo, hi)` in ms, clamped to `0..=NOISE_MAX_TIME`
    /// and sorted (see [`Self::rand_range`] — the clamp keeps a legacy huge/negative
    /// delay from overflowing xray's `time.Duration`).
    pub(crate) fn delay_range(&self) -> (i64, i64) {
        clamped_range(self.delay_min, self.delay_max, NOISE_MAX_TIME)
    }

    /// Canonical lowercase, even-length hex of the literal prefix — the SAME
    /// bytes [`decode_hex_relaxed`] feeds into the server proto, re-encoded.
    /// The operator may type `0x`, colons, commas or whitespace (the UI regex
    /// and tooltip invite it), but xray's client parses `fm=` `packet` via a
    /// STRICT `hex.DecodeString` that rejects all of those and odd lengths — so
    /// the share-link must ship clean hex or the client fails to load the node.
    pub(crate) fn packet_hex_canonical(&self) -> String {
        use std::fmt::Write as _;
        let bytes = decode_hex_relaxed(&self.packet_hex);
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            // Infallible: writing to a String never errors.
            let _ = write!(out, "{b:02x}");
        }
        out
    }
}

/// Noise finalmask knobs. xray's wire shape is a list of `Item`s plus a
/// reset interval (rotates which item is used between datagrams). We expose
/// the full item list with per-item random-length and delay ranges — covers
/// both the common "N random bytes per datagram" QUIC-masking case and
/// multi-item sequences (e.g. a literal fake-handshake item followed by a
/// random-filler item, each with its own delay).
///
/// Older rows stored a single item inline (`packet_hex`/`rand_min`/`rand_max`
/// at the top level). The hand-written [`Deserialize`] (below) folds that
/// legacy shape into `items` DURING deserialization via [`NoiseParamsRepr`],
/// so EVERY read path (API GET, config-gen reconcile, share-link, and request
/// bodies) sees one shape with no per-call-site `normalize()` to forget — no
/// data migration needed, and the serialized form is always the new `items[]`
/// layout.
#[derive(Debug, Clone, Default, Serialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/finalmask.ts")]
pub struct NoiseParams {
    /// Ordered list of noise items applied per datagram.
    pub items: Vec<NoiseItem>,
    /// Datagram count after which xray rotates noise state. `0..0` ≡ xray
    /// default. Not surfaced in the UI (pinned null → 0).
    #[ts(type = "number | null")]
    pub reset_min: Option<i64>,
    #[ts(type = "number | null")]
    pub reset_max: Option<i64>,
}

/// Deserialize-only wire form accepting BOTH the current `items[]` layout and
/// the legacy single-item inline shape (`packet_hex`/`rand_min`/`rand_max` at
/// the top level). Converted to [`NoiseParams`] via `From`, which folds a
/// legacy inline item into `items`. Not `TS`-exported and never serialized —
/// [`NoiseParams`] itself owns the (clean) output shape.
#[derive(Deserialize)]
struct NoiseParamsRepr {
    #[serde(default)]
    items: Vec<NoiseItem>,
    #[serde(default)]
    reset_min: Option<i64>,
    #[serde(default)]
    reset_max: Option<i64>,
    // legacy single-item inline fields
    #[serde(default)]
    packet_hex: Option<String>,
    #[serde(default)]
    rand_min: Option<i64>,
    #[serde(default)]
    rand_max: Option<i64>,
}

impl From<NoiseParamsRepr> for NoiseParams {
    fn from(r: NoiseParamsRepr) -> Self {
        let mut items = r.items;
        // Fold a legacy inline item into the list only when the new `items[]`
        // field is absent/empty, so a genuine new-shape blob is never
        // double-counted. A fully-blank legacy draft (all None) folds to no
        // item — harmless.
        if items.is_empty()
            && (r.packet_hex.is_some() || r.rand_min.is_some() || r.rand_max.is_some())
        {
            let packet_hex = r.packet_hex.unwrap_or_default();
            // The old UI seeded a random count ALONGSIDE a literal packet, but
            // the semantics are "packet wins". Drop the now-ignored rand as we
            // fold so the row self-heals to the clean single-meaning shape (and
            // the form no longer shows a misleading random range for a literal).
            let has_literal = !packet_hex.trim().is_empty();
            items.push(NoiseItem {
                rand_min: if has_literal { None } else { r.rand_min },
                rand_max: if has_literal { None } else { r.rand_max },
                packet_hex,
                delay_min: None,
                delay_max: None,
            });
        }
        Self {
            items,
            reset_min: r.reset_min,
            reset_max: r.reset_max,
        }
    }
}

impl NoiseParams {
    /// Reset interval `(lo, hi)` in seconds, clamped to `0..=NOISE_MAX_TIME` and
    /// sorted (see [`NoiseItem::rand_range`]). Not exposed in the UI (always
    /// `(0, 0)` from the panel); the clamp neutralizes a legacy hand-crafted
    /// blob whose huge reset would overflow xray's `time.Duration` (turning
    /// noise into per-datagram spam), and keeps the proto and `fm=` identical.
    pub(crate) fn reset_range(&self) -> (i64, i64) {
        clamped_range(self.reset_min, self.reset_max, NOISE_MAX_TIME)
    }
}

impl<'de> Deserialize<'de> for NoiseParams {
    /// Deserialize via [`NoiseParamsRepr`] so a legacy single-item blob folds
    /// into `items` on EVERY read path. Hand-written rather than
    /// `#[serde(from = "NoiseParamsRepr")]` so `#[derive(TS)]`'s serde-compat
    /// parser doesn't emit "failed to parse serde attribute" on a container
    /// attribute it can't read.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        NoiseParamsRepr::deserialize(deserializer).map(Self::from)
    }
}

/// Max bytes for a noise random-length or literal packet — the IPv4 UDP
/// payload ceiling (65535 − 20 IP − 8 UDP). Beyond this the junk datagram
/// can't be sent and the client's int32 range would wrap.
const NOISE_MAX_BYTES: i64 = 65_507;
/// Max for a per-item delay (ms) or the reset interval (seconds) — a generous
/// ceiling that keeps xray's `time.Duration` math from overflowing.
const NOISE_MAX_TIME: i64 = 65_535;

impl FinalMask {
    /// Per-item Noise invariants that BOTH the inbound and outbound write paths
    /// must enforce before the config reaches xray — the two paths feed the
    /// SAME process, and a bad value panics or crash-loops it (`make([]byte,
    /// RandBetween(neg))`, a giant allocation, or a `time.Duration` overflow
    /// that turns noise into per-datagram spam). Returns a human-readable
    /// message the caller wraps in its own error type; a no-op for non-Noise.
    ///
    /// The UI clamps these (`InputNumber` `min=0`, a hex regex), so this mainly
    /// guards a hand-crafted API body — but it lives here, not in one handler,
    /// precisely so neither path can skip it.
    pub fn validate_noise(&self) -> Result<(), String> {
        let Self::Noise(p) = self else {
            return Ok(());
        };
        // Reset is SECONDS in xray (`Duration(reset) * time.Second`); a huge or
        // negative value overflows the duration → noise rotates every datagram.
        for v in [p.reset_min, p.reset_max].into_iter().flatten() {
            if !(0..=NOISE_MAX_TIME).contains(&v) {
                return Err(format!(
                    "Noise reset interval must be between 0 and {NOISE_MAX_TIME} seconds."
                ));
            }
        }
        for (i, it) in p.items.iter().enumerate() {
            let n = i + 1;
            // A literal packet and a random count are mutually exclusive in
            // xray, and the panel resolves that with "packet wins" EVERYWHERE
            // (the build accessors zero rand for a literal item, the `fm=`
            // encoder emits only the packet, share-link import nulls rand, and
            // the UI tooltip says rand is ignored). So we do NOT reject the
            // combination — that would 400 both the old UI's normal output
            // (which seeded rand alongside a literal) on any later edit and the
            // default literal flow. We just validate each field on its own.
            let has_literal = !it.packet_hex.trim().is_empty();
            // A non-empty literal must decode to ≥1 byte of even-length valid
            // hex; otherwise the relaxed build-time decoder would ship an empty
            // (no-op) or silently-truncated packet — and xray's client hex
            // decoder is strict.
            if has_literal {
                let Some(bytes) = decode_hex_strict(&it.packet_hex) else {
                    return Err(format!(
                        "Noise item {n}: the literal packet must be an even number of \
                         hex digits (0-9a-f)."
                    ));
                };
                if bytes.is_empty() {
                    return Err(format!(
                        "Noise item {n}: the literal packet has no hex bytes."
                    ));
                }
                if !matches!(i64::try_from(bytes.len()), Ok(len) if len <= NOISE_MAX_BYTES) {
                    return Err(format!(
                        "Noise item {n}: the literal packet is too long (max {NOISE_MAX_BYTES} bytes)."
                    ));
                }
            }
            for v in [it.rand_min, it.rand_max].into_iter().flatten() {
                if !(0..=NOISE_MAX_BYTES).contains(&v) {
                    return Err(format!(
                        "Noise item {n}: random length must be between 0 and {NOISE_MAX_BYTES}."
                    ));
                }
            }
            for v in [it.delay_min, it.delay_max].into_iter().flatten() {
                if !(0..=NOISE_MAX_TIME).contains(&v) {
                    return Err(format!(
                        "Noise item {n}: delay must be between 0 and {NOISE_MAX_TIME} ms."
                    ));
                }
            }
        }
        Ok(())
    }
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
            // Noise is active when at least one item contributes a prefix
            // (literal packet or a non-zero random byte count).
            Self::Noise(p) => p.items.iter().any(NoiseItem::is_active),
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
                // One proto Item per active operator row. A literal packet and
                // a random count are mutually exclusive (xray rejects an item
                // with both), so a literal item zeroes rand and vice-versa —
                // this keeps the server (proto) and client (`fm=` conf) in sync.
                // Invalid hex collapses to empty bytes; validation runs at
                // form-submit time, so we never bury errors inside a 200.
                let items = p
                    .items
                    .iter()
                    .filter(|it| it.is_active())
                    .map(|it| {
                        let literal = it.has_literal();
                        // `rand_range` / `delay_range` are the single source of
                        // truth shared with the `fm=` builder (sorted, literal
                        // zeroes rand) so the server proto and the client conf
                        // never diverge.
                        let (rand_min, rand_max) = it.rand_range();
                        let (delay_min, delay_max) = it.delay_range();
                        fm::noise::Item {
                            rand_min,
                            rand_max,
                            // Byte-value range for the random prefix. Mirror
                            // xray's conf default (`randRange` → 0..255); the
                            // proto default (0..0) would make the server emit an
                            // all-zero "random" prefix — itself a fingerprint,
                            // and asymmetric with the client (whose `fm=` conf
                            // defaults to 0..255).
                            rand_range_min: 0,
                            rand_range_max: 255,
                            packet: if literal {
                                decode_hex_relaxed(&it.packet_hex)
                            } else {
                                Vec::new()
                            },
                            delay_min,
                            delay_max,
                        }
                    })
                    .collect();
                let (reset_min, reset_max) = p.reset_range();
                let proto = fm::noise::Config {
                    reset_min,
                    reset_max,
                    items,
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

const fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strip the operator-friendly separators the UI/tooltip allow (leading `0x`,
/// whitespace, `:` and `,`) from a hex string, leaving only the raw nibbles.
fn strip_hex_separators(s: &str) -> impl Iterator<Item = u8> + '_ {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':' && *b != b',')
}

/// Loose hex-decoder for the noise `packet_hex` operator input. Strips
/// whitespace, `:` / `,` separators, and a leading `0x`; a trailing odd nibble
/// is silently dropped, and any invalid nibble collapses to an empty Vec so the
/// orchestrator stays infallible. Build-time only — `validate_noise` rejects
/// odd/invalid input up front, so by the time this runs the input is clean.
fn decode_hex_relaxed(s: &str) -> Vec<u8> {
    let mut nibbles = strip_hex_separators(s);
    let mut out = Vec::with_capacity(s.len() / 2);
    while let (Some(hi), Some(lo)) = (nibbles.next(), nibbles.next()) {
        let (Some(h), Some(l)) = (nibble(hi), nibble(lo)) else {
            return Vec::new();
        };
        out.push((h << 4) | l);
    }
    out
}

/// Strict hex-decoder for VALIDATION. Returns `None` when the input (after
/// separator stripping) has an odd nibble count or any non-hex character — so
/// the operator gets an error instead of a silently-truncated or empty
/// (no-op) noise packet. `Some(vec![])` means the input was genuinely empty.
fn decode_hex_strict(s: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = strip_hex_separators(s).collect();
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Clamp a possibly-partial `(min, max)` pair to `0..=ceiling` (a missing
/// bound ≡ 0), then sort. The clamp is a build-time safety net that coerces any
/// out-of-range DB residue (a legacy blob written before `validate_noise`
/// existed, rebuilt on reconcile without re-validation) into an xray-safe range
/// — so it can never reach the proto as a negative length or an oversized
/// allocation. The sort mirrors xray's client `Int32Range.ensureOrder` so the
/// server proto and the client `fm=` see the SAME `(lo, hi)`; `crypto.RandBetween`
/// itself swaps inverted bounds, so the sort is for symmetry, not anti-panic.
fn clamped_range(min: Option<i64>, max: Option<i64>, ceiling: i64) -> (i64, i64) {
    let lo = min.unwrap_or(0).clamp(0, ceiling);
    let hi = max.unwrap_or(0).clamp(0, ceiling);
    (lo.min(hi), lo.max(hi))
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
            items: vec![NoiseItem {
                rand_min: Some(1),
                rand_max: Some(10),
                ..NoiseItem::default()
            }],
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

    /// A multi-item noise config emits one proto Item per active row, drops
    /// blank rows, keeps order, carries per-item delay, and enforces the
    /// literal-XOR-random rule (a literal item zeroes its random count).
    #[test]
    fn noise_multi_item_emits_ordered_items() {
        let (msg, _) = FinalMask::Noise(NoiseParams {
            items: vec![
                NoiseItem {
                    packet_hex: "deadbeef".into(),
                    // rand set alongside a literal must be dropped in favour
                    // of the literal (xray rejects an item with both).
                    rand_min: Some(9),
                    rand_max: Some(9),
                    delay_min: Some(1),
                    delay_max: Some(2),
                },
                // Blank row — no packet, no rand — must be dropped.
                NoiseItem::default(),
                NoiseItem {
                    rand_min: Some(4),
                    rand_max: Some(8),
                    ..NoiseItem::default()
                },
            ],
            ..NoiseParams::default()
        })
        .to_typed_message()
        .expect("noise with an active item is active");
        let cfg = fm::noise::Config::decode(msg.value.as_slice()).expect("decode noise config");
        assert_eq!(
            cfg.items.len(),
            2,
            "blank row dropped, two active items kept"
        );
        // Item 0: literal wins → packet set, rand zeroed, delay carried.
        assert_eq!(cfg.items[0].packet, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(cfg.items[0].rand_min, 0);
        assert_eq!(cfg.items[0].rand_max, 0);
        assert_eq!(cfg.items[0].delay_min, 1);
        assert_eq!(cfg.items[0].delay_max, 2);
        // Item 1: random mode → no packet, rand carried.
        assert!(cfg.items[1].packet.is_empty());
        assert_eq!(cfg.items[1].rand_min, 4);
        assert_eq!(cfg.items[1].rand_max, 8);
    }

    /// A legacy single-item blob (pre-`items[]` schema) must still load and
    /// fold into one item PURELY ON DESERIALIZE (no explicit normalize call),
    /// so existing stored inbounds keep working on every read path.
    #[test]
    fn noise_legacy_blob_folds_into_items() {
        let fm: FinalMask = serde_json::from_str(
            r#"{"kind":"noise","packet_hex":"","rand_min":5,"rand_max":10,"reset_min":null,"reset_max":null}"#,
        )
        .expect("legacy noise blob deserializes");
        let FinalMask::Noise(p) = &fm else {
            panic!("expected noise variant");
        };
        assert_eq!(p.items.len(), 1, "legacy inline item folded into items[]");
        assert_eq!(p.items[0].rand_min, Some(5));
        assert_eq!(p.items[0].rand_max, Some(10));
        // Re-serialize: the output is the clean `items[]` layout — the legacy
        // top-level keys never round-trip back.
        let json = serde_json::to_string(&fm).expect("serialize");
        assert!(
            json.contains("\"items\""),
            "serializes with items[]: {json}"
        );
        let reparsed: FinalMask = serde_json::from_str(&json).expect("re-parse");
        let FinalMask::Noise(p2) = &reparsed else {
            panic!("expected noise variant");
        };
        assert_eq!(p2.items.len(), 1, "round-trips as a single item");
    }

    /// The old UI stored a random count ALONGSIDE a literal packet; the fold
    /// drops the now-ignored rand ("packet wins") so the row self-heals to a
    /// clean packet-only item and later edits don't hit stale rand fields.
    #[test]
    fn noise_legacy_literal_folds_without_rand() {
        let fm: FinalMask = serde_json::from_str(
            r#"{"kind":"noise","packet_hex":"deadbeef","rand_min":5,"rand_max":10}"#,
        )
        .expect("legacy literal blob deserializes");
        let FinalMask::Noise(p) = &fm else {
            panic!("expected noise variant");
        };
        assert_eq!(p.items.len(), 1);
        assert_eq!(p.items[0].packet_hex, "deadbeef");
        assert_eq!(p.items[0].rand_min, None, "literal → ignored rand dropped");
        assert_eq!(p.items[0].rand_max, None);
    }

    /// Regression: a legacy blob deserialized on the config-gen reconcile path
    /// (`main.rs::hydrate_inbound_row`, which also goes through
    /// `serde_json::from_str`) must be ACTIVE and emit a UDP mask — otherwise a
    /// pre-upgrade noise inbound would be silently pushed to xray with no mask
    /// on every boot/restart. Folding lives in `Deserialize`, so this holds on
    /// every read path without a per-call-site `normalize()`.
    #[test]
    fn noise_legacy_blob_stays_active_and_emits_mask() {
        let fm: FinalMask =
            serde_json::from_str(r#"{"kind":"noise","packet_hex":"","rand_min":5,"rand_max":10}"#)
                .expect("legacy noise blob deserializes");
        assert!(fm.is_active(), "legacy noise must stay active after fold");
        let (tcp, udp) = fm.masks(false);
        assert!(tcp.is_empty(), "noise is UDP-only");
        assert_eq!(udp.len(), 1, "server-side udp mask emitted for legacy blob");
    }

    /// A NEW-shape blob that ALSO carries stray legacy top-level keys must NOT
    /// double-count: the populated `items[]` wins and the legacy keys are
    /// ignored.
    #[test]
    fn noise_new_shape_ignores_stray_legacy_keys() {
        let fm: FinalMask = serde_json::from_str(
            r#"{"kind":"noise","items":[{"packet_hex":"","rand_min":3,"rand_max":6,"delay_min":null,"delay_max":null}],"rand_min":99,"rand_max":99}"#,
        )
        .expect("deserializes");
        let FinalMask::Noise(p) = &fm else {
            panic!("expected noise variant");
        };
        assert_eq!(p.items.len(), 1, "items[] wins, no fold");
        assert_eq!(p.items[0].rand_max, Some(6));
    }

    /// A partially-filled random range (min set, max blank → 0) is sorted in
    /// the SERVER proto too, so it matches the client `fm=` (which xray sorts
    /// via `ensureOrder`) instead of the server emitting a 0-byte datagram.
    #[test]
    fn noise_partial_rand_range_proto_is_sorted() {
        let (msg, _) = FinalMask::Noise(NoiseParams {
            items: vec![NoiseItem {
                rand_min: Some(5),
                rand_max: None,
                ..NoiseItem::default()
            }],
            ..NoiseParams::default()
        })
        .to_typed_message()
        .expect("active");
        let cfg = fm::noise::Config::decode(msg.value.as_slice()).expect("decode");
        assert_eq!(cfg.items[0].rand_min, 0, "sorted lo");
        assert_eq!(cfg.items[0].rand_max, 5, "sorted hi");
    }

    /// The shared `validate_noise` helper (used by BOTH the inbound and outbound
    /// write paths) enforces every per-item invariant.
    #[test]
    fn validate_noise_covers_all_item_invariants() {
        let chk = |items: Vec<NoiseItem>| {
            FinalMask::Noise(NoiseParams {
                items,
                ..NoiseParams::default()
            })
            .validate_noise()
        };
        // Valid: a plain random item, and a literal with operator separators.
        chk(vec![NoiseItem {
            rand_min: Some(5),
            rand_max: Some(10),
            ..NoiseItem::default()
        }])
        .unwrap();
        chk(vec![NoiseItem {
            packet_hex: "de:ad be,ef".into(),
            ..NoiseItem::default()
        }])
        .unwrap();
        // Negative rand → would panic xray's make([]byte, RandBetween(neg)).
        assert!(
            chk(vec![NoiseItem {
                rand_min: Some(-1),
                rand_max: Some(4),
                ..NoiseItem::default()
            }])
            .is_err()
        );
        // Oversized rand / delay beyond the UDP / duration ceilings.
        assert!(
            chk(vec![NoiseItem {
                rand_max: Some(70_000),
                ..NoiseItem::default()
            }])
            .is_err()
        );
        assert!(
            chk(vec![NoiseItem {
                rand_max: Some(5),
                delay_max: Some(70_000),
                ..NoiseItem::default()
            }])
            .is_err()
        );
        // Literal + a stray rand is ACCEPTED (packet wins — see the build
        // accessors and the tooltip); it is NOT rejected.
        chk(vec![NoiseItem {
            packet_hex: "dead".into(),
            rand_min: Some(3),
            ..NoiseItem::default()
        }])
        .unwrap();
        // Odd-length and separators-only literals decode to junk/empty.
        assert!(
            chk(vec![NoiseItem {
                packet_hex: "abc".into(),
                ..NoiseItem::default()
            }])
            .is_err()
        );
        assert!(
            chk(vec![NoiseItem {
                packet_hex: ":,".into(),
                ..NoiseItem::default()
            }])
            .is_err()
        );
    }

    /// `reset` (seconds) is bounded on write and clamped+sorted on build, so a
    /// hand-crafted body can't overflow xray's `time.Duration` math.
    #[test]
    fn validate_noise_bounds_reset() {
        let mk = |lo, hi| NoiseParams {
            items: vec![NoiseItem {
                rand_max: Some(5),
                ..NoiseItem::default()
            }],
            reset_min: lo,
            reset_max: hi,
        };
        FinalMask::Noise(mk(Some(0), Some(600)))
            .validate_noise()
            .unwrap();
        assert!(
            FinalMask::Noise(mk(Some(-1), Some(5)))
                .validate_noise()
                .is_err(),
            "negative"
        );
        assert!(
            FinalMask::Noise(mk(Some(0), Some(100_000)))
                .validate_noise()
                .is_err(),
            "oversized"
        );
        // Inverted reset is sorted at build time (no RandBetween panic).
        assert_eq!(mk(Some(7), Some(3)).reset_range(), (3, 7));
    }

    /// Build-time safety net: a legacy DB blob with an out-of-range rand —
    /// storable before `validate_noise` existed and rebuilt on reconcile
    /// WITHOUT re-validation — is CLAMPED into an xray-safe range instead of
    /// shipping a negative length (`make([]byte, RandBetween(neg))` panic) or a
    /// multi-GB allocation.
    #[test]
    fn noise_legacy_poison_rand_is_clamped_at_build() {
        let fm: FinalMask = serde_json::from_str(
            r#"{"kind":"noise","packet_hex":"","rand_min":-5,"rand_max":5000000000}"#,
        )
        .expect("legacy poison blob deserializes");
        let (msg, _) = fm.to_typed_message().expect("active");
        let cfg = fm::noise::Config::decode(msg.value.as_slice()).expect("decode");
        assert_eq!(cfg.items.len(), 1);
        assert_eq!(cfg.items[0].rand_min, 0, "negative clamped to 0");
        assert_eq!(
            cfg.items[0].rand_max, 65_507,
            "oversized clamped to ceiling"
        );
    }
}

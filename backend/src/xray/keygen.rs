//! Reality keypair + `short_id` generation.
//!
//! Server-side: when the operator creates an inbound without supplying a
//! private key, we generate one via x25519 and derive the public key. Both
//! are stored as **base64-url, no padding** (43 chars) — exactly the format
//! `xray x25519` prints to stdout, so operators can paste the `public_key`
//! into client share-links / QR codes without any re-encoding.
//!
//! `short_id` is 0–8 random bytes; we emit a fresh 8-byte one (16 hex chars)
//! as the default. The empty `short_id` `""` is also valid in Reality and
//! means "no shortId requirement"; we leave that as an opt-in (operator
//! types it explicitly), not a default.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
// OS entropy via `rand`'s `SysRng` — the same OS-CSPRNG source the JWT secret
// and subscription tokens draw from. We fill raw bytes and hand them to
// `StaticSecret::from`, which stores them verbatim (x25519 clamps at DH time),
// so this is byte-for-byte equivalent to x25519-dalek's own `random_from_rng`
// while staying decoupled from that crate's internal rand_core version.
use rand::TryRng as _;
use x25519_dalek::{PublicKey, StaticSecret};

/// A freshly-generated Reality keypair, both halves encoded as base64-url
/// without padding (43-char strings, like `xray x25519` output).
///
/// Body-carried like `VlessEncryptionKeypair`: the frontend pre-generates a
/// pair via `POST /api/keygen/reality-keypair` so the operator sees the
/// `public_key` the moment they pick Reality on the create form, holds both
/// halves in form state, and sends them back with the inbound. On save the
/// server re-derives the public from the private, so a hand-crafted request
/// can't slip in a mismatched pair.
#[derive(serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub struct RealityKeypair {
    /// Server's private half. SECRET — never log.
    pub private_key: String,
    pub public_key: String,
}

/// Fill an `N`-byte array from the OS CSPRNG. A failure means the OS entropy
/// source is unavailable — unrecoverable for a server whose security rests on
/// unpredictable keys, so we panic rather than emit guessable bytes (exactly
/// what x25519-dalek's own `StaticSecret::random()` does internally).
fn os_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    bytes
}

/// Generate a fresh x25519 keypair for Reality.
///
/// Uses the OS-level CSPRNG — Reality's security model rests on the
/// `private_key` being unknown to the client, so this must come from a
/// cryptographically secure source.
pub fn generate_reality_keypair() -> RealityKeypair {
    let secret = StaticSecret::from(os_random_bytes::<32>());
    let public = PublicKey::from(&secret);
    RealityKeypair {
        private_key: URL_SAFE_NO_PAD.encode(secret.to_bytes()),
        public_key: URL_SAFE_NO_PAD.encode(public.to_bytes()),
    }
}

/// Derive the x25519 public key from a base64-url (no-pad) private key.
///
/// Lets the server guarantee the public half matches the private one the
/// frontend sent with a body-carried keypair: a hand-crafted API request that
/// pastes a mismatched `public_key` would otherwise make Reality silently
/// reject every client. Returns Err if the private key isn't a valid 32-byte
/// x25519 scalar.
pub fn derive_reality_public_key(private_key: &str) -> anyhow::Result<String> {
    let bytes = decode_x25519_key(private_key)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("x25519 private key must be 32 bytes"))?;
    let public = PublicKey::from(&StaticSecret::from(arr));
    Ok(URL_SAFE_NO_PAD.encode(public.to_bytes()))
}

/// A VLESS Encryption keypair (post-quantum or X25519 variant of
/// `mlkem768x25519plus`). Both halves are base64-url no-pad strings,
/// directly usable as the trailing `<key>` segment of the
/// `mlkem768x25519plus.<mode>.<seconds>[.<padding>].<key>` wire format
/// — that's the canonical encoding `xray vlessenc` emits.
#[derive(serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub struct VlessEncryptionKeypair {
    /// Server's private half. SECRET — never log.
    pub server_key: String,
    /// Client's public half. Embedded in every share-link.
    pub client_key: String,
}

/// Generate a VLESS Encryption keypair by shelling out to `xray vlessenc`.
///
/// Why subprocess instead of pure Rust: `xray vlessenc` always prints
/// *both* an X25519 pair and an ML-KEM-768 pair in one shot, formatted
/// inside ready-to-use `mlkem768x25519plus.<mode>.<secs>.<key>` strings.
/// Reproducing this in Rust would require pulling in `ml-kem` (a freshly-
/// standardised FIPS-203 implementation) and tracking xray's exact
/// canonical encoding by hand. The xray binary is already shipped under
/// `data/xray/` (the installer puts it there on first run), so calling
/// it gives us bit-for-bit compatibility for free.
///
/// The output is parsed to extract the trailing `<key>` segment of the
/// `"decryption"` and `"encryption"` lines for the requested auth mode.
/// We discard everything else (the prefix, the mode, the seconds) —
/// the panel assembles its own wire string from operator-chosen
/// `xor_mode/seconds/padding` at proto-build time.
pub fn generate_vless_encryption_keypair(
    xray_binary: &std::path::Path,
    auth: crate::protocols::vless::VlessEncryptionAuth,
) -> anyhow::Result<VlessEncryptionKeypair> {
    use crate::protocols::vless::VlessEncryptionAuth;

    let output = std::process::Command::new(xray_binary)
        .arg("vlessenc")
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to invoke `{} vlessenc`: {e}. Is xray installed at this path?",
                xray_binary.display()
            )
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "`xray vlessenc` exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The output has two blocks — one X25519, one ML-KEM-768. We find
    // the right block by its "Authentication:" header line, then pluck
    // the `"decryption": "..."` and `"encryption": "..."` lines from
    // the next two lines.
    //
    // Sample:
    //   Authentication: X25519, not Post-Quantum
    //   "decryption": "mlkem768x25519plus.native.600s.<32-byte-key>"
    //   "encryption": "mlkem768x25519plus.native.0rtt.<32-byte-key>"
    //
    //   Authentication: ML-KEM-768, Post-Quantum
    //   "decryption": "mlkem768x25519plus.native.600s.<64-byte-seed>"
    //   "encryption": "mlkem768x25519plus.native.0rtt.<1184-byte-client>"
    let block_header = match auth {
        VlessEncryptionAuth::X25519 => "Authentication: X25519",
        VlessEncryptionAuth::Mlkem768 => "Authentication: ML-KEM-768",
    };
    let lines: Vec<&str> = stdout.lines().collect();
    let header_idx = lines
        .iter()
        .position(|l| l.starts_with(block_header))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "`xray vlessenc` output missing header `{block_header}` — \
                 xray version may be too old (need post-mlkem support)"
            )
        })?;
    // The decryption line is at +1, encryption at +2 from the header.
    let server_str = lines
        .get(header_idx + 1)
        .ok_or_else(|| anyhow::anyhow!("vlessenc output truncated after header"))?;
    let client_str = lines
        .get(header_idx + 2)
        .ok_or_else(|| anyhow::anyhow!("vlessenc output truncated after decryption line"))?;

    Ok(VlessEncryptionKeypair {
        server_key: extract_trailing_key(server_str, "decryption")?,
        client_key: extract_trailing_key(client_str, "encryption")?,
    })
}

/// Pluck the base64 key from a `"<label>": "mlkem768x25519plus.<mode>.<secs>.<key>"`
/// line. We ignore mode/secs because those come from the operator's form
/// settings at runtime — we only need the raw key half.
fn extract_trailing_key(line: &str, label: &str) -> anyhow::Result<String> {
    // Find the `"` after `:` to get the quoted value
    let prefix = format!("\"{label}\":");
    let after_label = line
        .find(&prefix)
        .map(|i| &line[i + prefix.len()..])
        .ok_or_else(|| anyhow::anyhow!("`{label}` field not found in line: {line:?}"))?;
    let quoted = after_label
        .trim()
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| anyhow::anyhow!("`{label}` value not quoted in: {line:?}"))?;
    // The value format is `mlkem768x25519plus.<mode>.<secs>.<key>`.
    // The key is everything after the last dot.
    let key = quoted
        .rsplit('.')
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty value for `{label}`"))?;
    if key.is_empty() {
        anyhow::bail!("extracted `{label}` key is empty");
    }
    Ok(key.to_owned())
}

/// Generate a fresh 8-byte `short_id`, returned as a 16-character lowercase
/// hex string.
pub fn generate_short_id() -> String {
    hex_lower(&os_random_bytes::<8>())
}

/// Encode bytes as a lowercase hex string. Uses a single allocation +
/// `write!` instead of `bytes.iter().map(format!).collect()`, which
/// allocates one `String` per byte. Writing to a `String` is infallible,
/// so the `write!` results can't fail.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A freshly-generated ECH (Encrypted Client Hello) key bundle. Both halves
/// are `base64.StdEncoding` strings — exactly what `xray tls ech` prints and
/// what the `tls::Config.ech_server_keys` / `ech_config_list` fields expect.
///
/// * `ech_server_keys` — secret. Goes into the inbound's TLS settings; the
///   panel sends this byte-stream (after base64-decode) to xray as
///   `ech_server_keys` in the proto. **Never log.**
/// * `ech_config_list` — public. Clients embed this in their TLS Client
///   Hello to negotiate ECH. We currently surface it for the operator to
///   copy into client config; the panel doesn't persist it because xray
///   derives it from `ech_server_keys` on boot.
#[derive(serde::Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub struct EchKeyBundle {
    pub ech_server_keys: String,
    pub ech_config_list: String,
}

/// Generate a fresh ECH keypair by shelling out to `xray tls ech`.
///
/// Why subprocess (same rationale as `generate_vless_encryption_keypair`):
/// the ECH wire format is a non-trivial concatenation of HPKE public-key,
/// AEAD/KDF lists, `MaxNameLength`, `PublicName`, and extension blob, all
/// length-prefixed per RFC. xray's CLI gets this right by construction;
/// duplicating the format in Rust would mean tracking the spec by hand and
/// would risk drift between what we generate and what xray accepts at
/// handshake time. The xray binary is already installed under `data/xray/`
/// — calling it is the cheap, correct path.
///
/// `server_name` is the public `ECHConfig` `public_name` — clients fall back
/// to this hostname when ECH-rejected (handshake without encrypted SNI).
/// Defaults to `cloudflare-ech.com` to match xray's own default, which
/// blends in with the largest public ECH-using bucket.
pub fn generate_ech_server_keys(
    xray_binary: &std::path::Path,
    server_name: Option<&str>,
) -> anyhow::Result<EchKeyBundle> {
    let server_name = server_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("cloudflare-ech.com");

    let output = std::process::Command::new(xray_binary)
        .args(["tls", "ech", "--serverName", server_name])
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to invoke `{} tls ech`: {e}. Is xray installed at this path?",
                xray_binary.display()
            )
        })?;

    if !output.status.success() {
        anyhow::bail!(
            "`xray tls ech` exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Output shape:
    //   ECH config list:
    //   <base64.StdEncoding>
    //   ECH server keys:
    //   <base64.StdEncoding>
    //
    // We pull the values by walking the lines once and grabbing the line
    // after each header marker. Trim() the value defensively in case xray
    // ever adds trailing whitespace.
    let mut iter = stdout.lines();
    let mut config_list = None;
    let mut server_keys = None;
    while let Some(line) = iter.next() {
        let line = line.trim();
        if line.starts_with("ECH config list") {
            config_list = iter.next().map(|s| s.trim().to_owned());
        } else if line.starts_with("ECH server keys") {
            server_keys = iter.next().map(|s| s.trim().to_owned());
        }
    }

    let ech_server_keys = server_keys
        .ok_or_else(|| anyhow::anyhow!("`xray tls ech` output missing `ECH server keys` block"))?;
    let ech_config_list = config_list
        .ok_or_else(|| anyhow::anyhow!("`xray tls ech` output missing `ECH config list` block"))?;
    if ech_server_keys.is_empty() {
        anyhow::bail!("`xray tls ech` returned empty ECH server keys");
    }

    Ok(EchKeyBundle {
        ech_server_keys,
        ech_config_list,
    })
}

/// Decode a base64-url (no-pad) x25519 key back into raw 32 bytes for proto
/// serialization.
pub fn decode_x25519_key(encoded: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid base64-url x25519 key: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("x25519 key must decode to 32 bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

/// Decode a hex-encoded `short_id` (0–16 chars) into **exactly 8 bytes**,
/// zero-padded on the right. A shorter id like `"324a8e7c"` becomes
/// `0x324a8e7c` followed by four zero bytes; the empty string becomes all
/// zeros.
///
/// The fixed 8-byte width is mandatory, not cosmetic: xray's runtime Reality
/// config (`reality/config.go`) builds its shortId set with
/// `*(*[8]byte)(shortId)`, which reinterprets the slice's backing array as a
/// fixed `[8]byte`. If the slice is shorter than 8 bytes that read runs past
/// the allocation and the Go runtime **panics**, killing the whole xray
/// process the moment the inbound is added over gRPC. xray's own JSON config
/// path pads identically (`make([]byte, 8)` then `hex.Decode`), so emitting 8
/// bytes here keeps the two paths byte-for-byte equivalent.
pub fn decode_short_id(hex_str: &str) -> anyhow::Result<Vec<u8>> {
    if hex_str.len() > 16 || !hex_str.len().is_multiple_of(2) {
        anyhow::bail!(
            "short_id must be 0–16 hex chars (got {} chars)",
            hex_str.len()
        );
    }
    let mut out = vec![0u8; 8];
    for (i, chunk) in hex_str.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| anyhow::anyhow!("non-utf8 short_id"))?;
        out[i] = u8::from_str_radix(s, 16)
            .map_err(|e| anyhow::anyhow!("invalid hex in short_id: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // === generate_reality_keypair =========================================
    #[test]
    fn keypair_has_correct_base64url_length() {
        // x25519 keys are 32 raw bytes → base64-url-no-pad = 43 chars.
        let kp = generate_reality_keypair();
        assert_eq!(kp.private_key.len(), 43, "private: {}", kp.private_key);
        assert_eq!(kp.public_key.len(), 43, "public: {}", kp.public_key);
    }

    #[test]
    fn keypair_uses_url_safe_alphabet() {
        // No `+`, `/`, or `=` — those would break URL-embedded share links.
        let kp = generate_reality_keypair();
        for ch in kp.private_key.chars().chain(kp.public_key.chars()) {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "non-url-safe char {ch:?}"
            );
        }
    }

    #[test]
    fn keypair_is_distinct_between_calls() {
        // OS RNG: two consecutive calls must not collide.
        let a = generate_reality_keypair();
        let b = generate_reality_keypair();
        assert_ne!(a.private_key, b.private_key);
    }

    #[test]
    fn keypair_roundtrips_through_decode_x25519_key() {
        let kp = generate_reality_keypair();
        assert_eq!(decode_x25519_key(&kp.private_key).unwrap().len(), 32);
        assert_eq!(decode_x25519_key(&kp.public_key).unwrap().len(), 32);
    }

    // === generate_short_id ================================================
    #[test]
    fn short_id_is_16_lowercase_hex() {
        let s = generate_short_id();
        assert_eq!(s.len(), 16);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn short_id_distinct_between_calls() {
        let a = generate_short_id();
        let b = generate_short_id();
        assert_ne!(a, b);
    }

    // === decode_x25519_key ================================================
    #[test]
    fn decode_x25519_rejects_non_base64() {
        assert!(decode_x25519_key("not valid base64!!").is_err());
    }

    #[test]
    fn decode_x25519_rejects_wrong_length() {
        // 16 bytes of zeros in base64-url
        let too_short = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let err = decode_x25519_key(&too_short).unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "got: {err}");
    }

    // === decode_short_id ==================================================
    #[test]
    fn decode_short_id_empty_is_valid() {
        // "" is valid and pads to the all-zero 8-byte shortId (matches xray's
        // JSON path, which also yields 8 zero bytes for an empty string).
        assert_eq!(decode_short_id("").unwrap(), vec![0u8; 8]);
    }

    #[test]
    fn decode_short_id_full_8_bytes() {
        let bytes = decode_short_id("324a8e7cebaec7c2").unwrap();
        assert_eq!(bytes, vec![0x32, 0x4a, 0x8e, 0x7c, 0xeb, 0xae, 0xc7, 0xc2]);
    }

    #[test]
    fn decode_short_id_partial_is_zero_padded_to_8() {
        // Shorter short_ids are valid, but MUST be right-padded to 8 bytes —
        // xray's runtime Reality config does `*(*[8]byte)(shortId)` and panics
        // (taking the whole process down) on anything shorter. Regression test
        // for the gRPC AddInbound crash.
        assert_eq!(
            decode_short_id("01ab23cd").unwrap(),
            vec![0x01, 0xab, 0x23, 0xcd, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn decode_short_id_rejects_odd_length() {
        let err = decode_short_id("abc").unwrap_err().to_string();
        assert!(err.contains("hex chars"), "got: {err}");
    }

    #[test]
    fn decode_short_id_rejects_too_long() {
        // 18 hex chars = 9 bytes — Reality caps at 8.
        assert!(decode_short_id("324a8e7cebaec7c2ff").is_err());
    }

    #[test]
    fn decode_short_id_rejects_non_hex_chars() {
        assert!(decode_short_id("zzzzzzzz").is_err());
    }

    #[test]
    fn decode_short_id_roundtrips_with_generator() {
        let s = generate_short_id();
        assert_eq!(decode_short_id(&s).unwrap().len(), 8);
    }
}

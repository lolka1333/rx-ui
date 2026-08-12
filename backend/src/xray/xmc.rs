//! XMC finalmask key derivation, borrowed from xray itself.
//!
//! `xmc.Config` carries an RSA-1024 keypair alongside the password. The
//! runtime does NOT derive it: `wrapConnServer` bails with "empty rsa private
//! key" the moment either field is empty. Derivation lives only in xray's JSON
//! parser (`infra/conf`, `XMC.Build` → `DeriveRSAKey`), and the panel never
//! goes through that path — user inbounds are pushed straight into the running
//! process as protobuf over gRPC (see `xray::config_gen`).
//!
//! Reimplementing the derivation would mean matching Go bit for bit: a
//! SHA-256 keystream seeded with `password + "-p-prime"` / `"-q-prime"`, the
//! next prime above each 512-bit candidate with `gcd(p-1, 65537) == 1`, then
//! PKCS#1 and PKIX DER. Doable, but it drags a pure-Rust bignum + RSA stack
//! into a tree that deliberately has none (see the `jsonwebtoken` note in
//! Cargo.toml).
//!
//! So we ask xray. `xray convert pb` runs a JSON config through the very same
//! parser and writes the compiled protobuf, keypair included; we pull the
//! `xmc.Config` back out of it. This mirrors what the panel already does for
//! `xray vlessenc`, and it is derivation by the implementation itself rather
//! than a second implementation that can drift.
//!
//! Verified against the core's own golden vector: password
//! `deterministic-rsa-key-golden` yields a PKCS#1 DER whose SHA-256 is
//! `3a8c4ad5…798d2f`, the value asserted by `TestDeriveRSAKeyGoldenPrivateKey`
//! in `transport/internet/finalmask/xmc/derivation_test.go`.

use anyhow::{Context, bail};
use serde_json::json;
use std::path::Path;

/// Type URL of the built mask config, as it appears in the protobuf we parse
/// back out and in the `TypedMessage` we later hand to `AddInbound`.
const TYPE_URL: &str = "xray.transport.internet.finalmask.xmc.Config";

/// The password-derived keypair, DER-encoded exactly as xray expects it:
/// PKCS#1 for the private half, PKIX for the public one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmcKeypair {
    pub private_der: Vec<u8>,
    pub public_der: Vec<u8>,
}

/// Derive the keypair for `password` by having xray build a throwaway config.
///
/// Only the password matters to the result — the hostname and the profile are
/// filler that has to pass validation for the build to reach the derivation.
/// The filler profile uses a syntactically valid username/UUID and single-byte
/// textures; none of it reaches the returned keys.
pub fn derive_keypair(xray_binary: &Path, password: &str) -> anyhow::Result<XmcKeypair> {
    if password.is_empty() {
        bail!("xmc password must not be empty");
    }

    let dir = scratch_dir()?;
    let config_path = dir.0.join("probe.json");
    let out_path = dir.0.join("probe.pb");

    // A minimal config that reaches `XMC.Build`. It never runs: `convert pb`
    // parses and compiles, nothing is listened on.
    let probe = json!({
        "inbounds": [{
            "port": 1,
            "protocol": "vless",
            "settings": { "clients": [], "decryption": "none" },
            "streamSettings": {
                "network": "tcp",
                "finalmask": { "tcp": [{
                    "type": "xmc",
                    "settings": {
                        "password": password,
                        "profiles": [{
                            "username": "probe",
                            "uuid": "00000000-0000-4000-8000-000000000000",
                            "texturesValue": "x",
                            "texturesSignature": "x"
                        }]
                    }
                }]}
            }
        }],
        "outbounds": [{ "protocol": "freedom" }]
    });
    std::fs::write(&config_path, serde_json::to_vec(&probe)?)
        .context("write probe config for xmc key derivation")?;

    let output = std::process::Command::new(xray_binary)
        .arg("convert")
        .arg("pb")
        .arg("-outpbfile")
        .arg(&out_path)
        .arg(&config_path)
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to invoke `{} convert pb`: {e}. Is xray installed at this path?",
                xray_binary.display()
            )
        })?;

    if !output.status.success() {
        bail!(
            "`xray convert pb` exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let compiled = std::fs::read(&out_path).context("read protobuf built by `xray convert pb`")?;
    extract_keypair(&compiled)
}

/// Pull the keypair out of a compiled `core.Config`.
///
/// The panel does not generate the whole `core.Config` proto, and pulling it
/// in just to reach one nested field would be a lot of surface for one lookup.
/// Instead we find the mask's `TypedMessage` by its type URL — a length-
/// delimited string that appears verbatim in the encoding — and decode the
/// `value` that follows it. Everything after that point is ordinary protobuf
/// parsed by field number, no guessing at offsets.
fn extract_keypair(compiled: &[u8]) -> anyhow::Result<XmcKeypair> {
    let at = find(compiled, TYPE_URL.as_bytes())
        .with_context(|| format!("`{TYPE_URL}` not found in the config built by xray"))?;
    let after_url = at + TYPE_URL.len();

    // TypedMessage.value is field 2, wire type 2 → tag byte 0x12.
    if compiled.get(after_url) != Some(&0x12) {
        bail!("unexpected TypedMessage layout after the xmc type URL");
    }
    let (len, rest) =
        varint(&compiled[after_url + 1..]).context("read the length of the xmc config payload")?;
    let value = rest.get(..len).context("xmc config payload is truncated")?;

    let private_der = field(value, 8)?.context("xray built an xmc config with no private key")?;
    let public_der = field(value, 9)?.context("xray built an xmc config with no public key")?;

    Ok(XmcKeypair {
        private_der: private_der.to_vec(),
        public_der: public_der.to_vec(),
    })
}

/// A private directory under the system temp dir, removed when dropped.
///
/// Not worth a `tempfile` dependency for one call site: the probe holds only
/// the operator's own password, it lives for the length of one `convert pb`,
/// and the name is unique per process and instant so two concurrent saves
/// cannot collide.
struct ScratchDir(std::path::PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        // Best-effort: a leftover directory in temp is not worth failing a
        // save that has otherwise succeeded.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch_dir() -> anyhow::Result<ScratchDir> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let path = std::env::temp_dir().join(format!("rx-xmc-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&path).context("create scratch dir for xmc key derivation")?;
    Ok(ScratchDir(path))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Read a protobuf varint, returning its value and the bytes after it.
fn varint(buf: &[u8]) -> anyhow::Result<(usize, &[u8])> {
    let mut value: usize = 0;
    for (i, byte) in buf.iter().enumerate().take(10) {
        value |= usize::from(byte & 0x7f)
            .checked_shl(7 * u32::try_from(i)?)
            .context("varint too large")?;
        if byte & 0x80 == 0 {
            return Ok((value, &buf[i + 1..]));
        }
    }
    bail!("malformed varint")
}

/// Find a length-delimited field by number in a flat message. Every field of
/// `xmc.Config` we care about is wire type 2; anything else means the shape
/// changed under us and guessing would be worse than failing.
fn field(mut buf: &[u8], wanted: u32) -> anyhow::Result<Option<&[u8]>> {
    while !buf.is_empty() {
        let (tag, rest) = varint(buf)?;
        let number = u32::try_from(tag >> 3)?;
        let wire = tag & 7;
        if wire != 2 {
            bail!("field {number} of the xmc config is wire type {wire}, expected 2");
        }
        let (len, rest) = varint(rest)?;
        let (value, tail) = rest
            .split_at_checked(len)
            .context("field of the xmc config is truncated")?;
        if number == wanted {
            return Ok(Some(value));
        }
        buf = tail;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout we rely on: type URL, `0x12`, length, then the payload.
    #[test]
    fn extracts_both_halves_of_the_keypair() {
        let mut payload = Vec::new();
        // field 1 (password)
        payload.extend_from_slice(&[0x0a, 0x02, b'h', b'i']);
        // field 8 (private key)
        payload.extend_from_slice(&[0x42, 0x03, 1, 2, 3]);
        // field 9 (public key)
        payload.extend_from_slice(&[0x4a, 0x02, 4, 5]);

        let mut compiled = b"\x0a\x2cprefix-junk".to_vec();
        compiled.extend_from_slice(TYPE_URL.as_bytes());
        compiled.push(0x12);
        compiled.push(u8::try_from(payload.len()).unwrap());
        compiled.extend_from_slice(&payload);

        let keys = extract_keypair(&compiled).unwrap();
        assert_eq!(keys.private_der, vec![1, 2, 3]);
        assert_eq!(keys.public_der, vec![4, 5]);
    }

    #[test]
    fn rejects_a_config_without_keys() {
        let payload = [0x0a, 0x02, b'h', b'i'];
        let mut compiled = TYPE_URL.as_bytes().to_vec();
        compiled.push(0x12);
        compiled.push(u8::try_from(payload.len()).unwrap());
        compiled.extend_from_slice(&payload);

        let err = extract_keypair(&compiled).unwrap_err().to_string();
        assert!(err.contains("no private key"), "{err}");
    }

    #[test]
    fn rejects_a_missing_type_url() {
        let err = extract_keypair(b"nothing to see here")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"), "{err}");
    }

    /// End-to-end against the bundled binary, pinned to the core's own golden
    /// vector (`TestDeriveRSAKeyGoldenPrivateKey`). If xray ever changes how it
    /// derives the key, or we ever pull the wrong bytes out of the compiled
    /// config, this is what says so — a mismatch here means every XMC inbound
    /// the panel writes would fail its handshake.
    ///
    /// Skipped when the binary isn't there (a checkout without `data/xray/`),
    /// because that is a missing fixture and not a failure of this code.
    #[test]
    fn derives_the_key_the_core_expects() {
        use sha2::{Digest, Sha256};

        let binary = std::path::Path::new("data/xray").join(super::super::installer::binary_name());
        if !binary.exists() {
            eprintln!("skipping: no xray binary at {}", binary.display());
            return;
        }

        let keys = derive_keypair(&binary, "deterministic-rsa-key-golden")
            .expect("derive the golden keypair");
        let digest = Sha256::digest(&keys.private_der)
            .iter()
            .fold(String::new(), |mut s, b| {
                use std::fmt::Write;
                let _ = write!(s, "{b:02x}");
                s
            });

        assert_eq!(
            digest, "3a8c4ad56a6fb42dab73c4d5fc3af754460a2db1441edc0970cbc7f4e0798d2f",
            "derived private key does not match the core's golden vector"
        );
        assert!(!keys.public_der.is_empty(), "public half came back empty");
    }
}

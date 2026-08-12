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

use crate::xray::scratch::ScratchDir;
use anyhow::{Context, bail};
use serde_json::json;
use std::ffi::OsStr;
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
/// Runs on a blocking thread with a deadline: `output()` waits for the child,
/// and an axum handler that waits with it is a tokio worker taken out of
/// service. On a single-vCPU box that is the whole runtime. The deadline is
/// belt for the same braces — a wedged child would otherwise hold the request
/// open forever, and this call sits on the save path of every XMC inbound.
pub async fn derive_keypair(xray_binary: &Path, password: &str) -> anyhow::Result<XmcKeypair> {
    let binary = xray_binary.to_path_buf();
    let password = password.to_owned();
    // The whole derivation — scratch dir, probe config, subprocess, protobuf
    // read-back — moves to a blocking thread as one unit, rather than only the
    // subprocess: the file I/O around it is on the same request path.
    match tokio::time::timeout(
        crate::xray::cli::CLI_TIMEOUT,
        tokio::task::spawn_blocking(move || derive_blocking(&binary, &password)),
    )
    .await
    {
        Ok(joined) => joined.context("xmc key derivation task failed")?,
        Err(_) => bail!(
            "deriving the xmc key did not finish within {}s",
            crate::xray::cli::CLI_TIMEOUT.as_secs()
        ),
    }
}

fn derive_blocking(xray_binary: &Path, password: &str) -> anyhow::Result<XmcKeypair> {
    if password.is_empty() {
        bail!("xmc password must not be empty");
    }

    let dir = ScratchDir::new("xmc")?;
    let config_path = dir.path().join("probe.json");
    let out_path = dir.path().join("probe.pb");

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

    crate::xray::cli::run_blocking(
        xray_binary,
        &[
            OsStr::new("convert"),
            OsStr::new("pb"),
            OsStr::new("-outpbfile"),
            out_path.as_os_str(),
            config_path.as_os_str(),
        ],
    )?;

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

/// Find a length-delimited field by number in a flat message.
///
/// The two fields we read are wire type 2, but the rest of the message is
/// skipped by wire type rather than rejected: `xmc.Config` already carries a
/// `reserved`, the panel lets the operator install any core release, and a
/// future scalar field next to the keys must not turn every XMC save into an
/// error. Groups (3/4) are gone from proto3, so meeting one really does mean
/// the message is not what we think it is.
fn field(mut buf: &[u8], wanted: u32) -> anyhow::Result<Option<&[u8]>> {
    while !buf.is_empty() {
        let (tag, rest) = varint(buf)?;
        let number = u32::try_from(tag >> 3)?;
        let wire = tag & 7;
        buf = match wire {
            0 => varint(rest)?.1,
            1 | 5 => {
                let width = if wire == 1 { 8 } else { 4 };
                rest.split_at_checked(width)
                    .with_context(|| format!("field {number} of the xmc config is truncated"))?
                    .1
            }
            2 => {
                let (len, rest) = varint(rest)?;
                let (value, tail) = rest
                    .split_at_checked(len)
                    .with_context(|| format!("field {number} of the xmc config is truncated"))?;
                if number == wanted {
                    return Ok(Some(value));
                }
                tail
            }
            other => bail!("field {number} of the xmc config is wire type {other}"),
        };
    }
    Ok(None)
}

/// Fill in the server-derived half of a `FinalMask` before it is stored.
///
/// Only XMC has one: an RSA-1024 keypair seeded by the password. Re-derived on
/// every save rather than carried forward, so a changed password can never
/// leave a stale key behind — that failure is invisible in the form and breaks
/// the handshake for every client at once. It also means an upgraded xray
/// re-syncs the key on the next save instead of pinning whatever the old
/// binary produced.
///
/// Shared by the inbound and outbound write paths on purpose. They feed the
/// same xray, and the outbound needs the public half just as much: xray's
/// client refuses an empty `rsaPublicKey`, so an outbound saved without this
/// dials out with no mask at all while the form shows one configured.
pub async fn complete_finalmask(
    xray_binary: &Path,
    finalmask: &mut crate::transports::finalmask::FinalMask,
) -> anyhow::Result<()> {
    use crate::transports::finalmask::FinalMask;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

    let FinalMask::Xmc(p) = finalmask else {
        return Ok(());
    };
    let password = p.password.trim().to_owned();
    if password.is_empty() {
        // Nothing to derive from. Clearing matters even though validation
        // rejects an empty password on both write paths today: without it a
        // half-edited mask would carry the previous password's keys into the
        // row, and the next reader would trust them.
        p.rsa_private_key.clear();
        p.rsa_public_key.clear();
        return Ok(());
    }
    let keys = derive_keypair(xray_binary, &password).await?;
    p.password = password;
    p.rsa_private_key = B64.encode(&keys.private_der);
    p.rsa_public_key = B64.encode(&keys.public_der);
    Ok(())
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

        let keys = derive_blocking(&binary, "deterministic-rsa-key-golden")
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

//! Reality security — xray's TLS-handshake-masquerade-as-real-site
//! mechanism. Operator-supplied x25519 keypair + dest host + serverNames
//! list. The server steals the real site's certificate during handshake
//! when it doesn't match `serverNames` exactly, returning a "real"
//! TLS error to any DPI / scanner that probes the port.

use super::{Security, SecurityKind};
use crate::xray::keygen;
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::reality::Config as XrayRealityConfig;
use prost::Message;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

const TYPE_REALITY_CONFIG: &str = "xray.transport.internet.reality.Config";

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub struct RealitySecurity {
    /// Target site the inbound impersonates ("dest" in xray docs).
    /// e.g. "www.cloudflare.com:443". xray opens a real TLS connection
    /// to this host during MITM moments.
    pub dest: String,
    /// Allowed SNI values clients can use. Connection's SNI must match
    /// one of these for Reality to serve our own handshake (otherwise
    /// it proxies to `dest`).
    pub server_names: Vec<String>,
    /// base64-url 32-byte x25519 private key. Secret.
    pub private_key: String,
    /// base64-url 32-byte x25519 public key. Embedded in share-links.
    pub public_key: String,
    /// Each entry is 0-16 hex chars (0-8 bytes). Empty string is a
    /// valid value meaning "no shortId restriction".
    pub short_ids: Vec<String>,
    /// uTLS fingerprint emulation. "chrome" / "firefox" / "ios" etc.
    /// Defaults to "chrome" — the safest blanket profile.
    pub fingerprint: String,
    /// PROXY-protocol version (0/1/2). 0 = off.
    pub xver: u32,
    /// `SpiderX` — the crawl path the client walks on the real `dest` after
    /// an unverified handshake (client-side camouflage against active
    /// probing). Emitted to clients as the share-link `spx=` param;
    /// xray's server-side Reality config has no spiderX field, so it's
    /// share-link-only. Empty defaults to "/". `#[serde(default)]` keeps
    /// inbound rows whose stored JSON predates this field deserializing.
    #[serde(default)]
    pub spider_x: String,
    /// Oldest client this server will complete a handshake with, written the
    /// way xray writes it: up to three dot-separated numbers, each 0-255
    /// ("26.3.27"). Empty is NOT "any client" — since v26.7.11 the core fills
    /// in 26.3.27 of its own accord, so anything built before that is refused
    /// and this field is the only way to let it back in.
    #[serde(default)]
    pub min_client_ver: String,
    /// Newest client this server will talk to, same spelling. Empty ≡ no upper
    /// bound, which is the core's default and almost always what you want.
    #[serde(default)]
    pub max_client_ver: String,
}

/// Read a `minClientVer` / `maxClientVer` the way xray does
/// (`infra/conf/transport_security.go`): up to three dot-separated numbers,
/// each fitting in a byte, into a fixed three-byte field. Empty stays empty,
/// which leaves the core on its own default.
///
/// Refused here rather than at core start: REALITY settings ride into xray
/// inside an inbound push, and a bad value there takes the whole handler down
/// with a message the operator never sees.
fn parse_client_ver(field: &str, value: &str) -> anyhow::Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = vec![0u8; 3];
    for (i, part) in value.split('.').enumerate() {
        let slot = out
            .get_mut(i)
            .ok_or_else(|| anyhow::anyhow!("{field}: at most three parts, got '{value}'"))?;
        *slot = part
            .trim()
            .parse::<u8>()
            .map_err(|_| anyhow::anyhow!("{field}: '{part}' is not a number between 0 and 255"))?;
    }
    Ok(out)
}

impl RealitySecurity {
    /// uTLS fingerprint, defaulting to "chrome" (the safest blanket profile)
    /// when unset. Shared by the share-link and the outbound client build.
    fn effective_fingerprint(&self) -> &str {
        if self.fingerprint.is_empty() {
            "chrome"
        } else {
            &self.fingerprint
        }
    }
    /// `SpiderX` crawl path, defaulting to "/" when unset.
    fn effective_spider_x(&self) -> &str {
        if self.spider_x.is_empty() {
            "/"
        } else {
            &self.spider_x
        }
    }
}

impl Security for RealitySecurity {
    fn kind(&self) -> SecurityKind {
        SecurityKind::Reality
    }
    fn xray_type_url(&self) -> &'static str {
        TYPE_REALITY_CONFIG
    }
    fn share_link_params(&self, _fallback_host: &str) -> Vec<(String, String)> {
        let mut params = vec![("security".to_owned(), "reality".to_owned())];
        if let Some(sni) = self.server_names.first() {
            params.push(("sni".to_owned(), sni.clone()));
        }
        let sid = self.short_ids.first().map_or("", String::as_str).to_owned();
        params.push(("sid".to_owned(), sid));
        params.push(("pbk".to_owned(), self.public_key.clone()));
        params.push(("fp".to_owned(), self.effective_fingerprint().to_owned()));
        // SpiderX crawl path — URL-encoded by the share-link builder ("/" → %2F).
        params.push(("spx".to_owned(), self.effective_spider_x().to_owned()));
        params
    }
    fn build_settings(&self) -> anyhow::Result<Option<TypedMessage>> {
        let private_key = keygen::decode_x25519_key(&self.private_key)
            .map_err(|e| anyhow::anyhow!("private_key: {e}"))?;
        let short_ids = self
            .short_ids
            .iter()
            .map(|s| keygen::decode_short_id(s))
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(|e| anyhow::anyhow!("short_ids: {e}"))?;

        let cfg = XrayRealityConfig {
            show: false,
            dest: self.dest.clone(),
            // `type` = network protocol for the dest dial. Reality MITMs
            // a TLS handshake which is always TCP — hard-code accordingly.
            // Leaving it empty causes "REALITY: failed to dial dest"
            // at every incoming connection, bricking the inbound.
            r#type: "tcp".to_owned(),
            xver: u64::from(self.xver),
            server_names: self.server_names.clone(),
            private_key,
            short_ids,
            min_client_ver: parse_client_ver("min_client_ver", &self.min_client_ver)?,
            max_client_ver: parse_client_ver("max_client_ver", &self.max_client_ver)?,
            // `fingerprint` proto field is NOT set here — xray validates
            // it against a whitelist and rejects unknowns. The operator-
            // chosen fingerprint travels via the share-link only (uTLS
            // emulation happens on the client side).
            ..XrayRealityConfig::default()
        };
        Ok(Some(TypedMessage {
            r#type: TYPE_REALITY_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        }))
    }

    fn build_client_settings(&self) -> anyhow::Result<Option<TypedMessage>> {
        // Outbound/client Reality uses the CLIENT fields of the same proto:
        // the server's `public_key`, the chosen SNI (`server_name`), one
        // `short_id`, the uTLS `Fingerprint`, and the `spider_x` crawl path.
        // The server-only fields (private_key / server_names[] / short_ids[] /
        // dest) stay unset.
        let public_key = keygen::decode_x25519_key(&self.public_key)
            .map_err(|e| anyhow::anyhow!("public_key: {e}"))?;
        let short_id = self
            .short_ids
            .first()
            .map(|s| keygen::decode_short_id(s))
            .transpose()
            .map_err(|e| anyhow::anyhow!("short_id: {e}"))?
            .unwrap_or_default();
        let server_name = self.server_names.first().cloned().unwrap_or_default();
        let cfg = XrayRealityConfig {
            server_name,
            public_key,
            short_id,
            fingerprint: self.effective_fingerprint().to_owned(),
            spider_x: self.effective_spider_x().to_owned(),
            ..XrayRealityConfig::default()
        };
        Ok(Some(TypedMessage {
            r#type: TYPE_REALITY_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_client_ver;

    /// The three bytes xray compares against, zero-padded — "26" means 26.0.0,
    /// not "26 and anything after it".
    #[test]
    fn a_version_becomes_three_bytes() {
        assert_eq!(parse_client_ver("f", "26.3.27").unwrap(), vec![26, 3, 27]);
        assert_eq!(parse_client_ver("f", "26.9").unwrap(), vec![26, 9, 0]);
        assert_eq!(parse_client_ver("f", "26").unwrap(), vec![26, 0, 0]);
        assert_eq!(
            parse_client_ver("f", "  26.3.27  ").unwrap(),
            vec![26, 3, 27]
        );
    }

    /// Empty stays empty so the field is absent from the proto and the core
    /// keeps its own default. Sending three zero bytes instead would read as
    /// "accept any client from 0.0.0 up", which is a different setting.
    #[test]
    fn empty_leaves_the_core_to_decide() {
        assert!(parse_client_ver("f", "").unwrap().is_empty());
        assert!(parse_client_ver("f", "   ").unwrap().is_empty());
    }

    /// Refused here rather than at core start, where a bad value takes the
    /// whole inbound down with a message the operator never sees.
    #[test]
    fn a_malformed_version_is_refused() {
        for bad in ["26.3.27.1", "26.3.256", "26.x.1", "v26.3.27", "26..1", "-1"] {
            assert!(
                parse_client_ver("min_client_ver", bad).is_err(),
                "{bad} should be refused"
            );
        }
    }
}

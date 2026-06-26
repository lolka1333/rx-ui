//! Standard TLS — operator-provided cert chain + key, optional ALPN,
//! min/max version, cipher suites, session resumption, ECH, master-key-log.
//! Cert material lives as either inline PEM (stored in the panel DB) or
//! a filesystem path read by xray at handshake time.

use super::{Security, SecurityKind};
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::transport::internet::tls::{
    Certificate as XrayCertificate, Config as XrayTlsConfig, certificate::Usage as XrayCertUsage,
};
use base64::Engine as _;
use prost::Message;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

const TYPE_TLS_CONFIG: &str = "xray.transport.internet.tls.Config";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub enum TlsCertSource {
    Inline,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub enum TlsCertUsage {
    #[default]
    Encipherment,
    Verify,
    Issue,
}

const fn default_true_bool() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, TS, PartialEq, Eq)]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub struct TlsCertificate {
    pub source: TlsCertSource,
    /// PEM blob (Inline) or filesystem path (Path).
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub usage: TlsCertUsage,
    #[serde(default)]
    #[ts(type = "number")]
    pub ocsp_stapling: i64,
    #[serde(default)]
    pub build_chain: bool,
    #[serde(default = "default_true_bool")]
    pub one_time_loading: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub struct TlsSecurity {
    /// At least one entry required when actually using TLS. Empty
    /// vector is valid for "configured TLS but not enabled" pre-stage.
    pub certificates: Vec<TlsCertificate>,
    pub server_name: Option<String>,
    /// `["h2","http/1.1"]` — order is significant, first wins ALPN
    /// negotiation. Default behaviour (None) = `["http/1.1"]` only
    /// (WS-compatible).
    pub alpn: Option<Vec<String>>,
    /// "1.2" / "1.3" / "" (xray default = "1.2")
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub cipher_suites: Option<String>,
    pub enable_session_resumption: Option<bool>,
    pub reject_unknown_sni: Option<bool>,
    /// NSS-keylog file path. Debug only — exposes session keys.
    pub master_key_log: Option<String>,
    /// base64-encoded ECH server key bundle (PRIVATE — never leaves
    /// the panel except as part of the inbound config xray reads).
    pub ech_server_keys: Option<String>,
    /// base64-encoded ECH config list (PUBLIC — clients embed this in
    /// the TLS Client Hello). Derived from `ech_server_keys` by xray
    /// at keygen time. Persisted so the share-link builder can embed
    /// it as the `ech=` URL param without re-running keygen.
    pub ech_config_list: Option<String>,
    /// TLS 1.3 curves list. None = xray default.
    pub curve_preferences: Option<Vec<String>>,
    /// uTLS `ClientHello` fingerprint the client emulates ("chrome",
    /// "firefox", "randomized", a version-pinned `hello*`, …). On an inbound
    /// this travels in the share-link as `fp=` (the server doesn't emulate);
    /// on an OUTBOUND it IS emitted into the TLS proto (`fingerprint`, field
    /// 11) so the relay's dialer emulates it. `None`/empty defaults to
    /// "chrome".
    pub fingerprint: Option<String>,
    /// CLIENT-side (outbound relay) only — verify the upstream server's
    /// certificate against these names instead of the dial address. The
    /// sanctioned replacement for the removed `allowInsecure` when relaying
    /// to a server whose cert SAN doesn't match the address it's dialed by.
    /// Ignored on inbounds (the server build never reads it).
    #[serde(default)]
    pub verify_peer_cert_by_name: Option<Vec<String>>,
    /// CLIENT-side only — pin the upstream's certificate by SHA-256 (hex,
    /// optionally colon-separated, or base64). The strict alternative to
    /// `verify_peer_cert_by_name`. Ignored on inbounds.
    #[serde(default)]
    pub pinned_peer_cert_sha256: Option<Vec<String>>,
}

impl TlsSecurity {
    /// SNI a remote client should send: explicit `server_name` when set,
    /// otherwise the caller's fallback (transport-level host, or the
    /// share-link host for protocols without their own host field).
    pub fn effective_sni<'a>(&'a self, fallback: &'a str) -> &'a str {
        self.server_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback)
    }

    fn build_one_certificate(spec: &TlsCertificate) -> anyhow::Result<XrayCertificate> {
        let cert_trim = spec.cert.trim();
        let key_trim = spec.key.trim();
        if cert_trim.is_empty() {
            anyhow::bail!("certificate has empty 'cert'");
        }
        if key_trim.is_empty() {
            anyhow::bail!("certificate has empty 'key'");
        }
        let (certificate, key, certificate_path, key_path) = match spec.source {
            TlsCertSource::Inline => (
                cert_trim.as_bytes().to_vec(),
                key_trim.as_bytes().to_vec(),
                String::new(),
                String::new(),
            ),
            TlsCertSource::Path => (
                Vec::new(),
                Vec::new(),
                cert_trim.to_owned(),
                key_trim.to_owned(),
            ),
        };
        let usage = match spec.usage {
            TlsCertUsage::Encipherment => XrayCertUsage::Encipherment,
            TlsCertUsage::Verify => XrayCertUsage::AuthorityVerify,
            TlsCertUsage::Issue => XrayCertUsage::AuthorityIssue,
        };
        #[allow(clippy::cast_sign_loss)]
        let ocsp = spec.ocsp_stapling.max(0) as u64;
        let one_time_loading =
            matches!(spec.source, TlsCertSource::Inline) || spec.one_time_loading;
        Ok(XrayCertificate {
            certificate,
            key,
            usage: usage as i32,
            ocsp_stapling: ocsp,
            certificate_path,
            key_path,
            one_time_loading,
            build_chain: spec.build_chain,
        })
    }
}

impl Security for TlsSecurity {
    fn kind(&self) -> SecurityKind {
        SecurityKind::Tls
    }
    fn xray_type_url(&self) -> &'static str {
        TYPE_TLS_CONFIG
    }
    fn share_link_params(&self, fallback_host: &str) -> Vec<(String, String)> {
        let sni = self.effective_sni(fallback_host);
        let mut params = vec![("security".to_owned(), "tls".to_owned())];
        if !sni.is_empty() {
            params.push(("sni".to_owned(), sni.to_owned()));
        }
        if let Some(alpn) = &self.alpn
            && !alpn.is_empty()
        {
            params.push(("alpn".to_owned(), alpn.join(",")));
        }
        // uTLS fingerprint the client emulates. Operator-chosen; defaults
        // to chrome (safest blanket value behind CDNs / inspectors) when
        // unset, matching the value pinned before the field existed.
        let fp = self
            .fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("chrome");
        params.push(("fp".to_owned(), fp.to_owned()));
        // Public ECH config list. xray-compatible clients (NekoBox,
        // v2rayN, Stash, sing-box) read `ech=` from the URL and feed
        // it into TLS Client Hello — no out-of-band copy-paste.
        if let Some(ech) = &self.ech_config_list
            && !ech.is_empty()
        {
            params.push(("ech".to_owned(), ech.clone()));
        }
        params
    }
    fn build_settings(&self) -> anyhow::Result<Option<TypedMessage>> {
        if self.certificates.is_empty() {
            anyhow::bail!("security=tls requires at least one certificate");
        }

        let certificates: anyhow::Result<Vec<XrayCertificate>> = self
            .certificates
            .iter()
            .map(Self::build_one_certificate)
            .collect();
        let certificate = certificates?;

        let alpn = self
            .alpn
            .clone()
            .unwrap_or_else(|| vec!["http/1.1".to_owned()]);
        let min_version = self
            .min_version
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "1.2".to_owned());
        let max_version = self.max_version.clone().unwrap_or_default();
        let cipher_suites = self.cipher_suites.clone().unwrap_or_default();
        let master_key_log = self.master_key_log.clone().unwrap_or_default();

        let ech_server_keys = self
            .ech_server_keys
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(|e| anyhow::anyhow!("ech_server_keys: invalid base64: {e}"))
            })
            .transpose()?
            .unwrap_or_default();

        let curve_preferences = self.curve_preferences.clone().unwrap_or_default();

        let cfg = XrayTlsConfig {
            certificate,
            server_name: self.server_name.clone().unwrap_or_default(),
            next_protocol: alpn,
            min_version,
            max_version,
            cipher_suites,
            enable_session_resumption: self.enable_session_resumption.unwrap_or(false),
            master_key_log,
            ech_server_keys,
            curve_preferences,
            reject_unknown_sni: self.reject_unknown_sni.unwrap_or(false),
            ..XrayTlsConfig::default()
        };
        Ok(Some(TypedMessage {
            r#type: TYPE_TLS_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        }))
    }

    fn build_client_settings(&self) -> anyhow::Result<Option<TypedMessage>> {
        // Outbound/client TLS: NO certificates (the client validates the
        // upstream server's chain) — SNI + ALPN + version knobs, PLUS the
        // client-only fields a relay needs: the uTLS `fingerprint` (proto
        // field 11, read by the TCP dialer), and the `allowInsecure`
        // replacements `verify_peer_cert_by_name` / `pinned_peer_cert_sha256`
        // for self-signed upstreams (allowInsecure itself hard-errors in this
        // xray version).
        let alpn = self
            .alpn
            .clone()
            .unwrap_or_else(|| vec!["http/1.1".to_owned()]);
        let min_version = self
            .min_version
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "1.2".to_owned());
        // Match the share-link default ("chrome") so the relay's emulated
        // ClientHello lines up with what the operator advertises to clients.
        let fingerprint = self
            .fingerprint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("chrome")
            .to_owned();
        let pinned_peer_cert_sha256 = self
            .pinned_peer_cert_sha256
            .clone()
            .unwrap_or_default()
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| decode_cert_sha256(s))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let cfg = XrayTlsConfig {
            certificate: Vec::new(),
            server_name: self.server_name.clone().unwrap_or_default(),
            next_protocol: alpn,
            min_version,
            max_version: self.max_version.clone().unwrap_or_default(),
            cipher_suites: self.cipher_suites.clone().unwrap_or_default(),
            fingerprint,
            verify_peer_cert_by_name: self
                .verify_peer_cert_by_name
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| !s.trim().is_empty())
                .collect(),
            pinned_peer_cert_sha256,
            ..XrayTlsConfig::default()
        };
        Ok(Some(TypedMessage {
            r#type: TYPE_TLS_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        }))
    }
}

/// Decode an operator-supplied SHA-256 cert hash (hex, optionally
/// colon/space-separated, or base64) into the 32 raw bytes xray pins against.
fn decode_cert_sha256(s: &str) -> anyhow::Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    // SHA-256 = 32 bytes = 64 hex chars; otherwise treat as base64.
    let bytes = if cleaned.len() == 64 && cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| anyhow::anyhow!("pinned_peer_cert_sha256: invalid hex: {e}"))?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(&cleaned)
            .map_err(|e| anyhow::anyhow!("pinned_peer_cert_sha256: invalid hex/base64: {e}"))?
    };
    if bytes.len() != 32 {
        anyhow::bail!(
            "pinned_peer_cert_sha256 must be a 32-byte SHA-256 (got {} bytes)",
            bytes.len()
        );
    }
    Ok(bytes)
}

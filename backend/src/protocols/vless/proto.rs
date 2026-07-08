//! VLESS-specific proto building. Owns the operator-facing knobs
//! (flow, decryption=none vs mlkem768x25519plus encryption mode, ...)
//! and the conversion into xray's `vless::inbound::Config` /
//! `vless::Account` proto messages.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::models::Client;
use crate::protocols::Protocol;
use crate::xray::proto::xray::common::protocol::User;
use crate::xray::proto::xray::common::serial::TypedMessage;
use crate::xray::proto::xray::proxy::vless::Account as XrayVlessAccount;
use crate::xray::proto::xray::proxy::vless::inbound::{
    Config as XrayVlessInboundConfig, Fallback as XrayVlessFallback,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

const TYPE_VLESS_INBOUND_CONFIG: &str = "xray.proxy.vless.inbound.Config";
const TYPE_VLESS_ACCOUNT: &str = "xray.proxy.vless.Account";

/// VLESS flow setting. None = plain VLESS, `XtlsRprxVision` = the XTLS
/// "Vision" optimisation (TCP-only, mostly used with Reality).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub enum VlessFlow {
    #[default]
    None,
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
}

impl VlessFlow {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::XtlsRprxVision => "xtls-rprx-vision",
        }
    }
}

/// VLESS Encryption mode (xray-core's `mlkem768x25519plus` application-
/// layer cipher, on top of TLS/Reality). `None` is the historical default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub enum VlessEncryptionMode {
    #[default]
    None,
    #[serde(rename = "mlkem768x25519plus")]
    Mlkem768x25519Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub enum VlessEncryptionAuth {
    #[default]
    Mlkem768,
    X25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub enum VlessXorMode {
    #[default]
    Native,
    Xorpub,
    Random,
}

impl VlessXorMode {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Xorpub => "xorpub",
            Self::Random => "random",
        }
    }
    pub const fn as_proto_u32(self) -> u32 {
        match self {
            Self::Native => 0,
            Self::Xorpub => 1,
            Self::Random => 2,
        }
    }
}

/// Destination type for a VLESS fallback. Mirrors xray's auto-inference
/// of the proto-level `type` field — operator picks explicitly so the
/// panel doesn't have to replicate xray's heuristics (port-number ↔ tcp,
/// abstract-socket prefix ↔ unix, etc.). Empty defaults to `Tcp` at
/// proto build time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS, Default)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub enum VlessFallbackType {
    #[default]
    Tcp,
    Unix,
    /// xray's built-in `serve` (currently only `dest = "serve-ws-none"`
    /// is documented, lets xray host a tiny inline WS endpoint instead
    /// of proxying to an external one).
    Serve,
}

impl VlessFallbackType {
    pub const fn as_proto_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Unix => "unix",
            Self::Serve => "serve",
        }
    }
}

/// One fallback route on a VLESS inbound. xray-core treats fallbacks as
/// a 3-level routing matrix keyed on (SNI substring, ALPN, HTTP-path),
/// firing when a connection makes it through TLS/Reality but fails to
/// produce a valid VLESS header within ~18 bytes — i.e. the probe is
/// most likely a real HTTP/H2 request from a search engine, scanner,
/// or genuine browser. The matched fallback forwards the raw bytes to
/// `dest` so the IP can credibly host both VLESS and a real web app.
///
/// All match fields default to empty (= wildcard / "any"); only `dest`
/// is meaningful in the simplest single-fallback case. Mutually
/// exclusive with `VlessEncryption` (xray errors at startup with
/// `fallbacks can not be used together with decryption`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub struct VlessFallback {
    /// Operator label. Not used for routing — xray groups by SNI
    /// substring through this field, but our UI uses empty string for
    /// the default route and a substring for named virtual hosts.
    pub name: String,
    /// ALPN match: `""` = any, `"h2"`, `"http/1.1"`. Path-based
    /// matching is documented as unreliable under `h2`.
    pub alpn: String,
    /// HTTP-path match. Empty = any. Non-empty MUST start with `/` or
    /// xray's config parser rejects the inbound.
    pub path: String,
    /// Destination kind. See `VlessFallbackType`.
    #[serde(rename = "type")]
    pub kind: VlessFallbackType,
    /// Where to forward. Format depends on `kind`:
    /// * tcp:   `host:port`, IPv4 ok, IPv6 must be bracketed
    /// * unix:  absolute filesystem path or `@abstract` socket name
    /// * serve: only `serve-ws-none` is documented today
    pub dest: String,
    /// PROXY-protocol version to prepend to forwarded bytes so the
    /// downstream sees the real client IP. `0` = off, `1` = text v1,
    /// `2` = binary v2. Anything > 2 is rejected by xray.
    pub xver: u32,
}

/// VLESS protocol config — everything the panel stores in the
/// `protocol_config` JSON blob for a VLESS inbound.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/protocol.ts")]
pub struct VlessProtocol {
    pub flow: VlessFlow,
    /// Encryption mode for the application-layer cipher. `None` keeps
    /// historical plain-VLESS-over-TLS/Reality behaviour.
    pub encryption_mode: VlessEncryptionMode,
    pub encryption_auth: Option<VlessEncryptionAuth>,
    pub encryption_xor_mode: Option<VlessXorMode>,
    #[ts(type = "number | null")]
    pub encryption_seconds_from: Option<i64>,
    #[ts(type = "number | null")]
    pub encryption_seconds_to: Option<i64>,
    pub encryption_padding: Option<String>,
    /// SECRET. base64-url. Server's private half of the ML-KEM/X25519
    /// keypair. Never logged.
    pub encryption_server_key: Option<String>,
    /// Public. base64-url. Embedded in share-links.
    pub encryption_client_key: Option<String>,
    /// Optional fallback table. Empty = no fallbacks (the historical
    /// behaviour). `#[serde(default)]` keeps DB rows written before
    /// this field landed deserialising cleanly.
    #[serde(default)]
    pub fallbacks: Vec<VlessFallback>,
}

impl VlessProtocol {
    /// Wire value for the `encryption=` URI param. Mirrors what xray's
    /// client-side outbound JSON parser accepts:
    ///   * `none` — plain VLESS (every existing inbound).
    ///   * `mlkem768x25519plus.<xor>.0rtt[.<padding>].<client_key>` — the
    ///     post-quantum / X25519 application-layer cipher. `0rtt` (≡
    ///     Seconds=1) is the only client-side mode the panel exposes;
    ///     `1rtt` (Seconds=0, legacy) is intentionally not surfaced in
    ///     the UI so share-links can't drift onto the slow path.
    fn share_link_encryption_value(&self) -> String {
        match self.encryption_mode {
            VlessEncryptionMode::None => "none".to_owned(),
            VlessEncryptionMode::Mlkem768x25519Plus => {
                let xor = self.encryption_xor_mode.unwrap_or_default();
                let pad = self.encryption_padding.clone().unwrap_or_default();
                let key = self.encryption_client_key.clone().unwrap_or_default();
                let mut s = format!("mlkem768x25519plus.{}.0rtt", xor.as_db_str());
                if !pad.is_empty() {
                    s.push('.');
                    s.push_str(&pad);
                }
                s.push('.');
                s.push_str(&key);
                s
            }
        }
    }

    /// Compute the inbound's `decryption` proto field plus the separate
    /// `padding` field.
    ///
    /// Returns `(decryption_string, padding, xor_proto_u32, secs_from, secs_to)`.
    ///
    /// `decryption` is the KEY ONLY — no `mlkem768x25519plus.<mode>.<secs>.`
    /// prefix and, crucially, no inline padding token. xray's direct-proto
    /// loader (`proxy/vless/inbound/inbound.go`) splits `Decryption` on `.` and
    /// decodes EVERY token as a key, so an inline padding token like `100-111-1111`
    /// decodes to a 9-byte slice and fails `mlkem: invalid seed length` at
    /// `AddInbound` (verified live against xray 26.6.27). Padding instead rides
    /// in the dedicated `padding` proto field, which xray's `ParsePadding`
    /// consumes at Init. The prefixed + inline-padding form exists only for
    /// xray's JSON-config parser / share-links, which strip both back out.
    fn server_encryption_fields(&self) -> (String, String, u32, i64, i64) {
        match self.encryption_mode {
            VlessEncryptionMode::None => (String::new(), String::new(), 0, 0, 0),
            VlessEncryptionMode::Mlkem768x25519Plus => {
                let xor = self.encryption_xor_mode.unwrap_or_default();
                let pad = self.encryption_padding.clone().unwrap_or_default();
                let from = self.encryption_seconds_from.unwrap_or(600);
                let to = self.encryption_seconds_to.unwrap_or(0);
                let key = self.encryption_server_key.clone().unwrap_or_default();
                (key, pad, xor.as_proto_u32(), from, to)
            }
        }
    }

    /// Validate the server decryption key when VLESS post-quantum encryption is
    /// enabled. xray's `ServerInstance.Init` (`proxy/vless/encryption/server.go`)
    /// base64-url-decodes the key and accepts only a 32-byte X25519 private key
    /// or a 64-byte ML-KEM-768 seed; anything else fails `AddInbound`. Checking
    /// it here — the shared `build_proxy_settings` choke point that both create
    /// and update pre-commit validation run — turns a malformed key into a
    /// pre-commit 400 instead of a committed row xray rejects. That matters most
    /// on update, where `sync_inbound_update_to_xray` removes the old handler
    /// before failing to add the new one, taking the inbound offline. An empty
    /// key is skipped here — on create `complete_server_managed_fields` backfills
    /// it before the build; an empty key that still reaches the build makes
    /// `decryption` fall back to `none`.
    fn validate_server_encryption_key(&self) -> anyhow::Result<()> {
        if self.encryption_mode != VlessEncryptionMode::Mlkem768x25519Plus {
            return Ok(());
        }
        let Some(key) = self
            .encryption_server_key
            .as_deref()
            .filter(|k| !k.is_empty())
        else {
            return Ok(());
        };
        let len = URL_SAFE_NO_PAD
            .decode(key)
            .map_err(|e| {
                anyhow::anyhow!("VLESS encryption server key is not valid base64-url: {e}")
            })?
            .len();
        anyhow::ensure!(
            len == 32 || len == 64,
            "VLESS encryption server key must decode to 32 bytes (X25519) or 64 bytes \
             (ML-KEM-768), got {len}"
        );
        Ok(())
    }

    /// Validate `encryption_padding` against xray's `ParsePadding`
    /// (`proxy/vless/encryption/common.go`) so a malformed value is a pre-commit
    /// 400 rather than an `AddInbound` failure after the row is committed —
    /// padding rides in its own proto field (see `server_encryption_fields`) and
    /// is only consumed there. Empty is valid (no padding). Each `.`-separated
    /// token is `min-a-b` (three ints); the first token additionally requires
    /// `min >= 100` and both gaps `>= 35`, and the summed length is capped.
    fn validate_encryption_padding(&self) -> anyhow::Result<()> {
        if self.encryption_mode != VlessEncryptionMode::Mlkem768x25519Plus {
            return Ok(());
        }
        let Some(padding) = self.encryption_padding.as_deref().filter(|p| !p.is_empty()) else {
            return Ok(());
        };
        let mut max_len: i64 = 0;
        for (i, token) in padding.split('.').enumerate() {
            let parts: Vec<&str> = token.split('-').collect();
            if parts.len() < 3 || parts[..3].iter().any(|p| p.is_empty()) {
                anyhow::bail!("invalid encryption padding length/gap parameter: {token}");
            }
            let y = parts[..3]
                .iter()
                .map(|p| p.parse::<i64>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| {
                    anyhow::anyhow!("encryption padding parameter is not an integer: {token}")
                })?;
            if i == 0 && (y[0] < 100 || y[1] < 35 || y[2] < 35) {
                anyhow::bail!("first encryption padding length must not be smaller than 35");
            }
            if i % 2 == 0 {
                max_len += y[1].max(y[2]);
            }
        }
        anyhow::ensure!(
            max_len <= 18 + 65535,
            "total encryption padding length must not be larger than 65553"
        );
        Ok(())
    }

    fn client_encryption_fields(&self) -> (String, u32, u32, String) {
        vless_client_encryption_fields(
            self.encryption_mode,
            self.encryption_xor_mode,
            self.encryption_client_key.as_deref(),
            self.encryption_padding.as_deref(),
        )
    }
}

/// Compute the client-side VLESS `Account` proto fields
/// `(encryption, xor_mode, seconds, padding)` for the given encryption
/// settings — shared by inbound user-building (`VlessProtocol`) and custom
/// **outbounds** (the relay client must mirror the upstream server's cipher).
///
/// `encryption` is the KEY ONLY — no `mlkem768x25519plus.<xor>.0rtt.` prefix
/// and no inline padding token. xray's direct-proto client loader
/// (`proxy/vless/outbound/outbound.go`) splits `Encryption` on `.` and decodes
/// every token as a key, so an inline padding token fails `mlkem: invalid seed
/// length` exactly like the inbound side. Padding rides in the dedicated
/// `padding` proto field instead; the prefixed/inline form is only for the JSON
/// parser / share-links. Clients use `Seconds=1` (`0rtt`); legacy `1rtt` is
/// never surfaced.
pub fn vless_client_encryption_fields(
    mode: VlessEncryptionMode,
    xor_mode: Option<VlessXorMode>,
    client_key: Option<&str>,
    padding: Option<&str>,
) -> (String, u32, u32, String) {
    match mode {
        VlessEncryptionMode::None => (String::new(), 0, 0, String::new()),
        VlessEncryptionMode::Mlkem768x25519Plus => {
            let xor = xor_mode.unwrap_or_default();
            let pad = padding.unwrap_or_default().to_owned();
            let key = client_key.unwrap_or_default().to_owned();
            (key, xor.as_proto_u32(), 1, pad)
        }
    }
}

impl Protocol for VlessProtocol {
    fn build_proxy_settings(&self, users: Vec<User>) -> anyhow::Result<TypedMessage> {
        self.validate_server_encryption_key()?;
        self.validate_encryption_padding()?;
        let (decryption, padding, xor_mode, seconds_from, seconds_to) =
            self.server_encryption_fields();
        let decryption = if decryption.is_empty() {
            "none".to_owned()
        } else {
            decryption
        };
        let fallbacks = self
            .fallbacks
            .iter()
            .map(|f| XrayVlessFallback {
                name: f.name.clone(),
                alpn: f.alpn.clone(),
                path: f.path.clone(),
                r#type: f.kind.as_proto_str().to_owned(),
                dest: f.dest.clone(),
                xver: u64::from(f.xver),
            })
            .collect();
        let cfg = XrayVlessInboundConfig {
            users,
            fallbacks,
            decryption,
            xor_mode,
            seconds_from,
            seconds_to,
            padding,
        };
        Ok(TypedMessage {
            r#type: TYPE_VLESS_INBOUND_CONFIG.to_owned(),
            value: cfg.encode_to_vec(),
        })
    }

    fn build_user(&self, client: &Client) -> anyhow::Result<User> {
        // Client-level flow override beats inbound default. `None` on
        // the client = inherit.
        let flow = client
            .flow
            .clone()
            .unwrap_or_else(|| self.flow.as_db_str().to_owned());

        let (encryption, xor_mode, seconds, padding) = self.client_encryption_fields();

        let account = XrayVlessAccount {
            id: client.uuid.clone(),
            flow,
            encryption,
            xor_mode,
            seconds,
            padding,
            reverse: None,
            testpre: 0,
            testseed: Vec::new(),
        };
        Ok(User {
            level: 0,
            email: client.email.clone(),
            account: Some(TypedMessage {
                r#type: TYPE_VLESS_ACCOUNT.to_owned(),
                value: account.encode_to_vec(),
            }),
        })
    }

    fn share_link_params(&self, client: &Client) -> Vec<(String, String)> {
        let mut params = vec![("encryption".to_owned(), self.share_link_encryption_value())];
        // `flow=` is only present for the Vision XTLS variant. Older
        // VLESS clients reject an unknown flow value with a parse error,
        // so omit the param entirely when the effective flow is plain.
        let effective_flow = client
            .flow
            .clone()
            .unwrap_or_else(|| self.flow.as_db_str().to_owned());
        if effective_flow == VlessFlow::XtlsRprxVision.as_db_str() {
            params.push(("flow".to_owned(), effective_flow));
        }
        params
    }
}

#[cfg(test)]
mod encryption_key_tests {
    //! The VLESS post-quantum server key must build only when xray's
    //! `ServerInstance.Init` would accept it (32-byte X25519 or 64-byte
    //! ML-KEM-768), so a malformed key is a pre-commit 400, never a committed
    //! row that `AddInbound` rejects.
    use super::*;

    fn mlkem(server_key: Option<String>) -> VlessProtocol {
        VlessProtocol {
            encryption_mode: VlessEncryptionMode::Mlkem768x25519Plus,
            encryption_server_key: server_key,
            ..VlessProtocol::default()
        }
    }

    #[test]
    fn valid_x25519_and_mlkem_lengths_build() {
        for n in [32usize, 64] {
            let key = URL_SAFE_NO_PAD.encode(vec![7u8; n]);
            assert!(
                mlkem(Some(key)).build_proxy_settings(vec![]).is_ok(),
                "{n}-byte key should build"
            );
        }
    }

    #[test]
    fn malformed_key_fails_to_build() {
        let err = mlkem(Some("not-a-key!".into()))
            .build_proxy_settings(vec![])
            .unwrap_err()
            .to_string();
        assert!(err.contains("base64-url"), "got: {err}");
    }

    #[test]
    fn wrong_length_key_fails_to_build() {
        let short = URL_SAFE_NO_PAD.encode([7u8; 16]);
        let err = mlkem(Some(short))
            .build_proxy_settings(vec![])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("32 bytes") && err.contains("64 bytes"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_key_and_plain_mode_skip_validation() {
        // Empty key degrades to decryption=none — not this check's concern.
        assert!(
            mlkem(Some(String::new()))
                .build_proxy_settings(vec![])
                .is_ok()
        );
        assert!(mlkem(None).build_proxy_settings(vec![]).is_ok());
        // encryption_mode=None never validates, even with garbage in the field.
        let plain = VlessProtocol {
            encryption_mode: VlessEncryptionMode::None,
            encryption_server_key: Some("garbage!".into()),
            ..VlessProtocol::default()
        };
        assert!(plain.build_proxy_settings(vec![]).is_ok());
    }

    fn mlkem_padded(padding: &str) -> VlessProtocol {
        VlessProtocol {
            encryption_mode: VlessEncryptionMode::Mlkem768x25519Plus,
            encryption_server_key: Some(URL_SAFE_NO_PAD.encode([7u8; 32])),
            encryption_padding: Some(padding.to_owned()),
            ..VlessProtocol::default()
        }
    }

    #[test]
    fn decryption_is_key_only_padding_in_its_own_field() {
        // Regression guard for the live-confirmed mlkem bug: the proto
        // `decryption` field must be the KEY ALONE. An inline padding token there
        // decodes to a short byte slice and fails `mlkem: invalid seed length` at
        // AddInbound (xray splits Decryption on '.' and treats every token as a
        // key). Padding must ride in the dedicated `padding` field.
        let key = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let msg = mlkem_padded("100-111-1111")
            .build_proxy_settings(vec![])
            .unwrap();
        let cfg = XrayVlessInboundConfig::decode(&msg.value[..]).unwrap();
        assert_eq!(cfg.decryption, key, "decryption must be the key only");
        assert_eq!(
            cfg.padding, "100-111-1111",
            "padding rides in its own field"
        );
    }

    #[test]
    fn valid_padding_builds() {
        assert!(
            mlkem_padded("100-111-1111")
                .build_proxy_settings(vec![])
                .is_ok()
        );
    }

    #[test]
    fn malformed_padding_fails_to_build() {
        // Fewer than three dash-separated parts.
        assert!(
            mlkem_padded("100-200")
                .build_proxy_settings(vec![])
                .unwrap_err()
                .to_string()
                .contains("padding")
        );
        // Non-integer parameter.
        assert!(
            mlkem_padded("aa-bb-cc")
                .build_proxy_settings(vec![])
                .is_err()
        );
        // First token below xray's minimums (100 / 35 / 35).
        assert!(
            mlkem_padded("50-35-35")
                .build_proxy_settings(vec![])
                .unwrap_err()
                .to_string()
                .contains("35")
        );
    }
}

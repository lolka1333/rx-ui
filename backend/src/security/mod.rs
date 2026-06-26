//! Stream-level security layers — None, TLS, Reality. Same trait-based
//! decomposition as `transports/`: every concrete layer lives in its
//! own file behind a small `Security` trait; the orchestrator wires
//! protocol+transport+security together without knowing the concrete
//! variants.

use crate::xray::proto::xray::common::serial::TypedMessage;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod reality;
pub mod tls;

/// "None" — plaintext over the chosen transport. Useful behind a CDN
/// or reverse proxy that terminates TLS. xray treats empty
/// `security_type` as no security layer; `build_settings` returns
/// `None` so the orchestrator leaves `security_settings` unpopulated.
/// Lives in this module (rather than its own file) because the
/// struct is field-less and the impl is three trivial methods.
#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub struct NoneSecurity {}

impl Security for NoneSecurity {
    fn kind(&self) -> SecurityKind {
        SecurityKind::None
    }
    fn xray_type_url(&self) -> &'static str {
        ""
    }
    fn build_settings(&self) -> anyhow::Result<Option<TypedMessage>> {
        Ok(None)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub enum SecurityKind {
    None,
    Tls,
    Reality,
}

impl SecurityKind {
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls => "tls",
            Self::Reality => "reality",
        }
    }
}

/// Each variant implements `Security`. Builds the security-side of an
/// xray `StreamConfig`: returns the `security_type` URL (or empty for
/// plaintext) + the wrapped `TypedMessage`.
pub trait Security: Send + Sync {
    /// Discriminator. Drives the default `share_link_params` impl below
    /// (`self.kind().as_db_str()` → the URL `security=` value).
    fn kind(&self) -> SecurityKind;

    /// Type URL placed in `StreamConfig.security_type`. Empty string
    /// for `None` — xray treats this as "no security layer".
    fn xray_type_url(&self) -> &'static str;

    /// `None` for `Security::None` (no `security_settings`), `Some(msg)`
    /// otherwise. The orchestrator wraps it as a single-element vec.
    fn build_settings(&self) -> anyhow::Result<Option<TypedMessage>>;

    /// Client-side (outbound) variant of `build_settings`. Differs from the
    /// server build: TLS drops the certificates (the client validates the
    /// server's chain); Reality populates the client fields (`server_name` /
    /// `public_key` / `short_id` / `Fingerprint` / `spider_x`) instead of the
    /// server's `private_key` / `server_names[]` / `short_ids[]`. The default
    /// delegates to the server build — correct for `None` (returns `None`);
    /// TLS and Reality override it.
    fn build_client_settings(&self) -> anyhow::Result<Option<TypedMessage>> {
        self.build_settings()
    }

    /// Key/value pairs this security layer contributes to the share-link
    /// URL. Default impl emits `security=<kind>`. Reality + TLS override
    /// to add their own `pbk`/`sid`/`fp`/`sni`/`alpn` etc.
    ///
    /// `fallback_host` is the host the operator may have set on a
    /// non-Reality transport (e.g. xhttp.host or ws.host) — TLS uses it
    /// as a fallback for `sni=` when the operator didn't set an
    /// explicit `tls_server_name`.
    fn share_link_params(&self, fallback_host: &str) -> Vec<(String, String)> {
        let _ = fallback_host;
        vec![("security".to_owned(), self.kind().as_db_str().to_owned())]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[ts(export, export_to = "../../frontend/src/api/types/security.ts")]
pub enum SecurityConfig {
    None(NoneSecurity),
    Tls(tls::TlsSecurity),
    Reality(reality::RealitySecurity),
}

impl SecurityConfig {
    pub fn as_security(&self) -> &dyn Security {
        match self {
            Self::None(s) => s,
            Self::Tls(s) => s,
            Self::Reality(s) => s,
        }
    }
}

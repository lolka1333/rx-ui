//! VLESS protocol module. The struct holds VLESS-specific operator
//! choices (flow, decryption mode, post-quantum encryption settings);
//! the impl turns them into xray's `vless::inbound::Config` proto +
//! per-user `vless::Account` proto.

mod proto;

pub use proto::{
    VlessEncryptionAuth, VlessEncryptionMode, VlessFlow, VlessProtocol, VlessXorMode,
    vless_client_encryption_fields,
};

// `VlessFallback` / `VlessFallbackType` live inside `proto` and are
// referenced from the proto module's own helpers — no production code
// outside this module needs them today. The validation test in
// `api/inbounds.rs` does, so we expose them under `cfg(test)` only;
// re-exporting unconditionally would warn "unused" on every release build.
#[cfg(test)]
pub use proto::{VlessFallback, VlessFallbackType};

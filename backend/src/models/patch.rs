//! Tri-state PATCH field — distinguishes "leave alone" from "clear" from
//! "set to value". Plain `Option<T>` collapses the first two: serde maps
//! both `{}` (key absent) and `{"k": null}` to `None`, so the operator
//! can't actually clear a nullable column via PATCH.
//!
//! Self-contained `Deserialize` impl, so no `#[serde(deserialize_with)]`
//! is needed at the field site — which keeps `ts-rs` happy (it can't
//! parse free-standing function references in serde attributes).
//!
//! Usage:
//! ```ignore
//! #[derive(Deserialize, TS)]
//! pub struct ClientUpdate {
//!     #[serde(default)]
//!     #[ts(type = "number | null | undefined")]
//!     pub traffic_limit_bytes: PatchField<i64>,
//! }
//!
//! match body.traffic_limit_bytes {
//!     PatchField::Set(v)    => /* UPDATE … SET col = $1   */,
//!     PatchField::Clear     => /* UPDATE … SET col = NULL */,
//!     PatchField::Unchanged => /* leave col alone */,
//! }
//! ```

use serde::{Deserialize, Deserializer};

/// Tri-state field for HTTP PATCH bodies. `Unchanged` ≡ key absent in
/// JSON, `Clear` ≡ `"k": null`, `Set(v)` ≡ `"k": v`. Needs `#[serde(default)]`
/// at the field site so the deserializer falls back to `Default::default()`
/// (which is `Unchanged`) when the JSON key is missing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum PatchField<T> {
    #[default]
    Unchanged,
    Clear,
    Set(T),
}

impl<T> PatchField<T> {
    /// Borrowed view — useful when the consumer wants to bind into a
    /// SQL builder without consuming the value. `Option<Option<&T>>` is
    /// the same tri-state the enum expresses (outer = is-change,
    /// inner = is-set); the docstring above the type explains why.
    #[allow(clippy::option_option)]
    pub const fn as_change(&self) -> Option<Option<&T>> {
        match self {
            Self::Unchanged => None,
            Self::Clear => Some(None),
            Self::Set(v) => Some(Some(v)),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for PatchField<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // serde's `Option` deserializer maps explicit JSON null → None
        // and any value → Some(v). Key-absent never reaches us — that's
        // handled upstream by `#[serde(default)]`.
        Option::<T>::deserialize(d).map(|opt| opt.map_or_else(|| Self::Clear, Self::Set))
    }
}

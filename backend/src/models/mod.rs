pub mod auth;
pub mod client;
pub mod inbound;
pub mod outbound;
pub mod patch;
pub mod stats;

pub use auth::*;
pub use client::*;
pub use inbound::*;
pub use outbound::*;
pub use stats::*;

/// serde default for a flag that predates its own column: a body written by an
/// older client carries no field, and for these the historical state is "on".
pub const fn default_true() -> bool {
    true
}

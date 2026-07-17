pub mod config_gen;
pub mod control;
pub mod grpc;
pub mod installer;
pub mod keygen;
pub mod orchestrator;
pub mod outbound_test;
pub mod proto;
pub mod reload;
pub mod router_rules;
pub mod share_link;

pub use control::XrayController;
pub use grpc::XrayClient;

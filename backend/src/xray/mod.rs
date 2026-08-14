pub mod cli;
pub mod config_gen;
pub mod control;
pub mod geofiles;
pub mod grpc;
pub mod installer;
pub mod keygen;
pub mod orchestrator;
pub mod outbound_test;
pub mod proto;
pub mod reload;
pub mod router_rules;
pub mod scratch;
pub mod share_link;
pub mod xmc;

pub use control::XrayController;
pub use grpc::XrayClient;

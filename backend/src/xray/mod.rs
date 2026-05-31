pub mod config_gen;
pub mod control;
pub mod grpc;
pub mod installer;
pub mod keygen;
pub mod orchestrator;
pub mod proto;
pub mod reload;
pub mod share_link;

pub use control::XrayController;
pub use grpc::XrayClient;

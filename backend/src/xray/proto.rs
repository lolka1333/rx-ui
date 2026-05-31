//! Generated protobuf bindings for Xray-core's gRPC surface.
//!
//! The `tonic::include_proto!` calls pull in the Rust code that `build.rs`
//! emits into `$OUT_DIR` from the `.proto` files vendored under `proto/`.
//! Module layout mirrors Xray's Go package paths so that any reference like
//! `xray.app.proxyman.command.HandlerService` translates one-to-one to
//! `pb::xray::app::proxyman::command::handler_service_client::*` here.
//!
//! Anything we don't actively use (sniffing, fallbacks, geodata, the
//! outbound-side of `HandlerService`, etc.) is generated but unused — the dead
//! code lives in `$OUT_DIR` and doesn't bloat the binary if LTO is on.

// `tonic::include_proto!` expands to `include!(concat!(env!("OUT_DIR"), "/<pkg>.rs"))`.
// We re-export everything verbatim under the original package hierarchy.
//
// `dead_code` is suppressed because the generated tree includes many proto
// messages we don't actively reference (geodata, empty placeholder configs,
// outbound-side handlers) — they exist purely to satisfy proto-level
// imports from messages we *do* use. Re-trimming the .proto vendor set to
// drop them would be possible but fragile; suppressing the lint is the
// cheaper, less-coupled choice.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    rustdoc::all,
    dead_code,
    non_snake_case,
    non_camel_case_types,
    unused_qualifications,
    missing_docs
)]
pub mod xray {
    pub mod app {
        pub mod proxyman {
            tonic::include_proto!("xray.app.proxyman");
            pub mod command {
                tonic::include_proto!("xray.app.proxyman.command");
            }
        }
        pub mod stats {
            pub mod command {
                tonic::include_proto!("xray.app.stats.command");
            }
        }
    }
    pub mod common {
        pub mod geodata {
            tonic::include_proto!("xray.common.geodata");
        }
        pub mod net {
            tonic::include_proto!("xray.common.net");
        }
        pub mod protocol {
            tonic::include_proto!("xray.common.protocol");
        }
        pub mod serial {
            tonic::include_proto!("xray.common.serial");
        }
    }
    pub mod core {
        tonic::include_proto!("xray.core");
    }
    pub mod proxy {
        pub mod vless {
            tonic::include_proto!("xray.proxy.vless");
            pub mod inbound {
                tonic::include_proto!("xray.proxy.vless.inbound");
            }
        }
        pub mod hysteria {
            tonic::include_proto!("xray.proxy.hysteria");
            pub mod account {
                tonic::include_proto!("xray.proxy.hysteria.account");
            }
        }
    }
    pub mod transport {
        pub mod internet {
            tonic::include_proto!("xray.transport.internet");
            pub mod finalmask {
                pub mod sudoku {
                    tonic::include_proto!("xray.transport.internet.finalmask.sudoku");
                }
                pub mod fragment {
                    tonic::include_proto!("xray.transport.internet.finalmask.fragment");
                }
                pub mod noise {
                    tonic::include_proto!("xray.transport.internet.finalmask.noise");
                }
            }
            pub mod hysteria {
                tonic::include_proto!("xray.transport.internet.hysteria");
            }
            pub mod reality {
                tonic::include_proto!("xray.transport.internet.reality");
            }
            pub mod splithttp {
                tonic::include_proto!("xray.transport.internet.splithttp");
            }
            pub mod tcp {
                tonic::include_proto!("xray.transport.internet.tcp");
            }
            pub mod tls {
                tonic::include_proto!("xray.transport.internet.tls");
            }
            pub mod websocket {
                tonic::include_proto!("xray.transport.internet.websocket");
            }
        }
    }
}

//! Compile Xray-core's protobuf definitions into Rust modules.
//!
//! Only the `client`-side bindings are generated (`build_server(false)`) —
//! the panel never serves the `HandlerService`, only consumes it.
//!
//! The set of `compile_protos` entries below covers the panel's supported
//! VLESS transports: TCP, XHTTP (splithttp), WebSocket. Any new protocol
//! or transport added to the panel must list its `.proto` here and its
//! file vendored under `proto/` (mirror Xray-core's source layout).

// `std::env::set_var` is `unsafe` in Rust 2024 because env vars are
// process-global state. In a build script we run synchronously on a single
// thread before anything else touches the environment, so the unsafety is
// inert here — the workspace-wide `unsafe-code = "forbid"` lint just needs
// a one-line local override.
#[allow(unsafe_code)]
fn set_protoc_env(path: std::path::PathBuf) {
    // SAFETY: build.rs is single-threaded; no other code reads PROTOC.
    unsafe {
        std::env::set_var("PROTOC", path);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic-build defaults to looking up `protoc` on PATH; we ship a vendored
    // binary via the `protoc-bin-vendored` crate so the build works on any
    // dev machine without a system protobuf install. The crate's `protoc_bin_path`
    // returns the precompiled binary for the current target.
    set_protoc_env(protoc_bin_vendored::protoc_bin_path()?);

    let protos = [
        // HandlerService — runtime inbound / user CRUD.
        "proto/app/proxyman/command/command.proto",
        // StatsService — per-user traffic counters + online IP lists,
        // surfaced on the Clients page (live indicator + bytes/sec).
        // The matching policy in `config_gen` enables the counters.
        "proto/app/stats/command/command.proto",
        // VLESS server-side protocol settings + account shape.
        "proto/proxy/vless/inbound/config.proto",
        "proto/proxy/vless/account.proto",
        // Hysteria 2 — proxy + per-user account. ServerConfig carries the
        // users[]; per-user Account.auth is the shared secret. ClientConfig
        // is generated but unused (the panel never dials out).
        "proto/proxy/hysteria/config.proto",
        "proto/proxy/hysteria/account/config.proto",
        // Transports we support today.
        "proto/transport/internet/reality/config.proto",
        "proto/transport/internet/splithttp/config.proto",
        "proto/transport/internet/tcp/config.proto",
        "proto/transport/internet/tls/config.proto",
        "proto/transport/internet/websocket/config.proto",
        // Hysteria 2 QUIC transport — tightly coupled with the hysteria
        // proxy (xray's stream layer dispatches both together). Carries
        // auth/masq_*/udp_idle_timeout.
        "proto/transport/internet/hysteria/config.proto",
        // FinalMask — wire-level traffic obfuscation that wraps TCP and
        // UDP sockets AFTER TLS/Reality handshakes complete. Each
        // variant's TypedMessage is routed into StreamConfig.tcpmasks
        // and/or .udpmasks so xray applies it on whichever transport
        // the inbound is bound to (or just one for TCP-only / UDP-only
        // variants like fragment / noise).
        //   * sudoku   — password-derived lookup + ASCII entropy + padding
        //                (TCP and UDP)
        //   * fragment — TCP-side packet splitting for DPI-evasion
        //   * noise    — UDP-side prepended noise items for QUIC masking
        "proto/transport/internet/finalmask/sudoku/config.proto",
        "proto/transport/internet/finalmask/fragment/config.proto",
        "proto/transport/internet/finalmask/noise/config.proto",
    ];

    for p in &protos {
        println!("cargo:rerun-if-changed={p}");
    }
    println!("cargo:rerun-if-changed=proto");

    // tonic 0.14 split prost-based codegen out of the main `tonic-build`
    // crate into `tonic-prost-build`. The builder API is identical —
    // `configure()` returns a Builder with the same chainable methods,
    // just imported from the new crate.
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        // Don't fail compilation on Xray's many unused fields — we don't use
        // most of the optional features, and `unused_imports` warnings from
        // generated code would spam every build.
        .compile_protos(&protos, &["proto"])?;

    // Frontend-dist embed: `rust-embed` reads files at compile time. If
    // someone forgets `pnpm build` before `cargo build --release`, the
    // embedded asset set is empty and the resulting binary silently 500s
    // every page request. Detect it here with a loud, actionable error
    // instead.
    //
    // Dev builds (debug_assertions) skip this — the frontend is served
    // by Vite on :5173 during development, and an empty dist/ is normal
    // when the developer hasn't built yet. Vite's HMR provides the page
    // content; the backend's static_assets fallback just returns "frontend
    // assets not embedded" which is fine because the operator browses on
    // :5173 in dev.
    let dist_index = std::path::Path::new("../frontend/dist/index.html");
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    if is_release && !dist_index.exists() {
        return Err(format!(
            "frontend not built — release binary embeds ../frontend/dist/ but \
             `{}` is missing. Run `pnpm install && pnpm build` inside frontend/ \
             before `cargo build --release`.",
            dist_index.display()
        )
        .into());
    }
    // Force re-embed when frontend output changes — rust-embed reads the
    // folder at compile time and won't otherwise notice a fresh `pnpm build`.
    println!("cargo:rerun-if-changed=../frontend/dist");

    Ok(())
}

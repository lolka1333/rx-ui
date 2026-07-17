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
        // VLESS client-side (outbound) settings — a single `vnext` endpoint.
        // Used by custom outbounds to relay through an upstream VLESS server.
        "proto/proxy/vless/outbound/config.proto",
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
        //   * salamander — UDP-side Hysteria 2 obfs (password-keyed); the
        //                  hysteria2 share-link ships it as the standard
        //                  `obfs=salamander&obfs-password=` so native clients
        //                  pick it up too
        "proto/transport/internet/finalmask/sudoku/config.proto",
        "proto/transport/internet/finalmask/fragment/config.proto",
        "proto/transport/internet/finalmask/noise/config.proto",
        "proto/transport/internet/finalmask/salamander/config.proto",
        // RoutingService — live routing-rule mutation (AddRule/RemoveRule)
        // so rule changes apply without an xray restart. `config.proto`
        // carries the RoutingRule / router Config shapes we build and push;
        // `command.proto` is the service. Needs `common/net/network.proto`.
        "proto/app/router/config.proto",
        "proto/app/router/command/command.proto",
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
    // Non-release builds (PROFILE != "release") skip this — the frontend is
    // served by Vite on :5173 during development, and an empty dist/ is normal
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
    // Force re-embed when frontend output changes. `rust-embed` bakes the dist
    // tree into the binary during `static_assets.rs`'s proc-macro expansion, and
    // cargo only re-runs that macro when the MODULE recompiles. A bare
    // `rerun-if-changed=../frontend/dist` re-runs this script but does not
    // invalidate that module, so an incremental release build after a fresh
    // `pnpm build` can silently embed the PREVIOUS dist. To make the embed track
    // dist reliably we walk the tree here (emitting a per-file rerun-if-changed
    // so this script re-runs on any change), fingerprint it, and write the
    // digest to OUT_DIR. `static_assets.rs` pulls that digest in via
    // `include_str!`, so a changed dist changes the digest, recompiles the
    // module, and makes rust-embed re-read the folder.
    println!("cargo:rerun-if-changed=../frontend/dist");
    let mut entries = Vec::new();
    let dist = std::path::Path::new("../frontend/dist");
    fingerprint_dist(dist, dist, &mut entries);
    entries.sort();
    let out_dir = std::env::var("OUT_DIR")?;
    std::fs::write(
        std::path::Path::new(&out_dir).join("dist_fingerprint.txt"),
        entries.join("\n"),
    )?;

    Ok(())
}

/// Walk `dir`, emitting a `cargo:rerun-if-changed` for every file (so the build
/// script re-runs whenever a `pnpm build` rewrites the output) and collecting a
/// `relpath:len:mtime` line per file into `out`. The sorted join of these lines
/// is the dist fingerprint that gates the embed: any added, removed, resized, or
/// rewritten file changes it. A missing dir (dev builds with no `pnpm build`
/// yet) simply yields no entries, so the digest is empty and stable.
fn fingerprint_dist(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        println!("cargo:rerun-if-changed={}", path.display());
        if path.is_dir() {
            fingerprint_dist(root, &path, out);
        } else if let Ok(meta) = entry.metadata() {
            let rel = path.strip_prefix(root).unwrap_or(&path);
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_nanos());
            out.push(format!("{}:{}:{}", rel.display(), meta.len(), mtime));
        }
    }
}

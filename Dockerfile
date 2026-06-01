# syntax=docker/dockerfile:1
#
# rx-ui ships as a single binary: the Rust backend embeds the built React
# SPA (via rust-embed) and supervises an xray-core child process. This
# multi-stage build compiles both and produces a small runtime image with
# just that binary. xray-core itself is NOT baked in — the panel downloads
# the matching release into its data volume on first run.

# ---- Stage 1: build the frontend (Vite -> frontend/dist) --------------------
FROM node:22-bookworm-slim AS frontend
# corepack ships with Node 22 and reads the "packageManager" field
# (pnpm@11.5.0) from package.json, so the pnpm version matches CI exactly.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /app/frontend
RUN corepack enable
# Install deps first (this layer is cached until the lockfile changes),
# then copy the rest of the sources.
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm run build

# ---- Stage 2: build the backend (embeds frontend/dist) ----------------------
FROM rust:1.95-bookworm AS backend
# aws-lc-rs (rustls' crypto provider, pulled in via reqwest) needs cmake to
# build; the rust image already provides gcc/make. protoc is vendored by the
# protoc-bin-vendored crate, so no system protobuf install is required.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Compile-time-checked queries resolve against the committed .sqlx cache, so
# the build needs no live database.
ENV SQLX_OFFLINE=true
# Workspace manifests + the pinned toolchain, then the backend crate.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY backend/ ./backend/
# The release build embeds ../frontend/dist via rust-embed, so the SPA built
# in stage 1 must be present before cargo runs (build.rs hard-errors if not).
COPY --from=frontend /app/frontend/dist ./frontend/dist
# Cache the cargo registry + target dir across builds (BuildKit). The binary
# is copied out of the cached target dir into a normal layer path so the
# runtime stage can pick it up.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --bin rx-ui \
    && cp /app/target/release/rx-ui /usr/local/bin/rx-ui

# ---- Stage 3: runtime -------------------------------------------------------
# Same Debian release as the build image so the glibc the binary links
# against matches. xray-core's Linux release is a static Go binary and runs
# here as-is.
FROM debian:bookworm-slim AS runtime
# ca-certificates: TLS trust store for the xray child process / general HTTPS.
# curl: used only by the container HEALTHCHECK below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend /usr/local/bin/rx-ui /usr/local/bin/rx-ui

# Container-friendly defaults. PANEL_HOST is the critical one: the binary
# defaults to 127.0.0.1 (localhost-only), which is unreachable from outside
# the container. All of these can be overridden via compose / .env.
ENV PANEL_HOST=0.0.0.0 \
    PANEL_PORT=8080 \
    RUST_LOG=rx_ui=info,tower_http=info,sqlx=warn

# Panel state — SQLite DB, the auto-generated JWT secret, and the downloaded
# xray binary/config/geofiles — all live under ./data (relative to WORKDIR).
# Mount a volume here so it survives container recreation.
VOLUME ["/app/data"]

EXPOSE 8080

# The SPA index answers 200 once the HTTP listener is up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PANEL_PORT}/" >/dev/null || exit 1

# rx-ui is on PATH; WORKDIR /app makes it create/use ./data = /app/data.
ENTRYPOINT ["rx-ui"]

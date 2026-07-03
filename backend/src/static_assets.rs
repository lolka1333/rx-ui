//! Single-binary mode: serve the built frontend (`frontend/dist/`) embedded
//! directly into the backend executable via `rust-embed`.
//!
//! The macro reads every file under `../frontend/dist/` at COMPILE TIME and
//! stores its bytes (gzip-compressed) inside the binary. At runtime we look up
//! the requested path against the embedded set, fall back to `index.html` for
//! SPA-style client-routed paths, and return `404` only for truly unknown
//! files (e.g. an asset path that doesn't exist).
//!
//! The panel can be mounted under a secret URL prefix (`panel_base_path`). To
//! make the SPA work both at the root and under a prefix, the frontend is built
//! with `base: './'` (relative asset URLs) and a relative axios `baseURL`, and
//! the served `index.html` carries an injected `<base href="{prefix}/">` so all
//! of those relative URLs resolve under the actual mount — see `render_index`.

use crate::AppState;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../frontend/dist/"]
struct Asset;

// Ties this module's compilation to the dist fingerprint that `build.rs` writes
// into OUT_DIR. rust-embed bakes the dist tree in during THIS module's macro
// expansion; when `pnpm build` changes the output, build.rs rewrites the
// fingerprint, which changes this `include_str!` input and forces a recompile —
// so an incremental release build can never embed a stale dist. The value is
// intentionally unused (anonymous const); only the compile-time file dependency
// matters.
const _: &str = include_str!(concat!(env!("OUT_DIR"), "/dist_fingerprint.txt"));

/// SPA fallback for the ADMIN listener. Reads the panel's current mount prefix
/// from state so the served `index.html` carries the right `<base href>` (the
/// panel may be mounted under a secret URL prefix). Wire via `.fallback(serve)`
/// as the last layer (BEFORE `.with_state`, so it can extract `State`) — it
/// catches everything not claimed by an `/api/*` nest.
pub async fn serve(State(state): State<AppState>, req: Request) -> Response {
    let base_path = state.base_path.read().await.clone();
    serve_with_base(&base_path, &req)
}

/// Handler for the exact mount root. Wired as `.route("/", get(serve_index_root))`
/// because axum's `nest` does NOT route the bare `{prefix}/` (trailing slash) to
/// the inner fallback — without an explicit `/` route, visiting the secret-prefix
/// root (`/secret/`) 404s. Serves the SPA with the prefix's `<base href>`.
pub async fn serve_index_root(State(state): State<AppState>) -> Response {
    let base_path = state.base_path.read().await.clone();
    render_index(&base_path, None)
}

/// Serve an embedded `assets/{path}` file at the ROOT, outside any admin URL
/// prefix. The public subscription landing (`/sub/{token}`, also served at the
/// root) loads its bundle via relative `./assets/...` against a root
/// `<base href>`, so the fingerprinted asset files must stay reachable at the
/// root even when the admin panel is hidden under a secret prefix. Only the
/// asset files are exposed this way — the SPA shell and client routes stay
/// under the prefix, and the bundle carries no copy of the secret path.
pub async fn serve_asset(Path(path): Path<String>) -> Response {
    let rel = format!("assets/{path}");
    Asset::get(&rel).map_or_else(
        || (StatusCode::NOT_FOUND, format!("asset not found: /{rel}")).into_response(),
        |asset| asset_response(&rel, asset),
    )
}

fn serve_with_base(base_path: &str, req: &Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    // Empty path = the mount root (`/` or the prefix root `/secret/`) — serve
    // the SPA so it boots.
    if path.is_empty() {
        return render_index(base_path, None);
    }
    if let Some(asset) = Asset::get(path) {
        return asset_response(path, asset);
    }
    // Asset-y paths (under `assets/` or with a file extension) that don't exist
    // are real 404s — returning HTML for `/assets/foo.js` would confuse the
    // module loader. Everything else (e.g. `/inbounds`) is a client route → SPA.
    if is_asset_like(path) {
        not_found_for_uri(req.uri())
    } else {
        render_index(base_path, None)
    }
}

/// Serve `index.html` with the `<title>` rewritten to `title`. Used by the
/// subscription landing so the operator brand shows in the tab from the first
/// paint (no flash from the static "Admin Panel" placeholder). Rendered at the
/// root mount — subscriptions live at `/sub`, never under the admin prefix.
pub fn serve_index_with_title(title: &str) -> Response {
    render_index("", (!title.is_empty()).then_some(title))
}

/// Render the SPA `index.html`: inject `<base href="{base_path}/">` so the
/// frontend's relative asset (`./assets/...`) and API URLs resolve correctly
/// whether the panel is mounted at the root or under a secret prefix, and
/// optionally override the `<title>`. `base_path` is validated to URL-safe
/// chars upstream (`normalize_base_path`), so it needs no attribute escaping.
fn render_index(base_path: &str, title: Option<&str>) -> Response {
    let Some(asset) = Asset::get("index.html") else {
        return missing_index_response();
    };
    let Ok(original) = std::str::from_utf8(&asset.data) else {
        return asset_response("index.html", asset);
    };
    let mut html = original.to_owned();
    let base_href = if base_path.is_empty() {
        "/".to_owned()
    } else {
        format!("{base_path}/")
    };
    // Inject right after `<head>` (Vite always emits one). If it's absent the
    // page degrades to the unmodified HTML rather than crashing.
    if let Some(head) = html.find("<head>") {
        html.insert_str(
            head + "<head>".len(),
            &format!("<base href=\"{base_href}\">"),
        );
    }
    // Optional `<title>` override, HTML-escaped so a brand with `<`/`&` can't
    // break out of the element.
    if let Some(title) = title
        && let (Some(open), Some(close)) = (html.find("<title>"), html.find("</title>"))
        && open < close
    {
        let mut escaped = String::new();
        push_html_escaped(&mut escaped, title);
        html.replace_range(open + "<title>".len()..close, &escaped);
    }
    html_response(html)
}

fn push_html_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
}

fn html_response(body: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

fn missing_index_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "frontend assets not embedded in this binary — \
         rebuild with `pnpm build && cargo build --release`",
    )
        .into_response()
}

fn asset_response(path: &str, asset: rust_embed::EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    let body = Body::from(asset.data.into_owned());
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime.as_ref()),
            // Aggressive cache for fingerprinted Vite assets, no-cache for
            // index.html (so a backend rebuild propagates immediately).
            (
                header::CACHE_CONTROL,
                if path == "index.html" {
                    "no-cache"
                } else if path.starts_with("assets/") {
                    "public, max-age=31536000, immutable"
                } else {
                    "public, max-age=3600"
                },
            ),
        ],
        body,
    )
        .into_response()
}

fn not_found_for_uri(uri: &Uri) -> Response {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("asset not found: {}", uri.path()),
    )
        .into_response()
}

/// Heuristic to distinguish a "real asset request" (must 404 if missing) from a
/// "client-routed SPA path" (must fall back to index.html). Asset paths in Vite
/// output always sit under `assets/` (hashed filenames) or are top-level files
/// with extensions (`favicon.ico`, `vite.svg`); client routes are extension-less.
fn is_asset_like(path: &str) -> bool {
    path.starts_with("assets/") || path.contains('.')
}

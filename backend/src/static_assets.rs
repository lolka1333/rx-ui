//! Single-binary mode: serve the built frontend (`frontend/dist/`)
//! embedded directly into the backend executable via `rust-embed`.
//!
//! The macro reads every file under `../frontend/dist/` at COMPILE TIME
//! and stores its bytes (gzip-compressed) inside the binary. At runtime
//! we look up the requested path against the embedded set, fall back to
//! `index.html` for SPA-style client-routed paths, and return a `404`
//! only for truly unknown files (e.g. an asset path that doesn't exist).
//!
//! Why a fallback to `index.html` instead of `404` for unknown paths:
//! Vite produces a single-page-app; React would handle `/inbounds` /
//! `/dashboard` etc. client-side once `index.html` loads. Returning the
//! HTML for any non-asset path is what every SPA reverse-proxy config
//! does. Real asset 404s are still distinguishable: paths starting with
//! `/assets/` always have a file extension; if we can't find a
//! `/assets/foo.js`, returning index.html would just confuse the JS
//! loader, so we return 404 for those instead of the fallback.

use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../frontend/dist/"]
struct Asset;

/// Returns an axum router that serves the embedded frontend on every
/// path NOT already claimed by an `/api/*` nest. Wire it via
/// `Router::fallback_service(static_assets::router())` AFTER all `nest`
/// calls have been made — the fallback runs last by definition.
pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new().fallback(serve)
}

async fn serve(req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    // Empty path = the operator typed bare `http://host:port/` — serve
    // index.html so the SPA boots.
    if path.is_empty() {
        return serve_index();
    }
    if let Some(asset) = Asset::get(path) {
        return asset_response(path, asset);
    }
    // Asset-y paths (anything under /assets/, or with a recognisable
    // file extension) that we couldn't find are real 404s — not SPA
    // routes. Returning HTML for `/assets/foo.js` would confuse the
    // browser's module loader. Everything else (e.g. `/inbounds`,
    // `/dashboard`) gets the SPA fallback.
    if is_asset_like(path) {
        not_found_for_uri(req.uri())
    } else {
        serve_index()
    }
}

/// Serve the embedded SPA `index.html` with the `<title>` element
/// rewritten to `title`. Used by the subscription endpoint so a
/// browser visit to `/sub/{token}` lands on a page that already
/// carries the operator-configured brand in the tab — no
/// `document.title = ...` from React and no flash from the static
/// "Admin Panel" placeholder. `title` is HTML-escaped here so a
/// brand string with `<` / `&` can't break out of the element. Empty
/// `title` (operator hasn't set a brand) falls through to the
/// unmodified default.
pub fn serve_index_with_title(title: &str) -> Response {
    if title.is_empty() {
        return serve_index();
    }
    let Some(asset) = Asset::get("index.html") else {
        return missing_index_response();
    };
    let Ok(original) = std::str::from_utf8(&asset.data) else {
        return asset_response("index.html", asset);
    };
    // Substring swap on `<title>...</title>`. If the placeholder isn't
    // where we expect (someone edited index.html without coordinating)
    // the served HTML stays unchanged — degrades to the React-side
    // setter rather than crashing.
    let Some(open) = original.find("<title>") else {
        return asset_response("index.html", asset);
    };
    let Some(close_rel) = original[open..].find("</title>") else {
        return asset_response("index.html", asset);
    };
    let close = open + close_rel;
    let mut rewritten = String::with_capacity(original.len() + title.len());
    rewritten.push_str(&original[..open + "<title>".len()]);
    push_html_escaped(&mut rewritten, title);
    rewritten.push_str(&original[close..]);
    html_response(rewritten)
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

/// Serve the embedded SPA `index.html` verbatim. Used by the admin
/// shell and the static-fallback router; subscription HTML responses
/// go through `serve_index_with_title` so the tab title is right
/// from the first paint.
pub fn serve_index() -> Response {
    Asset::get("index.html").map_or_else(missing_index_response, |content| {
        asset_response("index.html", content)
    })
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

/// Heuristic to distinguish "real asset request" (must 404 if missing)
/// from "client-routed SPA path" (must fall back to index.html). Asset
/// paths in Vite output always sit under `assets/` (hashed filenames)
/// or are top-level files with extensions (`favicon.ico`, `vite.svg`).
/// Client routes are extension-less (`/inbounds`, `/dashboard/foo`).
fn is_asset_like(path: &str) -> bool {
    path.starts_with("assets/") || path.contains('.')
}

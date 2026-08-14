//! Geofile sources: fetch `geoip.dat` / `geosite.dat` from a rules repository
//! instead of taking whatever the xray release archive happened to ship.
//!
//! Until this module existed the two files arrived only inside the release zip
//! (see [`crate::xray::installer`]), which pinned the rule set to the core's
//! release cadence — a panel on a six-month-old xray was routing against
//! six-month-old lists, with no way to refresh them short of reinstalling the
//! binary.
//!
//! Three things matter here and shape the code:
//!
//! * **"Did it change?" must be cheap to answer honestly.** The panel stores
//!   the SHA-256 of the bytes it last wrote. A refresh downloads, hashes, and
//!   compares — so "already current" is a fact about the file on disk, not a
//!   guess from a timestamp or an `ETag` the mirror may not send.
//! * **A half-written dat is worse than an old one.** xray memory-maps these
//!   at startup and a truncated file is a hard failure, so the download lands
//!   in a `.partial` sibling and is renamed over the target only once it is
//!   complete and has passed a sanity check.
//! * **xray reads them once, at start.** Replacing the files under a running
//!   process changes nothing until it restarts — the core caches its geo
//!   matchers by FILE NAME (`common/geodata`), so even re-pushing the routing
//!   rules over gRPC reuses the old in-memory lists. Downloading is therefore
//!   safe and applying is not: a restart drops every live connection, and the
//!   upstream sources publish daily. Whether to take that cost belongs to the
//!   caller — see `api::xray::run_geo_refresh`, where the manual button applies
//!   and the nightly task only downloads and flags that a restart is owed.

use crate::xray::keygen::hex_lower;
use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The two files xray looks for. Names are fixed by the core: it resolves
/// `geoip:…` / `geosite:…` against exactly these, next to the binary.
pub const GEOIP: &str = "geoip.dat";
pub const GEOSITE: &str = "geosite.dat";

/// Smallest plausible dat file. The real ones are megabytes; anything this
/// small is a GitHub error page, an HTML redirect or a truncated transfer that
/// happened to return 200. Cheap guard against writing garbage over a working
/// rule set.
const MIN_DAT_BYTES: u64 = 64 * 1024;

/// Refuse absurdly large bodies rather than filling the disk on a bad URL.
const MAX_DAT_BYTES: u64 = 128 * 1024 * 1024;

/// A named pair of URLs. Kept in code, not in the DB: the repositories move
/// their asset paths from time to time, and a corrected path should arrive
/// with a panel release rather than needing every operator to re-enter it.
/// The DB stores only which id was chosen.
pub struct GeoSource {
    pub id: &'static str,
    pub geoip: &'static str,
    pub geosite: &'static str,
}

/// `xray` is not listed: it is the absence of a source — the files are
/// whatever the release archive installed, and "refresh" there means
/// reinstalling the core.
pub const SOURCES: &[GeoSource] = &[
    GeoSource {
        id: "loyalsoldier",
        geoip: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
        geosite: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
    },
    GeoSource {
        id: "runet",
        geoip: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat",
        geosite: "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat",
    },
    GeoSource {
        id: "v2fly",
        geoip: "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
        geosite: "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
    },
];

/// Resolve the two URLs for a stored choice. `custom` takes them from the
/// operator's own fields; `xray` has none by definition.
pub fn urls_for(
    source: &str,
    custom_geoip: &str,
    custom_geosite: &str,
) -> anyhow::Result<(String, String)> {
    if source == "custom" {
        let (ip, site) = (custom_geoip.trim(), custom_geosite.trim());
        if ip.is_empty() || site.is_empty() {
            bail!("custom geofile source needs both a geoip.dat and a geosite.dat URL");
        }
        for u in [ip, site] {
            if !(u.starts_with("https://") || u.starts_with("http://")) {
                bail!("geofile URL must start with http:// or https://: {u}");
            }
        }
        return Ok((ip.to_owned(), site.to_owned()));
    }
    let src = SOURCES
        .iter()
        .find(|s| s.id == source)
        .with_context(|| format!("unknown geofile source '{source}'"))?;
    Ok((src.geoip.to_owned(), src.geosite.to_owned()))
}

/// What one file on disk looks like right now. `sha256` is computed from the
/// bytes, not remembered — a file replaced by hand outside the panel still
/// reports the truth.
#[derive(Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/geofiles.ts")]
pub struct GeoFileStatus {
    pub name: String,
    pub present: bool,
    #[ts(type = "number")]
    pub size_bytes: u64,
    /// RFC 3339, or empty when the file is missing.
    pub modified_at: String,
    /// Full lowercase hex; the UI shows a prefix.
    pub sha256: String,
}

/// Read both files' current state. A missing file is reported, not an error:
/// "you have never installed xray" is a legitimate state the UI must render.
pub async fn status(install_dir: &Path) -> Vec<GeoFileStatus> {
    let mut out = Vec::with_capacity(2);
    for name in [GEOIP, GEOSITE] {
        out.push(status_one(&install_dir.join(name), name).await);
    }
    out
}

async fn status_one(path: &Path, name: &str) -> GeoFileStatus {
    let Ok(meta) = tokio::fs::metadata(path).await else {
        return GeoFileStatus {
            name: name.to_owned(),
            present: false,
            size_bytes: 0,
            modified_at: String::new(),
            sha256: String::new(),
        };
    };
    let modified_at = meta
        .modified()
        .ok()
        .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
        .unwrap_or_default();
    GeoFileStatus {
        name: name.to_owned(),
        present: true,
        size_bytes: meta.len(),
        modified_at,
        sha256: sha256_file(path).await.unwrap_or_default(),
    }
}

/// Hash a file without holding it in memory — these are tens of megabytes and
/// the panel runs on boxes where that matters.
async fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut f = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

/// Outcome of refreshing one file.
#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../frontend/src/api/types/geofiles.ts")]
pub struct GeoFileOutcome {
    pub name: String,
    /// False when the downloaded bytes hashed identically to what is already
    /// on disk — the common case on a daily check, and the reason a refresh
    /// does not restart xray every night.
    pub changed: bool,
    #[ts(type = "number")]
    pub size_bytes: u64,
    pub sha256: String,
}

/// Fetch both files and hash them, WITHOUT touching the disk.
///
/// Split from the write on purpose. Downloading is the slow, failure-prone
/// half (two ~20 MB transfers from someone else's CDN); writing is fast and
/// local. Doing them in one pass meant a failure on the second file left the
/// first already renamed into place — geoip from the new source, geosite from
/// the old, with none of the bookkeeping recorded. It also meant holding the
/// caller's xray lock for the whole transfer.
pub async fn fetch(geoip_url: &str, geosite_url: &str) -> anyhow::Result<Vec<GeoFetched>> {
    let mut out = Vec::with_capacity(2);
    for (name, url) in [(GEOIP, geoip_url), (GEOSITE, geosite_url)] {
        let bytes = download(url)
            .await
            .with_context(|| format!("{name} from {url}"))?;
        if (bytes.len() as u64) < MIN_DAT_BYTES {
            bail!(
                "{name}: downloaded {} bytes — too small to be a geo database (expected at least {MIN_DAT_BYTES})",
                bytes.len()
            );
        }
        let sha256 = hex_lower(&Sha256::digest(&bytes));
        out.push(GeoFetched {
            name: name.to_owned(),
            bytes,
            sha256,
        });
    }
    Ok(out)
}

/// A downloaded file held in memory, not yet on disk.
pub struct GeoFetched {
    pub name: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// Write the fetched files that actually differ from what is on disk.
///
/// By the time this runs both transfers have succeeded, so the only failures
/// left are local and rare — which is what makes "geoip written, geosite not"
/// an acceptable residue rather than the routine outcome it was before.
pub async fn apply(
    install_dir: &Path,
    fetched: &[GeoFetched],
) -> anyhow::Result<Vec<GeoFileOutcome>> {
    tokio::fs::create_dir_all(install_dir)
        .await
        .with_context(|| format!("create {}", install_dir.display()))?;
    let mut out = Vec::with_capacity(fetched.len());
    for f in fetched {
        out.push(write_one(install_dir, f).await?);
    }
    Ok(out)
}

async fn write_one(install_dir: &Path, f: &GeoFetched) -> anyhow::Result<GeoFileOutcome> {
    let (name, bytes, sha) = (f.name.as_str(), &f.bytes, f.sha256.clone());
    let dest = install_dir.join(name);

    // The comparison that makes a daily check free: identical bytes mean the
    // file on disk is already this exact release, so leave it alone — no
    // write, no changed mtime, no restart.
    if let Ok(existing) = sha256_file(&dest).await
        && existing == sha
    {
        return Ok(GeoFileOutcome {
            name: name.to_owned(),
            changed: false,
            size_bytes: bytes.len() as u64,
            sha256: sha,
        });
    }

    // Land it beside the target first: xray maps these at startup, and a
    // torn write would leave the panel with a rule set that cannot load.
    let tmp = install_dir.join(format!(".{name}.partial"));
    tokio::fs::write(&tmp, &bytes)
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    if let Err(e) = tokio::fs::rename(&tmp, &dest).await {
        tokio::fs::remove_file(&tmp).await.ok();
        return Err(anyhow::Error::new(e)).with_context(|| format!("replace {}", dest.display()));
    }
    tracing::info!(
        "geofile updated: {} ({} bytes)",
        dest.display(),
        bytes.len()
    );
    Ok(GeoFileOutcome {
        name: name.to_owned(),
        changed: true,
        size_bytes: bytes.len() as u64,
        sha256: sha,
    })
}

async fn download(url: &str) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent(crate::xray::installer::USER_AGENT)
        // Generous: these are tens of megabytes and some mirrors are slow.
        .timeout(std::time::Duration::from_mins(5))
        .build()
        .context("build http client")?;
    let resp = client.get(url).send().await.context("request")?;
    let status = resp.status();
    if !status.is_success() {
        bail!("source returned {status}");
    }
    // Trust the header only to refuse early; the real guard is the length of
    // what actually arrived, checked by the caller.
    if let Some(len) = resp.content_length()
        && len > MAX_DAT_BYTES
    {
        bail!("source advertises {len} bytes, over the {MAX_DAT_BYTES} limit");
    }
    let bytes = resp.bytes().await.context("read body")?;
    if bytes.len() as u64 > MAX_DAT_BYTES {
        bail!(
            "body is {} bytes, over the {MAX_DAT_BYTES} limit",
            bytes.len()
        );
    }
    Ok(bytes.to_vec())
}

/// Where the geofiles live for a given xray binary — they sit next to it,
/// which is where the core looks unless `XRAY_LOCATION_ASSET` says otherwise.
pub fn dir_for_binary(binary: &Path) -> PathBuf {
    binary
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

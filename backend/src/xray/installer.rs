//! Downloads xray-core releases from GitHub and unpacks them into the panel's
//! data directory. Used both for first-run auto-install and the in-UI version
//! switcher.

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};
use std::{
    io::Cursor,
    path::{Path, PathBuf},
};
use ts_rs::TS;

const GITHUB_RELEASES: &str = "https://api.github.com/repos/XTLS/Xray-core/releases";
const USER_AGENT: &str = concat!("panel/", env!("CARGO_PKG_VERSION"));

/// One row in the "Обновления Xray" modal — what the UI needs per version.
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "../../frontend/src/api/types/stats.ts")]
pub struct XrayRelease {
    pub tag: String,
    pub published_at: String,
    pub prerelease: bool,
    /// Direct download URL of the asset matching the host platform, if any.
    /// `None` means this release has no build for the current OS/arch.
    pub asset_url: Option<String>,
    // Same trick as SystemStats: keep number on the JS side — release archives
    // are tens of MB, well within JS-safe int range.
    #[ts(type = "number | null")]
    pub asset_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    published_at: String,
    prerelease: bool,
    draft: bool,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Returns the asset filename xray ships for the current host. Bails on
/// architectures we don't know how to map — better than silently downloading
/// the wrong build.
pub fn current_asset_name() -> anyhow::Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "Xray-windows-64.zip",
        ("windows", "x86") => "Xray-windows-32.zip",
        ("windows", "aarch64") => "Xray-windows-arm64-v8a.zip",
        ("linux", "x86_64") => "Xray-linux-64.zip",
        ("linux", "x86") => "Xray-linux-32.zip",
        ("linux", "aarch64") => "Xray-linux-arm64-v8a.zip",
        ("macos", "x86_64") => "Xray-macos-64.zip",
        ("macos", "aarch64") => "Xray-macos-arm64-v8a.zip",
        (os, arch) => anyhow::bail!("no xray prebuilt for {os}/{arch}"),
    })
}

/// Filename of the xray binary as it appears inside the release zip and on disk.
pub const fn binary_name() -> &'static str {
    if cfg!(windows) { "xray.exe" } else { "xray" }
}

/// Where the panel stores xray + geofiles. Resolves to `<install_root>/xray`.
pub fn default_install_dir(install_root: &Path) -> PathBuf {
    install_root.join("xray")
}

fn http() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(std::time::Duration::from_mins(1))
        .build()
        .context("build http client")
}

/// Fetch the most recent N releases from GitHub. Filters out drafts; flags
/// prereleases so the UI can hide them by default.
pub async fn fetch_releases(limit: u32) -> anyhow::Result<Vec<XrayRelease>> {
    let client = http()?;
    let url = format!("{GITHUB_RELEASES}?per_page={limit}");
    let resp = client.get(&url).send().await.context("github request")?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("github returned {status}: {body}");
    }
    let raw: Vec<GhRelease> = resp.json().await.context("decode github releases")?;
    let want_asset = current_asset_name().ok();

    Ok(raw
        .into_iter()
        .filter(|r| !r.draft)
        .map(|r| {
            let asset = want_asset.and_then(|name| r.assets.iter().find(|a| a.name == name));
            XrayRelease {
                tag: r.tag_name,
                published_at: r.published_at,
                prerelease: r.prerelease,
                asset_url: asset.map(|a| a.browser_download_url.clone()),
                asset_size: asset.map(|a| a.size),
            }
        })
        .collect())
}

/// Resolve the latest non-prerelease tag, regardless of how many we want to
/// expose in the UI. Used by first-run bootstrap.
pub async fn fetch_latest_stable() -> anyhow::Result<XrayRelease> {
    let client = http()?;
    let resp = client
        .get(format!("{GITHUB_RELEASES}/latest"))
        .send()
        .await
        .context("github latest")?;
    if !resp.status().is_success() {
        anyhow::bail!("github returned {} for latest release", resp.status());
    }
    let r: GhRelease = resp.json().await.context("decode github latest")?;
    let want = current_asset_name()?;
    let asset = r
        .assets
        .iter()
        .find(|a| a.name == want)
        .ok_or_else(|| anyhow!("latest release {} has no asset {}", r.tag_name, want))?;
    Ok(XrayRelease {
        tag: r.tag_name,
        published_at: r.published_at,
        prerelease: r.prerelease,
        asset_url: Some(asset.browser_download_url.clone()),
        asset_size: Some(asset.size),
    })
}

/// Download the release zip into memory, extract xray + geofiles into
/// `install_dir`, mark the binary executable on Unix. Atomic-ish: we extract
/// to a sibling dir first, then swap files in place.
pub async fn install_release(release: &XrayRelease, install_dir: &Path) -> anyhow::Result<()> {
    let asset_url = release
        .asset_url
        .as_ref()
        .ok_or_else(|| anyhow!("release {} has no asset for this platform", release.tag))?;

    tokio::fs::create_dir_all(install_dir)
        .await
        .with_context(|| format!("create {}", install_dir.display()))?;

    tracing::info!("downloading xray {} from {}", release.tag, asset_url);
    let client = http()?;
    let bytes = client
        .get(asset_url)
        .send()
        .await
        .context("download xray asset")?
        .error_for_status()
        .context("github asset download status")?
        .bytes()
        .await
        .context("read xray asset body")?;

    let install_dir = install_dir.to_path_buf();
    let bin_name = binary_name().to_string();

    // zip crate is sync — push the unpack to a blocking thread so we don't
    // stall the runtime during extraction of ~30MB of dat files.
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("open zip archive")?;
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).context("read zip entry")?;
            let name = entry.name().to_string();
            // Reject any entry whose name contains a path separator or parent
            // ref — guards against zip-slip even if the matching list below
            // is later broadened. The official xray release archives ship
            // their payload at the archive root, so this loses nothing.
            if name.contains('/') || name.contains('\\') || name.contains("..") {
                continue;
            }
            // Only extract files we actually need; skip LICENSE/README/etc.
            let want = name == bin_name || name == "geoip.dat" || name == "geosite.dat";
            if !want || entry.is_dir() {
                continue;
            }
            let dest = install_dir.join(&name);
            let tmp = install_dir.join(format!(".{name}.partial"));
            {
                let mut out = std::fs::File::create(&tmp)
                    .with_context(|| format!("create {}", tmp.display()))?;
                std::io::copy(&mut entry, &mut out)
                    .with_context(|| format!("write {}", tmp.display()))?;
            }
            // On Windows we can't rename onto a running .exe — but xray is
            // stopped before install so this is fine.
            if dest.exists() {
                std::fs::remove_file(&dest).ok();
            }
            std::fs::rename(&tmp, &dest)
                .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;

            #[cfg(unix)]
            if name == bin_name {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dest)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dest, perms)?;
            }
            tracing::info!("installed {}", dest.display());
        }
        Ok(())
    })
    .await
    .context("zip extract task")??;
    Ok(())
}

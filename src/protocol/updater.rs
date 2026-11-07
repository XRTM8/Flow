//! Explicit, verified updates from the official GitHub release.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "windows")]
use std::path::PathBuf;
use std::time::Duration;
#[cfg(target_os = "windows")]
use tokio::io::AsyncWriteExt;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GITHUB_RELEASES_API: &str = "https://api.github.com/repos/XRTM8/Flow/releases/latest";
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_PACKAGE: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    #[serde(default)]
    pub digest: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub name: Option<String>,
    pub html_url: String,
    pub assets: Vec<GitHubAsset>,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
}
#[derive(Debug, Clone)]
pub struct AvailableUpdate {
    pub version: String,
    pub tag_name: String,
    pub download_url: String,
    pub asset_name: String,
    pub asset_size: u64,
    pub sha256: String,
    pub is_setup: bool,
    pub release_notes_url: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateTarget {
    WindowsInstalled,
    WindowsPortable,
    AndroidArm64,
    AndroidX86_64,
    Unsupported,
}
#[derive(Debug, Clone, Copy)]
pub enum UpdateOutcome {
    Restarting,
    InstallerOpened,
}
fn version_parts(version: &str) -> Option<[u32; 3]> {
    let value = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version);
    let pieces: Vec<_> = value.split('.').collect();
    if pieces.len() != 3
        || pieces
            .iter()
            .any(|p| p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()))
    {
        return None;
    }
    Some([
        pieces[0].parse().ok()?,
        pieces[1].parse().ok()?,
        pieces[2].parse().ok()?,
    ])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn is_newer_version(current: &str, remote: &str) -> bool {
    match (version_parts(current), version_parts(remote)) {
        (Some(current), Some(remote)) => remote > current,
        _ => false,
    }
}
pub fn current_target() -> UpdateTarget {
    #[cfg(target_os = "windows")]
    {
        if crate::update_windows::is_installed() {
            UpdateTarget::WindowsInstalled
        } else {
            UpdateTarget::WindowsPortable
        }
    }
    #[cfg(all(target_os = "android", target_arch = "aarch64"))]
    {
        UpdateTarget::AndroidArm64
    }
    #[cfg(all(target_os = "android", target_arch = "x86_64"))]
    {
        UpdateTarget::AndroidX86_64
    }
    #[cfg(not(any(
        target_os = "windows",
        all(
            target_os = "android",
            any(target_arch = "aarch64", target_arch = "x86_64")
        )
    )))]
    {
        UpdateTarget::Unsupported
    }
}
fn package_url_valid(url: &str, tag: &str, name: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(url) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == format!("/XRTM8/Flow/releases/download/{tag}/{name}")
}
pub fn select_update(
    release: &GitHubRelease,
    current: &str,
    target: UpdateTarget,
) -> Result<Option<AvailableUpdate>, String> {
    if release.draft || release.prerelease || !is_newer_version(current, &release.tag_name) {
        return Ok(None);
    }
    let version = release.tag_name.trim_start_matches(['v', 'V']);
    let names = match target {
        UpdateTarget::WindowsInstalled => vec![format!("OtiumFlow-v{version}-Setup-x64.exe")],
        UpdateTarget::WindowsPortable => vec![format!("OtiumFlow-v{version}-Portable-x64.exe")],
        UpdateTarget::AndroidArm64 => vec![
            format!("otium-flow-v{version}-arm64-v8a.apk"),
            format!("otium-flow-v{version}-universal.apk"),
        ],
        UpdateTarget::AndroidX86_64 => vec![
            format!("otium-flow-v{version}-x86_64.apk"),
            format!("otium-flow-v{version}-universal.apk"),
        ],
        UpdateTarget::Unsupported => {
            return Err("In-app updates are not supported on this platform.".into())
        }
    };
    let asset = names
        .iter()
        .find_map(|name| release.assets.iter().find(|asset| &asset.name == name))
        .ok_or("This release has no update package compatible with this installation.")?;
    let sha256 = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()))
        .ok_or("GitHub has not provided a SHA-256 digest for this package. Try again later.")?
        .to_ascii_lowercase();
    if asset.size == 0
        || asset.size > MAX_PACKAGE
        || !package_url_valid(&asset.browser_download_url, &release.tag_name, &asset.name)
    {
        return Err("The update package metadata is invalid.".into());
    }
    Ok(Some(AvailableUpdate {
        version: version.into(),
        tag_name: release.tag_name.clone(),
        download_url: asset.browser_download_url.clone(),
        asset_name: asset.name.clone(),
        asset_size: asset.size,
        sha256,
        is_setup: target == UpdateTarget::WindowsInstalled,
        release_notes_url: release.html_url.clone(),
    }))
}
fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("OtiumFlow/", env!("CARGO_PKG_VERSION")))
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let host = attempt.url().host_str().unwrap_or("");
            let allowed = host == "github.com"
                || host == "api.github.com"
                || host == "release-assets.githubusercontent.com"
                || host == "objects.githubusercontent.com";
            if attempt.previous().len() < 5 && attempt.url().scheme() == "https" && allowed {
                attempt.follow()
            } else {
                attempt.error("Unexpected update redirect")
            }
        }))
        .build()
        .map_err(|e| format!("Cannot initialize secure update connection: {e}"))
}
pub async fn check_latest_release() -> Result<Option<AvailableUpdate>, String> {
    check_latest_release_for(CURRENT_VERSION, current_target()).await
}
pub async fn check_latest_release_for(
    current: &str,
    target: UpdateTarget,
) -> Result<Option<AvailableUpdate>, String> {
    let mut response = client()?
        .get(GITHUB_RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| {
            format!("Cannot check for updates. Check your internet connection and retry: {e}")
        })?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if body.len() as u64 + chunk.len() as u64 > MAX_MANIFEST {
            return Err("Release metadata is too large.".into());
        }
        body.extend_from_slice(&chunk);
    }
    let release: GitHubRelease =
        serde_json::from_slice(&body).map_err(|_| "GitHub returned invalid release metadata.")?;
    select_update(&release, current, target)
}
/// Revalidate a stored selection before download; never trust a filename as a path.
fn validate_selection(update: &AvailableUpdate) -> Result<(), String> {
    let release = GitHubRelease {
        tag_name: update.tag_name.clone(),
        name: None,
        html_url: update.release_notes_url.clone(),
        assets: vec![GitHubAsset {
            name: update.asset_name.clone(),
            browser_download_url: update.download_url.clone(),
            size: update.asset_size,
            digest: Some(format!("sha256:{}", update.sha256)),
        }],
        draft: false,
        prerelease: false,
    };
    let selected = select_update(&release, CURRENT_VERSION, current_target())?
        .ok_or("This update is no longer newer than the running version.")?;
    if selected.is_setup != update.is_setup {
        return Err("Update installation type changed. Check for updates again.".into());
    }
    Ok(())
}
#[cfg(target_os = "windows")]
async fn download_verified(update: &AvailableUpdate) -> Result<PathBuf, String> {
    let directory = crate::platform::app_data_dir()?
        .join("updates")
        .join(uuid::Uuid::new_v4().to_string());
    tokio::fs::create_dir_all(&directory)
        .await
        .map_err(|e| e.to_string())?;
    let path = directory.join(&update.asset_name);
    let result = async {
        let mut response = client()?
            .get(&update.download_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| format!("Update download failed: {e}"))?;
        if response
            .content_length()
            .is_some_and(|length| length != update.asset_size)
        {
            return Err("Update download size does not match GitHub metadata.".into());
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        let mut bytes = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            bytes = bytes
                .checked_add(chunk.len() as u64)
                .ok_or("Update is too large.")?;
            if bytes > update.asset_size {
                return Err("Update download exceeded the expected size.".into());
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        file.sync_all().await.map_err(|e| e.to_string())?;
        if bytes != update.asset_size || hex(&hasher.finalize()) != update.sha256 {
            return Err(
                "Update verification failed. The installed application was not changed.".into(),
            );
        }
        Ok(path.clone())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&path).await;
        let _ = tokio::fs::remove_dir(&directory).await;
    }
    result
}
/// Shared verifier also used for native Android DownloadManager output.
pub fn verify_package(
    reader: &mut impl std::io::Read,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(), String> {
    let mut hash = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or("Package is too large.")?;
        if length > expected_size || length > MAX_PACKAGE {
            return Err("Downloaded package size is invalid.".into());
        }
        hash.update(&buffer[..count]);
    }
    if length != expected_size || hex(&hash.finalize()) != expected_hash.to_ascii_lowercase() {
        return Err("Downloaded package failed SHA-256 verification. It was not installed.".into());
    }
    Ok(())
}
pub async fn apply_update_in_place(update: &AvailableUpdate) -> Result<UpdateOutcome, String> {
    validate_selection(update)?;
    #[cfg(target_os = "windows")]
    {
        let path = download_verified(update).await?;
        let is_setup = update.is_setup;
        let handoff_path = path.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::update_windows::apply_verified(&handoff_path, is_setup)
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|result| result);
        // The helper owns a separate staged copy after accepting the handoff.
        let _ = tokio::fs::remove_file(&path).await;
        if let Some(directory) = path.parent() {
            let _ = tokio::fs::remove_dir(directory).await;
        }
        result?;
        Ok(UpdateOutcome::Restarting)
    }
    #[cfg(target_os = "android")]
    {
        let update = update.clone();
        tokio::task::spawn_blocking(move || crate::update_android::apply_update(&update))
            .await
            .map_err(|e| e.to_string())??;
        Ok(UpdateOutcome::InstallerOpened)
    }
    #[cfg(not(any(target_os = "windows", target_os = "android")))]
    {
        Err("In-app installation is not supported on this platform.".into())
    }
}
pub fn cleanup_old_executables() {
    #[cfg(target_os = "windows")]
    crate::update_windows::cleanup_old_executables();
}
pub fn run_helper_if_requested() -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        crate::update_windows::run_helper_if_requested()
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> GitHubRelease {
        let tag = "v9.8.7";
        let names = [
            "otium-flow-v9.8.7-arm64-v8a.apk",
            "OtiumFlow-v9.8.7-Setup-x64.exe",
            "otium-flow-v9.8.7-universal.apk",
            "OtiumFlow-v9.8.7-Portable-x64.exe",
        ];
        GitHubRelease {
            tag_name: tag.into(),
            name: None,
            html_url: format!("https://github.com/XRTM8/Flow/releases/tag/{tag}"),
            draft: false,
            prerelease: false,
            assets: names
                .into_iter()
                .map(|name| GitHubAsset {
                    name: name.into(),
                    browser_download_url: format!(
                        "https://github.com/XRTM8/Flow/releases/download/{tag}/{name}"
                    ),
                    size: 100,
                    digest: Some(format!("sha256:{}", "a".repeat(64))),
                })
                .collect(),
        }
    }
    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("v2.4.2", "v2.4.3"));
        assert!(is_newer_version("2.9.9", "2.10.0"));
        for remote in ["2.4.2", "2.4.1", "2.4.3-beta", "bad.9.8", "2.4", "2..5"] {
            assert!(!is_newer_version("2.4.2", remote));
        }
    }
    #[test]
    fn packages_match_installation_type_and_android_abi() {
        let release = release();
        for (target, suffix) in [
            (UpdateTarget::WindowsInstalled, "Setup-x64.exe"),
            (UpdateTarget::WindowsPortable, "Portable-x64.exe"),
            (UpdateTarget::AndroidArm64, "arm64-v8a.apk"),
            (UpdateTarget::AndroidX86_64, "universal.apk"),
        ] {
            assert!(select_update(&release, "2.4.2", target)
                .unwrap()
                .unwrap()
                .asset_name
                .ends_with(suffix));
        }
        let mut missing = release.clone();
        missing.assets.retain(|asset| !asset.name.contains("Setup"));
        assert!(select_update(&missing, "2.4.2", UpdateTarget::WindowsInstalled).is_err());
    }
    #[test]
    fn rejects_unverified_foreign_or_incompatible_packages() {
        for case in 0..4 {
            let mut release = release();
            let asset = release
                .assets
                .iter_mut()
                .find(|a| a.name.contains("Portable"))
                .unwrap();
            match case {
                0 => asset.digest = None,
                1 => {
                    asset.browser_download_url = asset
                        .browser_download_url
                        .replace("github.com", "example.com")
                }
                2 => asset.name = "../update.exe".into(),
                _ => asset.size = MAX_PACKAGE + 1,
            }
            assert!(select_update(&release, "2.4.2", UpdateTarget::WindowsPortable).is_err());
        }
        let mut release = release();
        release.prerelease = true;
        assert!(
            select_update(&release, "2.4.2", UpdateTarget::WindowsPortable)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn verification_rejects_tampering_truncation_and_extra_bytes() {
        let bytes = b"verified update";
        let digest = hex(&Sha256::digest(bytes));
        assert!(verify_package(&mut &bytes[..], bytes.len() as u64, &digest).is_ok());
        assert!(verify_package(&mut &b"tampered update"[..], bytes.len() as u64, &digest).is_err());
        assert!(verify_package(&mut &bytes[..3], bytes.len() as u64, &digest).is_err());
        assert!(verify_package(&mut &bytes[..], 3, &digest).is_err());
    }
}

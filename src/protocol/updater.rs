//! وحدة التحديث التلقائي الذكي الصامت لتطبيق FLOW by Otium
//! تدعم التحقق التلقائي من إصدارات GitHub الرسمية (XRTM8/Flow)
//! واستبدال الملفات التنفيذية أثناء التشغيل بدون تضارب حزم (Zero-Collision Self-Update)

use serde::{Deserialize, Serialize};

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GITHUB_RELEASES_API: &str = "https://api.github.com/repos/XRTM8/Flow/releases/latest";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub name: Option<String>,
    pub html_url: String,
    pub assets: Vec<GitHubAsset>,
}

#[derive(Debug, Clone)]
pub struct AvailableUpdate {
    pub version: String,
    pub tag_name: String,
    pub download_url: String,
    pub asset_name: String,
    pub is_setup: bool,
    pub release_notes_url: String,
}

/// مقارنة رقمين من إصدارات SemVer
pub fn is_newer_version(current: &str, remote: &str) -> bool {
    let clean_current = current.trim_start_matches('v').trim_start_matches('V');
    let clean_remote = remote.trim_start_matches('v').trim_start_matches('V');

    let cur_parts: Vec<u32> = clean_current
        .split('.')
        .filter_map(|s| s.split('-').next().unwrap_or("").parse().ok())
        .collect();
    let rem_parts: Vec<u32> = clean_remote
        .split('.')
        .filter_map(|s| s.split('-').next().unwrap_or("").parse().ok())
        .collect();

    for i in 0..3 {
        let c = cur_parts.get(i).copied().unwrap_or(0);
        let r = rem_parts.get(i).copied().unwrap_or(0);
        if r > c {
            return true;
        } else if r < c {
            return false;
        }
    }
    false
}

/// فحص وجود إصدار جديد عبر GitHub API
pub async fn check_latest_release(
) -> Result<Option<AvailableUpdate>, Box<dyn std::error::Error + Send + Sync>> {
    tokio::task::spawn_blocking(|| {
        #[cfg(target_os = "windows")]
        {
            let output = match std::process::Command::new("curl.exe")
                .args([
                    "-s",
                    "-H",
                    "User-Agent: Otium-Flow-AutoUpdater",
                    "-H",
                    "Accept: application/vnd.github.v3+json",
                    "--max-time",
                    "8",
                    GITHUB_RELEASES_API,
                ])
                .output()
            {
                Ok(out) => out,
                Err(_) => return Ok(None),
            };

            if !output.status.success() {
                return Ok(None);
            }

            let body = String::from_utf8_lossy(&output.stdout);
            let release: GitHubRelease = match serde_json::from_str(&body) {
                Ok(r) => r,
                Err(_) => return Ok(None),
            };

            if is_newer_version(CURRENT_VERSION, &release.tag_name) {
                // اختيار الحزمة المناسبة لبيئة التشغيل
                let current_exe = std::env::current_exe().unwrap_or_default();
                let is_in_program_files = current_exe.to_string_lossy().contains("Program Files");

                // البحث عن مثبت الإعداد (Setup) أو النسخة المحمولة (Portable)
                let chosen_asset = if is_in_program_files {
                    release
                        .assets
                        .iter()
                        .find(|a| {
                            a.name.ends_with(".exe") && a.name.to_lowercase().contains("setup")
                        })
                        .or_else(|| release.assets.iter().find(|a| a.name.ends_with(".exe")))
                } else {
                    release
                        .assets
                        .iter()
                        .find(|a| {
                            a.name.ends_with(".exe")
                                && (a.name.to_lowercase().contains("portable")
                                    || !a.name.to_lowercase().contains("setup"))
                        })
                        .or_else(|| release.assets.iter().find(|a| a.name.ends_with(".exe")))
                };

                if let Some(asset) = chosen_asset {
                    let is_setup = asset.name.to_lowercase().contains("setup");
                    return Ok(Some(AvailableUpdate {
                        version: release.tag_name.clone(),
                        tag_name: release.tag_name,
                        download_url: asset.browser_download_url.clone(),
                        asset_name: asset.name.clone(),
                        is_setup,
                        release_notes_url: release.html_url,
                    }));
                }
            }
        }

        #[cfg(target_os = "android")]
        {
            let output = std::process::Command::new("curl")
                .args([
                    "-s",
                    "-H",
                    "User-Agent: Otium-Flow-AutoUpdater",
                    GITHUB_RELEASES_API,
                ])
                .output();

            if let Ok(out) = output {
                let body = String::from_utf8_lossy(&out.stdout);
                if let Ok(release) = serde_json::from_str::<GitHubRelease>(&body) {
                    if is_newer_version(CURRENT_VERSION, &release.tag_name) {
                        if let Some(apk_asset) =
                            release.assets.iter().find(|a| a.name.ends_with(".apk"))
                        {
                            return Ok(Some(AvailableUpdate {
                                version: release.tag_name.clone(),
                                tag_name: release.tag_name,
                                download_url: apk_asset.browser_download_url.clone(),
                                asset_name: apk_asset.name.clone(),
                                is_setup: false,
                                release_notes_url: release.html_url,
                            }));
                        }
                    }
                }
            }
        }

        Ok(None)
    })
    .await?
}

/// تنزيل وتطبيق التحديث بسلاسة بدون تضارب حزم (Zero-Collision In-Place Upgrade)
pub async fn apply_update_in_place(
    update: &AvailableUpdate,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let update_clone = update.clone();
    tokio::task::spawn_blocking(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let temp_dir = std::env::temp_dir().join("OtiumFlowUpdate");
            let _ = std::fs::create_dir_all(&temp_dir);
            let target_file = temp_dir.join(&update_clone.asset_name);

            #[cfg(target_os = "windows")]
            {
                // 1. تنزيل الملف عبر curl
                let target_str = target_file.to_str().unwrap_or("update.exe");
                let dl_status = std::process::Command::new("curl.exe")
                    .args(["-L", "-s", "-o", target_str, &update_clone.download_url])
                    .status()?;

                if !dl_status.success() {
                    return Err("Failed to download update package".into());
                }

                if update_clone.is_setup {
                    // تشغيل المثبت الصامت مع إغلاق وإعادة فتح التطبيق تلقائياً
                    let _ = std::process::Command::new(&target_file)
                        .args(["/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"])
                        .spawn();
                    std::process::exit(0);
                } else {
                    // تحديث النسخة المحمولة (Self-Replacement Pattern)
                    let current_exe = std::env::current_exe()?;
                    let old_exe = current_exe.with_extension("exe.old");

                    // إعادة تسمية الملف التنفيذي الحالي للسماح باستبداله في نظام ويندوز
                    let _ = std::fs::remove_file(&old_exe);
                    std::fs::rename(&current_exe, &old_exe)?;
                    std::fs::copy(&target_file, &current_exe)?;

                    // تشغيل النسخة الجديدة وإغلاق الحالية
                    let _ = std::process::Command::new(&current_exe).spawn();
                    std::process::exit(0);
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                let _ = target_file;
                Ok(())
            }
        },
    )
    .await?
}

/// تنظيف أي مخلفات قديمة (.exe.old) عند بدء تشغيل التطبيق
pub fn cleanup_old_executables() {
    if let Ok(current_exe) = std::env::current_exe() {
        let old_exe = current_exe.with_extension("exe.old");
        if old_exe.exists() {
            let _ = std::fs::remove_file(old_exe);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("v2.0.0", "v2.0.1"));
        assert!(is_newer_version("2.0.0", "2.1.0"));
        assert!(is_newer_version("v2.0.0", "v3.0.0"));
        assert!(!is_newer_version("v2.0.1", "v2.0.0"));
        assert!(!is_newer_version("v2.0.0", "v2.0.0"));
    }
}

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub lang: String,
    pub dark_mode: bool,
    pub clean_links: bool,
    pub auto_copy: bool,
    pub selected_peer_id: Option<String>,
    pub selected_peer_name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: "EN".into(),
            dark_mode: true,
            clean_links: true,
            auto_copy: false,
            selected_peer_id: None,
            selected_peer_name: String::new(),
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Self {
        std::fs::read(dir.join("settings.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let target = dir.join("settings.json");
        let temp: PathBuf = dir.join(format!("settings.{}.tmp", uuid::Uuid::new_v4()));
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&temp, bytes).map_err(|e| e.to_string())?;
        if let Err(e) = std::fs::rename(&temp, target) {
            let _ = std::fs::remove_file(temp);
            return Err(e.to_string());
        }
        Ok(())
    }
}

pub fn tr<'a>(arabic: bool, en: &'a str, ar: &'a str) -> &'a str {
    if arabic {
        ar
    } else {
        en
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings_preserve_language_and_target() {
        let dir = std::env::temp_dir().join(format!("flow-settings-{}", uuid::Uuid::new_v4()));
        let s = Settings {
            lang: "AR".into(),
            selected_peer_id: Some("chosen-device".into()),
            ..Default::default()
        };
        s.save(&dir).unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.lang, "AR");
        assert_eq!(loaded.selected_peer_id.as_deref(), Some("chosen-device"));
        assert!(!loaded.auto_copy);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

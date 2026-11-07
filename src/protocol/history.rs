use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, path::PathBuf};
use tokio::sync::RwLock;

const MAX_HISTORY_ITEMS: usize = 200;
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HistoryKind {
    Clipboard,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub kind: HistoryKind,
    pub title: String,
    pub subtitle: String,
    pub timestamp_secs: u64,
    pub success: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub peer_id: String,
    #[serde(default)]
    pub peer_name: String,
    #[serde(default)]
    pub direction: String,
}
impl HistoryEntry {
    pub fn new(kind: HistoryKind, title: String, subtitle: String, success: bool) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            title,
            subtitle,
            success,
            timestamp_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            path: None,
            text: None,
            peer_id: String::new(),
            peer_name: String::new(),
            direction: String::new(),
        }
    }
}
pub struct HistoryManager {
    file_path: Option<PathBuf>,
    entries: RwLock<VecDeque<HistoryEntry>>,
}
impl HistoryManager {
    pub fn new() -> Self {
        Self {
            file_path: None,
            entries: RwLock::new(VecDeque::new()),
        }
    }
    pub fn with_storage(storage_dir: PathBuf) -> Self {
        let file_path = storage_dir.join("history.json");
        let mut entries: VecDeque<HistoryEntry> = std::fs::read(&file_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        entries.truncate(MAX_HISTORY_ITEMS);
        Self {
            file_path: Some(file_path),
            entries: RwLock::new(entries),
        }
    }
    fn persist(&self, entries: &VecDeque<HistoryEntry>) -> Result<(), String> {
        let Some(path) = &self.file_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let temp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        std::fs::write(
            &temp,
            serde_json::to_vec(entries).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        std::fs::rename(&temp, path).map_err(|e| {
            let _ = std::fs::remove_file(temp);
            e.to_string()
        })
    }
    pub async fn record(&self, entry: HistoryEntry) -> Result<(), String> {
        let mut entries = self.entries.write().await;
        entries.push_front(entry);
        entries.truncate(MAX_HISTORY_ITEMS);
        self.persist(&entries)
    }
    pub async fn add_entry(
        &self,
        kind: HistoryKind,
        title: String,
        subtitle: String,
        success: bool,
    ) {
        let _ = self
            .record(HistoryEntry::new(kind, title, subtitle, success))
            .await;
    }
    pub async fn get_all(&self) -> Vec<HistoryEntry> {
        self.entries.read().await.iter().cloned().collect()
    }
    pub async fn find(&self, id: &str) -> Option<HistoryEntry> {
        self.entries
            .read()
            .await
            .iter()
            .find(|e| e.id == id)
            .cloned()
    }
    pub async fn clear(&self) -> Result<(), String> {
        let mut entries = self.entries.write().await;
        self.persist(&VecDeque::new())?;
        entries.clear();
        Ok(())
    }
}
impl Default for HistoryManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn history_migrates_and_preserves_actions() {
        let dir = std::env::temp_dir().join(format!("flow-history-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("history.json"), r#"[{"id":"old","kind":"File","title":"old.txt","subtitle":"Received","timestamp_secs":1,"success":true}]"#).unwrap();
        let h = HistoryManager::with_storage(dir.clone());
        assert_eq!(h.get_all().await[0].path, None);
        let mut e = HistoryEntry::new(
            HistoryKind::Clipboard,
            "message".into(),
            "received".into(),
            true,
        );
        e.text = Some("full text".into());
        h.record(e).await.unwrap();
        let reopened = HistoryManager::with_storage(dir.clone());
        assert_eq!(
            reopened.get_all().await[0].text.as_deref(),
            Some("full text")
        );
        reopened.clear().await.unwrap();
        assert!(HistoryManager::with_storage(dir.clone())
            .get_all()
            .await
            .is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}

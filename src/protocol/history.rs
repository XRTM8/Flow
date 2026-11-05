use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

const MAX_HISTORY_ITEMS: usize = 25;

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
}

pub struct HistoryManager {
    file_path: Option<PathBuf>,
    entries: Arc<RwLock<VecDeque<HistoryEntry>>>,
}

impl HistoryManager {
    pub fn new() -> Self {
        Self {
            file_path: None,
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_HISTORY_ITEMS))),
        }
    }

    /// إنشاء مدير سجل نشاطات مع حفظ مستمر في القرص
    pub fn with_storage(storage_dir: PathBuf) -> Self {
        let file_path = storage_dir.join("history.json");
        let initial_entries = if let Ok(content) = std::fs::read_to_string(&file_path) {
            serde_json::from_str::<VecDeque<HistoryEntry>>(&content).unwrap_or_else(|_| VecDeque::with_capacity(MAX_HISTORY_ITEMS))
        } else {
            VecDeque::with_capacity(MAX_HISTORY_ITEMS)
        };

        Self {
            file_path: Some(file_path),
            entries: Arc::new(RwLock::new(initial_entries)),
        }
    }

    fn save_to_disk(&self, entries: &VecDeque<HistoryEntry>) {
        if let Some(path) = &self.file_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(serialized) = serde_json::to_string_pretty(entries) {
                // حفظ ذري عبر ملف مؤقت ثم Rename لضمان عدم تلف السجل عند انقطاع الطاقة
                let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
                if std::fs::write(&tmp_path, serialized).is_ok() {
                    let _ = std::fs::rename(&tmp_path, path);
                }
            }
        }
    }

    pub async fn add_entry(&self, kind: HistoryKind, title: String, subtitle: String, success: bool) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = HistoryEntry {
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            title,
            subtitle,
            timestamp_secs: now,
            success,
        };

        let mut entries = self.entries.write().await;
        if entries.len() >= MAX_HISTORY_ITEMS {
            entries.pop_back();
        }
        entries.push_front(entry);
        self.save_to_disk(&entries);
    }

    pub async fn get_all(&self) -> Vec<HistoryEntry> {
        let entries = self.entries.read().await;
        entries.iter().cloned().collect()
    }

    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
        self.save_to_disk(&entries);
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
    async fn test_history_limit_and_order() {
        let history = HistoryManager::new();

        for i in 0..30 {
            history.add_entry(HistoryKind::File, format!("file_{}.txt", i), "1 MB".to_string(), true).await;
        }

        let items = history.get_all().await;
        // التأكد من عدم تجاوز الحد الأقصى
        assert_eq!(items.len(), MAX_HISTORY_ITEMS);
        // التأكد من أن أحدث عنصر هو في المقدمة
        assert_eq!(items[0].title, "file_29.txt");

        history.clear().await;
        assert_eq!(history.get_all().await.len(), 0);
    }

    #[tokio::test]
    async fn test_history_disk_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("flow_hist_test_{}", uuid::Uuid::new_v4()));
        let history1 = HistoryManager::with_storage(temp_dir.clone());
        history1.add_entry(HistoryKind::File, "contract.pdf".to_string(), "2 MB".to_string(), true).await;

        // محاكاة إعادة فتح التطبيق واسترجاع السجل من القرص
        let history2 = HistoryManager::with_storage(temp_dir.clone());
        let items = history2.get_all().await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "contract.pdf");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

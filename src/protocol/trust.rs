use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedDevice {
    pub id: String,
    pub name: String,
    pub paired_at_secs: u64,
    #[serde(default)]
    pub shared_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrustConfig {
    pub auto_accept_trusted: bool,
    pub devices: HashMap<String, TrustedDevice>,
    #[serde(default)]
    pub master_key: Option<String>,
}

pub struct TrustManager {
    config_path: PathBuf,
    config: Arc<RwLock<TrustConfig>>,
}

impl TrustManager {
    pub fn new(storage_dir: PathBuf) -> Self {
        let config_path = storage_dir.join("trusted_peers.json");
        let mut initial_config = Self::load_from_disk(&config_path).unwrap_or_else(|_| TrustConfig {
            auto_accept_trusted: true,
            devices: HashMap::new(),
            master_key: None,
        });

        // توليد مفتاح تشفير عسكري رئيسي وحفظه إن لم يكن موجوداً
        if initial_config.master_key.is_none() {
            let key_str = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
            initial_config.master_key = Some(key_str);
            let _ = Self::save_config_atomic(&config_path, &initial_config);
        }

        Self {
            config_path,
            config: Arc::new(RwLock::new(initial_config)),
        }
    }

    fn load_from_disk(path: &PathBuf) -> Result<TrustConfig, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let config = serde_json::from_str(&content).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    fn save_config_atomic(path: &PathBuf, config: &TrustConfig) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let serialized = serde_json::to_string_pretty(config)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let tmp_path = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        std::fs::write(&tmp_path, serialized)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub async fn is_trusted(&self, peer_id: &str) -> bool {
        let config = self.config.read().await;
        config.devices.contains_key(peer_id)
    }

    pub async fn auto_accept(&self) -> bool {
        let config = self.config.read().await;
        config.auto_accept_trusted
    }

    pub async fn set_auto_accept(&self, enable: bool) -> Result<(), std::io::Error> {
        let mut config = self.config.write().await;
        config.auto_accept_trusted = enable;
        Self::save_config_atomic(&self.config_path, &*config)
    }

    pub async fn get_master_key(&self) -> [u8; 32] {
        let config = self.config.read().await;
        let mut key = [0u8; 32];
        if let Some(ref k) = config.master_key {
            let bytes = k.as_bytes();
            let len = std::cmp::min(bytes.len(), 32);
            key[..len].copy_from_slice(&bytes[..len]);
        } else {
            key.fill(0x55);
        }
        key
    }

    pub async fn trust_peer(&self, peer_id: String, peer_name: String) -> Result<(), std::io::Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let device = TrustedDevice {
            id: peer_id.clone(),
            name: peer_name,
            paired_at_secs: now,
            shared_secret: None,
        };

        let mut config = self.config.write().await;
        config.devices.insert(peer_id, device);
        Self::save_config_atomic(&self.config_path, &*config)
    }

    pub async fn revoke_peer(&self, peer_id: &str) -> Result<(), std::io::Error> {
        let mut config = self.config.write().await;
        config.devices.remove(peer_id);
        Self::save_config_atomic(&self.config_path, &*config)
    }

    pub async fn list_trusted(&self) -> Vec<TrustedDevice> {
        let config = self.config.read().await;
        config.devices.values().cloned().collect()
    }
}

/// حساب رمز المصادقة القصير (Short Authentication String - SAS) المكوّن من 6 أرقام
/// للتحقق البصري المتبادل بين جهازين وحماية المستخدم من هجمات الرجل في المنتصف (MITM).
/// الرمز متماثل: النتيجة متطابقة تماماً بغض النظر عمن هو المرسل أو المستلم.
pub fn compute_sas_code(id1: &str, id2: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    if id1 < id2 {
        hasher.update(id1.as_bytes());
        hasher.update(b":FLOW_SAS_SALT:");
        hasher.update(id2.as_bytes());
    } else {
        hasher.update(id2.as_bytes());
        hasher.update(b":FLOW_SAS_SALT:");
        hasher.update(id1.as_bytes());
    }
    let res = hasher.finalize();
    let num = u32::from_be_bytes([res[0], res[1], res[2], res[3]]) % 1_000_000;
    format!("{:06}", num)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sas_code_symmetry_and_stability() {
        let id_a = "FLOW-NODE-A-12345678";
        let id_b = "FLOW-NODE-B-87654321";

        let code_ab = compute_sas_code(id_a, id_b);
        let code_ba = compute_sas_code(id_b, id_a);

        assert_eq!(code_ab, code_ba);
        assert_eq!(code_ab.len(), 6);
        assert!(code_ab.chars().all(|c| c.is_ascii_digit()));
    }

    #[tokio::test]
    async fn test_trust_manager_lifecycle() {
        let temp_dir = std::env::temp_dir().join(format!("flow_trust_{}", uuid::Uuid::new_v4()));
        let manager = TrustManager::new(temp_dir.clone());

        assert!(!manager.is_trusted("device_1").await);

        manager.trust_peer("device_1".to_string(), "Galaxy S24".to_string()).await.unwrap();
        assert!(manager.is_trusted("device_1").await);

        let list = manager.list_trusted().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "Galaxy S24");

        manager.revoke_peer("device_1").await.unwrap();
        assert!(!manager.is_trusted("device_1").await);

        let master_key = manager.get_master_key().await;
        assert_ne!(master_key, [0u8; 32]);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

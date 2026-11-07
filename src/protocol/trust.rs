//! Explicit, out-of-band pairing. Discovery identifiers are never encryption keys.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
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
    #[serde(default)]
    pub devices: HashMap<String, TrustedDevice>,
    #[serde(default)]
    pub master_key: Option<String>,
}

pub struct TrustManager {
    config_path: PathBuf,
    config: RwLock<TrustConfig>,
    self_id: String,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Copy/pasted codes accept whitespace and letter case, never short numeric PINs.
pub fn normalize_pairing_code(code: &str) -> io::Result<String> {
    let normalized: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if normalized.len() != 64 || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(
            "Enter the complete 64-character pairing code from the other device",
        ));
    }
    Ok(normalized.to_ascii_lowercase())
}

fn random_code() -> String {
    let mut hash = Sha256::new();
    hash.update(uuid::Uuid::new_v4().as_bytes());
    hash.update(uuid::Uuid::new_v4().as_bytes());
    hash.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

impl TrustManager {
    pub fn new(storage_dir: PathBuf) -> Self {
        Self::with_self_id(storage_dir, uuid::Uuid::new_v4().to_string())
    }

    /// Compatibility constructor. Applications should use the fallible constructor.
    pub fn with_self_id(storage_dir: PathBuf, self_id: String) -> Self {
        Self::try_with_self_id(storage_dir, self_id)
            .expect("Unable to load private pairing configuration")
    }

    pub fn try_with_self_id(storage_dir: PathBuf, self_id: String) -> io::Result<Self> {
        let config_path = storage_dir.join("trusted_peers.json");
        let mut config = match std::fs::read(&config_path) {
            Ok(bytes) => serde_json::from_slice::<TrustConfig>(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => TrustConfig::default(),
            Err(e) => return Err(e),
        };
        if config
            .master_key
            .as_deref()
            .and_then(|v| normalize_pairing_code(v).ok())
            .is_none()
        {
            config.master_key = Some(random_code());
            config.devices.clear();
        }
        // Versions before protocol 3 recorded trust without exchanging a secret.
        config.devices.retain(|_, device| {
            device
                .shared_secret
                .as_deref()
                .and_then(|v| normalize_pairing_code(v).ok())
                .is_some()
        });
        Self::save_config_atomic(&config_path, &config)?;
        Ok(Self {
            config_path,
            config: RwLock::new(config),
            self_id,
        })
    }

    fn save_config_atomic(path: &Path, config: &TrustConfig) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec_pretty(config).map_err(io::Error::other)?;
        let temporary = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            use std::io::Write;
            let mut file = options.open(&temporary)?;
            file.write_all(&data)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    pub async fn pairing_code(&self) -> String {
        self.config
            .read()
            .await
            .master_key
            .clone()
            .unwrap_or_default()
    }

    pub async fn is_trusted(&self, peer_id: &str) -> bool {
        self.config
            .read()
            .await
            .devices
            .get(peer_id)
            .and_then(|device| device.shared_secret.as_ref())
            .is_some()
    }

    pub async fn trust_peer_with_secret(
        &self,
        peer_id: String,
        name: String,
        remote_code: &str,
    ) -> io::Result<()> {
        if peer_id == self.self_id || uuid::Uuid::parse_str(&peer_id).is_err() {
            return Err(invalid("Select a valid nearby device before pairing"));
        }
        let secret = normalize_pairing_code(remote_code)?;
        let mut config = self.config.write().await;
        if config.master_key.as_ref() == Some(&secret) {
            return Err(invalid(
                "Enter the other device's code, not this device's code",
            ));
        }
        let device = TrustedDevice {
            id: peer_id.clone(),
            name: name.chars().take(80).collect(),
            paired_at_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            shared_secret: Some(secret),
        };
        let mut next = config.clone();
        next.devices.insert(peer_id, device);
        Self::save_config_atomic(&self.config_path, &next)?;
        *config = next;
        Ok(())
    }

    /// Both ends must exchange their codes. The combined PSK binds both device IDs.
    pub async fn get_key_for_peer(&self, peer_id: &str) -> io::Result<[u8; 32]> {
        let config = self.config.read().await;
        let remote = config
            .devices
            .get(peer_id)
            .and_then(|d| d.shared_secret.as_deref())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Pair this device on both screens before sending",
                )
            })?;
        let local = config
            .master_key
            .as_deref()
            .ok_or_else(|| invalid("Missing local pairing code"))?;
        let mut hash = Sha256::new();
        hash.update(b"FLOW-3-PAIRING\0");
        let pairs = if self.self_id.as_str() < peer_id {
            [(&self.self_id[..], local), (peer_id, remote)]
        } else {
            [(peer_id, remote), (&self.self_id[..], local)]
        };
        for (id, code) in pairs {
            hash.update((id.len() as u32).to_be_bytes());
            hash.update(id.as_bytes());
            hash.update(normalize_pairing_code(code)?.as_bytes());
        }
        Ok(hash.finalize().into())
    }

    pub async fn revoke_peer(&self, peer_id: &str) -> io::Result<()> {
        let mut config = self.config.write().await;
        let mut next = config.clone();
        next.devices.remove(peer_id);
        Self::save_config_atomic(&self.config_path, &next)?;
        *config = next;
        Ok(())
    }

    pub async fn list_trusted(&self) -> Vec<TrustedDevice> {
        let mut devices: Vec<_> = self.config.read().await.devices.values().cloned().collect();
        devices.sort_by(|a, b| a.name.cmp(&b.name));
        devices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_normalization_rejects_short_public_ids() {
        assert!(normalize_pairing_code("123456").is_err());
        assert!(normalize_pairing_code(&uuid::Uuid::new_v4().to_string()).is_err());
        assert!(normalize_pairing_code(&"z".repeat(64)).is_err());
        assert_eq!(
            normalize_pairing_code(&format!("  {}\n", "A".repeat(64))).unwrap(),
            "a".repeat(64)
        );
    }
    #[tokio::test]
    async fn mutual_secret_is_required_and_survives_reload() {
        let base = std::env::temp_dir().join(format!("flow-trust-{}", uuid::Uuid::new_v4()));
        let id_a = uuid::Uuid::new_v4().to_string();
        let id_b = uuid::Uuid::new_v4().to_string();
        let a = TrustManager::try_with_self_id(base.join("a"), id_a.clone()).unwrap();
        let b = TrustManager::try_with_self_id(base.join("b"), id_b.clone()).unwrap();
        assert!(a.get_key_for_peer(&id_b).await.is_err());
        a.trust_peer_with_secret(id_b.clone(), "B".into(), &b.pairing_code().await)
            .await
            .unwrap();
        b.trust_peer_with_secret(id_a.clone(), "A".into(), &a.pairing_code().await)
            .await
            .unwrap();
        assert_eq!(
            a.get_key_for_peer(&id_b).await.unwrap(),
            b.get_key_for_peer(&id_a).await.unwrap()
        );
        let reloaded = TrustManager::try_with_self_id(base.join("a"), id_a).unwrap();
        assert_eq!(a.pairing_code().await, reloaded.pairing_code().await);
        assert!(reloaded.is_trusted(&id_b).await);
        reloaded.revoke_peer(&id_b).await.unwrap();
        assert!(reloaded.get_key_for_peer(&id_b).await.is_err());
        let _ = std::fs::remove_dir_all(base);
    }
}

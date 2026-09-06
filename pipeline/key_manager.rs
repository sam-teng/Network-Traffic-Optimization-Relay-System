use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub type KeyId = u16;

#[derive(Debug)]
pub enum KeyError {
    KeyNotFound(KeyId),
    EmptyKeyring,
    InvalidKeyLength,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::KeyNotFound(id) => write!(f, "找不到指定的 Key ID: {}", id),
            KeyError::EmptyKeyring => write!(f, "金鑰環為空，無可用 Primary Key"),
            KeyError::InvalidKeyLength => write!(f, "金鑰長度不合規範 (需至少 16 位元組)"),
        }
    }
}

impl std::error::Error for KeyError {}

/// 動態輪替預共享金鑰 (PSK) 管理器
#[derive(Clone)]
pub struct DynamicKeyManager {
    primary_key_id: Arc<RwLock<KeyId>>,
    keyring: Arc<RwLock<HashMap<KeyId, Vec<u8>>>>,
}

impl DynamicKeyManager {
    /// 以初始預設金鑰建立 Key Manager
    pub fn new(initial_key_id: KeyId, initial_key: Vec<u8>) -> Self {
        let mut keys = HashMap::new();
        keys.insert(initial_key_id, initial_key);
        Self {
            primary_key_id: Arc::new(RwLock::new(initial_key_id)),
            keyring: Arc::new(RwLock::new(keys)),
        }
    }

    /// 取得目前的 Primary Key ID 與對應 PSK
    pub async fn get_primary_key(&self) -> (KeyId, Vec<u8>) {
        let kid = *self.primary_key_id.read().await;
        let ring = self.keyring.read().await;
        let key = ring.get(&kid).cloned().unwrap_or_default();
        (kid, key)
    }

    /// 依據 Key ID 獲取對應的 PSK
    pub async fn get_key_by_id(&self, key_id: KeyId) -> Option<Vec<u8>> {
        let ring = self.keyring.read().await;
        ring.get(&key_id).cloned()
    }

    /// 註冊或加入新的金鑰至金鑰環 (Keyring)
    pub async fn register_key(&self, key_id: KeyId, key: Vec<u8>) -> Result<(), KeyError> {
        if key.len() < 16 {
            return Err(KeyError::InvalidKeyLength);
        }
        let mut ring = self.keyring.write().await;
        ring.insert(key_id, key);
        Ok(())
    }

    /// 動態切換啟用新的 Primary Key ID
    pub async fn rotate_primary_key(&self, new_key_id: KeyId) -> Result<(), KeyError> {
        let ring = self.keyring.read().await;
        if !ring.contains_key(&new_key_id) {
            return Err(KeyError::KeyNotFound(new_key_id));
        }
        drop(ring);

        let mut primary = self.primary_key_id.write().await;
        *primary = new_key_id;
        Ok(())
    }

    /// 淘汰舊的過期金鑰 (不可移除目前的 Primary Key)
    pub async fn revoke_key(&self, key_id: KeyId) -> Result<(), KeyError> {
        let primary = *self.primary_key_id.read().await;
        if primary == key_id {
            return Err(KeyError::EmptyKeyring);
        }
        let mut ring = self.keyring.write().await;
        ring.remove(&key_id);
        Ok(())
    }
}

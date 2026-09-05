use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::pipeline::key_manager::{DynamicKeyManager, KeyError};

type HmacSha256 = Hmac<Sha256>;

const HANDSHAKE_HEADER_SIZE: usize = 56;
const NONCE_LEN: usize = 12;
const MAX_ALLOWED_TIME_DRIFT_SECS: u64 = 30;

pub struct NdCodeAuth;

impl NdCodeAuth {
    /// 用戶端：自動讀取當前 Primary Key ID 發送握手請求
    pub async fn client_handshake<S>(stream: &mut S, key_mgr: &DynamicKeyManager) -> Result<(), String>
    where
        S: AsyncWriteExt + Unpin,
    {
        let (key_id, primary_key) = key_mgr.get_primary_key().await;

        let mut nonce = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // HMAC 計算
        let mut mac = HmacSha256::new_from_slice(&primary_key).map_err(|e| e.to_string())?;
        mac.update(&key_id.to_be_bytes());
        mac.update(&nonce);
        mac.update(&timestamp.to_be_bytes());
        let signature = mac.finalize().into_bytes();

        // 封裝 56 位元組報頭
        let mut header = [0u8; HANDSHAKE_HEADER_SIZE];
        header[0..2].copy_from_slice(&key_id.to_be_bytes());
        header[2..4].copy_from_slice(&[0u8; 2]); // Reserved
        header[4..16].copy_from_slice(&nonce);
        header[16..24].copy_from_slice(&timestamp.to_be_bytes());
        header[24..56].copy_from_slice(&signature);

        stream.write_all(&header).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        Ok(())
    }

    /// 伺服器端：讀取 Header 中的 Key ID，比對 Keyring 中對應的金鑰
    pub async fn server_handshake<S>(stream: &mut S, key_mgr: &DynamicKeyManager) -> Result<(), String>
    where
        S: AsyncReadExt + Unpin,
    {
        let mut header = [0u8; HANDSHAKE_HEADER_SIZE];
        stream.read_exact(&mut header).await.map_err(|e| e.to_string())?;

        let key_id = u16::from_be_bytes([header[0], header[1]]);
        let nonce = &header[4..16];
        let timestamp_bytes = &header[16..24];
        let client_timestamp = u64::from_be_bytes(timestamp_bytes.try_into().unwrap());
        let received_signature = &header[24..56];

        // 1. 時間戳防重放檢查
        let current_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if current_ts.abs_diff(client_timestamp) > MAX_ALLOWED_TIME_DRIFT_SECS {
            return Err(format!("時間戳偏差過大: {} 秒", current_ts.abs_diff(client_timestamp)));
        }

        // 2. 依 Key ID 尋找對應的 PSK
        let psk = key_mgr
            .get_key_by_id(key_id)
            .await
            .ok_ok_or_else(|| format!("伺服器找不到對應 Key ID ({}) 的金鑰，驗證拒絕", key_id))?;

        // 3. 常數時間 HMAC 校驗
        let mut mac = HmacSha256::new_from_slice(&psk).map_err(|e| e.to_string())?;
        mac.update(&key_id.to_be_bytes());
        mac.update(nonce);
        mac.update(timestamp_bytes);

        mac.verify_slice(received_signature)
            .map_err(|_| "HMAC 簽名驗證失敗，金鑰不符或封包遭竄改".to_string())?;

        Ok(())
    }
}

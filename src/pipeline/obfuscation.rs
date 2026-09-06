use anyhow::{anyhow, Result};
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// 混淆區塊對齊大小 (例如 64 或 128 Bytes，消除特定協定特徵指紋)
pub const DEFAULT_ALIGN_BLOCK_SIZE: usize = 64;

/// 時間戳量化窗口大小 (以秒為單位，例如 5 秒區間量化防止重放同時容許微幅時間差)
pub const TIMESTAMP_QUANT_WINDOW_SECS: u64 = 5;

/// 動態 Padding 對齊與量化時間戳混淆模組
pub struct Obfuscator {
    block_size: usize,
}

impl Default for Obfuscator {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_ALIGN_BLOCK_SIZE,
        }
    }
}

impl Obfuscator {
    pub fn new(block_size: usize) -> Self {
        Self {
            block_size: if block_size == 0 { DEFAULT_ALIGN_BLOCK_SIZE } else { block_size },
        }
    }

    /// 取得當前量化時間戳 (以 5 秒為窗口階梯化)
    pub fn get_quantized_timestamp() -> u64 {
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now_sec / TIMESTAMP_QUANT_WINDOW_SECS
    }

    /// 驗證時間戳是否在容許窗口內 (預設容許前後 1 個量化窗口，即 ±5 秒)
    pub fn verify_quantized_timestamp(ts: u64, max_window_diff: u64) -> bool {
        let current = Self::get_quantized_timestamp();
        current.abs_diff(ts) <= max_window_diff
    }

    /// 混淆包裝 (Obfuscate Payload):
    /// 格式: [2-Byte 原始長度 (Big-Endian)] + [4-Byte 量化時間戳 (Big-Endian)] + [原始數據] + [隨機動態 Padding]
    /// 總長度向上對齊至 `block_size` 之整數倍
    pub fn obfuscate(&self, payload: &[u8]) -> Vec<u8> {
        let raw_len = payload.len();
        let header_len = 2 + 4; // 2 bytes length + 4 bytes quantized timestamp
        let total_content_len = header_len + raw_len;

        // 計算對齊至 block_size 所需的 Padding 長度
        let rem = total_content_len % self.block_size;
        let pad_len = if rem == 0 {
            0
        } else {
            self.block_size - rem
        };

        let mut output = Vec::with_capacity(total_content_len + pad_len);

        // 1. 寫入原始長度 (u16)
        output.extend_from_slice(&(raw_len as u16).to_be_bytes());

        // 2. 寫入 4 位元組量化時間戳 (u32 低位)
        let q_ts = (Self::get_quantized_timestamp() & 0xFFFFFFFF) as u32;
        output.extend_from_slice(&q_ts.to_be_bytes());

        // 3. 寫入原始資料
        output.extend_from_slice(payload);

        // 4. 填充密碼學隨機 Padding
        if pad_len > 0 {
            let mut pad_buf = vec![0u8; pad_len];
            rand::thread_rng().fill_bytes(&mut pad_buf);
            output.extend_from_slice(&pad_buf);
        }

        output
    }

    /// 解除混淆 (Deobfuscate Payload):
    /// 檢查量化時間戳並還原原始數據長度
    pub fn deobfuscate(&self, obfuscated_data: &[u8]) -> Result<Vec<u8>> {
        if obfuscated_data.len() < 6 {
            return Err(anyhow!("混淆資料長度不足 (至少需要 6 Bytes 標頭)"));
        }

        // 1. 讀取長度
        let raw_len = u16::from_be_bytes([obfuscated_data[0], obfuscated_data[1]]) as usize;

        // 2. 讀取量化時間戳
        let q_ts = u32::from_be_bytes([
            obfuscated_data[2],
            obfuscated_data[3],
            obfuscated_data[4],
            obfuscated_data[5],
        ]) as u64;

        // 3. 檢查時間戳窗口防重放 (容許 ±6 個量化窗口，約 30 秒)
        if !Self::verify_quantized_timestamp(q_ts, 6) {
            return Err(anyhow!("量化時間戳過期或異常，疑似重放攻擊"));
        }

        let total_required = 6 + raw_len;
        if obfuscated_data.len() < total_required {
            return Err(anyhow!(
                "混淆資料長度 ({}) 小於宣告的內容長度 ({})",
                obfuscated_data.len(),
                total_required
            ));
        }

        // 4. 提取原始有效載荷 (剔除 Padding)
        let original_data = &obfuscated_data[6..total_required];
        Ok(original_data.to_vec())
    }
}

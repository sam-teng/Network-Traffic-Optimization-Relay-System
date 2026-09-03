use anyhow::{anyhow, Context, Result};
use std::io::{Read, Write};

// 引用整合進來的 logic 模組
use NDcode3::logic::{
    NDCodeLogic, RaptorQEngine, MASTER_MAGIC_HEADER, safe_xz_decompress,
    NDcodePixelGrid,
};
use NDcode3::file_utils::{
    xz_compress,
};

/// 觸發 NDcode 3 編碼的封包門檻 (例如 1024 Bytes)
pub const NDCODE_PACKET_THRESHOLD: usize = 1024;

/// 傳輸協定封包標頭類別
#[repr(u8)]
pub enum PacketHeader {
    XzStream = 0x01,      // 小封包：純 XZ 串流
    NDcode3Stream = 0x03, // 大封包：NDcode 3 位元串流
}

pub struct NDcodeTunEngine {
    logic: NDCodeLogic,
}

impl NDcodeTunEngine {
    pub fn new() -> Self {
        Self {
            logic: NDCodeLogic::default(),
        }
    }

    /// 【傳送端】根據封包大小動態處理：超過門檻則使用 NDcode 3 編碼
    pub fn process_outgoing_packet(&self, raw_packet: &[u8]) -> Result<Vec<u8>> {
        if raw_packet.len() >= NDCODE_PACKET_THRESHOLD {
            // 1. 呼叫 NDCodeLogic 建構 Payload
            // 這裡設定單一 Chunk 尺寸為 512，直接使用內部 cascade 邏輯
            let l1_raptorq_bytes = self.build_ndcode3_payload(raw_packet, 512)?;

            // 2. 組合 MASTER_MAGIC_HEADER 與位元串流，直接輸出 
            let mut final_payload = Vec::with_capacity(1 + MASTER_MAGIC_HEADER.len() + l1_raptorq_bytes.len());
            final_payload.push(PacketHeader::NDcode3Stream as u8);
            final_payload.extend_from_slice(MASTER_MAGIC_HEADER);
            final_payload.extend_from_slice(&l1_raptorq_bytes);

            Ok(final_payload)
        } else {
            // 小封包：直接進行 XZ 壓縮
            let mut xz_buf = xz_compress(&raw_packet)?;

            let mut final_payload = Vec::with_capacity(1 + xz_buf.len());
            final_payload.push(PacketHeader::XzStream as u8);
            final_payload.extend_from_slice(&xz_buf);

            Ok(final_payload)
        }
    }

    /// 【接收端】解析接收到的 Payload 並完成解碼與資料還原
    pub fn process_incoming_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.is_empty() {
            return Err(anyhow!("收到空白數據包"));
        }

        let header = payload[0];
        let data = &payload[1..];

        match header {
            x if x == PacketHeader::NDcode3Stream as u8 => {
                // 1. 檢查並剝離 MASTER_MAGIC_HEADER (b"ND3:")
                if !data.starts_with(MASTER_MAGIC_HEADER) {
                    return Err(anyhow!("無效的 NDcode 3 Master 標頭"));
                }
                let raptorq_payload = &data[MASTER_MAGIC_HEADER.len()..];

                // 2. 執行解碼與還原
                self.decode_ndcode3_stream(raptorq_payload)
            }
            x if x == PacketHeader::XzStream as u8 => {
                // 小封包解壓縮
                safe_xz_decompress(data)
            }
            _ => Err(anyhow!("未知的封包標頭類別: {}", header)),
        }
    }

    /// 私有輔助函式：調用 logic.rs 中的 build_chained_cascade
    fn build_ndcode3_payload(&self, full_data: &[u8], target_chunk_size: usize) -> Result<Vec<u8>> {
        self.logic.build_chained_cascade(full_data, target_chunk_size)
    }

    /// 私有輔助函式：執行 RaptorQ 與 NDcode 3 連鎖還原
    fn decode_ndcode3_stream(&self, initial_raptorq_payload: &[u8]) -> Result<Vec<u8>> {
        self.logic.decode_ndcode3_stream(initial_raptorq_payload)
    }
}

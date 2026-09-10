use anyhow::{anyhow, Context, Result};
use crate::pipeline::streaming_compressor::decode_segment;

// 引用整合進來的 logic 模組 (統一傳輸入口)
use NDcode3::logic::{NDCodeLogic, TransportMedium, TransportOutput};

/// 觸發 NDcode 3 編碼的封包門檻 (例如 1024 Bytes)
pub const NDCODE_PACKET_THRESHOLD: usize = 1024;

/// 傳輸協定封包標頭類別
#[repr(u8)]
pub enum PacketHeader {
    XzStream = 0x01,      // 小封包：純 XZ 串流
    StreamedSegment = 0x02, // 串流段：下載流量邊接收邊壓縮 (Phase 2)
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

    /// 【傳送端】連線端自帶傳輸編碼：直接委派統一序列傳輸入口
    /// 小封包 (<1024) → [0x01] + XZ；大封包 (≥1024) → [0x03] + ND3: + (平行鏈)
    pub fn process_outgoing_packet(&self, raw_packet: &[u8]) -> Result<Vec<u8>> {
        match self.logic.create_transport_cascade(
            raw_packet,
            512,
            TransportMedium::Serial,
            |_, _, _| {},
        )? {
            TransportOutput::Serial(bytes) => Ok(bytes),
            other => Err(anyhow!(
                "連線端序列傳輸應產出 Serial 位元流，實際: {:?}",
                std::mem::discriminant(&other)
            )),
        }
    }

    /// 【接收端】連線端自帶傳輸解碼：依序列封包標頭自動分派 (XZ / ND3 平行鏈)
    pub fn process_incoming_payload(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.is_empty() {
            return Err(anyhow!("收到空白數據包"));
        }

        match payload[0] {
            x if x == PacketHeader::StreamedSegment as u8 => {
                // 串流段 (含 0x02 標頭)：走串流段協定解碼 (與序列傳輸解碼互斥分派)
                decode_segment(payload, Some(&self.logic)).context("串流段解碼失敗")
            }
            h => self.logic.decode_transport_serial(payload, |_: String| {}).context(format!(
                "序列傳輸解碼失敗 (標頭 0x{0:02X})",
                h
            )),
        }
    }
}

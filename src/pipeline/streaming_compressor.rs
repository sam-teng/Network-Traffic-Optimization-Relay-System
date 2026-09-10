// src/pipeline/streaming_compressor.rs - NDcode3 串流壓縮引擎 (純連線端)
//
// 直接引用 NDcode3 函式庫進行增量串流壓縮 / 解壓縮：
//   - XZ (低熵)      : NDcode3::file_utils::xz_compress / NDcode3::logic::safe_xz_decompress
//   - NDCODE3 (中高熵) : NDcode3::logic::NDCodeLogic::build_chained_cascade / decode_ndcode3_stream
//
// 串流段協定 (Streaming Segment Protocol)：
//   [STREAM_SEGMENT_HEADER (0x02)] [engine_tag (0x01/0x05)] [len_be u32] [encoded_bytes]
// 每段皆為自包含 (self-contained)，接收端可獨立解壓並依序重組。

use anyhow::{Context, Result};
use NDcode3::file_utils::{calculate_shannon_entropy, xz_compress};
use NDcode3::logic::{safe_xz_decompress, NDCodeLogic};

/// 串流段標頭 (對應 PacketHeader::StreamedSegment = 0x02)
pub const STREAM_SEGMENT_HEADER: u8 = 0x02;
/// 段內壓縮引擎標籤：XZ (LZMA2)
pub const ENGINE_TAG_XZ: u8 = 0x01;
/// 段內壓縮引擎標籤：NDcode3 連鎖級聯 (XZ + RaptorQ + 像素網格)
pub const ENGINE_TAG_NDCODE3: u8 = 0x05;

/// 預設串流 flush 門檻 (8KB)：達標即輸出一個壓縮段
pub const DEFAULT_FLUSH_THRESHOLD: usize = 8192;

/// 壓縮模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMode {
    /// 純 XZ 串流 (低延遲、高壓縮率，適合結構化下載)
    Xz,
    /// NDcode3 連鎖級聯 (中高熵：XZ → RaptorQ → 像素網格，抗遺失 + 高壓縮)
    Ndcode3,
    /// 依資料熵自動切換 (低熵 XZ，中高熵 NDCODE3)
    Adaptive,
    /// 不壓縮 (透傳)
    None,
}

/// 壓縮涵蓋範圍 (預留介面：全部流量壓縮將於最後階段實作)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionScope {
    /// 僅明文 HTTP 下載流 (Phase 2 預設)
    HttpOnly,
    /// HTTP + HTTPS 下載流
    HttpAndHttps,
    /// 全部流量皆須壓縮 (保留介面，最後實作)
    AllTraffic,
}

impl Default for CompressionScope {
    fn default() -> Self {
        CompressionScope::HttpOnly
    }
}

/// 壓縮器配置
#[derive(Debug, Clone)]
pub struct CompressorConfig {
    pub mode: CompressionMode,
    pub scope: CompressionScope,
    /// XZ 串流 flush 門檻 (Byte)
    pub flush_threshold: usize,
}

impl Default for CompressorConfig {
    fn default() -> Self {
        Self {
            mode: CompressionMode::Adaptive,
            scope: CompressionScope::HttpOnly,
            flush_threshold: DEFAULT_FLUSH_THRESHOLD,
        }
    }
}

impl CompressorConfig {
    /// CompressionMode::None 時全透傳，管線應走 legacy 路徑
    pub fn is_passthrough(&self) -> bool {
        matches!(self.mode, CompressionMode::None)
    }

    /// 該流量類別是否屬於當前壓縮範圍 (預留 AllTraffic 擴充點)
    pub fn in_scope(&self, class: crate::pipeline::traffic_classifier::TrafficClass) -> bool {
        use crate::pipeline::traffic_classifier::TrafficClass;
        match self.scope {
            CompressionScope::AllTraffic => true,
            CompressionScope::HttpAndHttps => class.compressible(),
            CompressionScope::HttpOnly => matches!(class, TrafficClass::Http),
        }
    }
}

/// 串流壓縮器 Trait
pub trait StreamingCompressor: Send {
    /// 壓縮一個資料塊。
    /// 回傳 0..N 個已封裝成「串流段」的 Payload。
    /// is_final = true 時強制 flush 尾段並清空緩衝。
    fn compress_chunk(&mut self, data: &[u8], is_final: bool) -> Result<Vec<Vec<u8>>>;

    /// 目前尚未 flush 的緩衝長度
    fn buffered_len(&self) -> usize;

    /// 估算壓縮率 (已輸出 / 已輸入)
    fn estimated_ratio(&self) -> f32;

    /// 重置會話狀態
    fn reset(&mut self);
}

// =============================================================================
// 串流段封包協定 (pack / unpack / decode)
// =============================================================================

/// 將單一引擎編碼結果包成串流段 Payload (含標頭)
pub fn pack_segment(engine_tag: u8, encoded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + encoded.len());
    out.push(STREAM_SEGMENT_HEADER);
    out.push(engine_tag);
    out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    out.extend_from_slice(encoded);
    out
}

/// 解析串流段 Payload → (engine_tag, encoded_bytes)
pub fn unpack_segment(payload: &[u8]) -> Result<(u8, &[u8])> {
    if payload.len() < 6 {
        return Err(anyhow::anyhow!("串流段 Payload 長度不足 ({})", payload.len()));
    }
    if payload[0] != STREAM_SEGMENT_HEADER {
        return Err(anyhow::anyhow!(
            "非串流段 Payload (標頭 0x{:02X})",
            payload[0]
        ));
    }
    let engine_tag = payload[1];
    let len = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]) as usize;
    if payload.len() != 6 + len {
        return Err(anyhow::anyhow!(
            "串流段長度不符 (宣告 {}B, 實際 {}B)",
            len,
            payload.len().saturating_sub(6)
        ));
    }
    Ok((engine_tag, &payload[6..]))
}

/// 直接解碼一個串流段 Payload → 原始 bytes
/// (需 NDCodeLogic 實例以支援 NDCODE3 連鎖級聯解碼)
pub fn decode_segment(payload: &[u8], logic: Option<&NDCodeLogic>) -> Result<Vec<u8>> {
    let (engine_tag, encoded) = unpack_segment(payload)?;
    match engine_tag {
        ENGINE_TAG_XZ => safe_xz_decompress(encoded),
        ENGINE_TAG_NDCODE3 => {
            let l = logic.context("NDCODE3 串流段需要 NDCodeLogic 實例")?;
            l.decode_ndcode3_stream(encoded)
                .context("NDcode3 連鎖級聯解碼失敗")
        }
        t => Err(anyhow::anyhow!("未知的串流段引擎標籤: 0x{:02X}", t)),
    }
}

/// 被動式解壓縮器：接收端依序餵入串流段即可還原資料流
pub struct StreamingDecompressor {
    logic: NDCodeLogic,
    total_decoded: u64,
}

impl StreamingDecompressor {
    pub fn new() -> Self {
        Self {
            logic: NDCodeLogic::default(),
            total_decoded: 0,
        }
    }

    /// 解壓單一串流段，追加還原的原始資料
    pub fn decompress_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let raw = decode_segment(payload, Some(&self.logic))?;
        self.total_decoded += raw.len() as u64;
        Ok(raw)
    }

    pub fn total_decoded(&self) -> u64 {
        self.total_decoded
    }

    pub fn reset(&mut self) {
        self.total_decoded = 0;
    }
}

// =============================================================================
// XZ 串流壓縮器 - 直接引用 NDcode3::file_utils::xz_compress
// =============================================================================

pub struct StreamingXzCompressor {
    buffer: Vec<u8>,
    flush_threshold: usize,
    total_input: u64,
    total_output: u64,
}

impl StreamingXzCompressor {
    pub fn new(flush_threshold: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(flush_threshold),
            flush_threshold,
            total_input: 0,
            total_output: 0,
        }
    }

    fn flush(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        if !self.buffer.is_empty() {
            let encoded = xz_compress(&self.buffer)?;
            self.total_output += encoded.len() as u64;
            out.push(pack_segment(ENGINE_TAG_XZ, &encoded));
            self.buffer.clear();
        }
        Ok(out)
    }
}

impl StreamingCompressor for StreamingXzCompressor {
    fn compress_chunk(&mut self, data: &[u8], is_final: bool) -> Result<Vec<Vec<u8>>> {
        self.total_input += data.len() as u64;
        self.buffer.extend_from_slice(data);

        if self.buffer.len() >= self.flush_threshold || is_final {
            self.flush()
        } else {
            Ok(Vec::new())
        }
    }

    fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    fn estimated_ratio(&self) -> f32 {
        if self.total_input == 0 {
            return 1.0;
        }
        self.total_output as f32 / self.total_input as f32
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.total_input = 0;
        self.total_output = 0;
    }
}

// =============================================================================
// NDcode3 連鎖級聯串流壓縮器
// 直接引用 NDcode3::logic::NDCodeLogic::build_chained_cascade
// =============================================================================

pub struct StreamingNdcode3Compressor {
    logic: NDCodeLogic,
    buffer: Vec<u8>,
    flush_threshold: usize,
    /// cascade 分塊大小 (壓縮後 chunk)
    cascade_chunk_size: usize,
    total_input: u64,
    total_output: u64,
}

impl StreamingNdcode3Compressor {
    pub fn new(flush_threshold: usize) -> Self {
        Self {
            logic: NDCodeLogic::default(),
            buffer: Vec::with_capacity(flush_threshold),
            flush_threshold,
            cascade_chunk_size: 512,
            total_input: 0,
            total_output: 0,
        }
    }

    fn flush(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        if !self.buffer.is_empty() {
            let cascade = self.logic
                .build_chained_cascade(&self.buffer, self.cascade_chunk_size)
                .context("NDcode3 連鎖級聯編碼失敗")?;
            self.total_output += cascade.len() as u64;
            out.push(pack_segment(ENGINE_TAG_NDCODE3, &cascade));
            self.buffer.clear();
        }
        Ok(out)
    }
}

impl StreamingCompressor for StreamingNdcode3Compressor {
    fn compress_chunk(&mut self, data: &[u8], is_final: bool) -> Result<Vec<Vec<u8>>> {
        self.total_input += data.len() as u64;
        self.buffer.extend_from_slice(data);

        if self.buffer.len() >= self.flush_threshold || is_final {
            self.flush()
        } else {
            Ok(Vec::new())
        }
    }

    fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    fn estimated_ratio(&self) -> f32 {
        if self.total_input == 0 {
            return 1.0;
        }
        self.total_output as f32 / self.total_input as f32
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.total_input = 0;
        self.total_output = 0;
    }
}

// =============================================================================
// 自適應串流壓縮器
// 依 Shannon 熵自動切換：
//   低熵 (≤5.0)   → XZ (LZMA2，純結構化文字壓縮)
//   中高熵 (>5.0)  → NDcode3::logic::build_chained_cascade (XZ+RaptorQ+像素網格級聯)
// =============================================================================

/// 低熵→中高熵切換門檻 (與 calculate_shannon_entropy 相同 f64 精度)
const ENTROPY_MEDIUM_THRESHOLD: f64 = 5.0;

pub struct AdaptiveStreamingCompressor {
    logic: NDCodeLogic,
    buffer: Vec<u8>,
    flush_threshold: usize,
    cascade_chunk_size: usize,
    total_input: u64,
    total_output_xz: u64,
    total_output_ndcode3: u64,
}

impl AdaptiveStreamingCompressor {
    pub fn new(flush_threshold: usize) -> Self {
        Self {
            logic: NDCodeLogic::default(),
            buffer: Vec::with_capacity(flush_threshold),
            flush_threshold,
            cascade_chunk_size: 512,
            total_input: 0,
            total_output_xz: 0,
            total_output_ndcode3: 0,
        }
    }

    fn flush(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        if !self.buffer.is_empty() {
            let entropy = calculate_shannon_entropy(&self.buffer);

            let (tag, encoded, is_ndcode3) = if entropy > ENTROPY_MEDIUM_THRESHOLD {
                // 中高熵：build_chained_cascade (XZ → 分塊 → RaptorQ → 像素網格級聯)
                let cascade = self.logic
                    .build_chained_cascade(&self.buffer, self.cascade_chunk_size)
                    .context("NDcode3 串流 flush 失敗")?;
                (ENGINE_TAG_NDCODE3, cascade, true)
            } else {
                // 低熵：純 XZ (LZMA2)
                let compressed = xz_compress(&self.buffer)?;
                (ENGINE_TAG_XZ, compressed, false)
            };

            if is_ndcode3 {
                self.total_output_ndcode3 += encoded.len() as u64;
            } else {
                self.total_output_xz += encoded.len() as u64;
            }
            out.push(pack_segment(tag, &encoded));
            self.buffer.clear();
        }
        Ok(out)
    }
}

impl StreamingCompressor for AdaptiveStreamingCompressor {
    fn compress_chunk(&mut self, data: &[u8], is_final: bool) -> Result<Vec<Vec<u8>>> {
        self.total_input += data.len() as u64;
        self.buffer.extend_from_slice(data);

        if self.buffer.len() >= self.flush_threshold || is_final {
            self.flush()
        } else {
            Ok(Vec::new())
        }
    }

    fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    fn estimated_ratio(&self) -> f32 {
        if self.total_input == 0 {
            return 1.0;
        }
        let total_output = self.total_output_xz + self.total_output_ndcode3;
        total_output as f32 / self.total_input as f32
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.total_input = 0;
        self.total_output_xz = 0;
        self.total_output_ndcode3 = 0;
    }
}

// =============================================================================
// 壓縮器工廠
// =============================================================================

pub struct CompressorFactory;

impl CompressorFactory {
    /// 依配置建立串流壓縮器
    pub fn create(config: &CompressorConfig) -> Result<Box<dyn StreamingCompressor>> {
        match config.mode {
            CompressionMode::Xz => Ok(Box::new(StreamingXzCompressor::new(
                config.flush_threshold,
            ))),
            CompressionMode::Ndcode3 => Ok(Box::new(StreamingNdcode3Compressor::new(
                config.flush_threshold,
            ))),
            CompressionMode::Adaptive => Ok(Box::new(AdaptiveStreamingCompressor::new(
                config.flush_threshold,
            ))),
            CompressionMode::None => Err(anyhow::anyhow!(
                "CompressionMode::None 不需建立壓縮器，請直接透傳"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payloads() -> Vec<Vec<u8>> {
        // 產生可壓縮的文言資料 (重複字串)，模擬 HTTP 下載體
        let base = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><body>";
        let mut chunks = Vec::new();
        let mut cur = Vec::new();
        for i in 0..40 {
            cur.extend_from_slice(base);
            cur.extend_from_slice(format!("<p>paragraph-{}</p>", i).as_bytes());
            if cur.len() >= 512 {
                chunks.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            chunks.push(cur);
        }
        chunks
    }

    #[test]
    fn test_xz_stream_roundtrip() {
        let mut compressor = StreamingXzCompressor::new(1024);
        let mut decompressor = StreamingDecompressor::new();
        let chunks = sample_payloads();
        let mut compressed_total = 0usize;

        let mut reconstructed = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_final = i == chunks.len() - 1;
            for seg in compressor.compress_chunk(chunk, is_final).unwrap() {
                compressed_total += seg.len();
                reconstructed.extend_from_slice(&decompressor.decompress_chunk(&seg).unwrap());
            }
        }

        let expected: Vec<u8> = chunks.concat();
        assert_eq!(reconstructed, expected);
        assert!(compressed_total < expected.len(), "XZ 串流應有壓縮效果");
        assert!(compressor.estimated_ratio() < 1.0);
    }

    #[test]
    fn test_ndcode3_stream_roundtrip() {
        let mut compressor = StreamingNdcode3Compressor::new(1024);
        let mut decompressor = StreamingDecompressor::new();
        let chunks = sample_payloads();

        let mut reconstructed = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_final = i == chunks.len() - 1;
            for seg in compressor.compress_chunk(chunk, is_final).unwrap() {
                reconstructed.extend_from_slice(&decompressor.decompress_chunk(&seg).unwrap());
            }
        }

        let expected: Vec<u8> = chunks.concat();
        assert_eq!(reconstructed, expected);
    }

    #[test]
    fn test_adaptive_stream_roundtrip() {
        let mut compressor = AdaptiveStreamingCompressor::new(2048);
        let mut decompressor = StreamingDecompressor::new();
        let chunks = sample_payloads();

        let mut reconstructed = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_final = i == chunks.len() - 1;
            for seg in compressor.compress_chunk(chunk, is_final).unwrap() {
                reconstructed.extend_from_slice(&decompressor.decompress_chunk(&seg).unwrap());
            }
        }

        let expected: Vec<u8> = chunks.concat();
        assert_eq!(reconstructed, expected);
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let packed = pack_segment(ENGINE_TAG_XZ, b"hello-ndcode3-streaming");
        let (tag, body) = unpack_segment(&packed).unwrap();
        assert_eq!(tag, ENGINE_TAG_XZ);
        assert_eq!(body, b"hello-ndcode3-streaming");
    }

    #[test]
    fn test_unpack_rejects_bad_header_and_trailing() {
        let mut packed = pack_segment(ENGINE_TAG_XZ, b"abc");
        assert!(unpack_segment(&packed[..3]).is_err()); // 過短
        packed[0] = 0xFF;
        assert!(unpack_segment(&packed).is_err()); // 錯誤標頭
        let mut trailing = pack_segment(ENGINE_TAG_XZ, b"abc");
        trailing.push(0x00);
        assert!(unpack_segment(&trailing).is_err()); // 尾端多餘位元組
    }

    #[test]
    fn test_config_scope() {
        use crate::pipeline::traffic_classifier::TrafficClass;

        let http_only = CompressorConfig {
            scope: CompressionScope::HttpOnly,
            ..Default::default()
        };
        assert!(http_only.in_scope(TrafficClass::Http));
        assert!(!http_only.in_scope(TrafficClass::Https));
        assert!(!http_only.in_scope(TrafficClass::Other));

        let all = CompressorConfig {
            scope: CompressionScope::AllTraffic,
            ..Default::default()
        };
        assert!(all.in_scope(TrafficClass::Other));
    }
}

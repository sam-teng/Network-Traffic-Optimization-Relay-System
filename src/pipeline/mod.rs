pub mod auth;
pub mod obfuscation;
pub mod key_manager;
pub mod gradient_mesh;
pub mod streaming_compressor;
pub mod traffic_classifier;

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use crate::ndcode_tun_engine::NDcodeTunEngine;
use crate::net_transport::{recv_framed_payload, send_framed_payload, TransportCodec};
pub use auth::NdCodeAuth;
pub use key_manager::DynamicKeyManager;
pub use obfuscation::Obfuscator;
pub use gradient_mesh::{GradientMeshEngine, GradientFeedbackPacket};
pub use streaming_compressor::{
    CompressorConfig, CompressorFactory, CompressionMode, StreamingCompressor,
    StreamingDecompressor, STREAM_SEGMENT_HEADER,
};
pub use traffic_classifier::{FlowKey, TrafficClassifier};

/// 管線 Channel 緩衝區容量
const PIPELINE_BUFFER_SIZE: usize = 1024;

pub struct NDcodePipeline;

impl NDcodePipeline {
    /// 啟動上行資料管線: TUN 讀取 ──> NDcode3 壓縮編碼 ──> 動態 Padding 混淆 ──> TCP 傳送
    pub async fn spawn_upstream_pipeline<R, W>(
        mut tun_reader: R,
        mut tcp_writer: W,
        engine: Arc<NDcodeTunEngine>,
        obfuscator: Arc<Obfuscator>,
        _mesh_engine: Arc<GradientMeshEngine>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (raw_tx, raw_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);
        let (proc_tx, mut proc_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);

        // Stage 1: Ingress Task (從 TUN 網卡擷取封包)
        let stage_ingress = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if raw_tx.send(buf[..n].to_vec()).await.is_err() {
                            break; // 管線下游關閉
                        }
                    }
                    _ => break,
                }
            }
        });

        // Stage 2: Processing Task (NDcode 3 噴泉碼/XZ 壓縮 + 混淆處理)
        let engine_proc = engine.clone();
        let obf_proc = obfuscator.clone();
        let mut raw_rx_stream = raw_rx;
        let stage_process = tokio::spawn(async move {
            while let Some(raw_packet) = raw_rx_stream.recv().await {
                if let Ok(compressed_payload) = engine_proc.process_outgoing_packet(&raw_packet) {
                    // 套用動態 Padding 與量化時間戳混淆
                    let obfuscated_payload = obf_proc.obfuscate(&compressed_payload);
                    if proc_tx.send(obfuscated_payload).await.is_err() {
                        break;
                    }
                }
            }
        });

        // Stage 3: Egress Task (將 Framing 封包寫入 TCP 串流)
        let stage_egress = tokio::spawn(async move {
            while let Some(payload) = proc_rx.recv().await {
                if send_framed_payload(&mut tcp_writer, &payload).await.is_err() {
                    break;
                }
            }
        });

        // 等待管線任一節點關閉
        let (res1, res2, res3) = tokio::join!(stage_ingress, stage_process, stage_egress);
        res1.context("stage_ingress panic")?;
        res2.context("stage_process panic")?;
        res3.context("stage_egress panic")?;
        Ok(())
    }

    /// 啟動下行資料管線: TCP 接收 ──> 解除混淆 ──> NDcode3 RaptorQ 解碼 ──> 梯度計算 ──> TUN 寫回
    pub async fn spawn_downstream_pipeline<R, W>(
        mut tcp_reader: R,
        mut tun_writer: W,
        engine: Arc<NDcodeTunEngine>,
        obfuscator: Arc<Obfuscator>,
        mesh_engine: Arc<GradientMeshEngine>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (compressed_tx, compressed_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);
        let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);

        // Stage 1: Ingress Task (從 TCP 接收長度前綴封包並解除混淆)
        let obf_ingress = obfuscator.clone();
        let mesh_ingress = mesh_engine.clone();
        let stage_ingress = tokio::spawn(async move {
            loop {
                match recv_framed_payload(&mut tcp_reader).await {
                    Ok(payload) => {
                        // 8-Byte 反向梯度封包：僅當 node_id 為已知 peer 才消費，避免誤吞正常流量
                        if payload.len() == 8 {
                            if let Some(feedback) = GradientFeedbackPacket::from_bytes(&payload) {
                                if mesh_ingress.get_peer_state(feedback.node_id).await.is_some() {
                                    mesh_ingress.apply_gradient_feedback(&feedback).await;
                                    continue;
                                }
                                // 未知 node_id：落入下方解混淆/解碼路徑
                            }
                        }

                        // 進行解混淆處理；時間戳失效(重放)直接丟棄，僅結構性錯誤才向下相容
                        match obf_ingress.deobfuscate(&payload) {
                            Ok(deobf) => {
                                if compressed_tx.send(deobf).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("時間戳") || msg.contains("重放") {
                                    eprintln!("⚠️ 下行混淆時間戳失效，丟棄: {}", e);
                                    continue;
                                }
                                if compressed_tx.send(payload).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Stage 2: Processing Task (RaptorQ 解碼與 XZ 還原)
        let engine_proc = engine.clone();
        let mut compressed_rx_stream = compressed_rx;
        let stage_process = tokio::spawn(async move {
            while let Some(payload) = compressed_rx_stream.recv().await {
                if let Ok(raw_packet) = engine_proc.process_incoming_payload(&payload) {
                    if raw_tx.send(raw_packet).await.is_err() {
                        break;
                    }
                }
            }
        });

        // Stage 3: Egress Task (將 IP 封包寫回 TUN 虛擬網卡)
        let stage_egress = tokio::spawn(async move {
            while let Some(raw_packet) = raw_rx.recv().await {
                if tun_writer.write_all(&raw_packet).await.is_err() {
                    break;
                }
            }
        });

        let (res1, res2, res3) = tokio::join!(stage_ingress, stage_process, stage_egress);
        res1.context("stage_ingress panic")?;
        res2.context("stage_process panic")?;
        res3.context("stage_egress panic")?;
        Ok(())
    }

    /// ⚡ 純連線端 (無需中繼伺服器) 上行管線：
    /// TUN ──> HTTP/HTTPS 流量識別 ──> NDcode3 串流壓縮 ──> 動態 Padding 混淆 ──> TCP
    ///
    /// 非壓縮範圍 (Other / DNS) 的封包維持原有 NDcodeTunEngine 單包壓縮方式透傳，
    /// 以確保遠端 (同樣以純連線端運行) 可還原。
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn_streaming_upstream_pipeline<R, W>(
        mut tun_reader: R,
        mut tcp_writer: W,
        engine: Arc<NDcodeTunEngine>,
        obfuscator: Arc<Obfuscator>,
        _mesh_engine: Arc<GradientMeshEngine>,
        mut classifier: TrafficClassifier,
        compressor_config: CompressorConfig,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (raw_tx, raw_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);
        let (proc_tx, mut proc_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);

        // Stage 1: Ingress Task (TUN 擷取原始 IP 封包)
        let stage_ingress = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if raw_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });

        // Stage 2: 串流壓縮 Processing Task
        //  - 依流量類別建立 per-flow StreamingCompressor
        //  - 達 flush 門檻 / TCP FIN 即輸出「串流段」，封裝後混淆送出
        //  - 非壓縮範圍流量走 legacy 單包壓縮 (向後相容)
        let engine_proc = engine.clone();
        let obf_proc = obfuscator.clone();
        let mut raw_rx_stream = raw_rx;
        let stage_process = tokio::spawn(async move {
            // 每個下載流 (FlowKey) 對應一個串流壓縮器
            let mut flows: HashMap<FlowKey, Box<dyn StreamingCompressor>> = HashMap::new();

            // CompressionMode::None = 全透傳 legacy 路徑，避免工廠 Err 造成 panic
            let streaming_enabled = compressor_config.mode != CompressionMode::None;

            while let Some(raw_packet) = raw_rx_stream.recv().await {
                // 單次解析：分類重用 ParsedPacket，不再二次 parse
                let parsed = classifier.parse(&raw_packet);
                let in_scope = match parsed {
                    Some(ref p) if streaming_enabled => {
                        let cls = classifier.classify_with_parsed(p);
                        compressor_config.in_scope(cls)
                    }
                    _ => false,
                };

                if in_scope {
                    let p = parsed.unwrap();
                    let key = FlowKey::from_parsed(&p);
                    let is_flow_end = p.tcp_flow_end;

                    let compressor = flows
                        .entry(key)
                        .or_insert_with(|| {
                            CompressorFactory::create(&compressor_config)
                                .expect("串流壓縮器建立失敗")
                        });

                    // 以 [len_be u16][完整 IP 封包] 的方式入流壓縮，
                    // 解壓端可依長度前綴逐一封包還原並寫回 TUN (Layer 3 語義不變)
                    let framed = frame_packet(&raw_packet);
                    match compressor.compress_chunk(&framed, is_flow_end) {
                        Ok(segments) => {
                            for seg in segments {
                                let obfuscated = obf_proc.obfuscate(&seg);
                                if proc_tx.send(obfuscated).await.is_err() {
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("⚠️ 串流壓縮失敗: {}", e);
                        }
                    }

                    // 流結束時釋放壓縮器 (後續新連線重新建立)
                    if is_flow_end {
                        flows.remove(&key);
                    }
                } else {
                    // 其他流量：沿用 NDcodeTunEngine 單包壓縮
                    if let Ok(compressed_payload) =
                        engine_proc.process_outgoing_packet(&raw_packet)
                    {
                        let obfuscated_payload = obf_proc.obfuscate(&compressed_payload);
                        if proc_tx.send(obfuscated_payload).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        // Stage 3: Egress Task (Framing 寫入 TCP)
        let stage_egress = tokio::spawn(async move {
            while let Some(payload) = proc_rx.recv().await {
                if send_framed_payload(&mut tcp_writer, &payload).await.is_err() {
                    break;
                }
            }
        });

        let (res1, res2, res3) = tokio::join!(stage_ingress, stage_process, stage_egress);
        res1.context("streaming stage_ingress panic")?;
        res2.context("streaming stage_process panic")?;
        res3.context("streaming stage_egress panic")?;
        Ok(())
    }

    /// ⚡ 純連線端 (無需中繼伺服器) 下行管線：
    /// TCP ──> 解除混淆 ──> [串流段] NDcode3 串流解壓縮 或 [legacy] 單包解碼 ──> TUN
    pub async fn spawn_streaming_downstream_pipeline<R, W>(
        mut tcp_reader: R,
        mut tun_writer: W,
        engine: Arc<NDcodeTunEngine>,
        obfuscator: Arc<Obfuscator>,
        mesh_engine: Arc<GradientMeshEngine>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);

        // Stage 1+2: Ingress + 解碼 (合併簡化)
        let obf_ingress = obfuscator.clone();
        let mesh_ingress = mesh_engine.clone();
        let engine_proc = engine.clone();
        let stage_process = tokio::spawn(async move {
            let mut decompressor = StreamingDecompressor::new();

            loop {
                match recv_framed_payload(&mut tcp_reader).await {
                    Ok(payload) => {
                        // 反向梯度控制封包 (8 Bytes)：僅已知 peer 才消費
                        if payload.len() == 8 {
                            if let Some(feedback) = GradientFeedbackPacket::from_bytes(&payload) {
                                if mesh_ingress.get_peer_state(feedback.node_id).await.is_some() {
                                    mesh_ingress.apply_gradient_feedback(&feedback).await;
                                    continue;
                                }
                            }
                        }

                        let deobf = match obf_ingress.deobfuscate(&payload) {
                            Ok(d) => d,
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("時間戳") || msg.contains("重放") {
                                    eprintln!("⚠️ 下行混淆時間戳失效，丟棄: {}", e);
                                    continue;
                                }
                                payload // 僅結構性錯誤向下相容
                            }
                        };

                        let decoded = if !deobf.is_empty() && deobf[0] == STREAM_SEGMENT_HEADER {
                            // NDcode3 串流段：邊接收邊解壓 → [len][封包]... 框架
                            decompressor.decompress_chunk(&deobf)
                        } else {
                            // legacy 單包 (XZ / NDcode3 RaptorQ 連鎖)
                            engine_proc.process_incoming_payload(&deobf)
                        };

                        let is_stream_segment =
                            !deobf.is_empty() && deobf[0] == STREAM_SEGMENT_HEADER;

                        match decoded {
                            Ok(bytes) => {
                                if is_stream_segment {
                                    // 依長度前綴拆回多個完整 IP 封包；跳過空包
                                    for pkt in unframe_packets(&bytes) {
                                        if pkt.is_empty() {
                                            continue;
                                        }
                                        if raw_tx.send(pkt).await.is_err() {
                                            return;
                                        }
                                    }
                                } else {
                                    if raw_tx.send(bytes).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("⚠️ 下行解碼失敗: {}", e);
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Stage 3: Egress Task (TUN 寫回)
        let stage_egress = tokio::spawn(async move {
            while let Some(raw_packet) = raw_rx.recv().await {
                if tun_writer.write_all(&raw_packet).await.is_err() {
                    break;
                }
            }
        });

        let (res1, res2) = tokio::join!(stage_process, stage_egress);
        res1.context("streaming stage_process panic")?;
        res2.context("streaming stage_egress panic")?;
        Ok(())
    }

    /// ⚡ 連線端自帶傳輸即編解碼 對稱管線:
    /// 上傳 (TUN → codec.write / 自動序列編碼 → TCP) 與
    /// 下載 (TCP → codec.read / 自動序列解碼 → TUN)
    /// 皆只透過同一個 TransportCodec，編解碼完全內建於連線端。
    ///
    /// 雙向共用同一條連線：內部用 tokio::io::split 拆分讀寫半部，
    /// 每一筆 IP 封包即一個自帶 XZ/ND3 標頭的獨立 frame，上傳下載同時運作。
    pub async fn spawn_self_transport_pipeline<R, W, S>(
        mut tun_reader: R,
        mut tun_writer: W,
        conn: S,
        engine: Arc<NDcodeTunEngine>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let codec = TransportCodec::new(conn, engine);
        let (mut reader_half, mut writer_half) = tokio::io::split(codec);

        // 上傳: TUN 讀取原始 IP 封包 → 連線端自動編碼 → 寫入 TCP
        // (65535 緩衝與下載對稱，保證單次 read 取得一整個 IP 封包，避免大封包被截斷)
        let stage_upload = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match tun_reader.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if writer_half.write_all(&buf[..n]).await.is_err() {
                            break; // TCP 關閉
                        }
                    }
                    _ => break,
                }
            }
        });

        // 下載: TCP 讀取 → 連線端自動解碼 → TUN 寫回完整封包
        // (65535 緩衝保證單次 read 即取得一整個 IP 封包，維持 Layer 3 語義)
        let stage_download = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            loop {
                match reader_half.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        if tun_writer.write_all(&buf[..n]).await.is_err() {
                            break; // TUN 關閉
                        }
                    }
                    _ => break,
                }
            }
        });

        let (res1, res2) = tokio::join!(stage_upload, stage_download);
        res1.context("self-transport stage_upload panic")?;
        res2.context("self-transport stage_download panic")?;
        Ok(())
    }
}

/// 將單一完整 IP 封包包上 [len_be u16] 前綴，供串流壓縮重組
fn frame_packet(packet: &[u8]) -> Vec<u8> {
    assert!(!packet.is_empty(), "拒絕空封包入流");
    assert!(
        packet.len() <= u16::MAX as usize,
        "IP 封包超過 u16 長度前綴上限"
    );
    let mut framed = Vec::with_capacity(2 + packet.len());
    framed.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    framed.extend_from_slice(packet);
    framed
}

#[cfg(test)]
mod frame_tests {
    use super::{frame_packet, unframe_packets};

    #[test]
    fn test_frame_unframe_multi_packet() {
        let p1 = vec![0x45u8; 64];
        let p2 = vec![0x60u8; 128];
        let mut framed = frame_packet(&p1);
        framed.extend_from_slice(&frame_packet(&p2));
        let out = unframe_packets(&framed);
        assert_eq!(out, vec![p1, p2]);
    }

    #[test]
    fn test_unframe_truncated_tail_dropped() {
        let p1 = vec![0x45u8; 32];
        let mut framed = frame_packet(&p1);
        framed.extend_from_slice(&[0x00, 0x40]); // 宣告 64B 但無內容
        let out = unframe_packets(&framed);
        assert_eq!(out, vec![p1]);
    }

    #[test]
    fn test_unframe_empty_sentinel_skipped() {
        let p1 = vec![0x45u8; 16];
        let mut framed = vec![0x00, 0x00]; // 空哨兵
        framed.extend_from_slice(&frame_packet(&p1));
        let out = unframe_packets(&framed);
        assert_eq!(out, vec![p1]);
    }
}

/// 將串流解壓後的框架資料回復為多個完整 IP 封包
fn unframe_packets(framed: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 2 <= framed.len() {
        let len = u16::from_be_bytes([framed[off], framed[off + 1]]) as usize;
        if len == 0 {
            off += 2;
            continue; // 跳過空哨兵，不向 TUN 寫空包
        }
        if off + 2 + len > framed.len() {
            eprintln!(
                "⚠️ 串流幀尾截斷 (off {} len {} total {})，丟棄尾段",
                off,
                len,
                framed.len()
            );
            break;
        }
        out.push(framed[off + 2..off + 2 + len].to_vec());
        off += 2 + len;
    }
    out
}
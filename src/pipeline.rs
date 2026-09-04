use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use crate::ndcode_tun_engine::NDcodeTunEngine;
use crate::net_transport::{recv_framed_payload, send_framed_payload};

/// 管線 Channel 緩衝區容量
const PIPELINE_BUFFER_SIZE: usize = 1024;

pub struct NDcodePipeline;

impl NDcodePipeline {
    /// 啟動上行資料管線: TUN 讀取 ──> NDcode3 壓縮編碼 ──> TCP 傳送
    pub async fn spawn_upstream_pipeline<R, W>(
        mut tun_reader: R,
        mut tcp_writer: W,
        engine: Arc<NDcodeTunEngine>,
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

        // Stage 2: Processing Task (NDcode 3 噴泉碼/XZ 壓縮處理)
        let engine_proc = engine.clone();
        let mut raw_rx_stream = raw_rx;
        let stage_process = tokio::spawn(async move {
            while let Some(raw_packet) = raw_rx_stream.recv().await {
                if let Ok(compressed_payload) = engine_proc.process_outgoing_packet(&raw_packet) {
                    if proc_tx.send(compressed_payload).await.is_err() {
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
        let _ = tokio::try_join!(stage_ingress, stage_process, stage_egress);
        Ok(())
    }

    /// 啟動下行資料管線: TCP 接收 ──> NDcode3 RaptorQ 解碼 ──> TUN 寫回
    pub async fn spawn_downstream_pipeline<R, W>(
        mut tcp_reader: R,
        mut tun_writer: W,
        engine: Arc<NDcodeTunEngine>,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (compressed_tx, compressed_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);
        let (raw_tx, mut raw_rx) = mpsc::channel::<Vec<u8>>(PIPELINE_BUFFER_SIZE);

        // Stage 1: Ingress Task (從 TCP 接收長度前綴封包)
        let stage_ingress = tokio::spawn(async move {
            loop {
                match recv_framed_payload(&mut tcp_reader).await {
                    Ok(payload) => {
                        if compressed_tx.send(payload).await.is_err() {
                            break;
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

        let _ = tokio::try_join!(stage_ingress, stage_process, stage_egress);
        Ok(())
    }
}

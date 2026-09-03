// main.rs - NDcode 3 TUN 虛擬網卡引擎
mod config;
mod decoder;
mod file_utils;
mod logic;
mod ndcode_tun_engine;
mod net_transport;

use anyhow::{Context, Result};
use config::{AppConfig, RunningMode};
use ndcode_tun_engine::NDcodeTunEngine;
use net_transport::{recv_framed_payload, send_framed_payload};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 解析命令列參數
    let config = AppConfig::parse_args();
    println!("🚀 啟動 NDcode 3 網路節流器 | 模式: {:?}", config.mode);

    // 2. 初始化 TUN 虛擬網卡
    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&config.tun_name)
        .address(&config.tun_ip)
        .netmask(&config.tun_netmask)
        .up();

    let dev = tun::create_as_async(&tun_config)
        .context("建立 TUN 虛擬網卡失敗 (請確認執行權限如 root/sudo)")?;
    println!("✅ TUN 網卡 [{}] 掛載成功 (IP: {})", config.tun_name, config.tun_ip);

    // 3. 建立 TUN Async 讀寫分離器與引擎
    let (mut tun_reader, mut tun_writer) = tokio::io::split(dev);
    let engine = Arc::new(NDcodeTunEngine::new());

    match config.mode {
        RunningMode::Client => {
            run_client_mode(config, engine, &mut tun_reader, &mut tun_writer).await?;
        }
        RunningMode::Server => {
            run_server_mode(config, engine, &mut tun_reader, &mut tun_writer).await?;
        }
    }

    Ok(())
}

/// -----------------------------------------------------------------------------
/// 客戶端邏輯 (Client Mode)
/// -----------------------------------------------------------------------------
async fn run_client_mode<R, W>(
    config: AppConfig,
    engine: Arc<NDcodeTunEngine>,
    tun_reader: &mut R,
    tun_writer: &mut W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    println!("📡 [Client] 正在連線至 Server 位址: {}", config.server_addr);
    let socket = TcpStream::connect(config.server_addr)
        .await
        .context("無法建立與伺服端的 TCP 連線")?;
    println!("✅ [Client] 連線成功！啟動雙向流量壓縮傳輸管線...");

    let (mut tcp_read, mut tcp_write) = socket.into_split();
    let tcp_writer_mutex = Arc::new(Mutex::new(tcp_write));

    // 任務 A: 本機 TUN 讀取 -> NDcode3 壓縮 -> 送出至 Server
    let engine_tx = engine.clone();
    let tcp_tx_writer = tcp_writer_mutex.clone();
    let upstream_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut *tun_reader, &buf).await {
                Ok(n) if n > 0 => n,
                _ => break,
            };

            let raw_packet = &buf[..n];
            if let Ok(compressed_payload) = engine_tx.process_outgoing_packet(raw_packet) {
                let mut lock = tcp_tx_writer.lock().await;
                if send_framed_payload(&mut *lock, &compressed_payload).await.is_err() {
                    eprintln!("❌ [Client] 傳送至 Server 失敗，中斷上行連線");
                    break;
                }
            }
        }
    });

    // 任務 B: Server 接收 compressed -> NDcode3 解壓 -> 寫回本機 TUN
    let engine_rx = engine.clone();
    let downstream_task = tokio::spawn(async move {
        loop {
            match recv_framed_payload(&mut tcp_read).await {
                Ok(payload) => {
                    if let Ok(raw_packet) = engine_rx.process_incoming_payload(&payload) {
                        let _ = tokio::io::AsyncWriteExt::write_all(&mut *tun_writer, &raw_packet).await;
                    }
                }
                Err(_) => {
                    eprintln!("❌ [Client] 與 Server 的下行斷開");
                    break;
                }
            }
        }
    });

    let _ = tokio::try_join!(upstream_task, downstream_task);
    Ok(())
}

/// -----------------------------------------------------------------------------
/// 伺服器端邏輯 (Server Mode)
/// -----------------------------------------------------------------------------
async fn run_server_mode<R, W>(
    config: AppConfig,
    engine: Arc<NDcodeTunEngine>,
    _tun_reader: &mut R,
    _tun_writer: &mut W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .context("無法綁定 Server 監聽埠")?;
    println!("🌐 [Server] 伺服端已啟動，監聽於: {}", config.listen_addr);

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        println!("🔗 [Server] 收到客戶端連線來自: {}", peer_addr);

        let engine_clone = engine.clone();

        tokio::spawn(async move {
            let (mut tcp_read, mut tcp_write) = socket.split();

            loop {
                // 讀取 Client 的壓縮封包
                let payload = match recv_framed_payload(&mut tcp_read).await {
                    Ok(p) => p,
                    Err(_) => {
                        println!("🔌 [Server] 客戶端 {} 已離線", peer_addr);
                        break;
                    }
                };

                // 解壓處理
                match engine_clone.process_incoming_payload(&payload) {
                    Ok(raw_packet) => {
                        // TODO: 伺服器端再處理 (如轉發至外網或系統網卡)
                        // Echo 測試或轉發處理：壓縮後回傳 Client
                        if let Ok(echo_payload) = engine_clone.process_outgoing_packet(&raw_packet) {
                            let _ = send_framed_payload(&mut tcp_write, &echo_payload).await;
                        }
                    }
                    Err(e) => eprintln!("⚠️ [Server] 封包解壓失敗: {}", e),
                }
            }
        });
    }
}

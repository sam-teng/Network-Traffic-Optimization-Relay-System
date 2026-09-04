// main.rs - NDcode 3 TUN 虛擬網卡引擎
mod config;
mod ndcode_tun_engine;
mod net_transport;
mod pipeline;

use anyhow::{Context, Result};
use config::{AppConfig, RunningMode};
use ndcode_tun_engine::NDcodeTunEngine;
use pipeline::NDcodePipeline;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::parse_args();
    println!("🚀 啟動 NDcode 3 網路節流器 (管線模式) | 模式: {:?}", config.mode);

    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&config.tun_name)
        .address(&config.tun_ip)
        .netmask(&config.tun_netmask)
        .up();

    let dev = tun::create_as_async(&tun_config)
        .context("建立 TUN 虛擬網卡失敗 (請確認執行權限如 root/sudo)")?;
    println!("✅ TUN 網卡 [{}] 掛載成功 (IP: {})", config.tun_name, config.tun_ip);

    let (tun_reader, tun_writer) = tokio::io::split(dev);
    let engine = Arc::new(NDcodeTunEngine::new());

    match config.mode {
        RunningMode::Client => {
            run_client_mode(config, engine, tun_reader, tun_writer).await?;
        }
        RunningMode::Server => {
            run_server_mode(config, engine).await?;
        }
    }

    Ok(())
}

async fn run_client_mode<R, W>(
    config: AppConfig,
    engine: Arc<NDcodeTunEngine>,
    tun_reader: R,
    tun_writer: W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    println!("📡 [Client] 連線至 Server: {}", config.server_addr);
    let socket = TcpStream::connect(config.server_addr)
        .await
        .context("無法建立 TCP 連線")?;
    println!("✅ [Client] 連線成功！平行雙向管線已建置");

    let (tcp_read, tcp_write) = socket.into_split();

    // 並行啟動獨立的上行與下行管線
    let upstream = NDcodePipeline::spawn_upstream_pipeline(tun_reader, tcp_write, engine.clone());
    let downstream = NDcodePipeline::spawn_downstream_pipeline(tcp_read, tun_writer, engine.clone());

    let _ = tokio::try_join!(upstream, downstream);
    Ok(())
}

async fn run_server_mode(
    config: AppConfig,
    engine: Arc<NDcodeTunEngine>,
) -> Result<()> {
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .context("無法綁定 Server 監聽埠")?;
    println!("🌐 [Server] 伺服端已啟動，監聽於: {}", config.listen_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        println!("🔗 [Server] 新連線來自: {}", peer_addr);

        let engine_clone = engine.clone();

        tokio::spawn(async move {
            let (tcp_read, tcp_write) = socket.into_split();
            
            // Server 端的內部 Echo 管線 (可根據需求對接外網介面)
            let _ = NDcodePipeline::spawn_downstream_pipeline(
                tcp_read,
                tokio::io::sink(), // 範例：丟入 Sink 或對接虛擬介面
                engine_clone,
            ).await;
        });
    }
}

// main.rs - NDcode 3 TUN 虛擬網卡引擎
mod config;
mod disclaimer;
mod net_routes;
mod privileges;
mod tls;
mod tun_backend;
#[cfg(target_os = "windows")]
mod win_wintun;

use config::{AppConfig, RunningMode};
use disclaimer::print_and_confirm_disclaimer;
use ntors::ndcode_tun_engine::NDcodeTunEngine;
use ntors::pipeline::{self, NDcodePipeline};
use ntors::traffic_meter::{CountingReader, CountingSocket, CountingWriter, TrafficMeter};

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// 共享 TUN 裝置：以 Arc<Mutex> 同時提供 AsyncRead 與 AsyncWrite，
/// Clone 後可反覆用於多次重連 (等同 tokio::io::split 的內部鎖定模式)。
#[derive(Clone)]
struct SharedTun {
    dev: Arc<Mutex<tun::AsyncDevice>>,
}

impl SharedTun {
    fn new(dev: tun::AsyncDevice) -> Self {
        Self { dev: Arc::new(Mutex::new(dev)) }
    }
}

impl AsyncRead for SharedTun {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut guard = self.dev.lock().unwrap();
        AsyncRead::poll_read(Pin::new(&mut *guard), cx, buf)
    }
}

impl AsyncWrite for SharedTun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut guard = self.dev.lock().unwrap();
        AsyncWrite::poll_write(Pin::new(&mut *guard), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.dev.lock().unwrap();
        AsyncWrite::poll_flush(Pin::new(&mut *guard), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.dev.lock().unwrap();
        AsyncWrite::poll_shutdown(Pin::new(&mut *guard), cx)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    print_and_confirm_disclaimer()?;
    #[cfg(target_os = "windows")]
    {
        // 啟動前自動釋放內嵌 DLL，無需外連下載 PowerShell 腳本
        win_wintun::win_wintun::ensure_wintun_embedded()
            .context("Wintun 內嵌驅動釋放失敗")?;
    }
    let args: Vec<String> = env::args().collect();

    // 若帶入 --setup 參數或找不到 config 時觸發跨平台自動化設定嚮導
    if args.contains(&"--setup".to_string()) || !std::path::Path::new("ndcode_config.json").exists() {
        run_interactive_setup_wizard()?;
    }

    let config = AppConfig::parse_args();

    // 權限就緒檢查：無管理權限時，依 --auto-elevate 觸發 UAC 提升或列印指引
    if !privileges::ensure_privilege_ready(config.auto_elevate)? {
        // Windows auto-elevate 已重新啟動新行程：舊行程直接結束
        return Ok(());
    }

    println!(
        "🚀 啟動 NDcode 3 網路節流器 (管線模式) | 模式: {:?} | OS: {} | TLS: {}",
        config.mode,
        env::consts::OS,
        if config.tls { "開啟" } else { "關閉" }
    );

    let backend = tun_backend::TunBackend::parse(&config.tun_backend);
    let tun_handle = tun_backend::create_with_fallback(
        &backend,
        &config.tun_name,
        &config.tun_ip,
        &config.tun_netmask,
    )
    .context("建立 TUN 虛擬網卡失敗（後端: {backend}），請參閱上方權限指引後重試")?;
    println!(
        "✅ TUN 網卡 [{}] 掛載成功 (IP: {}, 後端: {})",
        tun_handle.iface, config.tun_ip, backend
    );
    tun_backend::verify_iface_up(&tun_handle.iface);

    let tun = SharedTun::new(tun_handle.dev);
    let engine = Arc::new(NDcodeTunEngine::new());
    let traffic = Arc::new(TrafficMeter::new());

    // 建立隧道路由 (Client 才需要；Server 純轉發不搶路由)
    if config.mode == RunningMode::Client {
        if let Err(e) = net_routes::apply_tun_route(
            &tun_handle.iface,
            &config.tun_gateway,
            &config.tun_route,
            config.enable_route,
        ) {
            eprintln!("⚠️  [Route] 路由設定失敗: {:?} (可關閉路由或檢查權限)", e);
        }
    }

    match config.mode {
        RunningMode::Client => run_client_mode(config, engine, tun.clone(), tun, traffic.clone()).await?,
        RunningMode::Server => run_server_mode(config, engine, traffic.clone()).await?,
    }

    Ok(())
}

/// 跨平台互動式自動化設定嚮導
fn run_interactive_setup_wizard() -> Result<()> {
    println!("==================================================");
    println!("⚙️  NDcode 3 跨平台自動化環境設定嚮導");
    println!("==================================================");
    println!("偵測到作業系統: {}", env::consts::OS);

    // 1. 確認執行模式
    let mode = prompt_choice("請選擇運作模式:", &["Client (客戶端)", "Server (伺服端)"])?;
    let running_mode = if mode == 0 { RunningMode::Client } else { RunningMode::Server };

    // 2. 輸入 IP 與綁定資訊
    let tun_name = prompt_input("請輸入 TUN 介面名稱", "tun0")?;
    let tun_ip = prompt_input("請輸入 TUN 介面 IP 位址", "10.0.0.2")?;
    let tun_netmask = prompt_input("請輸入 TUN 子網路遮罩", "255.255.255.0")?;
    let tun_backend = prompt_input("TUN 後端 (auto / tun-rs / system)", "auto")?;
    let tun_gateway = prompt_input("請輸入 TUN 對端閘道 IP", "10.0.0.1")?;
    let tun_route = prompt_input("請輸入路由進 TUN 的目標 (default 或 CIDR)", "default")?;
    let server_addr = match running_mode {
        RunningMode::Client => prompt_input("請輸入遠端 Server TCP 位址", "127.0.0.1:8080")?,
        RunningMode::Server => prompt_input("請輸入本機 Server 監聽位址", "0.0.0.0:8080")?,
    };

    // 3. 自動調整系統核心網路優化參數 (Sysctl / Netsh)
    if prompt_confirm("是否自動優化作業系統網路核心參數以榨乾吞吐量？")? {
        apply_os_network_tuning()?;
    }

    // 3.5 權限就緒檢查 (TUN/路由需管理權限)
    privileges::wizard_ensure_privilege()?;

    // 3.6 TLS/SSL 加密傳輸
    let tls_enabled = prompt_confirm("是否啟用 TLS/SSL 加密傳輸 (rustls)？")?;
    let (tls_cert, tls_key, tls_ca, tls_insecure) = if tls_enabled {
        if running_mode == RunningMode::Server {
            let cert = prompt_input("TLS 憑證 PEM 路徑 (留空 = 自動產生自簽憑證)", "")?;
            let key = prompt_input("TLS 私鑰 PEM 路徑 (留空 = 自動產生)", "")?;
            (cert, key, String::new(), false)
        } else {
            let ca = prompt_input("TLS 憑證 PEM 路徑 (--tls-ca, 留空 = insecure)", "")?;
            let insecure = ca.is_empty();
            (String::new(), String::new(), ca, insecure)
        }
    } else {
        (String::new(), String::new(), String::new(), false)
    };

    // 4. Unix/Linux 專屬: 設定非 Root 帳號 Capabilities 權限
    #[cfg(target_os = "linux")]
    {
        if prompt_confirm("是否自動設定 Linux Binary Capabilities (免 root 存取 TUN)？")? {
            apply_linux_capabilities()?;
        }
    }

    // 5. 儲存設定至 ndcode_config.json
    let config_json = serde_json::json!({
        "mode": match running_mode { RunningMode::Client => "Client", RunningMode::Server => "Server" },
        "tun_name": tun_name,
        "tun_ip": tun_ip,
        "tun_netmask": tun_netmask,
        "tun_backend": tun_backend,
        "tun_gateway": tun_gateway,
        "tun_route": tun_route,
        "server_addr": server_addr,
        "listen_addr": server_addr,
        "tls": tls_enabled,
        "tls_cert": tls_cert,
        "tls_key": tls_key,
        "tls_ca": tls_ca,
        "tls_insecure": tls_insecure,
    });
    fs::write("ndcode_config.json", serde_json::to_string_pretty(&config_json)?)?;
    println!("\n✅ NDcode 3 設定檔已成功寫入至 `ndcode_config.json`！若同時以命令列參數啟動，命令列參數優先。");
    println!("--------------------------------------------------\n");
    Ok(())
}

/// 自動優化各 OS 網路核心參數
fn apply_os_network_tuning() -> Result<()> {
    let current_os = env::consts::OS;
    println!("🔧 正在針對 [{}] 自動優化網路核心參數...", current_os);

    match current_os {
        "linux" => {
            let sysctl_conf = r#"
# NDcode 3 High-Throughput Network Optimization
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 10000
"#;
            let conf_path = "/etc/sysctl.d/99-ndcode.conf";
            if let Err(_e) = fs::write(conf_path, sysctl_conf) {
                println!("⚠️ 無法直接寫入 {} (可能需要 sudo)，嘗試執行 sudo sysctl...", conf_path);
                let _ = Command::new("sudo").args(["sysctl", "-w", "net.core.rmem_max=16777216"]).status();
                let _ = Command::new("sudo").args(["sysctl", "-w", "net.core.wmem_max=16777216"]).status();
            } else {
                let _ = Command::new("sudo").args(["sysctl", "--system"]).status();
                println!("✅ Linux sysctl 優化參數已寫入 {}", conf_path);
            }
        }
        "macos" => {
            println!("🍎 套用 macOS 網路 Buffer 最佳化...");
            let _ = Command::new("sudo").args(["sysctl", "-w", "net.inet.tcp.sendspace=1048576"]).status();
            let _ = Command::new("sudo").args(["sysctl", "-w", "net.inet.tcp.recvspace=1048576"]).status();
            println!("✅ macOS 網路 TCP 視窗參數設定完成");
        }
        "windows" => {
            println!("🪟 套用 Windows netsh AutoTuning 最佳化...");
            let status = Command::new("netsh")
                .args(["interface", "tcp", "set", "global", "autotuninglevel=normal"])
                .status();
            if status.is_ok() {
                println!("✅ Windows TCP AutoTuning 設定完成");
            } else {
                println!("⚠️ 請以「系統管理員身分」執行以確保 Windows 網路參數寫入生效");
            }
        }
        _ => println!("⚠️ 未知的作業系統，跳過自動化網路調整"),
    }
    Ok(())
}

/// Linux 專用：賦予可執行檔 CAP_NET_ADMIN 權限
#[cfg(target_os = "linux")]
fn apply_linux_capabilities() -> Result<()> {
    let current_exe = env::current_exe()?;
    println!("🔐 嘗試賦予 [{}] CAP_NET_ADMIN 權限...", current_exe.display());
    let status = Command::new("sudo")
        .args(["setcap", "cap_net_admin=+ep", current_exe.to_str().unwrap()])
        .status();

    if status.is_ok() && status.unwrap().success() {
        println!("✅ 成功設定 Linux CAP_NET_ADMIN Capabilities！");
    } else {
        println!("⚠️ 授權失敗，請手動執行: sudo setcap cap_net_admin=+ep {}", current_exe.display());
    }
    Ok(())
}

// --- CLI 互動模組輔助函式 ---

fn prompt_input(label: &str, default_val: &str) -> Result<String> {
    print!("👉 {} [預設: {}]: ", label, default_val);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default_val.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn prompt_confirm(label: &str) -> Result<bool> {
    print!("❓ {} (y/N): ", label);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes"))
}

fn prompt_choice(label: &str, choices: &[&str]) -> Result<usize> {
    println!("{}", label);
    for (idx, choice) in choices.iter().enumerate() {
        println!("  [{}] {}", idx + 1, choice);
    }
    loop {
        print!("👉 請選擇數字 (1-{}): ", choices.len());
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if let Ok(num) = input.trim().parse::<usize>() {
            if num >= 1 && num <= choices.len() {
                return Ok(num - 1);
            }
        }
        println!("❌ 輸入無效，請再試一次。");
    }
}

/// 定期輸出流量統計摘要 (僅在 --traffic-stats 啟用時呼叫)。
fn spawn_traffic_display(traffic: Arc<TrafficMeter>, interval_secs: u64) {
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(1)));
        timer.tick().await; // 略過首次立即 tick，等待第一週期
        loop {
            timer.tick().await;
            println!("{}", traffic.display());
        }
    });
}

async fn run_client_mode<R, W>(
    config: AppConfig,
    engine: Arc<NDcodeTunEngine>,
    tun_reader: R,
    tun_writer: W,
    traffic: Arc<TrafficMeter>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static + Clone,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static + Clone,
{
    println!("📡 [Client] 連線至 Server: {}", config.server_addr);

    if config.traffic_stats {
        println!(
            "📊 [Client] 流量統計顯示已啟用 (每 {} 秒輸出一次)",
            config.traffic_interval
        );
        spawn_traffic_display(traffic.clone(), config.traffic_interval);
    }

    // 永久重連迴圈：TCP 斷線/EOF 後自動重新連線，維持 VPN 常駐
    let mut attempt = 0u32;
    loop {
        let tun_rd = tun_reader.clone();
        let tun_wr = tun_writer.clone();
        match run_client_connection(&config, &engine, &traffic, tun_rd, tun_wr).await {
            Ok(()) => {
                println!("⚠️ [Client] 連線已結束 (server 關閉連線)，2 秒後重連...");
            }
            Err(e) => {
                eprintln!("⚠️ [Client] 連線故障: {:?}，2 秒後重連...", e);
            }
        }
        attempt += 1;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        println!("🔁 [Client] 第 {} 次重連至 {}", attempt, config.server_addr);
    }
}

/// 單次連線的連線、握手與管線生命週期 (斷線後由 run_client_mode 重連)
async fn run_client_connection<R, W>(
    config: &AppConfig,
    engine: &Arc<NDcodeTunEngine>,
    traffic: &Arc<TrafficMeter>,
    tun_reader: R,
    tun_writer: W,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let tcp = TcpStream::connect(&config.server_addr)
        .await
        .context("無法建立 TCP 連線")?;

    // 若啟用 TLS：以 TLS 握手包覆 TCP (管線層使用同一 socket)
    let use_tls = config.tls;
    let client_tls = if use_tls {
        Some(
            tls::client_tls(
                if config.tls_ca.is_empty() { None } else { Some(&config.tls_ca) },
                config.tls_insecure,
            )
            .context("Client TLS 設定失敗")?,
        )
    } else {
        None
    };

    // 初始化安全模組：動態金鑰管理器、混淆模組與梯度網格引擎
    let key_mgr = pipeline::key_manager::DynamicKeyManager::new(1, b"NDcode3_Default_PSK_SecretKey_2026".to_vec());
    let obfuscator = Arc::new(pipeline::obfuscation::Obfuscator::default());
    let mesh_engine = Arc::new(pipeline::gradient_mesh::GradientMeshEngine::new(1001, 0.7, 0.3, 0.05));
    mesh_engine.register_peer(1, config.server_addr).await;

    if use_tls {
        // ── TLS 分支：Client 側 TLS 握手後再進行 HMAC 安全握手 ──
        let tls_stream = client_tls
            .as_ref()
            .unwrap()
            .connect(tcp)
            .await
            .context("Client TLS 握手失敗")?;
        println!("🔒 [Client] TLS 握手完成 (rustls, server: {})", tls::SERVER_NAME);

        // 執行 HMAC-SHA256 安全握手
        {
            let mut conn = tls_stream;
            pipeline::auth::NdCodeAuth::client_handshake(&mut conn, &key_mgr)
                .await
                .map_err(|e| anyhow::anyhow!("Client 握手失敗: {}", e))?;
            println!("🔐 [Client] HMAC-SHA256 握手驗證通過！動態 Padding 混淆與反向梯度控制就緒");
            println!("✅ [Client] 連線成功！雙向平行管線運作中 (TLS 加密)");

            if config.standalone {
                let conn = CountingSocket::new(conn, traffic.clone());
                let self_transport =
                    NDcodePipeline::spawn_self_transport_pipeline(tun_reader, tun_writer, conn, engine.clone());
                self_transport.await?;
                return Ok(());
            }

            let (read, write) = tokio::io::split(conn);
            let read = CountingReader::new(read, traffic.clone());
            let write = CountingWriter::new(write, traffic.clone());
            let upstream = NDcodePipeline::spawn_upstream_pipeline(
                tun_reader,
                write,
                engine.clone(),
                obfuscator.clone(),
                mesh_engine.clone(),
            );
            let downstream = NDcodePipeline::spawn_downstream_pipeline(
                read,
                tun_writer,
                engine.clone(),
                obfuscator.clone(),
                mesh_engine.clone(),
            );
            let (res_up, res_down) = tokio::join!(upstream, downstream);
            res_up?;
            res_down?;
        }
        return Ok(());
    }

    // ── 非 TLS 分支 (原始行為) ──
    let mut socket = tcp;

    // 執行 HMAC-SHA256 安全握手
    pipeline::auth::NdCodeAuth::client_handshake::<TcpStream>(&mut socket, &key_mgr)
        .await
        .map_err(|e| anyhow::anyhow!("Client 握手失敗: {}", e))?;
    println!("🔐 [Client] HMAC-SHA256 握手驗證通過！動態 Padding 混淆與反向梯度控制就緒");

    println!("✅ [Client] 連線成功！雙向平行管線運作中");

    if config.standalone {
        // ⚡ 純連線端模式 (self-transport)：無需中繼伺服器，雙端皆以 Client 運行
        //    上傳: TUN ──▶ TransportCodec 自動序列編碼 ──▶ TCP
        //    下載: TCP ──▶ TransportCodec 自動序列解碼 ──▶ TUN
        //    上傳與下載都只透過「連線端自帶傳輸即編解碼」，不需額外 framing/混淆層
        println!(
            "⚡ [Client::Standalone] 連線端自帶傳輸編解碼就緒 (上傳+下載皆透過 TransportCodec)"
        );

        let socket = CountingSocket::new(socket, traffic.clone());
        let self_transport =
            NDcodePipeline::spawn_self_transport_pipeline(tun_reader, tun_writer, socket, engine.clone());
        self_transport.await?;
        return Ok(());
    }

    let (tcp_read, tcp_write) = socket.into_split();

    let tcp_read = CountingReader::new(tcp_read, traffic.clone());
    let tcp_write = CountingWriter::new(tcp_write, traffic.clone());

    let upstream = NDcodePipeline::spawn_upstream_pipeline(
        tun_reader,
        tcp_write,
        engine.clone(),
        obfuscator.clone(),
        mesh_engine.clone(),
    );
    let downstream = NDcodePipeline::spawn_downstream_pipeline(
        tcp_read,
        tun_writer,
        engine.clone(),
        obfuscator.clone(),
        mesh_engine.clone(),
    );

    let (res_up, res_down) = tokio::join!(upstream, downstream);
    res_up?;
    res_down?;
    Ok(())
}

async fn run_server_mode(config: AppConfig, engine: Arc<NDcodeTunEngine>, traffic: Arc<TrafficMeter>) -> Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .context("無法綁定 Server 監聽埠")?;
    println!("🌐 [Server] 伺服端已啟動，監聽於: {}", config.listen_addr);
    if config.standalone {
        eprintln!("⚠️ [Server] --standalone/--scope 在 server 模式下被忽略 (server 僅解碼後 sink，未寫回 TUN)");
    }
    if config.traffic_stats {
        println!(
            "📊 [Server] 流量統計顯示已啟用 (每 {} 秒輸出一次)",
            config.traffic_interval
        );
        spawn_traffic_display(traffic.clone(), config.traffic_interval);
    }

let key_mgr = Arc::new(pipeline::key_manager::DynamicKeyManager::new(
        1,
        b"NDcode3_Default_PSK_SecretKey_2026".to_vec(),
    ));
    let obfuscator = Arc::new(pipeline::obfuscation::Obfuscator::default());
    let mesh_engine = Arc::new(pipeline::gradient_mesh::GradientMeshEngine::new(1, 0.7, 0.3, 0.05));

    // 若啟用 TLS：建立 Server TLS acceptor (憑證可由 --tls-cert/--tls-key 或自動自簽)
    let server_tls = if config.tls {
        let srv = tls::server_tls(
            if config.tls_cert.is_empty() { None } else { Some(&config.tls_cert) },
            if config.tls_key.is_empty() { None } else { Some(&config.tls_key) },
        )
        .or_else(|_| tls::server_tls(None, None))
        .context("Server TLS 設定失敗")?;
        println!("🔒 [Server] TLS 已啟用 (rustls, SAN: {})", tls::SERVER_NAME);
        if !config.tls_cert.is_empty() {
            println!("🔐 [Server] 使用憑證: {}", config.tls_cert);
        } else {
            println!("🔐 [Server] 自動產生自簽憑證。Client 需以 --tls-ca 指定憑證 PEM 或加 --tls-insecure");
        }
        Some(srv)
    } else {
        None
    };

    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        println!("🔗 [Server] 新連線來自: {}", peer_addr);
        let engine_clone = engine.clone();
        let key_mgr_clone = key_mgr.clone();
        let obfuscator_clone = obfuscator.clone();
        let mesh_engine_clone = mesh_engine.clone();
        let server_tls_clone = server_tls.clone();
        let traffic_clone = traffic.clone();

        tokio::spawn(async move {
            // 若啟用 TLS：先完成 TLS 握手再進行 HMAC 驗證
            let tls_enabled = server_tls_clone.is_some();
            if tls_enabled {
                let tls_stream = match server_tls_clone.as_ref().unwrap().accept(tcp).await {
                    Ok(s) => {
                        println!("🔒 [Server] Peer ({}) TLS 握手完成", peer_addr);
                        s
                    }
                    Err(e) => {
                        eprintln!("❌ [Server] Peer ({}) TLS 握手失敗: {:?}", peer_addr, e);
                        return;
                    }
                };

                // 伺服端驗證 Client 握手封包
                let mut conn = tls_stream;
                if let Err(e) = pipeline::auth::NdCodeAuth::server_handshake(&mut conn, &key_mgr_clone).await {
                    eprintln!("❌ [Server] Peer ({}) 握手驗證拒絕 (TLS): {}", peer_addr, e);
                    return;
                }
                println!("🔐 [Server] Peer ({}) 握手驗證成功！(TLS)", peer_addr);
                mesh_engine_clone.register_peer(1001, peer_addr).await;

                if config.standalone {
                    println!("⚡ [Server::Standalone] 對稱連線端自帶傳輸編解碼 (TLS)");
                    let conn = CountingSocket::new(conn, traffic_clone.clone());
                    let _ = NDcodePipeline::spawn_self_transport_pipeline(
                        tokio::io::empty(),
                        tokio::io::sink(),
                        conn,
                        engine_clone,
                    )
                    .await;
                    return;
                }

                let (read, _write) = tokio::io::split(conn);
                let read = CountingReader::new(read, traffic_clone.clone());
                let _ = NDcodePipeline::spawn_downstream_pipeline(
                    read,
                    tokio::io::sink(),
                    engine_clone,
                    obfuscator_clone,
                    mesh_engine_clone,
                )
                .await;
                return;
            }

            // ── 非 TLS 分支 (原始行為) ──
            let mut socket = tcp;
            // 伺服端驗證 Client 握手封包
            if let Err(e) = pipeline::auth::NdCodeAuth::server_handshake::<TcpStream>(&mut socket, &key_mgr_clone).await {
                eprintln!("❌ [Server] Peer ({}) 握手驗證拒絕: {}", peer_addr, e);
                return;
            }
            println!("🔐 [Server] Peer ({}) 握手驗證成功！", peer_addr);

            mesh_engine_clone.register_peer(1001, peer_addr).await;

            if config.standalone {
                // 純連線端 server：與對端同一套 TransportCodec 對稱
                // 此端為 sink 端：peer 寫來的封包自動解碼後丟棄 (驗證/統計用途)
                println!("⚡ [Server::Standalone] 對稱連線端自帶傳輸編解碼");
                let socket = CountingSocket::new(socket, traffic_clone.clone());
                let _ = NDcodePipeline::spawn_self_transport_pipeline(
                    tokio::io::empty(),
                    tokio::io::sink(),
                    socket,
                    engine_clone,
                )
                .await;
                return;
            }

            let (tcp_read, _tcp_write) = socket.into_split();
            let tcp_read = CountingReader::new(tcp_read, traffic_clone.clone());
            let _ = NDcodePipeline::spawn_downstream_pipeline(
                tcp_read,
                tokio::io::sink(),
                engine_clone,
                obfuscator_clone,
                mesh_engine_clone,
            )
            .await;
        });
    }
}


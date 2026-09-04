// main.rs - NDcode 3 TUN 虛擬網卡引擎
mod config;
mod ndcode_tun_engine;
mod net_transport;
mod pipeline;

use config::{AppConfig, RunningMode};
use ndcode_tun_engine::NDcodeTunEngine;
use pipeline::NDcodePipeline;

use anyhow::{Context, Result};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::Command;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    // 若帶入 --setup 參數或找不到 config 時觸發跨平台自動化設定嚮導
    if args.contains(&"--setup".to_string()) || !std::path::Path::new("ndcode_config.json").exists() {
        run_interactive_setup_wizard()?;
    }

    let config = AppConfig::load_or_parse_args()?;
    println!(
        "🚀 啟動 NDcode 3 網路節流器 (管線模式) | 模式: {:?} | OS: {}",
        config.mode,
        env::consts::OS
    );

    let mut tun_config = tun::Configuration::default();
    tun_config
        .name(&config.tun_name)
        .address(&config.tun_ip)
        .netmask(&config.tun_netmask)
        .up();

    let dev = tun::create_as_async(&tun_config)
        .context("建立 TUN 虛擬網卡失敗，請確認是否具備系統管理權限 (如 setcap 或 Administrator)")?;
    println!("✅ TUN 網卡 [{}] 掛載成功 (IP: {})", config.tun_name, config.tun_ip);

    let (tun_reader, tun_writer) = tokio::io::split(dev);
    let engine = Arc::new(NDcodeTunEngine::new());

    match config.mode {
        RunningMode::Client => run_client_mode(config, engine, tun_reader, tun_writer).await?,
        RunningMode::Server => run_server_mode(config, engine).await?,
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
    let server_addr = match running_mode {
        RunningMode::Client => prompt_input("請輸入遠端 Server TCP 位址", "127.0.0.1:8080")?,
        RunningMode::Server => prompt_input("請輸入本機 Server 監聽位址", "0.0.0.0:8080")?,
    };

    // 3. 自動調整系統核心網路優化參數 (Sysctl / Netsh)
    if prompt_confirm("是否自動優化作業系統網路核心參數以榨乾吞吐量？")? {
        apply_os_network_tuning()?;
    }

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
        "tun_netmask": "255.255.255.0",
        "server_addr": server_addr,
        "listen_addr": server_addr,
    });

    fs::write("ndcode_config.json", serde_json::to_string_pretty(&config_json)?)?;
    println!("\n✅ NDcode 3 設定檔已成功寫入至 `ndcode_config.json`！");
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
            if let Err(e) = fs::write(conf_path, sysctl_conf) {
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
    let socket = TcpStream::connect(&config.server_addr)
        .await
        .context("無法建立 TCP 連線")?;
    println!("✅ [Client] 連線成功！雙向平行管線運作中");

    let (tcp_read, tcp_write) = socket.into_split();
    let upstream = NDcodePipeline::spawn_upstream_pipeline(tun_reader, tcp_write, engine.clone());
    let downstream = NDcodePipeline::spawn_downstream_pipeline(tcp_read, tun_writer, engine.clone());

    let _ = tokio::try_join!(upstream, downstream);
    Ok(())
}

async fn run_server_mode(config: AppConfig, engine: Arc<NDcodeTunEngine>) -> Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .context("無法綁定 Server 監聽埠")?;
    println!("🌐 [Server] 伺服端已啟動，監聽於: {}", config.listen_addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        println!("🔗 [Server] 新連線來自: {}", peer_addr);
        let engine_clone = engine.clone();

        tokio::spawn(async move {
            let (tcp_read, tcp_write) = socket.into_split();
            let _ = NDcodePipeline::spawn_downstream_pipeline(
                tcp_read,
                tokio::io::sink(),
                engine_clone,
            )
            .await;
        });
    }
}

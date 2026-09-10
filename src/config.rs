use clap::parser::ValueSource;
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum RunningMode {
    /// 客戶端：擷取本機 TUN 流量，經 NDcode 3 壓縮後傳送給 Server
    Client,
    /// 伺服器端：接收 Client 壓縮封包，解壓後還原至 Server TUN / 網際網路
    Server,
}

/// 串流壓縮涵蓋範圍 (純連線端模式)
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum CompressionScopeArg {
    /// 僅明文 HTTP (埠 80) 下載流 - Phase 2 預設
    #[value(name = "http")]
    Http,
    /// HTTP + HTTPS 下載流
    #[value(name = "http-https")]
    HttpHttps,
    /// 全部流量皆須壓縮 (預留介面，最後實作)
    #[value(name = "all")]
    All,
}

impl CompressionScopeArg {
    pub fn to_pipeline_scope(self) -> ntors::pipeline::streaming_compressor::CompressionScope {
        use ntors::pipeline::streaming_compressor::CompressionScope;
        match self {
            CompressionScopeArg::Http => CompressionScope::HttpOnly,
            CompressionScopeArg::HttpHttps => CompressionScope::HttpAndHttps,
            CompressionScopeArg::All => CompressionScope::AllTraffic,
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "NTORS",
    author = "NDcode Firmware Team",
    version = "0.0.0-NDcode3",
    about = "NDcode 3 Layer 3 跨平台網路流量節流器 (支持 Client / Server 模式)"
)]
pub struct AppConfig {
    /// 運行模式：client 或 server
    #[arg(short, long, value_enum, default_value_t = RunningMode::Client)]
    pub mode: RunningMode,

    /// [Client 模式] 遠端 NDcode 伺服器位址
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    pub server_addr: SocketAddr,

    /// [Server 模式] 本機監聽位址
    #[arg(short, long, default_value = "0.0.0.0:8080")]
    pub listen_addr: SocketAddr,

    /// TUN 虛擬網卡名稱
    #[arg(long, default_value = "tun0")]
    pub tun_name: String,

    /// TUN 虛擬網卡 IP 位址
    #[arg(long, default_value = "10.0.0.1")]
    pub tun_ip: String,

    /// TUN 虛擬網卡 子網路遮罩
    #[arg(long, default_value = "255.255.255.0")]
    pub tun_netmask: String,

    /// TUN 對端閘道 IP (Client 通常為 Server 的隧道 IP)
    #[arg(long, default_value = "10.0.0.1")]
    pub tun_gateway: String,

    /// 要路由進 TUN 的目標: default 或 CIDR (如 192.168.50.0/24)
    #[arg(long, default_value = "default")]
    pub tun_route: String,

    /// 是否套用 OS 路由表修改 (真機需管理員權限；設 false 只印出計畫指令)
    #[arg(long, default_value_t = true)]
    pub enable_route: bool,

    /// Windows：非管理員啟動時自動以 UAC 重新啟動 (runas)
    #[arg(long, default_value_t = false)]
    pub auto_elevate: bool,

    /// 純連線端模式 (無需中繼伺服器)：雙端皆以 Client 運行，
    /// 下載流量以 NDcode3 邊接收邊串流壓縮
    #[arg(long, default_value_t = false)]
    pub standalone: bool,

    /// 串流壓縮涵蓋範圍：http | http-https | all
    #[arg(long, value_enum, default_value_t = CompressionScopeArg::Http)]
    pub scope: CompressionScopeArg,

    /// 啟用 TLS/SSL 加密傳輸 (rustls)。Server 需提供憑證；Client 需 --tls-ca 或 --tls-insecure
    #[arg(long, default_value_t = false)]
    pub tls: bool,

    /// [Server] TLS 憑證 PEM 檔路徑
    #[arg(long, default_value = "")]
    pub tls_cert: String,

    /// [Server] TLS 私鑰 PEM 檔路徑
    #[arg(long, default_value = "")]
    pub tls_key: String,

    /// [Client] 可信任的伺服器憑證 PEM (含自簽)
    #[arg(long, default_value = "")]
    pub tls_ca: String,

    /// [Client] 跳過 TLS 憑證驗證 (身份仍由 HMAC 握手確認)
    #[arg(long, default_value_t = false)]
    pub tls_insecure: bool,
}

impl AppConfig {
    pub fn parse_args() -> Self {
        Self::parse_args_from(std::env::args_os(), std::path::Path::new("ndcode_config.json"))
    }

    /// 以自訂 argv 解析 (設定檔為預設、CLI 給的參數優先)
    fn parse_args_from<I, T>(args: I, config_path: &std::path::Path) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // 1. 先以 clap 解析 CLI (含命令列參數與內建預設值)
        let matches = Self::command().try_get_matches_from(args).unwrap_or_else(|e| e.exit());
        let mut cfg: Self = Self::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

        // 2. 讀取 ndcode_config.json (設定精靈寫入)。
        //    僅當該欄位「CLI 沒有明確給出」時，以設定檔內容覆寫預設值。
        let cli_gave = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);
        if let Some(file_cfg) = load_config_file_at(config_path) {
            if !cli_gave("mode") {
                if let Some(m) = file_cfg.mode.as_deref().map(str::to_ascii_lowercase) {
                    cfg.mode = match m.as_str() {
                        "server" => RunningMode::Server,
                        _ => RunningMode::Client,
                    };
                }
            }
            if !cli_gave("server_addr") {
                if let Some(ref s) = file_cfg.server_addr {
                    if let Ok(addr) = s.parse() {
                        cfg.server_addr = addr;
                    }
                }
            }
            if !cli_gave("listen_addr") {
                if let Some(ref s) = file_cfg.listen_addr {
                    if let Ok(addr) = s.parse() {
                        cfg.listen_addr = addr;
                    }
                }
            }
            if !cli_gave("tun_name") {
                if let Some(ref s) = file_cfg.tun_name {
                    cfg.tun_name = s.clone();
                }
            }
            if !cli_gave("tun_ip") {
                if let Some(ref s) = file_cfg.tun_ip {
                    cfg.tun_ip = s.clone();
                }
            }
            if !cli_gave("tun_netmask") {
                if let Some(ref s) = file_cfg.tun_netmask {
                    cfg.tun_netmask = s.clone();
                }
            }
            if !cli_gave("tun_gateway") {
                if let Some(ref s) = file_cfg.tun_gateway {
                    cfg.tun_gateway = s.clone();
                }
            }
            if !cli_gave("tun_route") {
                if let Some(ref s) = file_cfg.tun_route {
                    cfg.tun_route = s.clone();
                }
            }
            if !cli_gave("enable_route") {
                if let Some(v) = file_cfg.enable_route {
                    cfg.enable_route = v;
                }
            }
            if !cli_gave("scope") {
                if let Some(m) = file_cfg.scope.as_deref().map(str::to_ascii_lowercase) {
                    cfg.scope = match m.as_str() {
                        "http-https" => CompressionScopeArg::HttpHttps,
                        "all" => CompressionScopeArg::All,
                        _ => CompressionScopeArg::Http,
                    };
                }
            }
            // --standalone 是 SetTrue flag：檔案為 true 且 CLI 未給時套用
            if file_cfg.standalone.unwrap_or(false) && !cli_gave("standalone") {
                cfg.standalone = true;
            }
            // TLS 相關：檔案 true 且 CLI 未給時套用；路徑檔案未有則忽略
            if file_cfg.tls.unwrap_or(false) && !cli_gave("tls") {
                cfg.tls = true;
            }
            if !cli_gave("tls_cert") {
                if let Some(ref s) = file_cfg.tls_cert {
                    if !s.is_empty() { cfg.tls_cert = s.clone(); }
                }
            }
            if !cli_gave("tls_key") {
                if let Some(ref s) = file_cfg.tls_key {
                    if !s.is_empty() { cfg.tls_key = s.clone(); }
                }
            }
            if !cli_gave("tls_ca") {
                if let Some(ref s) = file_cfg.tls_ca {
                    if !s.is_empty() { cfg.tls_ca = s.clone(); }
                }
            }
            if file_cfg.tls_insecure.unwrap_or(false) && !cli_gave("tls_insecure") {
                cfg.tls_insecure = true;
            }
        }
        cfg
    }
}

/// 設定精靈寫入的 ndcode_config.json 對應結構 (欄位皆可選)
#[derive(Deserialize, Debug, Default)]
struct ConfigFile {
    mode: Option<String>,
    server_addr: Option<String>,
    listen_addr: Option<String>,
    tun_name: Option<String>,
    tun_ip: Option<String>,
    tun_netmask: Option<String>,
    tun_gateway: Option<String>,
    tun_route: Option<String>,
    enable_route: Option<bool>,
    standalone: Option<bool>,
    scope: Option<String>,
    tls: Option<bool>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    tls_ca: Option<String>,
    tls_insecure: Option<bool>,
}

fn load_config_file() -> Option<ConfigFile> {
    load_config_file_at(std::path::Path::new("ndcode_config.json"))
}

fn load_config_file_at(path: &std::path::Path) -> Option<ConfigFile> {
    if !path.exists() {
        return None;
    }
    let text = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(content: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let name = format!(
            "ntors_test_config_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(name);
        std::fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_config_file_loaded_as_defaults() {
        // 設定檔內容應被讀回 (mode 大寫也要能對應到 Server)
        let path = temp_config(
            r#"{
                "mode": "Server",
                "server_addr": "1.2.3.4:9999",
                "listen_addr": "0.0.0.0:7777",
                "tun_name": "wm0",
                "tun_ip": "10.9.9.9",
                "tun_netmask": "255.255.0.0",
                "standalone": true,
                "scope": "all"
            }"#,
        );
        let cfg = AppConfig::parse_args_from(["ntors"], &path);
        assert_eq!(cfg.mode, RunningMode::Server);
        assert_eq!(cfg.server_addr.to_string(), "1.2.3.4:9999");
        assert_eq!(cfg.listen_addr.to_string(), "0.0.0.0:7777");
        assert_eq!(cfg.tun_name, "wm0");
        assert_eq!(cfg.tun_ip, "10.9.9.9");
        assert_eq!(cfg.tun_netmask, "255.255.0.0");
        assert!(cfg.standalone);
        assert_eq!(cfg.scope, CompressionScopeArg::All);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_cli_args_override_config_file() {
        let path = temp_config(
            r#"{
                "mode": "Server",
                "tun_name": "wm0",
                "standalone": true
            }"#,
        );
        // CLI 明確給 mode=client，需覆蓋檔案中的 Server
        let cfg = AppConfig::parse_args_from(["ntors", "--mode", "client"], &path);
        assert_eq!(cfg.mode, RunningMode::Client);

        // CLI 給 --no-standalone 無法關閉 SetTrue flag；但至少 CLI 無 standalone 時檔案 true 生效
        let cfg2 = AppConfig::parse_args_from(["ntors", "--tun-name", "vm0"], &path);
        assert_eq!(cfg2.tun_name, "vm0", "CLI tun-name 優先於檔案");
        assert!(cfg2.standalone, "檔案 standalone=true 應生效");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_tls_config_file_fields() {
        let path = temp_config(
            r#"{
                "mode": "Client",
                "tls": true,
                "tls_ca": "server_cert.pem",
                "tls_insecure": true
            }"#,
        );
        let cfg = AppConfig::parse_args_from(["ntors"], &path);
        assert!(cfg.tls, "檔案 tls=true 應生效");
        assert_eq!(cfg.tls_ca, "server_cert.pem");
        assert!(cfg.tls_insecure);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_tls_cli_override_config_file() {
        let path = temp_config(
            r#"{
                "mode": "Client",
                "tls": true,
                "tls_ca": "from_file.pem"
            }"#,
        );
        // CLI 給 --tls-ca 應覆蓋檔案值
        let cfg = AppConfig::parse_args_from(["ntors", "--tls-ca", "from_cli.pem"], &path);
        assert!(cfg.tls);
        assert_eq!(cfg.tls_ca, "from_cli.pem");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_no_config_file_uses_cli_defaults() {
        let path = std::env::temp_dir().join(format!(
            "ntors_missing_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cfg = AppConfig::parse_args_from(["ntors", "--mode", "server"], &path);
        assert_eq!(cfg.mode, RunningMode::Server);
        assert_eq!(cfg.tun_name, "tun0");
        assert!(!cfg.standalone);
        // 檔案不存在，無需清理
    }
}

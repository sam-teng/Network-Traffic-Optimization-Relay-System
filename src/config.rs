use clap::{Parser, ValueEnum};
use std::net::SocketAddr;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum RunningMode {
    /// 客戶端：擷取本機 TUN 流量，經 NDcode 3 壓縮後傳送給 Server
    Client,
    /// 伺服器端：接收 Client 壓縮封包，解壓後還原至 Server TUN / 網際網路
    Server,
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
}

impl AppConfig {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}

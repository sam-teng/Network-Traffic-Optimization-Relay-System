// src/tun_backend.rs - TUN 虛擬網卡建立後端與容錯 (跨平台，含 tun-rs 備用方案)
//
// 提供三種後端選擇：
//   auto   : 優先 tun-rs 建立（完整設定）；macOS/Linux 自動降級為「最小建立 + 系統工具賦址/啟動」
//   tun-rs : 僅使用 tun crate，失敗時直接結束 (default on Windows)
//   system : macOS/Linux 以最小建立 + 系統工具 (`ip` / `ifconfig`) 賦址並啟動介面
//
// 建立後跨平台驗證介面是否存在且 UP：
//   Linux  : `ip -o link show dev <name>`
//   macOS  : `ifconfig <name>`  (自動辨識 utunN)
//   Windows: 跳過 (wintun 由驅動管理；建立成功即視為正常)

use anyhow::{bail, Result};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use std::fmt;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command as PCommand;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::privileges;

// ── Public API ──────────────────────────────────────────────────────────────

/// TUN 後端類型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunBackend {
    /// 嘗試 tun-rs 建立；失敗且為 macOS/Linux 時自動嘗試系統工具備用方案
    Auto,
    /// 僅使用 tun crate (即 tun-rs)
    TunRs,
    /// macOS/Linux 專用：最小 tun-rs 建立 + 系統工具賦址與啟動
    System,
}

impl TunBackend {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "tun-rs" | "tunrs" | "tun" => TunBackend::TunRs,
            "system" | "sys" => TunBackend::System,
            other => {
                if !other.is_empty() && other != "auto" {
                    eprintln!(
                        "⚠️ [TUN] 未知後端 `{other}`，改以 auto 處理 (可用: auto | tun-rs | system)"
                    );
                }
                TunBackend::Auto
            }
        }
    }

    fn is_system_candidate(&self) -> bool {
        matches!(self, TunBackend::System)
            || (*self == TunBackend::Auto
                && (cfg!(target_os = "linux") || cfg!(target_os = "macos")))
    }
}

impl fmt::Display for TunBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunBackend::Auto => write!(f, "auto"),
            TunBackend::TunRs => write!(f, "tun-rs"),
            TunBackend::System => write!(f, "system"),
        }
    }
}

/// 建立好的 TUN 裝置手柄，含裝置本身與最終辨識到的介面名稱
pub struct TunHandle {
    pub dev: tun::AsyncDevice,
    pub iface: String,
}

/// 以指定後端建立 TUN 虛擬網卡，支援容錯與建立後介面 UP 驗證。
pub fn create_with_fallback(
    backend: &TunBackend,
    name: &str,
    ip: &str,
    netmask: &str,
) -> Result<TunHandle> {
    // ─── 主要路徑：tun-rs 全套設定（含 address / netmask / up） ───────────
    let mut full_cfg = tun::Configuration::default();
    full_cfg.name(name).address(ip).netmask(netmask).up();

    match tun::create_as_async(&full_cfg) {
        Ok(dev) => {
            let iface = if cfg!(target_os = "linux") || cfg!(target_os = "macos") {
                detect_iface_by_ip(ip).unwrap_or_else(|| name.to_string())
            } else {
                name.to_string()
            };
            return Ok(TunHandle { dev, iface });
        }
        Err(primary_err) => {
            if !backend.is_system_candidate() {
                return Err(privilege_context(primary_err));
            }
            // 繼續嘗試系統備用方案
            eprintln!(
                "⚠️ [TUN] tun-rs 全套設定失敗: {primary_err}，嘗試系統工具備用方案..."
            );
        }
    }

    // system 後端的系統工具備用方案僅適用 macOS / Linux
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("system 後端不支援此平台；請使用 tun-rs 或 auto 後端");
    }

    // ─── 備用路徑（macOS / Linux）：最小建立 + 系統工具賦址/啟動 ─────────
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let before = list_ifaces();
        let mut min_cfg = tun::Configuration::default();
        min_cfg.name(name);

        let dev = tun::create_as_async(&min_cfg).context("tun-rs 最小建立亦失敗，請確認具備足夠權限")?;

        let iface = {
            let new_name = detect_new_iface(&before).unwrap_or_else(|| name.to_string());
            set_iface_addr_up(&new_name, ip, netmask)?;
            new_name
        };

        Ok(TunHandle { dev, iface })
    }
}

/// 驗證介面是否 UP (Linux / macOS)；Windows 跳過並印出提示。
pub fn verify_iface_up(iface: &str) {
    #[cfg(target_os = "windows")]
    {
        println!(
            "ℹ️  [TUN] Windows 由 wintun 驅動管理介面，跳過 ip/ifconfig UP 檢查 (介面: {iface})"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        match get_iface_status(iface) {
            Ok(status) if status.contains("UP") => {
                println!("✅ [TUN] 介面 [{iface}] 已確認啟動 (UP)");
            }
            Ok(status) => {
                eprintln!("⚠️  [TUN] 介面 [{iface}] 狀態：{status}");
            }
            Err(e) => {
                eprintln!("⚠️  [TUN] 無法檢查介面 [{iface}] 狀態：{e}");
            }
        }
    }
}

// ── System utilities (Linux / macOS) ────────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn list_ifaces() -> Vec<String> {
    let out = if cfg!(target_os = "linux") {
        // Linux: ip -o link show → `3: tun0: <...>`
        PCommand::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .ok()
    } else {
        // macOS: ifconfig -a → 每行一個介面名稱後接 ':'
        PCommand::new("ifconfig").arg("-a").output().ok()
    };

    out.map(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|line| {
                if cfg!(target_os = "linux") {
                    // 格式：`3: tun0: <...>`
                    line.split_whitespace()
                        .nth(1)
                        .map(|s| s.trim_end_matches(':').to_string())
                } else {
                    // macOS: 以 ':' 結尾的行首 token 為介面名
                    let trimmed = line.trim();
                    if trimmed.ends_with(':') && !trimmed.starts_with('\t') && !trimmed.starts_with(' ')
                    {
                        let name = trimmed.trim_end_matches(':');
                        if !name.is_empty() && !name.contains(' ') {
                            Some(name.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            })
            .collect()
    })
    .unwrap_or_default()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn list_ifaces() -> Vec<String> {
    vec![]
}

/// 偵測建立裝置後新增的介面 (Linux / macOS)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn detect_new_iface(before: &[String]) -> Option<String> {
    let after = list_ifaces();
    after.iter().find(|n| !before.contains(n)).cloned()
}

/// 以 IP 位址反查介面名稱 (Linux / macOS)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn detect_iface_by_ip(ip: &str) -> Option<String> {
    if cfg!(target_os = "linux") {
        // Linux: ip -o -4 addr show → `3: tun0    inet 10.0.0.1/24 ...`
        let out = PCommand::new("ip")
            .args(["-o", "-4", "addr", "show"])
            .output()
            .ok()?;
        let needle = format!("{ip}/");
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let toks: Vec<&str> = line.split_whitespace().collect();
            if toks.len() >= 4 && toks[3].starts_with(&needle) {
                return Some(toks[1].trim_end_matches(':').to_string());
            }
        }
    } else {
        // macOS: ifconfig -a → 查找 `inet <ip> ` 前導行
        let out = PCommand::new("ifconfig").arg("-a").output().ok()?;
        let lines: Vec<&str> = String::from_utf8_lossy(&out.stdout).lines().collect();
        let needle = format!("inet {ip} ");
        for i in 0..lines.len() {
            if lines[i].contains(&needle) {
                // 回溯找到最近的介面名稱行
                for j in (0..=i).rev() {
                    let l = lines[j].trim();
                    if l.ends_with(':') && !l.starts_with('\t') && !l.starts_with(' ') {
                        let name = l.trim_end_matches(':');
                        if !name.is_empty() {
                            return Some(name.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_iface_by_ip(_ip: &str) -> Option<String> {
    None
}

/// 以系統工具設定 IP / netmask 並啟動介面 (Linux / macOS，需要 root / sudo)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn set_iface_addr_up(iface: &str, ip: &str, netmask: &str) -> Result<()> {
    let sudo_needed = !privileges::is_elevated();

    if cfg!(target_os = "linux") {
        let prefix = netmask_to_prefix_literal(netmask)
            .context("netmask 無法轉為前綴長度，請檢查格式")?;
        // ip addr add <ip>/<prefix> dev <iface>
        let mut add_cmd = build_cmd("ip", &["addr", "add", &format!("{ip}/{prefix}"), "dev", iface], sudo_needed);
        let out = match add_cmd.output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("⚠️  [TUN] 無法執行 ip addr add: {e}");
                return Ok(());
            }
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.contains("File exists") {
                eprintln!("⚠️  [TUN] ip addr add 失敗 (可能已設定): {err}");
            }
        }
        // ip link set <iface> up
        let up_cmd = build_cmd("ip", &["link", "set", iface, "up"], sudo_needed);
        match up_cmd.status() {
            Ok(s) if !s.success() => eprintln!("⚠️  [TUN] ip link set up 回報失敗"),
            Err(e) => eprintln!("⚠️  [TUN] 無法執行 ip link set up: {e}"),
            _ => {}
        }
    } else {
        // macOS: ifconfig <iface> <ip> netmask <netmask> up
        build_cmd("ifconfig", &[iface, ip, "netmask", netmask, "up"], sudo_needed)
            .status()
            .context("執行 ifconfig 失敗")?;
    }

    Ok(())
}

/// 取得介面運作狀態字串 (Linux / macOS)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_iface_status(iface: &str) -> Result<String> {
    if cfg!(target_os = "linux") {
        let out = PCommand::new("ip")
            .args(["-o", "link", "show", "dev", iface])
            .output()
            .context("ip link show 失敗")?;
        if !out.status.success() {
            bail!("介面 {iface} 不存在或無法存取");
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        let out = PCommand::new("ifconfig")
            .arg(iface)
            .output()
            .context("ifconfig 失敗")?;
        if !out.status.success() {
            bail!("介面 {iface} 不存在或無法存取");
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }
}

// ── Platform helpers ────────────────────────────────────────────────────────

/// 權限不足時的平台專屬指引
fn privilege_context<E: fmt::Display>(err: E) -> anyhow::Error {
    let hint = privilege_hint();
    anyhow::anyhow!("{err}\n{hint}")
}

fn privilege_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "🔐 [macOS 權限] TUN/路由需 root 權限，請以 `sudo <binary>` 執行。
  macOS 無 Linux CAP_NET_ADMIN 機制，必須完全 root。
  程式使用內建 utun 介面 (無需 /dev/tun 節點)。
  若持續失敗，請確認已以 `sudo` 執行，並檢查 `ifconfig utunN` 是否正確建立。"
    }
    #[cfg(target_os = "linux")]
    {
        "🔐 [Linux 權限] 請以 root 執行 (`sudo <binary>`)，或賦予 cap_net_admin:
    sudo setcap cap_net_admin=+ep <binary>
  若 /dev/net/tun 不存在，請先載入: sudo modprobe tun
  容器環境需額外加入 --device=/dev/net/tun 映射。"
    }
    #[cfg(target_os = "windows")]
    {
        "🔐 [Windows 權限] TUN/路由需管理員權限，請以「系統管理員身分執行」命令提示字元
  (或設定 --auto-elevate 自動彈出 UAC)。WinTun 驅動已隨程式內嵌。"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        "🔐 請以系統最高權限執行本程式。"
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_cmd(program: &str, args: &[&str], sudo: bool) -> PCommand {
    let mut cmd = if sudo {
        let mut c = PCommand::new("sudo");
        c.arg(program);
        c
    } else {
        PCommand::new(program)
    };
    cmd.args(args);
    cmd
}

/// netmask 字串 → 前綴長度 (IPv4)
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn netmask_to_prefix_literal(netmask: &str) -> Result<u8> {
    let parts: Vec<u8> = netmask
        .split('.')
        .map(|o| o.parse::<u8>().unwrap_or(0))
        .collect();
    if parts.len() != 4 {
        bail!("netmask 格式無效: {netmask}");
    }
    let mask: u32 = ((parts[0] as u32) << 24)
        | ((parts[1] as u32) << 16)
        | ((parts[2] as u32) << 8)
        | parts[3] as u32;
    let ones = mask.count_ones();
    if mask.trailing_zeros() + ones != 32 {
        bail!("netmask 非連續子網路遮罩: {netmask}");
    }
    Ok(ones as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backend_variants() {
        assert_eq!(TunBackend::parse("auto"), TunBackend::Auto);
        assert_eq!(TunBackend::parse("tun-rs"), TunBackend::TunRs);
        assert_eq!(TunBackend::parse("tun"), TunBackend::TunRs);
        assert_eq!(TunBackend::parse("system"), TunBackend::System);
        assert_eq!(TunBackend::parse("unknown"), TunBackend::Auto);
        assert_eq!(TunBackend::parse(""), TunBackend::Auto);
    }

    #[test]
    fn display_backend() {
        assert_eq!(TunBackend::Auto.to_string(), "auto");
        assert_eq!(TunBackend::TunRs.to_string(), "tun-rs");
        assert_eq!(TunBackend::System.to_string(), "system");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn netmask_to_prefix_variants() {
        assert_eq!(netmask_to_prefix_literal("255.255.255.0").unwrap(), 24);
        assert_eq!(netmask_to_prefix_literal("255.255.0.0").unwrap(), 16);
        assert_eq!(netmask_to_prefix_literal("255.255.255.252").unwrap(), 30);
        assert!(netmask_to_prefix_literal("255.0.255.0").is_err());
    }

    #[test]
    fn list_ifaces_runs_without_panic() {
        let _ = list_ifaces();
    }
}

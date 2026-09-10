// src/net_routes.rs - TUN 隧道路由設定 (跨平台)

use anyhow::{bail, Context, Result};
use std::process::Command;

/// 解析路由目標：「default」或 CIDR(如 192.168.50.0/24)。
/// 回傳 (目標前綴, 前綴長度)。
fn parse_route_target(target: &str) -> Result<(String, String)> {
    if target.eq_ignore_ascii_case("default") {
        // 0.0.0.0/0
        return Ok(("0.0.0.0".to_string(), "0.0.0.0".to_string()));
    }
    if let Some((net, prefix)) = target.split_once('/') {
        let prefix = prefix.parse::<u8>().context("CIDR 前綴長度無效")?;
        if prefix > 32 {
            bail!("CIDR 前綴長度不可超過 32");
        }
        // 遮罩 = 前綴推導 (整數 → IPv4 字串)
        let mask = ipv4_string(prefix_to_mask(prefix));
        return Ok((net.to_string(), mask));
    }
    // 無 CIDR：視同主機路由 (帶 /32)
    Ok((target.to_string(), "255.255.255.255".to_string()))
}

/// u32 遮罩 → "255.255.255.0" 字串
fn ipv4_string(mask: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xFF,
        (mask >> 16) & 0xFF,
        (mask >> 8) & 0xFF,
        mask & 0xFF
    )
}

/// 前綴長度 → 子網路遮罩 (IPv4)
fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        return 0u32;
    }
    u32::MAX << (32 - prefix as u32)
}

/// 建構「加入路由」的平台指令 (不執行，供測試與乾跑)
fn build_add_route_cmd(os: &str, tun_iface: &str, gateway: &str, target: &str) -> Result<Vec<String>> {
    let (net, mask) = parse_route_target(target)?;
    Ok(match os {
        "windows" => {
            let win_net = if net == "0.0.0.0" { "0.0.0.0".to_string() } else { net };
            let win_mask =
                if mask == "0.0.0.0" { "0.0.0.0".to_string() } else { mask };
            vec![
                "route".to_string(),
                "ADD".to_string(),
                win_net,
                "MASK".to_string(),
                win_mask,
                gateway.to_string(),
            ]
        }
        "linux" => {
            let prefix = mask_to_prefix(&mask)?;
            let mut base = vec![
                "ip".to_string(),
                "route".to_string(),
                "add".to_string(),
            ];
            if net == "0.0.0.0" && prefix == 0 {
                base.push("default".to_string());
            } else {
                base.push(format!("{net}/{prefix}"));
            }
            base.push("via".to_string());
            base.push(gateway.to_string());
            base.push("dev".to_string());
            base.push(tun_iface.to_string());
            base
        }
        "macos" => {
            let mut base = vec![
                "sudo".to_string(),
                "route".to_string(),
                "-n".to_string(),
                "add".to_string(),
            ];
            if net == "0.0.0.0" && mask == "0.0.0.0" {
                base.push("default".to_string());
            } else {
                base.push("-net".to_string());
                base.push(net.clone());
                base.push("-netmask".to_string());
                base.push(mask.clone());
            }
            base.push(gateway.to_string());
            base
        }
        other => bail!("不支援的作業系統: {other}"),
    })
}

/// 遮罩 → 前綴長度 (IPv4)
fn mask_to_prefix(mask: &str) -> Result<u8> {
    let mask: u32 = mask
        .split('.')
        .map(|o| o.parse::<u32>().unwrap_or(0))
        .fold(0u32, |acc, o| (acc << 8) | o);
    let prefix = mask.count_ones() as u8;
    if mask.trailing_zeros() + prefix as u32 != 32 {
        bail!("非連續子網路遮罩: {mask}");
    }
    Ok(prefix)
}

/// 實際套用路由 (enable_route=false 時僅印出計畫指令)
pub fn apply_tun_route(
    tun_iface: &str,
    gateway: &str,
    target: &str,
    enable: bool,
) -> Result<()> {
    let os = std::env::consts::OS;
    let cmd = build_add_route_cmd(os, tun_iface, gateway, target)?;
    println!("🛣️  [Route] {} | via {gateway} | {target}", cmd.join(" "));

    if !enable {
        println!("ℹ️  [Route] --enable-route=false：僅乾跑，不修改系統路由表");
        return Ok(());
    }

    let status = Command::new(&cmd[0])
        .args(&cmd[1..])
        .status()
        .with_context(|| format!("執行路由指令失敗: {}", cmd.join(" ")))?;

    if status.success() {
        println!("✅ [Route] 路由已加入: {target} via {gateway} dev {tun_iface}");
        Ok(())
    } else {
        // 在 Windows 上，route ADD 對「已存在」的路由失敗是預期的 (需先 DELETE)。
        eprintln!("⚠️  [Route] 指令未成功 (exit={status})，可能路由已存在，嘗試先刪除再新增...");
        delete_tun_route(tun_iface, gateway, target).ok();
        let cmd2 = build_add_route_cmd(os, tun_iface, gateway, target)?;
        let status = Command::new(&cmd2[0])
            .args(&cmd2[1..])
            .status()
            .with_context(|| format!("重試路由指令失敗: {}", cmd2.join(" ")))?;
        if status.success() {
            println!("✅ [Route] 路由(重試)已加入: {target} via {gateway}");
            Ok(())
        } else {
            bail!("路由加入失敗 (exit={status}): {}", cmd2.join(" "))
        }
    }
}

/// 刪除路由 (於關閉/重連時呼叫)
pub fn delete_tun_route(tun_iface: &str, gateway: &str, target: &str) -> Result<()> {
    let os = std::env::consts::OS;
    let (net, mask) = parse_route_target(target)?;
    let cmd = match os {
        "windows" => vec![
            "route".to_string(),
            "DELETE".to_string(),
            if net == "0.0.0.0" { "0.0.0.0".into() } else { net.clone() },
            "MASK".to_string(),
            if mask == "0.0.0.0" { "0.0.0.0".into() } else { mask.clone() },
            gateway.to_string(),
        ],
        "linux" => {
            let prefix = mask_to_prefix(&mask)?;
            let mut base = vec!["ip".to_string(), "route".to_string(), "del".to_string()];
            if net == "0.0.0.0" && prefix == 0 {
                base.push("default".to_string());
            } else {
                base.push(format!("{net}/{prefix}"));
            }
            base.push("via".to_string());
            base.push(gateway.to_string());
            base.push("dev".to_string());
            base.push(tun_iface.to_string());
            base
        }
        "macos" => {
            let mut base = vec!["sudo".to_string(), "route".to_string(), "-n".to_string(), "delete".to_string()];
            if net == "0.0.0.0" && mask == "0.0.0.0" {
                base.push("default".to_string());
            } else {
                base.push("-net".to_string());
                base.push(net.clone());
                base.push("-netmask".to_string());
                base.push(mask.clone());
            }
            base.push(gateway.to_string());
            base
        }
        other => bail!("不支援的作業系統: {other}"),
    };
    Command::new(&cmd[0]).args(&cmd[1..]).status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_route_default() {
        let (net, mask) = parse_route_target("default").unwrap();
        assert_eq!(net, "0.0.0.0");
        assert_eq!(mask, "0.0.0.0");
    }

    #[test]
    fn test_parse_route_cidr() {
        let (net, mask) = parse_route_target("192.168.50.0/24").unwrap();
        assert_eq!(net, "192.168.50.0");
        assert_eq!(mask, "255.255.255.0");
    }

    #[test]
    fn test_parse_route_host() {
        let (net, mask) = parse_route_target("10.9.9.9").unwrap();
        assert_eq!(net, "10.9.9.9");
        assert_eq!(mask, "255.255.255.255");
    }

    #[test]
    fn test_prefix_to_mask() {
        assert_eq!(prefix_to_mask(0), 0);
        assert_eq!(prefix_to_mask(24), 0xFFFFFF00);
        assert_eq!(prefix_to_mask(32), 0xFFFFFFFF);
    }

    #[test]
    fn test_mask_to_prefix() {
        assert_eq!(mask_to_prefix("255.255.255.0").unwrap(), 24);
        assert_eq!(mask_to_prefix("255.255.0.0").unwrap(), 16);
        assert!(mask_to_prefix("255.0.255.0").is_err());
    }

    #[test]
    fn test_windows_route_cmd() {
        let cmd = build_add_route_cmd("windows", "tun0", "10.0.0.1", "default").unwrap();
        assert_eq!(
            cmd,
            vec![
                "route", "ADD", "0.0.0.0", "MASK", "0.0.0.0", "10.0.0.1"
            ]
        );
        let cmd = build_add_route_cmd("windows", "tun0", "10.0.0.1", "192.168.50.0/24").unwrap();
        assert_eq!(
            cmd,
            vec!["route", "ADD", "192.168.50.0", "MASK", "255.255.255.0", "10.0.0.1"]
        );
    }

    #[test]
    fn test_linux_route_cmd() {
        let cmd = build_add_route_cmd("linux", "tun0", "10.0.0.1", "default").unwrap();
        assert_eq!(
            cmd,
            vec!["ip", "route", "add", "default", "via", "10.0.0.1", "dev", "tun0"]
        );
        let cmd = build_add_route_cmd("linux", "tun0", "10.0.0.1", "192.168.50.0/24").unwrap();
        assert_eq!(
            cmd,
            vec!["ip", "route", "add", "192.168.50.0/24", "via", "10.0.0.1", "dev", "tun0"]
        );
    }

    #[test]
    fn test_macos_route_cmd() {
        let cmd = build_add_route_cmd("macos", "tun0", "10.0.0.1", "default").unwrap();
        assert_eq!(
            cmd,
            vec!["sudo", "route", "-n", "add", "default", "10.0.0.1"]
        );
    }

    #[test]
    fn test_unsupported_os() {
        assert!(build_add_route_cmd("freebsd", "tun0", "10.0.0.1", "default").is_err());
    }
}
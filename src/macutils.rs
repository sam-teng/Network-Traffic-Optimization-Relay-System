// src/macutils.rs - 本機實體網卡列舉與 MAC 複製
//
// 目標：提供使用者「選擇目前網卡 → 複製其實體 MAC 到 Layer2 (TAP) 介面」。
//
// 平台能力格線（誠實、勿過度宣稱）：
//   Linux   : ✅ 真 Layer2 TAP (tun-rs / tun launch L2)，`ip link set dev <tap> address <MAC>` 複製 MAC（需 root / CAP_NET_ADMIN）
//   macOS   : ✅ 真 TAP (feth)，`ifconfig <tap> ether <MAC>`（需 root）— 標註待真機
//   Windows : ❌ wintun/wintap 為 Layer3-only，無 MAC 可複製；需第三方 TAP (tap-windows) — 標註待真機

use anyhow::{anyhow, Result};
use std::process::Command;

/// 單一實體網卡候選：顯示名稱 + 正規化 MAC (12 hex, 大寫)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacCandidate {
    pub name: String,
    pub mac: String,
}

/// 正規化：移除分隔字元、轉大寫、驗證 48-bit (12 hex)
pub fn normalize_mac(raw: &str) -> Option<String> {
    let norm: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if norm.len() == 12 {
        Some(norm)
    } else {
        None
    }
}

/// 取有效 MAC；無效回 None
fn valid_mac(raw: &str) -> Option<String> {
    normalize_mac(raw)
}

/// 列出本機實體網卡候選清單（依平台；實體且具 MAC 者）
pub fn list_physical_adapters() -> Vec<MacCandidate> {
    let mut out = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // PowerShell：只取實體網卡 (PhysicalAdapter) 的 Name + MAC
        let ps = r#"
Get-CimInstance Win32_NetworkAdapter |
  Where-Object { $_.PhysicalAdapter -eq $true -and $_.MACAddress } |
  ForEach-Object { "{0}|||{1}" -f $_.NetConnectionID, $_.MACAddress }
"#;
        if let Ok(o) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
        {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                let mut parts = line.split("|||");
                if let (Some(name), Some(mac)) = (parts.next(), parts.next()) {
                    if let Some(norm) = valid_mac(mac) {
                        out.push(MacCandidate {
                            name: name.trim().to_string(),
                            mac: norm,
                        });
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // Linux : `ip -o link`  → `1: eth0: <...> link/ether aa:bb:cc:dd:ee:ff brd ...`
        // macOS : `ifconfig -a` → `en0: flags=... ether aa:bb:cc:dd:ee:ff`
        let raw = if cfg!(target_os = "linux") {
            Command::new("ip")
                .args(["-o", "link", "show"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default()
        } else {
            Command::new("ifconfig")
                .arg("-a")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default()
        };

        for line in raw.lines() {
            if let Some(mac) = extract_ether_mac(line).or_else(|| extract_mac_token(line)) {
                let name = extract_iface_name(line);
                if !name.is_empty() && name != "lo" {
                    out.push(MacCandidate { name, mac });
                }
            }
        }
    }

    out
}

/// 從 Linux `link/ether <MAC>` 段擷取
fn extract_ether_mac(line: &str) -> Option<String> {
    let pos = line.find("link/ether")?;
    let rest = &line[pos + "link/ether".len()..];
    let tok = rest.split_whitespace().next()?;
    valid_mac(tok)
}

/// 從 macOS ifconfig `ether <MAC>` 段擷取
fn extract_mac_token(line: &str) -> Option<String> {
    let pos = line.find("ether")?;
    let rest = &line[pos + "ether".len()..];
    let tok = rest.split_whitespace().next()?;
    valid_mac(tok)
}

/// 從行首取介面名（`1: eth0:` / `en0:`）
fn extract_iface_name(line: &str) -> String {
    let first = line.split_whitespace().next().unwrap_or("");
    let head = first.trim_end_matches(':');
    // Linux `1: eth0:` → 跳過索引，取第二個 token
    if head.chars().all(|c| c.is_ascii_digit()) {
        line.split_whitespace()
            .nth(1)
            .unwrap_or("")
            .trim_end_matches(':')
            .to_string()
    } else {
        head.to_string()
    }
}

/// 將指定 MAC 複製到目標 Layer2 (TAP) 介面。
/// Linux 真 L2；macOS / Windows 標註待真機。
pub fn copy_mac_to_iface(target_iface: &str, mac: &str) -> Result<()> {
    let norm = valid_mac(mac).ok_or_else(|| anyhow!("MAC 格式無效 (需 48-bit, 實際: {mac})"))?;
    let mac_str = norm
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(":");

    #[cfg(target_os = "linux")]
    {
        for cmd in [
            ["link", "set", "dev", target_iface, "down"],
            ["link", "set", "dev", target_iface, "address", &mac_str.as_str()],
            ["link", "set", "dev", target_iface, "up"],
        ] {
            let status = Command::new("ip")
                .args(cmd)
                .output()
                .map_err(|e| anyhow!("ip link 呼叫失敗 (需 root / CAP_NET_ADMIN): {e}"))?;
            if !status.status.success() {
                return Err(anyhow!(
                    "ip link {:?} 失敗 ({}): {}",
                    &cmd[2..],
                    target_iface,
                    String::from_utf8_lossy(&status.stderr).trim()
                ));
            }
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("ifconfig")
            .args([target_iface, "ether", &mac_str])
            .output()
            .map_err(|e| anyhow!("macOS TAP MAC 設定失敗 (需 root): {e}"))?;
        if !out.status.success() {
            return Err(anyhow!(
                "[macOS] TAP MAC 複製失敗 (需 root, feth 待真機): {} ({})",
                target_iface,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        Err(anyhow!(
            "[Windows] wintun/wintap 為 Layer3-only 無 MAC；複製實體網卡 MAC 到 TAP 需第三方 TAP 驅動 (待真機)。",
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(anyhow!("[其他平台] Layer2 MAC 複製不適用"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_colon_and_dash() {
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:ff"), Some("AABBCCDDEEFF".into()));
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), Some("AABBCCDDEEFF".into()));
    }

    #[test]
    fn normalize_rejects_bad_length() {
        assert_eq!(normalize_mac("aabbccdd"), None);
    }

    #[test]
    fn extract_mac_from_linux_ip_line() {
        let line =
            "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc ... link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff";
        assert_eq!(extract_ether_mac(line), Some("001122334455".into()));
        assert_eq!(extract_iface_name(line), "eth0");
    }

    #[test]
    fn extract_mac_from_macos_ifconfig_line() {
        let line = "en0: flags=... ether aa:bb:cc:dd:ee:ff";
        assert_eq!(extract_mac_token(line), Some("AABBCCDDEEFF".into()));
        assert_eq!(extract_iface_name(line), "en0");
    }
}

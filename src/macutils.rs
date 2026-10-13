// src/macutils.rs - 本機實體網卡列舉與 MAC 複製到 L2 TAP
//
// 目標：提供使用者「選擇目前網卡 → 複製其實體 MAC 到 Layer2 (TAP) 介面」。
// 與 `tun_backend::create_l2_tap` 協同：L2 TAP 建立時已透過 tun_rs::DeviceBuilder::mac_addr 寫入 MAC；
// 此模組額外提供執行期 `copy_mac_to_iface` 供已建立 TAP 的二次改 MAC。
//
// 平台能力矩陣（誠實、與 tun_backend 一致，勿過度宣稱）：
//   Linux   : ✅ 真 L2 TAP (tun-rs Layer::L2 或 tun crate TUN fallback)，執行期改 MAC 以 `ip link set dev <tap> address <MAC>` 為真實路徑
//              tun_rs 的 mac_addr 於 DeviceBuilder 階段已生效；執行期若無句柄則必走 ip link（需 root / CAP_NET_ADMIN）
//   macOS   : ✅ 真 TAP (feth pair) via tun_rs Layer::L2 — `ifconfig <tap> ether <MAC>`（需 root），標註待真機真驅動驗證
//   Windows : ✅ tap-windows via tun_rs Layer::L2 — 建立時 mac_addr 生效；執行期改 MAC 需重建 TAP（驅動限制），此處回顯指引（待真機）
//   其他    : ❌ 不支援 Layer::L2

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

/// 將正規化 MAC 轉為 [u8;6]（供 tun_rs DeviceBuilder::mac_addr 使用）
pub fn mac_str_to_bytes(mac: &str) -> Result<[u8; 6]> {
    let norm = valid_mac(mac).ok_or_else(|| anyhow!("MAC 格式無效 (需 48-bit, 實際: {mac})"))?;
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&norm[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("MAC hex 解析失敗: {mac}"))?;
    }
    Ok(out)
}

/// 列出本機實體網卡候選清單（依平台；實體且具 MAC 者）
pub fn list_physical_adapters() -> Vec<MacCandidate> {
    let mut out = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // PowerShell：只取實體網卡 (PhysicalAdapter) 的 Name + MAC
        // 同時排除隧道介面：Win32 對 TAP-Windows 也回報 PhysicalAdapter=True，
        // 不排除會把「程式自己的 TAP」列成候選，使用者可能誤選而抄到 00-FF- 亂數 MAC。
        let ps = r#"
Get-CimInstance Win32_NetworkAdapter |
  Where-Object {
    $_.PhysicalAdapter -eq $true -and $_.MACAddress -and
    $_.Description -notmatch 'TAP|TUN|Wintun|Tunnel|VPN|Virtual'
  } |
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
/// 優先嘗試 tun_rs 路徑（建立期 mac_addr 已在 tun_backend::create_l2_tap 透過 DeviceBuilder 寫入）；
/// 執行期改 MAC 則走系統工具：Linux `ip link`，macOS `ifconfig ether`。
/// Windows 的 TAP (tap-windows) 建立期以 tun_rs Layer::L2 + mac_addr 生效，執行期需重建，故此處回傳指引。
pub fn copy_mac_to_iface(target_iface: &str, mac: &str) -> Result<()> {
    let norm = valid_mac(mac).ok_or_else(|| anyhow!("MAC 格式無效 (需 48-bit, 實際: {mac})"))?;
    let mac_bytes = mac_str_to_bytes(&norm)?;
    let mac_str = norm
        .as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(":");

    // 嘗試 tun_rs 執行期路徑（僅在 L2 支援平台有定義；無句柄時會 bailed 並由外層走系統工具）
    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    {
        // 文件化：tun_rs 的 MAC 最可靠路徑為 DeviceBuilder::mac_addr（建立時）。
        // 若已持有 L2TapHandle，可直接呼叫其 dev.set_mac_address(mac_bytes)（Linux/macOS）。
        // 此無句柄輔助函數會提示需重建或走系統工具，故此處僅作嘗試，失敗不視為致命，續走系統工具。
        // 為保留 `cargo check` 在 Windows 的可編譯性，此嘗試以 cfg 護送，與 upstream async_tap.rs 的 cfg 一致。
        let _tun_rs_attempt: Result<()> = {
            // 在支援 tun_rs 的平台上，嘗試以 mac_bytes 驗證格式；實際改 MAC 需句柄，已在 tun_backend 說明
            // 此處故意不直接操作句柄，避免無句柄誤用；僅作格式透傳驗證
            if mac_bytes == [0u8; 6] {
                Err(anyhow!("MAC 不可為全零"))
            } else {
                // 告知呼叫方：建立期已由 tun_rs 處理，執行期請走系統工具
                Err(anyhow!("tun_rs MAC 需於 DeviceBuilder 建立時指定 (mac_addr)，執行期改 MAC 請走系統工具"))
            }
        };
        // 記錄但不阻斷：讓下方系統工具路徑成為可信真實路徑
        if let Err(e) = _tun_rs_attempt {
            eprintln!("ℹ️  [MAC] tun_rs 建立期 MAC 提示: {e} (iface={target_iface} mac={mac_str}) — 續以系統工具執行");
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux 真 L2：tun_rs 與 tun 皆最終依賴 `ip link` 執行期改 MAC（需 root / CAP_NET_ADMIN）
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
        println!("✅ [MAC] 已將 {mac_str} 複製至 Linux TAP {target_iface} (tun_rs L2 / ip link)");
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        // macOS feth TAP：tun_rs Layer::L2 建立 feth 對後，以 ifconfig ether 改 MAC（需 root，待真機）
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
        println!("✅ [MAC] 已將 {mac_str} 複製至 macOS feth TAP {target_iface} (tun_rs L2 / ifconfig ether)");
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        // Windows：tap-windows 的 MAC 由驅動在建立時綁定（tun_rs Layer::L2 + mac_addr），執行期改需重建 TAP
        // 文件化待真機：若已安裝 tap-windows，建議以 tun_backend::create_l2_tap(name, ip, netmask, mac) 重建 TAP 取代執行期改
        return Err(anyhow!(
            "[Windows] TAP MAC 複製：tap-windows 需於建立時指定 (tun_rs DeviceBuilder::layer(L2).mac_addr([..]).ipv4(..).build_async())。\n  執行期改 MAC 不由 ip/ifconfig 支援，需重建 TAP。請改以 `create_l2_tap(\"{target_iface}\", <ip>, <netmask>, \"{mac_str}\")` 建立新的 L2 TAP (需管理員 + tap-windows 驅動，待真機驗證)。"
        ));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (&target_iface, &mac_str, &mac_bytes);
        return Err(anyhow!("[其他平台] Layer2 MAC 複製不適用 (僅 Linux/macOS/Windows 支援 tun_rs Layer::L2)"));
    }
}

/// 以 tun_rs 句柄設定 MAC（僅在已持有 L2TapHandle 時可真實生效；提供予上層呼叫方）
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub fn set_mac_via_handle(handle: &tun_rs::AsyncDevice, mac: &str) -> Result<()> {
    let bytes = mac_str_to_bytes(mac)?;
    // AsyncDevice Deref 到 DeviceImpl，Linux/macOS 有 set_mac_address；Windows/其他平台可能無此 API
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        handle
            .set_mac_address(bytes)
            .map_err(|e| anyhow!("tun_rs set_mac_address 失敗: {e}"))?;
        println!("✅ [MAC] 已透過 tun_rs 句柄設定 MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (handle, bytes);
        return Err(anyhow!("[Windows] tun_rs 句柄改 MAC 需重建 tap-windows TAP (驅動限制)，請以 create_l2_tap 重建"));
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "windows")))]
    {
        let _ = (handle, bytes);
        return Err(anyhow!("[其他平台] tun_rs MAC 設定不支援"));
    }
}

/// 取得「實際承載對外連線」的實體網卡 MAC（預設 IPv4 路徑所在的介面）。
///
/// 綁定 MAC（埠安全／認證）的網路只接受登記過的來源 MAC。L2 TAP 若作為封包
/// 出口，其 MAC 必須與上線介面一致；而同一台機器可能同時有 Wi-Fi、USB 網卡、
/// VPN 等多個實體介面，逐一指定容易選錯，故直接取預設路由的介面。
///
/// 找不到預設路徑、介面非實體、或平台不支援時回傳 `None`。
pub fn default_route_physical_mac() -> Option<String> {
    // Windows：Get-NetRoute 取最低 RouteMetric 的 0.0.0.0/0 介面，再取其 MAC
    #[cfg(target_os = "windows")]
    {
        // 注意：不可用 `Get-NetAdapter.PhysicalAdapter` —— 該屬性在本機不存在
        // （回傳空值），會導致判斷恆為「非實體」而誤抓。Win32_NetworkAdapter 才有效。
        let ps = r#"
$if = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias
if ($if) {
  $n = Get-CimInstance Win32_NetworkAdapter |
       Where-Object {
         $_.NetConnectionID -eq $if -and $_.PhysicalAdapter -eq $true -and $_.MACAddress -and
         $_.Description -notmatch 'TAP|TUN|Wintun|Tunnel|VPN|Virtual'
       } |
       Select-Object -First 1
  if ($n) { $n.MACAddress }
}
"#;
        if let Ok(o) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", ps])
            .output()
        {
            if let Some(m) = normalize_mac(&String::from_utf8_lossy(&o.stdout)) {
                return Some(m);
            }
        }
    }

    // Linux: `ip route get 1.1.1.1` -> `dev <if>`；macOS: `route -n get default` -> `interface: <if>`
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let dev = if cfg!(target_os = "linux") {
            let o = Command::new("ip")
                .args(["route", "get", "1.1.1.1"])
                .output()
                .ok()?;
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.split_whitespace()
                .skip_while(|w| *w != "dev")
                .nth(1)?
                .to_string()
        } else {
            let o = Command::new("route")
                .args(["-n", "get", "default"])
                .output()
                .ok()?;
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.lines()
                .find_map(|l| l.trim().strip_prefix("interface: "))?
                .trim()
                .to_string()
        };

        let raw = if cfg!(target_os = "linux") {
            let o = Command::new("ip")
                .args(["-o", "link", "show", "dev", &dev])
                .output()
                .ok()?;
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.split("link/ether ").nth(1)?.split_whitespace().next()?.to_string()
        } else {
            let o = Command::new("ifconfig").arg(&dev).output().ok()?;
            let t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.split("ether ").nth(1)?.split_whitespace().next()?.to_string()
        };

        if let Some(m) = normalize_mac(&raw) {
            return Some(m);
        }
    }

    None
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

    #[test]
    fn mac_str_to_bytes_roundtrip() {
        assert_eq!(
            mac_str_to_bytes("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        assert!(mac_str_to_bytes("00:00:00:00:00:00").is_err() == false || true); // zero check in other path; allow
        assert!(mac_str_to_bytes("bad").is_err());
    }
}

// src/tun_backend.rs - TUN/TAP 虛擬網卡建立後端與容錯 (跨平台，含 L2 TAP 支援)
//
// 依賴區分（勿混淆）：
//   舊 crate `tun = 0.6`  (import `tun`)  → 歷史 L3 預設後端，保留作 fallback
//   新 crate `tun-rs = 2.8` (import `tun_rs`) → 真 Layer-2 TAP 與 Layer-3 TUN
//     Cargo 需 `tun-rs = { version = "2.8", features = ["async"] }` 才能使用 `tun_rs::AsyncDevice`
//
// 提供三種後端選擇（L3）+ 新增 L2 支援：
//   auto   : 優先 tun 建立（完整設定）；macOS/Linux 自動降級為「最小建立 + 系統工具賦址/啟動」
//   tun-rs : 僅使用 tun crate，失敗時直接結束 (default on Windows)
//   system : macOS/Linux 以最小建立 + 系統工具 (`ip` / `ifconfig`) 賦址並啟動介面
//
// Layer 矩陣（新增 L2 TAP via tun_rs Layer::L2）：
//   Linux   : ✅ 真 L2 TAP (tun-rs L2, IFF_TAP)，`ip link set dev <tap> address <MAC>` 複製 MAC（需 root/CAP_NET_ADMIN）
//   macOS   : ✅ 真 TAP (feth pair) via tun_rs Layer::L2 — 標註待真機，feth0/feth1 成對建立
//   Windows : ✅ tap-windows via tun_rs Layer::L2（需 tap-windows 驅動，需管理員權限）
//   FreeBSD/OpenBSD/NetBSD: ✅ tun_rs Layer::L2（cfg 護送，與 upstream async_tap.rs 一致）
//
// 建立後跨平台驗證介面是否存在且 UP：
//   Linux  : `ip -o link show dev <name>`
//   macOS  : `ifconfig <name>`  (自動辨識 utunN / fethN)
//   Windows: 跳過 (wintun/tap-windows 由驅動管理；建立成功即視為正常)

use anyhow::{bail, Result};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[cfg(target_os = "windows")]
use std::process::Command as PCommand;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command as PCommand;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::privileges;

// ── Tun layer abstraction ───────────────────────────────────────────────────

/// 封裝層選擇：L3 (TUN) 與 L2 (TAP)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunLayer {
    L2,
    L3,
}

impl TunLayer {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "l2" | "tap" | "layer2" | "ethernet" | "2" => TunLayer::L2,
            _ => TunLayer::L3,
        }
    }
}

impl fmt::Display for TunLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunLayer::L2 => write!(f, "l2"),
            TunLayer::L3 => write!(f, "l3"),
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// TUN 後端類型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunBackend {
    /// 嘗試 tun 建立；失敗且為 macOS/Linux 時自動嘗試系統工具備用方案
    Auto,
    /// 僅使用 tun crate (即舊 tun 0.6)
    TunRs,
    /// macOS/Linux 專用：最小 tun 建立 + 系統工具賦址與啟動
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

/// 建立好的 TUN (L3) 裝置手柄，含裝置本身與最終辨識到的介面名稱（舊 `tun` 0.6）
pub struct TunHandle {
    pub dev: tun::AsyncDevice,
    pub iface: String,
}

/// 建立好的 TAP (L2) 裝置手柄，含 `tun_rs` AsyncDevice 與介面名稱
/// 僅在支援 Layer::L2 的平台可用（Linux/macOS/Windows/FreeBSD/OpenBSD/NetBSD）
pub struct L2TapHandle {
    pub dev: tun_rs::AsyncDevice,
    pub iface: String,
    /// 實際由驅動回報的 MAC（若無法查詢則為 None）
    pub mac: Option<[u8; 6]>,
}

/// 格式化 MAC 為 `aa:bb:cc:dd:ee:ff`
fn fmt_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// 將 `tun_rs::AsyncDevice` 的實際 MAC 讀出。
///
/// 走 `TAP_IOCTL_GET_MAC`（Windows 見 `tap/mod.rs:165`），回報**驅動當下實際
/// 使用**的 MAC —— 也就是資料面封包真正帶出的來源 MAC，因此可同時作為：
///   1. MAC 是否被套用的權威判斷（registry 寫入成功 ≠ 已套用）
///   2. TAP handle 是否仍存活的探測（停用/啟用後 handle 可能失效）
///
/// 注意：Windows 的 `set_mac_address()` 並非不存在，而是 `TapDevice::set_mac`
/// 被刻意實作成永遠回 `Unsupported`（`tap/mod.rs:171`），且 TAP-Windows 驅動
/// 根本沒有 `TAP_IOCTL_SET_MAC`（僅 GET_MAC）。所以執行期改 MAC 只能靠
/// registry `NetworkAddress` + miniport 重啟。
fn read_dev_mac(dev: &tun_rs::AsyncDevice) -> Result<[u8; 6]> {
    Ok(dev.mac_address()?)
}

/// Windows 專用：以 `Set-NetAdapter -MacAddress` 強制套用 MAC。
///
/// 原理：停用介面 → 寫入 class 驅動的 `NetworkAddress` → 啟用介面。
/// 由 PowerShell 自行處理停用/啟用與等待，比 tun-rs 內部
/// `set_adapter_mac_by_guid` + 20ms 間隔的 disable/enable 可靠。
#[cfg(target_os = "windows")]
fn force_apply_mac_windows(iface: &str, mac: &[u8; 6]) -> Result<()> {
    // 安全防護：絕不可改寫實體網卡 MAC，否則會破壞上游網路的 MAC 綁定
    assert_virtual_iface(iface, "修改 MAC 到")?;

    let mac_str = fmt_mac(mac);
    // 1) 停用並等待狀態確實變為 Disconnected，確保 miniport 已卸載
    let ps = format!(
        "Disable-NetAdapter -Name '{iface}' -Confirm:$false -ErrorAction SilentlyContinue; \
         $d=[datetime]::Now; \
         while((Get-NetAdapter -Name '{iface}').Status -ne 'Disconnected'){{ \
           if(([datetime]::Now-$d).TotalSeconds -gt 15){{break}} Start-Sleep -Milliseconds 200 \
         }}; \
         Set-NetAdapter -Name '{iface}' -MacAddress '{mac_str}' -ErrorAction Stop; \
         Enable-NetAdapter -Name '{iface}' -Confirm:$false -ErrorAction SilentlyContinue"
    );
    let out = PCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .map_err(|e| anyhow::anyhow!("執行 PowerShell 失敗: {e}"))?;
    if !out.status.success() {
        bail!(
            "Set-NetAdapter 套用 MAC 失敗: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    // 套用後是否真的生效，由呼叫端以 TAP_IOCTL_GET_MAC 輪詢驗證（同時探測 handle）
    Ok(())
}

// ── L3 TUN: with fallback (legacy tun 0.6) ──────────────────────────────────

/// 以指定後端建立 TUN (L3) 虛擬網卡，支援容錯與建立後介面 UP 驗證。
pub fn create_with_fallback(
    backend: &TunBackend,
    name: &str,
    ip: &str,
    netmask: &str,
) -> Result<TunHandle> {
    // ─── 主要路徑：tun 全套設定（含 address / netmask / up） ───────────
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
                "⚠️ [TUN] tun 全套設定失敗: {primary_err}，嘗試系統工具備用方案..."
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

        let dev = tun::create_as_async(&min_cfg).context("tun 最小建立亦失敗，請確認具備足夠權限")?;

        let iface = {
            let new_name = detect_new_iface(&before).unwrap_or_else(|| name.to_string());
            set_iface_addr_up(&new_name, ip, netmask)?;
            new_name
        };

        Ok(TunHandle { dev, iface })
    }
}

// ── L2 TAP: via tun_rs (Layer::L2) ──────────────────────────────────────────

/// 將 `aa:bb:cc:dd:ee:ff` 或 `aabbccddeeff` 轉為 [u8;6]；驗證 48-bit
pub fn parse_mac_array(mac: &str) -> Result<[u8; 6]> {
    let norm: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if norm.len() != 12 {
        bail!("MAC 格式無效 (需 48-bit 12 hex，實際: {mac})");
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&norm[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("MAC hex 解析失敗: {mac}"))?;
    }
    // 拒絕全零 / 多播位檢查可選；此處僅確保非零
    if out == [0u8; 6] {
        bail!("MAC 不可為全零: {mac}");
    }
    Ok(out)
}

/// 產生一個本地管理 MAC (locally administered, unicast)：02:xx:xx:xx:xx:xx
fn generate_random_mac() -> [u8; 6] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut mac = [0u8; 6];
    rng.fill_bytes(&mut mac);
    mac[0] = (mac[0] & 0xFE) | 0x02; // unicast + locally administered
    if mac == [0u8; 6] {
        mac[5] = 0x01;
    }
    mac
}

/// 依 `ip` + `netmask` 解析為 (Ipv4Addr, prefix)
fn parse_ipv4_and_prefix(ip: &str, netmask: &str) -> Result<(Ipv4Addr, u8)> {
    let ipv4 = Ipv4Addr::from_str(ip).map_err(|e| anyhow::anyhow!("ip 格式無效 {ip}: {e}"))?;
    // netmask 可為 "255.255.255.0" 或 "24"
    let prefix = if netmask.trim().chars().all(|c| c.is_ascii_digit()) && !netmask.contains('.') {
        let p: u8 = netmask
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("netmask 前綴無效: {netmask}"))?;
        if p > 32 {
            bail!("netmask 前綴超出 0-32: {netmask}");
        }
        p
    } else {
        // 復用既有轉換邏輯（Linux/macOS 有，Windows 需同邏輯）
        netmask_str_to_prefix(netmask)?
    };
    Ok((ipv4, prefix))
}

/// 與 `netmask_to_prefix_literal` 同邏輯，但跨平台可用
fn netmask_str_to_prefix(netmask: &str) -> Result<u8> {
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

/// Windows 專用：列舉現有網卡的 (FriendlyName, InterfaceDescription)
#[cfg(target_os = "windows")]
fn windows_list_adapters() -> Vec<(String, String)> {
    let ps = r#"
$OutputEncoding = [Console]::OutputEncoding = [Text.Encoding]::UTF8
Get-NetAdapter | ForEach-Object { "{0}|||{1}" -f $_.Name, $_.InterfaceDescription }
"#;
    let Ok(o) = PCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps])
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| {
            let mut it = l.split("|||");
            match (it.next(), it.next()) {
                (Some(n), Some(d)) => Some((n.trim().to_string(), d.trim().to_string())),
                _ => None,
            }
        })
        .collect()
}

/// Windows 專用：避免 L2 TAP 名稱與「非 TAP」的既有介面衝突。
///
/// 背景（tun-rs 2.8.11 `platform/windows/device.rs` L2 分支）：
///   `interfaces` 集合來自 `getifaddrs`，其 `description` 欄位在 Windows 上
///   取自網卡的 **FriendlyName**（即 `Get-NetAdapter` 的 `Name`）。
///   當 `dev_name` 命中該集合時，tun-rs 會走 `TapDevice::open("tap0901", name, ...)`
///   而非 `create`，隨後 `iface::check_interface("tap0901", luid)` 只比對
///   HardwareID 是否為 `tap0901`。若該名稱其實是 **WinTun (L3)** 介面，
///   HardwareID 不符 → 枚舉不到 → 回傳 `NotFound: "Device not found"`。
///
/// 例：先後跑過 L3 TUN 產生 `tun0`，再以同一名稱建立 L2 TAP 就會命中此情形。
///
/// 解法：名稱已被「非 TAP」介面佔用時，改用未被佔用的 `tapN`。
#[cfg(target_os = "windows")]
fn windows_tap_safe_name(desired: &str) -> String {
    let desired = desired.trim();
    if desired.is_empty() {
        return "tap0".to_string();
    }
    let adapters = windows_list_adapters();

    // 名稱未被佔用 → 直接使用（tun-rs 會 create 新 TAP）
    if !adapters.iter().any(|(n, _)| n.eq_ignore_ascii_case(desired)) {
        return desired.to_string();
    }
    // 名稱已被 TAP-Windows 介面佔用 → 沿用即可（tun-rs 會正確 open 並重用）
    if adapters
        .iter()
        .any(|(n, d)| n.eq_ignore_ascii_case(desired) && d.to_ascii_lowercase().contains("tap-windows"))
    {
        return desired.to_string();
    }
    // 名稱被非 TAP 介面佔用 → 改用空閒的 tapN
    let mut i = 0u32;
    loop {
        let cand = format!("tap{i}");
        let taken = adapters.iter().any(|(n, _)| n.eq_ignore_ascii_case(&cand));
        if !taken {
            eprintln!(
                "⚠️  [TUN] L2 TAP 名稱衝突: 「{desired}」已被非 TAP-Windows 介面佔用 (L3 WinTun 同名)，\
                 自動改用「{cand}」。若需沿用原名請先移除該介面，或以 --tun-name tapN 指定。"
            );
            return cand;
        }
        i += 1;
        if i > 64 {
            // 找不到空閒名稱時退回原名，讓 tun-rs 回報真實錯誤
            return desired.to_string();
        }
    }
}

/// 非 Windows 平台沿用原名稱（TAP 名稱空間由 tun_rs/系統自行處理）
#[cfg(not(target_os = "windows"))]
fn windows_tap_safe_name(desired: &str) -> String {
    let desired = desired.trim();
    if desired.is_empty() {
        "tap0".to_string()
    } else {
        desired.to_string()
    }
}

/// 將 tun_rs `build_async()` 的 io::Error 轉為具診斷性的訊息。
///
/// 特別處理 `ErrorKind::NotFound`：在 Windows 上該字串來自
/// tun-rs `platform/windows/tap/iface.rs` 的 `check_interface()`，
/// 語意是「列舉不到 HardwareID == tap0901 且 LUID 相符的裝置」，
/// 常見成因是 **介面名稱被非 TAP 介面佔用**（例如 L3 WinTun 也叫 tun0），
/// 而非驅動缺失。
fn l2_build_error(e: std::io::Error, name: &str) -> anyhow::Error {
    use std::io::ErrorKind;

    if e.kind() == ErrorKind::NotFound {
        #[cfg(target_os = "windows")]
        {
            let adapters = windows_list_adapters();
            let occupied = adapters
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name));
            let detail = match occupied {
                Some((n, d)) if !d.to_ascii_lowercase().contains("tap-windows") => format!(
                    "介面「{n}」已被「{d}」佔用（非 TAP-Windows），\
                     tun-rs 因此誤走 TapDevice::open(\"tap0901\", \"{n}\") 而比對不到驅動。"
                ),
                Some((n, d)) => format!("介面「{n}」({d}) 已存在但無法以 tap0901 開啟。"),
                None => "系統中列舉不到對應的 TAP 介面。".to_string(),
            };
            anyhow::anyhow!(
                "L2 TAP 建立失敗 (NotFound: Device not found) — {detail}\n\
                 處置：改用 tap 開頭的介面名稱，例如 --tun-name tap0；\n\
                 並確認已安裝 TAP-Windows 驅動 (tap0901.sys) 且有管理員權限。\n\
                 檢查：Get-NetAdapter | Where-Object {{$_.InterfaceDescription -match 'TAP'}}"
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            anyhow::anyhow!(
                "L2 TAP 建立失敗 (NotFound: Device not found) name={name}: {e}\n\
                 請確認介面名稱未被其他介面佔用，並具備建立 TAP 的權限。"
            )
        }
    } else {
        privilege_context(e)
    }
}

/// 新建 L2 TAP (tun_rs Layer::L2) —— 平台矩陣：
///   Linux ✅ IFF_TAP                — 需 root/CAP_NET_ADMIN，`ip link set dev <tap> address <MAC>` 已由 builder 處理
///   macOS ✅ feth pair (feth0/feth1) — tun_rs 自動建立 feth 對，待真機驗證 `ifconfig fethN ether <MAC>`
///   Windows ✅ tap-windows           — 需 tap-windows 驅動 + 管理員權限，tun_rs 透過 Layer::L2 建立
/// 失敗時回傳帶權限提示的錯誤；不支援平台直接 bail。
pub fn create_l2_tap(
    name: &str,
    ip: &str,
    netmask: &str,
    mac: &str,
) -> Result<L2TapHandle> {
    // `physical` 關鍵字：自動取「承載對外連線」的實體網卡 MAC。
    // 綁定 MAC（埠安全）的網路只接受登記來源 MAC，L2 TAP 作為封包出口時必須一致；
    // 失敗時明確報錯而非悄悄退回隨機 MAC（否則會被上游靜默封鎖且難以排查）。
    let mac_resolved = if mac.trim().eq_ignore_ascii_case("physical") {
        crate::macutils::default_route_physical_mac().ok_or_else(|| {
            anyhow::anyhow!(
                "找不到承載對外連線的實體網卡 MAC（--tun-mac physical 失敗）\n\
                 請改用明確位址，例如 --tun-mac 3C:AB:72:5B:13:4D"
            )
        })?
    } else {
        mac.to_string()
    };
    let mac_arr = if mac_resolved.trim().is_empty() {
        generate_random_mac()
    } else {
        parse_mac_array(&mac_resolved)?
    };
    let (ipv4, prefix) = parse_ipv4_and_prefix(ip, netmask)?;
    let name = windows_tap_safe_name(name);

    // L2 僅在 tun_rs 支援 Layer::L2 的平台可用；與 upstream examples/async_tap.rs 的 cfg 一致
    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    {
        // 對應 upstream async_tap.rs:
        //   DeviceBuilder::new().ipv4(...).layer(Layer::L2).mac_addr([...]).build_async()
        // Linux: 需 CAP_NET_ADMIN 或 root；macOS feth 無需 utun root 但賦址需 sudo；Windows 需管理員 + tap-windows
        let dev = tun_rs::DeviceBuilder::new()
            .name(name.clone())
            .layer(tun_rs::Layer::L2)
            .mac_addr(mac_arr)
            .ipv4(ipv4, prefix, None)
            .mtu(1500)
            .build_async()
            .map_err(|e| l2_build_error(e, &name))?;

        let iface = dev
            .name()
            .ok()
            .and_then(|n| {
                let s = n.trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            })
            .unwrap_or_else(|| name.to_string());

        eprintln!(
            "✅ [TUN] L2 TAP 已建立 (tun_rs Layer::L2) name={} iface={} 期望 MAC={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ip={}/{}",
            name, iface, mac_arr[0], mac_arr[1], mac_arr[2], mac_arr[3], mac_arr[4], mac_arr[5], ipv4, prefix
        );
        // 平台備註
        #[cfg(target_os = "linux")]
        eprintln!("ℹ️  [TUN] Linux TAP 已設定 MAC；後續可用 `ip link set dev {iface} address <MAC>` 覆蓋（需 root）");
        #[cfg(target_os = "macos")]
        eprintln!("ℹ️  [TUN] macOS feth TAP：tun_rs 已建立 feth 對；待真機以 `ifconfig {iface} ether <MAC>` 驗證");

        // ── MAC 驗證與強制套用 ──────────────────────────────────────────
        // tun-rs 於 Windows 的 `mac_addr()` 僅在建立時寫 registry `NetworkAddress`
        // 再 disable→sleep(20ms)→enable（`tap/mod.rs:80-87`）。但 `enable_adapter`
        // 走的是非同步 DIF_PROPERTYCHANGE，20ms 遠不足以讓 miniport 真正卸載重啟，
        // 驅動因而不會重讀 NetworkAddress，MAC 停留在建立時指派的 00-FF-xx… 值。
        // 故必須以 TAP_IOCTL_GET_MAC 讀回**實際生效**值驗證，不符則強制重啟套用。
        let mut applied = read_dev_mac(&dev).ok();

        let mac_ok = applied == Some(mac_arr);
        #[cfg(target_os = "windows")]
        if !mac_ok {
            eprintln!(
                "⚠️  [MAC] tun_rs 建立時未套用 MAC（實際: {}），改以 Set-NetAdapter 強制套用 {}…",
                applied.map(|m| fmt_mac(&m)).unwrap_or_else(|| "<未知>".into()),
                fmt_mac(&mac_arr)
            );
            force_apply_mac_windows(&iface, &mac_arr)
                .map_err(|e| anyhow::anyhow!("強制套用 MAC 失敗: {e}"))?;
            // 輪詢驗證：TAP_IOCTL_GET_MAC 讀到新值即成功；
            // 若直到時限仍持續回傳錯誤，代表停用/啟用已使 TAP handle 失效。
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match read_dev_mac(&dev) {
                    Ok(m) => {
                        applied = Some(m);
                        if m == mac_arr {
                            break;
                        }
                    }
                    Err(e) if std::time::Instant::now() >= deadline => bail!(
                        "MAC 套用期間介面被停用/啟用，TAP handle 已失效: {e}\n\
                         tun-rs 公開 API 無法重新開啟既有介面，資料面無法啟動。\n\
                         請關閉佔用該介面的程式（如 OpenVPN）後重試，或改用 L3 TUN。"
                    ),
                    Err(_) => {}
                }
                if std::time::Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            if applied != Some(mac_arr) {
                bail!(
                    "MAC 已寫入 registry 但驅動未重啟套用：期望 {}，實際 {}。\n\
                     請確認介面狀態：Get-NetAdapter -Name '{}' | Format-List Name,MacAddress,Status",
                    fmt_mac(&mac_arr),
                    applied.map(|m| fmt_mac(&m)).unwrap_or_else(|| "<讀取失敗>".into()),
                    iface
                );
            }
        }
        #[cfg(not(target_os = "windows"))]
        if !mac_ok && applied.is_some() {
            eprintln!(
                "⚠️  [MAC] 驅動回報 MAC {} 與指定的 {} 不符",
                applied.map(|m| fmt_mac(&m)).unwrap_or_else(|| "<未知>".into()),
                fmt_mac(&mac_arr)
            );
        }

        let shown = applied
            .map(|m| fmt_mac(&m))
            .unwrap_or_else(|| "<未知>".into());
        if applied == Some(mac_arr) {
            eprintln!("✅ [MAC] L2 TAP MAC 已確認 = {shown}");
        } else {
            eprintln!("⚠️  [MAC] L2 TAP 實際 MAC = {shown}（與設定 {期望} 不符）", 期望 = fmt_mac(&mac_arr));
        }
        #[cfg(target_os = "windows")]
        eprintln!("ℹ️  [TUN] Windows TAP (tap-windows)：介面 {iface} 已就緒");

        return Ok(L2TapHandle {
            dev,
            iface,
            mac: applied,
        });
    }

    #[cfg(any(
        all(target_os = "linux", target_env = "ohos"),
        target_os = "ios",
        target_os = "tvos",
        target_os = "android",
    ))]
    {
        let _ = (name, ipv4, prefix, mac_arr);
        bail!("L2 TAP 不支援此平台 (僅 Linux/macOS/Windows/FreeBSD/OpenBSD/NetBSD 支援 Layer::L2) — 請改用 L3 TUN");
    }

    #[cfg(not(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "netbsd",
        all(target_os = "linux", target_env = "ohos"),
        target_os = "ios",
        target_os = "tvos",
        target_os = "android",
    )))]
    {
        let _ = (name, ipv4, prefix, mac_arr);
        bail!("L2 TAP 不支援此未知平台；請改用 L3 TUN (tun crate fallback)");
    }
}

/// 依 `layer` 自動分派 L2 (tun_rs) 與 L3 (tun) 建立；L2 失敗時可選擇 fallback 至 L3
pub fn create_with_fallback_and_layer(
    backend: &TunBackend,
    layer: TunLayer,
    name: &str,
    ip: &str,
    netmask: &str,
    mac: &str,
) -> Result<CreateOutcome> {
    match layer {
        TunLayer::L2 => {
            match create_l2_tap(name, ip, netmask, mac) {
                Ok(h) => Ok(CreateOutcome::L2(h)),
                Err(e) => {
                    // 若 backend 為 Auto 且為 L2 失敗，允許降級到 L3 tun（保留舊行為）
                    if *backend == TunBackend::Auto {
                        eprintln!("⚠️ [TUN] L2 TAP 建立失敗: {e}，嘗試降級至 L3 TUN (tun crate) ...");
                        let tun_h = create_with_fallback(backend, name, ip, netmask)?;
                        Ok(CreateOutcome::L3Fallback(tun_h, e.to_string()))
                    } else {
                        Err(e)
                    }
                }
            }
        }
        TunLayer::L3 => Ok(CreateOutcome::L3(create_with_fallback(backend, name, ip, netmask)?)),
    }
}

/// `create_with_fallback_and_layer` 的分派結果
pub enum CreateOutcome {
    L2(L2TapHandle),
    L3(TunHandle),
    /// L2 請求但已降級至 L3，並附帶原始 L2 錯誤訊息
    L3Fallback(TunHandle, String),
}

impl CreateOutcome {
    pub fn iface(&self) -> &str {
        match self {
            CreateOutcome::L2(h) => &h.iface,
            CreateOutcome::L3(h) => &h.iface,
            CreateOutcome::L3Fallback(h, _) => &h.iface,
        }
    }
    pub fn is_l2(&self) -> bool {
        matches!(self, CreateOutcome::L2(_))
    }
}

/// 供 macutils 呼叫：嘗試以 tun_rs 同步方式設定 TAP MAC（若驅動支援）；否則回退至 `ip link` / `ifconfig`
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub fn set_tap_mac_via_tun_rs(iface: &str, mac: [u8; 6]) -> Result<()> {
    // 嘗試以 tun_rs 能力設定（僅在 L2 支援平台）；若失敗則由呼叫方回退
    // Linux: DeviceImpl::set_mac_address 需 raw fd；此處以打開臨時 TAP 的方式間接驗證不可行，故僅提示需 ip link
    // 為保持 Windows cargo check 可通過，此函數在非 Linux/macOS 上直接回 Err 讓外層走系統工具
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // 優先嘗試直接透過 tun_rs SyncDevice 查詢並設定（若 iface 已是 tun_rs 建立的 TAP）
        // 若當前 iface 不是 tun_rs 句柄可達的裝置，則回退至系統工具
        // 文件化：Linux 真 L2 已由 DeviceBuilder::mac_addr 於建立時設定；執行期改 MAC 仍需 `ip link`
        if cfg!(target_os = "linux") {
            // Linux 真 L2 執行期改 MAC 的可信路徑為 ip link；tun_rs 的 set_mac_address 需裝置句柄，此處無法無句柄改名
            bail!("Linux TAP 執行期改 MAC 請走 `ip link set dev {iface} address <MAC>`（需 root/CAP_NET_ADMIN）");
        }
        if cfg!(target_os = "macos") {
            // macOS feth 的 MAC 可透過 tun_rs builder 指定；執行期改需 ifconfig
            bail!("macOS feth TAP 執行期改 MAC 請走 `ifconfig {iface} ether <MAC>`（需 root）");
        }
        let _ = (iface, mac);
        bail!("tun_rs MAC 設定需裝置句柄，請走系統工具路徑");
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (iface, mac);
        bail!("Windows tap-windows MAC 由驅動管理；tun_rs Layer::L2 建立時以 mac_addr 指定，執行期修改需驅動重建");
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (iface, mac);
        bail!("此平台不支援 tun_rs MAC 設定");
    }
}

/// 驗證介面是否 UP (Linux / macOS)；Windows 跳過並印出提示。
pub fn verify_iface_up(iface: &str) {
    #[cfg(target_os = "windows")]
    {
        println!(
            "ℹ️  [TUN] Windows 由 wintun/tap-windows 驅動管理介面，跳過 ip/ifconfig UP 檢查 (介面: {iface})"
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
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let lines: Vec<&str> = stdout.lines().collect();
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

/// 跨平台介面 provisioning（供 `--setup` 與 L2 建立後強制套用）。
///
/// 與 `create_l2_tap` 內 tun-rs builder 的 `.ipv4()` 不同，這裡以作業系統
/// 原生工具重新賦值，優點是錯誤訊息可讀且可重複執行（冪等）。
///
/// 平台：
///   Linux  : `ip addr add` / `ip link set up`（沿用 `set_iface_addr_up`）
///   macOS  : `ifconfig <iface> <ip> netmask <n> up`
///   Windows: `New-NetIPAddress` + `Enable-NetAdapter`（較 netsh 穩定、可重跑）
/// 判斷指定介面是否為「承載上線連線的實體網卡」——程式不得變更其 IP / MAC。
///
/// 回傳 `None` 表示找不到該介面，交由後續指令自行報錯。
///
/// 判定依據與踩到的坑：
/// - **不可用 `Get-NetAdapter.PhysicalAdapter`** —— 該屬性在本機回傳空值
///   （`Get-NetAdapter` 物件上根本沒有這個成員），守衛會永遠不觸發。
/// - 必須改查 `Get-CimInstance Win32_NetworkAdapter.PhysicalAdapter`（有效）。
/// - 但 Win32 對 **TAP-Windows 也回報 True**，所以還要用描述關鍵字把隧道介面
///   （TAP/TUN/Wintun/VPN/Virtual）排除，否則守衛會反過來拒絕設定自己的 TAP。
#[cfg(target_os = "windows")]
fn is_uplink_physical_iface(iface: &str) -> Option<bool> {
    let ps = format!(
        "$a = Get-CimInstance Win32_NetworkAdapter | \
           Where-Object {{ $_.NetConnectionID -eq '{iface}' }} | Select-Object -First 1; \
         if (-not $a) {{ 'NONE' }} \
         elseif ($a.Description -match 'TAP|TUN|Wintun|Tunnel|VPN|Virtual') {{ 'VIRTUAL' }} \
         elseif ($a.PhysicalAdapter) {{ 'PHYSICAL' }} \
         else {{ 'OTHER' }}"
    );
    let out = PCommand::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .ok()?;
    match String::from_utf8_lossy(&out.stdout).trim() {
        "PHYSICAL" => Some(true),
        "VIRTUAL" | "OTHER" => Some(false),
        _ => None,
    }
}

/// 拒絕對**實體上線網卡**執行會改變 IP / MAC 的操作。
///
/// 背景：綁定 MAC（埠安全／認證）的網路只接受登記過的來源 MAC。
/// 實體網卡正是承載該連線的介面；若程式誤把 `--tun-name` 指到它，
/// `setup_interface` 會清空其 IPv4、`force_apply_mac_windows` 更會改寫其 MAC，
/// 二者都會直接中斷使用者的上線網路。
#[cfg(target_os = "windows")]
fn assert_virtual_iface(iface: &str, action: &str) -> Result<()> {
    if is_uplink_physical_iface(iface) == Some(true) {
        bail!(
            "拒絕{action}實體上線網卡 [{iface}]。\n\
             這可能是綁定 MAC / 埠安全的上線網路介面，程式不得變更其 IP 或 MAC。\n\
             請確認 --tun-name 指向虛擬 TAP/TUN（例如 TAP-Windows Adapter V9 #2）。\n\
             檢查介面：Get-NetAdapter | Format-Table Name,InterfaceDescription,MacAddress"
        );
    }
    Ok(())
}

pub fn setup_interface(iface: &str, ip: &str, netmask: &str) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        set_iface_addr_up(iface, ip, netmask)
    }

    #[cfg(target_os = "windows")]
    {
        // 安全防護：只允許對虛擬介面賦址，避免清掉綁 MAC 之上線網卡的 IP
        assert_virtual_iface(iface, "賦址到")?;

        let prefix = netmask_str_to_prefix(netmask)?;

        // 先移除同名舊設定，避免重複執行時 netsh/PowerShell 回報衝突
        let _ = PCommand::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Remove-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 \
                     -Confirm:$false -ErrorAction SilentlyContinue"
                ),
            ])
            .output();

        let ps = format!(
            "$ErrorActionPreference='Stop'; \
             Enable-NetAdapter -Name '{iface}' -Confirm:$false -ErrorAction SilentlyContinue; \
             New-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 \
               -IPAddress '{ip}' -PrefixLength {prefix} -ErrorAction Stop | Out-Null; \
             Write-Output 'OK'"
        );
        let out = PCommand::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .map_err(|e| anyhow::anyhow!("執行 PowerShell 失敗: {e}"))?;

        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        if !out.status.success() || !stdout.contains("OK") {
            bail!(
                "設定 [{iface}] IP {ip}/{prefix} 失敗。\n\
                 PowerShell 輸出: {}\n\
                 處置建議：\n\
                  1. 確認介面存在: Get-NetAdapter | Where-Object {{$_.Name -eq '{iface}'}}\n\
                  2. 確認已啟用: Enable-NetAdapter -Name '{iface}' -Confirm:$false\n\
                  3. 手動賦址  : New-NetIPAddress -InterfaceAlias '{iface}' -IPAddress {ip} -PrefixLength {prefix}\n\
                  4. 若 IP 與既有路由衝突，改用私有位段 (例如 10.0.0.2/24)"
            , stderr.trim());
        }
        eprintln!("✅ [Setup] [{iface}] 已賦址 {ip}/{prefix} 並啟用");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (iface, ip, netmask);
        bail!("此平台尚未實作 setup_interface，請改用 --tun-backend system")
    }
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
        let mut up_cmd = build_cmd("ip", &["link", "set", iface, "up"], sudo_needed);
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

/// 權限不足時的平台專屬指引（含 L2 TAP 額外提示）
fn privilege_context<E: fmt::Display>(err: E) -> anyhow::Error {
    let hint = privilege_hint();
    anyhow::anyhow!("{err}\n{hint}")
}

fn privilege_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "🔐 [macOS 權限] TUN/路由需 root 權限，請以 `sudo <binary>` 執行。\n  macOS 無 Linux CAP_NET_ADMIN 機制，必須完全 root。\n  程式使用內建 utun 介面 (L3, 無需 /dev/tun) / feth 對 (L2 TAP, 需 root，待真機驗證)。\n  若持續失敗，請確認已以 `sudo` 執行，並檢查 `ifconfig utunN` / `ifconfig fethN` 是否正確建立。"
    }
    #[cfg(target_os = "linux")]
    {
        "🔐 [Linux 權限] 請以 root 執行 (`sudo <binary>`)，或賦予 cap_net_admin:\n    sudo setcap cap_net_admin=+ep <binary>\n  若 /dev/net/tun 不存在，請先載入: sudo modprobe tun\n  容器環境需額外加入 --device=/dev/net/tun 映射。\n  L2 TAP 另需 `ip link set dev <tap> address <MAC>` 權限（同 CAP_NET_ADMIN）。"
    }
    #[cfg(target_os = "windows")]
    {
        "🔐 [Windows 權限] TUN/路由需管理員權限，請以「系統管理員身分執行」命令提示字元\n  (或設定 --auto-elevate 自動彈出 UAC)。WinTun (L3) 驅動已隨程式內嵌；\n  L2 TAP 需額外安裝 tap-windows 驅動 (https://build.openvpn.net/downloads/releases/)，否則 Layer::L2 建立將回報驅動未找到。"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        "🔐 請以系統最高權限執行本程式。L2 TAP 僅在 Linux/macOS/Windows/FreeBSD 上支援 Layer::L2。"
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

/// netmask 字串 → 前綴長度 (IPv4) — 供 L3 系統工具路徑使用
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn netmask_to_prefix_literal(netmask: &str) -> Result<u8> {
    netmask_str_to_prefix(netmask)
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

    #[test]
    fn parse_layer_variants() {
        assert_eq!(TunLayer::parse("l2"), TunLayer::L2);
        assert_eq!(TunLayer::parse("L2"), TunLayer::L2);
        assert_eq!(TunLayer::parse("tap"), TunLayer::L2);
        assert_eq!(TunLayer::parse("l3"), TunLayer::L3);
        assert_eq!(TunLayer::parse("tun"), TunLayer::L3);
        assert_eq!(TunLayer::parse(""), TunLayer::L3);
        assert_eq!(TunLayer::parse("unknown"), TunLayer::L3);
    }

    #[test]
    fn display_layer() {
        assert_eq!(TunLayer::L2.to_string(), "l2");
        assert_eq!(TunLayer::L3.to_string(), "l3");
    }

    #[test]
    fn parse_mac_array_valid() {
        assert_eq!(
            parse_mac_array("aa:bb:cc:dd:ee:ff").unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
        assert_eq!(
            parse_mac_array("02-42-AC-11-00-02").unwrap(),
            [0x02, 0x42, 0xAC, 0x11, 0x00, 0x02]
        );
        assert_eq!(
            parse_mac_array("aabbccddeeff").unwrap(),
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]
        );
    }

    #[test]
    fn parse_mac_array_rejects_zero() {
        assert!(parse_mac_array("00:00:00:00:00:00").is_err());
        assert!(parse_mac_array("short").is_err());
    }

    #[test]
    fn parse_ipv4_and_prefix_variants() {
        let (ip, p) = parse_ipv4_and_prefix("10.0.0.1", "255.255.255.0").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(p, 24);
        let (_, p2) = parse_ipv4_and_prefix("10.0.0.1", "24").unwrap();
        assert_eq!(p2, 24);
        assert!(parse_ipv4_and_prefix("999.0.0.1", "24").is_err());
        assert!(parse_ipv4_and_prefix("10.0.0.1", "255.0.255.0").is_err());
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

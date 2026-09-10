//! # NDcode 3 - 跨平台權限管理 (Privilege Management)
//!
//! TUN 虛擬網卡建立 / 路由修改 / system sysctl-netsh 調校皆需系統管理權限。
//! 本模組提供：
//!   1. `is_elevated()`     ─ 偵測目前是否具備管理員 / root 權限
//!   2. `relaunch_as_admin()` ─ Windows 以 UAC `runas` 重新啟動自身
//!   3. `privilege_guidance()` ─ 各平台明確的權限取得指引
//!
//! ## 各平台偵測方式
//! - **Windows**: PowerShell `WindowsPrincipal.IsInRole(Administrator)`
//! - **Linux**  : `id -u` == 0 (root)；另支援 `CAP_NET_ADMIN` capabilities
//! - **macOS**  : `id -u` == 0 (root)

use anyhow::Result;
use std::process::Command;

/// 目前是否以系統管理員 (Windows) / root (Linux/macOS) 執行
pub fn is_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_is_admin()
    }
    #[cfg(target_os = "linux")]
    {
        id_is_root() || has_cap_net_admin()
    }
    #[cfg(target_os = "macos")]
    {
        id_is_root()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Windows：以 PowerShell 檢查目前主體是否屬於 Administrators 群組
fn windows_is_admin() -> bool {
    let ps = windows_admin_check_script();
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps])
        .output()
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

/// Windows：管理員檢查用的 PowerShell 指令 (供測試)
fn windows_admin_check_script() -> &'static str {
    "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
}

/// Unix 通用：`id -u` 是否為 0 (root)
fn id_is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Linux：檢查當前可執行檔是否擁有 `cap_net_admin` (免 root 存取 TUN)
fn has_cap_net_admin() -> bool {
    let Ok(current_exe) = std::env::current_exe() else {
        return false;
    };
    Command::new("getcap")
        .arg(&current_exe)
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            out.contains("cap_net_admin")
        })
        .unwrap_or(false)
}

/// 重新以系統管理員啟動本行程式 (Windows UAC)。
/// 回傳是否已提出提升請求 (呼叫成功即回 true；成功後原行程應結束)。
/// 非 Windows 平台一律回傳 false。
pub fn relaunch_as_admin(extra_args: &[String]) -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_relaunch_as_admin(extra_args)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = extra_args;
        false
    }
}

/// Windows：以 `Start-Process -Verb RunAs` 重新啟動自身並帶上原參數 + extra_args
fn windows_relaunch_as_admin(extra_args: &[String]) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let ps = format_relaunch_script(&exe.to_string_lossy(), extra_args);
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 建構 UAC 重新啟動的 PowerShell 指令 (純函式，供測試)
fn format_relaunch_script(exe_path: &str, extra_args: &[String]) -> String {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    args.extend(extra_args.iter().cloned());
    let quoted = args
        .iter()
        .map(|a| format!("'{}'", a.replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "Start-Process -FilePath '{}' -ArgumentList {} -Verb RunAs",
        exe_path.replace('\'', "''"),
        quoted
    )
}

/// 各平台取得權限的明確指引
pub fn privilege_guidance() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "🔐 [Windows] TUN/路由需管理員權限。請以「系統管理員身分執行」命令提示字元 (或設定 --auto-elevate 自動彈出 UAC)。\n  並確認已具備 Administrator 群組成員身分。"
    }
    #[cfg(target_os = "linux")]
    {
        "🔐 [Linux] 請以 root 執行 (`sudo {}`)，或執行:\n    sudo setcap cap_net_admin=+ep <binary>\n  以授予免 root 的 TUN 存取權限。"
    }
    #[cfg(target_os = "macos")]
    {
        "🔐 [macOS] TUN/路由需 root 權限，請以 `sudo {}` 執行。macOS 不支援 Linux capabilities 免 root 方案。"
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        "🔐 [其他平台] 請以系統最高權限執行本程式以取得 TUN 虛擬網卡存取權。"
    }
}

/// 執行時權限就緒檢查：不足時列印指引，回傳是否繼續。
/// `auto_elevate=true` 時 (Windows) 自動請求 UAC 提升。
pub fn ensure_privilege_ready(auto_elevate: bool) -> Result<bool> {
    if is_elevated() {
        println!("🔐 [Privilege] 已具備系統管理權限");
        return Ok(true);
    }

    #[cfg(target_os = "windows")]
    if auto_elevate {
        println!("🔐 [Privilege] 未具備管理員權限，嘗試自動提升 (UAC)...");
        if relaunch_as_admin(&[]) {
            println!("🔐 [Privilege] 已觸發 UAC 提升請求，請於彈出視窗允許後，於新視窗繼續；舊視窗可關閉。");
            return Ok(false);
        }
        println!("⚠️  [Privilege] UAC 提升觸發失敗，改以手動方式進行。");
    }

    eprintln!("⚠️  [Privilege] 權限不足！請指派權限後重新執行。");
    eprintln!("{}", privilege_guidance());
    Ok(false)
}

/// 在設定精靈中提供權限處理 (回傳是否已就緒)
pub fn wizard_ensure_privilege() -> Result<()> {
    if is_elevated() {
        println!("🔐 [Privilege] 已具備系統管理權限");
        return Ok(());
    }

    eprintln!("⚠️  [Privilege] 尚未就緒：請依下列指引取得管理權限後再啟動：");
    eprintln!("{}", privilege_guidance());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_admin_check_script_is_valid_ps() {
        let script = windows_admin_check_script();
        assert!(
            script.contains("WindowsPrincipal")
                && script.contains("IsInRole")
                && script.contains("Administrator")
        );
    }

    #[test]
    fn test_windows_relaunch_ps_quotes_args() {
        // 具名 exe 路徑 + 明確 extra args；此處 argv 不影響斷言主體
        let ps = format_relaunch_script("C:\\Program Files\\ntors.exe", &["--mode".into(), "client".into()]);
        assert!(ps.contains("-Verb RunAs"));
        assert!(ps.contains("'--mode'"));
        assert!(ps.contains("'client'"));
        assert!(ps.contains("'C:\\Program Files\\ntors.exe'"));
    }

    #[test]
    fn test_guidance_mentions_each_os() {
        let g = privilege_guidance();
        assert!(!g.is_empty());
        #[cfg(target_os = "windows")]
        assert!(g.contains("管理員"));
        #[cfg(target_os = "linux")]
        assert!(g.contains("setcap"));
        #[cfg(target_os = "macos")]
        assert!(g.contains("sudo"));
    }

    #[test]
    fn test_elevated_detection_runs_without_panic() {
        // 此測試不假設是否具權限，僅確認偵測流程不 panic
        let _ = is_elevated();
    }
}
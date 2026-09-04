//! # NDcode 3 - Wintun 驅動靜態內嵌與管理模組
//!
//! 本模組負責在 Windows 平台上於編譯期將原生 `wintun.dll` 靜態內嵌至二進位檔中，
//! 並於運行期自動釋放，提供跨平台無縫運作能力。
//!
//! ## 📜 第三方來源與授權聲明 (Attribution & Licensing)
//! - **專案名稱**: Wintun (Layer 3 TUN Driver for Windows)
//! - **官方網站**: <https://www.wintun.net/>
//! - **專案原始碼**: <https://git.zx2c4.com/wintun/>
//! - **版權所有**: Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved.
//! - **授權條款**:
//!   - `wintun.dll` (User-space API & Loader): **MIT License**
//!   - `wintun.sys` (Kernel-space Driver): **GPL-2.0**
//!
//! > **MIT License 摘要**：
//! > Permission is hereby granted, free of charge, to any person obtaining a copy
//! > of this software and associated documentation files (the "Software"), to deal
//! > in the Software without restriction, including without limitation the rights
//! > to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! > copies of the Software.

#[cfg(target_os = "windows")]
pub mod win_wintun {
    use anyhow::{anyhow, Context, Result};
    use std::fs;
    use std::path::PathBuf;

    // 於編譯期將目標架構的 wintun.dll 靜態內嵌至 Binary 中
    #[cfg(target_arch = "x86_64")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../assets/wintun/amd64/wintun.dll");

    #[cfg(target_arch = "aarch64")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../assets/wintun/arm64/wintun.dll");

    #[cfg(target_arch = "x86")]
    static WINTUN_DLL_BYTES: &[u8] = include_bytes!("../assets/wintun/x86/wintun.dll");

    /// 自動檢查並釋放內嵌的 wintun.dll 至執行目錄
    pub fn ensure_wintun_embedded() -> Result<PathBuf> {
        let current_exe = std::env::current_exe().context("無法取得當前執行檔路徑")?;
        let exe_dir = current_exe
            .parent()
            .ok_or_else(|| anyhow!("無法取得執行檔所在目錄"))?;
        let target_dll_path = exe_dir.join("wintun.dll");

        // 若檔案已存在且可讀取，直接回傳
        if target_dll_path.exists() {
            println!("✅ [Wintun] 偵測到現有驅動檔: {}", target_dll_path.display());
            return Ok(target_dll_path);
        }

        println!("📦 [Wintun] 偵測到缺失 wintun.dll，正在從內建資源釋放原生地質組件...");
        
        // 將內嵌的 Bytes 寫入磁碟
        fs::write(&target_dll_path, WINTUN_DLL_BYTES)
            .context("寫入 wintun.dll 失敗，請確認是否具有該目錄寫入權限")?;

        println!("✅ [Wintun] 成功釋放驅動至: {}", target_dll_path.display());
        Ok(target_dll_path)
    }
}

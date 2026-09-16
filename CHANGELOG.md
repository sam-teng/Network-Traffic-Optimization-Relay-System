# Changelog

本專案版本以 `v0.0.0-NDcode3-*` 標記。變更依日期與版本記錄於下。

## [0.0.0-NDcode3-beta.7] - 2026-09-17

### 新增
- TUN 後端可設定化 (`--tun-backend` auto / tun-rs / system，也可寫入 `ndcode_config.json` 與設定精靈)：auto 於 macOS/Linux 建立失敗時自動降級為「最小建立 + 系統工具 (`ip` / `ifconfig`) 賦址與啟動」備用方案，避免 root 環境下 tun-rs 全設定失敗即退出
- TUN 建立後介面 UP 驗證：Linux 以 `ip -o link show`、macOS 以 `ifconfig <utunN>` 確認介面已啟動；Windows 由 wintun 驅動管理，顯示提示略過。macOS 自動辨識實際 `utunN` 介面名 (不再假設為 `tun0`)
- 系統工具降級時依權限自動套用 `sudo` 前置；失敗時輸出各平台權限診斷指引 (macOS 完整 root 說明、Linux setcap/CAP_NET_ADMIN、Windows 內嵌 wintun)
- 流量統計顯示加入「總流量」(累計上傳+下載)與「區間流量」(每次顯示間隔內之上傳/下載增量，`traffic_meter::interval_stats`)

### 變更
- 版本號同步為 `0.0.0-NDcode3-beta.7`

## [0.0.0-NDcode3-beta.6] - 2026-09-16

### 新增
- CI 對 windows / macos / linux 三大平台皆實施 Debug (dev profile) 與 Release 建置：`release + dev × 5 個目標` 共 10 個 job；windows、linux 於 `ubuntu-latest` 交叉編譯，macOS 於 `macos-latest` 原生編譯，artifact 按 `NTORS-<profile>-<target>` 分名上傳
- README 用詞統一：設定嚮導 → 設定精靈、非法資料拒絕 → 阻絕、運行 → 執行

### 變更
- NDcode3 核心引擎相依由 `path = "NDcode3"` 改為 `git = "https://github.com/sam-teng/NDcode3.git"`,核心程式碼改由獨立儲存庫提供
- 版本號同步為 `0.0.0-NDcode3-beta.6`,並新增本 CHANGELOG

### 修正
- 修正 Windows (`x86_64-pc-windows-gnu`) 鏈接失敗 `export ordinal too large: 131415`：NDcode3 的 `crate-type` 移除 `cdylib`(不再產出 `.dll`)，避免 PE 匯出符號超過 65,535 上限；`Cargo.lock` 已重新鎖定 NDcode3 `8f1e293`
- 修正 CI matrix 崩潰:偵測到 `profile: [release, dev]` 主軸與 `include`(os/target/runner)未對齊,依 GitHub include 規則後寫條目覆蓋先寫,導致只展開 `macOS × 2` 兩個 job;改以 `target` 同步為主軸(5×2=10 個組合),`include` 依 `target` 合併 `os/runner/cross` 額外鍵
- 移除舊版 `.github/workflows/rust.yml`：其僅於 tag push 觸發、缺少 NDcode3 擷取 / wintun DLL / build-std 與 macOS 原生支援，與 `cross-build.yml` 重複並導致多個失敗 job
- 修正 CI 的 `--release` 重複錯誤:改以 cargo-cross action 的 `profile: release`,移除手動 `cargo-args: --release`
- 修正 Windows 交叉編譯缺少 `assets/wintun/amd64/wintun.dll` 而無法嵌入:CI 於 `x86_64-pc-windows-gnu` 建置前自 wintun.net 下載官方簽署 DLL(wintun 0.14.1,並以 SHA-256 驗證)

## [0.0.0-NDcode3-beta.5] - 2026-09-16

### 新增
- Wasm 沙盒解壓隧道（選項 B：Code-as-Data）`src/wasm_tunnel.rs`:
  - 純 Rust 解譯器 wasmi 2.0,支援記憶體 / CPU fuel 限制
  - fuel budget 500,000、宿主執行緒 stack 1 GiB、並行上限 4
  - Guest 框架格式與 ABI;示範 decoder 以 `memory.fill` 消除逐位元組遞迴
- 流量計算 / 顯示模組 `src/traffic_meter.rs`(CLI 參數 `--traffic-stats` / `--traffic-interval`)

### 修正
- 全歷史清理閉源資產:自所有 commit 移除 `NDcode3/`、`ndcode_config.json` 與頂層 `pipeline/`,author/committer 信箱改為 GitHub noreply
- cross-build workflow 改為 ubuntu-latest + cargo-cross / macos-latest 原生編譯;新增 NDcode3 私有引擎 fetch 步驟

## [0.0.0-NDcode3-beta.4] - 2026-09-15

### 新增
- 新增跨平台構建 workflow(`cross-build.yml`,透過 zijiren233/cargo-cross @v1)
- NDcode3 核心引擎以 PAT 自動擷取

> 說明:`alpha`、`beta`、`beta.1`–`beta.3` 為 `main`(public)既有歷史標記,本表不另記錄。
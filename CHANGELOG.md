# Changelog

本專案版本以 `v0.0.0-NDcode3-*` 標記。變更依日期與版本記錄於下。

## [0.0.0-NDcode3-beta.6] - 2026-09-16

### 變更
- NDcode3 核心引擎相依由 `path = "NDcode3"` 改為 `git = "https://github.com/sam-teng/NDcode3.git"`,核心程式碼改由獨立儲存庫提供
- 版本號同步為 `0.0.0-NDcode3-beta.6`,並新增本 CHANGELOG

### 修正
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
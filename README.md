[![Cross Build NTORS Static Binaries](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/cross-build.yml/badge.svg)](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/cross-build.yml) [![Semgrep](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/semgrep.yml/badge.svg)](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/semgrep.yml)
# Network-Traffic-Optimization-Relay-System (NTORS)

Network Traffic Optimization & Relay System

- **Contributors can use AI, except for those with invisible watermarks (such as Claude, etc.)!**

# NDcode 3 網路流量最佳化中繼系統

NDcode 3 (Network Traffic Optimization Relay System) 是一個高效能、跨平台的開源網路流量最佳化中繼架構，結合多維條碼 / 噴泉網格編碼（NDcode 3）、Tokio 非同步管線與核心網路參數調校，專為提升網路傳輸效率與穩定性而設計。

本專案透過 **TUN 虛擬網卡 (Layer 3)** 擷取 IP 封包，在**用戶端**以 NDcode3 演算法對 HTTP / HTTPS 下載流量進行**邊接收邊串流壓縮**，再經由混淆與 HMAC-SHA256 握手安全通道傳輸。

* **GitHub Repository**: [https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/)
* **Copyright**: Copyright (c) 2026 Sam Teng. All rights reserved.
* **核心引擎**: 見 [NDcode3/README.md](NDcode3/README.md)

---

## ⚠️ 免責聲明與法律條款 (Disclaimer & Legal Notice)

### 1. 軟體使用與現狀聲明 (As-Is Notice)
本軟體以「現狀 (As-Is)」提供，不保證服務不中斷或完全無誤。使用者須自行承擔執行系統層級權限變更（如建立 TUN 虛擬網卡、載入核心驅動及調整 `sysctl` / `netsh` 網路參數）之風險。

### 2. 雙重用途與相關電信法規 (Regulatory Compliance)
# ***本軟體專為學術研究、教育訓練與個人合法網路最佳化而開發。使用者在使用本系統時，必須嚴格遵守當地網路通訊與資訊安全法規（例如《中華民國刑法》第 36 章妨害電腦使用罪）。禁止將本軟體用於任何未經授權之流量攔截、竊聽、惡意跳板或商業等違法用途。***

### 3. 專利與演算法免責聲明 (Patent Disclaimer)
NDcode 3 包含引用[https://crates.io/crates/raptorq](https://crates.io/crates/raptorq)（FEC / RaptorQ - RFC 6330）演算法。本專案不提供任何顯式或默示之專利授權擔保（包括但不限於 Qualcomm Incorporated 或其他實體持有之專利）。使用者若將本系統用於商業化產品部署，需自行評估並取得相關專利授權。

### 4. 資訊收集與隱私政策 (Information collection and privacy policy)
請參閱[https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/PRIVACY.md](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/blob/main/PRIVACY.md)

---

## 🔒 資安防護與審計機制 (Security & Audit Integration)

NDcode 3 內建以下安全架構入口：
* **HMAC-SHA256 手掌握手驗證**：防禦未授權連線與重放攻擊 (Replay Attack)。
* **Dynamic Key Rotation**：支援不中斷服務的雙向金鑰環動態輪替。
* **Traffic Obfuscation**：封包位元組混淆（u16 長度欄位防溢位防護），並對未知來源的 8-byte 封包提供拒收防護。
* **Gradient-Mesh 反向梯度控制**：雙向流量 / 背壓回饋機制。
* **EULA Guard**：整合 `.ndcode3_eula_accepted` 標記檔與 `NDCODE3_ACCEPT_EULA` 環境變數。
* **Structured Audit Log**：非同步記錄 JSONL 審計日誌，並支援自動加密備份。

---

## 架構 (Architecture)

### 純連線端串流壓縮 (Standalone / 雙端皆 Client)

本模式**不需要中繼伺服器**，兩個端點皆以 `--mode client --standalone` 執行，透過 TCP 直接配對。下載流量在 TUN 層被分類並串流壓縮。

```text
[ 用戶端 A TUN (Layer 3) ]                  [ 用戶端 B TUN (Layer 3) ]
        │  Raw IP Packets                            ▲  Raw IP Packets
        ▼                                            │
┌───────────────────────────────┐        ┌───────────────────────────────┐
│  NDcode 3 串流壓縮引擎 (上行)      │        │ NDcode 3 串流解壓引擎 (下行)    │
│ 1. 流量分類器 (FlowKey)           │        │ 5. 解除混淆 (Obfuscator)        │
│ 2. 封包緩衝 / TCP FIN 偵測        │  TCP   │ 6. NDcode3 / XZ 解壓           │
│ 3. 熵值判斷:                      │◄─────►│ 7. 訊框還原 (unframe)          │
│    - 低熵 (<5.0) → XZ 串流        │        │ 8. 寫回 TUN                    │
│    - 中/高熵 → NDCodeLogic::      │        │                               │
│       build_chained_cascade      │        │                               │
│ 4. 混淆 (Obfuscator)             │        │                               │
└───────────────────────────────┘        └───────────────────────────────┘
        │  HMAC-SHA256 握手 + 加密通道                                     │
```

### 中繼模式 (Server / Client)

由一台 Server 作為中繼，多台 Client 連入；Server 端完成握手驗證後僅負責解壓還原與卸載 (sink)。

---

## 系統運作流程 (Packet Pipeline)

```text
[ TUN 虛擬網卡 (Layer 3) ]
           │
           ▼ Raw IP Packets
┌─────────────────────────────────────────────────────────────────┐
│                 NDcode 3 網路節流引擎                             │
├─────────────────────────────────────────────────────────────────┤
│ 1. 封包大小 / 流量分類 (Traffic Classifier, FlowKey)              │
│    - HTTP(80) / HTTPS(443) 識別，TCP FIN 邊緣偵測                  │
│ 2. 熵值判斷 (Shannon Entropy)                                     │
│    - 低熵 (< 5.0) ──► 純 XZ (LZMA2) 高速串流                       │
│    - 中/高熵 (>= 5.0) ──► NDCodeLogic::build_chained_cascade()    │
│       (SIMD 差值 → XZ 預壓縮 → RaptorQ 噴泉碼 → 像素網格連鎖)       │
│ 3. 附加引擎標籤 ENGINE_TAG_NDCODE3 (0x05) + 長度前導               │
│ 4. 混淆 (Obfuscator) 並傳輸                                        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────┴──────────────────────────────┐
│ 5. 接收端: 解除混淆 → decode_segment()                        │
│    - ENGINE_TAG_NDCODE3 → logic.decode_ndcode3_stream()      │
│    - 低熵 XZ → xz_decompress()                                │
│ 6. unframe_packets 還原原始 IP 封包 → 寫回 TUN                 │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚙️ 前置需求與 NDcode3 核心引擎

本倉庫**不含 NDcode3 核心引擎原始碼**（自有 / 閉源，7.02 MB）。Cargo.toml 以路徑相依 `NDcode3 = { path = "NDcode3", ... }` 引用。

### 取得核心引擎
1. 於本專案根目錄建立 `NDcode3/` 目錄。
2. 將 NDcode3 核心引擎（含 `Cargo.toml`、`src/`、`assets/`）放置於 `NDcode3/` 下。
3. 確認版本對應與 `features = ["xz2"]` 相容。

> `NDcode3/` 已被 `.gitignore` 排除，不會納入版本控制。

### 建置 (Build)

前置需求：
- **Rust nightly toolchain**（NDcode3 依賴 `#![feature(portable_simd)]`）
- **系統管理員權限**（建立 TUN 虛擬網卡；Windows 上需 Administrator）

```bash
cargo +nightly build --release
```

> 若編譯記憶體不足，可設 `$env:CARGO_BUILD_JOBS="1"` 與 `$env:CARGO_PROFILE_DEV_DEBUG="0"`。

### 檢查與測試
```bash
cargo +nightly check
cargo +nightly test --bin NTORS
```

---

## CLI 使用方式 (Usage)

> 完整的可執行腳本範例請見 [`examples/`](examples/) 目錄：
> - [`standalone.ps1`](examples/standalone.ps1) — 純連線端雙端互連
> - [`relay_mode.ps1`](examples/relay_mode.ps1) — 中繼模式（Server / Client）
> - [`cli_reference.txt`](examples/cli_reference.txt) — 完整參數參考
> - [`ndcode_config.example.json`](examples/ndcode_config.example.json) — 設定檔範例

### 互動式設定精靈
首次執行（或不存在 `ndcode_config.json` 時）會自動進入跨平台互動式設定精靈，或手動指定：
```bash
sudo ./target/release/NTORS --setup
```

### 純連線端模式（雙端皆 Client，無需中繼伺服器）
```bash
# 端點 A（壓縮端）
sudo ./target/release/NTORS --mode client --standalone --server-addr <END_POINT_B_IP>:8080 --scope http

# 端點 B（解壓端，互連）
sudo ./target/release/NTORS --mode client --standalone --server-addr <END_POINT_A_IP>:8080 --scope http-https
```

### 中繼模式
> Server mode
```bash
sudo ./target/release/NTORS --mode server --listen-addr 0.0.0.0:8080
```
> Client mode
```bash
sudo ./target/release/NTORS --mode client --server-addr <SERVER_IP>:8080
```

### TLS/SSL 加密傳輸
```bash
# Server：啟用 TLS（--tls-cert / --tls-key 可指定 PEM；未指定則自動自簽）
sudo ./target/release/NTORS --mode server --listen-addr 0.0.0.0:8080 --tls

# Client：以 --tls-ca 信任自簽憑證，或 --tls-insecure 跳過憑證驗證（HMAC 仍驗證身份）
sudo ./target/release/NTORS --mode client --server-addr <SERVER_IP>:8080 --tls --tls-ca server_cert.pem
```

### 完整參數 (CLI Reference)
| 參數 | 說明 | 預設值 |
| :--- | :--- | :--- |
| `-m, --mode <client\|server>` | 執行模式 | `client` |
| `-s, --server-addr <ADDR>` | [Client] 遠端位址 | `127.0.0.1:8080` |
| `-l, --listen-addr <ADDR>` | [Server] 監聽位址 | `0.0.0.0:8080` |
| `--tun-name <NAME>` | TUN 虛擬網卡名稱 | `tun0` |
| `--tun-ip <IP>` | TUN 網卡 IP | `10.0.0.1` |
| `--tun-netmask <MASK>` | TUN 子網路遮罩 | `255.255.255.0` |
| `--standalone` | 純連線端模式（雙端皆 Client） | `false` |
| `--scope <http\|http-https\|all>` | 串流壓縮涵蓋範圍 | `http` |
| `--tls` | 啟用 TLS/SSL 加密傳輸 (rustls) | `false` |
| `--tls-cert <PEM>` | [Server] TLS 憑證檔 | - |
| `--tls-key <PEM>` | [Server] TLS 私鑰檔 | - |
| `--tls-ca <PEM>` | [Client] 可信任的伺服器憑證 | - |
| `--tls-insecure` | [Client] 跳過 TLS 憑證驗證 | `false` |
| `--traffic-stats` | 啟用即時流量統計顯示 (見 `src/traffic_meter.rs`) | `false` |
| `--traffic-interval <SEC>` | 流量統計輸出間隔秒數 | `10` |
| `--auto-elevate` | Windows 非管理員時自動 UAC 重新啟動 | `false` |
| `--setup` | 進入互動式設定精靈 | - |

**說明**：
- `--scope all` 為最後階段預留介面，尚未實作。
- 在 `server` 模式下，`--standalone` / `--scope` 會被忽略（Server 僅解碼後 sink，未寫回 TUN）。

---

## 串流區段線路協定 (Streaming Segment Wire Protocol)

每個串流壓縮區段為 self-contained，格式如下：

```text
[0x02] [engine_tag u8] [len_be u32] [encoded_bytes...]
```

| 欄位 | 長度 | 說明 |
| :--- | :---: | :--- |
| 前導 | 1 byte | `0x02` 串流區段標記 |
| `engine_tag` | 1 byte | 引擎標籤：`0x01` = XZ、`0x05` = NDcode3 |
| `len_be` | 4 bytes | 後方編碼資料之 big-endian 長度 |
| `encoded_bytes` | 可變 | 各引擎之壓縮 / 編碼輸出 |

> 訊框層（壓縮前）使用 `[len_be u16][full IP packet]`；解壓後 `unframe_packets` 逐一還原 IP 封包。

---

## 🧩 Wasm 沙盒解壓隧道 (Code-as-Data Decompression)

連線握手階段由 Client 上傳 `decompress.wasm`（二進位 WebAssembly），接收端將其放入 **wasmi 2.0 跨平台沙盒**執行以解開資料框；沙盒與 `conn_id` 綁定，連線關閉即自動卸載並抹除。可於中繼 / 雙端間彈性分攤解壓運算，並隔離不可信程式碼（Cargo 相依見 `src/wasm_tunnel.rs`）。

### 沙盒防護 (Sandbox Hardening)
- **記憶體上限 2 MiB**（`StoreLimits` + 記憶體 max 32 頁）與 **CPU fuel 預算 500,000 op**（耗盡即 trap）。
- **輸出上限 1 MiB**；僅接受**二進位 .wasm**（不允許 WAT 文字格式）且 **≤256 KiB**；禁用 `start` 函式。
- `EnforcedLimits::strict()`；每次執行於全新 Store 實例化，返回前將沙盒記憶體清零。
- 1 GiB 專用執行緒 stack，保證 fuel trap 恆先於宿主 stack 溢位；同時至多 4 個沙盒執行緒並行（全域號誌）。
- 註冊表上限 1024 個 session；解壓失敗自動 `uninstall(conn_id)`。

### Wire 框格式 (Tunnel Frame)
```text
[0x57] [kind u8] [conn_id u64 (LE)] [body_len u32 (LE)] [body...]
```
| 欄位 | 大小 | 說明 |
| :--- | :---: | :--- |
| 魔數 | 1 byte | `0x57` |
| `kind` | 1 byte | `0x27` = 握手（body 為 `decompress.wasm` 二進位）、`0x21` = 資料框 |
| `conn_id` | 8 bytes | 連線 ID（綁定沙盒） |
| `body_len` | 4 bytes | body 長度（LE） |
| `body` | 可變 | 握手：wasm 二進位；資料：壓縮載荷 |

### Guest ABI 契約
Guest 必須 export：
- `memory`（1~32 頁）
- `decompress(in_ptr i32, in_len i32, out_ptr i32, out_cap i32) -> i32`
  - 輸入緩衝固定位址 `0`；輸出緩衝固定位址 `0x100000`（1 MiB）。
  - 回傳輸出長度，失敗回傳 `-1`。

> 大量解壓建議使用 bulk 指令（`memory.fill` / `memory.copy`）或拆分段落，以降低逐位元組迴圈所消耗的 fuel / stack。

---

## 效能調校 (Performance Tuning)

NAT / relay 環境常見瓶頸為 OS 網路緩衝。本專案可自動調整：

- **Linux**: 寫入 `/etc/sysctl.d/99-ndcode.conf`（rmem/wmem=16MB、netdev_max_backlog 等）。
- **macOS**: `sysctl net.inet.tcp.sendspace/recvspace`。
- **Windows**: `netsh interface tcp set global autotuninglevel=normal`。

多半由互動式設定精靈自動完成，亦可於執行時手動確認。

---

## 測試 (Tests)

內建單元測試涵蓋：
- 訊框封裝 / 解封（含截斷尾端丟棄、空封包跳過）。
- **Frame 長度防護**：越界 / 零長度長度前綴阻絕（`MAX_FRAME_LEN`，防止 OOM）。
- XZ 串流往返 (roundtrip)。
- Adaptive 串流（熵值切換引擎）往返。
- **NDcode3 連鎖編碼串流** 往返（`ENGINE_TAG_NDCODE3`）。
- 流量分類（HTTP / HTTPS / 非 IPv4 / 其他 UDP / TCP FIN 偵測）。
- TLS/SSL：真實握手雙向傳送、錯誤 CA 阻絕、insecure 連線。
- 套件封裝 header 校驗與非法資料阻絕。

```bash
cargo +nightly test --bin NTORS        # 23 bin 測試
cargo +nightly test                     # 全部測試 (66)
```

---

## 🗂️ 版本控制 (Version Control)

本專案使用 Git 管理版本：

```bash
git log --oneline          # 檢視提交歷史
git status                 # 檢視變更狀態
git diff                   # 檢視未提交的變更
```

- 所有原始碼與文件皆納入版控；`NDcode3/`（核心引擎）與 `target/`（編譯產物）已於 `.gitignore` 排除。
- 提交訊息使用 Conventional Commits 風格（`feat:`、`fix:`、`docs:`、`chore:`）。

---

## 🙏 開源專案致謝 (Acknowledgements)

感謝以下優秀開源專案及其開發團隊對 NTORS 與 NDcode 3 的無私貢獻：

1. **[Rust Programming Language](https://www.rust-lang.org/)** - 高效、安全的系統程式語言
2. **[Tokio](https://tokio.rs/)** - Rust 非同步 Runtime 執行期
3. **[Hyper](https://hyper.rs/)** - 高效能 HTTP / Socket 網路堆疊
4. **[tun](https://crates.io/crates/tun)** & **[WinTun](https://wintun.net/)** - Linux/macOS TUN 與 Windows WinTun 虛擬網卡驅動
5. **[Clap](https://crates.io/crates/clap)** - 命令列參數解析器
6. **[Anyhow](https://crates.io/crates/anyhow)** - 彈性錯誤處理庫
7. **[Cargo-cross](https://crates.io/crates/cargo-cross)** - 嵌入式與 ARM64/樹莓派 零配置跨平台編譯工具
8. **[Criterion](https://crates.io/crates/criterion)** - 統計級系統效能 Benchmark 工具
9. **[Rand](https://crates.io/crates/rand)** - 密碼學隨機數產生器
10. **[Serde](https://crates.io/crates/serde)** & **[Serde_json](https://crates.io/crates/serde_json)** - 高效能資料序列化與 JSON 處理器
11. **[NDcode3](NDcode3/README.md)** - 多維雙軌 QR 與連鎖網格編碼引擎（本專案核心引擎）

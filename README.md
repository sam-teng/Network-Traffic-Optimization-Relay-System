[![Build NTORS Rust APP Upload a Build Artifact](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/rust.yml/badge.svg)](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/rust.yml)
# Network-Traffic-Optimization-Relay-System(NTORS)
Network Traffic Optimization &amp; Relay System

- **Contributors can use AI, except for those with invisible watermarks (such as Claude, etc.)!**

# Network Traffic Optimization Relay System (NTORS) - NDcode 3

NDcode 3 (Network Traffic Optimization Relay System) 是一個高效能、跨平台的開源網路流量最佳化中繼架構，結合多維條碼/噴泉網格編碼（NDcode 3）、Tokio 非同步管線與核心網路參數調校，專為提升網路傳輸效率與穩定性而設計。

* **GitHub Repository**: [https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/)
* **Copyright**: Copyright (c) 2026 Sam Teng. All rights reserved.

---

## ⚠️ 免責聲明與法律條款 (Disclaimer & Legal Notice)

### 1. 軟體使用與現狀聲明 (As-Is Notice)
本軟體以「現狀 (As-Is)」提供，不保證服務不中斷或完全無誤。使用者須自行承擔執行系統層級權限變更（如建立 TUN 虛擬網卡、載入核心驅動及調整 `sysctl` / `netsh` 網路參數）之風險。

### 2. 雙重用途與相關電信法規 (Regulatory Compliance)
# ***本軟體專為學術研究、教育訓練與個人合法網路最佳化而開發。使用者在使用本系統時，必須嚴格遵守當地網路通訊與資訊安全法規（例如《中華民國刑法》第 36 章妨害電腦使用罪）。禁止將本軟體用於任何未經授權之流量攔截、竊聽、惡意跳板或商業等違法用途。***

### 3. 專利與演算法免責聲明 (Patent Disclaimer)
NDcode 3 包含引用[https://crates.io/crates/raptorq](https://crates.io/crates/raptorq)多維網格編碼與前向糾錯（FEC / RaptorQ - RFC 6330）演算法。本專案不提供任何顯式或默示之專利授權擔保（包括但不限於 Qualcomm Incorporated 或其他實體持有之專利）。使用者若將本系統用於商業化產品部署，需自行評估並取得相關專利授權。

### 4. 資訊收集與隱私政策 (Information collection and privacy policy)
請參閱[PRIVACY.md](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/PRIVACY.md)

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

---

## 🔒 資安防護與審計機制 (Security & Audit Integration)

NDcode 3 內建以下安全架構入口：
* **HMAC-SHA256 手掌握手驗證**：防禦未授權連線與重放攻擊 (Replay Attack)。
* **Dynamic Key Rotation**：支援不中斷服務的雙向金鑰環動態輪替。
* **EULA Guard**：整合 `.ndcode3_eula_accepted` 標記檔與 `NDCODE3_ACCEPT_EULA` 環境變數。
* **Structured Audit Log**：非同步記錄 JSONL 審計日誌，並支援自動加密備份。

> 系統運作架構 (Architecture)

```text
[ TUN 虛擬網卡 (Layer 3) ]
           │
           ▼ Raw IP Packets
┌─────────────────────────────────────────────────────────────────┐
│                 NDcode 3 網路節流引擎                             │
├─────────────────────────────────────────────────────────────────┤
│ 1. 封包大小檢測 (Packet Threshold Inspection)                     │
│    - 小封包 (< 1024B) ──> 純 XZ (LZMA2) 高速串流                   │
│    - 大封包 (>= 1024B) ─┐                                        │
│                        ▼                                        │
│ 2. 呼叫 NDCodeLogic::build_chained_cascade()                     │
│    - 逐位元組 SIMD 差值計算                                        │
│    - XZ 預壓縮                                                   │
│ 3. 附加 MASTER_MAGIC_HEADER (b"ND3:")                            │
│ 4.    跳過渲染 ──> 直接輸出位元串流 (Raw Bytes)                      │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼ 傳輸至遠端代理伺服器 (Server)
┌──────────────────────────────┴──────────────────────────────┐
│ 5. 接收端 parse_and_decode_incoming_stream()                 │
│    - 檢查 Header 類型                                        │
│    - 走 safe_xz_decompress() 與連鎖鏈還原原始 IP 封包           │
└─────────────────────────────────────────────────────────────┘
```

# ***How to use***
> Server mode
```bash
sudo ./target/release/NTORS --mode server --listen-addr 0.0.0.0:8080
```

> Client mode
```bash
sudo ./target/release/NTORS --mode client --server-addr <SERVER_IP>:8080
```

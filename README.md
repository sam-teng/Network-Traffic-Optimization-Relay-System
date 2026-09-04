[![Build NTORS Rust APP Upload a Build Artifact](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/rust.yml/badge.svg)](https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/actions/workflows/rust.yml)
# Network-Traffic-Optimization-Relay-System(NTORS)
Network Traffic Optimization &amp; Relay System

- **Contributors can use AI, except for those with invisible watermarks (such as Claude, etc.)!**

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

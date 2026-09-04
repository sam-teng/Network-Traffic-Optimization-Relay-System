# NDcode 3 (NTORS) - 隱私政策與資料處理透明化聲明 (Privacy Policy & Transparency Notice)

**生效日期**：2026 年 9 月 5 日  
**適用架構**：NDcode Version 3 多維網格與噴泉編碼轉接管線 (Linux / macOS / Windows)

NDcode 3 開發團隊極為重視使用者的資訊隱私與資料安全。本軟體設計遵循「預設隱私 (Privacy by Design)」與「最小化收集 (Data Minimization)」原則，以下說明本系統運作時的資料處理細節：

---

## 1. 零封包內容檢查聲明 (Zero Payload Inspection)
NDcode 3 作為底層網路轉接與噴泉編碼 (RaptorQ / XZ) 節流管線，**絕不記錄、讀取、分析或儲存任何經過 TUN/TAP 網卡或 Socket 傳輸的用戶封包實際內容 (Payload)**。所有轉接封包僅在記憶體 (RAM) 中完成切片編碼與動態流量控制，隨即送出並釋放記憶體。

---

## 2. 審計與維運資料收集範圍 (Logged Metadata)
當啟動本地審計日誌 (`AuditPipeline`) 時，系統僅收集以下維運必備的去識別化後中繼資料 (Metadata)：

| 資料項目 | 收集目的 | 保存位置 |
| :--- | :--- | :--- |
| **時間戳記 (Timestamp)** | 防禦 HMAC 重放攻擊與紀錄統計 | 本地 `.jsonl` 日誌檔 |
| **客戶端 IP 位址** | 連線鑑別與異常存取排查（支援 IP 遮蔽匿名化） | 本地 `.jsonl` 日誌檔 |
| **HMAC Key ID** | 辨識金鑰環 (Keyring) 驗證身份 | 本地 `.jsonl` 日誌檔 |
| **傳輸效能指標** | 統計吞吐量 (Throughput) 與噴泉碼恢復率 (FEC Rate) | 本地 `.jsonl` 日誌檔 |

---

## 3. 無回傳與純本地處理聲明 (Zero Telemetry & Phoning-Home)
* **無遠端伺服器回傳**：NDcode 3 為 100% 獨立運行之開源軟體，不包含任何診斷資料上傳、Telemetry 追蹤或「電話回報 (Phoning-Home)」機制。
* **本地化儲存**：所有產生的審計日誌與 `.ndcode3_eula_accepted` 同意檔均嚴格儲存於使用者自訂的本地檔案系統，未經管理員手動匯出，絕不會離開宿主機。

---

## 4. 資料保留期限與自動清理 (Data Lifecycle)
* **日誌自動輪替與 Gzip 壓縮**：當單一 `.jsonl` 日誌檔超過 10MB 時，系統會自動非同步進行壓縮備份。
* **過期 purge 機制**：可設定 `NDCODE3_LOG_RETENTION_DAYS` 環境變數（預設 365 天，最少 14 天），過期之備份日誌將由系統背景任務自動刪除，避免佔用磁碟空間。

---

## 5. 使用者控制權 (User Opt-out & Privacy Controls)
使用者具備最高資料掌控權，可透過以下方式停用或提高隱私保護層級：
1. **完全關閉日誌**：設定環境變數 `NDCODE3_LOG_LEVEL=off` 或設定 CLI 參數 `--silent`。
2. **啟動 IP 匿名化**：設定環境變數 `NDCODE3_ANONYMIZE_IP=1`，系統將自動以 SHA-256 遮蔽 IP 後兩位數。
3. **手動清除**：可隨時直接刪除專案目錄下的 `logs/` 資料夾與 `.ndcode3_eula_accepted` 檔案。

# NTORS 中繼模式範例 (Client / Server)
# 用法: Windows PowerShell 下執行，或改為 bash 對應指令

# ── 伺服器端 (中繼，解壓後 sink) ────────────────────────────
# -m server               伺服器模式
# -l 0.0.0.0:8080         監聽所有介面
# --tls                   啟用 TLS（自動產生自簽憑證，Client 需 --tls-ca 或 --tls-insecure）
& ".\target\release\NTORS.exe" --mode server `
    --listen-addr "0.0.0.0:8080" `
    --tls

# ── 用戶端 (連入伺服器) ─────────────────────────────────────
# -m client               用戶端模式
# -s <SERVER_IP>:8080     伺服器位址
# --tls --tls-insecure    連 TSL，跳過憑證驗證（身份仍由 HMAC 握手確認）
& ".\target\release\NTORS.exe" --mode client `
    --server-addr "192.168.1.10:8080" `
    --tls `
    --tls-insecure
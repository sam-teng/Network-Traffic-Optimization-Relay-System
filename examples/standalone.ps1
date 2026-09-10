# NTORS Standalone 純連線端模式範例
# 用法: Windows PowerShell 下執行，或改為 bash 對應指令
#
# Standalone 模式 = 雙端皆為 Client，無需中繼伺服器。
# 端點 A 壓縮上傳，端點 B 解壓還原並寫回 TUN。

# ── 端點 A（壓縮端，連至端點 B）──────────────────────────────
# -m client --standalone       純連線端模式
# -s <END_POINT_B_IP>:8080    對端位址（端點 B）
# --scope http                串流壓縮涵蓋範圍 (http / http-https / all)
# --tun-ip 10.0.0.2           本機 TUN 網卡 IP（與端點 B 不同）
& ".\target\release\NTORS.exe" --mode client --standalone `
    --server-addr "192.168.1.50:8080" `
    --scope http `
    --tun-ip "10.0.0.2"

# ── 端點 B（解壓端，互連至端點 A）──────────────────────────────
# --scope http-https  同時壓縮 HTTP + HTTPS 下行流量
& ".\target\release\NTORS.exe" --mode client --standalone `
    --server-addr "192.168.1.40:8080" `
    --scope http-https `
    --tun-ip "10.0.0.3"
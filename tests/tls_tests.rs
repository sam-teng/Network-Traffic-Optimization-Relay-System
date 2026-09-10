use anyhow::Result;
use ntors::tls;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn write_temp_pem(prefix: &str, pem: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = d.join(format!("ntors_{prefix}_{ts}.pem"));
    std::fs::write(&path, pem).unwrap();
    path
}

/// 完整 TLS 握手 + 資料傳輸往返 (自簽憑證，client 用 --tls-ca pin 驗證)
#[tokio::test]
async fn test_tls_handshake_two_way_transfer() -> Result<()> {
    // Server: 自動自簽 (但不輸出 pem 檔案 ── 直接抓取 PEM 字串給 client)
    let (cert_der, key_der, cert_pem) = tls::generate_self_signed();
    let server = tls::server_tls_raw(cert_der, key_der)?;
    let accepted = Arc::new(server);

    let ca_file = write_temp_pem("ca", &cert_pem);

    // 建立 Server listener
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Server task: accept → TLS handshake → 收 5 bytes → 回傳
    let srv = accepted.clone();
    let srv_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut conn = srv.accept(tcp).await.unwrap();
        let mut buf = [0u8; 5];
        conn.read_exact(&mut buf).await.unwrap();
        conn.write_all(b"pong!").await.unwrap();
        conn.flush().await.unwrap();
        buf
    });

    // Client: 以 CA 檔案 pin 驗證連線
    let client = tls::client_tls(Some(ca_file.to_str().unwrap()), false)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut conn = client.connect(tcp).await?;
    conn.write_all(b"hello").await?;
    conn.flush().await?;
    let mut resp = [0u8; 5];
    conn.read_exact(&mut resp).await?;

    let recv = srv_task.await.unwrap();
    assert_eq!(&recv, b"hello", "Server 端應收到 hello");
    assert_eq!(&resp, b"pong!", "Client 端應收到 pong!");

    let _ = std::fs::remove_file(&ca_file);
    Ok(())
}

/// TLS 加 pin 驗證且憑證不符時握手應失敗 (防替換)
#[tokio::test]
async fn test_tls_wrong_ca_rejected() -> Result<()> {
    // Server 自簽 cert A
    let (cert_der, key_der, cert_pem_a) = tls::generate_self_signed();
    let (_, _, _cert_pem_b) = tls::generate_self_signed();
    let server = tls::server_tls_raw(cert_der, key_der)?;
    let accepted = Arc::new(server);

    // Client 用「不同的」CA 憑證 pin → 握手應被拒絕
    let ca_file = write_temp_pem("wrong_ca", &_cert_pem_b);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let srv = accepted.clone();
    let srv_task = tokio::spawn(async move {
        // Server 端 TLS handshake 本身會成功 (因 server 接受任何 client；驗證是 client 端)
        let (tcp, _) = listener.accept().await.unwrap();
        srv.accept(tcp).await
    });

    let client = tls::client_tls(Some(ca_file.to_str().unwrap()), false)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    // 驗證 client 方向握手失敗 或 server 端握手失敗皆可
    let client_res = client.connect(tcp).await;
    let server_res = srv_task.await.unwrap();

    // 至少一端應失敗 (此處 client pin 不符 → client 握手必失敗)
    assert!(client_res.is_err(), "憑證不符時 Client 握手應失敗");
    let _ = server_res;

    let _ = std::fs::remove_file(&ca_file);
    Ok(())
}

/// insecure 模式：任何憑證皆可連線
#[tokio::test]
async fn test_tls_insecure_connects() -> Result<()> {
    let (cert_der, key_der, _pem) = tls::generate_self_signed();
    let server = Arc::new(tls::server_tls_raw(cert_der, key_der)?);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let srv = server.clone();
    let srv_task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut conn = srv.accept(tcp).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut buf = [0u8; 3];
            conn.read_exact(&mut buf).await.unwrap();
            buf
        })
        .await
        .unwrap()
    });

    let client = tls::client_tls(None, true)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let mut conn = client.connect(tcp).await?;
    conn.write_all(b"hi!").await?;
    conn.flush().await?;

    let recv = srv_task.await.unwrap();
    assert_eq!(&recv, b"hi!");
    Ok(())
}
// src/tls.rs - TLS/SSL 加密傳輸層 (rustls)
//
// 設計原則：
//   1. Server 端憑證：接受 `--tls-cert` + `--tls-key` 載入 PEM；未提供時自動以 rcgen
//      產生自簽憑證 (固定 SAN: ndcode3)，PEM 字串一併回傳供設定精靈/訊息印出。
//   2. Client 端驗證：接受 `--tls-ca` (信任該 PEM 憑證，含自簽場景) 正常驗證，或以
//      `--tls-insecure` 跳過驗證。
//   3. 管線層全部泛型化 (AsyncRead/AsyncWrite)，故 TLS 分支直接使用
//      tokio_rustls::client::TlsStream / server::TlsStream，不需統一 enum。

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;

/// NDcode 自簽憑證固定的 SAN (DNS 名稱)。Client 以此為 ServerName 進行驗證。
pub const SERVER_NAME: &str = "ndcode3";

/// Server 端 TLS 綁定組態 (acceptor + 憑證 PEM)
#[derive(Clone)]
pub struct ServerTls {
    acceptor: tokio_rustls::TlsAcceptor,
    _cert_pem: String,
}

/// Client 端 TLS 綁定組態 (connector + 固定 ServerName)
#[derive(Clone)]
pub struct ClientTls {
    connector: tokio_rustls::TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
}

/// 建立 Server 端 TLS：
/// - `cert_pem_path` / `key_pem_path` 兩者同時提供時載入 PEM；
/// - 皆為 None 時自動產生自簽憑證 (SAN: ndcode3)。
pub fn server_tls(
    cert_pem_path: Option<&str>,
    key_pem_path: Option<&str>,
) -> Result<ServerTls> {
    let (cert_der, key_der, cert_pem) = if let (Some(c), Some(k)) = (cert_pem_path, key_pem_path) {
        let cert = load_cert_der(c)?;
        let key = load_private_key_der(k)?;
        let pem = file_text(c)?;
        (cert, key, pem)
    } else if cert_pem_path.is_some() || key_pem_path.is_some() {
        bail!("--tls-cert 與 --tls-key 必須同時提供");
    } else {
        let (cert, key, pem) = generate_self_signed();
        (cert, key, pem)
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("ServerConfig 不支援安全預設 TLS 版本")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("無法載入 Server TLS 憑證與私鑰")?;

    Ok(ServerTls {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        _cert_pem: cert_pem,
    })
}

impl ServerTls {
    /// 接受 TCP 連線並完成 TLS 握手
    pub async fn accept(&self, tcp: TcpStream) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
        self.acceptor
            .accept(tcp)
            .await
            .context("Server TLS 握手失敗")
    }
}

/// 建立 Client 端 TLS：
/// - `ca_pem_path` Some：以 --tls-ca 認定伺服器憑證 (自簽場景 pinning)；
/// - `insecure` true：跳過憑證驗證 (需上層 HMAC 握手做身份確認)。
pub fn client_tls(ca_pem_path: Option<&str>, insecure: bool) -> Result<ClientTls> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("ClientConfig 不支援安全預設 TLS 版本")?;

    let config = if let Some(ca) = ca_pem_path {
        let pinned = load_cert_der(ca)?;
        Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier { pinned }))
                .with_no_client_auth(),
        )
    } else if insecure {
        Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifyVerifier))
                .with_no_client_auth(),
        )
    } else {
        bail!("--tls 需要 --tls-ca (信任憑證) 或 --tls-insecure (跳過驗證) 之一")
    };

    let server_name = rustls::pki_types::ServerName::try_from(SERVER_NAME.to_string())
        .context("無法建立 TLS ServerName")?;

    Ok(ClientTls {
        connector: tokio_rustls::TlsConnector::from(config),
        server_name,
    })
}

impl ClientTls {
    /// 以 TLS 連接到指定 TCP
    pub async fn connect(&self, tcp: TcpStream) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
        self.connector
            .connect(self.server_name.clone(), tcp)
            .await
            .context("Client TLS 握手失敗")
    }
}

/// 以 rcgen 產生自簽憑證：回傳 (cert_der, key_der, pem 字串)
pub fn generate_self_signed(
) -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
    String,
) {
    let CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
            .expect("rcgen self-signed 產生失敗");

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
    );
    let pem = cert.pem();
    (cert_der, key_der, pem)
}

/// 以既有的 cert_der/key_der 直接建立 ServerTls (供測試與程式化注入)
pub fn server_tls_raw(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<ServerTls> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("ServerConfig 不支援安全預設 TLS 版本")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("無法載入 Server TLS 憑證與私鑰")?;

    Ok(ServerTls {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        _cert_pem: String::new(),
    })
}

use rcgen::CertifiedKey;

/// 載入 TLS 憑證 (PEM -> DER)
pub fn load_cert_der(pem_path: &str) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let file = File::open(pem_path).with_context(|| format!("無法開啟憑證檔: {pem_path}"))?;
    let mut reader = BufReader::new(file);
    let mut certs = rustls_pemfile::certs(&mut reader);
    certs
        .next()
        .context("憑證檔中沒有 PEM 憑證")?
        .with_context(|| format!("解析憑證失敗: {pem_path}"))
}

/// 載入 TLS 私鑰 (PEM -> DER)
pub fn load_private_key_der(pem_path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(pem_path).with_context(|| format!("無法開啟私鑰檔: {pem_path}"))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("解析私鑰失敗: {pem_path}"))?
        .with_context(|| format!("私鑰檔中沒有 PEM 私鑰: {pem_path}"))
}

fn file_text(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("無法讀取檔案: {path}"))
}

/// 固定的伺服器憑證驗證器：比對端點憑證 DER 與 pin 的 DER (自簽/私有 CA 場景)。
#[derive(Debug)]
struct PinnedCertVerifier {
    pinned: rustls::pki_types::CertificateDer<'static>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.pinned.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "伺服器憑證與 --tls-ca 不符 (可能遭替換)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 接受任何憑證的驗證器 (僅 --tls-insecure 使用；防中間人須依賴更上層 HMAC 握手)
#[derive(Debug)]
struct NoVerifyVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn test_generate_self_signed_produces_valid_pem() {
        let (cert, key, pem) = generate_self_signed();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
        assert!(!cert.is_empty());
        assert!(
            matches!(key, rustls::pki_types::PrivateKeyDer::Pkcs8(_)),
            "私鑰應為 PKCS8"
        );
    }

    #[test]
    fn test_self_signed_server_tls_builds() {
        let srv = server_tls(None, None).unwrap();
        assert!(!srv._cert_pem.is_empty());
    }

    #[test]
    fn test_client_tls_requires_ca_or_insecure() {
        // 兩者皆無 → 應報錯
        assert!(client_tls(None, false).is_err());
        // insecure → OK
        assert!(client_tls(None, true).is_ok());
    }

    #[test]
    fn test_client_tls_with_pinned_ca() {
        let (_, _, pem) = generate_self_signed();
        let mut tmp = std::env::temp_dir();
        let name = format!(
            "ntors_tls_ca_{}.pem",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        tmp.push(name);
        let mut f = File::create(&tmp).unwrap();
        f.write_all(pem.as_bytes()).unwrap();
        drop(f);

        let res = client_tls(Some(tmp.to_str().unwrap()), false);
        assert!(res.is_ok());
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_server_tls_loads_from_pem_files() {
        // 同一次產生的 cert + key (需配對，否則載入會失敗)
        use rcgen::CertifiedKey;
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()]).unwrap();
        let cert_pem = cert.pem();
        let key_pem = signing_key.serialize_pem();
        let d = std::env::temp_dir();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let cert_path = d.join(format!("ntors_tls_cert_{ts}.pem"));
        let key_path = d.join(format!("ntors_tls_key_{ts}.pem"));
        let mut fc = File::create(&cert_path).unwrap();
        fc.write_all(cert_pem.as_bytes()).unwrap();
        drop(fc);
        let mut fk = File::create(&key_path).unwrap();
        fk.write_all(key_pem.as_bytes()).unwrap();
        drop(fk);

        let res = server_tls(Some(cert_path.to_str().unwrap()), Some(key_path.to_str().unwrap()));
        assert!(res.is_ok());
        // 只給 cert → 應報錯
        assert!(server_tls(Some(cert_path.to_str().unwrap()), None).is_err());

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }
}
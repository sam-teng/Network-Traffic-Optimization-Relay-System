use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// 透過 TCP 發送經過 NDcode 壓縮處里的 Payload (長度前綴)
pub async fn send_framed_payload(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let length = payload.len() as u32;
    // 寫入 4 欄位長度標頭
    stream.write_u32(length).await.context("寫入長度標頭失敗")?;
    // 寫入實際 Payload
    stream.write_all(payload).await.context("寫入 Payload 數據失敗")?;
    stream.flush().await.context("Flush TCP stream 失敗")?;
    Ok(())
}

/// 從 TCP 接收完整的 NDcode Payload
pub async fn recv_framed_payload(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // 讀取 4 欄位長度標頭
    let length = stream.read_u32().await.context("讀取長度標頭失敗")? as usize;
    
    let mut buf = vec![0u8; length];
    stream.read_exact(&mut buf).await.context("讀取完整 Payload 失敗")?;
    Ok(buf)
}

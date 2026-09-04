use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 透過非同步串流發送經過 NDcode 壓縮處理的 Payload (長度前綴)
pub async fn send_framed_payload<W>(stream: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = payload.len() as u32;
    // 寫入 4 位元組 Big-Endian 長度標頭
    stream.write_u32(length).await.context("寫入長度標頭失敗")?;
    // 寫入實際 Payload
    stream.write_all(payload).await.context("寫入 Payload 數據失敗")?;
    stream.flush().await.context("Flush 串流失敗")?;
    Ok(())
}

/// 從非同步串流接收完整的 NDcode Payload
pub async fn recv_framed_payload<R>(stream: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    // 讀取 4 位元組 Big-Endian 長度標頭
    let length = stream.read_u32().await.context("讀取長度標頭失敗")? as usize;
    
    let mut buf = vec![0u8; length];
    stream.read_exact(&mut buf).await.context("讀取完整 Payload 失敗")?;
    Ok(buf)
}
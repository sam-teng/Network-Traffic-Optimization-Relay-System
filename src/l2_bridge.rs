//! src/l2_bridge.rs - L2 TAP 資料面橋接
//!
//! `tun_rs::AsyncDevice`（真 tun-rs crate，import `tun_rs`）**未實作**
//! `tokio::io::AsyncRead` / `AsyncWrite`，僅提供：
//!   * `pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>`
//!   * `pub async fn send(&self, buf: &[u8]) -> io::Result<usize>`
//!   * `pub fn poll_readable(&self, cx) -> Poll<io::Result<()>>`
//!
//! 而 NTORS 的 NDcode 管線以 `AsyncRead + AsyncWrite` 泛型驅動
//! （見 `main.rs::run_client_mode`）。舊 crate `tun`（import `tun`）的
//! `tun::AsyncDevice` 有內建 tokio trait 實作，新 crate 沒有。
//!
//! 本模組以「背景任務 + channel」轉接：
//!   * RX：背景任務 `loop { dev.recv(&mut buf).await }` → mpsc → `poll_recv`
//!   * TX：`poll_write` 直接丟入 unbounded channel，背景任務 `dev.send(&pkt).await`
//!
//! 語意對齊 TUN/TAP 裝置慣例：**每次 `poll_read` 回傳一個完整封包**
//! （等同 Linux TUN 的單次 read = 單一 IP packet）。

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Ethernet 標頭 14 bytes + 最大 MTU；另預留 packet-information 標頭空間。
/// 與 upstream `examples/async_tap.rs` 的 `vec![0; 14 + 65536]` 一致。
const L2_RECV_BUF: usize = 14 + 65536;

/// 可 Clone 的 L2 TAP 端點，同時實作 `AsyncRead` 與 `AsyncWrite`。
///
/// Clone 共用同一個 TAP 裝置，語意等同 `main.rs::SharedTun`
/// （`Arc<Mutex<tun::AsyncDevice>>`）以支援反覆重連。
#[derive(Clone)]
pub struct SharedL2 {
    inner: Arc<L2Inner>,
}

struct L2Inner {
    /// 已由背景任務取出、等待被管線消費的封包
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    /// 管線送入、等待背景任務寫入裝置的封包
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl SharedL2 {
    /// 由 `tun_rs::AsyncDevice` 建立橋接，並啟動 RX/TX 背景任務。
    ///
    /// 背景任務結束（裝置關閉 / I/O 錯誤）時會記錄日誌；
    /// RX channel 關閉後 `poll_read` 回傳 `BrokenPipe`，讓管線正常收尾。
    pub fn new(dev: Arc<tun_rs::AsyncDevice>) -> Self {
        // TX 用 unbounded：poll_write 不可 await，且封包已由管線分片，
        // 額外背壓交由管線自身的節流控制。
        let (tx, mut tx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        // RX 用有界，避免異常對端無限灌入封包耗盡記憶體。
        let (rx_tx, rx) = mpsc::channel::<Vec<u8>>(256);

        let dev_rx = Arc::clone(&dev);
        tokio::spawn(async move {
            let mut buf = vec![0u8; L2_RECV_BUF];
            loop {
                match dev_rx.recv(&mut buf).await {
                    Ok(n) => {
                        if n == 0 {
                            continue;
                        }
                        if rx_tx.send(buf[..n].to_vec()).await.is_err() {
                            break; // 管線已釋放 RX
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  [L2] TAP 讀取結束: {e}");
                        break;
                    }
                }
            }
        });

        let dev_tx = Arc::clone(&dev);
        tokio::spawn(async move {
            while let Some(pkt) = tx_rx.recv().await {
                if let Err(e) = dev_tx.send(&pkt).await {
                    eprintln!("⚠️  [L2] TAP 寫入失敗: {e}");
                    break;
                }
            }
        });

        Self {
            inner: Arc::new(L2Inner {
                rx: Mutex::new(rx),
                tx,
            }),
        }
    }
}

impl AsyncRead for SharedL2 {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 僅做非 await 的通道操作，鎖不會跨 poll 持有。
        let mut rx = this.inner.rx.lock().unwrap();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                buf.put_slice(&pkt);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "L2 TAP 讀取端已關閉",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SharedL2 {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.inner.tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            // RX 側關閉代表管線已結束，寫入無意義
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "L2 TAP 寫入端已關閉",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // 封包已交給 unbounded channel 背景任務，無需額外 flush
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recv_buf_covers_ethernet_mtu() {
        // 14 (Ethernet) + 1500 (MTU) 必須被容納
        assert!(L2_RECV_BUF >= 14 + 1500);
    }
}

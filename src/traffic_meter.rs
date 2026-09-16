// src/traffic_meter.rs - 流量計算 / 顯示模組
//
// 提供執行緒安全的流量計 (TrafficMeter)：以原子計數器統計上傳/下載的
// 位元組數與封包數，換算即時速率，並輸出人類可讀的統計摘要。
// 另附 async 計數包裝器 (CountingReader / CountingWriter / CountingSocket)，
// 可直接包覆 socket / TLS 串流，於主流程傳輸時自動計數。

use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 資料方向：上傳 (Upload = tx，送往對端) / 下載 (Download = rx，自對端接收)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Upload,
    Download,
}

/// 流量計：於建立時記錄起點，記錄 bytes/packets，提供速率與顯示。
#[derive(Debug, Clone)]
pub struct TrafficMeter {
    inner: Arc<TrafficMeterInner>,
}

#[derive(Debug)]
struct TrafficMeterInner {
    started: Instant,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    // 區間流量基準點：(上次間隔取樣時間, 當時 tx, 當時 rx)
    interval: Mutex<Option<(Instant, u64, u64)>>,
}

impl Default for TrafficMeter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMeter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(TrafficMeterInner {
                started: Instant::now(),
                tx_bytes: AtomicU64::new(0),
                rx_bytes: AtomicU64::new(0),
                tx_packets: AtomicU64::new(0),
                rx_packets: AtomicU64::new(0),
                interval: Mutex::new(None),
            }),
        }
    }

    /// 記錄一次「往對端送出」的資料量 (單一傳送事件視為一個封包)。
    pub fn record_tx(&self, bytes: u64) {
        self.inner.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.inner.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// 記錄一次「自對端接收」的資料量 (單一接收事件視為一個封包)。
    pub fn record_rx(&self, bytes: u64) {
        self.inner.rx_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.inner.rx_packets.fetch_add(1, Ordering::Relaxed);
    }

    /// 依方向記錄一次資料量。
    pub fn record(&self, dir: Direction, bytes: u64) {
        match dir {
            Direction::Upload => self.record_tx(bytes),
            Direction::Download => self.record_rx(bytes),
        }
    }

    pub fn tx_bytes(&self) -> u64 {
        self.inner.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.inner.rx_bytes.load(Ordering::Relaxed)
    }

    pub fn tx_packets(&self) -> u64 {
        self.inner.tx_packets.load(Ordering::Relaxed)
    }

    pub fn rx_packets(&self) -> u64 {
        self.inner.rx_packets.load(Ordering::Relaxed)
    }

    /// 總流量 (上傳 + 下載位元組)。
    pub fn total_bytes(&self) -> u64 {
        self.inner.tx_bytes.load(Ordering::Relaxed) + self.inner.rx_bytes.load(Ordering::Relaxed)
    }

    /// 區間流量：回傳自上次呼叫以來的上傳/下載增量，並重置基準點。
    /// 第一次呼叫僅建立基準 (增量為 0)，後續呼叫即反映兩次取樣間的區間流量。
    pub fn interval_stats(&self) -> IntervalStats {
        let now = Instant::now();
        let tx = self.tx_bytes();
        let rx = self.rx_bytes();
        let mut guard = self.inner.interval.lock().unwrap();
        let (start, tx0, rx0) = match *guard {
            Some((s, t, r)) => (s, t, r),
            None => (now, tx, rx),
        };
        let stats = IntervalStats {
            tx_bytes: tx.saturating_sub(tx0),
            rx_bytes: rx.saturating_sub(rx0),
            elapsed: now.duration_since(start),
        };
        *guard = Some((now, tx, rx));
        stats
    }

    /// 自建立以來的經過時間。
    pub fn elapsed(&self) -> Duration {
        self.inner.started.elapsed()
    }

    /// 取得當前彙總快照 (計數值 + 累計時間)。
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            tx_bytes: self.tx_bytes(),
            rx_bytes: self.rx_bytes(),
            tx_packets: self.tx_packets(),
            rx_packets: self.rx_packets(),
            elapsed: self.elapsed(),
        }
    }

    /// 上傳 / 下載速率 (bytes/sec)；以各自位元組數 + 總經過時間換算。
    pub fn tx_rate(&self) -> f64 {
        rate(self.tx_bytes(), self.elapsed())
    }

    pub fn rx_rate(&self) -> f64 {
        rate(self.rx_bytes(), self.elapsed())
    }

    /// 人類可讀統計摘要 (含速率與封包數)。
    pub fn display(&self) -> String {
        let snap = self.snapshot();
        let iv = self.interval_stats();
        format!(
            "📊 [流量統計] 執行 {} | 總流量: {} | 上傳: {} ({}/s, {} 封包) | 下載: {} ({}/s, {} 封包) | 區間: 上傳 {} ({}/s) / 下載 {} ({}/s)",
            format_duration(snap.elapsed),
            format_bytes(self.total_bytes()),
            format_bytes(snap.tx_bytes),
            format_rate_bytes(snap.tx_bytes, snap.elapsed),
            snap.tx_packets,
            format_bytes(snap.rx_bytes),
            format_rate_bytes(snap.rx_bytes, snap.elapsed),
            snap.rx_packets,
            format_bytes(iv.tx_bytes),
            format_rate_bytes(iv.tx_bytes, iv.elapsed),
            format_bytes(iv.rx_bytes),
            format_rate_bytes(iv.rx_bytes, iv.elapsed),
        )
    }
}

/// 一次性流量彙總快照。
#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficSnapshot {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub elapsed: Duration,
}

/// 區間流量增量快照 (兩次區間取樣之間的上傳/下載增量)。
#[derive(Debug, Clone, Copy, Default)]
pub struct IntervalStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub elapsed: Duration,
}

impl fmt::Display for TrafficSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "上傳: {} ({} 封包), 下載: {} ({} 封包), 歷時 {}",
            format_bytes(self.tx_bytes),
            self.tx_packets,
            format_bytes(self.rx_bytes),
            self.rx_packets,
            format_duration(self.elapsed),
        )
    }
}

/// 將位元組數格式化為人類可讀單位 (B / KiB / MiB / GiB / TiB)。
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

/// 將 Bytes/sec 縮放為可讀單位加 /s。
pub fn format_rate_bytes(bytes: u64, elapsed: Duration) -> String {
    format_rate(rate(bytes, elapsed))
}

/// 將速率值 (bytes/sec) 格式化。
pub fn format_rate(rate_per_sec: f64) -> String {
    format!("{}/s", format_bytes(rate_per_sec.max(0.0) as u64))
}

/// 計算 bytes / elapsed 的速率 (bytes/sec)；無時間流逝時回傳 0。
fn rate(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return 0.0;
    }
    bytes as f64 / secs
}

/// 將 Duration 格式化為 `Xh Ym Zs`。
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    if h > 0 {
        format!("{}h {:02}m {:02}s", h, m, s)
    } else if m > 0 {
        format!("{}m {:02}s", m, s)
    } else {
        format!("{}s", s)
    }
}

/// 計數讀取包裝器：讀取後記錄為「下載 (rx)」。
#[derive(Debug)]
pub struct CountingReader<R> {
    inner: R,
    meter: Arc<TrafficMeter>,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R, meter: Arc<TrafficMeter>) -> Self {
        Self { inner, meter }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = (buf.filled().len() - before) as u64;
                if read > 0 {
                    this.meter.record_rx(read);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// 計數寫入包裝器：寫入後記錄為「上傳 (tx)」。
#[derive(Debug)]
pub struct CountingWriter<W> {
    inner: W,
    meter: Arc<TrafficMeter>,
}

impl<W> CountingWriter<W> {
    pub fn new(inner: W, meter: Arc<TrafficMeter>) -> Self {
        Self { inner, meter }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.meter.record_tx(n as u64);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 計數雙向包裝器：同時包覆讀取與寫入 (適用於未 split 前的完整串流)，
/// 讀取記 rx、寫入記 tx。
#[derive(Debug)]
pub struct CountingSocket<S> {
    inner: S,
    meter: Arc<TrafficMeter>,
}

impl<S> CountingSocket<S> {
    pub fn new(inner: S, meter: Arc<TrafficMeter>) -> Self {
        Self { inner, meter }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingSocket<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let read = (buf.filled().len() - before) as u64;
                if read > 0 {
                    this.meter.record_rx(read);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingSocket<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.meter.record_tx(n as u64);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn initial_snapshot_is_zero() {
        let m = TrafficMeter::new();
        let snap = m.snapshot();
        assert_eq!(snap.tx_bytes, 0);
        assert_eq!(snap.rx_bytes, 0);
        assert_eq!(snap.tx_packets, 0);
        assert_eq!(snap.rx_packets, 0);
    }

    #[test]
    fn counting_accumulates_bytes_and_packets() {
        let m = TrafficMeter::new();
        m.record_tx(1024);
        m.record_tx(2048);
        m.record(Direction::Download, 4096);
        assert_eq!(m.tx_bytes(), 3072);
        assert_eq!(m.tx_packets(), 2);
        assert_eq!(m.rx_bytes(), 4096);
        assert_eq!(m.rx_packets(), 1);
        let snap = m.snapshot();
        assert_eq!(snap.tx_bytes, 3072);
        assert_eq!(snap.rx_bytes, 4096);
    }

    #[test]
    fn concurrent_records_are_exact() {
        let m = Arc::new(TrafficMeter::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let meter = Arc::clone(&m);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    meter.record_tx(10);
                    meter.record_rx(20);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.tx_bytes(), 8 * 1_000 * 10);
        assert_eq!(m.rx_bytes(), 8 * 1_000 * 20);
        assert_eq!(m.tx_packets(), 8 * 1_000);
        assert_eq!(m.rx_packets(), 8 * 1_000);
    }

    #[test]
    fn display_contains_human_units() {
        let m = TrafficMeter::new();
        m.record_tx(1_048_576);
        m.record_rx(2_048_576 + 1024);
        let text = m.display();
        assert!(text.contains("MiB"));
        assert!(text.contains("/s"));
        assert!(text.contains("封包"));
        assert!(text.contains("上傳"));
        assert!(text.contains("下載"));
        assert!(text.contains("總流量"), "display 應包含總流量");
        assert!(text.contains("區間"), "display 應包含區間");
    }

    #[test]
    fn format_bytes_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.00 GiB");
    }

    #[test]
    fn zero_elapsed_rate_is_zero() {
        // rate() returns 0 when elapsed is zero (防除以零)。
        assert_eq!(rate(100, Duration::ZERO), 0.0);
        // 初始流量計的 bytes 為零 → 速率恆為 0 B/s。
        let m = TrafficMeter::new();
        assert!(m.display().contains("0 B/s"));
    }

    #[tokio::test]
    async fn counting_wrappers_accumulate_stream_traffic() {
        let meter = Arc::new(TrafficMeter::new());
        let (mut a, mut b) = tokio::io::duplex(4096);

        let mut writer = CountingWriter::new(a, Arc::clone(&meter));
        let mut reader = CountingReader::new(b, Arc::clone(&meter));

        let payload = vec![0xABu8; 3000];
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();

        let mut recv = vec![0u8; 3000];
        reader.read_exact(&mut recv).await.unwrap();

        assert_eq!(meter.tx_bytes() as usize, payload.len());
        assert_eq!(meter.rx_bytes() as usize, payload.len());
        assert_eq!(meter.tx_packets(), 1);
        assert_eq!(meter.rx_packets(), 1);
        assert_eq!(recv, payload);
    }

    #[tokio::test]
    async fn counting_socket_counts_both_directions() {
        let meter = Arc::new(TrafficMeter::new());
        let (a, mut b) = tokio::io::duplex(4096);
        let mut socket = CountingSocket::new(a, meter.clone());

        socket.write_all(b"hello").await.unwrap();
        socket.flush().await.unwrap();

        let mut buf = [0u8; 5];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(meter.tx_bytes(), 5);

        b.write_all(b"world").await.unwrap();
        b.flush().await.unwrap();
        let mut buf2 = [0u8; 5];
        socket.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"world");
        assert_eq!(meter.rx_bytes(), 5);
    }

    #[test]
    fn duration_formatting() {
        assert_eq!(format_duration(Duration::from_secs(9)), "9s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 05s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 01m 01s");
    }

    #[test]
    fn total_and_interval_stats() {
        let m = TrafficMeter::new();
        assert_eq!(m.total_bytes(), 0);

        m.record_tx(1000);
        m.record_rx(2000);
        assert_eq!(m.total_bytes(), 3000);

        // 第一次呼叫建立基準，無增量
        let first = m.interval_stats();
        assert_eq!(first.tx_bytes, 0);
        assert_eq!(first.rx_bytes, 0);

        // 第二次呼叫反映兩次之間的增量
        m.record_tx(500);
        m.record_rx(250);
        let second = m.interval_stats();
        assert_eq!(second.tx_bytes, 500);
        assert_eq!(second.rx_bytes, 250);
        // total_bytes 仍反映累計
        assert_eq!(m.total_bytes(), 3750);
    }
}
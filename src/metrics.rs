use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

/// NDcode 3 節流器運行時效能指標收集器
pub struct PerformanceMetrics {
    total_packets_processed: AtomicU64,
    total_raw_bytes: AtomicU64,
    total_compressed_bytes: AtomicU64,
    raptorq_encode_failures: AtomicU64,
    processing_latency_sum_us: AtomicU64,
    max_latency_us: AtomicU64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            total_packets_processed: AtomicU64::new(0),
            total_raw_bytes: AtomicU64::new(0),
            total_compressed_bytes: AtomicU64::new(0),
            raptorq_encode_failures: AtomicU64::new(0),
            processing_latency_sum_us: AtomicU64::new(0),
            max_latency_us: AtomicU64::new(0),
        }
    }

    /// 紀錄單次封包處理指標
    pub fn record_tx_event(&self, raw_size: usize, compressed_size: usize, start_time: Instant) {
        let latency_us = start_time.elapsed().as_micros() as u64;

        self.total_packets_processed.fetch_add(1, Ordering::Relaxed);
        self.total_raw_bytes.fetch_add(raw_size as u64, Ordering::Relaxed);
        self.total_compressed_bytes.fetch_add(compressed_size as u64, Ordering::Relaxed);
        self.processing_latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);

        // 更新最大延遲
        let _ = self.max_latency_us.fetch_max(latency_us, Ordering::Relaxed);
    }

    pub fn record_raptorq_failure(&self) {
        self.raptorq_encode_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// 計算目前壓縮效率 (Compression Ratio)
    /// $$CompressionRatio = \left(1 - \frac{CompressedBytes}{RawBytes}\right) \times 100\%$$
    pub fn get_compression_efficiency(&self) -> f64 {
        let raw = self.total_raw_bytes.load(Ordering::Relaxed) as f64;
        let compressed = self.total_compressed_bytes.load(Ordering::Relaxed) as f64;
        if raw == 0.0 {
            return 0.0;
        }
        (1.0 - (compressed / raw)) * 100.0
    }

    /// 輸出當前效能分析摘要
    pub fn print_summary(&self) {
        let pkts = self.total_packets_processed.load(Ordering::Relaxed);
        let raw = self.total_raw_bytes.load(Ordering::Relaxed);
        let comp = self.total_compressed_bytes.load(Ordering::Relaxed);
        let latency_sum = self.processing_latency_sum_us.load(Ordering::Relaxed);
        let max_lat = self.max_latency_us.load(Ordering::Relaxed);
        let failures = self.raptorq_encode_failures.load(Ordering::Relaxed);

        let avg_lat = if pkts > 0 { latency_sum as f64 / pkts as f64 } else { 0.0 };

        println!("====== 📊 NDcode 3 效能與數據分析摘要 ======");
        println!("  已處理總封包數 : {} pkts", pkts);
        println!("  原始數據總量   : {} Bytes", raw);
        println!("  壓縮傳輸總量   : {} Bytes", comp);
        println!("  平均節約效率   : {:.2}%", self.get_compression_efficiency());
        println!("  平均處理延遲   : {:.2} μs", avg_lat);
        println!("  峰值處理延遲   : {} μs", max_lat);
        println!("  RaptorQ 異常數 : {} 次", failures);
        println!("===========================================");
    }
}

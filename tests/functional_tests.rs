use anyhow::Result;
use rand::Rng;

// 引入本體 Engine
use crate::ndcode_tun_engine::{NDcodeTunEngine, NDCODE_PACKET_THRESHOLD};

/// 生成指定長度的隨機 Payload 數據
fn generate_dummy_packet(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.r#gen::<u8>()).collect()
}

#[test]
fn test_small_packet_xz_roundtrip() -> Result<()> {
    let engine = NDcodeTunEngine::new();
    let original_payload = generate_dummy_packet(256); // < 1024 走純 XZ

    // 1. 壓包
    let compressed = engine.process_outgoing_packet(&original_payload)?;
    assert_eq!(compressed[0], 0x01, "小封包標頭應為 XzStream (0x01)");

    // 2. 解包
    let restored = engine.process_incoming_payload(&compressed)?;
    assert_eq!(original_payload, restored, "小封包數據比對失敗，未無損還原");

    Ok(())
}

#[test]
fn test_ndcode3_raptorq_chained_roundtrip() -> Result<()> {
    let engine = NDcodeTunEngine::new();
    // >= 1024B 觸發 NDcode 3 噴泉碼與 54x54 連鎖網格編碼
    let original_payload = generate_dummy_packet(4096);

    // 1. 壓包 (發送端)
    let compressed = engine.process_outgoing_packet(&original_payload)?;
    assert_eq!(compressed[0], 0x03, "大封包標頭應為 NDcode3Stream (0x03)");

    // 2. 解包 (接收端)
    let restored = engine.process_incoming_payload(&compressed)?;
    assert_eq!(
        original_payload, restored,
        "NDcode 3 噴泉碼與網格還原數據不吻合"
    );

    Ok(())
}

#[test]
fn test_corrupted_header_resilience() {
    let engine = NDcodeTunEngine::new();
    let mut invalid_payload = vec![0x03, 0x00, 0x00, 0x00]; // 錯誤標頭
    invalid_payload.extend_from_slice(b"BAD_HEADER_STREAM_DATA");

    let result = engine.process_incoming_payload(&invalid_payload);
    assert!(result.is_err(), "無效 Master Header 應拋出解碼錯誤");
}

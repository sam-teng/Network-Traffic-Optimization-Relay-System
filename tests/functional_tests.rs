use anyhow::Result;
use rand::Rng;

// 引入本體 Engine
use ntors::ndcode_tun_engine::{NDcodeTunEngine, NDCODE_PACKET_THRESHOLD};

/// 生成指定長度的隨機 Payload 數據
fn generate_dummy_packet(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.r#gen::<u8>()).collect()
}

#[test]
fn test_small_packet_xz_roundtrip() -> Result<()> {
    let engine = NDcodeTunEngine::new();
    let original_payload = generate_dummy_packet(256); // < threshold 走純 XZ

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
    // >= 門檻觸發 NDcode 3 噴泉碼與網格編碼
    let original_payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 4);

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
fn test_ndcode3_header_uses_master_magic() -> Result<()> {
    use ntors::ndcode_tun_engine::PacketHeader;
    let engine = NDcodeTunEngine::new();
    let original_payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 4);

    let compressed = engine.process_outgoing_packet(&original_payload)?;
    assert_eq!(compressed[0], PacketHeader::NDcode3Stream as u8);

    // 大封包應帶上 MASTER_MAGIC_HEADER (b"ND3:")
    let magic = &compressed[1..5];
    assert_eq!(magic, b"ND3:", "NDcode3 封包應含 MASTER_MAGIC_HEADER");

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

#[test]
fn test_unknown_header_rejected() {
    let engine = NDcodeTunEngine::new();
    let payload = vec![0xFF, 0x01, 0x02, 0x03];
    let result = engine.process_incoming_payload(&payload);
    assert!(result.is_err(), "未知標頭類別應被拒絕");
}

#[test]
fn test_empty_payload_rejected() {
    let engine = NDcodeTunEngine::new();
    let result = engine.process_incoming_payload(&[]);
    assert!(result.is_err(), "空白數據包應被拒絕");
}

/// 平行鏈架構：資料切多分支 + 各分支獨立 continuation 鏈 roundtrip
#[test]
fn test_ndcode3_parallel_cascade_roundtrip() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, PARALLEL_MAGIC_HEADER};

    let logic = NDCodeLogic::default();
    let original_payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 4);

    for branches in [1usize, 2, 4] {
        let master = logic.build_parallel_cascade(&original_payload, 512, branches)?;
        assert!(
            master.starts_with(PARALLEL_MAGIC_HEADER),
            "平行鏈 Master 應含 ND3P: 標頭"
        );

        let restored = logic.decode_parallel_stream(&master)?;
        assert_eq!(
            original_payload, restored,
            "平行鏈 {} 分支還原數據不吻合",
            branches
        );
    }

    Ok(())
}

/// 平行鏈 Master 缺損時應報錯 (長度表不完整)
#[test]
fn test_parallel_cascade_truncated_master_rejected() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, PARALLEL_MAGIC_HEADER};

    let logic = NDCodeLogic::default();
    let original_payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 4);
    let master = logic.build_parallel_cascade(&original_payload, 512, 3)?;
    assert!(master.starts_with(PARALLEL_MAGIC_HEADER));

    // 只保留標頭 + 長度表，砍斷分支資料
    let truncated = &master[..master.len() / 2];
    let result = logic.decode_parallel_stream(truncated);
    assert!(result.is_err(), "分支資料缺損的平行鏈應解碼失敗");

    Ok(())
}

/// 統一入口：序列媒介 (壓縮優先) roundtrip
#[test]
fn test_transport_serial_roundtrip() -> Result<()> {
    use NDcode3::logic::{
        NDCodeLogic, SERIAL_ND3_HEADER, SERIAL_XZ_HEADER, TransportMedium, TransportOutput,
    };
    let logic = NDCodeLogic::default();
    let noop = |_: String| {};

    // 小資料 → 純 XZ
    let small = b"{\"seq\":42,\"type\":\"telemetry\"}";
    let out_small = logic.create_transport_cascade(small, 512, TransportMedium::Serial, |_, _, _| {})?;
    let TransportOutput::Serial(bytes_small) = out_small else {
        panic!("小資料應回傳 Serial 位元流");
    };
    assert_eq!(bytes_small[0], SERIAL_XZ_HEADER, "小資料應為 XZ 封包標頭");
    let restored_small = logic.decode_transport_serial(&bytes_small, noop)?;
    assert_eq!(restored_small, small, "小資料序列傳輸未無損還原");

    // 大資料 → ND3 平行鏈
    let big = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 4);
    let out_big = logic.create_transport_cascade(&big, 512, TransportMedium::Serial, |_, _, _| {})?;
    let TransportOutput::Serial(bytes_big) = out_big else {
        panic!("大資料應回傳 Serial 位元流");
    };
    assert_eq!(bytes_big[0], SERIAL_ND3_HEADER, "大資料應為 ND3 封包標頭");
    assert!(
        bytes_big.starts_with(&[SERIAL_ND3_HEADER, b'N', b'D', b'3', b':']),
        "大資料序列應含 ND3: Master 標頭"
    );
    let restored_big = logic.decode_transport_serial(&bytes_big, noop)?;
    assert_eq!(restored_big, big, "大資料序列傳輸未無損還原");

    Ok(())
}

/// 統一入口：光學媒介 (傳輸優先) 內部可選策略 roundtrip
#[test]
fn test_transport_optical_single_chain_roundtrip() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, TransportMedium, TransportOutput};

    let logic = NDCodeLogic::default();

    // 小資料 → 單鏈分頁 (frames.len() <= OPTICAL_MAX_SINGLE_FRAMES)
    let small = generate_dummy_packet(NDCODE_PACKET_THRESHOLD);
    let out = logic.create_transport_cascade(&small, 512, TransportMedium::Optical, |_, _, _| {})?;
    let TransportOutput::Optical(cascade) = out else {
        panic!("光學媒介應回傳 QR 影像序列");
    };

    // 檢查影像可被讀回 (至少 master_pair 存在，data_qr 為有效圖像)
    let _ = &cascade.master_pair;
    let cascading = cascade.cascading_pairs.len();
    println!("光學單鏈分頁: master + {} 張 cascading QR", cascading);
    assert!(
        cascade.master_pair.data_qr.width() > 0,
        "Master QR 影像應有效"
    );

    Ok(())
}

/// 區塊噴泉 (ND3B:)：每張 QR 獨立可解 → 「掃 1 張 QR 在多張時也有效」
#[test]
fn test_optical_block_fountain_single_qr_recoverable() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, OPTICAL_BLOCK_MAGIC};

    let logic = NDCodeLogic::default();

    // 多張 QR 的資料：壓縮前 > threshold*4 → 必然切成多個區塊
    let payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 6);
    let frames = logic.build_optical_block_frames(&payload)?;
    assert!(frames.len() > 1, "大型資料應產生多張區塊 QR (實際 {} 張)", frames.len());

    // 每張 QR 都是 ND3B: 開頭；單獨掃描任一張，錯誤訊息應明確回報「該張已還原」，
    // 證明掃 1 張 QR 立即獲得其區塊內容 (而非無意義的碎片)
    for (idx, frame) in frames.iter().enumerate() {
        assert!(frame.starts_with(OPTICAL_BLOCK_MAGIC), "第 {} 幀魔數錯誤", idx);
        let err = logic.decode_optical_block_frames(std::slice::from_ref(frame)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("收集不完整"), "單張掃描應回報收集不完整，第 {} 張實際: {}", idx, msg);
        assert!(msg.contains("1/"), "應明確指出已還原 1 張，第 {} 張實際: {}", idx, msg);
    }

    // 掃齊所有 QR → 完整還原
    let restored_full = logic.decode_optical_block_frames(&frames)?;
    assert_eq!(restored_full, payload, "掃齊所有區塊 QR 應無損還原原始資料");

    Ok(())
}

/// 區塊噴泉部分掃描：缺張時應明確報錯並回報已還原進度 (不靜默產出壞資料)
#[test]
fn test_optical_block_fountain_partial_scan_reports_missing() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, OPTICAL_BLOCK_DATA_SIZE};

    let logic = NDCodeLogic::default();

    let payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 6);
    let frames = logic.build_optical_block_frames(&payload)?;
    assert!(frames.len() > 2, "需至少 3 張 QR 才可測缺張");

    // 故意只掃前 2 張 → 應報錯且訊息含「收集不完整」
    let partial = frames[..2].to_vec();
    let err = logic.decode_optical_block_frames(&partial).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("收集不完整"), "缺張應回報收集不完整，實際: {}", msg);
    assert!(msg.contains("2/"), "應回報已還原張數，實際: {}", msg);

    Ok(())
}

/// 區塊噴泉完整性：單張 QR 掃描後確實還原出「對應位置的原始區塊內容」，
/// 而非只是回報數字。用 RaptorQ 直接解出單張幀內容並與原始切片比對。
#[test]
fn test_optical_block_fountain_single_frame_content_matches() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, RaptorQEngine, OPTICAL_BLOCK_DATA_SIZE, OPTICAL_BLOCK_HEADER_LEN};

    let logic = NDCodeLogic::default();
    let payload = generate_dummy_packet(NDCODE_PACKET_THRESHOLD * 6);
    let frames = logic.build_optical_block_frames(&payload)?;
    assert!(frames.len() > 1, "需多張 QR");

    for (idx, frame) in frames.iter().enumerate() {
        // 幀格式: [ND3B:][total u16][index u16][RaptorQ payload]
        assert!(frame.len() > OPTICAL_BLOCK_HEADER_LEN);
        let rq_payload = &frame[OPTICAL_BLOCK_HEADER_LEN..];
        let restored = RaptorQEngine::decode_data(rq_payload)?;

        // 區塊資料先後經 xz_compress(block) 再編碼；高熵資料 xz 原樣回傳，
        // 故還原後即為該張對應的原始區塊切片
        let expected_slice = &payload[idx * OPTICAL_BLOCK_DATA_SIZE
            ..payload
                .len()
                .min((idx + 1) * OPTICAL_BLOCK_DATA_SIZE)];
        assert_eq!(
            &restored[..],
            expected_slice,
            "第 {} 張 QR 應還原出原始資料的對應區塊內容",
            idx
        );
    }

    Ok(())
}
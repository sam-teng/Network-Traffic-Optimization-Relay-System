use anyhow::Result;
use rand::Rng;
use NDcode3::logic::{NDCodeLogic, RaptorQEngine, TransportMedium, TransportOutput};

fn main() -> Result<()> {
    let sizes = [64usize, 300, 512, 900, 4096, 8192];
    for &size in &sizes {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.r#gen::<u8>()).collect();
        let encoded = RaptorQEngine::encode_data(&data, None)?;
        let decoded = match RaptorQEngine::decode_data(&encoded) {
            Ok(d) => d,
            Err(e) => {
                println!("size={size} ENCODED={} -> DECODE FAIL: {e}", encoded.len());
                continue;
            }
        };
        let ok = decoded == data;
        println!(
            "size={size} data_len={} encoded_len={} decoded_len={} ok={ok}",
            data.len(),
            encoded.len(),
            decoded.len()
        );
    }

    // 全連鎖編碼 / 解碼往返 (build_chained_cascade -> decode_ndcode3_stream)
    let logic = NDCodeLogic::default();
    // 純高熵資料：縮小尺寸避免 debug 模式 RaptorQ 多層連鎖過慢
    let big: Vec<u8> = {
        let mut rng = rand::thread_rng();
        (0..2048).map(|_| rng.r#gen::<u8>()).collect()
    };
    let chain = logic.build_chained_cascade(&big, 512)?;
    let restored = logic.decode_ndcode3_stream(&chain)?;
    println!(
        "chain 2048B high-entropy: encoded={}B restored={}B ok={}",
        chain.len(),
        restored.len(),
        restored == big
    );

    let text = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}", "<p>hello</p>".repeat(2000));
    let chain2 = logic.build_chained_cascade(text.as_bytes(), 512)?;
    let restored2 = logic.decode_ndcode3_stream(&chain2)?;
    println!(
        "chain compressible-text: encoded={}B restored={}B ok={}",
        chain2.len(),
        restored2.len(),
        restored2 == text.as_bytes()
    );

    // 平行鏈架構：資料切多分支，每分支為獨立 continuation 鏈
    for branches in [2usize, 4] {
        let parallel = logic.build_parallel_cascade(&big, 512, branches)?;
        let restored_p = logic.decode_parallel_stream(&parallel)?;
        println!(
            "parallel branches={}: master={}B restored={}B ok={}",
            branches,
            parallel.len(),
            restored_p.len(),
            restored_p == big
        );
    }

    // 統一入口：序列媒介 (壓縮優先)
    let serial_small = logic.create_transport_cascade(b"{\"seq\":42}", 512, TransportMedium::Serial, |_,_,s| println!("  [serial small] {s}"))?;
    if let TransportOutput::Serial(bytes) = &serial_small {
        let restored_s = logic.decode_transport_serial(bytes, |s| println!("  [serial small decode] {s}"))?;
        println!("transport serial small: {}B restored ok={}", bytes.len(), restored_s == b"{\"seq\":42}");
    }

    let serial_big = logic.create_transport_cascade(&big, 512, TransportMedium::Serial, |_,_,s| println!("  [serial big] {s}"))?;
    if let TransportOutput::Serial(bytes) = &serial_big {
        let restored_s = logic.decode_transport_serial(bytes, |s| println!("  [serial big decode] {s}"))?;
        println!("transport serial big: {}B restored ok={}", bytes.len(), restored_s == big);
    }
    probe_rq_size()?;
    Ok(())
}

fn probe_rq_size() -> Result<()> {
    use NDcode3::logic::{NDCodeLogic, OPTICAL_BLOCK_PAYLOAD_CAP, OPTICAL_BLOCK_SYMBOL_SIZES};
    let logic = NDCodeLogic::default();
    for size in [1024usize, 1536] {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.r#gen::<u8>()).collect();
        for &sym in &OPTICAL_BLOCK_SYMBOL_SIZES {
            let aligned = sym - (sym % 8);
            let packets_needed = (data.len() as u32).div_ceil(aligned as u32) as usize;
            let available = (OPTICAL_BLOCK_PAYLOAD_CAP - 16) / (aligned as usize + 4);
            if packets_needed <= available {
                let encoded = RaptorQEngine::encode_data(&data, Some(sym))?;
                let mut truncated = encoded.clone();
                if truncated.len() > OPTICAL_BLOCK_PAYLOAD_CAP {
                    truncated.resize(OPTICAL_BLOCK_PAYLOAD_CAP, 0);
                }
                let restored = RaptorQEngine::decode_data(&truncated).ok();
                println!(
                    "probe: size={size} sym={sym} needed={packets_needed} avail={available} encoded={}B cap={OPTICAL_BLOCK_PAYLOAD_CAP} truncated={}B restore_ok={}",
                    encoded.len(),
                    truncated.len(),
                    restored.as_ref().map(|d| d == &data).unwrap_or(false)
                );
                break;
            }
        }
    }
    Ok(())
}
// main.rs - NDcode 3 TUN 虛擬網卡引擎
mod ndcode_tun_engine;

use anyhow::{Context, Result};
use ndcode_tun_engine::NDcodeTunEngine;
use std::io::{Read, Write};

fn main() -> Result<()> {
    // TODO: User can configure TUN interface parameters via command line arguments or config file
    let mut config = tun::Configuration::default();
    config
        .name("tun0")
        .address("10.0.0.1")
        .netmask("255.255.255.0")
        .up();

    let mut dev = tun::create(&config).context("無法建立 TUN 虛擬網卡")?;
    println!("🚀 [網路節流器] 掛載 TUN 成功 (10.0.0.1)");

    let engine = NDcodeTunEngine::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = dev.read(&buf).context("TUN 讀取失敗")?;
        if n == 0 { continue; }

        let raw_packet = &buf[..n];

        // 判斷長度並執行打包（自動判斷 XZ 或 NDcode）
        let outgoing_payload = engine.process_outgoing_packet(raw_packet)?;

        // TODO: 透過 Socket/Web 傳送 outgoing_payload 至遠端 Proxy 伺服器
        // ...
    }
}
//! # NDcode 3 - Disclaimer & Legal Notice Module

use std::io::{self, Write};
use anyhow::{anyhow, Result};

pub fn print_and_confirm_disclaimer() -> Result<()> {
    println!("==================================================================");
    println!("⚠️  NDcode 3 Network Traffic Optimization Relay System(NTORS) - 免責與法律聲明 (Legal Notice)  ⚠️");
    println!("⚠️  NDcode 3 Network Traffic Optimization Relay System(NTORS) - Disclaimer & Legal Notice  ⚠️");
    println!("==================================================================");
    println!("1. 本軟體以「現狀 (As-Is)」提供，不保證不中斷或完全無誤。");
    println!("2. 程式運行涉及系統層級 TUN 虛擬網卡建立與核心網路參數 (sysctl/netsh) 調整。");
    println!("3. 使用者須自行承擔系統權限變更之風險，並遵守當地網路通訊與資訊安全法規。");
    println!("4. 本軟體僅供學術研究、教育與個人免費使用，禁止用於任何非法或商業用途。");
    println!("------------------------------------------------------------------");
    println!();
    println!("------------------------------------------------------------------");
    println!("Network-Traffic-Optimization-Relay-System(NTORS) 是一個開源的網路流量最佳化中繼架構，旨在提升網路傳輸效率與穩定性。 Source code URL: https://github.com/sam-teng/Network-Traffic-Optimization-Relay-System/ ");
    
    println!("Copyright (c) 2026 Sam Teng. All rights reserved.");
    
    println!("Thanks to the following open-source projects for their invaluable contributions:");
    println!("1. Rust Programming Language: https://www.rust-lang.org/");
    println!("2. Tokio: https://tokio.rs/");
    println!("3. Hyper: https://hyper.rs/");
    println!("4. TUN/TAP: https://crates.io/crates/tun");
    println!("\t& WinTun: https://wintun.net/");
    println!("5. Clap: https://crates.io/crates/clap");
    println!("6. Anyhow: https://crates.io/crates/anyhow");
    println!("7. Cargo-cross: https://crates.io/crates/cargo-cross");
    println!("8. criterion: https://crates.io/crates/criterion");
    println!("9. rand: https://crates.io/crates/rand");
    println!("10. serde: https://crates.io/crates/serde");
    println!("11. serde_json: https://crates.io/crates/serde_json");
    println!("\tand many other open-source projects that have contributed to the development of NTORS.");
    println!("Thank for all the developers and contributors of these projects for their dedication and hard work!");
    println!("------------------------------------------------------------------");

    print!("👉 是否已閱讀並同意上述聲明以繼續執行？ (y/N): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.trim().eq_ignore_ascii_case("y") || input.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err(anyhow!("使用者拒絕接受免責聲明，程式已終止。"))
    }
}

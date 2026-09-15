// src/lib.rs - NDcode 3 網路節流引擎函式庫入口
// 提供 integration test 與 benchmark 存取核心引擎與管線模組。

pub mod ndcode_tun_engine;
pub mod net_transport;
pub mod tls;
pub mod traffic_meter;
pub mod wasm_tunnel;
#[path = "pipeline/mod.rs"]
pub mod pipeline;
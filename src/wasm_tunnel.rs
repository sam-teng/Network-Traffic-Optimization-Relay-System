//! 選項 B：無伺服器端實作的 Wasm 沙盒解壓縮隧道（Code-as-Data）。
//!
//! 背景（參考 Gemini 規劃：方案 B — Wasm 沙盒隧道）：
//! - 連線建立階段：發送端把自訂解壓縮引擎 `decompress.wasm` 作為「資料」直接送達接收端，
//!   無需任何伺服器更新、無需先約定演算法，支援頻繁更新 / 自創演算法。
//! - 接收端：將收到的 wasm 載入純 Rust 沙盒（wasmi）執行，並綁定至 Connection ID。
//! - 資料階段：後續壓縮封包直接餵入該沙盒解壓，還原原始資料。
//! - 斷線：立即抹除該沙盒實例的記憶體。
//!
//! 安全邊界（防 RCE / DoS，對比直接傳送 .so/.dll/指令碼）：
//! - 記憶體上限：每個沙盒線性記憶體被 StoreLimits 限制為 [`SANDBOX_MEMORY_SIZE_BYTES`]（2 MiB）。
//! - CPU 上限：每次呼叫預設 fuel 預算 [`FUEL_BUDGET`]，耗盡即 trap，阻斷無窮迴圈。
//! - 禁止 `start` 函式自執行（`Config::allow_start_fn(false)`）。
//! - 強制二進位 .wasm（拒絕 WAT 文字，避免文字→二進位展開型 DoS）。
//! - 嚴苛編譯限制（`EnforcedLimits::strict()`）與輸出長度上限 [`MAX_OUTPUT_BYTES`]。
//! - 每次解壓皆於 128 MiB 大 stack 執行緒中完成，避免 wasmi per-`br` 原生递迴的溢位風險。
//!
//! 對端 ABI 契約（`decompress.wasm` 必須 export）：
//! - `memory`：可成長至 [`SANDBOX_MEMORY_SIZE_BYTES`] 的線性記憶體。
//! - `decompress(in_ptr i32, in_len i32, out_ptr i32, out_cap i32) -> i32`：
//!   自 `in_ptr` 讀取 `in_len` 位元組壓縮資料，解壓至 `out_ptr`（上限 `out_cap`）；
//!   回傳輸出長度，或 -1 表示失敗（如輸出超過 `out_cap`）。
//!
//! 隧道框格式（1 位元組魔數 + 1 位元組種類 + 8 位元組 Connection ID + 4 位元組 body 長度）：
//! - 握手框 `[0x57, 0x27]`：body = `decompress.wasm` 二進位。
//! - 資料框 `[0x57, 0x21]`：body = 壓縮載荷。

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use wasmi::{Config, Engine, EnforcedLimits, Extern, Linker, Memory, MemoryType, Module, Store, StoreLimits, StoreLimitsBuilder};

/// 隧道框魔數。
pub const MAGIC_BYTE: u8 = 0x57;
/// 握手框種類：body 為 `decompress.wasm`。
pub const KIND_HANDSHAKE: u8 = 0x27;
/// 資料框種類：body 為壓縮載荷。
pub const KIND_PAYLOAD: u8 = 0x21;
/// 固定框表頭長度（魔數 1 + 種類 1 + conn_id 8 + body 長度 4）。
pub const FRAME_HEADER_LEN: usize = 14;

/// 沙盒線性記憶體上限（對應 Gemini 建議的 2 MiB）。輸入緩衝與輸出緩衝各 1 MiB。
pub const SANDBOX_MEMORY_SIZE_BYTES: usize = 2 * 1024 * 1024;
/// 輸入緩衝於 linearmemory 中的起始位址（固定 0）。
pub const INPUT_BUF_PTR: usize = 0;
/// 輸出緩衝於 linearmemory 中的起始位址（1 MiB 處）。
pub const OUTPUT_BUF_PTR: usize = SANDBOX_MEMORY_SIZE_BYTES / 2;
/// 每次解壓呼叫的 fuel 預算（CPU 週期上限，耗盡即 `OutOfFuel` trap）。
///
/// 安全設計：`fuel × 每回合 frame 大小` 必須小於沙盒執行緒 stack
/// （500_000 × ~1 KiB ≈ 500 MiB < 1 GiB），確保惡意逐位元組迴圈在逼近
/// 原生 stack 溢位**之前**先被 fuel trap 終止。合法大量解壓請善用 bulk
/// 指令（`memory.fill/copy`）或拆分段落，避免逐位元組迴圈。
pub const FUEL_BUDGET: u64 = 500_000;
/// 容許上傳的 wasm 大小上限（防握手洪泛）。
pub const MAX_WASM_SIZE_BYTES: usize = 256 * 1024;
/// 每框壓縮載荷上限（對應資料框 body 上限）。
pub const MAX_PAYLOAD_BODY_BYTES: usize = 1024 * 1024;
/// 單次解壓輸出上限。
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
/// 同時啟用沙盒數量上限（防註冊表 DoS）。
pub const MAX_SESSIONS: usize = 1024;
/// 同時在途的沙盒執行數上限（常駐大 stack 執行緒會保留大量虛擬記憶體，需限制並行）。
pub const SANDBOX_MAX_CONCURRENT_RUNS: usize = 4;
/// 每次解壓呼叫所啟動的宿主執行緒 stack 大小（容纳 wasmi per-`br` 原生递迴）。
///
/// debug build 的 interpreter frame 可達 ~1 KiB/回合，1 GiB 容 ~1M 回合，
/// 大於 [`FUEL_BUDGET`] 允許的 500k 回合 — 保證 fuel trap 恆先於 hosting stack 溢位。
const SANDBOX_HOST_STACK_BYTES: usize = 1024 * 1024 * 1024;

/// 限制同時進行的沙盒執行緒數量，避免 1 GiB stack × 大量並行造成虛擬記憶體枯竭。
static SANDBOX_CONCURRENCY: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(SANDBOX_MAX_CONCURRENT_RUNS));

const MEMORY_PAGES: u64 = (SANDBOX_MEMORY_SIZE_BYTES as u64) / 65_536; // 32 頁 = 2 MiB
const MEMORY_INITIAL_PAGES: u32 = 16; // 初始 1 MiB

fn build_sandbox_config() -> Result<(Config, StoreLimits, MemoryType)> {
    let mut config = Config::default();
    config
        .consume_fuel(true)
        .allow_start_fn(false)
        .set_max_stack_height(1 << 20)
        .set_max_recursion_depth(1024)
        .enforced_limits(EnforcedLimits::strict());

    let limits = StoreLimitsBuilder::new()
        .memory_size(SANDBOX_MEMORY_SIZE_BYTES)
        .instances(4)
        .memories(1)
        .tables(4)
        .trap_on_grow_failure(true)
        .build();

    let memory_type = MemoryType::new(MEMORY_INITIAL_PAGES, Some(MEMORY_PAGES as u32));
    Ok((config, limits, memory_type))
}

/// 一個綁定至單一 Connection ID 的 Wasm 沙盒。
///
/// 實際的 Store / Memory 狀態**不**存放於此結構，
/// 而是在每次 `decompress` 呼叫時，於具備 128 MiB stack 的獨立執行緒內部建立與銷毀，
/// 確保 wasmi 的 per-`br` 原生递迴絕不會溢位呼叫者（tokio 工作執行緒）的 1 MiB stack。
pub struct WasmSandbox {
    engine: Engine,
    module: Module,
}

impl WasmSandbox {
    /// 載入二進位 `decompress.wasm` 並驗證，建立可重複執行的沙盒模板。
    pub fn install(wasm: &[u8]) -> Result<Self> {
        if wasm.len() > MAX_WASM_SIZE_BYTES {
            bail!("上傳的 wasm 大小 {} 超過上限 {} bytes", wasm.len(), MAX_WASM_SIZE_BYTES);
        }
        if wasm.len() < 4 || &wasm[..4] != b"\0asm" {
            bail!("僅接受二進位 .wasm 模組（前 4 bytes 需為 \\0asm 魔數）");
        }
        let (config, _, _) = build_sandbox_config()?;
        let engine = Engine::new(&config);
        // SAFETY: 呼叫端已確認前 4 bytes == b"\0asm" 二進位魔數；
        // wasmi 內部仍會對輸入做完整解析與驗證，驗證失敗以 Err 回傳。
        let module = unsafe { Module::new_unchecked(&engine, wasm) }.context("Wasm 模組解析 / 驗證失敗")?;
        Ok(Self { engine, module })
    }

    /// 將壓縮載荷餵入沙盒解壓，回傳還原的原始資料。
    pub fn decompress(&self, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.is_empty() {
            bail!("空壓縮載荷");
        }
        if payload.len() > MAX_PAYLOAD_BODY_BYTES {
            bail!("載荷大小 {} 超過上限 {} bytes", payload.len(), MAX_PAYLOAD_BODY_BYTES);
        }
        let payload = payload.to_vec();
        let engine = self.engine.clone();
        let module = self.module.clone();
        let permit = loop {
            if let Ok(p) = SANDBOX_CONCURRENCY.try_acquire() {
                break p;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let handle = std::thread::Builder::new()
            .name("wasm-sandbox-decompress".into())
            .stack_size(SANDBOX_HOST_STACK_BYTES)
            .spawn(move || run_in_sandbox(&engine, &module, &payload))
            .map_err(|err| anyhow!("無法建立沙盒執行緒：{}", err))?;
        let result = handle.join().map_err(|_| anyhow!("沙盒執行緒 panic（内部未捕獲異常）"))?;
        drop(permit);
        result
    }
}

fn run_in_sandbox(engine: &Engine, module: &Module, payload: &[u8]) -> Result<Vec<u8>> {
    let (_, limits, memory_type) = build_sandbox_config()?;
    let mut store = Store::new(engine, limits);
    store.set_fuel(FUEL_BUDGET)?;

    let mut linker = Linker::new(engine);
    let memory = Memory::new(&mut store, memory_type)?;
    linker.define("env", "memory", memory).context("注入 env.memory 失敗")?;

    let instance = linker.instantiate_and_start(&mut store, module).context("Wasm 實例化失敗（含 start 函式將被拒絕）")?;

    let memory = instance.get_export(&store, "memory").and_then(Extern::into_memory).unwrap_or(memory);
    let decompress = instance
        .get_typed_func::<(i32, i32, i32, i32), i32>(&store, "decompress")
        .context("缺少 ABI 函式 decompress(in_ptr i32, in_len i32, out_ptr i32, out_cap i32) -> i32")?;

    // 確保線性記憶體成長至 2 MiB。
    let current: u64 = memory.size(&store).into();
    let target = MEMORY_PAGES;
    if current < target {
        memory.grow(&mut store, target - current).map_err(|err| anyhow!("沙盒記憶體成長被限制器拒絕（{}）", err))?;
    }

    {
        let data = memory.data_mut(&mut store);
        data[INPUT_BUF_PTR..INPUT_BUF_PTR + payload.len()].copy_from_slice(payload);
    }

    store.set_fuel(FUEL_BUDGET)?;

    let out_len: i32 = decompress
        .call(&mut store, (INPUT_BUF_PTR as i32, payload.len() as i32, OUTPUT_BUF_PTR as i32, MAX_OUTPUT_BYTES as i32))
        .map_err(|err| anyhow!("沙盒解壓縮失敗（可能為 fuel 耗盡或記憶體 limit）：{}", err))?;

    if out_len < 0 {
        bail!("decompress.wasm 回傳錯誤碼 {}", out_len);
    }
    let out_len = out_len as usize;
    if out_len > MAX_OUTPUT_BYTES {
        bail!("decompress.wasm 宣稱輸出 {} 超過上限 {} bytes", out_len, MAX_OUTPUT_BYTES);
    }

    let data = memory.data(&store);
    let out = &data[OUTPUT_BUF_PTR..OUTPUT_BUF_PTR + out_len];
    let result = Ok(out.to_vec());
    // 斷線即抹除：釋放前先將整個線性記憶體清零。
    memory.data_mut(&mut store).fill(0);
    result
}

/// Connection ID → Wasm 沙盒 的註冊表（進程級單例）。
pub struct WasmTunnel {
    sessions: Mutex<HashMap<u64, WasmSandbox>>,
}

impl WasmTunnel {
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    /// 安裝（或覆蓋）指定連線的解壓縮沙盒。
    pub fn install(&self, conn_id: u64, wasm: &[u8]) -> Result<()> {
        let mut sessions = self.sessions.lock().map_err(|err| anyhow!("沙盒註冊表中毒：{}", err))?;
        if sessions.len() >= MAX_SESSIONS && !sessions.contains_key(&conn_id) {
            bail!("同時啟用沙盒數量已達上限 {}", MAX_SESSIONS);
        }
        let sandbox = WasmSandbox::install(wasm)?;
        sessions.insert(conn_id, sandbox);
        Ok(())
    }

    /// 抹除指定連線的沙盒。
    pub fn uninstall(&self, conn_id: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&conn_id);
        }
    }

    /// 目前活躍的沙盒數量。
    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// 以指定連線的沙盒解壓載荷；解壓失敗時自動抹除該沙盒以防重複濫用。
    pub fn decompress(&self, conn_id: u64, payload: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .sessions
            .lock()
            .map_err(|err| anyhow!("沙盒註冊表中毒：{}", err))?
            .get(&conn_id)
            .ok_or_else(|| anyhow!("未安裝 conn_id={} 的沙盒，需先以握手框傳輸 decompress.wasm", conn_id))?
            .decompress(payload);
        if result.is_err() {
            self.uninstall(conn_id);
        }
        result
    }
}

impl Default for WasmTunnel {
    fn default() -> Self {
        Self::new()
    }
}

/// 隧道框（共通結構，握手與資料皆適用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrame {
    pub conn_id: u64,
    pub kind: u8,
    pub body: Vec<u8>,
}

fn encode_frame(conn_id: u64, kind: u8, body: &[u8]) -> Result<Vec<u8>> {
    if body.len() > u32::MAX as usize {
        bail!("frame body 過大，無法以 u32 長度欄位表達");
    }
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    out.push(MAGIC_BYTE);
    out.push(kind);
    out.extend_from_slice(&conn_id.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// 握手框：將 `decompress.wasm` 傳送給對端。
pub fn encode_handshake(conn_id: u64, wasm: &[u8]) -> Result<Vec<u8>> {
    if wasm.len() > MAX_WASM_SIZE_BYTES {
        bail!("握手 wasm 大小 {} 超過上限 {} bytes", wasm.len(), MAX_WASM_SIZE_BYTES);
    }
    encode_frame(conn_id, KIND_HANDSHAKE, wasm)
}

/// 資料框：包裝壓縮載荷。
pub fn encode_payload_frame(conn_id: u64, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_PAYLOAD_BODY_BYTES {
        bail!("資料框載荷大小 {} 超過上限 {} bytes", payload.len(), MAX_PAYLOAD_BODY_BYTES);
    }
    encode_frame(conn_id, KIND_PAYLOAD, payload)
}

fn body_max_for(kind: u8) -> Result<usize> {
    match kind {
        KIND_HANDSHAKE => Ok(MAX_WASM_SIZE_BYTES),
        KIND_PAYLOAD => Ok(MAX_PAYLOAD_BODY_BYTES),
        _ => bail!("未知 frame kind {:#04x}", kind),
    }
}

/// 嘗試從緩衝前端解析出一個隧道框。
/// - `Ok(Some(frame))`：解析成功。
/// - `Ok(None)`：資料不足，需繼續累積。
/// - `Err`：違反協定（錯誤魔數 / 種類 / 宣稱長度超限）。
pub fn try_parse_frame(buf: &[u8]) -> Result<Option<TunnelFrame>> {
    if buf.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }
    if buf[0] != MAGIC_BYTE {
        bail!("魔數字不符 {:#04x}", buf[0]);
    }
    let kind = buf[1];
    body_max_for(kind)?;
    let mut conn_id_bytes = [0u8; 8];
    conn_id_bytes.copy_from_slice(&buf[2..10]);
    let conn_id = u64::from_le_bytes(conn_id_bytes);
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[10..14]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > body_max_for(kind)? {
        bail!("frame body 宣稱長度 {} 超過上限", len);
    }
    if buf.len() < FRAME_HEADER_LEN + len {
        return Ok(None);
    }
    let body = buf[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len].to_vec();
    Ok(Some(TunnelFrame { conn_id, kind, body }))
}

/// 自緩衝中萃取出所有完整框，並將已消耗的前綴移除。
pub fn drain_frames(buf: &mut Vec<u8>) -> Result<Vec<TunnelFrame>> {
    let mut frames = Vec::new();
    loop {
        match try_parse_frame(buf)? {
            Some(frame) => {
                let consumed = FRAME_HEADER_LEN + frame.body.len();
                buf.drain(..consumed);
                frames.push(frame);
            }
            None => break,
        }
    }
    Ok(frames)
}

/// 將隧道框寫入串流。
pub async fn send_frame<W>(io: &mut W, conn_id: u64, kind: u8, body: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes = encode_frame(conn_id, kind, body)?;
    io.write_all(&bytes).await.context("寫入隧道框至串流失敗")?;
    Ok(())
}

/// 從串流讀取一個完整隧道框。
pub async fn recv_frame<R>(io: &mut R) -> Result<TunnelFrame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    io.read_exact(&mut header).await.context("讀取隧道框表頭失敗")?;
    if header[0] != MAGIC_BYTE {
        bail!("魔數字不符 {:#04x}", header[0]);
    }
    let kind = header[1];
    let body_max = body_max_for(kind)?;
    let mut conn_id_bytes = [0u8; 8];
    conn_id_bytes.copy_from_slice(&header[2..10]);
    let conn_id = u64::from_le_bytes(conn_id_bytes);
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&header[10..14]);
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > body_max {
        bail!("frame body 宣稱長度 {} 超過上限 {}", len, body_max);
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await.context("讀取隧道框 body 失敗")?;
    Ok(TunnelFrame { conn_id, kind, body })
}

/// 向對端傳送解壓縮引擎（握手）。
pub async fn send_handshake<W>(io: &mut W, conn_id: u64, wasm: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send_frame(io, conn_id, KIND_HANDSHAKE, wasm).await
}

/// 讀取對端的解壓縮引擎（握手），並回傳其 body 供遠端安裝。
pub async fn recv_handshake<R>(io: &mut R) -> Result<TunnelFrame>
where
    R: AsyncRead + Unpin,
{
    let frame = recv_frame(io).await?;
    if frame.kind != KIND_HANDSHAKE {
        bail!("預期握手框，卻收到 kind {:#04x}", frame.kind);
    }
    Ok(frame)
}

/// 傳送壓縮載荷資料框。
pub async fn send_payload<W>(io: &mut W, conn_id: u64, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    send_frame(io, conn_id, KIND_PAYLOAD, payload).await
}

/// 讀取壓縮載荷資料框。
pub async fn recv_payload<R>(io: &mut R) -> Result<TunnelFrame>
where
    R: AsyncRead + Unpin,
{
    let frame = recv_frame(io).await?;
    if frame.kind != KIND_PAYLOAD {
        bail!("預期資料框，卻收到 kind {:#04x}", frame.kind);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 範例 decompressor：RLE（[count u8][value u8] 重複對），
    /// 以 bulk 指令 `memory.fill` 填滿 run，避免逐位元組迴圈（drives wasmi native 遞迴）。
    const RLE_DECOMPRESSOR_WAT: &str = r#"
(module
  (import "env" "memory" (memory $mem 1 32))
  (func $decompress (export "decompress")
    (param $in i32)
    (param $inLen i32)
    (param $out i32)
    (param $outCap i32)
    (result i32)
    (local $r i32)
    (local $o i32)
    (local $cnt i32)
    (local $val i32)
    (block $done
      (loop $outer
        (br_if $done (i32.ge_u (local.get $r) (local.get $inLen)))
        (local.set $cnt (i32.load8_u (i32.add (local.get $in) (local.get $r))))
        (local.set $r (i32.add (local.get $r) (i32.const 1)))
        (local.set $val (i32.load8_u (i32.add (local.get $in) (local.get $r))))
        (local.set $r (i32.add (local.get $r) (i32.const 1)))
        (if (i32.gt_u (i32.add (local.get $o) (local.get $cnt)) (local.get $outCap))
          (then (return (i32.const -1))))
        (memory.fill (i32.add (local.get $out) (local.get $o)) (local.get $val) (local.get $cnt))
        (local.set $o (i32.add (local.get $o) (local.get $cnt)))
        (br $outer)))
    (local.get $o)))
"#;

    fn rle_encode(runs: &[(u8, u8)]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(count, value) in runs {
            out.push(count);
            out.push(value);
        }
        out
    }

    #[test]
    fn rle_sandbox_roundtrip() -> Result<()> {
        let wasm = wat::parse_str(RLE_DECOMPRESSOR_WAT).expect("WAT 編譯失敗");
        let sandbox = WasmSandbox::install(&wasm)?;

        let payload = rle_encode(&[(3, b'A'), (2, b'B'), (1, b'C')]);
        let out = sandbox.decompress(&payload)?;
        assert_eq!(out, b"AAABBC");

        let payload2 = rle_encode(&[(5, 0x00), (5, 0xff)]);
        let out2 = sandbox.decompress(&payload2)?;
        let mut expected = vec![0x00; 5];
        expected.extend_from_slice(&[0xff; 5]);
        assert_eq!(out2, expected);

        // 大型迴圈壓力測試：產生 ~1 MiB 輸出（4000 段 × 255 bytes ≈ 1.02M 回合），
        // 驗證 512 MiB 大 stack + fuel 1.2M 能容納真實解壓縮量。
        let mut big = Vec::with_capacity(8000);
        for _ in 0..4000 {
            big.push(255);
            big.push(0x5A);
        }
        let big_out = sandbox.decompress(&big)?;
        assert_eq!(big_out.len(), 4000 * 255);
        assert!(big_out.iter().all(|&b| b == 0x5A));
        Ok(())
    }

    #[test]
    fn infinite_loop_traps_on_fuel() -> Result<()> {
        // 迴圈每回合執行大量操作且無終止條件：fuel 計量應終止。
        let wasm = wat::parse_str(
            r#"(module
  (import "env" "memory" (memory 1))
  (func (export "decompress") (param i32 i32 i32 i32) (result i32)
    (local $n i32)
    (local.set $n (i32.const 0))
    (block $done
      (loop $l
        (br_if $done (i32.ge_u (local.get $n) (i32.const 4294967295)))
        (i32.store8 (i32.const 0) (local.get $n))
        (local.set $n (i32.add (local.get $n) (i32.const 1)))
        (br $l)))
    (i32.const 0)))"#,
        )?;
        let sandbox = WasmSandbox::install(&wasm)?;
        let err = sandbox.decompress(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("fuel"), "應因 fuel 耗盡而失敗，實際：{}", err);
        Ok(())
    }

    #[test]
    fn start_function_rejected() -> Result<()> {
        let wasm = wat::parse_str(
            r#"(module
  (import "env" "memory" (memory 1))
  (func $bootstrap (memory.grow (i32.const 8)) drop)
  (start $bootstrap)
  (func (export "decompress") (param i32 i32 i32 i32) (result i32) (i32.const 0)))"#,
        )?;
        assert!(WasmSandbox::install(&wasm).is_err());
        Ok(())
    }

    #[test]
    fn out_of_bounds_memory_access_traps() -> Result<()> {
        let wasm = wat::parse_str(
            r#"(module
  (import "env" "memory" (memory 1))
  (func (export "decompress") (param i32 i32 i32 i32) (result i32)
    (i32.store8 (i32.const 0x200000) (i32.const 7))
    (i32.const 0)))"#,
        )?;
        let sandbox = WasmSandbox::install(&wasm)?;
        assert!(sandbox.decompress(&[42]).is_err(), "越界記憶體存取應失敗");
        Ok(())
    }

    #[test]
    fn non_binary_rejected() {
        assert!(WasmSandbox::install(b"this is not wasm").is_err());
        assert!(WasmSandbox::install(&[0x00; 0]).is_err());
    }

    #[test]
    fn oversized_wasm_rejected() {
        let big = vec![0x00; MAX_WASM_SIZE_BYTES + 1];
        assert!(WasmSandbox::install(&big).is_err());
    }

    #[test]
    fn registry_lifecycle() -> Result<()> {
        let wasm = wat::parse_str(RLE_DECOMPRESSOR_WAT)?;
        let tunnel = WasmTunnel::new();
        let conn_id = 42u64;

        assert!(tunnel.decompress(conn_id, &[1, 2]).is_err(), "未安裝時應失敗");
        tunnel.install(conn_id, &wasm)?;
        assert_eq!(tunnel.active_sessions(), 1);

        let out = tunnel.decompress(conn_id, &rle_encode(&[(2, b'x'), (1, b'y')]))?;
        assert_eq!(out, b"xxy");

        tunnel.uninstall(conn_id);
        assert_eq!(tunnel.active_sessions(), 0);
        Ok(())
    }

    #[test]
    fn frame_encode_parse_roundtrip() -> Result<()> {
        let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01];
        let bytes = encode_handshake(7, &wasm)?;
        assert_eq!(bytes.len(), FRAME_HEADER_LEN + wasm.len());
        let frame = try_parse_frame(&bytes)?.expect("完整框應可解析");
        assert_eq!(frame.conn_id, 7);
        assert_eq!(frame.kind, KIND_HANDSHAKE);
        assert_eq!(frame.body, wasm);

        let bytes2 = encode_payload_frame(7, &[9, 8, 7])?;
        let mut buf = [bytes.clone(), bytes2.clone()].concat();
        let frames = drain_frames(&mut buf)?;
        assert_eq!(frames.len(), 2);
        assert!(buf.is_empty(), "消耗後緩衝應為空");
        assert_eq!(frames[1].body, vec![9, 8, 7]);
        Ok(())
    }

    #[test]
    fn invalid_frames_rejected() -> Result<()> {
        let mut buf = vec![MAGIC_BYTE, KIND_PAYLOAD];
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&(MAX_PAYLOAD_BODY_BYTES as u32 + 1).to_le_bytes());
        assert!(try_parse_frame(&buf).is_err(), "宣稱長度超限應拒絕");

        let mut bad_magic = vec![0x00, KIND_PAYLOAD];
        bad_magic.extend_from_slice(&0u64.to_le_bytes());
        bad_magic.extend_from_slice(&0u32.to_le_bytes());
        assert!(try_parse_frame(&bad_magic).is_err());

        let mut unknown = vec![MAGIC_BYTE, 0x99];
        unknown.extend_from_slice(&0u64.to_le_bytes());
        unknown.extend_from_slice(&0u32.to_le_bytes());
        assert!(try_parse_frame(&unknown).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_frame_returns_none() -> Result<()> {
        let bytes = encode_payload_frame(3, &[1, 2, 3, 4, 5])?;
        assert_eq!(try_parse_frame(&bytes[..FRAME_HEADER_LEN])?, None);
        assert_eq!(try_parse_frame(&bytes[..FRAME_HEADER_LEN + 3])?, None);
        Ok(())
    }

    #[tokio::test]
    async fn async_stream_handshake_and_payload() -> Result<()> {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let wasm = wat::parse_str(RLE_DECOMPRESSOR_WAT)?;
        let conn_id = 99u64;

        let client = tokio::spawn(async move {
            send_handshake(&mut a, conn_id, &wasm).await?;
            send_payload(&mut a, conn_id, &rle_encode(&[(1, b'z')])).await?;
            Ok::<_, anyhow::Error>(())
        });

        let frame = recv_handshake(&mut b).await?;
        assert_eq!(frame.kind, KIND_HANDSHAKE);
        let tunnel = WasmTunnel::new();
        tunnel.install(frame.conn_id, &frame.body)?;
        let payload = recv_payload(&mut b).await?;
        let out = tunnel.decompress(payload.conn_id, &payload.body)?;
        assert_eq!(out, b"z");

        client.await.expect("client task panicked")?;
        Ok(())
    }
}
// src/pipeline/decompression_guard.rs - 解壓炸彈防護層 (42.zip / PASSEDA 思維)
//
// 背景（研究結論，勿憑感覺調參）：
//   1. 遞歸炸彈 (42.zip, 2001)：DEFLATE 格式上限是 1032:1，靠一層層嵌套把 1032 相乘
//      → 42 KB 展開 4.5 PB。只對「會遞歸解壓」的程式有效。
//   2. 非遞歸炸彈 (Fifield, USENIX WOOT'19 "PASSEDA")：靠 ZIP 允許多個檔案項目指向
//      同一段壓縮資料的「重疊檔案」，壓縮比隨輸入平方增長（10 MB → 281 TB），
//      單次解壓就爆，**繞過所有遞歸深度防護**。
//
// 因此單一防線都不夠，本模組同時提供三層（對應三個已知繞過路徑）：
//   A. 絕對輸出上限（真上限）→ XZ 路徑以 `Read::take()` 邊解邊數，超過即中止。
//      這是唯一能「在爆掉前」擋住的一層。
//   B. 壓縮比上限 → **僅告警不攔截**。理由：誠實資料（全 0、空白檔）本身就能合法
//      壓到 100000:1，攔截會誤殺正常流量，故只記錄供事後研判。
//   C. cascade 層數上限 → 請見 NDcode3 側 `decode_chain_raw`；本模組無法注入
//      NDcode3 內部（其 API 為 `(&[u8]) -> Result<Vec<u8>>`，無 max-size 參數）。
//
// ── 誠實的能力邊界（重要，勿誤信本模組為萬靈丹）─────────────────────────────
//   XZ 路徑       : `capped_xz_decompress` 是**真上限**（take() 在配置前中止）。
//   NDCODE3 路徑 : NDcode3 API 不接受 max-size，本層只能**事後驗證**，
//                  即輸出已配置完成才回頭檢查 → 只能 fail-loud，**不能事前阻止**。
//                  真正的事前防護在 NDcode3 側的 cascade 深度上限。
//   因此兩側必須同時落地，單做 NTORS 側對 NDCODE3 路徑只是「事後尖叫」。

use anyhow::{bail, Result};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

// ── NDcode 載荷標記（用於「是否為實際 NDcode 位元組」自動檢驗）──────────────
/// 序列主魔術標頭 `ND3:`
pub const ND3_MASTER: &[u8] = b"ND3:";
/// 平行鏈標頭 `ND3P:`
pub const ND3_PARALLEL: &[u8] = b"ND3P:";
/// XZ/LZMA 魔術 `FD 37 7A 58 5A 00`
pub const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
/// 連鎖結束標記
pub const NDCODE_EOF: &[u8] = b"NDCODE_EOF";
/// 影像載荷標頭 `ND3I` (後接 CRC32 LE + base64 PNG)
pub const ND3_IMAGE: &[u8] = b"ND3I";
/// 光學區塊標頭 `ND3B:`
pub const ND3_OPTICAL: &[u8] = b"ND3B:";

// ── 預設值 ──────────────────────────────────────────────────────────────────

/// 單次解壓輸出上限（位元組）。
///
/// 輸入端已受 `net_transport::MAX_FRAME_LEN` = 1 MiB 限制；合法的封包資料通常
/// 只會展開數倍。64 MiB 對正常流量極寬鬆，但對「1 MiB → GB」的炸彈是硬牆。
pub const DEFAULT_MAX_OUTPUT_PER_DECODE: u64 = 64 * 1024 * 1024;

/// 壓縮比告警門檻（僅記錄，不攔截）。
///
/// 1000 ≈ DEFLATE 自身的格式上限 (1032)，落在此以下幾乎不可能是炸彈。
/// 高於此值不必然惡意 —— 全 0 資料可合法超過，故僅告警。
pub const DEFAULT_MAX_RATIO_WARN: f64 = 1000.0;

/// 連線累計解壓預算上限（位元組）；`0` 表示不限制（預設，避免長連線被誤斷）。
pub const DEFAULT_MAX_TOTAL_DECODED: u64 = 0;

// ── 超限行為 ────────────────────────────────────────────────────────────────

/// 解壓輸出超過上限時的處置（可設定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceedAction {
    /// 直接回傳錯誤，中止此次解壓（最嚴格）。
    Reject,
    /// **預設**：自動檢驗輸出是否為實際 NDcode 位元組。
    ///   - 命中已知標記 / 合法封包框架 → 判定為誠實資料，放行並記錄
    ///   - 完全不像 → 判定為炸彈，拒絕
    /// 讓「合法的高壓縮比資料」與「垃圾填充炸彈」得以區分，避免誤殺。
    ValidateNdcodBytes,
    /// 忽略上限直接放行（等同關閉防護，僅供除錯）。
    PassThrough,
}

impl ExceedAction {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "reject" | "strict" | "hard" => ExceedAction::Reject,
            "passthrough" | "pass" | "off" | "none" => ExceedAction::PassThrough,
            // 未指明即採使用者指定的預設：自動檢驗
            _ => ExceedAction::ValidateNdcodBytes,
        }
    }
}

impl std::fmt::Display for ExceedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExceedAction::Reject => write!(f, "reject"),
            ExceedAction::ValidateNdcodBytes => write!(f, "validate-ndcode"),
            ExceedAction::PassThrough => write!(f, "passthrough"),
        }
    }
}

/// 解壓防護限值配置
#[derive(Debug, Clone)]
pub struct DecompressLimits {
    /// 單次解壓輸出上限（位元組）；`0` = 不限制
    pub max_output_per_decode: u64,
    /// 連線累計解壓預算（位元組）；`0` = 不限制
    pub max_total_decoded: u64,
    /// 壓縮比告警門檻（僅告警不攔截）；`<= 0.0` = 不告警
    pub max_ratio_warn: f64,
    /// 超限處置
    pub on_exceed: ExceedAction,
}

impl Default for DecompressLimits {
    fn default() -> Self {
        Self {
            max_output_per_decode: DEFAULT_MAX_OUTPUT_PER_DECODE,
            max_total_decoded: DEFAULT_MAX_TOTAL_DECODED,
            max_ratio_warn: DEFAULT_MAX_RATIO_WARN,
            on_exceed: ExceedAction::ValidateNdcodBytes,
        }
    }
}

impl DecompressLimits {
    /// 關閉所有限制（僅供測試 / 除錯）
    pub fn disabled() -> Self {
        Self {
            max_output_per_decode: 0,
            max_total_decoded: 0,
            max_ratio_warn: 0.0,
            on_exceed: ExceedAction::PassThrough,
        }
    }
}

// ── 程序級設定與累計計數 ────────────────────────────────────────────────────
//
// `decode_segment` / `NDcodeTunEngine::process_incoming_payload` 是無狀態自由函式，
// 無法攜帶每連線的守衛狀態；故以程序級靜態儲存（啟動時由設定初始化一次）。
// 需要每連線預算的呼叫方（如 `StreamingDecompressor`）則使用具狀態的
// [`guard_decoded`] 並傳入自己的計數器。

static LIMITS: std::sync::OnceLock<DecompressLimits> = std::sync::OnceLock::new();
static GLOBAL_TOTAL_DECODED: AtomicU64 = AtomicU64::new(0);

/// 取得目前生效的解壓限值（未初始化即用預設守限值）。
pub fn limits() -> &'static DecompressLimits {
    LIMITS.get_or_init(DecompressLimits::default)
}

/// 於啟動時設定解壓限值（僅第一次呼叫生效；後續呼叫忽略）。
pub fn set_limits(l: DecompressLimits) {
    let _ = LIMITS.set(l);
}

/// 程序級累計解壓量（位元組）。
pub fn global_total_decoded() -> u64 {
    GLOBAL_TOTAL_DECODED.load(Ordering::Relaxed)
}

/// 重置程序級累計（重連 / 測試用）。
pub fn reset_global_total_decoded() {
    GLOBAL_TOTAL_DECODED.store(0, Ordering::Relaxed);
}

/// 無狀態路徑的守衛：以程序級靜態限值與累計計數執行 [`guard_decoded`]。
///
/// 適用於 `decode_segment` 這類自由函式；每次呼叫即完成「限值檢查 + 計數累加」。
pub fn guard_decoded_global(encoded_len: usize, out: Vec<u8>, path: &str) -> Result<Vec<u8>> {
    let limits = limits();
    if limits.max_output_per_decode == 0
        && limits.max_total_decoded == 0
        && limits.max_ratio_warn <= 0.0
    {
        // 完全未設限：跳過，避免無謂的原子操作與日誌
        return Ok(out);
    }

    let mut total = GLOBAL_TOTAL_DECODED.load(Ordering::Relaxed);
    let out = guard_decoded(encoded_len, out, limits, &mut total, path)?;
    GLOBAL_TOTAL_DECODED.store(total, Ordering::Relaxed);
    Ok(out)
}

// ── 判別：這是不是「實際 NDcode 位元組」？───────────────────────────────────

/// 檢驗位元組序列是否「看起來像」誠實的 NDcode 載荷。
///
/// 用途：當輸出超過上限時，用來分辨
///   * 誠實的高壓縮比資料（應放行 —— 例如全 0 的正常檔案）
///   * 炸彈灌入的無意義填充（應拒絕）
///
/// 判定採**寬鬆**取向：命中任一標記、或具合法封包框架即通過。
/// 拒絕僅在「完全不像任何已知結構」時發生。
pub fn looks_like_ndcode(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        // 空輸出不具破壞性，視為無害
        return true;
    }

    // 1) 已知 NDcode 標記（出現於任何位置皆可，因輸出可能是串接後的頂層資料）
    for marker in [
        ND3_MASTER,
        ND3_PARALLEL,
        NDCODE_EOF,
        ND3_IMAGE,
        ND3_OPTICAL,
    ] {
        if find_subsequence(bytes, marker).is_some() {
            return true;
        }
    }

    // 2) XZ 魔術：輸出本身仍是壓縮容器（多層嵌套的合法中間態）
    if bytes.len() >= XZ_MAGIC.len() && bytes[..XZ_MAGIC.len()] == XZ_MAGIC {
        return true;
    }

    // 3) 串流段標頭 0x02 + 合法引擎標籤 (0x01 XZ / 0x05 NDcode3)
    if bytes.len() >= 6 && bytes[0] == 0x02 && (bytes[1] == 0x01 || bytes[1] == 0x05) {
        let decl = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
        if decl == bytes.len() - 6 {
            return true;
        }
    }

    // 4) 序列傳輸標頭 0x01 (XZ) / 0x03 (ND3) —— 隧道資料面實際產物
    if matches!(bytes[0], 0x01 | 0x03) {
        return true;
    }

    // 5) IPv4 / IPv6 封包框架：隧道解壓的正常結果
    //    IPv4: 版本 nibble = 4，首部長度 >= 5 → 0x45..0x4F
    //    IPv6: 版本 nibble = 6 → 0x6x
    let v = bytes[0] >> 4;
    if v == 4 && (bytes[0] & 0x0F) >= 5 && bytes.len() >= 20 {
        return true;
    }
    if v == 6 && bytes.len() >= 40 {
        return true;
    }

    false
}

/// 尋找子序列（避免引入額外相依）
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ── A. XZ 路徑：真上限（take() 在配置前中止）────────────────────────────────

/// 以輸出上限解壓 XZ 資料。
///
/// 與 `NDcode3::logic::safe_xz_decompress` 語意對齊（魔術不符即原樣放行），
/// 差別在於魔術相符時走 `Read::take()`，**邊解邊數、超過即中止**，
/// 因此不會先配置出一個巨大的 `Vec` 再回頭檢查。
///
/// 這是本模組唯一能在「炸彈爆開前」擋住的路徑。
pub fn capped_xz_decompress(data: &[u8], max_output: u64) -> Result<Vec<u8>> {
    if max_output == 0 {
        // 未設限：直接委派 NDcode3（維持原行為）
        return NDcode3::logic::safe_xz_decompress(data);
    }

    if data.len() < XZ_MAGIC.len() || data[..XZ_MAGIC.len()] != XZ_MAGIC {
        // 非 XZ：與 safe_xz_decompress 同樣原樣放行（輸出長度 == 輸入長度，無放大）
        return Ok(data.to_vec());
    }

    // take(max_output + 1)：多讀 1 位元組以區分「剛好滿」與「超過」
    let limit = max_output.saturating_add(1);
    let mut decoder = xz::read::XzDecoder::new(data).take(limit);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| anyhow::anyhow!("XZ 解壓失敗（可能已觸及輸出上限 {max_output}B）: {e}"))?;

    if out.len() as u64 > max_output {
        bail!(
            "解壓輸出超過上限：實際欲產出 > {}B（輸入 {}B）\n\
             已在配置完整輸出前中止，未耗盡記憶體。",
            fmt_bytes(max_output),
            fmt_bytes(data.len() as u64)
        );
    }
    Ok(out)
}

// ── B/C. 事後守衛（NDCODE3 路徑 + 累計預算 + 比率告警）──────────────────────

/// 守衛解壓結果：輸出大小上限 + 累計預算 + 壓縮比告警 + 超限處置。
///
/// 注意：此函式在**輸出已配置完成後**才執行，故對無 `max-size` 參數的
/// NDcode3 API 而言屬事後驗證（fail-loud）。事前阻斷請見
/// [`capped_xz_decompress`] 與 NDcode3 側的 cascade 深度上限。
pub fn guard_decoded(
    encoded_len: usize,
    out: Vec<u8>,
    limits: &DecompressLimits,
    total_decoded: &mut u64,
    path: &str,
) -> Result<Vec<u8>> {
    // B) 壓縮比告警（僅記錄，不攔截）
    if limits.max_ratio_warn > 0.0 && encoded_len > 0 {
        let ratio = out.len() as f64 / encoded_len as f64;
        if ratio > limits.max_ratio_warn {
            eprintln!(
                "⚠️  [BombGuard] 壓縮比告警: ratio={ratio:.0}:1 (門檻 {:.0}:1) \
                 路徑={path} 輸入={in} 輸出={out_}\n\
                 ℹ️  高壓縮比不必然惡意（全 0 等誠實資料可合法超過），本項僅告警不攔截。",
                limits.max_ratio_warn,
                in = fmt_bytes(encoded_len as u64),
                out_ = fmt_bytes(out.len() as u64),
            );
        }
    }

    let produced = out.len() as u64;

    // 累計預算（連線層）
    if limits.max_total_decoded > 0 {
        let projected = total_decoded.saturating_add(produced);
        if projected > limits.max_total_decoded {
            return apply_exceed_action(
                limits,
                encoded_len,
                out,
                path,
                &format!(
                    "連線累計解壓量 {projected}B 超過預算 {}B",
                    fmt_bytes(limits.max_total_decoded)
                ),
            );
        }
    }

    // A') 單次輸出上限（事後，對 NDCODE3 路徑）
    if limits.max_output_per_decode > 0 && produced > limits.max_output_per_decode {
        return apply_exceed_action(
            limits,
            encoded_len,
            out,
            path,
            &format!(
                "單次解壓輸出 {produced}B 超過上限 {}B（輸入 {}B）",
                fmt_bytes(limits.max_output_per_decode),
                fmt_bytes(encoded_len as u64)
            ),
        );
    }

    *total_decoded = total_decoded.saturating_add(produced);
    Ok(out)
}

/// 依配置的超限處置回應。
fn apply_exceed_action(
    limits: &DecompressLimits,
    encoded_len: usize,
    out: Vec<u8>,
    path: &str,
    reason: &str,
) -> Result<Vec<u8>> {
    match limits.on_exceed {
        ExceedAction::PassThrough => {
            eprintln!(
                "⚠️  [BombGuard] 超限但設定為 pass-through：{reason} (路徑={path})"
            );
            Ok(out)
        }
        ExceedAction::Reject => {
            bail!("[BombGuard] 拒絕解壓結果：{reason} (路徑={path})")
        }
        ExceedAction::ValidateNdcodBytes => {
            // 自動檢驗是否為實際 NDcode 位元組
            if looks_like_ndcode(&out) {
                eprintln!(
                    "ℹ️  [BombGuard] 超限但經自動檢驗屬實際 NDcode/封包位元組，放行：\
                     {reason} (路徑={path} 輸入={} 輸出={})",
                    fmt_bytes(encoded_len as u64),
                    fmt_bytes(out.len() as u64),
                );
                Ok(out)
            } else {
                bail!(
                    "[BombGuard] 拒絕：{reason} (路徑={path})\n\
                     自動檢驗失敗 —— 輸出不含任何已知 NDcode 標記或合法封包框架，\n\
                     判定為解壓炸彈填充資料。"
                )
            }
        }
    }
}

/// 人類可讀的位元組格式
fn fmt_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let n_f = n as f64;
    if n_f >= GIB {
        format!("{:.2} GiB", n_f / GIB)
    } else if n_f >= MIB {
        format!("{:.2} MiB", n_f / MIB)
    } else if n_f >= KIB {
        format!("{:.2} KiB", n_f / KIB)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ndcode_markers_detected() {
        assert!(looks_like_ndcode(b"ND3:something"));
        assert!(looks_like_ndcode(b"ND3P:abc"));
        assert!(looks_like_ndcode(b"prefix NDCODE_EOF suffix"));
        assert!(looks_like_ndcode(b"ND3I\0\0\0\0PNG"));
        assert!(looks_like_ndcode(&XZ_MAGIC));
    }

    #[test]
    fn ip_packet_framework_detected() {
        // IPv4, IHL=5, 20 bytes
        let mut v4 = vec![0x45u8; 20];
        v4[0] = 0x45;
        assert!(looks_like_ndcode(&v4));
        // IPv6, 40 bytes
        let v6 = vec![0x60u8; 40];
        assert!(looks_like_ndcode(&v6));
    }

    #[test]
    fn serial_and_segment_headers_detected() {
        assert!(looks_like_ndcode(&[0x01, 0x02, 0x03]));
        assert!(looks_like_ndcode(&[0x03, b'N', b'D', b'3', b':']));
        // 串流段 [0x02][0x01][len=0][空 payload]
        assert!(looks_like_ndcode(&[0x02, 0x01, 0, 0, 0, 0]));
    }

    #[test]
    fn garbage_rejected() {
        // 亂數、無標記、無封包框架
        let junk: Vec<u8> = (0x80u8..0xB0).flat_map(|i| std::iter::repeat(i).take(8)).collect();
        assert!(!looks_like_ndcode(&junk));
        assert!(!looks_like_ndcode(&[0x77; 64]));
    }

    #[test]
    fn empty_is_harmless() {
        assert!(looks_like_ndcode(b""));
    }

    #[test]
    fn exceed_action_parse_defaults_to_validate() {
        assert_eq!(ExceedAction::parse("reject"), ExceedAction::Reject);
        assert_eq!(ExceedAction::parse("PASS"), ExceedAction::PassThrough);
        assert_eq!(ExceedAction::parse("anything"), ExceedAction::ValidateNdcodBytes);
        assert_eq!(ExceedAction::parse(""), ExceedAction::ValidateNdcodBytes);
    }

    #[test]
    fn limits_default_is_guarded() {
        let l = DecompressLimits::default();
        assert!(l.max_output_per_decode > 0);
        assert!(l.max_ratio_warn > 0.0);
        assert_eq!(l.on_exceed, ExceedAction::ValidateNdcodBytes);
        let d = DecompressLimits::disabled();
        assert_eq!(d.max_output_per_decode, 0);
        assert_eq!(d.on_exceed, ExceedAction::PassThrough);
    }

    #[test]
    fn capped_xz_passes_through_non_xz() {
        // 非 XZ 魔術 → 原樣放行
        let raw = b"not xz data at all";
        let out = capped_xz_decompress(raw, 1024).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn capped_xz_respects_zero_limit_as_disabled() {
        let raw = b"plain";
        let out = capped_xz_decompress(raw, 0).unwrap();
        assert_eq!(out, raw);
    }

    #[test]
    fn guard_allows_within_limits() {
        let limits = DecompressLimits::default();
        let mut total = 0u64;
        let out = vec![0u8; 1024];
        let res = guard_decoded(256, out, &limits, &mut total, "test").unwrap();
        assert_eq!(res.len(), 1024);
        assert_eq!(total, 1024);
    }

    #[test]
    fn guard_rejects_on_reject_action() {
        let limits = DecompressLimits {
            max_output_per_decode: 16,
            on_exceed: ExceedAction::Reject,
            ..DecompressLimits::default()
        };
        let mut total = 0u64;
        let out = vec![0u8; 64];
        assert!(guard_decoded(1, out, &limits, &mut total, "test").is_err());
    }

    #[test]
    fn guard_validate_keeps_ndcode_rejects_garbage() {
        let mk = |act: ExceedAction| DecompressLimits {
            max_output_per_decode: 16,
            on_exceed: act,
            ..DecompressLimits::default()
        };
        let mut total = 0u64;

        // 看起來像 NDcode → 放行
        let ndcode_out = b"ND3:legit".to_vec();
        let r = guard_decoded(1, ndcode_out, &mk(ExceedAction::ValidateNdcodBytes), &mut total, "t");
        assert!(r.is_ok());

        // 垃圾填充 → 拒絕
        let garbage = vec![0x9Eu8; 64];
        let r = guard_decoded(1, garbage, &mk(ExceedAction::ValidateNdcodBytes), &mut total, "t");
        assert!(r.is_err());
    }

    #[test]
    fn guard_passthrough_always_allows() {
        let limits = DecompressLimits {
            max_output_per_decode: 4,
            on_exceed: ExceedAction::PassThrough,
            ..DecompressLimits::default()
        };
        let mut total = 0u64;
        let out = vec![0u8; 4096];
        assert!(guard_decoded(1, out, &limits, &mut total, "t").is_ok());
    }

    #[test]
    fn ratio_warning_is_non_fatal() {
        // 極高壓縮比：僅告警，不得回傳 Err
        let limits = DecompressLimits::default();
        let mut total = 0u64;
        // 1 byte 輸入 → 100KB 輸出，ratio = 102400（遠超 1000 告警門檻）
        // 但輸出 100KB < 64MiB 上限，故應通過
        let out = vec![0u8; 100_000];
        assert!(guard_decoded(1, out, &limits, &mut total, "test").is_ok());
    }

    #[test]
    fn total_budget_enforced_when_set() {
        let limits = DecompressLimits {
            max_total_decoded: 100,
            on_exceed: ExceedAction::Reject,
            ..DecompressLimits::default()
        };
        let mut total = 0u64;
        assert!(guard_decoded(1, vec![0u8; 60], &limits, &mut total, "t").is_ok());
        assert_eq!(total, 60);
        // 累計 60 + 60 = 120 > 100 → 超限
        assert!(guard_decoded(1, vec![0u8; 60], &limits, &mut total, "t").is_err());
    }
}

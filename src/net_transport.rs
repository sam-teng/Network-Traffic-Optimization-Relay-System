// src/net_transport.rs - NTORS 連線端自帶傳輸編解碼 (Connection-End Transport Codec)
//
// TransportCodec<S> 包住任何 socket/串流，實作 AsyncRead + AsyncWrite：
//   - 寫入 (poll_write) : 先經 NDcode 統一序列傳輸入口編碼後，加上 4-byte 長度前綴寫出
//   - 讀取               : 依長度前綴讀回完整 frame，經序列傳輸解碼後交付
//                          (read_frame 保證整封包交付；poll_read 可用於通用串流讀取)
//
// 因此「上傳 / 下載」都只是讀寫同一個 codec，編解碼完全內建於連線端，
// 不需額外 framing 協定層 (Obfuscator 等) 介入 —— 也就是連線端自帶傳輸即編解碼。

use anyhow::Context;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::ndcode_tun_engine::NDcodeTunEngine;

/// 連線端長度前綴大小
const FRAME_LEN_PREFIX: usize = 4;

/// 單一 frame 合理長度上限 (IPv6 jumbo frame 上限內)。
/// 若對端提供的長度前綴超過此值，視為協議違規/垃圾資料，拒絕而非配置巨量記憶體。
const MAX_FRAME_LEN: usize = 1 << 20; // 1 MiB

/// 讀取狀態機：正在組裝哪一段 wire frame
enum ReadPhase {
    /// 累積 4-byte Big-Endian 長度前綴
    Length(Vec<u8>),
    /// 累積 frame payload (長度已定)
    Payload { buf: Vec<u8>, filled: usize },
}

/// 連線端自帶傳輸編解碼器：內建 NDcode 序列編碼/解碼的雙向 Stream 包覆
pub struct TransportCodec<S> {
    inner: S,
    engine: Arc<NDcodeTunEngine>,
    /// 目前「已完整解碼的一整個封包」+ 已透過 poll_read 交付的 offset。
    /// read_frame 依此整包交付，不受先前部分讀取影響。
    packet: Option<(Vec<u8>, usize)>,
    /// 讀取狀態機 (wire frame 組裝)
    read_phase: ReadPhase,
    /// 尚未寫完的編碼 frame
    write_pending: Option<Vec<u8>>,
    write_offset: usize,
    write_accepted: usize,
    /// 單一負載解碼失敗次數 (不中斷連線，僅統計)
    pub decode_errors: u64,
}

impl<S> TransportCodec<S> {
    pub fn new(inner: S, engine: Arc<NDcodeTunEngine>) -> Self {
        Self {
            inner,
            engine,
            packet: None,
            read_phase: ReadPhase::Length(Vec::with_capacity(FRAME_LEN_PREFIX)),
            write_pending: None,
            write_offset: 0,
            write_accepted: 0,
            decode_errors: 0,
        }
    }

    /// 取回內部串流 (結束連線端傳輸)
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// 將單一 IP 封包編碼為 wire frame：[len_be u32][encoded]
fn encode_frame(engine: &NDcodeTunEngine, packet: &[u8]) -> io::Result<Vec<u8>> {
    let encoded = engine
        .process_outgoing_packet(packet)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("連線端編碼失敗: {e}")))?;
    let mut frame = Vec::with_capacity(FRAME_LEN_PREFIX + encoded.len());
    frame.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    frame.extend_from_slice(&encoded);
    Ok(frame)
}

/// 將 wire frame 解碼為原始 bytes
fn decode_frame(engine: &NDcodeTunEngine, frame: &[u8]) -> anyhow::Result<Vec<u8>> {
    engine
        .process_incoming_payload(frame)
        .context("連線端解碼失敗")
}

impl<S: AsyncRead + Unpin> TransportCodec<S> {
    /// 讀入一截內層資料。回傳 Some(got) 已讀 bytes (got > 0)；None 代表正常 EOF。
    fn poll_read_raw(
        &mut self,
        cx: &mut TaskContext<'_>,
        tmp: &mut [u8],
        need: usize,
    ) -> Poll<io::Result<Option<usize>>> {
        debug_assert!(need > 0);
        let mut rb = ReadBuf::new(&mut tmp[..need]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let got = rb.filled().len();
                if got == 0 {
                    Poll::Ready(Ok(None))
                } else {
                    Poll::Ready(Ok(Some(got)))
                }
            }
        }
    }

    /// 核心狀態機：盡力把「一個完整 frame」解碼成一個完整封包。
    /// Ok(Some(pkt)) 代表已取得完整封包；Ok(None) 代表正常 EOF (於 frame 邊界)。
    fn pump_one_frame(&mut self, cx: &mut TaskContext<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
        loop {
            let need = match &self.read_phase {
                ReadPhase::Length(h) => FRAME_LEN_PREFIX - h.len(),
                ReadPhase::Payload { buf, filled } => buf.len() - *filled,
            };

            if need == 0 {
                // frame 已組裝完整 → 解碼為一個完整封包
                let done = std::mem::replace(
                    &mut self.read_phase,
                    ReadPhase::Length(Vec::with_capacity(FRAME_LEN_PREFIX)),
                );
                let frame = match done {
                    ReadPhase::Payload { buf, .. } => buf,
                    ReadPhase::Length(..) => unreachable!("Length phase 不應在 need==0 時完成"),
                };
                match decode_frame(&self.engine, &frame) {
                    Ok(raw) if !raw.is_empty() => return Poll::Ready(Ok(Some(raw))),
                    _ => {
                        self.decode_errors += 1;
                        continue; // 壞 frame 略過，繼續讀下一 frame
                    }
                }
            }

            // 從內層串流讀入一截 (最多 2048 bytes)
            let mut tmp = [0u8; 2048];
            let read_need = need.min(tmp.len());
            match self.poll_read_raw(cx, &mut tmp, read_need) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(None)) => {
                    // 乾淨 EOF：僅當位於 frame 邊界 (Length 前綴尚未累積) 才視為正常結束
                    let at_frame_boundary = matches!(
                        &self.read_phase,
                        ReadPhase::Length(h) if h.is_empty()
                    );
                    if at_frame_boundary {
                        return Poll::Ready(Ok(None));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "連線端傳輸中途斷線 (frame 未完成)",
                    )));
                }
                Poll::Ready(Ok(Some(got))) => {
                    match &mut self.read_phase {
                        ReadPhase::Length(h) => {
                            h.extend_from_slice(&tmp[..got]);
                            if h.len() == FRAME_LEN_PREFIX {
                                let len = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as usize;
                                // 保護：拒絕離譜長度 (非 NDcode 對端垃圾資料/協定錯亂)
                                if len == 0 || len > MAX_FRAME_LEN {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "長度標頭 {len} bytes 超出合理上限 {MAX_FRAME_LEN}，疑為非 NDcode 對端"
                                        ),
                                    )));
                                }
                                self.read_phase = ReadPhase::Payload {
                                    buf: vec![0u8; len],
                                    filled: 0,
                                };
                            }
                        }
                        ReadPhase::Payload { buf, filled } => {
                            buf[*filled..*filled + got].copy_from_slice(&tmp[..got]);
                            *filled += got;
                        }
                    }
                    continue;
                }
            }
        }
    }

    /// 讀回「一個完整還原封包」(整包交付，不受先前部分 poll_read 影響)。
    /// Ok(None) 代表對端已正常結束 (乾淨 EOF)。
    pub async fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        std::future::poll_fn(|cx| loop {
            // 1. 若已有完整封包：把剩餘部分整包交付
            if let Some((pkt, off)) = &self.packet {
                let rest = pkt[*off..].to_vec();
                self.packet = None;
                return Poll::Ready(Ok(Some(rest)));
            }
            // 2. 否則驅動狀態機取得一個完整封包
            match self.pump_one_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(Some(pkt))) => return Poll::Ready(Ok(Some(pkt))),
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(None)),
            }
        })
        .await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TransportCodec<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 1. 已有完整封包：按 offset 交付未消耗部分
        if let Some((pkt, off)) = self.packet.take() {
            let remaining = pkt.len() - off;
            let n = remaining.min(buf.remaining());
            buf.put_slice(&pkt[off..off + n]);
            if n < remaining {
                self.packet = Some((pkt, off + n));
            }
            return Poll::Ready(Ok(()));
        }

        // 2. 驅動狀態機取得封包 (或在 EOF 時回報 0 bytes = EOF)
        match self.pump_one_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(Some(pkt))) => {
                let n = pkt.len().min(buf.remaining());
                if n == pkt.len() {
                    buf.put_slice(&pkt);
                } else {
                    // 呼叫者緩衝區太小：先交付部分，剩餘保留於 packet 供下次讀
                    buf.put_slice(&pkt[..n]);
                    self.packet = Some((pkt, n));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(())),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TransportCodec<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            // 若有未寫完的 frame，先盡力寫完
            if self.write_pending.is_none() {
                if buf.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                let frame = encode_frame(&self.engine, buf)?;
                self.write_pending = Some(frame);
                self.write_offset = 0;
                self.write_accepted = buf.len();
            }

            // 寫出待寫 frame 的剩餘部分 (複製一份，避免 `Pin<&mut self.inner>` 借用衝突)
            let pending_len = self.write_pending.as_ref().unwrap().len();
            let offset = self.write_offset;
            let data = self.write_pending.as_ref().unwrap()[offset..].to_vec();
            let done = Pin::new(&mut self.inner).poll_write(cx, &data);
            match done {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(written)) => {
                    self.write_offset += written;
                    if self.write_offset >= pending_len {
                        // frame 已完整送出：回報本次接受的原始 bytes，勿再重編同一 buf
                        self.write_pending = None;
                        return Poll::Ready(Ok(self.write_accepted));
                    }
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 透過非同步串流發送經過 NDcode 壓縮處理的 Payload (長度前綴)
pub async fn send_framed_payload<W>(stream: &mut W, payload: &[u8]) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let length = payload.len() as u32;
    // 寫入 4 位元組 Big-Endian 長度標頭
    stream
        .write_u32(length)
        .await
        .context("寫入長度標頭失敗")?;
    // 寫入實際 Payload
    stream
        .write_all(payload)
        .await
        .context("寫入 Payload 數據失敗")?;
    stream.flush().await.context("Flush 串流失敗")?;
    Ok(())
}

/// 從非同步串流接收完整的 NDcode Payload
pub async fn recv_framed_payload<R>(stream: &mut R) -> anyhow::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    // 讀取 4 位元組 Big-Endian 長度標頭
    let length = stream
        .read_u32()
        .await
        .context("讀取長度標頭失敗")? as usize;

    // 保護：拒絕離譜長度，避免對端惡意/垃圾資料觸發 OOM (如誤連到非 NDcode 服務)
    if length == 0 || length > MAX_FRAME_LEN {
        anyhow::bail!(
            "長度標頭超出合理範圍 ({length} bytes > {MAX_FRAME_LEN})，疑為非 NDcode 對端或連線錯亂"
        );
    }

    let mut buf = vec![0u8; length];
    stream
        .read_exact(&mut buf)
        .await
        .context("讀取完整 Payload 失敗")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use tokio::io::AsyncWriteExt;

    fn random_packet(size: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..size).map(|_| rng.r#gen::<u8>()).collect()
    }

    fn codec_pair() -> (
        TransportCodec<tokio::io::DuplexStream>,
        TransportCodec<tokio::io::DuplexStream>,
    ) {
        let (a, b) = tokio::io::duplex(1 << 20); // 1MB 記憶體串流，容納大 frame
        let engine = Arc::new(NDcodeTunEngine::new());
        (
            TransportCodec::new(a, engine.clone()),
            TransportCodec::new(b, engine),
        )
    }

    /// 上傳方向：A 端寫原始封包 → wire 上自動編碼 → B 端 read_frame 解碼還原
    #[tokio::test]
    async fn test_codec_upload_small_medium_roundtrip() {
        let (mut a, mut b) = codec_pair();
        for pkt in [random_packet(64), random_packet(256), random_packet(512)] {
            a.write_all(&pkt).await.unwrap();
            a.flush().await.unwrap();
            let restored = b.read_frame().await.unwrap().expect("應收到封包");
            assert_eq!(restored, pkt, "上傳 (小/中封包) 僅透過連線端編解碼應無損還原");
        }
        assert_eq!(b.decode_errors, 0);
    }

    /// 下載方向：B 端寫原始封包 → A 端 read_frame 還原 (與上傳完全對稱)
    #[tokio::test]
    async fn test_codec_download_big_packet_roundtrip() {
        let (mut a, mut b) = codec_pair();
        let pkts = vec![random_packet(3072), random_packet(4096)];
        let pkts_written = pkts.clone();

        // A 端背景讀取 (避免 duplex 塞住 B 的寫入)
        let mut a_reader = tokio::spawn(async move {
            let mut restored = Vec::new();
            while let Some(pkt) = a.read_frame().await.unwrap() {
                restored.push(pkt);
            }
            restored
        });

        for p in &pkts {
            b.write_all(p).await.unwrap();
            b.flush().await.unwrap();
        }
        b.shutdown().await.unwrap();

        let restored = a_reader.await.unwrap();
        assert_eq!(restored, pkts_written, "下載 (大封包 ND3 平行鏈) 應無損還原");
    }

    /// 同時雙向：同一個 codec pair 之上傳 + 下載皆可 (連線端自帶編解碼)
    /// A 端上傳 pkt_up、B 端下載 pkt_down；兩端各自持一個 codec 並行運作。
    #[tokio::test]
    async fn test_codec_bidirectional_both_directions() {
        let (mut a, mut b) = codec_pair();
        let pkt_up = random_packet(300); // A 上傳給 B
        let pkt_down = random_packet(4000); // B 下載給 A

        // A 端：先寫上傳，再等讀取到 B 送來的下載
        let up_for_a = pkt_up.clone();
        let task_a = tokio::spawn(async move {
            a.write_all(&up_for_a).await.unwrap();
            a.flush().await.unwrap();
            let mut restored = Vec::new();
            while let Some(pkt) = a.read_frame().await.unwrap() {
                restored.push(pkt);
            }
            restored.concat()
        });

        // B 端：先讀上傳 (A 的 pkt_up)，再寫下載 (pkt_down) 並關閉
        let down_for_b = pkt_down.clone();
        let task_b = tokio::spawn(async move {
            let received_up = b.read_frame().await.unwrap().expect("應收到上傳封包");
            b.write_all(&down_for_b).await.unwrap();
            b.flush().await.unwrap();
            b.shutdown().await.unwrap();
            received_up
        });

        let (res_a, res_b) = tokio::join!(task_a, task_b);
        let a_read_down = res_a.unwrap();
        let b_read_up = res_b.unwrap();

        assert_eq!(a_read_down, pkt_down, "下載方向 (peer→本機) 還原失敗");
        assert_eq!(b_read_up, pkt_up, "上傳方向 (本機→peer) 還原失敗");
    }

    /// 三封包串流：依序還原 (驗證多 frame 連續讀取)
    #[tokio::test]
    async fn test_codec_multi_packet_stream() {
        let (mut a, mut b) = codec_pair();
        let pkts = vec![random_packet(1000), random_packet(2400), random_packet(200)];
        let pkts_written = pkts.clone();

        let a_writer = tokio::spawn(async move {
            for p in &pkts_written {
                a.write_all(p).await.unwrap();
                a.flush().await.unwrap();
            }
            a.shutdown().await.unwrap();
        });

        let mut restored = Vec::new();
        while let Some(pkt) = b.read_frame().await.unwrap() {
            restored.push(pkt);
        }
        a_writer.await.unwrap();

        assert_eq!(restored, pkts, "多封包串流應逐一還原 (整包交付)");
    }

    /// 正常關閉時 read_frame 應回報乾淨 EOF (Ok(None))
    #[tokio::test]
    async fn test_codec_clean_eof() {
        let (mut a, mut b) = codec_pair();
        let pkt = random_packet(900);
        a.write_all(&pkt).await.unwrap();
        a.flush().await.unwrap();
        a.shutdown().await.unwrap();

        let first = b.read_frame().await.unwrap().expect("第一封包應可讀");
        assert_eq!(first, pkt);
        assert!(
            b.read_frame().await.unwrap().is_none(),
            "應回報乾淨 EOF"
        );
    }

    /// 越界長度前綴 (垃圾資料，如誤連非 NDcode 遠端) 應被拒絕，而非配置巨量記憶體
    /// (直接對 wire 寫入原始前綴，繞過 encode_frame)
    #[tokio::test]
    async fn test_codec_rejects_oversized_length_prefix() {
        let (mut raw_write, wire) = tokio::io::duplex(4096);
        let mut b = TransportCodec::new(wire, Arc::new(NDcodeTunEngine::new()));
        // 對端送出無限長度標頭 (0x48_00_00_00 ≈ 1.2 GB)
        raw_write.write_all(&[0x48, 0x00, 0x00, 0x00]).await.unwrap();
        raw_write.flush().await.unwrap();
        // 關閉寫端，避免 Pending
        raw_write.shutdown().await.unwrap();

        let res = b.read_frame().await;
        assert!(
            res.is_err(),
            "越界長度應回報錯誤而非默默 OOM (實際: {:?})",
            res.map(|_| "Ok".to_string())
        );
        if let Err(e) = res {
            let msg = format!("{e}");
            assert!(msg.contains("合理上限"), "錯誤訊息應提示長度上限: {msg}");
        }
    }

    /// recv_framed_payload 對越界長度前綴應拒絕而非 OOM
    #[tokio::test]
    async fn test_recv_framed_payload_rejects_oversized() {
        let (mut a, b) = tokio::io::duplex(4096);
        a.write_all(&1_500_000u32.to_be_bytes()).await.unwrap();
        a.flush().await.unwrap();

        let mut reader = b;
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            recv_framed_payload(&mut reader),
        )
        .await;
        let res = res.expect("不應逾時 (長度違規應立刻回報)");
        assert!(res.is_err(), "越界長度應被 recv_framed_payload 拒絕");
    }

    /// 長度 = 0 的前綴也應被拒絕 (直接對 wire 寫入原始前綴)
    #[tokio::test]
    async fn test_codec_rejects_zero_length_prefix() {
        let (mut raw_write, wire) = tokio::io::duplex(4096);
        let mut b = TransportCodec::new(wire, Arc::new(NDcodeTunEngine::new()));
        raw_write.write_all(&[0x00, 0x00, 0x00, 0x00]).await.unwrap();
        raw_write.flush().await.unwrap();
        raw_write.shutdown().await.unwrap();

        let res = b.read_frame().await;
        assert!(res.is_err(), "長度 0 前綴應被拒絕");
    }
}
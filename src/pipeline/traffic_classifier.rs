// src/pipeline/traffic_classifier.rs - TUN (L3) 流量識別與分流
//
// 從 Raw IP 封包中辨識 TCP/UDP 流，判斷是否屬於 HTTP (80) / HTTPS (443) 下載流量。
// 並提供 TCP FIN / RST 偵測，供串流壓縮器在流結束時 flush 尾段緩衝。

use std::collections::HashMap;

/// 流量分類結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    /// 明文 HTTP 下載流 (TCP, 埠號 80) - 優先串流壓縮
    Http,
    /// HTTPS 下載流 (TCP, 埠號 443) - 串流壓縮
    Https,
    /// 其他流量 (DNS / 遊戲 / 自訂埠) - 透傳
    Other,
}

impl TrafficClass {
    pub fn compressible(&self) -> bool {
        matches!(self, TrafficClass::Http | TrafficClass::Https)
    }
}

/// 流方向無關的完整金鑰 (雙向識別，含 IP，避免跨主機埠碰撞)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub version: IpVersion,
    pub proto: u8,
    pub addr_a: u128,
    pub addr_b: u128,
    pub port_a: u16,
    pub port_b: u16,
}

impl FlowKey {
    /// 由已解析封包建構方向無關的金鑰 (位址+埠皆排序)
    pub fn from_parsed(p: &ParsedPacket) -> Self {
        let (addr_a, addr_b) = if p.src_addr <= p.dst_addr {
            (p.src_addr, p.dst_addr)
        } else {
            (p.dst_addr, p.src_addr)
        };
        let (port_a, port_b) = if p.src_port <= p.dst_port {
            (p.src_port, p.dst_port)
        } else {
            (p.dst_port, p.src_port)
        };
        Self {
            version: p.version,
            proto: p.proto,
            addr_a,
            addr_b,
            port_a,
            port_b,
        }
    }
}

/// IP 版本
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpVersion {
    V4,
    V6,
}

/// 單一 IP 封包的解析結果
#[derive(Debug, Clone, Copy)]
pub struct ParsedPacket {
    pub version: IpVersion,
    pub proto: u8,
    /// 來源/目的 IP (v4 以 u32 存於低位，v6 以 u128)
    pub src_addr: u128,
    pub dst_addr: u128,
    pub src_port: u16,
    pub dst_port: u16,
    /// TCP 是否帶 FIN 或 RST 旗標 (串流結尾)
    pub tcp_flow_end: bool,
}

/// HTTP 下載流識別器
pub struct TrafficClassifier {
    /// 流快取：避免重複解析相同 5-Tuple
    flow_cache: HashMap<FlowKey, TrafficClass>,
    /// 快取上限 (簡單 FIFO 淘汰)
    max_flows: usize,
}

impl Default for TrafficClassifier {
    fn default() -> Self {
        Self::new(4096)
    }
}

impl TrafficClassifier {
    pub fn new(max_flows: usize) -> Self {
        let max_flows = max_flows.max(1);
        Self {
            flow_cache: HashMap::with_capacity(max_flows.next_power_of_two()),
            max_flows,
        }
    }

    /// 清除快取 (重設會話時使用)
    pub fn reset(&mut self) {
        self.flow_cache.clear();
    }

    /// 解析單一封包，回傳流量分類 (單次解析 + 完整 FlowKey 快取)
    pub fn classify(&mut self, packet: &[u8]) -> TrafficClass {
        let parsed = match Self::parse_packet(packet) {
            Some(p) => p,
            None => return TrafficClass::Other,
        };
        self.classify_with_parsed(&parsed)
    }

    /// 由已解析結果分類 (供管線單次解析後重用，避免重複解析)
    pub fn classify_with_parsed(&mut self, parsed: &ParsedPacket) -> TrafficClass {
        // 僅對 TCP/UDP 建立流快取
        if parsed.proto == 6 || parsed.proto == 17 {
            let key = FlowKey::from_parsed(parsed);
            if let Some(&cls) = self.flow_cache.get(&key) {
                return cls;
            }
            if self.flow_cache.len() >= self.max_flows {
                // 任意淘汰 (HashMap 無序，非嚴格 FIFO)：快取滿時清空一半避免無界增長
                let drop_n = self.max_flows / 2;
                let stale: Vec<FlowKey> = self.flow_cache.keys().take(drop_n).copied().collect();
                for k in stale {
                    self.flow_cache.remove(&k);
                }
            }
            let cls = Self::classify_ports(parsed.proto, parsed.src_port, parsed.dst_port);
            self.flow_cache.insert(key, cls);
            return cls;
        }

        TrafficClass::Other
    }

    /// 供串流管線使用的完整解析 (含 TCP FIN/RST 偵測)
    pub fn parse(&self, packet: &[u8]) -> Option<ParsedPacket> {
        Self::parse_packet(packet)
    }

    /// 根據 Layer 4 埠號判定 HTTP / HTTPS / Other
    pub fn classify_ports(proto: u8, src_port: u16, dst_port: u16) -> TrafficClass {
        if proto != 6 {
            return TrafficClass::Other;
        }
        if src_port == 80 || dst_port == 80 {
            TrafficClass::Http
        } else if src_port == 443 || dst_port == 443 {
            TrafficClass::Https
        } else {
            TrafficClass::Other
        }
    }

    /// 解析 Raw IP 封包 → 傳輸層資訊
    pub fn parse_packet(packet: &[u8]) -> Option<ParsedPacket> {
        if packet.len() < 1 {
            return None;
        }
        match packet[0] >> 4 {
            4 => Self::parse_ipv4(packet),
            6 => Self::parse_ipv6(packet),
            _ => None,
        }
    }

    /// IPv4: 標頭 20~60 bytes，TCP/UDP 埠位於 IHL*4 偏移
    fn parse_ipv4(packet: &[u8]) -> Option<ParsedPacket> {
        if packet.len() < 20 {
            return None;
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if ihl < 20 || packet.len() < ihl + 4 {
            return None;
        }
        let proto = packet[9];
        let src_addr = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]) as u128;
        let dst_addr = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]) as u128;
        if proto != 6 && proto != 17 {
            // 僅解析 TCP / UDP，其餘 (ICMP=1, GRE=47...) 直接視為 Other
            return Some(ParsedPacket {
                version: IpVersion::V4,
                proto,
                src_addr,
                dst_addr,
                src_port: 0,
                dst_port: 0,
                tcp_flow_end: false,
            });
        }
        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

        let tcp_flow_end = if proto == 6 {
            // TCP: Flags 位於 13th byte (data offset 後的相對偏移 13)
            let flags_offset = ihl + 13;
            if flags_offset < packet.len() {
                let flags = packet[flags_offset];
                (flags & 0x01) != 0 || (flags & 0x04) != 0 // FIN=0x01, RST=0x04
            } else {
                false
            }
        } else {
            false
        };

        Some(ParsedPacket {
            version: IpVersion::V4,
            proto,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            tcp_flow_end,
        })
    }

    /// IPv6: 固定標頭 40 bytes，Next Header 位於 byte 6
    fn parse_ipv6(packet: &[u8]) -> Option<ParsedPacket> {
        if packet.len() < 40 {
            return None;
        }
        let next_header = packet[6];
        let mut src_b = [0u8; 16];
        let mut dst_b = [0u8; 16];
        src_b.copy_from_slice(&packet[8..24]);
        dst_b.copy_from_slice(&packet[24..40]);
        let src_addr = u128::from_be_bytes(src_b);
        let dst_addr = u128::from_be_bytes(dst_b);
        // 只直接處理 TCP/UDP；若含擴充標頭 (0,43,44,51,60...) 則暫時視為 Other
        let proto = match next_header {
            6 | 17 => next_header,
            _ => 0u8,
        };
        if proto == 0 {
            return Some(ParsedPacket {
                version: IpVersion::V6,
                proto: next_header,
                src_addr,
                dst_addr,
                src_port: 0,
                dst_port: 0,
                tcp_flow_end: false,
            });
        }
        let src_port = u16::from_be_bytes([packet[40], packet[41]]);
        let dst_port = u16::from_be_bytes([packet[42], packet[43]]);

        let tcp_flow_end = if proto == 6 {
            let flags_offset = 40 + 13;
            if flags_offset < packet.len() {
                let flags = packet[flags_offset];
                (flags & 0x01) != 0 || (flags & 0x04) != 0
            } else {
                false
            }
        } else {
            false
        };

        Some(ParsedPacket {
            version: IpVersion::V6,
            proto,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            tcp_flow_end,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建立 IPv4 TCP 封包 (src_port, dst_port, flags)
    fn build_tcp_ipv4(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 34]; // 20 IP + 14 TCP
        pkt[0] = 0x45; // IPv4 + IHL=5
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP protocol
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1; // src 10.0.0.1
        pkt[16] = 203;
        pkt[17] = 0;
        pkt[18] = 113;
        pkt[19] = 12; // dst 203.0.113.12
        pkt[20] = (src_port >> 8) as u8;
        pkt[21] = (src_port & 0xFF) as u8;
        pkt[22] = (dst_port >> 8) as u8;
        pkt[23] = (dst_port & 0xFF) as u8;
        pkt[32] = 0x50; // Data Offset=5 (4bits) + reserved
        pkt[33] = flags; // TCP Flags
        pkt
    }

    #[test]
    fn test_http_classify() {
        let mut classifier = TrafficClassifier::new(64);
        let pkt = build_tcp_ipv4(49152, 80, 0);
        assert_eq!(classifier.classify(&pkt), TrafficClass::Http);
    }

    #[test]
    fn test_https_classify() {
        let mut classifier = TrafficClassifier::new(64);
        let pkt = build_tcp_ipv4(443, 49152, 0);
        assert_eq!(classifier.classify(&pkt), TrafficClass::Https);
    }

    #[test]
    fn test_other_udp() {
        let mut classifier = TrafficClassifier::new(64);
        // UDP: proto 17
        let mut pkt = build_tcp_ipv4(49152, 53, 0);
        pkt[9] = 17;
        assert_eq!(classifier.classify(&pkt), TrafficClass::Other);
    }

    #[test]
    fn test_tcp_fin_detection() {
        let fin_pkt = build_tcp_ipv4(50000, 80, 0x01); // FIN
        let parsed = TrafficClassifier::parse_packet(&fin_pkt).unwrap();
        assert!(parsed.tcp_flow_end);

        let rst_pkt = build_tcp_ipv4(50000, 80, 0x04); // RST
        let parsed = TrafficClassifier::parse_packet(&rst_pkt).unwrap();
        assert!(parsed.tcp_flow_end);

        let normal_pkt = build_tcp_ipv4(50000, 80, 0x18); // PSH+ACK
        let parsed = TrafficClassifier::parse_packet(&normal_pkt).unwrap();
        assert!(!parsed.tcp_flow_end);
    }

    #[test]
    fn test_non_ipv4() {
        // 版本=0 → 無法解析
        let mut classifier = TrafficClassifier::new(64);
        assert_eq!(classifier.classify(&[0u8; 4]), TrafficClass::Other);
    }
}
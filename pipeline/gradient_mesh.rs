use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 反向梯度回傳封包 (8-Byte Compact Packet)
/// 依據架構設計：[2-Byte NodeID] + [2-Byte Loss Gradient (f16/Fixed-Point)] + [2-Byte Queue Pressure] + [2-Byte Reserved/Checksum]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GradientFeedbackPacket {
    pub node_id: u16,
    /// 縮放整數表示的梯度值 (固定點數: 實際值 * 1000)
    pub loss_gradient: i16,
    /// 緩衝區壓力 (0 ~ 1000 代表 0.0% ~ 100.0%)
    pub queue_pressure: u16,
    pub reserved: u16,
}

impl GradientFeedbackPacket {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&self.node_id.to_be_bytes());
        buf[2..4].copy_from_slice(&self.loss_gradient.to_be_bytes());
        buf[4..6].copy_from_slice(&self.queue_pressure.to_be_bytes());
        buf[6..8].copy_from_slice(&self.reserved.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        Some(Self {
            node_id: u16::from_be_bytes([bytes[0], bytes[1]]),
            loss_gradient: i16::from_be_bytes([bytes[2], bytes[3]]),
            queue_pressure: u16::from_be_bytes([bytes[4], bytes[5]]),
            reserved: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}

/// Mesh 節點鏈路狀態與路由權重
#[derive(Debug, Clone)]
pub struct MeshPeerState {
    pub addr: SocketAddr,
    pub node_id: u16,
    /// 路由轉發權重 (初始值 1.0)
    pub weight: f32,
    /// 當前鏈路估算之損失值
    pub current_loss: f32,
    /// 冗餘乘數 (Redundancy factor，根據梯度動態調節)
    pub redundancy_factor: f32,
}

/// 去中心化 P2P 網格與梯度流量控制引擎
#[derive(Clone)]
pub struct GradientMeshEngine {
    local_node_id: u16,
    /// 損失函數超參數 α (Rank 缺損損失權重) 與 β (佇列壓力權重)
    alpha: f32,
    beta: f32,
    /// SGD 學習率 (Learning Rate)
    learning_rate: f32,
    /// P2P 鄰居節點狀態表
    peers: Arc<RwLock<HashMap<u16, MeshPeerState>>>,
}

impl GradientMeshEngine {
    pub fn new(local_node_id: u16, alpha: f32, beta: f32, learning_rate: f32) -> Self {
        Self {
            local_node_id,
            alpha: if alpha <= 0.0 { 0.7 } else { alpha },
            beta: if beta <= 0.0 { 0.3 } else { beta },
            learning_rate: if learning_rate <= 0.0 { 0.05 } else { learning_rate },
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 註冊或更新鄰居節點
    pub async fn register_peer(&self, node_id: u16, addr: SocketAddr) {
        let mut peers = self.peers.write().await;
        peers.entry(node_id).or_insert(MeshPeerState {
            addr,
            node_id,
            weight: 1.0,
            current_loss: 0.0,
            redundancy_factor: 1.1, // 預設 10% 冗餘
        });
    }

    /// 移除失效節點
    pub async fn unregister_peer(&self, node_id: u16) {
        let mut peers = self.peers.write().await;
        peers.remove(&node_id);
    }

    /// 下游節點計算反向損失梯度並生成 8-Byte 反饋包:
    /// 損失函數：
    /// $$L = \alpha \cdot (1 - RankRatio)^2 + \beta \cdot QueuePressure$$
    /// 梯度近似 (對缺損率之導數)：
    /// $$\nabla L = 2 \cdot \alpha \cdot (1 - RankRatio) \cdot (-1) + \beta \cdot \Delta Queue$$
    pub fn calculate_gradient_feedback(
        &self,
        rank_ratio: f32, // 當前解碼 Rank 達成率 (0.0 ~ 1.0)
        queue_pressure: f32, // 佇列填滿率 (0.0 ~ 1.0)
    ) -> GradientFeedbackPacket {
        let clamped_rank = rank_ratio.clamp(0.0, 1.0);
        let clamped_queue = queue_pressure.clamp(0.0, 1.0);

        // 計算損失 L
        let rank_defect = 1.0 - clamped_rank;
        let loss = self.alpha * rank_defect * rank_defect + self.beta * clamped_queue;

        // 計算梯度 ∇L
        let grad = -2.0 * self.alpha * rank_defect + self.beta * clamped_queue;
        let fixed_grad = (grad * 1000.0).clamp(i16::MIN as f32, i16::MAX as f32) as i16;
        let fixed_queue = (clamped_queue * 1000.0).clamp(0.0, 1000.0) as u16;

        GradientFeedbackPacket {
            node_id: self.local_node_id,
            loss_gradient: fixed_grad,
            queue_pressure: fixed_queue,
            reserved: (loss * 1000.0).min(u16::MAX as f32) as u16,
        }
    }

    /// 上游節點接收 8-Byte 反向梯度封包，使用隨機梯度下降 (SGD) 更新轉發路徑權重與冗餘比
    pub async fn apply_gradient_feedback(&self, feedback: &GradientFeedbackPacket) {
        let mut peers = self.peers.write().await;
        if let Some(peer) = peers.get_mut(&feedback.node_id) {
            let grad_val = (feedback.loss_gradient as f32) / 1000.0;
            let queue_ratio = (feedback.queue_pressure as f32) / 1000.0;

            // 1. SGD 權重更新: 梯度越大 (損失增加)，權重越降低，自適應繞路
            peer.weight -= self.learning_rate * grad_val;
            // 權重限制在 [0.05, 5.0] 區間避免路徑餓死或失控
            peer.weight = peer.weight.clamp(0.05, 5.0);

            // 2. 動態調節噴泉碼冗餘度 (Redundancy Factor):
            // 若 Queue 壓力高但 Rank Ratio 不足，提高冗餘填補丟包；若 Queue 即將滿載則適度節流
            if queue_ratio > 0.8 {
                peer.redundancy_factor = (peer.redundancy_factor * 0.95).max(1.0);
            } else if grad_val < 0.0 {
                // grad_val < 0 表示 rank_defect 偏大，需增加噴泉切片補充
                peer.redundancy_factor = (peer.redundancy_factor + 0.05).min(2.0);
            }

            peer.current_loss = (feedback.reserved as f32) / 1000.0;
        }
    }

    /// 根據當前各節點 SGD 權重進行加權路徑選擇 (Softmax / Weighted Selection)
    pub async fn select_best_forward_peer(&self) -> Option<(u16, SocketAddr, f32)> {
        let peers = self.peers.read().await;
        if peers.is_empty() {
            return None;
        }

        // 挑選權重最高之節點
        peers
            .values()
            .max_by(|a, b| a.weight.partial_cmp(&b.weight).unwrap())
            .map(|peer| (peer.node_id, peer.addr, peer.redundancy_factor))
    }

    /// 取得指定 Peer 的當前狀態快照
    pub async fn get_peer_state(&self, node_id: u16) -> Option<MeshPeerState> {
        let peers = self.peers.read().await;
        peers.get(&node_id).cloned()
    }
}

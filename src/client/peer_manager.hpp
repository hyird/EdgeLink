#pragma once

#include "common/types.hpp"
#include "client/crypto_engine.hpp"
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace edgelink::client {

// 简化的 Peer 结构 - 只包含基本信息和会话密钥状态
// 连接状态（P2PConnectionState, PeerDataPath）由 ClientStateMachine 管理
struct Peer {
    PeerInfo info;                      // 基本信息（从 Controller 获取）
    bool session_key_derived = false;   // 是否已派生会话密钥
    uint64_t last_seen = 0;             // 最后活跃时间（毫秒时间戳）
};

// Peer 管理器 - 负责管理对端信息和会话密钥
// 注意：连接状态管理已移至 ClientStateMachine
class PeerManager {
public:
    explicit PeerManager(CryptoEngine& crypto);

    // ========================================================================
    // Peer 管理
    // ========================================================================

    // 从 CONFIG 消息更新所有 peer（清空现有数据）
    void update_from_config(const std::vector<PeerInfo>& peers);

    // 从 CONFIG_UPDATE 消息增量更新
    void add_peer(const PeerInfo& peer);
    void remove_peer(NodeId peer_id);
    void update_peer_online(NodeId peer_id, bool online);

    // 获取 peer 信息
    std::optional<Peer> get_peer(NodeId peer_id) const;
    std::vector<Peer> get_all_peers() const;
    std::vector<Peer> get_online_peers() const;

    // 通过虚拟 IP 查找 peer
    std::optional<Peer> get_peer_by_ip(const IPv4Address& ip) const;

    // 获取 peer IP 字符串（用于日志）
    std::string get_peer_ip_str(NodeId peer_id) const;

    // 检查 peer 是否存在
    bool has_peer(NodeId peer_id) const;

    // 获取 peer 的 node_key（用于 P2P 加密）
    std::optional<std::array<uint8_t, X25519_KEY_SIZE>> get_peer_node_key(NodeId peer_id) const;

    // ========================================================================
    // 会话密钥管理
    // ========================================================================

    // 确保已为 peer 派生会话密钥（懒加载）
    bool ensure_session_key(NodeId peer_id);

    // 检查是否已派生会话密钥
    bool has_session_key(NodeId peer_id) const;

    // ========================================================================
    // 活跃时间
    // ========================================================================

    // 更新最后活跃时间
    void update_last_seen(NodeId peer_id);

    // ========================================================================
    // 统计
    // ========================================================================

    size_t peer_count() const;
    size_t online_peer_count() const;

private:
    CryptoEngine& crypto_;

    mutable std::shared_mutex mutex_;
    std::unordered_map<NodeId, Peer> peers_;

    // 虚拟 IP 到 NodeId 的映射（快速查找）
    std::unordered_map<uint32_t, NodeId> ip_to_node_;
};

} // namespace edgelink::client

#pragma once

#include "common/types.hpp"
#include "common/message.hpp"
#include <unordered_map>
#include <shared_mutex>
#include <optional>

namespace edgelink::client {

// 单个 Peer 的路由信息
struct PeerRoute {
    NodeId peer_node_id = 0;           // 目标节点 ID
    ServerId relay_id = 0;             // 使用的 Relay ID (0 = P2P 直连)
    ConnectionId connection_id = 0;    // 使用的连接 ID
    uint8_t priority = 0;              // 优先级 (0 = 最高)
    uint64_t update_time = 0;          // 更新时间
};

// ============================================================================
// PeerRoutingTable - 存储每个 Peer 的最优路径
// ============================================================================

class PeerRoutingTable {
public:
    PeerRoutingTable() = default;

    // 更新路由表（收到 PEER_ROUTING_UPDATE 时调用）
    void update(const PeerRoutingUpdate& update);

    // 获取到指定 Peer 的路由
    std::optional<PeerRoute> get_route(NodeId peer_id) const;

    // 获取所有路由
    std::vector<PeerRoute> all_routes() const;

    // 清空路由表
    void clear();

    // 当前版本号
    uint64_t version() const { return version_; }

    // 路由数量
    size_t size() const;

    // 检查是否有到指定 Peer 的路由
    bool has_route(NodeId peer_id) const;

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<NodeId, PeerRoute> routes_;
    uint64_t version_ = 0;
};

} // namespace edgelink::client

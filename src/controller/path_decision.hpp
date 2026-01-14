#pragma once

#include "common/types.hpp"
#include "common/message.hpp"
#include <map>
#include <tuple>
#include <shared_mutex>
#include <chrono>
#include <optional>
#include <functional>

namespace edgelink::controller {

// 延迟矩阵条目
struct LatencyMatrixEntry {
    uint16_t latency_ms = 0;        // 延迟毫秒数
    uint8_t packet_loss = 0;        // 丢包率
    uint64_t last_update = 0;       // 最后更新时间
    uint32_t sample_count = 0;      // 样本数量
};

// 路径选择结果
struct PathDecision {
    ServerId relay_id = 0;
    ConnectionId connection_id = 0;
    uint16_t estimated_latency = 0;
    std::string reason;
};

// ============================================================================
// PathDecisionEngine - Controller 端路径决策引擎
// ============================================================================

class PathDecisionEngine {
public:
    using RoutingUpdateCallback = std::function<void(NodeId, const PeerRoutingUpdate&)>;

    PathDecisionEngine();

    // 收到 Client 上报的延迟数据
    void handle_peer_path_report(NodeId from_node, const PeerPathReport& report);

    // 为指定 Client 计算到所有 Peer 的最优路由
    PeerRoutingUpdate compute_routing_for_node(NodeId node_id);

    // 计算单个路径的最优选择
    std::optional<PathDecision> select_best_path(NodeId from, NodeId to);

    // 设置路由更新回调
    void set_routing_update_callback(RoutingUpdateCallback callback);

    // 周期性重算所有路由（如有显著变化则通知）
    void recompute_all();

    // 获取延迟数据
    std::optional<uint16_t> get_latency(NodeId from, NodeId to, ServerId relay);

    // 获取当前路由版本
    uint64_t current_version() const { return version_; }

    // 清理过期数据
    void cleanup_stale_data(std::chrono::seconds max_age);

private:
    // 计算 from → to 经过 relay 的总延迟
    uint16_t compute_path_latency(NodeId from, NodeId to, ServerId relay);

    // 生成新版本号
    uint64_t next_version();

    mutable std::shared_mutex mutex_;

    // 延迟矩阵: (from_node, to_peer, relay_id) -> latency
    std::map<std::tuple<NodeId, NodeId, ServerId>, LatencyMatrixEntry> latency_matrix_;

    // 当前每个节点的路由表
    std::map<NodeId, PeerRoutingUpdate> node_routing_;

    // 版本号
    uint64_t version_ = 0;

    // 回调
    RoutingUpdateCallback routing_callback_;
};

} // namespace edgelink::controller

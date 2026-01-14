#include "controller/path_decision.hpp"
#include "common/log.hpp"
#include <algorithm>
#include <set>

namespace edgelink::controller {

namespace {
spdlog::logger& log() {
    static auto logger = edgelink::create_logger("path_decision");
    return *logger;
}
} // anonymous namespace

PathDecisionEngine::PathDecisionEngine() = default;

void PathDecisionEngine::handle_peer_path_report(
    NodeId from_node, const PeerPathReport& report) {

    log().debug("Received PEER_PATH_REPORT from node {}: {} entries",
                from_node, report.entries.size());

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::unique_lock lock(mutex_);

    for (const auto& entry : report.entries) {
        auto key = std::make_tuple(from_node, entry.peer_node_id, entry.relay_id);

        auto& matrix_entry = latency_matrix_[key];
        matrix_entry.last_update = now;
        matrix_entry.sample_count++;
        matrix_entry.packet_loss = entry.packet_loss;

        // 使用指数移动平均
        if (matrix_entry.latency_ms == 0) {
            matrix_entry.latency_ms = entry.latency_ms;
        } else {
            matrix_entry.latency_ms = (matrix_entry.latency_ms * 7 + entry.latency_ms) / 8;
        }

        log().trace("Updated latency: {} -> {} via relay {}: {}ms",
                    from_node, entry.peer_node_id, entry.relay_id,
                    matrix_entry.latency_ms);
    }
}

PeerRoutingUpdate PathDecisionEngine::compute_routing_for_node(NodeId node_id) {
    std::shared_lock lock(mutex_);

    PeerRoutingUpdate update;
    update.version = next_version();

    // 收集该节点可达的所有 Peer
    std::set<NodeId> peers;
    for (const auto& [key, entry] : latency_matrix_) {
        if (std::get<0>(key) == node_id) {
            peers.insert(std::get<1>(key));
        }
    }

    // 为每个 Peer 选择最优路径
    for (NodeId peer_id : peers) {
        auto decision = select_best_path(node_id, peer_id);
        if (decision) {
            PeerRoutingEntry route;
            route.peer_node_id = peer_id;
            route.relay_id = decision->relay_id;
            route.connection_id = decision->connection_id;
            route.priority = 0;  // 最高优先级

            update.routes.push_back(route);

            log().debug("Route for {} -> {}: relay={}, latency={}ms ({})",
                        node_id, peer_id, decision->relay_id,
                        decision->estimated_latency, decision->reason);
        }
    }

    log().info("Computed routing for node {}: {} routes, version {}",
               node_id, update.routes.size(), update.version);

    return update;
}

std::optional<PathDecision> PathDecisionEngine::select_best_path(
    NodeId from, NodeId to) {

    // 注意：调用者需要持有锁

    PathDecision best;
    best.estimated_latency = UINT16_MAX;

    // 收集该路径的所有 Relay 选项
    for (const auto& [key, entry] : latency_matrix_) {
        if (std::get<0>(key) == from && std::get<1>(key) == to) {
            ServerId relay_id = std::get<2>(key);

            // 简单实现：直接使用上报的延迟
            // 完整实现应该计算 from→relay + relay→to 的总延迟
            uint16_t latency = entry.latency_ms;

            if (latency < best.estimated_latency) {
                best.relay_id = relay_id;
                best.estimated_latency = latency;
                best.reason = fmt::format("lowest latency via relay {}", relay_id);
            }
        }
    }

    if (best.estimated_latency == UINT16_MAX) {
        return std::nullopt;
    }

    return best;
}

void PathDecisionEngine::set_routing_update_callback(RoutingUpdateCallback callback) {
    routing_callback_ = std::move(callback);
}

void PathDecisionEngine::recompute_all() {
    std::set<NodeId> all_nodes;

    {
        std::shared_lock lock(mutex_);
        for (const auto& [key, entry] : latency_matrix_) {
            all_nodes.insert(std::get<0>(key));
        }
    }

    log().info("Recomputing routes for {} node(s)", all_nodes.size());

    for (NodeId node_id : all_nodes) {
        auto update = compute_routing_for_node(node_id);

        // 检查是否有变化
        bool changed = false;
        {
            std::shared_lock lock(mutex_);
            auto it = node_routing_.find(node_id);
            if (it == node_routing_.end() ||
                it->second.routes.size() != update.routes.size()) {
                changed = true;
            }
        }

        if (changed && routing_callback_) {
            routing_callback_(node_id, update);
        }

        // 更新缓存
        {
            std::unique_lock lock(mutex_);
            node_routing_[node_id] = update;
        }
    }
}

std::optional<uint16_t> PathDecisionEngine::get_latency(
    NodeId from, NodeId to, ServerId relay) {

    std::shared_lock lock(mutex_);
    auto key = std::make_tuple(from, to, relay);
    auto it = latency_matrix_.find(key);
    if (it != latency_matrix_.end()) {
        return it->second.latency_ms;
    }
    return std::nullopt;
}

void PathDecisionEngine::cleanup_stale_data(std::chrono::seconds max_age) {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto threshold = now - std::chrono::duration_cast<std::chrono::milliseconds>(
        max_age).count();

    std::unique_lock lock(mutex_);

    size_t removed = 0;
    for (auto it = latency_matrix_.begin(); it != latency_matrix_.end();) {
        if (it->second.last_update < static_cast<uint64_t>(threshold)) {
            it = latency_matrix_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    if (removed > 0) {
        log().info("Cleaned up {} stale latency entries", removed);
    }
}

uint16_t PathDecisionEngine::compute_path_latency(
    NodeId from, NodeId to, ServerId relay) {

    // 简单实现：直接查找
    auto key = std::make_tuple(from, to, relay);
    auto it = latency_matrix_.find(key);
    if (it != latency_matrix_.end()) {
        return it->second.latency_ms;
    }

    // 完整实现：计算 from→relay + relay→to
    // 需要有 relay 的位置信息和 to 节点到 relay 的延迟
    return UINT16_MAX;
}

uint64_t PathDecisionEngine::next_version() {
    return ++version_;
}

} // namespace edgelink::controller

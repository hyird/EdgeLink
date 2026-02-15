#include "controller/path_decision.hpp"
#include "common/logger.hpp"
#include "common/math_utils.hpp"
#include <algorithm>
#include <format>
#include <set>

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.path_decision"); }
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
        // 使用指数移动平均更新延迟
        matrix_entry.latency_ms = exponential_moving_average(matrix_entry.latency_ms, entry.latency_ms);

        log().trace("Updated latency: {} -> {} via relay {}: {}ms",
                    from_node, entry.peer_node_id, entry.relay_id,
                    matrix_entry.latency_ms);
    }
}

void PathDecisionEngine::handle_relay_latency_report(
    NodeId from_node, const RelayLatencyReport& report) {

    log().debug("Received RELAY_LATENCY_REPORT from node {}: {} entries",
                from_node, report.entries.size());

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::unique_lock lock(mutex_);

    for (const auto& entry : report.entries) {
        auto key = std::make_pair(from_node, entry.relay_id);

        auto& latency_entry = node_relay_latencies_[key];
        latency_entry.last_update = now;
        latency_entry.sample_count++;
        latency_entry.packet_loss = entry.packet_loss;

        // 使用指数移动平均
        latency_entry.latency_ms = exponential_moving_average(latency_entry.latency_ms, entry.latency_ms);

        log().info("Updated node-relay latency: node {} -> relay {}: {}ms",
                   from_node, entry.relay_id, latency_entry.latency_ms);
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

    // 收集所有可能的 Relay（从 node_relay_latencies_ 中获取）
    std::set<ServerId> all_relays;
    for (const auto& [key, entry] : node_relay_latencies_) {
        all_relays.insert(key.second);
    }

    // 对每个 Relay，计算 from→relay + to→relay 的总延迟
    for (ServerId relay_id : all_relays) {
        uint16_t latency = compute_path_latency(from, to, relay_id);

        if (latency < best.estimated_latency) {
            best.relay_id = relay_id;
            best.estimated_latency = latency;
            best.reason = std::format("A+B RTT via relay {} ({}ms)", relay_id, latency);
        }
    }

    // 如果没有 relay 延迟数据，回退到使用端到端延迟
    if (best.estimated_latency == UINT16_MAX) {
        for (const auto& [key, entry] : latency_matrix_) {
            if (std::get<0>(key) == from && std::get<1>(key) == to) {
                ServerId relay_id = std::get<2>(key);
                uint16_t latency = entry.latency_ms;

                if (latency < best.estimated_latency) {
                    best.relay_id = relay_id;
                    best.estimated_latency = latency;
                    best.reason = std::format("e2e latency via relay {} ({}ms)", relay_id, latency);
                }
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

    // 清理 latency_matrix_
    for (auto it = latency_matrix_.begin(); it != latency_matrix_.end();) {
        if (it->second.last_update < static_cast<uint64_t>(threshold)) {
            it = latency_matrix_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }

    // 清理 node_relay_latencies_
    for (auto it = node_relay_latencies_.begin(); it != node_relay_latencies_.end();) {
        if (it->second.last_update < static_cast<uint64_t>(threshold)) {
            it = node_relay_latencies_.erase(it);
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

    // 使用 node_relay_latencies_ 计算 from→relay + to→relay 的总延迟
    auto from_key = std::make_pair(from, relay);
    auto to_key = std::make_pair(to, relay);

    auto from_it = node_relay_latencies_.find(from_key);
    auto to_it = node_relay_latencies_.find(to_key);

    if (from_it != node_relay_latencies_.end() && to_it != node_relay_latencies_.end()) {
        // 两端都有到这个 Relay 的延迟数据
        uint32_t total = static_cast<uint32_t>(from_it->second.latency_ms) +
                         static_cast<uint32_t>(to_it->second.latency_ms);
        return static_cast<uint16_t>(std::min(total, static_cast<uint32_t>(UINT16_MAX)));
    }

    // 回退到端到端延迟
    auto e2e_key = std::make_tuple(from, to, relay);
    auto e2e_it = latency_matrix_.find(e2e_key);
    if (e2e_it != latency_matrix_.end()) {
        return e2e_it->second.latency_ms;
    }

    return UINT16_MAX;
}

uint64_t PathDecisionEngine::next_version() {
    return ++version_;
}

} // namespace edgelink::controller

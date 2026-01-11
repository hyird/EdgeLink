#include "common/node_state.hpp"
#include "common/logger.hpp"
#include <algorithm>
#include <chrono>

namespace edgelink {

namespace {
auto& log() { return Logger::get("node_state"); }
} // anonymous namespace

// ============================================================================
// 状态名称转换
// ============================================================================

const char* node_role_name(NodeRole role) {
    switch (role) {
        case NodeRole::CLIENT: return "CLIENT";
        case NodeRole::CONTROLLER: return "CONTROLLER";
        case NodeRole::RELAY: return "RELAY";
        default: return "UNKNOWN";
    }
}

const char* node_connection_state_name(NodeConnectionState state) {
    switch (state) {
        case NodeConnectionState::OFFLINE: return "OFFLINE";
        case NodeConnectionState::CONNECTING: return "CONNECTING";
        case NodeConnectionState::AUTHENTICATING: return "AUTHENTICATING";
        case NodeConnectionState::ONLINE: return "ONLINE";
        case NodeConnectionState::DEGRADED: return "DEGRADED";
        case NodeConnectionState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* data_channel_state_name(DataChannelState state) {
    switch (state) {
        case DataChannelState::NONE: return "NONE";
        case DataChannelState::RELAY_ONLY: return "RELAY_ONLY";
        case DataChannelState::P2P_ONLY: return "P2P_ONLY";
        case DataChannelState::HYBRID: return "HYBRID";
        default: return "UNKNOWN";
    }
}

const char* p2p_connection_state_name(P2PConnectionState state) {
    switch (state) {
        case P2PConnectionState::NONE: return "NONE";
        case P2PConnectionState::INITIATING: return "INITIATING";
        case P2PConnectionState::WAITING_ENDPOINT: return "WAITING_ENDPOINT";
        case P2PConnectionState::PUNCHING: return "PUNCHING";
        case P2PConnectionState::CONNECTED: return "CONNECTED";
        case P2PConnectionState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

const char* node_event_name(NodeEvent event) {
    switch (event) {
        case NodeEvent::CONNECT: return "CONNECT";
        case NodeEvent::DISCONNECT: return "DISCONNECT";
        case NodeEvent::AUTH_SUCCESS: return "AUTH_SUCCESS";
        case NodeEvent::AUTH_FAILED: return "AUTH_FAILED";
        case NodeEvent::RELAY_CONNECTED: return "RELAY_CONNECTED";
        case NodeEvent::RELAY_DISCONNECTED: return "RELAY_DISCONNECTED";
        case NodeEvent::P2P_CONNECTED: return "P2P_CONNECTED";
        case NodeEvent::P2P_DISCONNECTED: return "P2P_DISCONNECTED";
        case NodeEvent::ENDPOINT_UPDATE: return "ENDPOINT_UPDATE";
        case NodeEvent::ENDPOINT_SYNCED: return "ENDPOINT_SYNCED";
        case NodeEvent::ROUTE_ANNOUNCE: return "ROUTE_ANNOUNCE";
        case NodeEvent::ROUTE_WITHDRAW: return "ROUTE_WITHDRAW";
        case NodeEvent::P2P_INIT: return "P2P_INIT";
        case NodeEvent::P2P_ENDPOINT_RECEIVED: return "P2P_ENDPOINT_RECEIVED";
        case NodeEvent::P2P_PUNCH_START: return "P2P_PUNCH_START";
        case NodeEvent::P2P_PUNCH_SUCCESS: return "P2P_PUNCH_SUCCESS";
        case NodeEvent::P2P_PUNCH_FAILED: return "P2P_PUNCH_FAILED";
        case NodeEvent::P2P_KEEPALIVE_TIMEOUT: return "P2P_KEEPALIVE_TIMEOUT";
        case NodeEvent::PING: return "PING";
        case NodeEvent::PONG: return "PONG";
        case NodeEvent::HEARTBEAT_TIMEOUT: return "HEARTBEAT_TIMEOUT";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// NodeStateMachine 实现
// ============================================================================

NodeStateMachine::NodeStateMachine(NodeId self_id, NodeRole self_role)
    : self_id_(self_id)
    , self_role_(self_role) {
}

void NodeStateMachine::set_callbacks(NodeStateCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void NodeStateMachine::handle_event(NodeId node_id, NodeEvent event) {
    log().debug("Node {} event: {}", node_id, node_event_name(event));

    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state && event != NodeEvent::CONNECT) {
        return;
    }

    switch (event) {
        case NodeEvent::CONNECT:
            if (!state) {
                node_states_[node_id] = NodeState{.node_id = node_id};
                state = &node_states_[node_id];
            }
            state->connection_state = NodeConnectionState::CONNECTING;
            state->last_seen_time = now_us();
            break;

        case NodeEvent::DISCONNECT:
            if (state) {
                auto old_state = state->connection_state;
                state->connection_state = NodeConnectionState::OFFLINE;
                state->data_channel = DataChannelState::NONE;
                lock.unlock();

                if (old_state != NodeConnectionState::OFFLINE) {
                    if (callbacks_.on_connection_state_change) {
                        callbacks_.on_connection_state_change(node_id, old_state, NodeConnectionState::OFFLINE);
                    }
                    if (callbacks_.on_node_status_change) {
                        callbacks_.on_node_status_change(node_id, false);
                    }
                }
            }
            return;

        case NodeEvent::AUTH_SUCCESS:
            if (state) {
                state->connection_state = NodeConnectionState::ONLINE;
                state->last_seen_time = now_us();
            }
            break;

        case NodeEvent::AUTH_FAILED:
            if (state) {
                state->connection_state = NodeConnectionState::OFFLINE;
            }
            break;

        case NodeEvent::RELAY_CONNECTED:
            if (state) {
                state->last_seen_time = now_us();
                update_data_channel_state(node_id);
            }
            break;

        case NodeEvent::RELAY_DISCONNECTED:
            if (state) {
                update_data_channel_state(node_id);
            }
            break;

        case NodeEvent::ENDPOINT_UPDATE:
            if (state) {
                state->endpoint_update_time = now_us();
            }
            break;

        case NodeEvent::ENDPOINT_SYNCED:
            if (state) {
                state->endpoint_synced = true;
            }
            break;

        case NodeEvent::PING:
            if (state) {
                state->last_ping_time = now_us();
                state->last_seen_time = now_us();
            }
            break;

        case NodeEvent::PONG:
            if (state) {
                state->last_seen_time = now_us();
            }
            break;

        case NodeEvent::HEARTBEAT_TIMEOUT:
            if (state && state->connection_state == NodeConnectionState::ONLINE) {
                state->connection_state = NodeConnectionState::DEGRADED;
            }
            break;

        default:
            break;
    }
}

void NodeStateMachine::handle_p2p_event(NodeId node_id, NodeId peer_id, NodeEvent event) {
    log().debug("Node {} P2P with {} event: {}", node_id, peer_id, node_event_name(event));

    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto& link = state->p2p_links[peer_id];
    if (link.peer_id == 0) {
        link.peer_id = peer_id;
    }

    auto old_p2p_state = link.state;

    switch (event) {
        case NodeEvent::P2P_INIT:
            if (link.state == P2PConnectionState::NONE ||
                link.state == P2PConnectionState::FAILED) {
                link.state = P2PConnectionState::INITIATING;
                link.connect_time = now_us();
            }
            break;

        case NodeEvent::P2P_ENDPOINT_RECEIVED:
            if (link.state == P2PConnectionState::INITIATING ||
                link.state == P2PConnectionState::WAITING_ENDPOINT) {
                link.state = P2PConnectionState::PUNCHING;
            }
            break;

        case NodeEvent::P2P_PUNCH_START:
            link.state = P2PConnectionState::PUNCHING;
            break;

        case NodeEvent::P2P_PUNCH_SUCCESS:
            link.state = P2PConnectionState::CONNECTED;
            link.connect_time = now_us();
            link.punch_failures = 0;
            break;

        case NodeEvent::P2P_PUNCH_FAILED:
            link.state = P2PConnectionState::FAILED;
            link.punch_failures++;
            break;

        case NodeEvent::P2P_KEEPALIVE_TIMEOUT:
            if (link.state == P2PConnectionState::CONNECTED) {
                link.state = P2PConnectionState::FAILED;
            }
            break;

        case NodeEvent::P2P_CONNECTED:
            link.state = P2PConnectionState::CONNECTED;
            link.last_recv_time = now_us();
            break;

        case NodeEvent::P2P_DISCONNECTED:
            link.state = P2PConnectionState::NONE;
            break;

        default:
            break;
    }

    // 更新数据通道状态
    update_data_channel_state(node_id);

    lock.unlock();

    // 触发回调
    if (link.state != old_p2p_state && callbacks_.on_p2p_state_change) {
        callbacks_.on_p2p_state_change(node_id, peer_id, old_p2p_state, link.state);
    }
}

// ============================================================================
// 节点管理
// ============================================================================

void NodeStateMachine::add_node(NodeId node_id, NetworkId network_id, NodeRole role) {
    std::unique_lock lock(nodes_mutex_);
    if (node_states_.find(node_id) == node_states_.end()) {
        node_states_[node_id] = NodeState{
            .node_id = node_id,
            .network_id = network_id,
            .role = role,
            .last_seen_time = now_us()
        };
        log().debug("Added node {} (network={}, role={})",
                   node_id, network_id, node_role_name(role));
    }
}

void NodeStateMachine::remove_node(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    if (it != node_states_.end()) {
        auto old_state = it->second.connection_state;
        bool was_online = it->second.is_online();
        node_states_.erase(it);
        lock.unlock();

        log().debug("Removed node {}", node_id);

        if (was_online && callbacks_.on_node_status_change) {
            callbacks_.on_node_status_change(node_id, false);
        }
    }
}

void NodeStateMachine::update_node_endpoints(NodeId node_id, const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        auto old_endpoints = state->endpoints;
        state->endpoints = endpoints;
        state->endpoint_update_time = now_us();
        lock.unlock();

        log().debug("Updated {} endpoints for node {}", endpoints.size(), node_id);

        if (callbacks_.on_endpoint_update) {
            callbacks_.on_endpoint_update(node_id, endpoints);
        }
    }
}

void NodeStateMachine::update_node_routes(NodeId node_id, const std::vector<RouteInfo>& add_routes,
                                           const std::vector<RouteInfo>& del_routes) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        // 删除路由
        for (const auto& del : del_routes) {
            state->announced_routes.erase(
                std::remove_if(state->announced_routes.begin(), state->announced_routes.end(),
                    [&del](const RouteInfo& r) {
                        return r.ip_type == del.ip_type &&
                               r.prefix == del.prefix &&
                               r.prefix_len == del.prefix_len;
                    }),
                state->announced_routes.end());
        }

        // 添加路由
        for (const auto& add : add_routes) {
            state->announced_routes.push_back(add);
        }

        state->route_update_time = now_us();
        lock.unlock();

        if (callbacks_.on_route_change && (!add_routes.empty() || !del_routes.empty())) {
            callbacks_.on_route_change(node_id, add_routes, del_routes);
        }
    }
}

void NodeStateMachine::update_node_ip(NodeId node_id, const IPv4Address& ip) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->virtual_ip = ip;
    }
}

void NodeStateMachine::update_node_latency(NodeId node_id, uint16_t latency_ms) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->latency_ms = latency_ms;
    }
}

void NodeStateMachine::record_node_activity(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->last_seen_time = now_us();
    }
}

// ============================================================================
// P2P 管理
// ============================================================================

void NodeStateMachine::initiate_p2p(NodeId peer_id, uint32_t seq) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(self_id_);
    if (!state) {
        // 如果自身状态不存在，创建一个
        node_states_[self_id_] = NodeState{.node_id = self_id_, .role = self_role_};
        state = &node_states_[self_id_];
    }

    auto& link = state->p2p_links[peer_id];
    link.peer_id = peer_id;
    link.state = P2PConnectionState::INITIATING;
    link.init_seq = seq;
    link.connect_time = now_us();
}

void NodeStateMachine::receive_peer_endpoints(NodeId peer_id, const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(self_id_);
    if (state) {
        auto& link = state->p2p_links[peer_id];
        link.peer_id = peer_id;
        link.peer_endpoints = endpoints;
        if (link.state == P2PConnectionState::INITIATING ||
            link.state == P2PConnectionState::WAITING_ENDPOINT) {
            link.state = P2PConnectionState::PUNCHING;
        }
    }
}

void NodeStateMachine::set_active_p2p_endpoint(NodeId peer_id, const Endpoint& endpoint) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(self_id_);
    if (state) {
        auto& link = state->p2p_links[peer_id];
        link.active_endpoint = endpoint;
    }
}

void NodeStateMachine::update_p2p_rtt(NodeId peer_id, uint16_t rtt_ms) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(self_id_);
    if (state) {
        auto it = state->p2p_links.find(peer_id);
        if (it != state->p2p_links.end()) {
            it->second.rtt_ms = rtt_ms;
            it->second.last_recv_time = now_us();
        }
    }
}

// ============================================================================
// 状态查询
// ============================================================================

std::optional<NodeState> NodeStateMachine::get_node_state(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    if (it != node_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<NodeId> NodeStateMachine::get_online_nodes() const {
    std::vector<NodeId> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [id, state] : node_states_) {
        if (state.is_online()) {
            result.push_back(id);
        }
    }
    return result;
}

std::vector<NodeId> NodeStateMachine::get_network_nodes(NetworkId network_id) const {
    std::vector<NodeId> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [id, state] : node_states_) {
        if (state.network_id == network_id) {
            result.push_back(id);
        }
    }
    return result;
}

std::vector<Endpoint> NodeStateMachine::get_node_endpoints(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    if (it != node_states_.end()) {
        return it->second.endpoints;
    }
    return {};
}

std::vector<RouteInfo> NodeStateMachine::get_node_routes(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    if (it != node_states_.end()) {
        return it->second.announced_routes;
    }
    return {};
}

std::vector<NodeId> NodeStateMachine::get_p2p_connected_nodes() const {
    std::vector<NodeId> result;
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(self_id_);
    if (it != node_states_.end()) {
        for (const auto& [peer_id, link] : it->second.p2p_links) {
            if (link.state == P2PConnectionState::CONNECTED) {
                result.push_back(peer_id);
            }
        }
    }
    return result;
}

std::vector<NodeId> NodeStateMachine::get_p2p_retry_nodes() const {
    std::vector<NodeId> result;
    uint64_t now = now_us();

    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(self_id_);
    if (it != node_states_.end()) {
        for (const auto& [peer_id, link] : it->second.p2p_links) {
            if (link.state == P2PConnectionState::FAILED) {
                // 检查是否到达重试时间
                if (now - link.connect_time >= p2p_retry_interval_ms_ * 1000ULL) {
                    result.push_back(peer_id);
                }
            }
        }
    }
    return result;
}

bool NodeStateMachine::is_node_online(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    return it != node_states_.end() && it->second.is_online();
}

bool NodeStateMachine::has_p2p_connection(NodeId peer_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(self_id_);
    if (it != node_states_.end()) {
        auto pit = it->second.p2p_links.find(peer_id);
        return pit != it->second.p2p_links.end() &&
               pit->second.state == P2PConnectionState::CONNECTED;
    }
    return false;
}

// ============================================================================
// 超时检测
// ============================================================================

void NodeStateMachine::check_timeouts() {
    uint64_t now = now_us();
    std::vector<std::pair<NodeId, NodeEvent>> events;
    std::vector<std::tuple<NodeId, NodeId, NodeEvent>> p2p_events;

    {
        std::shared_lock lock(nodes_mutex_);

        for (const auto& [node_id, state] : node_states_) {
            // 心跳超时检测
            if (state.is_online() && state.last_seen_time > 0) {
                if (now - state.last_seen_time > heartbeat_timeout_ms_ * 1000ULL) {
                    events.emplace_back(node_id, NodeEvent::HEARTBEAT_TIMEOUT);
                }
            }

            // P2P 超时检测
            for (const auto& [peer_id, link] : state.p2p_links) {
                switch (link.state) {
                    case P2PConnectionState::INITIATING:
                    case P2PConnectionState::WAITING_ENDPOINT:
                    case P2PConnectionState::PUNCHING:
                        if (link.connect_time > 0 &&
                            now - link.connect_time > p2p_punch_timeout_ms_ * 1000ULL) {
                            p2p_events.emplace_back(node_id, peer_id, NodeEvent::P2P_PUNCH_FAILED);
                        }
                        break;

                    case P2PConnectionState::CONNECTED:
                        if (link.last_recv_time > 0 &&
                            now - link.last_recv_time > p2p_keepalive_timeout_ms_ * 1000ULL) {
                            p2p_events.emplace_back(node_id, peer_id, NodeEvent::P2P_KEEPALIVE_TIMEOUT);
                        }
                        break;

                    default:
                        break;
                }
            }
        }
    }

    // 处理事件（在锁外）
    for (const auto& [node_id, event] : events) {
        handle_event(node_id, event);
    }

    for (const auto& [node_id, peer_id, event] : p2p_events) {
        handle_p2p_event(node_id, peer_id, event);
    }
}

uint64_t NodeStateMachine::now_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

// ============================================================================
// 重置
// ============================================================================

void NodeStateMachine::reset() {
    std::unique_lock lock(nodes_mutex_);
    node_states_.clear();
    log().info("Node state machine reset");
}

// ============================================================================
// 内部方法
// ============================================================================

void NodeStateMachine::set_connection_state(NodeId node_id, NodeConnectionState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->connection_state;
    if (old_state != new_state) {
        state->connection_state = new_state;
        lock.unlock();

        log().info("Node {} connection: {} -> {}",
                   node_id,
                   node_connection_state_name(old_state),
                   node_connection_state_name(new_state));

        if (callbacks_.on_connection_state_change) {
            callbacks_.on_connection_state_change(node_id, old_state, new_state);
        }

        // 节点上线/下线通知
        bool was_online = (old_state == NodeConnectionState::ONLINE ||
                           old_state == NodeConnectionState::DEGRADED);
        bool is_online = (new_state == NodeConnectionState::ONLINE ||
                          new_state == NodeConnectionState::DEGRADED);

        if (was_online != is_online && callbacks_.on_node_status_change) {
            callbacks_.on_node_status_change(node_id, is_online);
        }
    }
}

void NodeStateMachine::set_data_channel_state(NodeId node_id, DataChannelState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->data_channel;
    if (old_state != new_state) {
        state->data_channel = new_state;
        lock.unlock();

        log().debug("Node {} data channel: {} -> {}",
                   node_id,
                   data_channel_state_name(old_state),
                   data_channel_state_name(new_state));

        if (callbacks_.on_data_channel_change) {
            callbacks_.on_data_channel_change(node_id, old_state, new_state);
        }
    }
}

void NodeStateMachine::set_p2p_state(NodeId node_id, NodeId peer_id, P2PConnectionState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto& link = state->p2p_links[peer_id];
    auto old_state = link.state;
    if (old_state != new_state) {
        link.state = new_state;
        lock.unlock();

        log().info("Node {} P2P with {}: {} -> {}",
                   node_id, peer_id,
                   p2p_connection_state_name(old_state),
                   p2p_connection_state_name(new_state));

        if (callbacks_.on_p2p_state_change) {
            callbacks_.on_p2p_state_change(node_id, peer_id, old_state, new_state);
        }
    }
}

void NodeStateMachine::update_data_channel_state(NodeId node_id) {
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    bool has_relay = state->connection_state == NodeConnectionState::ONLINE;
    bool has_p2p = false;

    for (const auto& [peer_id, link] : state->p2p_links) {
        if (link.state == P2PConnectionState::CONNECTED) {
            has_p2p = true;
            break;
        }
    }

    DataChannelState new_channel;
    if (has_relay && has_p2p) {
        new_channel = DataChannelState::HYBRID;
    } else if (has_relay) {
        new_channel = DataChannelState::RELAY_ONLY;
    } else if (has_p2p) {
        new_channel = DataChannelState::P2P_ONLY;
    } else {
        new_channel = DataChannelState::NONE;
    }

    if (state->data_channel != new_channel) {
        auto old_channel = state->data_channel;
        state->data_channel = new_channel;

        if (callbacks_.on_data_channel_change) {
            callbacks_.on_data_channel_change(node_id, old_channel, new_channel);
        }
    }
}

NodeState* NodeStateMachine::get_node_state_mut(NodeId node_id) {
    auto it = node_states_.find(node_id);
    if (it != node_states_.end()) {
        return &it->second;
    }
    return nullptr;
}

} // namespace edgelink

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
        case NodeEvent::START_CONNECT: return "START_CONNECT";
        case NodeEvent::CONTROL_CONNECTED: return "CONTROL_CONNECTED";
        case NodeEvent::CONTROL_DISCONNECTED: return "CONTROL_DISCONNECTED";
        case NodeEvent::AUTH_REQUEST: return "AUTH_REQUEST";
        case NodeEvent::AUTH_SUCCESS: return "AUTH_SUCCESS";
        case NodeEvent::AUTH_FAILED: return "AUTH_FAILED";
        case NodeEvent::CONFIG_SENT: return "CONFIG_SENT";
        case NodeEvent::CONFIG_RECEIVED: return "CONFIG_RECEIVED";
        case NodeEvent::CONFIG_ACK: return "CONFIG_ACK";
        case NodeEvent::RELAY_AUTH: return "RELAY_AUTH";
        case NodeEvent::RELAY_AUTH_SUCCESS: return "RELAY_AUTH_SUCCESS";
        case NodeEvent::RELAY_CONNECTING: return "RELAY_CONNECTING";
        case NodeEvent::RELAY_CONNECTED: return "RELAY_CONNECTED";
        case NodeEvent::RELAY_DISCONNECTED: return "RELAY_DISCONNECTED";
        case NodeEvent::RELAY_RECONNECTING: return "RELAY_RECONNECTING";
        case NodeEvent::P2P_CONNECTED: return "P2P_CONNECTED";
        case NodeEvent::P2P_DISCONNECTED: return "P2P_DISCONNECTED";
        case NodeEvent::SOCKET_READY: return "SOCKET_READY";
        case NodeEvent::STUN_SUCCESS: return "STUN_SUCCESS";
        case NodeEvent::STUN_FAILED: return "STUN_FAILED";
        case NodeEvent::ENDPOINT_UPDATE: return "ENDPOINT_UPDATE";
        case NodeEvent::ENDPOINT_UPLOADED: return "ENDPOINT_UPLOADED";
        case NodeEvent::ENDPOINT_ACK: return "ENDPOINT_ACK";
        case NodeEvent::ENDPOINT_SYNCED: return "ENDPOINT_SYNCED";
        case NodeEvent::ROUTE_ANNOUNCE: return "ROUTE_ANNOUNCE";
        case NodeEvent::ROUTE_WITHDRAW: return "ROUTE_WITHDRAW";
        case NodeEvent::ROUTES_RECEIVED: return "ROUTES_RECEIVED";
        case NodeEvent::ROUTES_APPLIED: return "ROUTES_APPLIED";
        case NodeEvent::P2P_INIT: return "P2P_INIT";
        case NodeEvent::P2P_INIT_SENT: return "P2P_INIT_SENT";
        case NodeEvent::P2P_ENDPOINT_SENT: return "P2P_ENDPOINT_SENT";
        case NodeEvent::P2P_ENDPOINT_RECEIVED: return "P2P_ENDPOINT_RECEIVED";
        case NodeEvent::P2P_PUNCH_START: return "P2P_PUNCH_START";
        case NodeEvent::P2P_PUNCH_SUCCESS: return "P2P_PUNCH_SUCCESS";
        case NodeEvent::P2P_PUNCH_FAILED: return "P2P_PUNCH_FAILED";
        case NodeEvent::P2P_PUNCH_TIMEOUT: return "P2P_PUNCH_TIMEOUT";
        case NodeEvent::P2P_STATUS: return "P2P_STATUS";
        case NodeEvent::P2P_KEEPALIVE_TIMEOUT: return "P2P_KEEPALIVE_TIMEOUT";
        case NodeEvent::PEER_ONLINE: return "PEER_ONLINE";
        case NodeEvent::PEER_OFFLINE: return "PEER_OFFLINE";
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
    // 初始化自身状态
    self_state_.node_id = self_id;
    self_state_.role = self_role;
}

void NodeStateMachine::set_self_id(NodeId new_id) {
    log().debug("Updating self_id from {} to {}", self_id_, new_id);
    self_id_ = new_id;
    self_state_.node_id = new_id;
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

                if (old_state != NodeConnectionState::OFFLINE) {
                    log().info("Node {} disconnected: {} -> OFFLINE",
                               node_id, node_connection_state_name(old_state));
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

    // 【调试】检查是否为自身节点的 P2P 事件
    if (node_id == self_id_) {
        // Client 端的 P2P 状态存储在 self_state_ 中，应该使用专门的方法
        log().debug("P2P event for self node, delegating to self_state handling");
        handle_self_p2p_event(peer_id, event);
        return;
    }

    log().debug("Acquiring nodes_mutex_ for node {}", node_id);
    std::unique_lock lock(nodes_mutex_);
    log().debug("Acquired nodes_mutex_ for node {}", node_id);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        log().debug("Node {} not found in node_states_, returning", node_id);
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

    if (link.state != old_p2p_state) {
        log().info("Node {} P2P with {}: {} -> {}",
                   node_id, peer_id,
                   p2p_connection_state_name(old_p2p_state),
                   p2p_connection_state_name(link.state));
    }
}

void NodeStateMachine::handle_self_p2p_event(NodeId peer_id, NodeEvent event) {
    log().debug("Self P2P with {} event: {}", peer_id, node_event_name(event));

    std::unique_lock lock(nodes_mutex_);

    auto& link = self_state_.p2p_links[peer_id];
    if (link.peer_id == 0) {
        link.peer_id = peer_id;
    }

    auto old_p2p_state = link.state;

    switch (event) {
        case NodeEvent::P2P_INIT:
        case NodeEvent::P2P_INIT_SENT:
            if (link.state == P2PConnectionState::NONE ||
                link.state == P2PConnectionState::FAILED) {
                link.state = P2PConnectionState::INITIATING;
                link.connect_time = now_us();
            }
            break;

        case NodeEvent::P2P_ENDPOINT_RECEIVED:
            if (link.state == P2PConnectionState::INITIATING ||
                link.state == P2PConnectionState::WAITING_ENDPOINT ||
                link.state == P2PConnectionState::NONE) {
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
        case NodeEvent::P2P_PUNCH_TIMEOUT:
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

    // 更新数据面状态（在锁内，但不调用回调）
    bool has_p2p = false;
    for (const auto& [pid, plink] : self_state_.p2p_links) {
        if (plink.state == P2PConnectionState::CONNECTED) {
            has_p2p = true;
            break;
        }
    }

    DataPlaneState new_data_state = self_state_.data_plane;
    bool has_relay = self_state_.has_connected_relay();
    if (has_relay && has_p2p) {
        new_data_state = DataPlaneState::HYBRID;
    } else if (has_relay) {
        new_data_state = DataPlaneState::RELAY_ONLY;
    } else if (has_p2p) {
        new_data_state = DataPlaneState::DEGRADED;
    } else {
        new_data_state = DataPlaneState::OFFLINE;
    }

    auto old_data_state = self_state_.data_plane;
    bool data_state_changed = (old_data_state != new_data_state);
    if (data_state_changed) {
        self_state_.data_plane = new_data_state;
    }

    if (link.state != old_p2p_state) {
        log().info("Self P2P with {}: {} -> {}",
                   peer_id,
                   p2p_connection_state_name(old_p2p_state),
                   p2p_connection_state_name(link.state));
    }

    if (data_state_changed) {
        log().info("Data plane: {} -> {}",
                   data_plane_state_name(old_data_state),
                   data_plane_state_name(new_data_state));
    }

    lock.unlock();

    // 更新连接阶段（在锁外，因为它可能触发回调）
    if (data_state_changed) {
        update_connection_phase();
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
        bool was_online = it->second.is_online();
        node_states_.erase(it);

        if (was_online) {
            log().info("Removed online node {}", node_id);
        } else {
            log().debug("Removed node {}", node_id);
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
// 会话管理（Controller 端使用）
// ============================================================================

void NodeStateMachine::handle_auth_request(NodeId node_id, NetworkId network_id,
                                           const std::string& auth_key_hash,
                                           const std::array<uint8_t, 32>& session_key) {
    std::unique_lock lock(nodes_mutex_);

    // 如果节点不存在，创建它
    if (node_states_.find(node_id) == node_states_.end()) {
        node_states_[node_id] = NodeState{
            .node_id = node_id,
            .network_id = network_id,
            .role = NodeRole::CLIENT,
            .last_seen_time = now_us()
        };
    }

    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->auth_key_hash = auth_key_hash;
        state->session_key = session_key;
        state->session_state = ClientSessionState::AUTHENTICATING;
        state->auth_time = now_us();
    }
}

void NodeStateMachine::handle_auth_result(NodeId node_id, bool success) {
    if (success) {
        set_session_state_internal(node_id, ClientSessionState::AUTHENTICATED);
    } else {
        set_session_state_internal(node_id, ClientSessionState::DISCONNECTED);
    }
}

void NodeStateMachine::mark_config_sent(NodeId node_id, uint64_t config_version) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->config_version = config_version;
        state->config_acked = false;
        state->config_send_time = now_us();
        auto old_session = state->session_state;
        if (old_session == ClientSessionState::AUTHENTICATED) {
            state->session_state = ClientSessionState::CONFIGURING;

            log().info("Node {} session: {} -> CONFIGURING",
                       node_id, client_session_state_name(old_session));
        }
    }
}

void NodeStateMachine::mark_config_acked(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->config_acked = true;
        lock.unlock();

        // 更新会话状态
        update_session_state(node_id);
    }
}

void NodeStateMachine::set_session_state(NodeId node_id, ClientSessionState new_state) {
    set_session_state_internal(node_id, new_state);
}

void NodeStateMachine::set_relay_session_state(NodeId node_id, RelaySessionState new_state) {
    set_relay_state_internal(node_id, new_state);
}

void NodeStateMachine::record_ping(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->last_ping_time = now_us();
        state->last_seen_time = now_us();
    }
}

void NodeStateMachine::record_pong(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        state->last_seen_time = now_us();
    }
}

// ============================================================================
// P2P 协商管理（Controller 端使用）
// ============================================================================

void NodeStateMachine::handle_p2p_init_request(NodeId initiator, NodeId responder, uint32_t seq) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(initiator);
    if (state) {
        auto& negotiation = state->p2p_negotiations[responder];
        negotiation.peer_id = responder;
        negotiation.phase = P2PNegotiationPhase::INITIATED;
        negotiation.init_seq = seq;
        negotiation.init_time = now_us();

        log().debug("P2P negotiation {} -> {}: INITIATED (seq={})",
                   initiator, responder, seq);
    }
}

void NodeStateMachine::mark_p2p_endpoint_sent(NodeId node_id, NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        auto it = state->p2p_negotiations.find(peer_id);
        if (it != state->p2p_negotiations.end()) {
            it->second.phase = P2PNegotiationPhase::ENDPOINTS_SENT;
            it->second.endpoint_send_time = now_us();

            log().debug("P2P negotiation {} -> {}: ENDPOINTS_SENT",
                       node_id, peer_id);
        }
    }
}

void NodeStateMachine::handle_p2p_status(NodeId node_id, NodeId peer_id, bool success) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (state) {
        auto it = state->p2p_negotiations.find(peer_id);
        if (it != state->p2p_negotiations.end()) {
            auto new_phase = success ? P2PNegotiationPhase::ESTABLISHED : P2PNegotiationPhase::FAILED;
            it->second.phase = new_phase;

            log().debug("P2P negotiation {} -> {}: {}",
                       node_id, peer_id, p2p_negotiation_phase_name(new_phase));
        }
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

bool NodeStateMachine::is_client_online(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    return it != node_states_.end() && it->second.is_session_online();
}

bool NodeStateMachine::has_client_relay(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = node_states_.find(node_id);
    return it != node_states_.end() && it->second.has_relay();
}

std::vector<NodeId> NodeStateMachine::get_online_clients() const {
    std::vector<NodeId> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [id, state] : node_states_) {
        if (state.is_session_online()) {
            result.push_back(id);
        }
    }
    return result;
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

        log().info("Node {} connection: {} -> {}",
                   node_id,
                   node_connection_state_name(old_state),
                   node_connection_state_name(new_state));
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

        log().debug("Node {} data channel: {} -> {}",
                   node_id,
                   data_channel_state_name(old_state),
                   data_channel_state_name(new_state));
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

        log().info("Node {} P2P with {}: {} -> {}",
                   node_id, peer_id,
                   p2p_connection_state_name(old_state),
                   p2p_connection_state_name(new_state));
    }
}

void NodeStateMachine::set_session_state_internal(NodeId node_id, ClientSessionState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->session_state;
    if (old_state != new_state) {
        state->session_state = new_state;
        auto network_id = state->network_id;
        lock.unlock();

        log().info("Node {} session: {} -> {}",
                   node_id,
                   client_session_state_name(old_state),
                   client_session_state_name(new_state));

        // 客户端上线/下线通知
        bool was_online = (old_state == ClientSessionState::ONLINE);
        bool is_online = (new_state == ClientSessionState::ONLINE);

        if (!was_online && is_online && callbacks_.on_client_online) {
            callbacks_.on_client_online(node_id, network_id);
        } else if (was_online && !is_online && callbacks_.on_client_offline) {
            callbacks_.on_client_offline(node_id, network_id);
        }
    }
}

void NodeStateMachine::set_relay_state_internal(NodeId node_id, RelaySessionState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->relay_state;
    if (old_state != new_state) {
        state->relay_state = new_state;
        lock.unlock();

        log().info("Node {} relay: {} -> {}",
                   node_id,
                   relay_session_state_name(old_state),
                   relay_session_state_name(new_state));

        // 更新会话状态
        update_session_state(node_id);
    }
}

void NodeStateMachine::set_p2p_negotiation_phase(NodeId node_id, NodeId peer_id, P2PNegotiationPhase phase) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto& negotiation = state->p2p_negotiations[peer_id];
    negotiation.peer_id = peer_id;
    negotiation.phase = phase;

    log().debug("P2P negotiation {} -> {}: {}",
               node_id, peer_id, p2p_negotiation_phase_name(phase));
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

        log().debug("Node {} data channel: {} -> {}",
                   node_id, data_channel_state_name(old_channel), data_channel_state_name(new_channel));
    }
}

void NodeStateMachine::update_session_state(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* state = get_node_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->session_state;
    ClientSessionState new_state = old_state;

    // 根据 Relay 状态和配置确认状态更新会话状态
    if (state->config_acked && state->relay_state == RelaySessionState::CONNECTED) {
        new_state = ClientSessionState::ONLINE;
    } else if (state->config_acked && state->relay_state != RelaySessionState::CONNECTED) {
        new_state = ClientSessionState::DEGRADED;
    }

    if (old_state != new_state) {
        state->session_state = new_state;
        auto network_id = state->network_id;
        lock.unlock();

        log().info("Node {} session updated: {} -> {}",
                   node_id,
                   client_session_state_name(old_state),
                   client_session_state_name(new_state));

        // 客户端上线/下线通知（这是有业务逻辑的回调，需要保留）
        bool was_online = (old_state == ClientSessionState::ONLINE);
        bool is_online = (new_state == ClientSessionState::ONLINE);

        if (!was_online && is_online && callbacks_.on_client_online) {
            callbacks_.on_client_online(node_id, network_id);
        } else if (was_online && !is_online && callbacks_.on_client_offline) {
            callbacks_.on_client_offline(node_id, network_id);
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

NodeState::P2PLink* NodeStateMachine::get_peer_link_mut(NodeId peer_id) {
    auto it = self_state_.p2p_links.find(peer_id);
    if (it != self_state_.p2p_links.end()) {
        return &it->second;
    }
    return nullptr;
}

NodeState::RelayConnection* NodeStateMachine::get_relay_connection_mut(const std::string& relay_id) {
    auto it = self_state_.relay_connections.find(relay_id);
    if (it != self_state_.relay_connections.end()) {
        return &it->second;
    }
    return nullptr;
}

// ============================================================================
// Client 端控制面/数据面管理
// ============================================================================

void NodeStateMachine::set_control_plane_state(ControlPlaneState state) {
    set_control_plane_state_internal(state);
}

void NodeStateMachine::set_data_plane_state_client(DataPlaneState state) {
    set_data_plane_state_internal(state);
}

void NodeStateMachine::set_connection_phase(ConnectionPhase phase) {
    set_connection_phase_internal(phase);
}

void NodeStateMachine::set_endpoint_sync_state(ClientEndpointSyncState state) {
    set_endpoint_sync_state_internal(state);
}

void NodeStateMachine::set_route_sync_state(RouteSyncState state) {
    set_route_sync_state_internal(state);
}

void NodeStateMachine::update_connection_phase() {
    // 基于控制面和数据面状态计算连接阶段
    ConnectionPhase new_phase = ConnectionPhase::OFFLINE;

    auto control = self_state_.control_plane;
    auto data = self_state_.data_plane;

    if (control == ControlPlaneState::DISCONNECTED) {
        new_phase = ConnectionPhase::OFFLINE;
    } else if (control == ControlPlaneState::CONNECTING ||
               control == ControlPlaneState::AUTHENTICATING) {
        new_phase = ConnectionPhase::AUTHENTICATING;
    } else if (control == ControlPlaneState::CONFIGURING) {
        new_phase = ConnectionPhase::CONFIGURING;
    } else if (control == ControlPlaneState::READY) {
        if (data == DataPlaneState::OFFLINE) {
            new_phase = ConnectionPhase::ESTABLISHING;
        } else {
            new_phase = ConnectionPhase::ONLINE;
        }
    } else if (control == ControlPlaneState::RECONNECTING) {
        new_phase = ConnectionPhase::RECONNECTING;
    }

    set_connection_phase_internal(new_phase);
}

void NodeStateMachine::update_data_plane_state_client() {
    // 基于 Relay 和 P2P 状态计算数据面状态
    bool has_relay = self_state_.has_connected_relay();
    size_t p2p_count = 0;

    for (const auto& [peer_id, link] : self_state_.p2p_links) {
        if (link.data_path == PeerDataPath::P2P) {
            ++p2p_count;
        }
    }

    DataPlaneState new_state = DataPlaneState::OFFLINE;

    if (has_relay && p2p_count > 0) {
        new_state = DataPlaneState::HYBRID;
    } else if (has_relay) {
        new_state = DataPlaneState::RELAY_ONLY;
    } else if (p2p_count > 0) {
        new_state = DataPlaneState::DEGRADED;
    }

    set_data_plane_state_internal(new_state);
}

void NodeStateMachine::set_control_plane_state_internal(ControlPlaneState new_state) {
    auto old_state = self_state_.control_plane;
    if (old_state != new_state) {
        self_state_.control_plane = new_state;

        log().info("Control plane: {} -> {}",
                   control_plane_state_name(old_state),
                   control_plane_state_name(new_state));

        // 更新连接阶段
        update_connection_phase();
    }
}

void NodeStateMachine::set_data_plane_state_internal(DataPlaneState new_state) {
    auto old_state = self_state_.data_plane;
    if (old_state != new_state) {
        self_state_.data_plane = new_state;

        log().info("Data plane: {} -> {}",
                   data_plane_state_name(old_state),
                   data_plane_state_name(new_state));

        // 更新连接阶段
        update_connection_phase();
    }
}

void NodeStateMachine::set_connection_phase_internal(ConnectionPhase new_phase) {
    auto old_phase = self_state_.connection_phase;
    if (old_phase != new_phase) {
        self_state_.connection_phase = new_phase;

        log().info("Connection phase: {} -> {}",
                   connection_phase_name(old_phase),
                   connection_phase_name(new_phase));

        // 保留此回调（有业务逻辑：更新 ClientState 兼容状态）
        if (callbacks_.on_connection_phase_change) {
            callbacks_.on_connection_phase_change(old_phase, new_phase);
        }
    }
}

void NodeStateMachine::set_endpoint_sync_state_internal(ClientEndpointSyncState new_state) {
    auto old_state = self_state_.endpoint_sync;
    if (old_state != new_state) {
        self_state_.endpoint_sync = new_state;

        log().debug("Endpoint sync: {} -> {}",
                   client_endpoint_sync_state_name(old_state),
                   client_endpoint_sync_state_name(new_state));
    }
}

void NodeStateMachine::set_route_sync_state_internal(RouteSyncState new_state) {
    auto old_state = self_state_.route_sync;
    if (old_state != new_state) {
        self_state_.route_sync = new_state;

        log().debug("Route sync: {} -> {}",
                   route_sync_state_name(old_state),
                   route_sync_state_name(new_state));
    }
}

// ============================================================================
// Client 端 Relay 管理
// ============================================================================

void NodeStateMachine::add_relay(const std::string& relay_id, bool is_primary) {
    std::unique_lock lock(nodes_mutex_);
    if (self_state_.relay_connections.find(relay_id) == self_state_.relay_connections.end()) {
        NodeState::RelayConnection relay;
        relay.relay_id = relay_id;
        relay.is_primary = is_primary;
        self_state_.relay_connections[relay_id] = relay;

        if (is_primary) {
            self_state_.primary_relay_id = relay_id;
        }

        log().debug("Added relay: {} (primary={})", relay_id, is_primary);
    }
}

void NodeStateMachine::remove_relay(const std::string& relay_id) {
    std::unique_lock lock(nodes_mutex_);
    auto it = self_state_.relay_connections.find(relay_id);
    if (it != self_state_.relay_connections.end()) {
        bool was_primary = it->second.is_primary;
        self_state_.relay_connections.erase(it);

        if (was_primary) {
            self_state_.primary_relay_id.clear();
            // 选择新的主 Relay
            for (auto& [id, relay] : self_state_.relay_connections) {
                if (relay.is_connected()) {
                    self_state_.primary_relay_id = id;
                    relay.is_primary = true;
                    break;
                }
            }
        }

        lock.unlock();

        log().debug("Removed relay: {}", relay_id);

        // 更新数据面状态
        update_data_plane_state_client();
    }
}

void NodeStateMachine::set_primary_relay(const std::string& relay_id) {
    std::unique_lock lock(nodes_mutex_);
    // 取消旧的主 Relay
    for (auto& [id, relay] : self_state_.relay_connections) {
        relay.is_primary = (id == relay_id);
    }
    self_state_.primary_relay_id = relay_id;
}

void NodeStateMachine::set_relay_connection_state(const std::string& relay_id, RelayConnectionState state) {
    set_relay_connection_state_internal(relay_id, state);
}

void NodeStateMachine::update_relay_latency(const std::string& relay_id, uint16_t latency_ms) {
    std::unique_lock lock(nodes_mutex_);
    auto* relay = get_relay_connection_mut(relay_id);
    if (relay) {
        relay->latency_ms = latency_ms;
    }
}

void NodeStateMachine::record_relay_recv(const std::string& relay_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* relay = get_relay_connection_mut(relay_id);
    if (relay) {
        relay->last_recv_time = now_us();
    }
}

void NodeStateMachine::record_relay_send(const std::string& relay_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* relay = get_relay_connection_mut(relay_id);
    if (relay) {
        relay->last_send_time = now_us();
    }
}

void NodeStateMachine::set_relay_connection_state_internal(const std::string& relay_id, RelayConnectionState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* relay = get_relay_connection_mut(relay_id);
    if (!relay) {
        // 如果 Relay 不存在，创建一个
        add_relay(relay_id, false);
        relay = get_relay_connection_mut(relay_id);
        if (!relay) return;
    }

    auto old_state = relay->state;
    if (old_state != new_state) {
        relay->state = new_state;

        if (new_state == RelayConnectionState::CONNECTED) {
            relay->last_connect_time = now_us();
        } else if (new_state == RelayConnectionState::RECONNECTING) {
            relay->reconnect_count++;
        }

        log().info("Relay {}: {} -> {}",
                   relay_id,
                   relay_connection_state_name(old_state),
                   relay_connection_state_name(new_state));

        lock.unlock();

        // 更新数据面状态（在锁外）
        update_data_plane_state_client();
    }
}

std::optional<NodeState::RelayConnection> NodeStateMachine::get_relay_info(const std::string& relay_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = self_state_.relay_connections.find(relay_id);
    if (it != self_state_.relay_connections.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<NodeState::RelayConnection> NodeStateMachine::get_all_relay_info() const {
    std::vector<NodeState::RelayConnection> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [id, relay] : self_state_.relay_connections) {
        result.push_back(relay);
    }
    return result;
}

bool NodeStateMachine::has_connected_relay() const {
    std::shared_lock lock(nodes_mutex_);
    return self_state_.has_connected_relay();
}

size_t NodeStateMachine::connected_relay_count() const {
    std::shared_lock lock(nodes_mutex_);
    return self_state_.connected_relay_count();
}

std::optional<std::string> NodeStateMachine::get_primary_relay() const {
    std::shared_lock lock(nodes_mutex_);
    if (!self_state_.primary_relay_id.empty()) {
        return self_state_.primary_relay_id;
    }
    return std::nullopt;
}

// ============================================================================
// Client 端对端管理
// ============================================================================

void NodeStateMachine::add_peer(NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    if (self_state_.p2p_links.find(peer_id) == self_state_.p2p_links.end()) {
        NodeState::P2PLink link;
        link.peer_id = peer_id;
        self_state_.p2p_links[peer_id] = link;

        log().debug("Added peer: {}", peer_id);
    }
}

void NodeStateMachine::remove_peer(NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    auto it = self_state_.p2p_links.find(peer_id);
    if (it != self_state_.p2p_links.end()) {
        bool was_p2p = it->second.data_path == PeerDataPath::P2P;
        self_state_.p2p_links.erase(it);

        lock.unlock();

        log().debug("Removed peer: {}", peer_id);

        if (was_p2p) {
            // 更新数据面状态
            update_data_plane_state_client();
        }
    }
}

void NodeStateMachine::set_peer_link_state(NodeId peer_id, PeerLinkState state) {
    set_peer_link_state_internal(peer_id, state);
}

void NodeStateMachine::set_peer_data_path(NodeId peer_id, PeerDataPath path) {
    set_peer_data_path_internal(peer_id, path);
}

void NodeStateMachine::update_peer_active_connection(NodeId peer_id,
                                                      const std::array<uint8_t, 16>& addr,
                                                      uint16_t port,
                                                      bool is_p2p) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (!link) {
        // 直接内联添加 peer，避免递归获取锁导致死锁
        if (self_state_.p2p_links.find(peer_id) == self_state_.p2p_links.end()) {
            NodeState::P2PLink new_link;
            new_link.peer_id = peer_id;
            self_state_.p2p_links[peer_id] = new_link;
            log().debug("Added peer {} (inline)", peer_id);
        }
        link = get_peer_link_mut(peer_id);
        if (!link) return;
    }

    link->p2p_addr = addr;
    link->p2p_port = port;

    auto old_path = link->data_path;
    auto new_path = is_p2p ? PeerDataPath::P2P : PeerDataPath::RELAY;

    if (old_path != new_path) {
        link->data_path = new_path;

        log().info("Peer {} data path: {} -> {}",
                   peer_id,
                   peer_data_path_name(old_path),
                   peer_data_path_name(new_path));

        lock.unlock();

        // 更新数据面状态（在锁外）
        update_data_plane_state_client();
    }
}

void NodeStateMachine::update_peer_latency(NodeId peer_id, uint16_t latency_ms) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (link) {
        link->rtt_ms = latency_ms;
    }
}

void NodeStateMachine::record_peer_recv(NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (link) {
        link->last_recv_time = now_us();
    }
}

void NodeStateMachine::record_peer_send(NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (link) {
        link->last_send_time = now_us();
    }
}

void NodeStateMachine::update_peer_link_state(NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (!link) return;

    PeerLinkState new_state = PeerLinkState::UNKNOWN;

    // 基于 P2P 状态和数据路径计算链路状态
    switch (link->state) {
        case P2PConnectionState::NONE:
            if (link->data_path == PeerDataPath::RELAY) {
                new_state = PeerLinkState::RELAY_FALLBACK;
            } else if (link->data_path == PeerDataPath::UNREACHABLE) {
                new_state = PeerLinkState::OFFLINE;
            } else {
                new_state = PeerLinkState::UNKNOWN;
            }
            break;

        case P2PConnectionState::INITIATING:
        case P2PConnectionState::WAITING_ENDPOINT:
            new_state = PeerLinkState::RESOLVING;
            break;

        case P2PConnectionState::PUNCHING:
            new_state = PeerLinkState::PUNCHING;
            break;

        case P2PConnectionState::CONNECTED:
            new_state = PeerLinkState::P2P_ACTIVE;
            break;

        case P2PConnectionState::FAILED:
            if (self_state_.has_connected_relay()) {
                new_state = PeerLinkState::RELAY_FALLBACK;
            } else {
                new_state = PeerLinkState::OFFLINE;
            }
            break;
    }

    // 直接内联更新链路状态（避免调用 set_peer_link_state_internal 导致递归锁）
    auto old_state = link->link_state;
    if (old_state != new_state) {
        link->link_state = new_state;

        log().debug("Peer {} link: {} -> {}",
                   peer_id,
                   peer_link_state_name(old_state),
                   peer_link_state_name(new_state));
    }
}

void NodeStateMachine::set_peer_link_state_internal(NodeId peer_id, PeerLinkState new_state) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (!link) {
        // 直接内联添加 peer，避免递归获取锁导致死锁
        if (self_state_.p2p_links.find(peer_id) == self_state_.p2p_links.end()) {
            NodeState::P2PLink new_link;
            new_link.peer_id = peer_id;
            self_state_.p2p_links[peer_id] = new_link;
            log().debug("Added peer {} (inline)", peer_id);
        }
        link = get_peer_link_mut(peer_id);
        if (!link) return;
    }

    auto old_state = link->link_state;
    if (old_state != new_state) {
        link->link_state = new_state;

        log().debug("Peer {} link: {} -> {}",
                   peer_id,
                   peer_link_state_name(old_state),
                   peer_link_state_name(new_state));
    }
}

void NodeStateMachine::set_peer_data_path_internal(NodeId peer_id, PeerDataPath new_path) {
    std::unique_lock lock(nodes_mutex_);
    auto* link = get_peer_link_mut(peer_id);
    if (!link) {
        // 直接内联添加 peer，避免递归获取锁导致死锁
        if (self_state_.p2p_links.find(peer_id) == self_state_.p2p_links.end()) {
            NodeState::P2PLink new_link;
            new_link.peer_id = peer_id;
            self_state_.p2p_links[peer_id] = new_link;
            log().debug("Added peer {} (inline)", peer_id);
        }
        link = get_peer_link_mut(peer_id);
        if (!link) return;
    }

    auto old_path = link->data_path;
    if (old_path != new_path) {
        link->data_path = new_path;

        log().info("Peer {} data path: {} -> {}",
                   peer_id,
                   peer_data_path_name(old_path),
                   peer_data_path_name(new_path));

        // 内联更新对端链路状态（避免递归锁）
        PeerLinkState new_link_state = PeerLinkState::UNKNOWN;
        switch (link->state) {
            case P2PConnectionState::NONE:
                if (new_path == PeerDataPath::RELAY) {
                    new_link_state = PeerLinkState::RELAY_FALLBACK;
                } else if (new_path == PeerDataPath::UNREACHABLE) {
                    new_link_state = PeerLinkState::OFFLINE;
                }
                break;
            case P2PConnectionState::INITIATING:
            case P2PConnectionState::WAITING_ENDPOINT:
                new_link_state = PeerLinkState::RESOLVING;
                break;
            case P2PConnectionState::PUNCHING:
                new_link_state = PeerLinkState::PUNCHING;
                break;
            case P2PConnectionState::CONNECTED:
                new_link_state = PeerLinkState::P2P_ACTIVE;
                break;
            case P2PConnectionState::FAILED:
                if (self_state_.has_connected_relay()) {
                    new_link_state = PeerLinkState::RELAY_FALLBACK;
                } else {
                    new_link_state = PeerLinkState::OFFLINE;
                }
                break;
        }
        if (link->link_state != new_link_state) {
            auto old_link_state = link->link_state;
            link->link_state = new_link_state;
            log().debug("Peer {} link: {} -> {}",
                       peer_id,
                       peer_link_state_name(old_link_state),
                       peer_link_state_name(new_link_state));
        }

        lock.unlock();

        // 更新数据面状态（在锁外）
        update_data_plane_state_client();
    }
}

PeerLinkState NodeStateMachine::get_peer_link_state(NodeId peer_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = self_state_.p2p_links.find(peer_id);
    if (it != self_state_.p2p_links.end()) {
        return it->second.link_state;
    }
    return PeerLinkState::UNKNOWN;
}

std::optional<NodeState::P2PLink> NodeStateMachine::get_peer_state(NodeId peer_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = self_state_.p2p_links.find(peer_id);
    if (it != self_state_.p2p_links.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::pair<NodeId, NodeState::P2PLink>> NodeStateMachine::get_all_peer_states() const {
    std::vector<std::pair<NodeId, NodeState::P2PLink>> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [peer_id, link] : self_state_.p2p_links) {
        result.emplace_back(peer_id, link);
    }
    return result;
}

bool NodeStateMachine::is_peer_p2p_ready(NodeId peer_id) const {
    std::shared_lock lock(nodes_mutex_);
    return self_state_.is_peer_p2p_ready(peer_id);
}

std::vector<NodeId> NodeStateMachine::get_peers_for_retry() const {
    std::vector<NodeId> result;
    uint64_t now = now_us();

    std::shared_lock lock(nodes_mutex_);
    for (const auto& [peer_id, link] : self_state_.p2p_links) {
        if (link.state == P2PConnectionState::FAILED) {
            // 检查是否到达重试时间
            if (link.next_retry_time > 0 && now >= link.next_retry_time) {
                result.push_back(peer_id);
            } else if (link.next_retry_time == 0 && link.connect_time > 0 &&
                       now - link.connect_time >= p2p_retry_interval_ms_ * 1000ULL) {
                result.push_back(peer_id);
            }
        }
    }
    return result;
}

std::vector<NodeId> NodeStateMachine::get_peers_for_keepalive() const {
    std::vector<NodeId> result;
    uint64_t now = now_us();
    uint64_t keepalive_interval = p2p_keepalive_timeout_ms_ * 500ULL; // 一半超时时间

    std::shared_lock lock(nodes_mutex_);
    for (const auto& [peer_id, link] : self_state_.p2p_links) {
        if (link.state == P2PConnectionState::CONNECTED &&
            link.data_path == PeerDataPath::P2P) {
            // 检查是否需要发送 keepalive
            if (link.last_send_time > 0 && now - link.last_send_time >= keepalive_interval) {
                result.push_back(peer_id);
            }
        }
    }
    return result;
}

uint32_t NodeStateMachine::next_init_seq() {
    return ++self_state_.next_init_seq;
}

// ============================================================================
// Client 端状态查询
// ============================================================================

ControlPlaneState NodeStateMachine::control_plane_state() const {
    return self_state_.control_plane;
}

bool NodeStateMachine::is_control_ready() const {
    return self_state_.is_control_ready();
}

DataPlaneState NodeStateMachine::data_plane_state_client() const {
    return self_state_.data_plane;
}

bool NodeStateMachine::has_data_path() const {
    return self_state_.has_data_path();
}

ConnectionPhase NodeStateMachine::connection_phase() const {
    return self_state_.connection_phase;
}

bool NodeStateMachine::is_client_connected() const {
    return self_state_.connection_phase == ConnectionPhase::ONLINE;
}

ClientEndpointSyncState NodeStateMachine::endpoint_sync_state() const {
    return self_state_.endpoint_sync;
}

bool NodeStateMachine::is_endpoint_synced() const {
    return self_state_.is_endpoint_synced();
}

RouteSyncState NodeStateMachine::route_sync_state() const {
    return self_state_.route_sync;
}

} // namespace edgelink

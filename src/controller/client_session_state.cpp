#include "controller/client_session_state.hpp"
#include "common/logger.hpp"
#include <algorithm>
#include <chrono>

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("session_state"); }
} // anonymous namespace

// ============================================================================
// ClientSessionStateMachine 实现
// ============================================================================

ClientSessionStateMachine::ClientSessionStateMachine() {
}

void ClientSessionStateMachine::set_callbacks(SessionStateCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

// ============================================================================
// 事件处理
// ============================================================================

void ClientSessionStateMachine::handle_event(NodeId node_id, SessionEvent event) {
    log().debug("Client {} event: {}", node_id, session_event_name(event));

    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (!state && event != SessionEvent::CONTROL_CONNECT) {
        return;
    }

    switch (event) {
        case SessionEvent::CONTROL_CONNECT:
            if (!state) {
                client_states_[node_id] = ClientState{.node_id = node_id};
                state = &client_states_[node_id];
            }
            state->session_state = ClientSessionState::AUTHENTICATING;
            break;

        case SessionEvent::CONTROL_DISCONNECT:
            if (state) {
                auto old_state = state->session_state;
                auto network_id = state->network_id;
                bool was_online = state->is_online();
                client_states_.erase(node_id);
                lock.unlock();

                if (old_state != ClientSessionState::DISCONNECTED) {
                    if (callbacks_.on_session_state_change) {
                        callbacks_.on_session_state_change(node_id, old_state, ClientSessionState::DISCONNECTED);
                    }
                    if (was_online && callbacks_.on_client_offline) {
                        callbacks_.on_client_offline(node_id, network_id);
                    }
                }
            }
            return;

        case SessionEvent::AUTH_SUCCESS:
            if (state) {
                state->session_state = ClientSessionState::AUTHENTICATED;
                state->auth_time = now_us();
            }
            break;

        case SessionEvent::AUTH_FAILED:
            if (state) {
                state->session_state = ClientSessionState::DISCONNECTED;
            }
            break;

        case SessionEvent::CONFIG_SENT:
            if (state && state->session_state == ClientSessionState::AUTHENTICATED) {
                state->session_state = ClientSessionState::CONFIGURING;
                state->config_send_time = now_us();
            }
            break;

        case SessionEvent::CONFIG_ACK:
            if (state && state->session_state == ClientSessionState::CONFIGURING) {
                auto old_state = state->session_state;
                state->session_state = ClientSessionState::ONLINE;
                state->config_acked = true;
                auto network_id = state->network_id;
                lock.unlock();

                if (callbacks_.on_session_state_change) {
                    callbacks_.on_session_state_change(node_id, old_state, ClientSessionState::ONLINE);
                }
                if (callbacks_.on_client_online) {
                    callbacks_.on_client_online(node_id, network_id);
                }
            }
            return;

        case SessionEvent::RELAY_CONNECT:
            if (state) {
                state->relay_state = RelaySessionState::AUTHENTICATING;
            }
            break;

        case SessionEvent::RELAY_DISCONNECT:
            if (state) {
                auto old_relay = state->relay_state;
                state->relay_state = RelaySessionState::DISCONNECTED;
                lock.unlock();

                if (old_relay != RelaySessionState::DISCONNECTED && callbacks_.on_relay_state_change) {
                    callbacks_.on_relay_state_change(node_id, old_relay, RelaySessionState::DISCONNECTED);
                }
            }
            return;

        case SessionEvent::PING_RECEIVED:
            if (state) {
                state->last_ping_time = now_us();
            }
            break;

        case SessionEvent::PONG_SENT:
            if (state) {
                state->last_pong_time = now_us();
            }
            break;

        case SessionEvent::HEARTBEAT_TIMEOUT:
            if (state && state->is_online()) {
                state->session_state = ClientSessionState::DEGRADED;
            }
            break;

        default:
            break;
    }
}

void ClientSessionStateMachine::handle_auth_request(NodeId node_id, NetworkId network_id,
                                                    const std::string& auth_key_hash,
                                                    const std::array<uint8_t, 32>& session_key) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (state) {
        state->network_id = network_id;
        state->auth_key_hash = auth_key_hash;
        state->session_key = session_key;
        state->session_state = ClientSessionState::AUTHENTICATING;
    }
}

void ClientSessionStateMachine::handle_auth_result(NodeId node_id, bool success) {
    if (success) {
        handle_event(node_id, SessionEvent::AUTH_SUCCESS);
    } else {
        handle_event(node_id, SessionEvent::AUTH_FAILED);
    }
}

void ClientSessionStateMachine::handle_endpoint_update(NodeId node_id, const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (state) {
        auto old_endpoints = state->endpoints;
        state->endpoints = endpoints;
        state->endpoint_update_time = now_us();
        state->endpoint_state = EndpointState::SYNCED;
        lock.unlock();

        log().debug("Client {} endpoints updated: {} endpoints", node_id, endpoints.size());

        if (callbacks_.on_endpoint_update) {
            callbacks_.on_endpoint_update(node_id, endpoints);
        }
    }
}

void ClientSessionStateMachine::handle_route_announce(NodeId node_id, const std::vector<RouteInfo>& routes) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (state) {
        // 添加新路由
        for (const auto& route : routes) {
            // 检查是否已存在
            bool exists = false;
            for (const auto& existing : state->announced_routes) {
                if (existing.ip_type == route.ip_type &&
                    existing.prefix == route.prefix &&
                    existing.prefix_len == route.prefix_len) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                state->announced_routes.push_back(route);
            }
        }
        state->route_update_time = now_us();
        lock.unlock();

        if (callbacks_.on_route_update && !routes.empty()) {
            callbacks_.on_route_update(node_id, routes, {});
        }
    }
}

void ClientSessionStateMachine::handle_route_withdraw(NodeId node_id, const std::vector<RouteInfo>& routes) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (state) {
        // 删除路由
        for (const auto& route : routes) {
            state->announced_routes.erase(
                std::remove_if(state->announced_routes.begin(), state->announced_routes.end(),
                    [&route](const RouteInfo& r) {
                        return r.ip_type == route.ip_type &&
                               r.prefix == route.prefix &&
                               r.prefix_len == route.prefix_len;
                    }),
                state->announced_routes.end());
        }
        state->route_update_time = now_us();
        lock.unlock();

        if (callbacks_.on_route_update && !routes.empty()) {
            callbacks_.on_route_update(node_id, {}, routes);
        }
    }
}

void ClientSessionStateMachine::handle_p2p_init(NodeId initiator, NodeId responder, uint32_t seq) {
    std::unique_lock lock(clients_mutex_);

    // 更新发起方状态
    auto* init_state = get_client_state_mut(initiator);
    if (init_state) {
        auto& nego = init_state->p2p_negotiations[responder];
        nego.peer_id = responder;
        nego.phase = P2PNegotiationPhase::INITIATED;
        nego.init_seq = seq;
        nego.init_time = now_us();
    }

    // 更新响应方状态
    auto* resp_state = get_client_state_mut(responder);
    if (resp_state) {
        auto& nego = resp_state->p2p_negotiations[initiator];
        nego.peer_id = initiator;
        nego.phase = P2PNegotiationPhase::INITIATED;
        nego.init_seq = seq;
        nego.init_time = now_us();
    }

    lock.unlock();

    if (callbacks_.on_p2p_negotiation_change) {
        callbacks_.on_p2p_negotiation_change(initiator, responder, P2PNegotiationPhase::INITIATED);
    }
}

void ClientSessionStateMachine::handle_p2p_status(NodeId node_id, NodeId peer_id, bool success) {
    std::unique_lock lock(clients_mutex_);

    auto new_phase = success ? P2PNegotiationPhase::ESTABLISHED : P2PNegotiationPhase::FAILED;

    // 更新双方状态
    auto* state1 = get_client_state_mut(node_id);
    if (state1) {
        auto it = state1->p2p_negotiations.find(peer_id);
        if (it != state1->p2p_negotiations.end()) {
            it->second.phase = new_phase;
        }
    }

    auto* state2 = get_client_state_mut(peer_id);
    if (state2) {
        auto it = state2->p2p_negotiations.find(node_id);
        if (it != state2->p2p_negotiations.end()) {
            it->second.phase = new_phase;
        }
    }

    lock.unlock();

    if (callbacks_.on_p2p_negotiation_change) {
        callbacks_.on_p2p_negotiation_change(node_id, peer_id, new_phase);
    }
}

// ============================================================================
// 状态查询
// ============================================================================

std::optional<ClientState> ClientSessionStateMachine::get_client_state(NodeId node_id) const {
    std::shared_lock lock(clients_mutex_);
    auto it = client_states_.find(node_id);
    if (it != client_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<NodeId> ClientSessionStateMachine::get_online_clients() const {
    std::vector<NodeId> result;
    std::shared_lock lock(clients_mutex_);
    for (const auto& [id, state] : client_states_) {
        if (state.is_online()) {
            result.push_back(id);
        }
    }
    return result;
}

std::vector<NodeId> ClientSessionStateMachine::get_network_clients(NetworkId network_id) const {
    std::vector<NodeId> result;
    std::shared_lock lock(clients_mutex_);
    for (const auto& [id, state] : client_states_) {
        if (state.network_id == network_id) {
            result.push_back(id);
        }
    }
    return result;
}

std::vector<Endpoint> ClientSessionStateMachine::get_client_endpoints(NodeId node_id) const {
    std::shared_lock lock(clients_mutex_);
    auto it = client_states_.find(node_id);
    if (it != client_states_.end()) {
        return it->second.endpoints;
    }
    return {};
}

std::vector<RouteInfo> ClientSessionStateMachine::get_client_routes(NodeId node_id) const {
    std::shared_lock lock(clients_mutex_);
    auto it = client_states_.find(node_id);
    if (it != client_states_.end()) {
        return it->second.announced_routes;
    }
    return {};
}

bool ClientSessionStateMachine::is_client_online(NodeId node_id) const {
    std::shared_lock lock(clients_mutex_);
    auto it = client_states_.find(node_id);
    return it != client_states_.end() && it->second.is_online();
}

bool ClientSessionStateMachine::has_client_relay(NodeId node_id) const {
    std::shared_lock lock(clients_mutex_);
    auto it = client_states_.find(node_id);
    return it != client_states_.end() && it->second.has_relay();
}

// ============================================================================
// 客户端管理
// ============================================================================

void ClientSessionStateMachine::add_client(NodeId node_id) {
    std::unique_lock lock(clients_mutex_);
    if (client_states_.find(node_id) == client_states_.end()) {
        client_states_[node_id] = ClientState{.node_id = node_id};
        log().debug("Added client {}", node_id);
    }
}

void ClientSessionStateMachine::remove_client(NodeId node_id) {
    handle_event(node_id, SessionEvent::CONTROL_DISCONNECT);
}

void ClientSessionStateMachine::update_client_latency(NodeId node_id, uint16_t latency_ms) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (state) {
        state->latency_ms = latency_ms;
    }
}

void ClientSessionStateMachine::record_ping(NodeId node_id) {
    handle_event(node_id, SessionEvent::PING_RECEIVED);
}

void ClientSessionStateMachine::record_pong(NodeId node_id) {
    handle_event(node_id, SessionEvent::PONG_SENT);
}

// ============================================================================
// 超时检测
// ============================================================================

void ClientSessionStateMachine::check_timeouts() {
    uint64_t now = now_us();
    std::vector<std::pair<NodeId, SessionEvent>> events;

    {
        std::shared_lock lock(clients_mutex_);

        for (const auto& [node_id, state] : client_states_) {
            // 认证超时
            if (state.session_state == ClientSessionState::AUTHENTICATING) {
                if (state.auth_time == 0) {
                    // auth_time 未设置，使用默认超时
                    continue;
                }
                // 这里需要记录认证开始时间，暂时跳过
            }

            // 配置确认超时
            if (state.session_state == ClientSessionState::CONFIGURING) {
                if (state.config_send_time > 0 &&
                    now - state.config_send_time > config_ack_timeout_ms_ * 1000ULL) {
                    events.emplace_back(node_id, SessionEvent::HEARTBEAT_TIMEOUT);
                }
            }

            // 心跳超时
            if (state.is_online()) {
                uint64_t last_activity = std::max(state.last_ping_time, state.last_pong_time);
                if (last_activity > 0 &&
                    now - last_activity > heartbeat_timeout_ms_ * 1000ULL) {
                    events.emplace_back(node_id, SessionEvent::HEARTBEAT_TIMEOUT);
                }
            }

            // P2P 协商超时
            for (const auto& [peer_id, nego] : state.p2p_negotiations) {
                if (nego.phase == P2PNegotiationPhase::INITIATED ||
                    nego.phase == P2PNegotiationPhase::ENDPOINTS_SENT) {
                    if (nego.init_time > 0 &&
                        now - nego.init_time > p2p_timeout_ms_ * 1000ULL) {
                        // P2P 超时处理
                        log().debug("P2P negotiation timeout: {} <-> {}", node_id, peer_id);
                    }
                }
            }
        }
    }

    // 处理事件（在锁外）
    for (const auto& [node_id, event] : events) {
        handle_event(node_id, event);
    }
}

uint64_t ClientSessionStateMachine::now_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

// ============================================================================
// 重置
// ============================================================================

void ClientSessionStateMachine::reset() {
    std::unique_lock lock(clients_mutex_);
    client_states_.clear();
    log().info("Client session state machine reset");
}

// ============================================================================
// 内部方法
// ============================================================================

void ClientSessionStateMachine::set_session_state(NodeId node_id, ClientSessionState new_state) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->session_state;
    if (old_state != new_state) {
        state->session_state = new_state;
        auto network_id = state->network_id;
        lock.unlock();

        log().info("Client {} session: {} -> {}",
                   node_id,
                   client_session_state_name(old_state),
                   client_session_state_name(new_state));

        if (callbacks_.on_session_state_change) {
            callbacks_.on_session_state_change(node_id, old_state, new_state);
        }

        // 客户端上线/下线通知
        bool was_online = (old_state == ClientSessionState::ONLINE);
        bool is_online = (new_state == ClientSessionState::ONLINE);

        if (was_online && !is_online && callbacks_.on_client_offline) {
            callbacks_.on_client_offline(node_id, network_id);
        } else if (!was_online && is_online && callbacks_.on_client_online) {
            callbacks_.on_client_online(node_id, network_id);
        }
    }
}

void ClientSessionStateMachine::set_relay_state(NodeId node_id, RelaySessionState new_state) {
    std::unique_lock lock(clients_mutex_);
    auto* state = get_client_state_mut(node_id);
    if (!state) {
        return;
    }

    auto old_state = state->relay_state;
    if (old_state != new_state) {
        state->relay_state = new_state;
        lock.unlock();

        log().debug("Client {} relay: {} -> {}",
                   node_id,
                   relay_session_state_name(old_state),
                   relay_session_state_name(new_state));

        if (callbacks_.on_relay_state_change) {
            callbacks_.on_relay_state_change(node_id, old_state, new_state);
        }
    }
}

void ClientSessionStateMachine::update_session_state(NodeId node_id) {
    // 根据组合条件更新会话状态
    auto* state = get_client_state_mut(node_id);
    if (!state) {
        return;
    }

    // 目前会话状态主要由事件驱动，此方法预留用于复杂状态逻辑
}

ClientState* ClientSessionStateMachine::get_client_state_mut(NodeId node_id) {
    auto it = client_states_.find(node_id);
    if (it != client_states_.end()) {
        return &it->second;
    }
    return nullptr;
}

} // namespace edgelink::controller

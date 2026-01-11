#include "client/connection_state.hpp"
#include "common/logger.hpp"
#include <chrono>

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("client.state"); }
} // anonymous namespace

// ============================================================================
// 状态名称转换
// ============================================================================

const char* control_plane_state_name(ControlPlaneState state) {
    switch (state) {
        case ControlPlaneState::DISCONNECTED: return "DISCONNECTED";
        case ControlPlaneState::CONNECTING: return "CONNECTING";
        case ControlPlaneState::AUTHENTICATING: return "AUTHENTICATING";
        case ControlPlaneState::CONFIGURING: return "CONFIGURING";
        case ControlPlaneState::READY: return "READY";
        case ControlPlaneState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* data_plane_state_name(DataPlaneState state) {
    switch (state) {
        case DataPlaneState::OFFLINE: return "OFFLINE";
        case DataPlaneState::RELAY_ONLY: return "RELAY_ONLY";
        case DataPlaneState::HYBRID: return "HYBRID";
        case DataPlaneState::DEGRADED: return "DEGRADED";
        default: return "UNKNOWN";
    }
}

const char* connection_phase_name(ConnectionPhase phase) {
    switch (phase) {
        case ConnectionPhase::OFFLINE: return "OFFLINE";
        case ConnectionPhase::AUTHENTICATING: return "AUTHENTICATING";
        case ConnectionPhase::CONFIGURING: return "CONFIGURING";
        case ConnectionPhase::ESTABLISHING: return "ESTABLISHING";
        case ConnectionPhase::ONLINE: return "ONLINE";
        case ConnectionPhase::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* peer_data_path_name(PeerDataPath path) {
    switch (path) {
        case PeerDataPath::UNKNOWN: return "UNKNOWN";
        case PeerDataPath::RELAY: return "RELAY";
        case PeerDataPath::P2P: return "P2P";
        case PeerDataPath::UNREACHABLE: return "UNREACHABLE";
        default: return "UNKNOWN";
    }
}

const char* peer_p2p_negotiation_state_name(PeerP2PNegotiationState state) {
    switch (state) {
        case PeerP2PNegotiationState::IDLE: return "IDLE";
        case PeerP2PNegotiationState::RESOLVING: return "RESOLVING";
        case PeerP2PNegotiationState::PUNCHING: return "PUNCHING";
        case PeerP2PNegotiationState::ESTABLISHED: return "ESTABLISHED";
        case PeerP2PNegotiationState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

const char* endpoint_sync_state_name(EndpointSyncState state) {
    switch (state) {
        case EndpointSyncState::NOT_READY: return "NOT_READY";
        case EndpointSyncState::DISCOVERING: return "DISCOVERING";
        case EndpointSyncState::READY: return "READY";
        case EndpointSyncState::UPLOADING: return "UPLOADING";
        case EndpointSyncState::SYNCED: return "SYNCED";
        default: return "UNKNOWN";
    }
}

const char* peer_link_state_name(PeerLinkState state) {
    switch (state) {
        case PeerLinkState::UNKNOWN: return "UNKNOWN";
        case PeerLinkState::RESOLVING: return "RESOLVING";
        case PeerLinkState::PUNCHING: return "PUNCHING";
        case PeerLinkState::P2P_ACTIVE: return "P2P_ACTIVE";
        case PeerLinkState::RELAY_FALLBACK: return "RELAY_FALLBACK";
        case PeerLinkState::OFFLINE: return "OFFLINE";
        default: return "UNKNOWN";
    }
}

const char* route_sync_state_name(RouteSyncState state) {
    switch (state) {
        case RouteSyncState::DISABLED: return "DISABLED";
        case RouteSyncState::PENDING: return "PENDING";
        case RouteSyncState::SYNCING: return "SYNCING";
        case RouteSyncState::SYNCED: return "SYNCED";
        default: return "UNKNOWN";
    }
}

const char* relay_connection_state_name(RelayConnectionState state) {
    switch (state) {
        case RelayConnectionState::DISCONNECTED: return "DISCONNECTED";
        case RelayConnectionState::CONNECTING: return "CONNECTING";
        case RelayConnectionState::AUTHENTICATING: return "AUTHENTICATING";
        case RelayConnectionState::CONNECTED: return "CONNECTED";
        case RelayConnectionState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

const char* state_event_name(StateEvent event) {
    switch (event) {
        case StateEvent::START_CONNECT: return "START_CONNECT";
        case StateEvent::AUTH_SUCCESS: return "AUTH_SUCCESS";
        case StateEvent::AUTH_FAILED: return "AUTH_FAILED";
        case StateEvent::CONFIG_RECEIVED: return "CONFIG_RECEIVED";
        case StateEvent::CONTROL_DISCONNECTED: return "CONTROL_DISCONNECTED";
        case StateEvent::RELAY_CONNECTING: return "RELAY_CONNECTING";
        case StateEvent::RELAY_CONNECTED: return "RELAY_CONNECTED";
        case StateEvent::RELAY_DISCONNECTED: return "RELAY_DISCONNECTED";
        case StateEvent::RELAY_RECONNECTING: return "RELAY_RECONNECTING";
        case StateEvent::SOCKET_READY: return "SOCKET_READY";
        case StateEvent::STUN_SUCCESS: return "STUN_SUCCESS";
        case StateEvent::STUN_FAILED: return "STUN_FAILED";
        case StateEvent::ENDPOINT_UPLOADED: return "ENDPOINT_UPLOADED";
        case StateEvent::ENDPOINT_ACK: return "ENDPOINT_ACK";
        case StateEvent::P2P_INIT_SENT: return "P2P_INIT_SENT";
        case StateEvent::P2P_ENDPOINT_RECEIVED: return "P2P_ENDPOINT_RECEIVED";
        case StateEvent::PUNCH_STARTED: return "PUNCH_STARTED";
        case StateEvent::PUNCH_SUCCESS: return "PUNCH_SUCCESS";
        case StateEvent::PUNCH_TIMEOUT: return "PUNCH_TIMEOUT";
        case StateEvent::P2P_KEEPALIVE_TIMEOUT: return "P2P_KEEPALIVE_TIMEOUT";
        case StateEvent::ROUTES_RECEIVED: return "ROUTES_RECEIVED";
        case StateEvent::ROUTES_APPLIED: return "ROUTES_APPLIED";
        case StateEvent::PEER_ONLINE: return "PEER_ONLINE";
        case StateEvent::PEER_OFFLINE: return "PEER_OFFLINE";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// ConnectionStateMachine 实现
// ============================================================================

ConnectionStateMachine::ConnectionStateMachine() = default;

void ConnectionStateMachine::set_callbacks(StateCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void ConnectionStateMachine::handle_event(StateEvent event) {
    log().debug("Global event: {}", state_event_name(event));

    switch (event) {
        // ========== 控制面事件 ==========
        case StateEvent::START_CONNECT:
            if (control_plane_ == ControlPlaneState::DISCONNECTED ||
                control_plane_ == ControlPlaneState::RECONNECTING) {
                set_control_plane_state(ControlPlaneState::CONNECTING);
            }
            break;

        case StateEvent::AUTH_SUCCESS:
            if (control_plane_ == ControlPlaneState::CONNECTING ||
                control_plane_ == ControlPlaneState::AUTHENTICATING) {
                set_control_plane_state(ControlPlaneState::CONFIGURING);
            }
            break;

        case StateEvent::AUTH_FAILED:
            set_control_plane_state(ControlPlaneState::DISCONNECTED);
            break;

        case StateEvent::CONFIG_RECEIVED:
            if (control_plane_ == ControlPlaneState::CONFIGURING) {
                set_control_plane_state(ControlPlaneState::READY);
            }
            break;

        case StateEvent::CONTROL_DISCONNECTED:
            if (control_plane_ == ControlPlaneState::READY) {
                set_control_plane_state(ControlPlaneState::RECONNECTING);
            } else {
                set_control_plane_state(ControlPlaneState::DISCONNECTED);
            }
            break;

        // 注意：RELAY_* 事件通过 handle_relay_event 处理

        // ========== 端点事件（控制面）==========
        case StateEvent::SOCKET_READY:
            if (endpoint_state_ == EndpointSyncState::NOT_READY) {
                set_endpoint_state(EndpointSyncState::DISCOVERING);
            }
            break;

        case StateEvent::STUN_SUCCESS:
        case StateEvent::STUN_FAILED:
            // STUN 成功或失败都进入 READY（使用可用的端点）
            if (endpoint_state_ == EndpointSyncState::DISCOVERING) {
                set_endpoint_state(EndpointSyncState::READY);
            }
            break;

        case StateEvent::ENDPOINT_UPLOADED:
            if (endpoint_state_ == EndpointSyncState::READY ||
                endpoint_state_ == EndpointSyncState::SYNCED) {
                set_endpoint_state(EndpointSyncState::UPLOADING);
            }
            break;

        case StateEvent::ENDPOINT_ACK:
            if (endpoint_state_ == EndpointSyncState::UPLOADING) {
                set_endpoint_state(EndpointSyncState::SYNCED);
            }
            break;

        // ========== 路由事件（控制面）==========
        case StateEvent::ROUTES_RECEIVED:
            if (route_state_ != RouteSyncState::DISABLED) {
                set_route_state(RouteSyncState::PENDING);
            }
            break;

        case StateEvent::ROUTES_APPLIED:
            if (route_state_ == RouteSyncState::PENDING ||
                route_state_ == RouteSyncState::SYNCING) {
                set_route_state(RouteSyncState::SYNCED);
            }
            break;

        default:
            break;
    }

    // 更新组合状态
    update_combined_phase();
}

void ConnectionStateMachine::handle_peer_event(NodeId peer_id, StateEvent event) {
    log().debug("Peer {} event: {}", peer_id, state_event_name(event));

    // 用于在锁外触发回调
    PeerP2PNegotiationState old_negotiation;
    PeerDataPath old_data_path;
    PeerLinkState old_link_state;
    PeerP2PNegotiationState new_negotiation;
    PeerDataPath new_data_path;
    PeerLinkState new_link_state;
    bool state_changed = false;

    {
        std::unique_lock lock(peers_mutex_);
        auto* state = get_peer_state_mut(peer_id);
        if (!state) {
            // 对于 PEER_ONLINE 事件，自动创建状态
            if (event == StateEvent::PEER_ONLINE) {
                peer_states_[peer_id] = PeerState{.peer_id = peer_id};
                state = &peer_states_[peer_id];
            } else {
                return;
            }
        }

        // 保存旧状态
        old_negotiation = state->negotiation_state;
        old_data_path = state->data_path;
        old_link_state = state->link_state;

        switch (event) {
            // ========== 对端在线/离线事件 ==========
            case StateEvent::PEER_ONLINE:
                if (state->data_path == PeerDataPath::UNREACHABLE) {
                    // 对端重新上线，通过 Relay 可达
                    state->data_path = PeerDataPath::RELAY;
                } else if (state->data_path == PeerDataPath::UNKNOWN) {
                    // 首次上线，默认通过 Relay
                    state->data_path = has_connected_relay_internal() ? PeerDataPath::RELAY : PeerDataPath::UNKNOWN;
                }
                break;

            case StateEvent::PEER_OFFLINE:
                state->negotiation_state = PeerP2PNegotiationState::IDLE;
                state->data_path = PeerDataPath::UNREACHABLE;
                break;

            // ========== 控制面事件（P2P 协商）==========
            case StateEvent::P2P_INIT_SENT:
                if (state->negotiation_state == PeerP2PNegotiationState::IDLE ||
                    state->negotiation_state == PeerP2PNegotiationState::FAILED) {
                    state->negotiation_state = PeerP2PNegotiationState::RESOLVING;
                    state->last_resolve_time = now_us();
                    state->init_seq = ++init_seq_;
                }
                break;

            case StateEvent::P2P_ENDPOINT_RECEIVED:
                if (state->negotiation_state == PeerP2PNegotiationState::RESOLVING ||
                    state->negotiation_state == PeerP2PNegotiationState::IDLE) {
                    state->negotiation_state = PeerP2PNegotiationState::PUNCHING;
                    state->last_endpoint_time = now_us();
                    state->last_punch_time = now_us();
                    state->punch_count = 0;
                }
                break;

            // ========== 数据面事件（P2P 连接）==========
            case StateEvent::PUNCH_STARTED:
                if (state->negotiation_state == PeerP2PNegotiationState::PUNCHING) {
                    state->last_punch_time = now_us();
                    state->punch_count++;
                }
                break;

            case StateEvent::PUNCH_SUCCESS:
                state->negotiation_state = PeerP2PNegotiationState::ESTABLISHED;
                state->data_path = PeerDataPath::P2P;
                state->last_recv_time = now_us();
                state->punch_failures = 0;
                break;

            case StateEvent::PUNCH_TIMEOUT:
                if (state->negotiation_state == PeerP2PNegotiationState::PUNCHING ||
                    state->negotiation_state == PeerP2PNegotiationState::RESOLVING) {
                    state->negotiation_state = PeerP2PNegotiationState::FAILED;
                    state->punch_failures++;
                    state->next_retry_time = now_us() + retry_interval_ms_ * 1000ULL;
                    // 回退到 Relay（如果可用）
                    if (has_connected_relay_internal()) {
                        state->data_path = PeerDataPath::RELAY;
                    }
                }
                break;

            case StateEvent::P2P_KEEPALIVE_TIMEOUT:
                if (state->data_path == PeerDataPath::P2P) {
                    state->negotiation_state = PeerP2PNegotiationState::FAILED;
                    // 回退到 Relay（如果可用）
                    state->data_path = has_connected_relay_internal() ? PeerDataPath::RELAY : PeerDataPath::UNREACHABLE;
                }
                break;

            default:
                break;
        }

        // 更新组合 link_state（在锁内）
        update_peer_link_state(peer_id);

        // 保存新状态用于锁外回调
        new_negotiation = state->negotiation_state;
        new_data_path = state->data_path;
        new_link_state = state->link_state;
        state_changed = (new_negotiation != old_negotiation ||
                         new_data_path != old_data_path ||
                         new_link_state != old_link_state);
    }
    // 锁已释放

    // 触发回调（在锁外，避免死锁）
    if (state_changed) {
        // 更新数据面状态
        update_data_plane_state();

        if (callbacks_.on_peer_state_change && new_link_state != old_link_state) {
            callbacks_.on_peer_state_change(peer_id, old_link_state, new_link_state);
        }

        if (callbacks_.on_peer_data_path_change && new_data_path != old_data_path) {
            callbacks_.on_peer_data_path_change(peer_id, old_data_path, new_data_path);
        }
    }
}

void ConnectionStateMachine::handle_relay_event(const std::string& relay_id, StateEvent event) {
    log().debug("Relay {} event: {}", relay_id, state_event_name(event));

    std::unique_lock lock(relays_mutex_);
    auto* info = get_relay_info_mut(relay_id);

    // 对于 RELAY_CONNECTING 事件，自动创建 Relay 状态
    if (!info) {
        if (event == StateEvent::RELAY_CONNECTING) {
            relay_states_[relay_id] = RelayInfo{.relay_id = relay_id};
            info = &relay_states_[relay_id];
        } else {
            return;
        }
    }

    auto old_state = info->state;

    switch (event) {
        case StateEvent::RELAY_CONNECTING:
            if (info->state == RelayConnectionState::DISCONNECTED ||
                info->state == RelayConnectionState::RECONNECTING) {
                info->state = RelayConnectionState::CONNECTING;
            }
            break;

        case StateEvent::RELAY_CONNECTED:
            info->state = RelayConnectionState::CONNECTED;
            info->last_connect_time = now_us();
            info->reconnect_count = 0;
            break;

        case StateEvent::RELAY_DISCONNECTED:
            info->state = RelayConnectionState::DISCONNECTED;
            break;

        case StateEvent::RELAY_RECONNECTING:
            if (info->state == RelayConnectionState::CONNECTED ||
                info->state == RelayConnectionState::DISCONNECTED) {
                info->state = RelayConnectionState::RECONNECTING;
                info->reconnect_count++;
            }
            break;

        default:
            break;
    }

    lock.unlock();

    // 触发回调并更新数据面状态
    if (info->state != old_state) {
        if (callbacks_.on_relay_state_change) {
            callbacks_.on_relay_state_change(relay_id, old_state, info->state);
        }
        update_data_plane_state();
    }
}

// ============================================================================
// 状态查询
// ============================================================================

PeerLinkState ConnectionStateMachine::get_peer_link_state(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        return it->second.link_state;
    }
    return PeerLinkState::UNKNOWN;
}

std::optional<PeerState> ConnectionStateMachine::get_peer_state(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::pair<NodeId, PeerState>> ConnectionStateMachine::get_all_peer_states() const {
    std::vector<std::pair<NodeId, PeerState>> result;
    std::shared_lock lock(peers_mutex_);
    result.reserve(peer_states_.size());
    for (const auto& [id, state] : peer_states_) {
        result.emplace_back(id, state);
    }
    return result;
}

bool ConnectionStateMachine::is_peer_p2p_ready(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    auto it = peer_states_.find(peer_id);
    return it != peer_states_.end() && it->second.link_state == PeerLinkState::P2P_ACTIVE;
}

std::vector<NodeId> ConnectionStateMachine::get_peers_for_retry() const {
    std::vector<NodeId> result;
    uint64_t now = now_us();
    uint64_t retry_threshold = retry_interval_ms_ * 1000ULL;

    std::shared_lock lock(peers_mutex_);
    for (const auto& [id, state] : peer_states_) {
        if (state.link_state == PeerLinkState::RELAY_FALLBACK) {
            // 检查是否到达重试时间
            uint64_t last_attempt = std::max(state.last_resolve_time, state.last_punch_time);
            if (now - last_attempt >= retry_threshold) {
                result.push_back(id);
            }
        }
    }
    return result;
}

std::vector<NodeId> ConnectionStateMachine::get_peers_for_keepalive() const {
    std::vector<NodeId> result;
    std::shared_lock lock(peers_mutex_);
    for (const auto& [id, state] : peer_states_) {
        if (state.link_state == PeerLinkState::P2P_ACTIVE) {
            result.push_back(id);
        }
    }
    return result;
}

std::optional<RelayInfo> ConnectionStateMachine::get_relay_info(const std::string& relay_id) const {
    std::shared_lock lock(relays_mutex_);
    auto it = relay_states_.find(relay_id);
    if (it != relay_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<RelayInfo> ConnectionStateMachine::get_all_relay_info() const {
    std::vector<RelayInfo> result;
    std::shared_lock lock(relays_mutex_);
    result.reserve(relay_states_.size());
    for (const auto& [id, info] : relay_states_) {
        result.push_back(info);
    }
    return result;
}

bool ConnectionStateMachine::has_connected_relay() const {
    std::shared_lock lock(relays_mutex_);
    for (const auto& [id, info] : relay_states_) {
        if (info.is_connected()) {
            return true;
        }
    }
    return false;
}

size_t ConnectionStateMachine::connected_relay_count() const {
    size_t count = 0;
    std::shared_lock lock(relays_mutex_);
    for (const auto& [id, info] : relay_states_) {
        if (info.is_connected()) {
            count++;
        }
    }
    return count;
}

std::optional<std::string> ConnectionStateMachine::get_primary_relay() const {
    std::shared_lock lock(relays_mutex_);
    if (!primary_relay_id_.empty()) {
        return primary_relay_id_;
    }
    // 如果没有设置主 Relay，返回第一个已连接的 Relay
    for (const auto& [id, info] : relay_states_) {
        if (info.is_connected()) {
            return id;
        }
    }
    return std::nullopt;
}

// ============================================================================
// Relay 管理
// ============================================================================

void ConnectionStateMachine::add_relay(const std::string& relay_id, bool is_primary) {
    std::unique_lock lock(relays_mutex_);
    if (relay_states_.find(relay_id) == relay_states_.end()) {
        relay_states_[relay_id] = RelayInfo{.relay_id = relay_id, .is_primary = is_primary};
        if (is_primary || primary_relay_id_.empty()) {
            primary_relay_id_ = relay_id;
        }
        log().debug("Added relay: {} (primary: {})", relay_id, is_primary);
    }
}

void ConnectionStateMachine::remove_relay(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    auto it = relay_states_.find(relay_id);
    if (it != relay_states_.end()) {
        auto old_state = it->second.state;
        relay_states_.erase(it);

        // 如果移除的是主 Relay，选择新的主 Relay
        if (primary_relay_id_ == relay_id) {
            primary_relay_id_.clear();
            for (const auto& [id, info] : relay_states_) {
                if (info.is_connected()) {
                    primary_relay_id_ = id;
                    break;
                }
            }
        }

        lock.unlock();
        log().debug("Removed relay: {}", relay_id);

        if (old_state != RelayConnectionState::DISCONNECTED && callbacks_.on_relay_state_change) {
            callbacks_.on_relay_state_change(relay_id, old_state, RelayConnectionState::DISCONNECTED);
        }
        update_data_plane_state();
    }
}

void ConnectionStateMachine::set_primary_relay(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    auto it = relay_states_.find(relay_id);
    if (it != relay_states_.end()) {
        // 清除旧的 primary 标记
        for (auto& [id, info] : relay_states_) {
            info.is_primary = (id == relay_id);
        }
        primary_relay_id_ = relay_id;
        log().debug("Set primary relay: {}", relay_id);
    }
}

void ConnectionStateMachine::update_relay_latency(const std::string& relay_id, uint16_t latency_ms) {
    std::unique_lock lock(relays_mutex_);
    auto* info = get_relay_info_mut(relay_id);
    if (info) {
        info->latency_ms = latency_ms;
    }
}

void ConnectionStateMachine::record_relay_recv(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    auto* info = get_relay_info_mut(relay_id);
    if (info) {
        info->last_recv_time = now_us();
    }
}

void ConnectionStateMachine::record_relay_send(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    auto* info = get_relay_info_mut(relay_id);
    if (info) {
        info->last_send_time = now_us();
    }
}

// ============================================================================
// 对端管理
// ============================================================================

void ConnectionStateMachine::add_peer(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    if (peer_states_.find(peer_id) == peer_states_.end()) {
        peer_states_[peer_id] = PeerState{.peer_id = peer_id};
        log().debug("Added peer {}", peer_id);
    }
}

void ConnectionStateMachine::remove_peer(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        auto old_state = it->second.link_state;
        peer_states_.erase(it);
        lock.unlock();

        log().debug("Removed peer {}", peer_id);

        if (old_state != PeerLinkState::UNKNOWN && callbacks_.on_peer_state_change) {
            callbacks_.on_peer_state_change(peer_id, old_state, PeerLinkState::OFFLINE);
        }
    }
}

void ConnectionStateMachine::update_peer_endpoints(NodeId peer_id,
                                                    const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (state) {
        state->peer_endpoints = endpoints;
    }
}

void ConnectionStateMachine::update_peer_active_connection(NodeId peer_id,
                                                            const std::array<uint8_t, 16>& addr,
                                                            uint16_t port,
                                                            bool is_p2p) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (state) {
        state->p2p_addr = addr;
        state->p2p_port = port;
        // 根据 is_p2p 更新数据路径
        if (is_p2p && state->data_path != PeerDataPath::P2P) {
            auto old_path = state->data_path;
            state->data_path = PeerDataPath::P2P;
            lock.unlock();

            if (callbacks_.on_peer_data_path_change) {
                callbacks_.on_peer_data_path_change(peer_id, old_path, PeerDataPath::P2P);
            }
            update_data_plane_state();
        }
    }
}

void ConnectionStateMachine::update_peer_latency(NodeId peer_id, uint16_t latency_ms) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (state) {
        state->latency_ms = latency_ms;
    }
}

void ConnectionStateMachine::record_peer_recv(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (state) {
        state->last_recv_time = now_us();
    }
}

void ConnectionStateMachine::record_peer_send(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (state) {
        state->last_send_time = now_us();
    }
}

// ============================================================================
// 超时检测
// ============================================================================

void ConnectionStateMachine::check_timeouts() {
    uint64_t now = now_us();

    std::vector<std::pair<NodeId, StateEvent>> events;

    {
        std::shared_lock lock(peers_mutex_);
        for (const auto& [id, state] : peer_states_) {
            switch (state.link_state) {
                case PeerLinkState::RESOLVING:
                    if (state.last_resolve_time > 0 &&
                        now - state.last_resolve_time > resolve_timeout_ms_ * 1000ULL) {
                        events.emplace_back(id, StateEvent::PUNCH_TIMEOUT);
                    }
                    break;

                case PeerLinkState::PUNCHING:
                    if (state.last_punch_time > 0 &&
                        now - state.last_punch_time > punch_timeout_ms_ * 1000ULL) {
                        events.emplace_back(id, StateEvent::PUNCH_TIMEOUT);
                    }
                    break;

                case PeerLinkState::P2P_ACTIVE:
                    if (state.last_recv_time > 0 &&
                        now - state.last_recv_time > keepalive_timeout_ms_ * 1000ULL) {
                        events.emplace_back(id, StateEvent::P2P_KEEPALIVE_TIMEOUT);
                    }
                    break;

                default:
                    break;
            }
        }
    }

    // 在锁外处理事件，避免死锁
    for (const auto& [peer_id, event] : events) {
        handle_peer_event(peer_id, event);
    }
}

uint64_t ConnectionStateMachine::now_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

// ============================================================================
// 重置
// ============================================================================

void ConnectionStateMachine::reset() {
    set_phase(ConnectionPhase::OFFLINE);
    set_endpoint_state(EndpointSyncState::NOT_READY);
    set_route_state(RouteSyncState::DISABLED);

    {
        std::unique_lock lock(peers_mutex_);
        peer_states_.clear();
    }

    log().info("State machine reset");
}

void ConnectionStateMachine::reset_peer(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        auto old_state = it->second.link_state;
        it->second = PeerState{.peer_id = peer_id};
        lock.unlock();

        if (old_state != PeerLinkState::UNKNOWN && callbacks_.on_peer_state_change) {
            callbacks_.on_peer_state_change(peer_id, old_state, PeerLinkState::UNKNOWN);
        }
    }
}

// ============================================================================
// 内部方法
// ============================================================================

void ConnectionStateMachine::set_phase(ConnectionPhase new_phase) {
    ConnectionPhase old_phase = phase_.exchange(new_phase);
    if (old_phase != new_phase) {
        log().info("Connection phase: {} -> {}",
                   connection_phase_name(old_phase), connection_phase_name(new_phase));

        if (callbacks_.on_phase_change) {
            callbacks_.on_phase_change(old_phase, new_phase);
        }
    }
}

void ConnectionStateMachine::set_endpoint_state(EndpointSyncState new_state) {
    EndpointSyncState old_state = endpoint_state_.exchange(new_state);
    if (old_state != new_state) {
        log().debug("Endpoint state: {} -> {}",
                    endpoint_sync_state_name(old_state), endpoint_sync_state_name(new_state));

        if (callbacks_.on_endpoint_state_change) {
            callbacks_.on_endpoint_state_change(old_state, new_state);
        }
    }
}

void ConnectionStateMachine::set_route_state(RouteSyncState new_state) {
    RouteSyncState old_state = route_state_.exchange(new_state);
    if (old_state != new_state) {
        log().debug("Route state: {} -> {}",
                    route_sync_state_name(old_state), route_sync_state_name(new_state));

        if (callbacks_.on_route_state_change) {
            callbacks_.on_route_state_change(old_state, new_state);
        }
    }
}

void ConnectionStateMachine::set_control_plane_state(ControlPlaneState new_state) {
    ControlPlaneState old_state = control_plane_.exchange(new_state);
    if (old_state != new_state) {
        log().info("Control plane: {} -> {}",
                   control_plane_state_name(old_state), control_plane_state_name(new_state));

        if (callbacks_.on_control_plane_change) {
            callbacks_.on_control_plane_change(old_state, new_state);
        }

        // 控制面状态变化后更新组合阶段
        update_combined_phase();
    }
}

void ConnectionStateMachine::set_data_plane_state(DataPlaneState new_state) {
    DataPlaneState old_state = data_plane_.exchange(new_state);
    if (old_state != new_state) {
        log().info("Data plane: {} -> {}",
                   data_plane_state_name(old_state), data_plane_state_name(new_state));

        if (callbacks_.on_data_plane_change) {
            callbacks_.on_data_plane_change(old_state, new_state);
        }

        // 数据面状态变化后更新组合阶段
        update_combined_phase();
    }
}

void ConnectionStateMachine::set_peer_data_path(NodeId peer_id, PeerDataPath new_path) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (!state) {
        return;
    }

    PeerDataPath old_path = state->data_path;
    if (old_path != new_path) {
        state->data_path = new_path;
        lock.unlock();

        log().debug("Peer {} data path: {} -> {}",
                    peer_id, peer_data_path_name(old_path), peer_data_path_name(new_path));

        if (callbacks_.on_peer_data_path_change) {
            callbacks_.on_peer_data_path_change(peer_id, old_path, new_path);
        }

        // 数据路径变化后更新数据面状态
        update_data_plane_state();
    }
}

void ConnectionStateMachine::update_combined_phase() {
    ControlPlaneState ctrl = control_plane_.load();
    DataPlaneState data = data_plane_.load();

    ConnectionPhase new_phase = ConnectionPhase::OFFLINE;

    switch (ctrl) {
        case ControlPlaneState::DISCONNECTED:
            new_phase = ConnectionPhase::OFFLINE;
            break;

        case ControlPlaneState::CONNECTING:
        case ControlPlaneState::AUTHENTICATING:
            new_phase = ConnectionPhase::AUTHENTICATING;
            break;

        case ControlPlaneState::CONFIGURING:
            new_phase = ConnectionPhase::CONFIGURING;
            break;

        case ControlPlaneState::READY:
            // 控制面就绪后，根据数据面状态决定组合阶段
            if (data == DataPlaneState::OFFLINE) {
                new_phase = ConnectionPhase::ESTABLISHING;
            } else {
                new_phase = ConnectionPhase::ONLINE;
            }
            break;

        case ControlPlaneState::RECONNECTING:
            new_phase = ConnectionPhase::RECONNECTING;
            break;
    }

    set_phase(new_phase);
}

void ConnectionStateMachine::update_data_plane_state() {
    bool relay = has_connected_relay_internal();

    // 统计 P2P 已连接的对端数
    uint32_t p2p_count = 0;
    uint32_t total_peers = 0;
    {
        std::shared_lock lock(peers_mutex_);
        for (const auto& [id, state] : peer_states_) {
            if (state.data_path != PeerDataPath::UNREACHABLE &&
                state.data_path != PeerDataPath::UNKNOWN) {
                total_peers++;
                if (state.data_path == PeerDataPath::P2P) {
                    p2p_count++;
                }
            }
        }
    }
    p2p_peer_count_ = p2p_count;

    DataPlaneState new_state;

    if (!relay && p2p_count == 0) {
        new_state = DataPlaneState::OFFLINE;
    } else if (relay && p2p_count == 0) {
        new_state = DataPlaneState::RELAY_ONLY;
    } else if (relay && p2p_count > 0) {
        new_state = DataPlaneState::HYBRID;
    } else {
        // !relay && p2p_count > 0
        new_state = DataPlaneState::DEGRADED;
    }

    set_data_plane_state(new_state);
}

void ConnectionStateMachine::update_peer_link_state(NodeId peer_id) {
    // 注意：调用者应该已经持有 peers_mutex_ 锁
    // 此函数只更新状态，不调用回调（回调由调用者在锁外处理）
    auto* state = get_peer_state_mut(peer_id);
    if (!state) {
        return;
    }

    PeerLinkState old_link = state->link_state;
    PeerLinkState new_link = PeerLinkState::UNKNOWN;

    // 根据协商状态和数据路径计算组合 link_state
    switch (state->negotiation_state) {
        case PeerP2PNegotiationState::IDLE:
            if (state->data_path == PeerDataPath::RELAY) {
                new_link = PeerLinkState::RELAY_FALLBACK;
            } else if (state->data_path == PeerDataPath::UNREACHABLE) {
                new_link = PeerLinkState::OFFLINE;
            } else {
                new_link = PeerLinkState::UNKNOWN;
            }
            break;

        case PeerP2PNegotiationState::RESOLVING:
            new_link = PeerLinkState::RESOLVING;
            break;

        case PeerP2PNegotiationState::PUNCHING:
            new_link = PeerLinkState::PUNCHING;
            break;

        case PeerP2PNegotiationState::ESTABLISHED:
            if (state->data_path == PeerDataPath::P2P) {
                new_link = PeerLinkState::P2P_ACTIVE;
            } else {
                // 协商成功但数据路径不是 P2P（异常状态）
                new_link = PeerLinkState::RELAY_FALLBACK;
            }
            break;

        case PeerP2PNegotiationState::FAILED:
            if (state->data_path == PeerDataPath::RELAY) {
                new_link = PeerLinkState::RELAY_FALLBACK;
            } else if (state->data_path == PeerDataPath::UNREACHABLE) {
                new_link = PeerLinkState::OFFLINE;
            } else {
                new_link = PeerLinkState::RELAY_FALLBACK;
            }
            break;
    }

    if (old_link != new_link) {
        state->link_state = new_link;

        log().info("Peer {} link state: {} -> {}",
                   peer_id, peer_link_state_name(old_link), peer_link_state_name(new_link));

        // 注意：不在此处调用回调，由调用者在锁外处理
        // on_peer_state_change 回调已由 handle_peer_event 负责
    }
}

void ConnectionStateMachine::set_peer_link_state(NodeId peer_id, PeerLinkState new_state) {
    std::unique_lock lock(peers_mutex_);
    auto* state = get_peer_state_mut(peer_id);
    if (!state) {
        return;
    }

    PeerLinkState old_state = state->link_state;
    if (old_state != new_state) {
        state->link_state = new_state;
        lock.unlock();

        log().info("Peer {} state: {} -> {}",
                   peer_id, peer_link_state_name(old_state), peer_link_state_name(new_state));

        if (callbacks_.on_peer_state_change) {
            callbacks_.on_peer_state_change(peer_id, old_state, new_state);
        }
    }
}

PeerState* ConnectionStateMachine::get_peer_state_mut(NodeId peer_id) {
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        return &it->second;
    }
    return nullptr;
}

RelayInfo* ConnectionStateMachine::get_relay_info_mut(const std::string& relay_id) {
    auto it = relay_states_.find(relay_id);
    if (it != relay_states_.end()) {
        return &it->second;
    }
    return nullptr;
}

void ConnectionStateMachine::set_relay_state(const std::string& relay_id, RelayConnectionState new_state) {
    std::unique_lock lock(relays_mutex_);
    auto* info = get_relay_info_mut(relay_id);
    if (!info) {
        return;
    }

    RelayConnectionState old_state = info->state;
    if (old_state != new_state) {
        info->state = new_state;
        if (new_state == RelayConnectionState::CONNECTED) {
            info->last_connect_time = now_us();
        }
        lock.unlock();

        log().info("Relay {} state: {} -> {}",
                   relay_id, relay_connection_state_name(old_state), relay_connection_state_name(new_state));

        if (callbacks_.on_relay_state_change) {
            callbacks_.on_relay_state_change(relay_id, old_state, new_state);
        }

        update_data_plane_state();
    }
}

bool ConnectionStateMachine::has_connected_relay_internal() const {
    std::shared_lock lock(relays_mutex_);
    for (const auto& [id, info] : relay_states_) {
        if (info.is_connected()) {
            return true;
        }
    }
    return false;
}

} // namespace edgelink::client

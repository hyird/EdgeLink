#include "common/node_state.hpp"
#include "common/logger.hpp"
#include "common/cobalt_utils.hpp"
#include <algorithm>
#include <chrono>

namespace edgelink {

namespace {
auto& log() { return Logger::get("node_state"); }
}  // anonymous namespace

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
// ControllerStateMachine 实现
// ============================================================================

ControllerStateMachine::ControllerStateMachine(asio::io_context& ioc)
    : ioc_(ioc) {
}

void ControllerStateMachine::add_node(NodeId node_id, NetworkId network_id) {
    std::unique_lock lock(nodes_mutex_);
    if (nodes_.find(node_id) == nodes_.end()) {
        ControllerNodeView node;
        node.node_id = node_id;
        node.network_id = network_id;
        node.last_seen_time = now_us();
        nodes_[node_id] = node;
        log().debug("Controller: Added node {} (network={})", node_id, network_id);
    }
}

void ControllerStateMachine::remove_node(NodeId node_id) {
    NetworkId network_id = 0;
    bool was_online = false;

    {
        std::unique_lock lock(nodes_mutex_);
        auto it = nodes_.find(node_id);
        if (it != nodes_.end()) {
            was_online = it->second.is_online();
            network_id = it->second.network_id;
            nodes_.erase(it);
            log().debug("Controller: Removed node {}", node_id);
        }
    }

    if (was_online) {
        notify_client_offline(node_id, network_id);
    }
}

std::optional<ControllerNodeView> ControllerStateMachine::get_node_view(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<NodeId> ControllerStateMachine::get_network_nodes(NetworkId network_id) const {
    std::vector<NodeId> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [id, node] : nodes_) {
        if (node.network_id == network_id) {
            result.push_back(id);
        }
    }
    return result;
}

std::vector<NodeId> ControllerStateMachine::get_online_nodes() const {
    std::vector<NodeId> result;
    std::shared_lock lock(nodes_mutex_);
    for (const auto& [id, node] : nodes_) {
        if (node.is_online()) {
            result.push_back(id);
        }
    }
    return result;
}

void ControllerStateMachine::handle_auth_request(NodeId node_id, NetworkId network_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (!node) {
        ControllerNodeView new_node;
        new_node.node_id = node_id;
        new_node.network_id = network_id;
        new_node.last_seen_time = now_us();
        nodes_[node_id] = new_node;
        node = &nodes_[node_id];
    }
    node->session_state = ClientSessionState::AUTHENTICATING;
    log().debug("Controller: Node {} auth request", node_id);
}

void ControllerStateMachine::handle_auth_result(NodeId node_id, bool success) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (!node) return;

    auto old_state = node->session_state;
    node->session_state = success ? ClientSessionState::AUTHENTICATED : ClientSessionState::DISCONNECTED;

    log().info("Controller: Node {} auth {}: {} -> {}",
               node_id, success ? "success" : "failed",
               client_session_state_name(old_state),
               client_session_state_name(node->session_state));
}

void ControllerStateMachine::mark_config_sent(NodeId node_id, uint64_t config_version) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (!node) return;

    node->config_version = config_version;
    node->config_acked = false;
    node->config_send_time = now_us();

    if (node->session_state == ClientSessionState::AUTHENTICATED) {
        auto old_state = node->session_state;
        node->session_state = ClientSessionState::CONFIGURING;
        log().info("Controller: Node {} session: {} -> CONFIGURING",
                   node_id, client_session_state_name(old_state));
    }
}

void ControllerStateMachine::mark_config_acked(NodeId node_id) {
    NetworkId network_id = 0;
    bool became_online = false;

    {
        std::unique_lock lock(nodes_mutex_);
        auto* node = get_node_view_mut(node_id);
        if (!node) return;

        node->config_acked = true;
        network_id = node->network_id;

        // 检查是否变为在线状态
        if (node->session_state == ClientSessionState::CONFIGURING &&
            node->relay_state == RelaySessionState::CONNECTED) {
            auto old_state = node->session_state;
            node->session_state = ClientSessionState::ONLINE;
            became_online = true;
            log().info("Controller: Node {} session: {} -> ONLINE",
                       node_id, client_session_state_name(old_state));
        }
    }

    if (became_online) {
        notify_client_online(node_id, network_id);
    }
}

void ControllerStateMachine::set_session_state(NodeId node_id, ClientSessionState state) {
    NetworkId network_id = 0;
    bool became_online = false;
    bool went_offline = false;

    {
        std::unique_lock lock(nodes_mutex_);
        auto* node = get_node_view_mut(node_id);
        if (!node) return;

        auto old_state = node->session_state;
        if (old_state == state) return;

        node->session_state = state;
        network_id = node->network_id;

        log().info("Controller: Node {} session: {} -> {}",
                   node_id, client_session_state_name(old_state),
                   client_session_state_name(state));

        became_online = (old_state != ClientSessionState::ONLINE && state == ClientSessionState::ONLINE);
        went_offline = (old_state == ClientSessionState::ONLINE && state != ClientSessionState::ONLINE);
    }

    if (became_online) {
        notify_client_online(node_id, network_id);
    } else if (went_offline) {
        notify_client_offline(node_id, network_id);
    }
}

void ControllerStateMachine::set_relay_session_state(NodeId node_id, RelaySessionState state) {
    NetworkId network_id = 0;
    bool became_online = false;

    {
        std::unique_lock lock(nodes_mutex_);
        auto* node = get_node_view_mut(node_id);
        if (!node) return;

        auto old_state = node->relay_state;
        if (old_state == state) return;

        node->relay_state = state;
        network_id = node->network_id;

        log().info("Controller: Node {} relay: {} -> {}",
                   node_id, relay_session_state_name(old_state),
                   relay_session_state_name(state));

        // 检查是否变为在线状态
        if (state == RelaySessionState::CONNECTED &&
            node->config_acked &&
            node->session_state != ClientSessionState::ONLINE) {
            auto old_session = node->session_state;
            node->session_state = ClientSessionState::ONLINE;
            became_online = true;
            log().info("Controller: Node {} session: {} -> ONLINE",
                       node_id, client_session_state_name(old_session));
        }
    }

    if (became_online) {
        notify_client_online(node_id, network_id);
    }
}

void ControllerStateMachine::update_node_endpoints(NodeId node_id, const std::vector<Endpoint>& endpoints) {
    {
        std::unique_lock lock(nodes_mutex_);
        auto* node = get_node_view_mut(node_id);
        if (!node) return;

        node->endpoints = endpoints;
        node->endpoint_update_time = now_us();
        node->endpoint_state = EndpointState::SYNCED;
    }

    log().debug("Controller: Updated {} endpoints for node {}", endpoints.size(), node_id);
    notify_endpoint_update(node_id, endpoints);
}

std::vector<Endpoint> ControllerStateMachine::get_node_endpoints(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        return it->second.endpoints;
    }
    return {};
}

void ControllerStateMachine::update_node_routes(NodeId node_id,
                                                  const std::vector<RouteInfo>& add_routes,
                                                  const std::vector<RouteInfo>& del_routes) {
    {
        std::unique_lock lock(nodes_mutex_);
        auto* node = get_node_view_mut(node_id);
        if (!node) return;

        // 删除路由
        for (const auto& del : del_routes) {
            node->announced_routes.erase(
                std::remove_if(node->announced_routes.begin(), node->announced_routes.end(),
                    [&del](const RouteInfo& r) {
                        return r.ip_type == del.ip_type &&
                               r.prefix == del.prefix &&
                               r.prefix_len == del.prefix_len;
                    }),
                node->announced_routes.end());
        }

        // 添加路由
        for (const auto& add : add_routes) {
            node->announced_routes.push_back(add);
        }

        node->route_update_time = now_us();
    }

    if (!add_routes.empty() || !del_routes.empty()) {
        notify_route_change(node_id, add_routes, del_routes);
    }
}

std::vector<RouteInfo> ControllerStateMachine::get_node_routes(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        return it->second.announced_routes;
    }
    return {};
}

void ControllerStateMachine::handle_p2p_init(NodeId initiator, NodeId responder, uint32_t seq) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(initiator);
    if (!node) return;

    auto& negotiation = node->p2p_negotiations[responder];
    negotiation.peer_id = responder;
    negotiation.phase = P2PNegotiationPhase::INITIATED;
    negotiation.init_seq = seq;
    negotiation.init_time = now_us();

    log().debug("Controller: P2P negotiation {} -> {}: INITIATED (seq={})",
               initiator, responder, seq);
}

void ControllerStateMachine::mark_p2p_endpoint_sent(NodeId node_id, NodeId peer_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (!node) return;

    auto it = node->p2p_negotiations.find(peer_id);
    if (it != node->p2p_negotiations.end()) {
        it->second.phase = P2PNegotiationPhase::ENDPOINTS_SENT;
        it->second.endpoint_send_time = now_us();
        log().debug("Controller: P2P negotiation {} -> {}: ENDPOINTS_SENT", node_id, peer_id);
    }
}

void ControllerStateMachine::handle_p2p_status(NodeId node_id, NodeId peer_id, bool success) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (!node) return;

    auto it = node->p2p_negotiations.find(peer_id);
    if (it != node->p2p_negotiations.end()) {
        it->second.phase = success ? P2PNegotiationPhase::ESTABLISHED : P2PNegotiationPhase::FAILED;
        log().debug("Controller: P2P negotiation {} -> {}: {}",
                   node_id, peer_id, p2p_negotiation_phase_name(it->second.phase));
    }
}

void ControllerStateMachine::record_ping(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (node) {
        auto now = now_us();
        node->last_ping_time = now;
        node->last_seen_time = now;
    }
}

void ControllerStateMachine::record_pong(NodeId node_id, uint16_t latency_ms) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (node) {
        node->last_seen_time = now_us();
        node->latency_ms = latency_ms;
    }
}

void ControllerStateMachine::record_activity(NodeId node_id) {
    std::unique_lock lock(nodes_mutex_);
    auto* node = get_node_view_mut(node_id);
    if (node) {
        node->last_seen_time = now_us();
    }
}

void ControllerStateMachine::check_timeouts() {
    uint64_t now = now_us();
    std::vector<std::pair<NodeId, NetworkId>> timed_out;

    {
        std::shared_lock lock(nodes_mutex_);
        for (const auto& [node_id, node] : nodes_) {
            // 心跳超时检测
            if (node.is_online() && node.last_seen_time > 0) {
                auto elapsed_ms = (now - node.last_seen_time) / 1000;
                if (elapsed_ms > static_cast<uint64_t>(heartbeat_timeout_.count())) {
                    timed_out.emplace_back(node_id, node.network_id);
                }
            }
        }
    }

    // 处理超时
    for (const auto& [node_id, network_id] : timed_out) {
        set_session_state(node_id, ClientSessionState::DEGRADED);
    }
}

bool ControllerStateMachine::is_node_online(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = nodes_.find(node_id);
    return it != nodes_.end() && it->second.is_online();
}

bool ControllerStateMachine::has_node_relay(NodeId node_id) const {
    std::shared_lock lock(nodes_mutex_);
    auto it = nodes_.find(node_id);
    return it != nodes_.end() && it->second.has_relay();
}

uint64_t ControllerStateMachine::now_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

void ControllerStateMachine::notify_client_online(NodeId node_id, NetworkId network_id) {
    if (client_online_channel_) {
        cobalt_utils::fire_write(*client_online_channel_, ClientOnlineEvent{node_id, network_id}, ioc_.get_executor());
    }
}

void ControllerStateMachine::notify_client_offline(NodeId node_id, NetworkId network_id) {
    if (client_offline_channel_) {
        cobalt_utils::fire_write(*client_offline_channel_, ClientOfflineEvent{node_id, network_id}, ioc_.get_executor());
    }
}

void ControllerStateMachine::notify_endpoint_update(NodeId node_id, const std::vector<Endpoint>& endpoints) {
    if (endpoint_update_channel_) {
        cobalt_utils::fire_write(*endpoint_update_channel_, EndpointUpdateEvent{node_id, endpoints}, ioc_.get_executor());
    }
}

void ControllerStateMachine::notify_route_change(NodeId node_id,
                                                   const std::vector<RouteInfo>& added,
                                                   const std::vector<RouteInfo>& removed) {
    if (route_change_channel_) {
        cobalt_utils::fire_write(*route_change_channel_, RouteChangeEvent{node_id, added, removed}, ioc_.get_executor());
    }
}

ControllerNodeView* ControllerStateMachine::get_node_view_mut(NodeId node_id) {
    auto it = nodes_.find(node_id);
    if (it != nodes_.end()) {
        return &it->second;
    }
    return nullptr;
}

// ============================================================================
// ClientStateMachine 实现
// ============================================================================

ClientStateMachine::ClientStateMachine(asio::io_context& ioc)
    : ioc_(ioc) {
}

void ClientStateMachine::set_node_id(NodeId node_id) {
    std::unique_lock lock(self_mutex_);
    state_.node_id = node_id;
}

NodeId ClientStateMachine::node_id() const {
    std::shared_lock lock(self_mutex_);
    return state_.node_id;
}

void ClientStateMachine::set_network_id(NetworkId network_id) {
    std::unique_lock lock(self_mutex_);
    state_.network_id = network_id;
}

NetworkId ClientStateMachine::network_id() const {
    std::shared_lock lock(self_mutex_);
    return state_.network_id;
}

void ClientStateMachine::set_virtual_ip(const IPv4Address& ip) {
    std::unique_lock lock(self_mutex_);
    state_.virtual_ip = ip;
}

IPv4Address ClientStateMachine::virtual_ip() const {
    std::shared_lock lock(self_mutex_);
    return state_.virtual_ip;
}

void ClientStateMachine::set_control_plane_state(ControlPlaneState state) {
    ConnectionPhase old_phase, new_phase;

    {
        std::unique_lock lock(self_mutex_);
        auto old_state = state_.control_plane;
        if (old_state == state) return;

        state_.control_plane = state;
        log().info("Client: Control plane: {} -> {}",
                   control_plane_state_name(old_state),
                   control_plane_state_name(state));

        // 计算新的连接阶段
        old_phase = state_.connection_phase;
        new_phase = calculate_connection_phase();
        if (old_phase != new_phase) {
            state_.connection_phase = new_phase;
            log().info("Client: Connection phase: {} -> {}",
                       connection_phase_name(old_phase),
                       connection_phase_name(new_phase));
        }
    }

    if (old_phase != new_phase) {
        notify_phase_change(old_phase, new_phase);
    }
}

ControlPlaneState ClientStateMachine::control_plane_state() const {
    std::shared_lock lock(self_mutex_);
    return state_.control_plane;
}

bool ClientStateMachine::is_control_ready() const {
    std::shared_lock lock(self_mutex_);
    return state_.is_control_ready();
}

void ClientStateMachine::set_data_plane_state(DataPlaneState state) {
    ConnectionPhase old_phase, new_phase;

    {
        std::unique_lock lock(self_mutex_);
        auto old_state = state_.data_plane;
        if (old_state == state) return;

        state_.data_plane = state;
        log().info("Client: Data plane: {} -> {}",
                   data_plane_state_name(old_state),
                   data_plane_state_name(state));

        // 计算新的连接阶段
        old_phase = state_.connection_phase;
        new_phase = calculate_connection_phase();
        if (old_phase != new_phase) {
            state_.connection_phase = new_phase;
            log().info("Client: Connection phase: {} -> {}",
                       connection_phase_name(old_phase),
                       connection_phase_name(new_phase));
        }
    }

    if (old_phase != new_phase) {
        notify_phase_change(old_phase, new_phase);
    }
}

DataPlaneState ClientStateMachine::data_plane_state() const {
    std::shared_lock lock(self_mutex_);
    return state_.data_plane;
}

bool ClientStateMachine::has_data_path() const {
    std::shared_lock lock(self_mutex_);
    return state_.has_data_path();
}

void ClientStateMachine::update_data_plane_state() {
    bool has_relay = false;
    size_t p2p_count = 0;

    {
        std::shared_lock relay_lock(relays_mutex_);
        has_relay = state_.has_connected_relay();
    }

    {
        std::shared_lock peers_lock(peers_mutex_);
        for (const auto& [peer_id, conn] : state_.peer_connections) {
            if (conn.data_path == PeerDataPath::P2P) {
                ++p2p_count;
            }
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

    set_data_plane_state(new_state);
}

void ClientStateMachine::set_connection_phase(ConnectionPhase phase) {
    ConnectionPhase old_phase;

    {
        std::unique_lock lock(self_mutex_);
        old_phase = state_.connection_phase;
        if (old_phase == phase) return;

        state_.connection_phase = phase;
        log().info("Client: Connection phase: {} -> {}",
                   connection_phase_name(old_phase),
                   connection_phase_name(phase));
    }

    notify_phase_change(old_phase, phase);
}

ConnectionPhase ClientStateMachine::connection_phase() const {
    std::shared_lock lock(self_mutex_);
    return state_.connection_phase;
}

bool ClientStateMachine::is_connected() const {
    std::shared_lock lock(self_mutex_);
    return state_.connection_phase == ConnectionPhase::ONLINE;
}

void ClientStateMachine::update_connection_phase() {
    ConnectionPhase old_phase, new_phase;

    {
        std::unique_lock lock(self_mutex_);
        old_phase = state_.connection_phase;
        new_phase = calculate_connection_phase();
        if (old_phase == new_phase) return;

        state_.connection_phase = new_phase;
        log().info("Client: Connection phase: {} -> {}",
                   connection_phase_name(old_phase),
                   connection_phase_name(new_phase));
    }

    notify_phase_change(old_phase, new_phase);
}

ConnectionPhase ClientStateMachine::calculate_connection_phase() const {
    // 注意：调用此方法时必须已持有 self_mutex_
    auto control = state_.control_plane;
    auto data = state_.data_plane;

    if (control == ControlPlaneState::DISCONNECTED) {
        return ConnectionPhase::OFFLINE;
    } else if (control == ControlPlaneState::CONNECTING ||
               control == ControlPlaneState::AUTHENTICATING) {
        return ConnectionPhase::AUTHENTICATING;
    } else if (control == ControlPlaneState::CONFIGURING) {
        return ConnectionPhase::CONFIGURING;
    } else if (control == ControlPlaneState::READY) {
        if (data == DataPlaneState::OFFLINE) {
            return ConnectionPhase::ESTABLISHING;
        } else {
            return ConnectionPhase::ONLINE;
        }
    } else if (control == ControlPlaneState::RECONNECTING) {
        return ConnectionPhase::RECONNECTING;
    }
    return ConnectionPhase::OFFLINE;
}

void ClientStateMachine::set_endpoint_sync_state(ClientEndpointSyncState state) {
    std::unique_lock lock(self_mutex_);
    auto old_state = state_.endpoint_sync;
    if (old_state == state) return;

    state_.endpoint_sync = state;
    log().debug("Client: Endpoint sync: {} -> {}",
               client_endpoint_sync_state_name(old_state),
               client_endpoint_sync_state_name(state));
}

ClientEndpointSyncState ClientStateMachine::endpoint_sync_state() const {
    std::shared_lock lock(self_mutex_);
    return state_.endpoint_sync;
}

bool ClientStateMachine::is_endpoint_synced() const {
    std::shared_lock lock(self_mutex_);
    return state_.is_endpoint_synced();
}

void ClientStateMachine::update_local_endpoints(const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(self_mutex_);
    state_.local_endpoints = endpoints;
    log().debug("Client: Updated {} local endpoints", endpoints.size());
}

std::vector<Endpoint> ClientStateMachine::local_endpoints() const {
    std::shared_lock lock(self_mutex_);
    return state_.local_endpoints;
}

void ClientStateMachine::set_route_sync_state(RouteSyncState state) {
    std::unique_lock lock(self_mutex_);
    auto old_state = state_.route_sync;
    if (old_state == state) return;

    state_.route_sync = state;
    log().debug("Client: Route sync: {} -> {}",
               route_sync_state_name(old_state),
               route_sync_state_name(state));
}

RouteSyncState ClientStateMachine::route_sync_state() const {
    std::shared_lock lock(self_mutex_);
    return state_.route_sync;
}

// ============================================================================
// Relay 连接管理
// ============================================================================

void ClientStateMachine::add_relay(const std::string& relay_id, bool is_primary) {
    std::unique_lock lock(relays_mutex_);
    if (state_.relay_connections.find(relay_id) == state_.relay_connections.end()) {
        ClientSelfState::RelayConnection relay;
        relay.relay_id = relay_id;
        relay.is_primary = is_primary;
        state_.relay_connections[relay_id] = relay;

        if (is_primary) {
            state_.primary_relay_id = relay_id;
        }

        log().debug("Client: Added relay: {} (primary={})", relay_id, is_primary);
    }
}

void ClientStateMachine::remove_relay(const std::string& relay_id) {
    bool was_connected = false;

    {
        std::unique_lock lock(relays_mutex_);
        auto it = state_.relay_connections.find(relay_id);
        if (it != state_.relay_connections.end()) {
            was_connected = it->second.is_connected();
            bool was_primary = it->second.is_primary;
            state_.relay_connections.erase(it);

            if (was_primary) {
                state_.primary_relay_id.clear();
                // 选择新的主 Relay
                for (auto& [id, relay] : state_.relay_connections) {
                    if (relay.is_connected()) {
                        state_.primary_relay_id = id;
                        relay.is_primary = true;
                        break;
                    }
                }
            }

            log().debug("Client: Removed relay: {}", relay_id);
        }
    }

    if (was_connected) {
        update_data_plane_state();
    }
}

void ClientStateMachine::set_primary_relay(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    for (auto& [id, relay] : state_.relay_connections) {
        relay.is_primary = (id == relay_id);
    }
    state_.primary_relay_id = relay_id;
}

void ClientStateMachine::set_relay_state(const std::string& relay_id, RelayConnectionState state) {
    bool state_changed = false;
    bool should_update_data_plane = false;

    {
        std::unique_lock lock(relays_mutex_);
        auto* relay = get_relay_mut(relay_id);
        if (!relay) {
            // 创建新的 Relay 连接
            ClientSelfState::RelayConnection new_relay;
            new_relay.relay_id = relay_id;
            state_.relay_connections[relay_id] = new_relay;
            relay = &state_.relay_connections[relay_id];
        }

        auto old_state = relay->state;
        if (old_state == state) return;

        relay->state = state;
        state_changed = true;

        if (state == RelayConnectionState::CONNECTED) {
            relay->last_connect_time = now_us();
        } else if (state == RelayConnectionState::RECONNECTING) {
            relay->reconnect_count++;
        }

        log().info("Client: Relay {}: {} -> {}",
                   relay_id,
                   relay_connection_state_name(old_state),
                   relay_connection_state_name(state));

        // 判断是否需要更新数据面
        should_update_data_plane = (old_state == RelayConnectionState::CONNECTED) !=
                                   (state == RelayConnectionState::CONNECTED);
    }

    if (should_update_data_plane) {
        update_data_plane_state();
    }
}

void ClientStateMachine::update_relay_latency(const std::string& relay_id, uint16_t latency_ms) {
    std::unique_lock lock(relays_mutex_);
    auto* relay = get_relay_mut(relay_id);
    if (relay) {
        relay->latency_ms = latency_ms;
    }
}

void ClientStateMachine::record_relay_recv(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    auto* relay = get_relay_mut(relay_id);
    if (relay) {
        relay->last_recv_time = now_us();
    }
}

void ClientStateMachine::record_relay_send(const std::string& relay_id) {
    std::unique_lock lock(relays_mutex_);
    auto* relay = get_relay_mut(relay_id);
    if (relay) {
        relay->last_send_time = now_us();
    }
}

std::optional<ClientSelfState::RelayConnection> ClientStateMachine::get_relay_info(const std::string& relay_id) const {
    std::shared_lock lock(relays_mutex_);
    auto it = state_.relay_connections.find(relay_id);
    if (it != state_.relay_connections.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ClientSelfState::RelayConnection> ClientStateMachine::get_all_relay_info() const {
    std::vector<ClientSelfState::RelayConnection> result;
    std::shared_lock lock(relays_mutex_);
    for (const auto& [id, relay] : state_.relay_connections) {
        result.push_back(relay);
    }
    return result;
}

bool ClientStateMachine::has_connected_relay() const {
    std::shared_lock lock(relays_mutex_);
    return state_.has_connected_relay();
}

size_t ClientStateMachine::connected_relay_count() const {
    std::shared_lock lock(relays_mutex_);
    return state_.connected_relay_count();
}

std::optional<std::string> ClientStateMachine::get_primary_relay() const {
    std::shared_lock lock(relays_mutex_);
    if (!state_.primary_relay_id.empty()) {
        return state_.primary_relay_id;
    }
    return std::nullopt;
}

// ============================================================================
// 对端连接管理
// ============================================================================

void ClientStateMachine::add_peer(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    if (state_.peer_connections.find(peer_id) == state_.peer_connections.end()) {
        ClientSelfState::PeerConnection conn;
        conn.peer_id = peer_id;
        state_.peer_connections[peer_id] = conn;
        log().debug("Client: Added peer: {}", peer_id);
    }
}

void ClientStateMachine::remove_peer(NodeId peer_id) {
    bool was_p2p = false;

    {
        std::unique_lock lock(peers_mutex_);
        auto it = state_.peer_connections.find(peer_id);
        if (it != state_.peer_connections.end()) {
            was_p2p = it->second.data_path == PeerDataPath::P2P;
            state_.peer_connections.erase(it);
            log().debug("Client: Removed peer: {}", peer_id);
        }
    }

    if (was_p2p) {
        update_data_plane_state();
    }
}

void ClientStateMachine::reset_all_peer_p2p_states() {
    std::unique_lock lock(peers_mutex_);

    size_t reset_count = 0;
    for (auto& [peer_id, conn] : state_.peer_connections) {
        // 只重置 FAILED 状态的 peer，让它们可以重新尝试打洞
        // 不影响 CONNECTED 状态的 peer（保持数据通路）
        if (conn.p2p_state == P2PConnectionState::FAILED) {
            conn.p2p_state = P2PConnectionState::NONE;
            conn.peer_endpoints.clear();
            conn.punch_failures = 0;
            conn.next_retry_time = 0;
            reset_count++;
        }
    }

    if (reset_count > 0) {
        log().info("Client: Reset {} failed P2P peers for retry", reset_count);
    }
}

void ClientStateMachine::set_peer_p2p_state(NodeId peer_id, P2PConnectionState state) {
    bool should_notify = false;
    PeerDataPath data_path;

    {
        std::unique_lock lock(peers_mutex_);
        auto* conn = get_peer_mut(peer_id);
        if (!conn) {
            ClientSelfState::PeerConnection new_conn;
            new_conn.peer_id = peer_id;
            state_.peer_connections[peer_id] = new_conn;
            conn = &state_.peer_connections[peer_id];
        }

        auto old_state = conn->p2p_state;
        if (old_state == state) return;

        conn->p2p_state = state;
        data_path = conn->data_path;
        should_notify = true;

        log().info("Client: Peer {} P2P: {} -> {}",
                   peer_id,
                   p2p_connection_state_name(old_state),
                   p2p_connection_state_name(state));
    }

    if (should_notify) {
        notify_peer_state_change(peer_id, state, data_path);
    }
}

void ClientStateMachine::set_peer_data_path(NodeId peer_id, PeerDataPath path) {
    bool should_notify = false;
    bool should_update_data_plane = false;
    P2PConnectionState p2p_state;

    {
        std::unique_lock lock(peers_mutex_);
        auto* conn = get_peer_mut(peer_id);
        if (!conn) {
            ClientSelfState::PeerConnection new_conn;
            new_conn.peer_id = peer_id;
            state_.peer_connections[peer_id] = new_conn;
            conn = &state_.peer_connections[peer_id];
        }

        auto old_path = conn->data_path;
        if (old_path == path) return;

        conn->data_path = path;
        p2p_state = conn->p2p_state;
        should_notify = true;

        log().info("Client: Peer {} data path: {} -> {}",
                   peer_id,
                   peer_data_path_name(old_path),
                   peer_data_path_name(path));

        // 判断是否需要更新数据面
        should_update_data_plane = (old_path == PeerDataPath::P2P) != (path == PeerDataPath::P2P);
    }

    if (should_notify) {
        notify_peer_state_change(peer_id, p2p_state, path);
    }

    if (should_update_data_plane) {
        update_data_plane_state();
    }
}

bool ClientStateMachine::set_peer_connection_state(NodeId peer_id, P2PConnectionState p2p_state, PeerDataPath data_path) {
    bool state_changed = false;
    bool should_update_data_plane = false;

    {
        std::unique_lock lock(peers_mutex_);
        auto* conn = get_peer_mut(peer_id);
        if (!conn) {
            ClientSelfState::PeerConnection new_conn;
            new_conn.peer_id = peer_id;
            state_.peer_connections[peer_id] = new_conn;
            conn = &state_.peer_connections[peer_id];
        }

        auto old_p2p_state = conn->p2p_state;
        auto old_data_path = conn->data_path;

        // 如果两个状态都没变，直接返回
        if (old_p2p_state == p2p_state && old_data_path == data_path) return false;

        conn->p2p_state = p2p_state;
        conn->data_path = data_path;
        state_changed = true;

        if (old_p2p_state != p2p_state) {
            log().info("Client: Peer {} P2P: {} -> {}",
                       peer_id,
                       p2p_connection_state_name(old_p2p_state),
                       p2p_connection_state_name(p2p_state));
        }

        if (old_data_path != data_path) {
            log().info("Client: Peer {} data path: {} -> {}",
                       peer_id,
                       peer_data_path_name(old_data_path),
                       peer_data_path_name(data_path));
            should_update_data_plane = (old_data_path == PeerDataPath::P2P) != (data_path == PeerDataPath::P2P);
        }
    }

    if (state_changed) {
        notify_peer_state_change(peer_id, p2p_state, data_path);
    }

    if (should_update_data_plane) {
        update_data_plane_state();
    }

    return state_changed;
}

void ClientStateMachine::initiate_p2p(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (!conn) {
        ClientSelfState::PeerConnection new_conn;
        new_conn.peer_id = peer_id;
        state_.peer_connections[peer_id] = new_conn;
        conn = &state_.peer_connections[peer_id];
    }

    conn->p2p_state = P2PConnectionState::INITIATING;
    conn->init_seq = state_.next_init_seq++;
    conn->last_resolve_time = now_us();
}

void ClientStateMachine::receive_peer_endpoints(NodeId peer_id, const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (!conn) return;

    conn->peer_endpoints = endpoints;
    conn->last_endpoint_time = now_us();

    if (conn->p2p_state == P2PConnectionState::INITIATING ||
        conn->p2p_state == P2PConnectionState::WAITING_ENDPOINT) {
        conn->p2p_state = P2PConnectionState::PUNCHING;
    }
}

void ClientStateMachine::set_peer_active_endpoint(NodeId peer_id, const asio::ip::udp::endpoint& endpoint) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (conn) {
        conn->active_endpoint = endpoint;
    }
}

void ClientStateMachine::update_peer_latency(NodeId peer_id, uint16_t rtt_ms) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (conn) {
        conn->rtt_ms = rtt_ms;
    }
}

void ClientStateMachine::record_peer_recv(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (conn) {
        conn->last_recv_time = now_us();
    }
}

void ClientStateMachine::record_peer_send(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (conn) {
        conn->last_send_time = now_us();
    }
}

void ClientStateMachine::record_punch_failure(NodeId peer_id) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (conn) {
        conn->punch_failures++;
        conn->p2p_state = P2PConnectionState::FAILED;
    }
}

void ClientStateMachine::set_peer_next_retry(NodeId peer_id, uint64_t time) {
    std::unique_lock lock(peers_mutex_);
    auto* conn = get_peer_mut(peer_id);
    if (conn) {
        conn->next_retry_time = time;
    }
}

std::optional<ClientSelfState::PeerConnection> ClientStateMachine::get_peer_state(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    auto it = state_.peer_connections.find(peer_id);
    if (it != state_.peer_connections.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::pair<NodeId, ClientSelfState::PeerConnection>> ClientStateMachine::get_all_peer_states() const {
    std::vector<std::pair<NodeId, ClientSelfState::PeerConnection>> result;
    std::shared_lock lock(peers_mutex_);
    for (const auto& [peer_id, conn] : state_.peer_connections) {
        result.emplace_back(peer_id, conn);
    }
    return result;
}

P2PConnectionState ClientStateMachine::get_peer_p2p_state(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    auto it = state_.peer_connections.find(peer_id);
    if (it != state_.peer_connections.end()) {
        return it->second.p2p_state;
    }
    return P2PConnectionState::NONE;
}

uint16_t ClientStateMachine::get_peer_rtt(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    auto it = state_.peer_connections.find(peer_id);
    if (it != state_.peer_connections.end()) {
        return it->second.rtt_ms;
    }
    return 0;
}

std::vector<NodeId> ClientStateMachine::get_peers_for_retry() const {
    std::vector<NodeId> result;
    uint64_t now = now_us();

    std::shared_lock lock(peers_mutex_);
    for (const auto& [peer_id, conn] : state_.peer_connections) {
        if (conn.p2p_state == P2PConnectionState::FAILED) {
            if (conn.next_retry_time > 0 && now >= conn.next_retry_time) {
                result.push_back(peer_id);
            } else if (conn.next_retry_time == 0 && conn.last_resolve_time > 0) {
                auto elapsed_ms = (now - conn.last_resolve_time) / 1000;
                if (elapsed_ms >= static_cast<uint64_t>(retry_interval_.count())) {
                    result.push_back(peer_id);
                }
            }
        }
    }
    return result;
}

std::vector<NodeId> ClientStateMachine::get_peers_for_keepalive() const {
    std::vector<NodeId> result;
    uint64_t now = now_us();
    uint64_t keepalive_interval_us = static_cast<uint64_t>(keepalive_timeout_.count()) * 500;  // 半超时

    std::shared_lock lock(peers_mutex_);
    for (const auto& [peer_id, conn] : state_.peer_connections) {
        if (conn.p2p_state == P2PConnectionState::CONNECTED &&
            conn.data_path == PeerDataPath::P2P) {
            if (conn.last_send_time > 0 && now - conn.last_send_time >= keepalive_interval_us) {
                result.push_back(peer_id);
            }
        }
    }
    return result;
}

bool ClientStateMachine::is_peer_p2p_ready(NodeId peer_id) const {
    std::shared_lock lock(peers_mutex_);
    return state_.is_peer_p2p_ready(peer_id);
}

uint32_t ClientStateMachine::next_init_seq() {
    std::unique_lock lock(self_mutex_);
    return ++state_.next_init_seq;
}

void ClientStateMachine::check_timeouts() {
    uint64_t now = now_us();
    std::vector<std::pair<NodeId, NodeEvent>> events;

    {
        std::shared_lock lock(peers_mutex_);
        for (const auto& [peer_id, conn] : state_.peer_connections) {
            switch (conn.p2p_state) {
                case P2PConnectionState::INITIATING:
                case P2PConnectionState::WAITING_ENDPOINT:
                    // 解析超时
                    if (conn.last_resolve_time > 0) {
                        auto elapsed_ms = (now - conn.last_resolve_time) / 1000;
                        if (elapsed_ms > static_cast<uint64_t>(resolve_timeout_.count())) {
                            events.emplace_back(peer_id, NodeEvent::P2P_PUNCH_TIMEOUT);
                        }
                    }
                    break;

                case P2PConnectionState::PUNCHING:
                    // 打洞超时
                    if (conn.last_punch_time > 0) {
                        auto elapsed_ms = (now - conn.last_punch_time) / 1000;
                        if (elapsed_ms > static_cast<uint64_t>(punch_timeout_.count())) {
                            events.emplace_back(peer_id, NodeEvent::P2P_PUNCH_TIMEOUT);
                        }
                    }
                    break;

                case P2PConnectionState::CONNECTED:
                    // Keepalive 超时
                    if (conn.last_recv_time > 0) {
                        auto elapsed_ms = (now - conn.last_recv_time) / 1000;
                        if (elapsed_ms > static_cast<uint64_t>(keepalive_timeout_.count())) {
                            events.emplace_back(peer_id, NodeEvent::P2P_KEEPALIVE_TIMEOUT);
                        }
                    }
                    break;

                default:
                    break;
            }
        }
    }

    // 处理事件
    for (const auto& [peer_id, event] : events) {
        if (event == NodeEvent::P2P_PUNCH_TIMEOUT || event == NodeEvent::P2P_KEEPALIVE_TIMEOUT) {
            record_punch_failure(peer_id);
        }
    }
}

void ClientStateMachine::reset() {
    {
        std::unique_lock lock(self_mutex_);
        state_.node_id = 0;
        state_.network_id = 0;
        state_.virtual_ip = {};
        state_.control_plane = ControlPlaneState::DISCONNECTED;
        state_.data_plane = DataPlaneState::OFFLINE;
        state_.connection_phase = ConnectionPhase::OFFLINE;
        state_.endpoint_sync = ClientEndpointSyncState::NOT_READY;
        state_.local_endpoints.clear();
        state_.route_sync = RouteSyncState::DISABLED;
    }

    {
        std::unique_lock lock(relays_mutex_);
        state_.relay_connections.clear();
        state_.primary_relay_id.clear();
    }

    {
        std::unique_lock lock(peers_mutex_);
        state_.peer_connections.clear();
    }

    log().info("Client: State machine reset");
}

uint64_t ClientStateMachine::now_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

void ClientStateMachine::notify_phase_change(ConnectionPhase old_phase, ConnectionPhase new_phase) {
    if (phase_channel_) {
        cobalt_utils::fire_write(*phase_channel_, ConnectionPhaseEvent{old_phase, new_phase}, ioc_.get_executor());
    }
}

void ClientStateMachine::notify_peer_state_change(NodeId peer_id, P2PConnectionState p2p_state, PeerDataPath data_path) {
    if (peer_state_channel_) {
        cobalt_utils::fire_write(*peer_state_channel_, PeerStateEvent{peer_id, p2p_state, data_path}, ioc_.get_executor());
    }
}

ClientSelfState::PeerConnection* ClientStateMachine::get_peer_mut(NodeId peer_id) {
    auto it = state_.peer_connections.find(peer_id);
    if (it != state_.peer_connections.end()) {
        return &it->second;
    }
    return nullptr;
}

ClientSelfState::RelayConnection* ClientStateMachine::get_relay_mut(const std::string& relay_id) {
    auto it = state_.relay_connections.find(relay_id);
    if (it != state_.relay_connections.end()) {
        return &it->second;
    }
    return nullptr;
}

}  // namespace edgelink

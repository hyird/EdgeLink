#include "controller/session_manager.hpp"
#include "controller/session.hpp"
#include "common/logger.hpp"
#include "common/message.hpp"
#include "common/frame.hpp"
#include "common/proto_convert.hpp"
#include "common/cobalt_utils.hpp"
#include <boost/cobalt.hpp>

namespace cobalt = boost::cobalt;

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.session_manager"); }
}

SessionManager::SessionManager(asio::io_context& ioc, Database& db, JwtUtil& jwt)
    : ioc_(ioc), db_(db), jwt_(jwt), state_machine_(ioc) {
    // 创建事件通道
    client_online_channel_ = std::make_unique<channels::ClientOnlineChannel>(64, ioc.get_executor());
    client_offline_channel_ = std::make_unique<channels::ClientOfflineChannel>(64, ioc.get_executor());
    endpoint_update_channel_ = std::make_unique<channels::EndpointUpdateChannel>(64, ioc.get_executor());
    route_change_channel_ = std::make_unique<channels::RouteChangeChannel>(64, ioc.get_executor());

    // 设置状态机的事件通道
    state_machine_.set_client_online_channel(client_online_channel_.get());
    state_machine_.set_client_offline_channel(client_offline_channel_.get());
    state_machine_.set_endpoint_update_channel(endpoint_update_channel_.get());
    state_machine_.set_route_change_channel(route_change_channel_.get());

    // 启动事件处理协程
    cobalt_utils::spawn_task(ioc_.get_executor(), client_online_handler());
    cobalt_utils::spawn_task(ioc_.get_executor(), client_offline_handler());
    cobalt_utils::spawn_task(ioc_.get_executor(), endpoint_update_handler());
    cobalt_utils::spawn_task(ioc_.get_executor(), route_change_handler());
}

// ============================================================================
// Control session management
// ============================================================================

void SessionManager::register_control_session(NodeId node_id, std::shared_ptr<ISession> session) {
    {
        std::unique_lock lock(control_mutex_);

        // Unregister existing session if any
        auto it = control_sessions_.find(node_id);
        if (it != control_sessions_.end()) {
            log().info("Replacing existing control session for node {}", node_id);
        }

        control_sessions_[node_id] = session;
    }

    // Cache the node IP for fast lookup (avoid DB query on every data forward)
    auto node = db_.get_node(node_id);
    NetworkId network_id = 0;
    if (node) {
        std::unique_lock lock(ip_cache_mutex_);
        node_ip_cache_[node_id] = node->virtual_ip.to_string();
        network_id = node->network_id;
    }

    // 添加客户端到状态机
    add_client(node_id, network_id);

    log().debug("Registered control session for node {}", node_id);
}

void SessionManager::unregister_control_session(NodeId node_id) {
    {
        std::unique_lock lock(control_mutex_);
        auto it = control_sessions_.find(node_id);
        if (it != control_sessions_.end()) {
            control_sessions_.erase(it);
        }
    }

    // Remove from IP cache
    {
        std::unique_lock lock(ip_cache_mutex_);
        node_ip_cache_.erase(node_id);
    }

    // Clear exit_node capability
    clear_node_exit_node(node_id);

    // 移除客户端
    remove_client(node_id);

    log().debug("Unregistered control session for node {}", node_id);
}

std::shared_ptr<ISession> SessionManager::get_control_session(NodeId node_id) {
    std::shared_lock lock(control_mutex_);
    auto it = control_sessions_.find(node_id);
    return it != control_sessions_.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<ISession>> SessionManager::get_all_control_sessions() {
    std::shared_lock lock(control_mutex_);
    std::vector<std::shared_ptr<ISession>> sessions;
    sessions.reserve(control_sessions_.size());
    for (const auto& [_, session] : control_sessions_) {
        sessions.push_back(session);
    }
    return sessions;
}

std::vector<std::shared_ptr<ISession>> SessionManager::get_network_control_sessions(NetworkId network_id) {
    std::shared_lock lock(control_mutex_);
    std::vector<std::shared_ptr<ISession>> sessions;
    for (const auto& [_, session] : control_sessions_) {
        if (session->network_id() == network_id) {
            sessions.push_back(session);
        }
    }
    return sessions;
}

// ============================================================================
// Relay session management
// ============================================================================

void SessionManager::register_relay_session(NodeId node_id, std::shared_ptr<ISession> session) {
    std::unique_lock lock(relay_mutex_);

    auto it = relay_sessions_.find(node_id);
    if (it != relay_sessions_.end()) {
        log().info("Replacing existing relay session for node {}", node_id);
    }

    relay_sessions_[node_id] = session;
    log().debug("Registered relay session for node {}", node_id);
}

void SessionManager::unregister_relay_session(NodeId node_id) {
    std::unique_lock lock(relay_mutex_);
    auto it = relay_sessions_.find(node_id);
    if (it != relay_sessions_.end()) {
        relay_sessions_.erase(it);
        log().debug("Unregistered relay session for node {}", node_id);
    }
}

std::shared_ptr<ISession> SessionManager::get_relay_session(NodeId node_id) {
    std::shared_lock lock(relay_mutex_);
    auto it = relay_sessions_.find(node_id);
    return it != relay_sessions_.end() ? it->second : nullptr;
}

// ============================================================================
// Broadcast/Notify
// ============================================================================

cobalt::task<void> SessionManager::broadcast_config_update(NetworkId network_id, NodeId except_node) {
    auto sessions = get_network_control_sessions(network_id);

    log().info("broadcast_config_update: network={}, except_node={}, active_sessions={}",
               network_id, except_node, sessions.size());

    // Get all nodes in the network
    auto nodes = db_.get_nodes_by_network(network_id);
    if (!nodes) {
        log().warn("broadcast_config_update: failed to get nodes for network {}", network_id);
        co_return;
    }

    log().info("broadcast_config_update: found {} nodes in network", nodes->size());

    auto version = next_config_version();
    int sent_count = 0;

    for (const auto& session : sessions) {
        if (session->node_id() == except_node) {
            log().debug("broadcast_config_update: skipping node {} (except_node)", session->node_id());
            continue;
        }

        // Build CONFIG_UPDATE message for each session (excluding self)
        ConfigUpdate update;
        update.version = version;
        update.update_flags = ConfigUpdateFlags::PEER_CHANGED;

        // Add peers (excluding self)
        for (const auto& node : *nodes) {
            if (node.id == session->node_id()) continue;

            PeerInfo peer;
            peer.node_id = node.id;
            peer.virtual_ip = node.virtual_ip;
            peer.node_key = node.node_key;
            peer.online = node.online;
            peer.name = node.hostname;
            update.add_peers.push_back(peer);
        }

        log().info("broadcast_config_update: sending to node {} with {} peers",
                   session->node_id(), update.add_peers.size());

        // Convert to protobuf and send
        pb::ConfigUpdate pb_update;
        to_proto(update, &pb_update);
        auto result = FrameCodec::encode_protobuf(FrameType::CONFIG_UPDATE, pb_update);
        if (result) {
            co_await session->send_raw(*result);
            ++sent_count;
        } else {
            log().error("broadcast_config_update: failed to encode for node {}", session->node_id());
        }
    }

    log().info("Broadcast CONFIG_UPDATE to {} sessions in network {}",
               sent_count, network_id);
}

cobalt::task<void> SessionManager::notify_peer_status(NodeId target_node, NodeId peer_node, bool online) {
    auto session = get_control_session(target_node);
    if (!session) {
        co_return;
    }

    // Get peer node info
    auto peer = db_.get_node(peer_node);
    if (!peer) {
        co_return;
    }

    ConfigUpdate update;
    update.version = current_config_version();
    update.update_flags = ConfigUpdateFlags::PEER_CHANGED;

    PeerInfo peer_info;
    peer_info.node_id = peer->id;
    peer_info.virtual_ip = peer->virtual_ip;
    peer_info.node_key = peer->node_key;
    peer_info.online = online;
    peer_info.name = peer->hostname;
    update.add_peers.push_back(peer_info);

    // Convert to protobuf and send
    pb::ConfigUpdate pb_update;
    to_proto(update, &pb_update);
    auto result = FrameCodec::encode_protobuf(FrameType::CONFIG_UPDATE, pb_update);
    if (result) {
        co_await session->send_raw(*result);
    }
}

cobalt::task<void> SessionManager::broadcast_route_update(
    NetworkId network_id, NodeId except_node,
    const std::vector<RouteInfo>& add_routes,
    const std::vector<RouteInfo>& del_routes) {

    if (add_routes.empty() && del_routes.empty()) {
        co_return;
    }

    auto sessions = get_network_control_sessions(network_id);
    auto version = next_config_version();
    int sent_count = 0;

    RouteUpdate update;
    update.version = version;
    update.add_routes = add_routes;
    update.del_routes = del_routes;

    pb::RouteUpdate pb_update;
    to_proto(update, &pb_update);
    auto result = FrameCodec::encode_protobuf(FrameType::ROUTE_UPDATE, pb_update);
    if (!result) {
        log().error("Failed to encode ROUTE_UPDATE");
        co_return;
    }

    for (const auto& session : sessions) {
        if (session->node_id() == except_node) {
            continue;
        }

        co_await session->send_raw(*result);
        ++sent_count;
    }

    log().debug("Broadcast ROUTE_UPDATE to {} sessions in network {} (+{} routes, -{} routes)",
                sent_count, network_id, add_routes.size(), del_routes.size());
}

// ============================================================================
// Statistics
// ============================================================================

size_t SessionManager::control_session_count() const {
    std::shared_lock lock(control_mutex_);
    return control_sessions_.size();
}

size_t SessionManager::relay_session_count() const {
    std::shared_lock lock(relay_mutex_);
    return relay_sessions_.size();
}

std::string SessionManager::get_node_ip_str(NodeId node_id) {
    // Try cache first (fast path, no DB access)
    {
        std::shared_lock lock(ip_cache_mutex_);
        auto it = node_ip_cache_.find(node_id);
        if (it != node_ip_cache_.end()) {
            return it->second;
        }
    }

    // Fallback to node ID (don't query DB on hot path)
    return std::to_string(node_id);
}

// ============================================================================
// 节点端点缓存
// ============================================================================

void SessionManager::update_node_endpoints(NodeId node_id, const std::vector<Endpoint>& endpoints) {
    std::unique_lock lock(endpoints_mutex_);
    node_endpoints_[node_id] = endpoints;
    log().debug("Updated endpoints for node {}: {} endpoints", node_id, endpoints.size());
}

std::vector<Endpoint> SessionManager::get_node_endpoints(NodeId node_id) const {
    std::shared_lock lock(endpoints_mutex_);
    auto it = node_endpoints_.find(node_id);
    if (it != node_endpoints_.end()) {
        return it->second;
    }
    return {};
}

void SessionManager::clear_node_endpoints(NodeId node_id) {
    std::unique_lock lock(endpoints_mutex_);
    node_endpoints_.erase(node_id);
    log().debug("Cleared endpoints for node {}", node_id);
}

// ============================================================================
// 节点 exit_node 能力缓存
// ============================================================================

void SessionManager::update_node_exit_node(NodeId node_id, bool is_exit_node) {
    std::unique_lock lock(exit_node_mutex_);
    node_exit_node_[node_id] = is_exit_node;
    if (is_exit_node) {
        log().info("Node {} declared as exit node", node_id);
    }
}

bool SessionManager::is_node_exit_node(NodeId node_id) const {
    std::shared_lock lock(exit_node_mutex_);
    auto it = node_exit_node_.find(node_id);
    return it != node_exit_node_.end() && it->second;
}

void SessionManager::clear_node_exit_node(NodeId node_id) {
    std::unique_lock lock(exit_node_mutex_);
    node_exit_node_.erase(node_id);
}

// ============================================================================
// 状态机管理
// ============================================================================

void SessionManager::add_client(NodeId node_id, NetworkId network_id) {
    state_machine_.add_node(node_id, network_id);
    log().debug("Added client {} to state machine in network {}", node_id, network_id);
}

void SessionManager::remove_client(NodeId node_id) {
    state_machine_.remove_node(node_id);
    clear_node_endpoints(node_id);
    log().debug("Removed client {} from state machine", node_id);
}

void SessionManager::handle_endpoint_update(NodeId node_id, const std::vector<Endpoint>& endpoints) {
    state_machine_.update_node_endpoints(node_id, endpoints);
}

void SessionManager::handle_route_announce(NodeId node_id, const std::vector<RouteInfo>& routes) {
    std::vector<RouteInfo> empty;
    state_machine_.update_node_routes(node_id, routes, empty);
}

void SessionManager::handle_route_withdraw(NodeId node_id, const std::vector<RouteInfo>& routes) {
    std::vector<RouteInfo> empty;
    state_machine_.update_node_routes(node_id, empty, routes);
}

void SessionManager::handle_p2p_init(NodeId initiator, NodeId responder, uint32_t seq) {
    state_machine_.handle_p2p_init(initiator, responder, seq);
}

void SessionManager::handle_p2p_status(NodeId node_id, NodeId peer_id, bool success) {
    state_machine_.handle_p2p_status(node_id, peer_id, success);
}

std::optional<ControllerNodeView> SessionManager::get_client_state(NodeId node_id) const {
    return state_machine_.get_node_view(node_id);
}

std::vector<NodeId> SessionManager::get_online_clients() const {
    return state_machine_.get_online_nodes();
}

void SessionManager::check_timeouts() {
    state_machine_.check_timeouts();
}

// ============================================================================
// Channel 事件处理协程
// ============================================================================

cobalt::task<void> SessionManager::client_online_handler() {
    while (true) {
        auto [ec, event] = co_await cobalt::as_tuple(client_online_channel_->read());
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                break;
            }
            break;  // broken_pipe means channel closed
        }

        log().info("Client {} online in network {}", event.node_id, event.network_id);

        // 通知同网络的其他客户端
        auto sessions = get_network_control_sessions(event.network_id);
        for (const auto& session : sessions) {
            if (session->node_id() != event.node_id) {
                co_await notify_peer_status(session->node_id(), event.node_id, true);
            }
        }

        // 更新数据库
        (void)db_.update_node_online(event.node_id, true);
    }
}

cobalt::task<void> SessionManager::client_offline_handler() {
    while (true) {
        auto [ec, event] = co_await cobalt::as_tuple(client_offline_channel_->read());
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                break;
            }
            break;  // broken_pipe means channel closed
        }

        log().info("Client {} offline from network {}", event.node_id, event.network_id);

        // 通知同网络的其他客户端
        auto sessions = get_network_control_sessions(event.network_id);
        for (const auto& session : sessions) {
            if (session->node_id() != event.node_id) {
                co_await notify_peer_status(session->node_id(), event.node_id, false);
            }
        }

        // 更新数据库
        (void)db_.update_node_online(event.node_id, false);
    }
}

cobalt::task<void> SessionManager::endpoint_update_handler() {
    while (true) {
        auto [ec, event] = co_await cobalt::as_tuple(endpoint_update_channel_->read());
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                break;
            }
            break;  // broken_pipe means channel closed
        }

        // 更新内部端点缓存
        update_node_endpoints(event.node_id, event.endpoints);
    }
}

cobalt::task<void> SessionManager::route_change_handler() {
    while (true) {
        auto [ec, event] = co_await cobalt::as_tuple(route_change_channel_->read());
        if (ec) {
            if (ec == asio::error::operation_aborted) {
                break;
            }
            break;  // broken_pipe means channel closed
        }

        // 广播路由变更
        auto state = get_client_state(event.node_id);
        if (state) {
            co_await broadcast_route_update(state->network_id, event.node_id, event.added, event.removed);
        }
    }
}

} // namespace edgelink::controller

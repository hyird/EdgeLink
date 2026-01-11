#include "controller/session_manager.hpp"
#include "controller/session.hpp"
#include "common/logger.hpp"
#include "common/message.hpp"

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.session_manager"); }
}

SessionManager::SessionManager(asio::io_context& ioc, Database& db, JwtUtil& jwt)
    : ioc_(ioc), db_(db), jwt_(jwt) {}

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
    if (node) {
        std::unique_lock lock(ip_cache_mutex_);
        node_ip_cache_[node_id] = node->virtual_ip.to_string();
    }

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

asio::awaitable<void> SessionManager::broadcast_config_update(NetworkId network_id, NodeId except_node) {
    auto sessions = get_network_control_sessions(network_id);

    // Get all nodes in the network
    auto nodes = db_.get_nodes_by_network(network_id);
    if (!nodes) {
        co_return;
    }

    auto version = next_config_version();
    int sent_count = 0;

    for (const auto& session : sessions) {
        if (session->node_id() == except_node) {
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

        co_await session->send_frame(FrameType::CONFIG_UPDATE, update.serialize());
        ++sent_count;
    }

    log().debug("Broadcast CONFIG_UPDATE to {} sessions in network {}",
                  sent_count, network_id);
}

asio::awaitable<void> SessionManager::notify_peer_status(NodeId target_node, NodeId peer_node, bool online) {
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

    auto payload = update.serialize();
    co_await session->send_frame(FrameType::CONFIG_UPDATE, payload);
}

asio::awaitable<void> SessionManager::broadcast_route_update(
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
    auto payload = update.serialize();

    for (const auto& session : sessions) {
        if (session->node_id() == except_node) {
            continue;
        }

        co_await session->send_frame(FrameType::ROUTE_UPDATE, payload);
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

} // namespace edgelink::controller

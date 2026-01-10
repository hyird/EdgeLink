#include "controller/session_manager.hpp"
#include "controller/session.hpp"
#include <spdlog/spdlog.h>

namespace edgelink::controller {

SessionManager::SessionManager(asio::io_context& ioc, Database& db, JwtUtil& jwt)
    : ioc_(ioc), db_(db), jwt_(jwt) {}

// ============================================================================
// Control session management
// ============================================================================

void SessionManager::register_control_session(NodeId node_id, std::shared_ptr<ControlSession> session) {
    std::unique_lock lock(control_mutex_);

    // Unregister existing session if any
    auto it = control_sessions_.find(node_id);
    if (it != control_sessions_.end()) {
        spdlog::info("Replacing existing control session for node {}", node_id);
    }

    control_sessions_[node_id] = session;
    spdlog::debug("Registered control session for node {}", node_id);
}

void SessionManager::unregister_control_session(NodeId node_id) {
    std::unique_lock lock(control_mutex_);
    auto it = control_sessions_.find(node_id);
    if (it != control_sessions_.end()) {
        control_sessions_.erase(it);
        spdlog::debug("Unregistered control session for node {}", node_id);
    }
}

std::shared_ptr<ControlSession> SessionManager::get_control_session(NodeId node_id) {
    std::shared_lock lock(control_mutex_);
    auto it = control_sessions_.find(node_id);
    return it != control_sessions_.end() ? it->second : nullptr;
}

std::vector<std::shared_ptr<ControlSession>> SessionManager::get_all_control_sessions() {
    std::shared_lock lock(control_mutex_);
    std::vector<std::shared_ptr<ControlSession>> sessions;
    sessions.reserve(control_sessions_.size());
    for (const auto& [_, session] : control_sessions_) {
        sessions.push_back(session);
    }
    return sessions;
}

std::vector<std::shared_ptr<ControlSession>> SessionManager::get_network_control_sessions(NetworkId network_id) {
    std::shared_lock lock(control_mutex_);
    std::vector<std::shared_ptr<ControlSession>> sessions;
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

void SessionManager::register_relay_session(NodeId node_id, std::shared_ptr<RelaySession> session) {
    std::unique_lock lock(relay_mutex_);

    auto it = relay_sessions_.find(node_id);
    if (it != relay_sessions_.end()) {
        spdlog::info("Replacing existing relay session for node {}", node_id);
    }

    relay_sessions_[node_id] = session;
    spdlog::debug("Registered relay session for node {}", node_id);
}

void SessionManager::unregister_relay_session(NodeId node_id) {
    std::unique_lock lock(relay_mutex_);
    auto it = relay_sessions_.find(node_id);
    if (it != relay_sessions_.end()) {
        relay_sessions_.erase(it);
        spdlog::debug("Unregistered relay session for node {}", node_id);
    }
}

std::shared_ptr<RelaySession> SessionManager::get_relay_session(NodeId node_id) {
    std::shared_lock lock(relay_mutex_);
    auto it = relay_sessions_.find(node_id);
    return it != relay_sessions_.end() ? it->second : nullptr;
}

// ============================================================================
// Broadcast/Notify
// ============================================================================

asio::awaitable<void> SessionManager::broadcast_config_update(NetworkId network_id, NodeId except_node) {
    auto sessions = get_network_control_sessions(network_id);

    // Build CONFIG_UPDATE message
    ConfigUpdate update;
    update.version = next_config_version();
    update.update_flags = ConfigUpdateFlags::PEER_CHANGED;

    // Get all nodes in the network
    auto nodes = db_.get_nodes_by_network(network_id);
    if (!nodes) {
        co_return;
    }

    // Add all peers
    for (const auto& node : *nodes) {
        PeerInfo peer;
        peer.node_id = node.id;
        peer.virtual_ip = node.virtual_ip;
        peer.node_key = node.node_key;
        peer.online = node.online;
        peer.name = node.hostname;
        update.add_peers.push_back(peer);
    }

    auto payload = update.serialize();
    auto frame_data = FrameCodec::encode(FrameType::CONFIG_UPDATE, payload);

    for (const auto& session : sessions) {
        if (session->node_id() != except_node) {
            co_await session->send_raw(frame_data);
        }
    }

    spdlog::debug("Broadcast CONFIG_UPDATE to {} sessions in network {}",
                  sessions.size() - (except_node ? 1 : 0), network_id);
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

} // namespace edgelink::controller

#pragma once

#include "common/types.hpp"
#include "controller/database.hpp"
#include "controller/jwt_util.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace asio = boost::asio;

namespace edgelink::controller {

// Forward declaration of session interface
class ISession;

// Session manager - manages all active sessions
class SessionManager {
public:
    SessionManager(asio::io_context& ioc, Database& db, JwtUtil& jwt);

    // ========================================================================
    // Control session management
    // ========================================================================

    void register_control_session(NodeId node_id, std::shared_ptr<ISession> session);
    void unregister_control_session(NodeId node_id);
    std::shared_ptr<ISession> get_control_session(NodeId node_id);
    std::vector<std::shared_ptr<ISession>> get_all_control_sessions();
    std::vector<std::shared_ptr<ISession>> get_network_control_sessions(NetworkId network_id);

    // ========================================================================
    // Relay session management
    // ========================================================================

    void register_relay_session(NodeId node_id, std::shared_ptr<ISession> session);
    void unregister_relay_session(NodeId node_id);
    std::shared_ptr<ISession> get_relay_session(NodeId node_id);

    // ========================================================================
    // Broadcast/Notify
    // ========================================================================

    // Broadcast CONFIG_UPDATE to all nodes in a network (except sender)
    asio::awaitable<void> broadcast_config_update(NetworkId network_id, NodeId except_node = 0);

    // Notify a specific node that a peer came online/offline
    asio::awaitable<void> notify_peer_status(NodeId target_node, NodeId peer_node, bool online);

    // ========================================================================
    // Statistics
    // ========================================================================

    size_t control_session_count() const;
    size_t relay_session_count() const;

    // ========================================================================
    // Accessors
    // ========================================================================

    Database& database() { return db_; }
    JwtUtil& jwt() { return jwt_; }
    asio::io_context& io_context() { return ioc_; }

    // Config version (incremented on any config change)
    uint64_t current_config_version() const { return config_version_.load(); }
    uint64_t next_config_version() { return ++config_version_; }

private:
    asio::io_context& ioc_;
    Database& db_;
    JwtUtil& jwt_;

    // Control sessions (by node_id)
    mutable std::shared_mutex control_mutex_;
    std::unordered_map<NodeId, std::shared_ptr<ISession>> control_sessions_;

    // Relay sessions (by node_id)
    mutable std::shared_mutex relay_mutex_;
    std::unordered_map<NodeId, std::shared_ptr<ISession>> relay_sessions_;

    // Config version counter
    std::atomic<uint64_t> config_version_{1};
};

} // namespace edgelink::controller

#pragma once

#include "common/types.hpp"
#include "common/config.hpp"
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

    // Broadcast ROUTE_UPDATE to all nodes in a network (except sender)
    asio::awaitable<void> broadcast_route_update(NetworkId network_id, NodeId except_node,
                                                  const std::vector<RouteInfo>& add_routes,
                                                  const std::vector<RouteInfo>& del_routes);

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

    // Get node IP string for logging (returns node_id as string if not found)
    std::string get_node_ip_str(NodeId node_id);

    // Config version (incremented on any config change)
    uint64_t current_config_version() const { return config_version_.load(); }
    uint64_t next_config_version() { return ++config_version_; }

    // ========================================================================
    // Builtin Relay/STUN 配置
    // ========================================================================

    void set_builtin_relay_config(const ControllerConfig::BuiltinRelayConfig& config) {
        builtin_relay_ = config;
    }
    const ControllerConfig::BuiltinRelayConfig& builtin_relay_config() const {
        return builtin_relay_;
    }

    void set_builtin_stun_config(const ControllerConfig::BuiltinStunConfig& config) {
        builtin_stun_ = config;
    }
    const ControllerConfig::BuiltinStunConfig& builtin_stun_config() const {
        return builtin_stun_;
    }

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

    // Node IP cache (populated on control session registration)
    mutable std::shared_mutex ip_cache_mutex_;
    std::unordered_map<NodeId, std::string> node_ip_cache_;

    // Config version counter
    std::atomic<uint64_t> config_version_{1};

    // Builtin Relay/STUN 配置
    ControllerConfig::BuiltinRelayConfig builtin_relay_;
    ControllerConfig::BuiltinStunConfig builtin_stun_;
};

} // namespace edgelink::controller

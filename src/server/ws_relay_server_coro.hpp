#pragma once

#include "common/io_context_pool.hpp"
#include "common/ws_server_coro.hpp"
#include "common/jwt.hpp"
#include "common/config.hpp"
#include "common/thread_local_session.hpp"
#include "common/data_forwarder.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>

#include <memory>
#include <string>
#include <atomic>
#include <shared_mutex>
#include <unordered_map>
#include <functional>

namespace edgelink {

namespace net = boost::asio;
namespace beast = boost::beast;

// Forward declarations
class ControllerClient;
class WsRelaySessionCoro;

/**
 * WsRelayServerCoro - Coroutine-based WebSocket Relay Server
 *
 * Uses the thread-per-core model with IOContextPool for high performance.
 * Each connection is assigned to a specific thread and stays there.
 *
 * Design (per architecture.md Section 8):
 * - Thread-per-core model via IOContextPool
 * - Round-robin connection distribution
 * - Thread-local session management (no global locks for hot path)
 * - Cross-thread forwarding via MPSC queues
 */
class WsRelayServerCoro : public WsServerCoro {
public:
    WsRelayServerCoro(IOContextPool& pool, const ServerConfig& config);
    ~WsRelayServerCoro() override;

    // Server ID management (assigned by controller)
    uint32_t server_id() const { return server_id_; }
    void set_server_id(uint32_t id);

    // Controller client
    void set_controller_client(std::shared_ptr<ControllerClient> client);
    ControllerClient* controller_client() { return controller_client_.get(); }

    // JWT secret for relay tokens (retrieved from controller)
    void set_jwt_secret(const std::string& secret);
    const std::string& jwt_secret() const { return jwt_secret_; }

    // Token validation
    bool validate_relay_token(const std::string& token, uint32_t& node_id, std::string& virtual_ip);

    // Token blacklist management
    void add_to_blacklist(const std::string& jti, int64_t expires_at);

    // Node location tracking (which relay servers a node is connected to)
    void update_node_locations(const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations);
    std::vector<uint32_t> get_node_relay_locations(uint32_t node_id) const;

    // Session management (thread-safe, uses DataForwarder internally)
    void add_client_session(uint32_t node_id, std::shared_ptr<WsSessionCoro> session);
    void remove_client_session(uint32_t node_id);

    // Mesh session management
    void add_mesh_session(uint32_t server_id, std::shared_ptr<WsSessionCoro> session);
    void remove_mesh_session(uint32_t server_id);
    std::shared_ptr<WsSessionCoro> get_mesh_session(uint32_t server_id);

    // Forward data to destination node
    bool forward_data(uint32_t src_node, uint32_t dst_node, std::vector<uint8_t> data);

    // Handle mesh forward from another relay
    void handle_mesh_forward(const wire::MeshForwardPayload& payload);

    // Get data forwarder
    DataForwarder& data_forwarder() { return data_forwarder_; }

    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_forwarded{0};
        std::atomic<uint64_t> packets_forwarded{0};
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> connections_active{0};
        std::atomic<uint64_t> auth_failures{0};
    };
    Stats& stats() { return stats_; }
    const Stats& stats() const { return stats_; }

    // Session counts
    size_t client_count() const;
    size_t mesh_count() const;

protected:
    // WsServerCoro interface
    std::shared_ptr<WsSessionCoro> create_session(
        net::io_context& ioc,
        tcp::socket socket,
        const std::string& path) override;

private:
    const ServerConfig& config_;
    std::shared_ptr<ControllerClient> controller_client_;

    // JWT management
    std::string jwt_secret_{"edgelink-relay-jwt-secret"};  // Default, should be set by controller
    std::unique_ptr<JWTManager> jwt_manager_;
    mutable std::shared_mutex jwt_mutex_;

    // Token blacklist
    mutable std::shared_mutex blacklist_mutex_;
    std::unordered_map<std::string, int64_t> token_blacklist_;

    // Node locations (which relay each node is on)
    mutable std::shared_mutex locations_mutex_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> node_locations_;

    // Mesh sessions (connections to other relay servers)
    mutable std::shared_mutex mesh_mutex_;
    std::unordered_map<uint32_t, std::weak_ptr<WsSessionCoro>> mesh_sessions_;

    // Data forwarding
    DataForwarder data_forwarder_;

    uint32_t server_id_{0};
    Stats stats_;
};

} // namespace edgelink

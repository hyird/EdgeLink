#pragma once

#include "common/io_context_pool.hpp"
#include "common/ws_server_coro.hpp"
#include "common/config.hpp"
#include "controller/db/database.hpp"
#include "controller/api/control_handler.hpp"
#include "controller/services/path_service.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <memory>
#include <string>
#include <atomic>
#include <shared_mutex>
#include <unordered_map>

namespace edgelink::controller {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

// Forward declarations
class BuiltinRelay;
class WsControlSessionCoro;
class WsServerSessionCoro;

/**
 * WsSessionManagerCoro - Thread-safe session manager for controller
 *
 * Tracks control sessions (nodes) and server sessions (relays).
 * Uses shared_mutex for concurrent read access.
 */
class WsSessionManagerCoro {
public:
    // Control sessions (nodes)
    void add_control_session(uint32_t node_id, uint32_t network_id, std::weak_ptr<WsSessionCoro> session);
    void remove_control_session(uint32_t node_id);
    std::shared_ptr<WsSessionCoro> get_control_session(uint32_t node_id);

    // Server sessions (relays/stun)
    void add_server_session(uint32_t server_id, std::weak_ptr<WsSessionCoro> session);
    void remove_server_session(uint32_t server_id);
    std::shared_ptr<WsSessionCoro> get_server_session(uint32_t server_id);

    // Broadcast to all nodes in a network
    void broadcast_to_network(uint32_t network_id, const std::string& text);

    // Get counts
    size_t node_count() const;
    size_t server_count() const;

    // Get all connected node IDs
    std::vector<uint32_t> get_connected_nodes() const;

private:
    mutable std::shared_mutex control_mutex_;
    mutable std::shared_mutex server_mutex_;

    struct ControlSessionInfo {
        std::weak_ptr<WsSessionCoro> session;
        uint32_t network_id;
    };

    std::unordered_map<uint32_t, ControlSessionInfo> control_sessions_;
    std::unordered_map<uint32_t, std::weak_ptr<WsSessionCoro>> server_sessions_;
};

/**
 * WsControllerServerCoro - Coroutine-based WebSocket server for Controller
 *
 * Handles three types of connections:
 * - /api/v1/control - Client (node) control connections
 * - /api/v1/server - Relay server connections
 * - /api/v1/relay - Built-in relay connections (optional)
 */
class WsControllerServerCoro : public WsServerCoro {
public:
    WsControllerServerCoro(IOContextPool& pool,
                            const ControllerConfig& config,
                            std::shared_ptr<Database> db);

    ~WsControllerServerCoro() override;

    // Access components
    WsSessionManagerCoro* get_session_manager() { return &session_manager_; }
    std::shared_ptr<Database> get_database() { return db_; }
    const ControllerConfig& get_config() const { return config_; }
    std::shared_ptr<PathService> get_path_service() { return path_service_; }

    // Set built-in relay (optional)
    void set_builtin_relay(BuiltinRelay* relay) { builtin_relay_ = relay; }
    BuiltinRelay* get_builtin_relay() { return builtin_relay_; }

protected:
    // WsServerCoro interface
    std::shared_ptr<WsSessionCoro> create_session(
        net::io_context& ioc,
        tcp::socket socket,
        const std::string& path) override;

private:
    ControllerConfig config_;
    std::shared_ptr<Database> db_;
    std::shared_ptr<PathService> path_service_;
    WsSessionManagerCoro session_manager_;
    BuiltinRelay* builtin_relay_{nullptr};
};

/**
 * WsControlSessionCoro - Coroutine-based control session for nodes
 *
 * Handles client (node) connections on /api/v1/control path.
 * Uses text (JSON) messages for control protocol.
 */
class WsControlSessionCoro : public WsSessionCoro {
public:
    WsControlSessionCoro(net::io_context& ioc, tcp::socket socket,
                          WsControllerServerCoro* server,
                          const std::string& query_string);

    ~WsControlSessionCoro() override;

protected:
    // WsSessionCoro interface
    net::awaitable<void> on_connected() override;
    net::awaitable<void> process_frame(const wire::Frame& frame) override;
    net::awaitable<void> on_disconnected(const std::string& reason) override;

private:
    // Binary frame handlers
    void handle_auth_request(const wire::Frame& frame);
    void handle_ping(const wire::Frame& frame);
    void handle_latency_report(const wire::Frame& frame);
    void handle_endpoint_report(const wire::Frame& frame);
    void handle_p2p_request(const wire::Frame& frame);
    void handle_config_ack(const wire::Frame& frame);
    void handle_route_announce(const wire::Frame& frame);
    void handle_route_withdraw(const wire::Frame& frame);

    // Helper methods
    void on_authenticated(uint32_t node_id, uint32_t network_id);
    void send_error(wire::ErrorCode code, const std::string& message);
    void send_config_update();

    WsControllerServerCoro* server_;
    std::string query_string_;
    bool control_authenticated_{false};

    // Node info after auth
    std::string machine_key_;
    std::string virtual_ip_;
};

/**
 * WsServerSessionCoro - Coroutine-based session for relay servers
 *
 * Handles relay server connections on /api/v1/server path.
 * Uses text (JSON) messages for server protocol.
 */
class WsServerSessionCoro : public WsSessionCoro {
public:
    WsServerSessionCoro(net::io_context& ioc, tcp::socket socket,
                         WsControllerServerCoro* server,
                         const std::string& query_string);

    ~WsServerSessionCoro() override;

    uint32_t server_id() const { return server_id_; }

protected:
    // WsSessionCoro interface
    net::awaitable<void> on_connected() override;
    net::awaitable<void> process_frame(const wire::Frame& frame) override;
    net::awaitable<void> on_disconnected(const std::string& reason) override;

private:
    // Binary frame handlers
    void handle_server_register(const wire::Frame& frame);
    void handle_ping(const wire::Frame& frame);
    void handle_stats_report(const wire::Frame& frame);
    void handle_mesh_forward(const wire::Frame& frame);

    // Helper methods
    void on_server_authenticated(uint32_t server_id);
    void send_error(wire::ErrorCode code, const std::string& message);

    WsControllerServerCoro* server_;
    std::string query_string_;
    bool server_authenticated_{false};
    uint32_t server_id_{0};
    std::string server_name_;
};

/**
 * WsBuiltinRelaySessionCoro - Handles client relay connections to built-in relay
 *
 * Used when the controller has a built-in relay enabled. Clients connect to
 * /api/v1/relay to relay data through the controller.
 */
class WsBuiltinRelaySessionCoro : public WsSessionCoro {
public:
    WsBuiltinRelaySessionCoro(net::io_context& ioc, tcp::socket socket,
                               WsControllerServerCoro* server);

    ~WsBuiltinRelaySessionCoro() override;

    const std::string& virtual_ip() const { return virtual_ip_; }

protected:
    // WsSessionCoro interface
    net::awaitable<void> on_connected() override;
    net::awaitable<void> process_frame(const wire::Frame& frame) override;
    net::awaitable<void> on_disconnected(const std::string& reason) override;

private:
    // Binary frame handlers
    net::awaitable<void> handle_relay_auth(const wire::Frame& frame);
    net::awaitable<void> handle_data(const wire::Frame& frame);
    net::awaitable<void> handle_ping(const wire::Frame& frame);

    // Helper methods
    void send_auth_response(bool success, uint32_t node_id, const std::string& error = "");
    void send_pong(uint64_t timestamp);
    void send_error(const std::string& code, const std::string& message);

    WsControllerServerCoro* server_;
    std::string virtual_ip_;
    bool relay_authenticated_{false};
};

} // namespace edgelink::controller

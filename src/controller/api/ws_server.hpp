#pragma once

#include "common/config.hpp"
#include "common/frame.hpp"
#include "controller/db/database.hpp"
#include "controller/api/control_handler.hpp"
#include "controller/services/path_service.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>

#include <memory>
#include <string>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace edgelink::controller {

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Forward declarations
class BuiltinRelay;
class WsControlSession;
class WsServerSession;

// ============================================================================
// WebSocket Session Manager
// ============================================================================

class WsSessionManager {
public:
    // Control sessions (nodes)
    void add_control_session(uint32_t node_id, uint32_t network_id, void* session);
    void remove_control_session(uint32_t node_id);
    void* get_control_session(uint32_t node_id);

    // Server sessions (relays/stun)
    void add_server_session(uint32_t server_id, void* session);
    void remove_server_session(uint32_t server_id);
    void* get_server_session(uint32_t server_id);

    // Broadcast to all nodes in a network
    void broadcast_to_network(uint32_t network_id, const std::string& text);

    // Get counts
    size_t node_count() const;
    size_t server_count() const;

    // Get all connected node IDs
    std::vector<uint32_t> get_connected_nodes() const;

private:
    mutable std::mutex control_mutex_;
    mutable std::mutex server_mutex_;

    struct ControlSession {
        void* session;
        uint32_t network_id;
    };

    struct ServerSession {
        void* session;
    };

    std::unordered_map<uint32_t, ControlSession> control_sessions_;
    std::unordered_map<uint32_t, ServerSession> server_sessions_;
};

// ============================================================================
// WebSocket Server
// ============================================================================

class WsServer {
public:
    WsServer(net::io_context& ioc,
             const ControllerConfig& config,
             std::shared_ptr<Database> db);

    ~WsServer();

    void start();
    void stop();

    WsSessionManager* get_session_manager() { return &session_manager_; }
    std::shared_ptr<Database> get_database() { return db_; }
    const ControllerConfig& get_config() const { return config_; }
    std::shared_ptr<PathService> get_path_service() { return path_service_; }

    // Set built-in relay (optional, for integrated relay functionality)
    void set_builtin_relay(BuiltinRelay* relay) { builtin_relay_ = relay; }
    BuiltinRelay* get_builtin_relay() { return builtin_relay_; }

private:
    void do_accept();
    void on_accept(beast::error_code ec, tcp::socket socket);

    net::io_context& ioc_;
    ControllerConfig config_;
    std::shared_ptr<Database> db_;
    std::shared_ptr<PathService> path_service_;

    std::unique_ptr<tcp::acceptor> acceptor_;
    ssl::context ssl_ctx_{ssl::context::tlsv12_server};
    WsSessionManager session_manager_;

    std::atomic<bool> running_{false};

    BuiltinRelay* builtin_relay_{nullptr};
};

// ============================================================================
// HTTP Session - Handles initial HTTP request and upgrades to WebSocket
// ============================================================================

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(tcp::socket&& socket, WsServer* server);

    void run();

private:
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);

    // Route handlers
    void handle_control_upgrade();
    void handle_server_upgrade();
    void handle_relay_upgrade();
    void send_not_found();

    tcp::socket socket_;
    WsServer* server_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
};

// ============================================================================
// WebSocket Control Session - Handles client connections on /control
// ============================================================================

class WsControlSession : public std::enable_shared_from_this<WsControlSession> {
public:
    WsControlSession(tcp::socket&& socket,
                     WsServer* server,
                     http::request<http::string_body>&& req);

    void run();
    void send(const std::vector<uint8_t>& data);
    void send_text(const std::string& text);
    void close();

    uint32_t node_id() const { return node_id_; }
    uint32_t network_id() const { return network_id_; }
    bool is_authenticated() const { return authenticated_; }

private:
    void do_accept();
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);

    void handle_message(const std::string& text);
    void on_authenticated(uint32_t node_id, uint32_t network_id);

    websocket::stream<tcp::socket> ws_;
    WsServer* server_;
    http::request<http::string_body> req_;

    beast::flat_buffer buffer_;
    std::vector<std::string> write_queue_;
    bool writing_{false};

    std::unique_ptr<ControlProtocolHandler> handler_;

    bool authenticated_{false};
    uint32_t node_id_{0};
    uint32_t network_id_{0};
};

// ============================================================================
// WebSocket Server Session - Handles relay/stun server connections on /server
// ============================================================================

class WsServerSession : public std::enable_shared_from_this<WsServerSession> {
public:
    WsServerSession(tcp::socket&& socket,
                    WsServer* server,
                    http::request<http::string_body>&& req);

    void run();
    void send(const std::vector<uint8_t>& data);
    void send_text(const std::string& text);
    void close();

    uint32_t server_id() const { return server_id_; }
    bool is_authenticated() const { return authenticated_; }

private:
    void do_accept();
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);

    void handle_message(const std::string& text);
    void on_authenticated(uint32_t server_id);

    websocket::stream<tcp::socket> ws_;
    WsServer* server_;
    http::request<http::string_body> req_;

    beast::flat_buffer buffer_;
    std::vector<std::string> write_queue_;
    bool writing_{false};

    std::unique_ptr<ServerProtocolHandler> handler_;

    bool authenticated_{false};
    uint32_t server_id_{0};
};

} // namespace edgelink::controller

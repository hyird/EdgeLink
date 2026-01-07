#pragma once

#include "common/config.hpp"
#include "controller/db/database.hpp"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/strand.hpp>
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>
#include <queue>
#include <variant>

namespace edgelink::controller {

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Forward declarations
class HttpSession;
class WebSocketSession;
class AuthService;
class NodeService;
class ConfigService;
class ControlProtocolHandler;
class ServerProtocolHandler;
class PathService;
class BuiltinRelay;

// ============================================================================
// HTTP Request Handler Types
// ============================================================================

using HttpRequest = http::request<http::string_body>;
using HttpResponse = http::response<http::string_body>;
using RouteHandler = std::function<HttpResponse(const HttpRequest&, const std::string&)>;

// ============================================================================
// HTTP Router
// ============================================================================

class HttpRouter {
public:
    void add_route(const std::string& method, const std::string& path, RouteHandler handler);
    std::pair<RouteHandler, std::string> find_route(const std::string& method, const std::string& path) const;
    
private:
    struct Route {
        std::string method;
        std::string pattern;
        RouteHandler handler;
        bool is_pattern{false};  // Has path parameters like :id
    };
    
    std::vector<Route> routes_;
    
    bool match_pattern(const std::string& pattern, const std::string& path, std::string& param) const;
};

// ============================================================================
// HTTP Session (handles one connection)
// ============================================================================

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(tcp::socket socket, 
                ssl::context& ctx,
                std::shared_ptr<HttpRouter> router,
                std::shared_ptr<Database> db,
                const std::string& jwt_secret,
                bool use_ssl,
                class WebSocketManager* ws_manager = nullptr,
                class BuiltinRelay* builtin_relay = nullptr,
                const std::string& server_token = "");
    
    void run();
    
private:
    void do_handshake();
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void handle_request();
    void send_response(HttpResponse&& response);
    void on_write(bool close, beast::error_code ec, std::size_t bytes_transferred);
    void do_close();
    
    // Check if this should upgrade to WebSocket
    bool should_upgrade_websocket();
    void upgrade_to_websocket();
    
    beast::flat_buffer buffer_;
    HttpRequest request_;
    std::shared_ptr<HttpResponse> response_;
    std::shared_ptr<HttpRouter> router_;
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;
    std::string server_token_;
    bool use_ssl_;
    class WebSocketManager* ws_manager_{nullptr};
    class BuiltinRelay* builtin_relay_{nullptr};
    
    // Socket variants
    std::variant<
        tcp::socket,
        beast::ssl_stream<tcp::socket>
    > stream_;
    
    ssl::context& ssl_ctx_;
};

// ============================================================================
// WebSocket Session Types
// ============================================================================

enum class WSSessionType {
    CONTROL,  // Node control connections (/ws/control)
    SERVER    // Server connections (/ws/server)
};

// ============================================================================
// WebSocket Session
// ============================================================================

class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
public:
    WebSocketSession(tcp::socket socket,
                     ssl::context& ctx,
                     WSSessionType type,
                     std::shared_ptr<Database> db,
                     const std::string& jwt_secret,
                     bool use_ssl,
                     class WebSocketManager* ws_manager = nullptr,
                     const std::string& server_token = "");
    
    void run(HttpRequest req);
    void send(const std::string& message);
    void send_config_update();  // Send config update using control handler
    void close();
    
    uint32_t get_node_id() const { return node_id_; }
    uint32_t get_server_id() const { return server_id_; }
    uint32_t get_network_id() const { return network_id_; }
    WSSessionType get_type() const { return type_; }
    bool is_authenticated() const { return authenticated_; }
    
    // Set by auth handlers
    void set_node_id(uint32_t id) { node_id_ = id; }
    void set_server_id(uint32_t id) { server_id_ = id; }
    void set_network_id(uint32_t id) { network_id_ = id; }
    void set_authenticated(bool auth) { authenticated_ = auth; }
    
    // Message callback
    using MessageCallback = std::function<void(std::shared_ptr<WebSocketSession>, const std::string&)>;
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    
    // Close callback
    using CloseCallback = std::function<void(std::shared_ptr<WebSocketSession>)>;
    void set_close_callback(CloseCallback cb) { close_callback_ = std::move(cb); }
    
    // Set path service for control sessions
    void set_path_service(std::shared_ptr<PathService> path_service);
    
private:
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    void fail(beast::error_code ec, const char* what);
    
    // Process message using protocol handler
    void process_message(const std::string& message);
    
    // Register session after authentication
    void register_with_manager();
    
    // Notify peers about online/offline status
    void notify_peer_status(bool online);
    
    beast::flat_buffer buffer_;
    WSSessionType type_;
    bool use_ssl_;
    bool authenticated_{false};
    bool registered_{false};
    uint32_t node_id_{0};
    uint32_t server_id_{0};
    uint32_t network_id_{0};
    
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;
    std::string server_token_;
    std::string query_string_;
    
    // Per-session protocol handlers (NOT static!)
    std::unique_ptr<ControlProtocolHandler> control_handler_;
    std::unique_ptr<ServerProtocolHandler> server_handler_;
    std::shared_ptr<PathService> path_service_;
    
    // WebSocket manager for session tracking
    class WebSocketManager* ws_manager_{nullptr};
    
    std::variant<
        websocket::stream<tcp::socket>,
        websocket::stream<beast::ssl_stream<tcp::socket>>
    > ws_;
    
    ssl::context& ssl_ctx_;
    
    std::queue<std::string> write_queue_;
    bool writing_{false};
    
    MessageCallback message_callback_;
    CloseCallback close_callback_;
};

// ============================================================================
// WebSocket Manager (tracks all connections)
// ============================================================================

class WebSocketManager {
public:
    void add_session(std::shared_ptr<WebSocketSession> session);
    void remove_session(std::shared_ptr<WebSocketSession> session);
    
    // Send to specific node
    void send_to_node(uint32_t node_id, const std::string& message);
    
    // Send to specific server
    void send_to_server(uint32_t server_id, const std::string& message);
    
    // Broadcast to all nodes in a network (optionally exclude one node)
    void broadcast_to_network(uint32_t network_id, const std::string& message, uint32_t exclude_node_id = 0);
    
    // Broadcast to all servers
    void broadcast_to_servers(const std::string& message);
    
    // Push config update to a specific node
    void push_config_update(uint32_t node_id);
    
    // Push config update to all nodes in a network
    void push_config_update_to_network(uint32_t network_id);
    
    // Get session counts
    size_t node_count() const { return node_sessions_.size(); }
    size_t server_count() const { return server_sessions_.size(); }
    
private:
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<WebSocketSession>> node_sessions_;
    std::unordered_map<uint32_t, std::shared_ptr<WebSocketSession>> server_sessions_;
};

// ============================================================================
// HTTP Server (accepts connections)
// ============================================================================

class HttpServer {
public:
    HttpServer(net::io_context& ioc,
               const ControllerConfig& config,
               std::shared_ptr<Database> db);
    
    ~HttpServer();
    
    void start();
    void stop();
    
    // Set built-in relay for /ws/data handling
    void set_builtin_relay(BuiltinRelay* relay) { builtin_relay_ = relay; }
    
    std::shared_ptr<HttpRouter> get_router() { return router_; }
    std::shared_ptr<WebSocketManager> get_ws_manager() { return ws_manager_; }
    std::shared_ptr<Database> get_db() { return db_; }
    
private:
    void do_accept();
    void on_accept(beast::error_code ec, tcp::socket socket);
    
    void setup_routes();
    void setup_ssl_context();
    
    net::io_context& ioc_;
    ssl::context ssl_ctx_{ssl::context::tlsv12};
    tcp::acceptor acceptor_;
    ControllerConfig config_;
    
    std::shared_ptr<HttpRouter> router_;
    std::shared_ptr<WebSocketManager> ws_manager_;
    std::shared_ptr<Database> db_;
    
    // Services
    std::shared_ptr<AuthService> auth_service_;
    std::shared_ptr<NodeService> node_service_;
    std::shared_ptr<ConfigService> config_service_;
    
    // Built-in relay (optional)
    BuiltinRelay* builtin_relay_{nullptr};
    
    bool running_{false};
};

// ============================================================================
// JSON Response Helpers
// ============================================================================

HttpResponse make_json_response(http::status status, const std::string& body);
HttpResponse make_error_response(http::status status, const std::string& error, const std::string& message);
HttpResponse make_success_response(const std::string& body);

} // namespace edgelink::controller

#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/jwt.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <functional>
#include <queue>

namespace edgelink {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

// Forward declarations
class RelaySessionManager;

// ============================================================================
// RelaySession - Handles a single node connection to the relay
// ============================================================================
class RelaySession : public std::enable_shared_from_this<RelaySession> {
public:
    using MessageCallback = std::function<void(std::shared_ptr<RelaySession>, const Frame&)>;
    using CloseCallback = std::function<void(std::shared_ptr<RelaySession>)>;
    using PathCallback = std::function<void(std::shared_ptr<RelaySession>, const std::string&)>;

    // Plain WebSocket constructor
    RelaySession(tcp::socket socket, RelaySessionManager& manager);
    
    // SSL WebSocket constructor
    RelaySession(tcp::socket socket, ssl::context& ssl_ctx, RelaySessionManager& manager);
    
    // Constructor without socket (for wrappers)
    explicit RelaySession(RelaySessionManager& manager);
    
    ~RelaySession();
    
    // Start the session (perform WebSocket handshake)
    void start();
    
    // Close the session
    void close();
    
    // Send a frame to the connected node
    void send(const Frame& frame);
    void send(std::vector<uint8_t> data);
    
    // Getters
    uint32_t node_id() const { return node_id_; }
    bool is_authenticated() const { return authenticated_; }
    const std::string& virtual_ip() const { return virtual_ip_; }
    const std::string& observed_ip() const { return observed_ip_; }
    uint16_t observed_port() const { return observed_port_; }
    const std::string& request_path() const { return request_path_; }
    
    // Set authentication info (called after token validation)
    void set_authenticated(uint32_t node_id, const std::string& virtual_ip);
    
    // Callbacks
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_close_callback(CloseCallback cb) { close_callback_ = std::move(cb); }
    // Called when path is determined (before WebSocket accept)
    void set_path_callback(PathCallback cb) { path_callback_ = std::move(cb); }

protected:
    void do_accept();
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    
    // HTTP request reading for path-based routing
    void do_read_http_request();
    void on_read_http_request(beast::error_code ec, std::size_t bytes_transferred);
    void do_ws_accept_with_request();
    
    // Process incoming frame
    void process_frame(const Frame& frame);
    
    RelaySessionManager& manager_;
    
    // WebSocket stream (plain or SSL)
    bool use_ssl_{false};
    std::unique_ptr<websocket::stream<tcp::socket>> ws_plain_;
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> ws_ssl_;
    
    // For HTTP request reading
    http::request<http::string_body> http_request_;
    std::string request_path_;
    
    // Receive buffer
    beast::flat_buffer read_buffer_;
    
    // Write queue
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_{false};
    
    // Node info (set after authentication)
    uint32_t node_id_{0};
    std::string virtual_ip_;
    bool authenticated_{false};
    
    // Observed endpoint (set from connection)
    std::string observed_ip_;
    uint16_t observed_port_{0};
    
    // Callbacks
    MessageCallback message_callback_;
    CloseCallback close_callback_;
    PathCallback path_callback_;
};

// ============================================================================
// RelaySessionManager - Manages all node sessions
// ============================================================================
class RelaySessionManager {
public:
    RelaySessionManager(JWTManager& jwt_manager);
    ~RelaySessionManager();
    
    // Session management
    void add_session(std::shared_ptr<RelaySession> session);
    void remove_session(std::shared_ptr<RelaySession> session);
    
    // Lookup sessions
    std::shared_ptr<RelaySession> get_session_by_node_id(uint32_t node_id);
    std::vector<std::shared_ptr<RelaySession>> get_all_sessions();
    size_t session_count() const;
    
    // Token validation
    bool validate_relay_token(const std::string& token, uint32_t& node_id, 
                              std::string& virtual_ip, std::vector<uint32_t>& allowed_relays);
    
    // Update blacklist (from controller)
    void add_to_blacklist(const std::string& jti, int64_t expires_at);
    void set_blacklist(const std::vector<std::pair<std::string, int64_t>>& entries);
    
    // Node location tracking (from controller)
    void update_node_locations(const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations);
    std::vector<uint32_t> get_node_relay_locations(uint32_t node_id) const;
    
    // Get JWT manager
    JWTManager& jwt_manager() { return jwt_manager_; }

private:
    JWTManager& jwt_manager_;
    
    // Active sessions
    mutable std::shared_mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::weak_ptr<RelaySession>> sessions_by_node_id_;
    std::unordered_set<std::shared_ptr<RelaySession>> all_sessions_;
    
    // Token blacklist
    mutable std::shared_mutex blacklist_mutex_;
    std::unordered_map<std::string, int64_t> token_blacklist_;  // jti -> expires_at
    
    // Node locations (node_id -> list of relay server IDs where node is connected)
    mutable std::shared_mutex locations_mutex_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> node_locations_;
};

} // namespace edgelink

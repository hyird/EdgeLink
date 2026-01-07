#pragma once

#include "common/config.hpp"
#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/jwt.hpp"
#include "controller/db/database.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <queue>

namespace edgelink::controller {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

// Forward declarations
class WebSocketManager;

// ============================================================================
// BuiltinRelaySession - A client data session for built-in relay
// ============================================================================
class BuiltinRelaySession : public std::enable_shared_from_this<BuiltinRelaySession> {
public:
    BuiltinRelaySession(tcp::socket socket, 
                        class BuiltinRelay* relay,
                        const std::string& jwt_secret);
    
    void run(boost::beast::http::request<boost::beast::http::string_body> req);
    void send(const std::vector<uint8_t>& data);
    void close();
    
    uint32_t node_id() const { return node_id_; }
    bool is_authenticated() const { return authenticated_; }

private:
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    
    void process_frame(const uint8_t* data, size_t size);
    void handle_auth(const Frame& frame);
    void handle_data(const Frame& frame);
    void handle_ping(const Frame& frame);
    
    websocket::stream<tcp::socket> ws_;
    beast::flat_buffer buffer_;
    
    class BuiltinRelay* relay_;
    JWTManager jwt_manager_;
    
    uint32_t node_id_{0};
    uint32_t network_id_{0};
    bool authenticated_{false};
    
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_{false};
    std::mutex write_mutex_;
};

// ============================================================================
// BuiltinRelay - Built-in relay functionality for Controller
// ============================================================================
class BuiltinRelay {
public:
    BuiltinRelay(net::io_context& ioc,
                 const BuiltinRelayConfig& config,
                 std::shared_ptr<Database> db,
                 const std::string& jwt_secret);
    ~BuiltinRelay();
    
    // Handle WebSocket upgrade for /ws/data path
    void handle_upgrade(tcp::socket socket, boost::beast::http::request<boost::beast::http::string_body> req);
    
    // Session management
    void register_session(uint32_t node_id, std::shared_ptr<BuiltinRelaySession> session);
    void unregister_session(uint32_t node_id);
    
    // Forward data to destination node
    bool forward_data(uint32_t dst_node_id, const std::vector<uint8_t>& data);
    
    // Get database
    std::shared_ptr<Database> database() { return db_; }
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_forwarded{0};
        std::atomic<uint64_t> packets_forwarded{0};
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> connections_active{0};
    };
    const Stats& stats() const { return stats_; }
    
    // Configuration
    const BuiltinRelayConfig& config() const { return config_; }
    
    // Check if enabled
    bool is_enabled() const { return config_.enabled; }

private:
    net::io_context& ioc_;
    BuiltinRelayConfig config_;
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;
    
    // Node sessions
    std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, std::weak_ptr<BuiltinRelaySession>> sessions_;
    
    Stats stats_;
};

} // namespace edgelink::controller

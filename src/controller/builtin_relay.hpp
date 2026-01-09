#pragma once

#include "common/config.hpp"
#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/jwt.hpp"
#include "controller/db/database.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>

#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>
#include <functional>

namespace edgelink::controller {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// ============================================================================
// Relay Session Manager - Manages relay data connections (WebSocket version)
// ============================================================================
class RelaySessionManager {
public:
    RelaySessionManager(const std::string& jwt_secret);

    // Session management using opaque pointers
    void add_session(uint32_t node_id, void* session);
    void remove_session(uint32_t node_id);
    void* get_session(uint32_t node_id);

    // Token validation
    bool validate_relay_token(const std::string& token, uint32_t& node_id,
                              std::string& virtual_ip);

    // Token blacklist
    void add_to_blacklist(const std::string& jti, int64_t expires_at);
    bool is_blacklisted(const std::string& jti) const;

    // Get session count
    size_t session_count() const;

    const std::string& jwt_secret() const { return jwt_secret_; }

private:
    std::string jwt_secret_;

    mutable std::shared_mutex sessions_mutex_;
    std::unordered_map<uint32_t, void*> sessions_;

    mutable std::shared_mutex blacklist_mutex_;
    std::unordered_map<std::string, int64_t> token_blacklist_;
};

// Forward declaration
class WsRelaySession;

// ============================================================================
// BuiltinRelay - Built-in relay functionality for Controller (WebSocket version)
// ============================================================================
class BuiltinRelay : public std::enable_shared_from_this<BuiltinRelay> {
public:
    BuiltinRelay(net::io_context& ioc,
                 const BuiltinRelayConfig& config,
                 std::shared_ptr<Database> db,
                 const std::string& jwt_secret);
    ~BuiltinRelay();

    void start();
    void stop();

    // Forward data to destination node
    bool forward_data(uint32_t dst_node_id, const std::vector<uint8_t>& data,
                      uint32_t src_node_id);

    // Send binary frame to a node
    bool send_to_node(uint32_t node_id, const std::vector<uint8_t>& frame_data);

    // Get session manager
    RelaySessionManager* session_manager() { return &session_manager_; }

    // Get database
    std::shared_ptr<Database> database() { return db_; }

    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_forwarded{0};
        std::atomic<uint64_t> packets_forwarded{0};
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> connections_active{0};
        std::atomic<uint64_t> auth_failures{0};
    };
    const Stats& stats() const { return stats_; }
    Stats& stats() { return stats_; }

    // Configuration
    const BuiltinRelayConfig& config() const { return config_; }

    // Check if enabled
    bool is_enabled() const { return config_.enabled; }

    // Get io_context
    net::io_context& get_io_context() { return ioc_; }

private:
    net::io_context& ioc_;
    BuiltinRelayConfig config_;
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;

    RelaySessionManager session_manager_;

    std::atomic<bool> running_{false};
    Stats stats_;
};

// ============================================================================
// WsRelaySession - Handles one client's relay WebSocket connection
// ============================================================================
class WsRelaySession : public std::enable_shared_from_this<WsRelaySession> {
public:
    using DataCallback = std::function<void(uint32_t src_node, uint32_t dst_node,
                                            const std::vector<uint8_t>& data)>;

    WsRelaySession(tcp::socket&& socket,
                   BuiltinRelay* relay);

    // Start the session
    void run();

    // Send binary data
    void send(const std::vector<uint8_t>& data);

    // Close the session
    void close();

    uint32_t node_id() const { return node_id_; }
    bool is_authenticated() const { return authenticated_; }

    void set_data_callback(DataCallback cb) { data_callback_ = std::move(cb); }

private:
    void do_accept();
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);

    // Message handlers
    void handle_message(const std::vector<uint8_t>& data);
    void handle_relay_auth(const boost::json::object& payload);
    void handle_data_frame(const wire::FrameHeader& header, std::span<const uint8_t> payload);
    void handle_ping(const boost::json::object& payload);

    // Response helpers
    void send_auth_response(bool success, uint32_t node_id, const std::string& error = "");
    void send_pong(uint64_t timestamp);
    void send_error(const std::string& code, const std::string& message);

    websocket::stream<tcp::socket> ws_;
    BuiltinRelay* relay_;

    beast::flat_buffer buffer_;
    std::vector<std::vector<uint8_t>> write_queue_;
    bool writing_{false};

    bool authenticated_{false};
    uint32_t node_id_{0};
    std::string virtual_ip_;

    DataCallback data_callback_;
};

} // namespace edgelink::controller

#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/config.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <memory>
#include <functional>
#include <atomic>
#include <queue>
#include <variant>

namespace edgelink {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

// Forward declarations
class RelayServer;

// Stream types
using plain_ws_stream = websocket::stream<beast::tcp_stream>;
using ssl_ws_stream = websocket::stream<ssl::stream<beast::tcp_stream>>;

// ============================================================================
// ControllerClient - WebSocket client to connect relay to controller
// ============================================================================
class ControllerClient : public std::enable_shared_from_this<ControllerClient> {
public:
    using ConnectCallback = std::function<void(bool success, const std::string& error)>;
    using MessageCallback = std::function<void(const Frame& frame)>;
    using DisconnectCallback = std::function<void(const std::string& reason)>;
    
    ControllerClient(asio::io_context& ioc, RelayServer& server, const ServerConfig& config);
    ~ControllerClient();
    
    // Connect to controller
    void connect();
    
    // Disconnect
    void disconnect();
    
    // Send a frame to controller
    void send(const Frame& frame);
    void send(std::vector<uint8_t> data);
    
    // Check connection state
    bool is_connected() const { return connected_; }
    
    // Set callbacks
    void set_connect_callback(ConnectCallback cb) { connect_callback_ = std::move(cb); }
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_disconnect_callback(DisconnectCallback cb) { disconnect_callback_ = std::move(cb); }
    
    // Send latency report to controller
    void send_latency_report(const std::vector<std::tuple<std::string, uint32_t, uint32_t>>& entries);
    
private:
    // Connection flow
    void do_resolve();
    void on_resolve(beast::error_code ec, tcp::resolver::results_type results);
    void do_connect(tcp::resolver::results_type::endpoint_type ep);
    void on_connect(beast::error_code ec);
    void do_ssl_handshake();
    void on_ssl_handshake(beast::error_code ec);
    void do_ws_handshake();
    void on_ws_handshake(beast::error_code ec);
    
    // Registration with controller
    void do_register();
    
    // Read/write operations
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    
    // Process incoming frame
    void process_frame(const Frame& frame);
    
    // Handle specific message types from controller
    void handle_server_node_loc(const Frame& frame);
    void handle_server_blacklist(const Frame& frame);
    void handle_server_relay_list(const Frame& frame);
    void handle_control_message(const Frame& frame);
    void handle_ping(const Frame& frame);
    void handle_error(const Frame& frame);
    
    // Reconnection
    void schedule_reconnect();
    void do_reconnect();
    
    // Heartbeat
    void start_heartbeat();
    void on_heartbeat_timer();
    
    // Helper to get the lowest layer for stream operations
    beast::tcp_stream& get_lowest_layer();
    
    asio::io_context& ioc_;
    RelayServer& server_;
    const ServerConfig& config_;
    
    // Resolver
    tcp::resolver resolver_;
    
    // SSL context
    ssl::context ssl_ctx_;
    
    // WebSocket stream - variant for SSL and plain TCP
    std::variant<
        std::unique_ptr<plain_ws_stream>,
        std::unique_ptr<ssl_ws_stream>
    > ws_;
    
    // URL parsing
    std::string host_;
    std::string port_;
    std::string path_;
    bool use_ssl_{true};
    
    // Read buffer
    beast::flat_buffer read_buffer_;
    
    // Write queue
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_{false};
    
    // State
    std::atomic<bool> connected_{false};
    std::atomic<bool> connecting_{false};
    std::atomic<bool> registered_{false};
    
    // Reconnection
    std::unique_ptr<asio::steady_timer> reconnect_timer_;
    int reconnect_attempts_{0};
    static constexpr int MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr int BASE_RECONNECT_DELAY_MS = 1000;
    static constexpr int MAX_RECONNECT_DELAY_MS = 60000;
    
    // Heartbeat
    std::unique_ptr<asio::steady_timer> heartbeat_timer_;
    static constexpr int HEARTBEAT_INTERVAL_SEC = 30;
    
    // Callbacks
    ConnectCallback connect_callback_;
    MessageCallback message_callback_;
    DisconnectCallback disconnect_callback_;
};

} // namespace edgelink

#pragma once

#include "mesh_manager.hpp"
#include "common/protocol.hpp"
#include "common/frame.hpp"

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <memory>
#include <string>
#include <queue>
#include <atomic>

namespace edgelink {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

class MeshManager;

// ============================================================================
// MeshClient - Outbound connection to another Relay's /ws/mesh endpoint
// ============================================================================
class MeshClient : public MeshConnection, public std::enable_shared_from_this<MeshClient> {
public:
    using ConnectCallback = std::function<void(bool success)>;
    using MessageCallback = std::function<void(const Frame& frame)>;
    using CloseCallback = std::function<void()>;
    
    MeshClient(asio::io_context& ioc, MeshManager& manager, 
               uint32_t local_relay_id, const MeshPeerInfo& peer);
    ~MeshClient();
    
    // Connect to the peer relay
    void connect();
    
    // MeshConnection interface
    void send(const Frame& frame) override;
    void send(std::vector<uint8_t> data) override;
    bool is_connected() const override { return connected_; }
    uint32_t peer_relay_id() const override { return peer_relay_id_; }
    void close() override;
    
    // Callbacks
    void set_connect_callback(ConnectCallback cb) { connect_callback_ = std::move(cb); }
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_close_callback(CloseCallback cb) { close_callback_ = std::move(cb); }
    
    // Get peer info
    const MeshPeerInfo& peer_info() const { return peer_info_; }

private:
    // Connection sequence
    void do_resolve();
    void on_resolve(beast::error_code ec, tcp::resolver::results_type results);
    void do_connect(tcp::resolver::results_type results);
    void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep);
    void do_ssl_handshake();
    void on_ssl_handshake(beast::error_code ec);
    void do_ws_handshake();
    void on_ws_handshake(beast::error_code ec);
    
    // Mesh handshake (exchange relay IDs)
    void do_mesh_handshake();
    void on_mesh_handshake_sent(beast::error_code ec, std::size_t bytes_transferred);
    void on_mesh_handshake_received(beast::error_code ec, std::size_t bytes_transferred);
    
    // Read/write operations
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    
    // Process incoming frame
    void process_frame(const Frame& frame);
    
    // Handle connection failure
    void on_connection_failed(const std::string& reason);
    
    // Parse URL
    bool parse_url(const std::string& url);
    
    asio::io_context& ioc_;
    MeshManager& manager_;
    uint32_t local_relay_id_;
    MeshPeerInfo peer_info_;
    uint32_t peer_relay_id_{0};  // Set after handshake
    
    // URL components
    std::string host_;
    std::string port_;
    std::string path_;
    bool use_ssl_{true};
    
    // Resolver
    tcp::resolver resolver_;
    
    // SSL context
    std::unique_ptr<ssl::context> ssl_ctx_;
    
    // WebSocket stream (plain or SSL) using beast::tcp_stream for timeout support
    std::unique_ptr<websocket::stream<beast::tcp_stream>> ws_plain_;
    std::unique_ptr<websocket::stream<beast::ssl_stream<beast::tcp_stream>>> ws_ssl_;
    
    // Buffers
    beast::flat_buffer read_buffer_;
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_{false};
    
    // State
    std::atomic<bool> connected_{false};
    std::atomic<bool> closing_{false};
    
    // Callbacks
    ConnectCallback connect_callback_;
    MessageCallback message_callback_;
    CloseCallback close_callback_;
    
    // Reconnection
    std::unique_ptr<asio::steady_timer> reconnect_timer_;
    int reconnect_attempts_{0};
    static constexpr int MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr int RECONNECT_DELAY_SEC = 5;
};

} // namespace edgelink

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
// MeshSession - Inbound connection from another Relay's /ws/mesh
// ============================================================================
class MeshSession : public MeshConnection, public std::enable_shared_from_this<MeshSession> {
public:
    using MessageCallback = std::function<void(const Frame& frame)>;
    using CloseCallback = std::function<void()>;
    
    // Plain WebSocket constructor
    MeshSession(tcp::socket socket, MeshManager& manager, uint32_t local_relay_id);
    
    // SSL WebSocket constructor
    MeshSession(tcp::socket socket, ssl::context& ssl_ctx, 
                MeshManager& manager, uint32_t local_relay_id);
    
    ~MeshSession();
    
    // Start the session (perform WebSocket handshake)
    void start();
    
    // MeshConnection interface
    void send(const Frame& frame) override;
    void send(std::vector<uint8_t> data) override;
    bool is_connected() const override { return connected_; }
    uint32_t peer_relay_id() const override { return peer_relay_id_; }
    void close() override;
    
    // Callbacks
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_close_callback(CloseCallback cb) { close_callback_ = std::move(cb); }
    
    // Check if handshake completed
    bool is_authenticated() const { return authenticated_; }

private:
    void do_accept();
    void on_accept(beast::error_code ec);
    
    // Mesh handshake
    void do_mesh_handshake_receive();
    void on_mesh_handshake_received(beast::error_code ec, std::size_t bytes_transferred);
    void send_mesh_handshake_response(bool accepted, const std::string& reason = "");
    void on_mesh_handshake_sent(beast::error_code ec, std::size_t bytes_transferred);
    
    // Read/write operations
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    
    // Process incoming frame
    void process_frame(const Frame& frame);
    
    MeshManager& manager_;
    uint32_t local_relay_id_;
    uint32_t peer_relay_id_{0};
    std::string peer_region_;
    
    // WebSocket stream (plain or SSL)
    bool use_ssl_{false};
    std::unique_ptr<websocket::stream<tcp::socket>> ws_plain_;
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> ws_ssl_;
    
    // Buffers
    beast::flat_buffer read_buffer_;
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_{false};
    
    // State
    std::atomic<bool> connected_{false};
    std::atomic<bool> authenticated_{false};
    std::atomic<bool> closing_{false};
    
    // Observed endpoint
    std::string observed_ip_;
    uint16_t observed_port_{0};
    
    // Callbacks
    MessageCallback message_callback_;
    CloseCallback close_callback_;
};

} // namespace edgelink

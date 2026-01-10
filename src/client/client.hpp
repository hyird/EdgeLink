#pragma once

#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/channel.hpp"
#include "client/tun_device.hpp"
#include "client/ipc_server.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace asio = boost::asio;
namespace ssl = asio::ssl;

namespace edgelink::client {

// Client configuration
struct ClientConfig {
    std::string controller_url = "ws://localhost:8080";  // Server address (path auto-appended)
    std::string authkey;
    bool tls = false;  // Enable TLS (wss://) - default disabled
    bool auto_reconnect = true;
    std::chrono::seconds reconnect_interval{5};
    std::chrono::seconds ping_interval{5};  // Keep connection alive, avoid CDN idle timeout
    std::chrono::seconds dns_refresh_interval{60};  // DNS resolution refresh interval (0 = disabled)
    std::chrono::seconds latency_measure_interval{30};  // Peer latency measurement interval (0 = disabled)

    // SSL/TLS settings
    bool ssl_verify = false;            // Verify server certificate (default: false for dev)
    std::string ssl_ca_file;            // Custom CA certificate file (empty = system default)
    bool ssl_allow_self_signed = false; // Allow self-signed certificates

    // State directory for storing persistent keys
    std::string state_dir;  // Empty = platform default

    // TUN mode settings
    bool enable_tun = false;       // Enable TUN device for IP-level routing
    std::string tun_name = "";     // TUN device name (empty = auto)
    uint32_t tun_mtu = 1420;       // MTU for TUN device

    // IPC server settings
    bool enable_ipc = true;        // Enable IPC control interface
    std::string ipc_socket_path;   // IPC socket path (empty = platform default)
};

// Client state
enum class ClientState {
    STOPPED,
    STARTING,
    AUTHENTICATING,
    CONNECTING_RELAY,
    RUNNING,
    RECONNECTING,
};

const char* client_state_name(ClientState state);

// Callbacks
struct ClientCallbacks {
    std::function<void()> on_connected;
    std::function<void()> on_disconnected;
    std::function<void(NodeId peer_id, std::span<const uint8_t> data)> on_data_received;
    std::function<void(uint16_t code, const std::string& msg)> on_error;
    std::function<void()> on_shutdown_requested;  // Called when shutdown is requested via IPC
};

// Main client coordinator
class Client : public std::enable_shared_from_this<Client> {
public:
    Client(asio::io_context& ioc, const ClientConfig& config);
    ~Client();

    // Start the client (authenticate and connect to relay)
    asio::awaitable<bool> start();

    // Stop the client
    asio::awaitable<void> stop();

    // Send data to a peer
    asio::awaitable<bool> send_to_peer(NodeId peer_id, std::span<const uint8_t> data);

    // Send data to a peer by virtual IP
    asio::awaitable<bool> send_to_ip(const IPv4Address& ip, std::span<const uint8_t> data);

    // Send raw IP packet (for TUN mode)
    asio::awaitable<bool> send_ip_packet(std::span<const uint8_t> packet);

    // Ping a peer and return latency in milliseconds (0 = timeout/error)
    asio::awaitable<uint16_t> ping_peer(NodeId peer_id, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    asio::awaitable<uint16_t> ping_ip(const IPv4Address& ip, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    // Set callbacks
    void set_callbacks(ClientCallbacks callbacks);

    // Accessors
    ClientState state() const { return state_; }
    bool is_running() const { return state_ == ClientState::RUNNING; }

    NodeId node_id() const { return crypto_.node_id(); }
    IPv4Address virtual_ip() const { return control_ ? control_->virtual_ip() : IPv4Address{}; }
    NetworkId network_id() const { return control_ ? control_->network_id() : 0; }

    CryptoEngine& crypto() { return crypto_; }
    PeerManager& peers() { return peers_; }

    // TUN device (if enabled)
    TunDevice* tun_device() { return tun_.get(); }
    bool is_tun_enabled() const { return config_.enable_tun && tun_ && tun_->is_open(); }

    // IPC server (if enabled)
    IpcServer* ipc_server() { return ipc_.get(); }
    bool is_ipc_enabled() const { return config_.enable_ipc && ipc_ && ipc_->is_running(); }

private:
    void setup_callbacks();

    // TUN device management
    bool setup_tun();
    void teardown_tun();
    void on_tun_packet(std::span<const uint8_t> packet);

    // IPC server management
    bool setup_ipc();
    void teardown_ipc();

    // Ping management
    void handle_ping_data(NodeId src, std::span<const uint8_t> data);
    void send_pong(NodeId peer_id, uint32_t seq_num, uint64_t timestamp);

    // Keepalive timer
    asio::awaitable<void> keepalive_loop();

    // DNS refresh loop - periodically check for DNS changes
    asio::awaitable<void> dns_refresh_loop();

    // Latency measurement loop - periodically measure peer latency
    asio::awaitable<void> latency_measure_loop();

    // Reconnection logic
    asio::awaitable<void> reconnect();

    asio::io_context& ioc_;
    ssl::context ssl_ctx_;
    ClientConfig config_;
    ClientState state_ = ClientState::STOPPED;

    CryptoEngine crypto_;
    PeerManager peers_;

    std::shared_ptr<ControlChannel> control_;
    std::shared_ptr<RelayChannel> relay_;

    asio::steady_timer keepalive_timer_;
    asio::steady_timer reconnect_timer_;
    asio::steady_timer dns_refresh_timer_;
    asio::steady_timer latency_timer_;

    // Cached DNS resolution results for change detection
    std::string cached_controller_endpoints_;

    // TUN device (optional)
    std::unique_ptr<TunDevice> tun_;

    // IPC server (optional)
    std::shared_ptr<IpcServer> ipc_;

    // Pending ping state
    struct PendingPing {
        uint64_t send_time = 0;
        std::function<void(uint16_t)> callback;  // latency_ms or 0 on timeout
    };
    std::mutex ping_mutex_;
    std::unordered_map<uint64_t, PendingPing> pending_pings_;  // key = (node_id << 32) | seq_num
    uint32_t ping_seq_ = 0;

    ClientCallbacks callbacks_;
};

} // namespace edgelink::client

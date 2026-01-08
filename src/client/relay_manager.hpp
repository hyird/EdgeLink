#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>
#include <queue>
#include <chrono>
#include <expected>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "client/control_channel.hpp"

namespace edgelink::client {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

// ============================================================================
// Relay Connection State
// ============================================================================
struct RelayConnection {
    using WsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
    using WsStreamPlain = websocket::stream<beast::tcp_stream>;
    
    uint32_t server_id = 0;
    std::string host;
    uint16_t port = 443;
    std::string path;
    std::string region;
    bool use_tls = true;
    
    // TLS or plain WebSocket (only one will be active)
    std::unique_ptr<WsStream> ws;
    std::unique_ptr<WsStreamPlain> ws_plain;
    beast::flat_buffer read_buffer;
    
    enum class State {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        RECONNECTING
    };
    std::atomic<State> state{State::DISCONNECTED};
    
    // Latency tracking
    uint32_t latency_ms = 0;
    std::chrono::steady_clock::time_point last_ping;
    std::chrono::steady_clock::time_point last_pong;
    uint32_t missed_pongs = 0;
    
    // Write queue
    std::mutex write_mutex;
    std::queue<std::vector<uint8_t>> write_queue;
    std::atomic<bool> writing{false};
    
    // Statistics
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    
    // Reconnection
    uint32_t reconnect_attempts = 0;
    
    // Helper to check if connected
    bool is_open() const {
        if (use_tls) {
            return ws && ws->is_open();
        } else {
            return ws_plain && ws_plain->is_open();
        }
    }
};

// ============================================================================
// Path Information (which relay to use for a peer)
// ============================================================================
struct PeerPath {
    uint32_t peer_node_id = 0;
    uint32_t primary_relay_id = 0;
    uint32_t backup_relay_id = 0;
    uint32_t latency_ms = 0;
    bool has_p2p = false;
    std::chrono::steady_clock::time_point updated_at;
};

// ============================================================================
// Relay Manager Callbacks
// ============================================================================
struct RelayManagerCallbacks {
    // Called when data is received from a peer (decrypted)
    std::function<void(uint32_t src_node_id, const std::vector<uint8_t>& data)> on_data_received;
    
    // Called when relay connection state changes
    std::function<void(uint32_t relay_id, RelayConnection::State state)> on_relay_state_changed;
    
    // Called when latency measurement is complete
    std::function<void(uint32_t relay_id, uint32_t peer_id, uint32_t latency_ms)> on_latency_measured;
};

// ============================================================================
// Relay Manager - Manages multiple relay connections
// ============================================================================
class RelayManager : public std::enable_shared_from_this<RelayManager> {
public:
    RelayManager(
        net::io_context& ioc,
        ssl::context& ssl_ctx,
        uint32_t local_node_id,
        const std::string& relay_token
    );
    
    ~RelayManager();
    
    // Non-copyable
    RelayManager(const RelayManager&) = delete;
    RelayManager& operator=(const RelayManager&) = delete;
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    // Set callbacks
    void set_callbacks(RelayManagerCallbacks callbacks);
    
    // Update relay token (for token refresh)
    void update_token(const std::string& new_token);
    
    // Update relay server list (from Controller config)
    void update_relays(const std::vector<RelayServerInfo>& relays);
    
    // Update peer paths (from Controller)
    void update_paths(const std::vector<PeerPath>& paths);
    
    // ========================================================================
    // Connection Management
    // ========================================================================
    
    // Connect to all configured relays
    void connect_all();
    
    // Connect to a specific relay
    void connect_relay(uint32_t relay_id);
    
    // Disconnect from a specific relay
    void disconnect_relay(uint32_t relay_id);
    
    // Disconnect from all relays
    void disconnect_all();
    
    // ========================================================================
    // Data Transmission
    // ========================================================================
    
    // Send data to a peer (via best relay path)
    std::expected<void, ErrorCode> send_to_peer(
        uint32_t dst_node_id,
        const std::vector<uint8_t>& encrypted_data
    );
    
    // Send data via specific relay
    std::expected<void, ErrorCode> send_via_relay(
        uint32_t relay_id,
        uint32_t dst_node_id,
        const std::vector<uint8_t>& encrypted_data
    );
    
    // ========================================================================
    // Latency Measurement
    // ========================================================================
    
    // Measure latency to a peer through each relay
    void measure_latency_to_peer(uint32_t peer_node_id);
    
    // Start periodic latency measurements
    void start_latency_measurements();
    
    // Stop periodic latency measurements
    void stop_latency_measurements();
    
    // ========================================================================
    // Status
    // ========================================================================
    
    // Get best relay for a peer
    uint32_t get_best_relay(uint32_t peer_node_id) const;
    
    // Get relay connection state
    RelayConnection::State get_relay_state(uint32_t relay_id) const;
    
    // Get all connected relay IDs
    std::vector<uint32_t> get_connected_relays() const;
    
    // Get latency to peer via relay
    uint32_t get_latency(uint32_t peer_node_id, uint32_t relay_id) const;
    
    // Statistics
    struct Stats {
        uint32_t connected_relays = 0;
        uint64_t total_bytes_sent = 0;
        uint64_t total_bytes_received = 0;
        uint64_t total_packets_sent = 0;
        uint64_t total_packets_received = 0;
    };
    Stats get_stats() const;

private:
    // Relay connection management
    void do_connect_relay(std::shared_ptr<RelayConnection> relay);
    void on_relay_resolve(std::shared_ptr<RelayConnection> relay, beast::error_code ec,
                          tcp::resolver::results_type results);
    void on_relay_connect(std::shared_ptr<RelayConnection> relay, beast::error_code ec);
    void on_relay_connect_plain(std::shared_ptr<RelayConnection> relay, beast::error_code ec);
    void on_relay_ssl_handshake(std::shared_ptr<RelayConnection> relay, beast::error_code ec);
    void on_relay_ws_handshake(std::shared_ptr<RelayConnection> relay, beast::error_code ec);
    
    // Authentication
    void do_relay_auth(std::shared_ptr<RelayConnection> relay);
    void on_relay_auth_response(std::shared_ptr<RelayConnection> relay, const Frame& frame);
    
    // Reading
    void do_relay_read(std::shared_ptr<RelayConnection> relay);
    void on_relay_read(std::shared_ptr<RelayConnection> relay, beast::error_code ec, 
                       std::size_t bytes_transferred);
    void process_relay_frame(std::shared_ptr<RelayConnection> relay, const Frame& frame);
    
    // Writing
    void do_relay_write(std::shared_ptr<RelayConnection> relay);
    void send_to_relay(std::shared_ptr<RelayConnection> relay, Frame frame);
    
    // Heartbeat
    void start_relay_heartbeat(std::shared_ptr<RelayConnection> relay);
    void on_relay_heartbeat(std::shared_ptr<RelayConnection> relay);
    
    // Reconnection
    void schedule_relay_reconnect(std::shared_ptr<RelayConnection> relay);
    void on_relay_reconnect(std::shared_ptr<RelayConnection> relay);
    
    // Latency measurement
    void on_latency_timer();
    void send_latency_probe(std::shared_ptr<RelayConnection> relay, uint32_t peer_node_id);
    
    // IO context
    net::io_context& ioc_;
    ssl::context& ssl_ctx_;
    tcp::resolver resolver_;
    
    // Local node info
    uint32_t local_node_id_;
    std::string relay_token_;
    
    // Relay connections
    mutable std::mutex relays_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<RelayConnection>> relays_;
    
    // Peer paths
    mutable std::mutex paths_mutex_;
    std::unordered_map<uint32_t, PeerPath> peer_paths_;
    
    // Latency data: relay_id -> (peer_id -> latency_ms)
    mutable std::mutex latency_mutex_;
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> latency_data_;
    
    // Callbacks
    RelayManagerCallbacks callbacks_;
    
    // Timers
    std::unordered_map<uint32_t, std::unique_ptr<net::steady_timer>> heartbeat_timers_;
    net::steady_timer latency_timer_;
    bool latency_measuring_ = false;
    
    // Pending latency probes: (relay_id, peer_id) -> send_time
    std::mutex probes_mutex_;
    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> pending_probes_;
};

} // namespace edgelink::client

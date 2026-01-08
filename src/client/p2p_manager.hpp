#pragma once

#include "endpoint_manager.hpp"
#include "crypto_engine.hpp"

#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <queue>

namespace edgelink::client {

namespace net = boost::asio;
using udp = net::ip::udp;

// ============================================================================
// P2P Connection State
// ============================================================================

enum class P2PState {
    DISCONNECTED,       // No P2P connection
    INITIATING,         // Sent punch init to controller
    EXCHANGING,         // Exchanging endpoints with peer
    PUNCHING,           // Sending UDP punch packets
    HANDSHAKING,        // Exchanged packets, doing P2P handshake
    CONNECTED,          // P2P connection established
    FAILED              // P2P failed, using relay
};

inline const char* p2p_state_to_string(P2PState state) {
    switch (state) {
        case P2PState::DISCONNECTED: return "disconnected";
        case P2PState::INITIATING: return "initiating";
        case P2PState::EXCHANGING: return "exchanging";
        case P2PState::PUNCHING: return "punching";
        case P2PState::HANDSHAKING: return "handshaking";
        case P2PState::CONNECTED: return "connected";
        case P2PState::FAILED: return "failed";
        default: return "unknown";
    }
}

// ============================================================================
// P2P Peer Connection
// ============================================================================

struct P2PConnection {
    uint32_t peer_node_id = 0;
    P2PState state = P2PState::DISCONNECTED;
    
    // Peer endpoints received from controller
    std::vector<Endpoint> peer_endpoints;
    
    // Current best endpoint
    udp::endpoint active_endpoint;
    
    // Punching state
    int punch_attempt = 0;
    int punch_retry = 0;
    std::chrono::steady_clock::time_point punch_start_time;
    std::chrono::steady_clock::time_point last_punch_sent;
    
    // Connection metrics
    uint32_t rtt_ms = 0;
    std::chrono::steady_clock::time_point last_ping_sent;
    std::chrono::steady_clock::time_point last_pong_received;
    uint32_t missed_keepalives = 0;
    
    // Keepalive
    std::chrono::steady_clock::time_point last_keepalive_sent;
    std::chrono::steady_clock::time_point last_keepalive_received;
    uint32_t keepalive_sequence = 0;
    
    // Statistics
    uint64_t packets_sent = 0;
    uint64_t packets_received = 0;
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;
    
    // Adaptive keepalive interval (25s - 55s)
    std::chrono::seconds keepalive_interval{25};
    int successful_keepalives = 0;
    
    // Reset for new connection attempt
    void reset() {
        state = P2PState::DISCONNECTED;
        peer_endpoints.clear();
        punch_attempt = 0;
        punch_retry = 0;
        missed_keepalives = 0;
        keepalive_interval = std::chrono::seconds{25};
        successful_keepalives = 0;
    }
};

// ============================================================================
// P2P Manager Callbacks
// ============================================================================

struct P2PCallbacks {
    // Data received from peer via P2P
    std::function<void(uint32_t peer_id, const std::vector<uint8_t>& data)> on_data_received;
    
    // P2P connection state changed
    std::function<void(uint32_t peer_id, P2PState new_state)> on_state_changed;
    
    // Request to send punch init to controller
    std::function<void(uint32_t peer_id)> on_punch_request;
    
    // P2P connection established (can switch from relay)
    std::function<void(uint32_t peer_id, uint32_t rtt_ms)> on_connected;
    
    // P2P connection lost (should switch to relay)
    std::function<void(uint32_t peer_id)> on_disconnected;
};

// ============================================================================
// P2P Manager
// ============================================================================

class P2PManager : public std::enable_shared_from_this<P2PManager> {
public:
    P2PManager(net::io_context& ioc,
               std::shared_ptr<EndpointManager> endpoint_manager,
               std::shared_ptr<CryptoEngine> crypto_engine,
               uint32_t local_node_id);
    
    ~P2PManager();
    
    // Non-copyable
    P2PManager(const P2PManager&) = delete;
    P2PManager& operator=(const P2PManager&) = delete;
    
    // ========================================================================
    // Lifecycle
    // ========================================================================
    
    void start();
    void stop();
    
    void set_callbacks(P2PCallbacks callbacks) { callbacks_ = std::move(callbacks); }
    
    // ========================================================================
    // P2P Connection Management
    // ========================================================================
    
    // Initiate P2P connection to peer
    void initiate_connection(uint32_t peer_node_id);
    
    // Handle peer endpoints received from controller
    void handle_peer_endpoints(uint32_t peer_node_id, 
                               const std::vector<Endpoint>& endpoints,
                               NatType peer_nat_type);
    
    // Handle P2P init message from controller (peer wants to connect)
    void handle_p2p_init(uint32_t peer_node_id,
                         const std::vector<Endpoint>& peer_endpoints,
                         NatType peer_nat_type);
    
    // Close P2P connection to peer
    void close_connection(uint32_t peer_node_id);
    
    // ========================================================================
    // Data Transmission
    // ========================================================================
    
    // Send data to peer via P2P (returns false if not connected)
    bool send_to_peer(uint32_t peer_node_id, const std::vector<uint8_t>& data);
    
    // ========================================================================
    // Status
    // ========================================================================
    
    // Check if P2P is available for peer
    bool is_connected(uint32_t peer_node_id) const;
    
    // Get P2P state for peer
    P2PState get_state(uint32_t peer_node_id) const;
    
    // Get RTT to peer (0 if not connected)
    uint32_t get_rtt(uint32_t peer_node_id) const;
    
    // Get all connected peer IDs
    std::vector<uint32_t> get_connected_peers() const;

private:
    // UDP receive loop
    void do_receive();
    void handle_receive(const boost::system::error_code& ec, 
                        std::size_t bytes_received,
                        const udp::endpoint& sender);
    
    // Process received P2P packet
    void process_p2p_packet(const udp::endpoint& sender,
                           const uint8_t* data, size_t len);
    
    // UDP hole punching
    void start_punching(std::shared_ptr<P2PConnection> conn);
    void send_punch_packet(std::shared_ptr<P2PConnection> conn, 
                          const udp::endpoint& target);
    void on_punch_timer(std::shared_ptr<P2PConnection> conn);
    
    // Handshake (after punch succeeds)
    void send_p2p_ping(std::shared_ptr<P2PConnection> conn);
    void handle_p2p_pong(std::shared_ptr<P2PConnection> conn,
                        const uint8_t* data, size_t len);
    
    // Keepalive
    void start_keepalive_timer();
    void on_keepalive_timer();
    void send_keepalive(std::shared_ptr<P2PConnection> conn);
    void handle_keepalive(std::shared_ptr<P2PConnection> conn,
                         const uint8_t* data, size_t len);
    
    // Connection state management
    void set_connection_state(std::shared_ptr<P2PConnection> conn, P2PState new_state);
    void handle_connection_timeout(std::shared_ptr<P2PConnection> conn);
    void handle_connection_lost(std::shared_ptr<P2PConnection> conn);
    
    // Helper: find connection by peer endpoint
    std::shared_ptr<P2PConnection> find_connection_by_endpoint(const udp::endpoint& ep);
    
    // Helper: check if P2P is feasible based on NAT types
    bool is_p2p_feasible(NatType our_nat, NatType peer_nat) const;
    
    net::io_context& ioc_;
    std::shared_ptr<EndpointManager> endpoint_manager_;
    std::shared_ptr<CryptoEngine> crypto_engine_;
    uint32_t local_node_id_;
    
    // Connections
    mutable std::mutex connections_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<P2PConnection>> connections_;
    
    // Reverse mapping: endpoint -> peer_node_id
    std::mutex endpoint_map_mutex_;
    std::unordered_map<std::string, uint32_t> endpoint_to_peer_;
    
    // UDP receive buffer
    std::vector<uint8_t> recv_buffer_;
    udp::endpoint recv_endpoint_;
    
    // Timers
    std::unordered_map<uint32_t, std::unique_ptr<net::steady_timer>> punch_timers_;
    net::steady_timer keepalive_timer_;
    
    // Callbacks
    P2PCallbacks callbacks_;
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Configuration
    static constexpr int MAX_PUNCH_ATTEMPTS = 10;
    static constexpr int MAX_PUNCH_RETRIES = 3;
    static constexpr auto PUNCH_INTERVAL = std::chrono::milliseconds(100);
    static constexpr auto PUNCH_TIMEOUT = std::chrono::seconds(5);
    static constexpr auto KEEPALIVE_CHECK_INTERVAL = std::chrono::seconds(5);
    static constexpr int MAX_MISSED_KEEPALIVES = 3;
};

} // namespace edgelink::client

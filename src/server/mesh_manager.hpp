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
#include <unordered_map>
#include <shared_mutex>
#include <optional>
#include <set>

namespace edgelink {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

// Forward declarations
class MeshClient;
class MeshSession;
class RelayServer;

// ============================================================================
// MeshPeerInfo - Information about a mesh peer relay
// ============================================================================
struct MeshPeerInfo {
    uint32_t relay_id{0};
    std::string url;        // wss://relay2.example.com/ws/mesh
    std::string region;
    
    // Parse from JSON
    bool from_json(const boost::json::object& obj);
    boost::json::object to_json() const;
};

// ============================================================================
// MeshConnection - Abstract interface for Mesh connections
// ============================================================================
class MeshConnection {
public:
    virtual ~MeshConnection() = default;
    
    virtual void send(const Frame& frame) = 0;
    virtual void send(std::vector<uint8_t> data) = 0;
    virtual bool is_connected() const = 0;
    virtual uint32_t peer_relay_id() const = 0;
    virtual void close() = 0;
};

// ============================================================================
// MeshManager - Manages all Relay-to-Relay mesh connections
// ============================================================================
class MeshManager : public std::enable_shared_from_this<MeshManager> {
public:
    using MessageCallback = std::function<void(uint32_t relay_id, const Frame& frame)>;
    using ConnectionCallback = std::function<void(uint32_t relay_id, bool connected)>;
    
    MeshManager(asio::io_context& ioc, RelayServer& server, const ServerConfig& config);
    ~MeshManager();
    
    // Start mesh connections (connect to configured peers)
    void start();
    void stop();
    
    // Update peer list from controller
    void update_peers(const std::vector<MeshPeerInfo>& peers);
    
    // Forward data to specific relay
    bool forward_to_relay(uint32_t relay_id, const Frame& frame);
    
    // Broadcast to all connected relays
    void broadcast(const Frame& frame);
    
    // Get latency to a specific relay (from probing)
    std::optional<uint32_t> get_latency(uint32_t relay_id) const;
    
    // Get all connected relay IDs
    std::vector<uint32_t> get_connected_relays() const;
    
    // Accept incoming mesh connection from another relay
    void accept_connection(std::shared_ptr<MeshSession> session);
    
    // Register inbound adapter (RelaySession wrapped as MeshConnection)
    void register_inbound_adapter(uint32_t relay_id, std::shared_ptr<MeshConnection> adapter);
    
    // Handle disconnection
    void on_peer_disconnected(uint32_t relay_id);
    
    // Handle incoming mesh frame
    void on_mesh_frame(uint32_t relay_id, const Frame& frame);
    
    // Set callbacks
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_connection_callback(ConnectionCallback cb) { connection_callback_ = std::move(cb); }
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> frames_forwarded{0};
        std::atomic<uint64_t> bytes_forwarded{0};
        std::atomic<uint64_t> mesh_connections{0};
    };
    const Stats& stats() const { return stats_; }

private:
    // Get or create connection to a relay
    std::shared_ptr<MeshConnection> get_connection(uint32_t relay_id);
    
    // Connect to a peer relay
    void connect_to_peer(const MeshPeerInfo& peer);
    void on_peer_connected(uint32_t relay_id, std::shared_ptr<MeshClient> client);
    
    // Latency probing
    void start_latency_probe();
    void on_latency_probe_timer();
    void send_ping_to_peer(uint32_t relay_id);
    void handle_pong(uint32_t relay_id, uint64_t send_time);
    
    // Report latencies to controller
    void report_latencies();
    
    // Get latency statistics for all connected relays
    std::vector<std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>> get_all_latencies() const;
    
    asio::io_context& ioc_;
    RelayServer& server_;
    const ServerConfig& config_;
    
    // Outbound connections (we connect to them)
    // Protected by mutex
    mutable std::shared_mutex outbound_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<MeshClient>> outbound_peers_;
    
    // Inbound connections (they connect to us) - stores MeshConnection adapters
    // Protected by mutex
    mutable std::shared_mutex inbound_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<MeshConnection>> inbound_peers_;
    
    // Peer info from controller
    mutable std::shared_mutex peers_mutex_;
    std::unordered_map<uint32_t, MeshPeerInfo> known_peers_;
    
    // Latency measurements
    // RTT 以实际测量为准，支持 CDN 代理场景
    struct LatencyStats {
        uint32_t current_rtt_ms{0};         // 最新一次测量
        uint32_t avg_rtt_ms{0};             // 滑动平均 (EMA)
        uint32_t min_rtt_ms{UINT32_MAX};    // 最小 RTT
        uint32_t max_rtt_ms{0};             // 最大 RTT
        uint32_t sample_count{0};           // 采样次数
        int64_t last_update_time{0};        // 最后更新时间
        
        void update(uint32_t rtt_ms) {
            current_rtt_ms = rtt_ms;
            min_rtt_ms = std::min(min_rtt_ms, rtt_ms);
            max_rtt_ms = std::max(max_rtt_ms, rtt_ms);
            
            if (sample_count == 0) {
                avg_rtt_ms = rtt_ms;
            } else {
                // Exponential Moving Average with alpha = 0.3
                avg_rtt_ms = static_cast<uint32_t>(0.3 * rtt_ms + 0.7 * avg_rtt_ms);
            }
            sample_count++;
            last_update_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }
    };
    
    mutable std::shared_mutex latency_mutex_;
    std::unordered_map<uint32_t, LatencyStats> relay_latencies_;
    
    // Pending pings for RTT calculation (ping_id -> send_time_ns)
    mutable std::mutex pending_pings_mutex_;
    std::unordered_map<uint64_t, std::pair<uint32_t, int64_t>> pending_pings_; // ping_id -> (relay_id, send_time)
    std::atomic<uint64_t> next_ping_id_{1};
    
    // Latency probe timer
    std::unique_ptr<asio::steady_timer> probe_timer_;
    static constexpr int PROBE_INTERVAL_SEC = 30;
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Callbacks
    MessageCallback message_callback_;
    ConnectionCallback connection_callback_;
    
    // Statistics
    Stats stats_;
};

} // namespace edgelink

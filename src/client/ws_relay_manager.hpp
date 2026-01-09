#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <functional>
#include <chrono>
#include <expected>

#include <boost/asio.hpp>

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/ws_client.hpp"
#include "client/control_channel.hpp"

namespace edgelink::client {

namespace net = boost::asio;

// Import wire protocol error codes
using ErrorCode = wire::ErrorCode;

// ============================================================================
// Path Information (which relay to use for a peer)
// ============================================================================
struct WsPeerPath {
    uint32_t peer_node_id = 0;
    uint32_t primary_relay_id = 0;
    uint32_t backup_relay_id = 0;
    uint32_t latency_ms = 0;
    bool has_p2p = false;
    std::chrono::steady_clock::time_point updated_at;
};

// ============================================================================
// Relay Connection State (uses WsClientState)
// ============================================================================
using RelayState = WsClientState;

// ============================================================================
// Relay Manager Callbacks
// ============================================================================
struct WsRelayManagerCallbacks {
    std::function<void(uint32_t src_node_id, const std::vector<uint8_t>& data)> on_data_received;
    std::function<void(uint32_t relay_id, RelayState state)> on_relay_state_changed;
    std::function<void(uint32_t relay_id, uint32_t peer_id, uint32_t latency_ms)> on_latency_measured;
};

// ============================================================================
// Relay Connection - Wraps WsClient for a single relay
// ============================================================================
class WsRelayConnection : public WsClient {
public:
    WsRelayConnection(net::io_context& ioc, uint32_t server_id,
                      const std::string& url, const std::string& region,
                      const std::string& relay_token,
                      std::function<void(uint32_t, const wire::Frame&)> on_frame);

    uint32_t server_id() const { return server_id_; }
    const std::string& region() const { return region_; }
    uint32_t latency_ms() const { return latency_ms_; }

    void update_token(const std::string& token) { relay_token_ = token; }

protected:
    void do_authenticate() override;
    void process_frame(const wire::Frame& frame) override;

private:
    uint32_t server_id_;
    std::string region_;
    std::string relay_token_;
    uint32_t latency_ms_ = 0;
    std::function<void(uint32_t, const wire::Frame&)> on_frame_callback_;
};

// ============================================================================
// WebSocket Relay Manager - Manages multiple relay connections
// ============================================================================
class WsRelayManager {
public:
    WsRelayManager(net::io_context& ioc, uint32_t local_node_id, const std::string& relay_token);
    ~WsRelayManager();

    // Non-copyable
    WsRelayManager(const WsRelayManager&) = delete;
    WsRelayManager& operator=(const WsRelayManager&) = delete;

    // ========================================================================
    // Configuration
    // ========================================================================
    void set_callbacks(WsRelayManagerCallbacks callbacks);
    void update_token(const std::string& new_token);
    void update_relays(const std::vector<RelayServerInfo>& relays);
    void update_paths(const std::vector<WsPeerPath>& paths);

    // ========================================================================
    // Connection Management
    // ========================================================================
    void connect_all();
    void connect_relay(uint32_t relay_id);
    void disconnect_relay(uint32_t relay_id);
    void disconnect_all();

    // ========================================================================
    // Data Transmission
    // ========================================================================
    std::expected<void, ErrorCode> send_to_peer(
        uint32_t dst_node_id,
        const std::vector<uint8_t>& encrypted_data);

    std::expected<void, ErrorCode> send_via_relay(
        uint32_t relay_id,
        uint32_t dst_node_id,
        const std::vector<uint8_t>& encrypted_data);

    // ========================================================================
    // Latency Measurement
    // ========================================================================
    void measure_latency_to_peer(uint32_t peer_node_id);
    void start_latency_measurements();
    void stop_latency_measurements();

    // ========================================================================
    // Status
    // ========================================================================
    uint32_t get_best_relay(uint32_t peer_node_id) const;
    RelayState get_relay_state(uint32_t relay_id) const;
    std::vector<uint32_t> get_connected_relays() const;
    uint32_t get_latency(uint32_t peer_node_id, uint32_t relay_id) const;

    struct Stats {
        uint32_t connected_relays = 0;
        uint64_t total_bytes_sent = 0;
        uint64_t total_bytes_received = 0;
        uint64_t total_packets_sent = 0;
        uint64_t total_packets_received = 0;
    };
    Stats get_stats() const;

private:
    void on_relay_frame(uint32_t relay_id, const wire::Frame& frame);

    // IO context reference
    net::io_context& ioc_;

    // Local node info
    uint32_t local_node_id_;
    std::string relay_token_;

    // Relay connections
    mutable std::mutex relays_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<WsRelayConnection>> relays_;

    // Relay server info
    std::vector<RelayServerInfo> relay_servers_;

    // Peer paths
    mutable std::mutex paths_mutex_;
    std::unordered_map<uint32_t, WsPeerPath> peer_paths_;

    // Latency data: relay_id -> (peer_id -> latency_ms)
    mutable std::mutex latency_mutex_;
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> latency_data_;

    // Callbacks
    WsRelayManagerCallbacks callbacks_;

    // Latency measurement
    std::atomic<bool> latency_measuring_{false};

    // Shutdown flag
    std::atomic<bool> shutdown_{false};
};

} // namespace edgelink::client

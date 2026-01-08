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
#include <thread>

#include <grpcpp/grpcpp.h>
#include "edgelink.grpc.pb.h"

#include "common/protocol.hpp"
#include "client/control_channel.hpp"

namespace edgelink::client {

// Import wire protocol error codes to avoid conflicts with proto types
using ErrorCode = wire::ErrorCode;

// ============================================================================
// Relay Connection State (gRPC version)
// ============================================================================
struct GrpcRelayConnection {
    uint32_t server_id = 0;
    std::string url;           // grpc://host:port or grpcs://host:port
    std::string region;

    std::shared_ptr<grpc::Channel> channel;
    std::unique_ptr<edgelink::RelayService::Stub> stub;
    std::unique_ptr<grpc::ClientContext> context;
    std::unique_ptr<grpc::ClientReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>> stream;

    enum class State {
        DISCONNECTED,
        CONNECTING,
        AUTHENTICATING,
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
    std::queue<edgelink::RelayMessage> write_queue;
    std::atomic<bool> writing{false};

    // Statistics
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_received{0};
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_received{0};

    // Reconnection
    uint32_t reconnect_attempts = 0;

    // Reader/writer threads
    std::unique_ptr<std::thread> read_thread;
    std::unique_ptr<std::thread> write_thread;
    std::atomic<bool> running{false};
};

// ============================================================================
// Path Information (which relay to use for a peer)
// ============================================================================
struct GrpcPeerPath {
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
struct GrpcRelayManagerCallbacks {
    std::function<void(uint32_t src_node_id, const std::vector<uint8_t>& data)> on_data_received;
    std::function<void(uint32_t relay_id, GrpcRelayConnection::State state)> on_relay_state_changed;
    std::function<void(uint32_t relay_id, uint32_t peer_id, uint32_t latency_ms)> on_latency_measured;
};

// ============================================================================
// gRPC Relay Manager - Manages multiple relay connections via gRPC
// ============================================================================
class GrpcRelayManager : public std::enable_shared_from_this<GrpcRelayManager> {
public:
    GrpcRelayManager(uint32_t local_node_id, const std::string& relay_token);
    ~GrpcRelayManager();

    // Non-copyable
    GrpcRelayManager(const GrpcRelayManager&) = delete;
    GrpcRelayManager& operator=(const GrpcRelayManager&) = delete;

    // ========================================================================
    // Configuration
    // ========================================================================
    void set_callbacks(GrpcRelayManagerCallbacks callbacks);
    void update_token(const std::string& new_token);
    void update_relays(const std::vector<RelayServerInfo>& relays);
    void update_paths(const std::vector<GrpcPeerPath>& paths);

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
    GrpcRelayConnection::State get_relay_state(uint32_t relay_id) const;
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
    void do_connect_relay(std::shared_ptr<GrpcRelayConnection> relay);
    void do_relay_auth(std::shared_ptr<GrpcRelayConnection> relay);
    void read_loop(std::shared_ptr<GrpcRelayConnection> relay);
    void write_loop(std::shared_ptr<GrpcRelayConnection> relay);
    void process_relay_message(std::shared_ptr<GrpcRelayConnection> relay,
                               const edgelink::RelayMessage& msg);
    void send_message(std::shared_ptr<GrpcRelayConnection> relay,
                      edgelink::RelayMessage msg);
    void schedule_relay_reconnect(std::shared_ptr<GrpcRelayConnection> relay);
    void start_relay_heartbeat(std::shared_ptr<GrpcRelayConnection> relay);

    // Local node info
    uint32_t local_node_id_;
    std::string relay_token_;

    // Relay connections
    mutable std::mutex relays_mutex_;
    std::unordered_map<uint32_t, std::shared_ptr<GrpcRelayConnection>> relays_;

    // Relay server info (for reconnection)
    std::vector<RelayServerInfo> relay_servers_;

    // Peer paths
    mutable std::mutex paths_mutex_;
    std::unordered_map<uint32_t, GrpcPeerPath> peer_paths_;

    // Latency data: relay_id -> (peer_id -> latency_ms)
    mutable std::mutex latency_mutex_;
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> latency_data_;

    // Callbacks
    GrpcRelayManagerCallbacks callbacks_;

    // Latency measurement
    std::atomic<bool> latency_measuring_{false};
    std::unique_ptr<std::thread> latency_thread_;

    // Pending latency probes: (relay_id << 32 | peer_id) -> send_time
    std::mutex probes_mutex_;
    std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> pending_probes_;

    // Heartbeat threads
    std::unordered_map<uint32_t, std::unique_ptr<std::thread>> heartbeat_threads_;

    // Shutdown flag
    std::atomic<bool> shutdown_{false};
};

} // namespace edgelink::client

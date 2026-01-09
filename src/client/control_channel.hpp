#pragma once

#include <string>
#include <memory>
#include <functional>
#include <expected>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <array>

#include <boost/asio.hpp>

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/ws_client.hpp"

namespace edgelink::client {

namespace net = boost::asio;

// Import wire protocol error codes to avoid conflicts with proto types
using ErrorCode = wire::ErrorCode;

// Network constants
namespace NetworkConstants {
    constexpr uint16_t DEFAULT_TUN_MTU = 1400;
    constexpr uint32_t DEFAULT_HEARTBEAT_INTERVAL = 30;  // seconds
    constexpr uint32_t DEFAULT_RECONNECT_INTERVAL = 5;   // seconds
    constexpr uint32_t MAX_RECONNECT_INTERVAL = 300;     // 5 minutes max
}

// ============================================================================
// Network Configuration (received from Controller)
// ============================================================================
struct NetworkConfig {
    uint32_t network_id = 0;
    std::string network_name;
    std::string cidr;                     // e.g., "10.100.0.0/16"
    uint16_t mtu = NetworkConstants::DEFAULT_TUN_MTU;
};

// ============================================================================
// Peer Information (received from Controller)
// ============================================================================
struct PeerInfo {
    uint32_t node_id = 0;
    std::string hostname;
    std::string virtual_ip;
    std::array<uint8_t, 32> node_key_pub;  // X25519 public key
    bool online = false;
    std::vector<std::string> endpoints;    // Known endpoints
    std::vector<std::string> allowed_subnets;  // Subnets this peer can route
    std::chrono::system_clock::time_point last_seen;
};

// ============================================================================
// Relay Server Info (received from Controller)
// ============================================================================
struct RelayServerInfo {
    uint32_t id = 0;          // Server ID
    std::string name;
    std::string region;
    std::string url;          // WSS URL: wss://host:port/relay
    uint8_t capabilities = 0;
    bool available = true;
};

// ============================================================================
// STUN Server Info
// ============================================================================
struct STUNServerInfo {
    uint32_t id = 0;
    std::string name;
    std::string ip;
    uint16_t port = 3478;
    std::string secondary_ip;  // For full NAT detection
};

// ============================================================================
// Subnet Route (advertised by gateway nodes)
// ============================================================================
struct SubnetRouteInfo {
    std::string cidr;                  // e.g., "192.168.1.0/24"
    uint32_t via_node_id = 0;          // Gateway node ID
    std::string gateway_ip;            // Gateway's virtual IP
    uint16_t priority = 100;           // Lower = more preferred
    uint16_t weight = 100;             // For load balancing
    uint32_t metric = 0;
    uint8_t flags = 0;
    bool gateway_online = false;       // Is gateway currently online?
};

// ============================================================================
// Full Configuration Update
// ============================================================================
struct ConfigUpdate {
    uint64_t version = 0;
    NetworkConfig network;
    std::vector<PeerInfo> peers;
    std::vector<RelayServerInfo> relays;
    std::vector<STUNServerInfo> stun_servers;
    std::vector<SubnetRouteInfo> subnet_routes;
    std::string auth_token;
    std::string relay_token;
    int64_t relay_token_expires_at = 0;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Control Channel Callbacks
// ============================================================================
struct ControlCallbacks {
    std::function<void(const ConfigUpdate&)> on_config_update;
    std::function<void()> on_connected;
    std::function<void(ErrorCode)> on_disconnected;
    std::function<void(uint32_t node_id, const PeerInfo&)> on_peer_online;
    std::function<void(uint32_t node_id)> on_peer_offline;
    std::function<void(const std::string& new_auth_token,
                       const std::string& new_relay_token)> on_token_refresh;
    std::function<void(uint32_t node_id,
                       const std::array<uint8_t, 32>& new_pubkey)> on_peer_key_update;
    std::function<void(uint32_t peer_id,
                       const std::vector<std::string>& endpoints,
                       wire::NATType nat_type)> on_p2p_endpoints;
    std::function<void(uint32_t peer_id,
                       const std::vector<std::string>& endpoints,
                       wire::NATType nat_type)> on_p2p_init;
    std::function<void(const std::string& old_ip,
                       const std::string& new_ip,
                       const std::string& reason)> on_ip_change;
    std::function<void(const wire::RouteUpdatePayload&)> on_route_update;
};

// ============================================================================
// Control Channel State (alias to WsClientState)
// ============================================================================
using ControlChannelState = WsClientState;

constexpr std::string_view control_state_to_string(ControlChannelState state) {
    return ws_client_state_to_string(state);
}

// ============================================================================
// Control Channel - WebSocket connection to Controller
// Uses WsClient base class for common WebSocket functionality
// ============================================================================
class ControlChannel : public WsClient {
public:
    using State = ControlChannelState;

    ControlChannel(
        net::io_context& ioc,
        const std::string& controller_url,
        const std::array<uint8_t, 32>& machine_key_pub,
        const std::array<uint8_t, 64>& machine_key_priv,
        const std::array<uint8_t, 32>& node_key_pub,
        const std::array<uint8_t, 32>& node_key_priv,
        const std::string& auth_key = ""
    );

    ~ControlChannel() override;

    // Non-copyable
    ControlChannel(const ControlChannel&) = delete;
    ControlChannel& operator=(const ControlChannel&) = delete;

    // Set callbacks
    void set_control_callbacks(ControlCallbacks callbacks);

    // ========================================================================
    // Control Messages
    // ========================================================================

    // Report latency measurements to controller
    void report_latency(uint32_t peer_node_id, uint32_t relay_id, uint32_t latency_ms);

    // Batch report multiple latency measurements
    struct LatencyMeasurement {
        std::string dst_type;  // "relay" or "node"
        uint32_t dst_id = 0;
        uint32_t rtt_ms = 0;
    };
    void report_latency_batch(const std::vector<LatencyMeasurement>& measurements);

    // Report endpoints discovered via STUN/local
    void report_endpoints(const std::vector<wire::Endpoint>& endpoints);

    // Request peer endpoints for P2P connection
    void request_peer_endpoints(uint32_t peer_node_id);

    // Report P2P connection status
    void report_p2p_status(uint32_t peer_node_id, bool connected,
                           const std::string& endpoint_ip, uint16_t endpoint_port,
                           uint32_t rtt_ms);

    // Report our new node_key_pub after rotation
    void report_key_rotation(const std::array<uint8_t, 32>& new_pubkey,
                             const std::array<uint8_t, 64>& signature);

    // Announce subnet route
    void announce_route(const std::string& prefix, uint8_t prefix_len,
                        uint16_t priority, uint16_t weight, uint8_t flags);

    // Withdraw subnet route
    void withdraw_route(const std::string& prefix, uint8_t prefix_len);

    // Send config acknowledgment
    void send_config_ack(uint64_t version);

    // ========================================================================
    // Getters
    // ========================================================================

    uint32_t node_id() const { return node_id_; }
    const std::string& virtual_ip() const { return virtual_ip_; }
    const std::string& auth_token() const { return auth_token_; }
    const std::string& relay_token() const { return relay_token_; }
    const NetworkConfig& network_config() const { return network_config_; }

protected:
    // Override WsClient methods
    void do_authenticate() override;
    void process_frame(const wire::Frame& frame) override;

private:
    // Message handling
    void handle_auth_response(const wire::Frame& frame);
    void handle_config(const wire::Frame& frame);
    void handle_config_update(const wire::Frame& frame);
    void handle_p2p_endpoint(const wire::Frame& frame);
    void handle_p2p_init(const wire::Frame& frame);
    void handle_route_update(const wire::Frame& frame);
    void handle_error(const wire::Frame& frame);

    // Authentication
    std::array<uint8_t, 32> machine_key_pub_;
    std::array<uint8_t, 64> machine_key_priv_;
    std::array<uint8_t, 32> node_key_pub_;
    std::array<uint8_t, 32> node_key_priv_;
    wire::AuthType auth_type_ = wire::AuthType::MACHINE;
    std::string auth_key_;

    // Node info (set after auth)
    uint32_t node_id_ = 0;
    uint32_t network_id_ = 0;
    std::string virtual_ip_;
    std::string auth_token_;
    std::string relay_token_;

    // Network configuration
    NetworkConfig network_config_;

    // Callbacks
    ControlCallbacks control_callbacks_;

    // Config version tracking
    uint64_t config_version_ = 0;
};

} // namespace edgelink::client

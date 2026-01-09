#pragma once

#include <string>
#include <memory>
#include <functional>
#include <expected>
#include <optional>
#include <vector>
#include <atomic>
#include <mutex>
#include <chrono>
#include <array>

#include <boost/asio.hpp>

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/ws_client_coro.hpp"

namespace edgelink::client {

namespace net = boost::asio;

// Import wire protocol error codes
using ErrorCode = wire::ErrorCode;

// Network constants
namespace NetworkConstants {
    constexpr uint16_t DEFAULT_TUN_MTU = 1400;
    constexpr uint32_t DEFAULT_HEARTBEAT_INTERVAL = 30;
    constexpr uint32_t DEFAULT_RECONNECT_INTERVAL = 5;
    constexpr uint32_t MAX_RECONNECT_INTERVAL = 300;
}

// ============================================================================
// Network Configuration (received from Controller)
// ============================================================================
struct NetworkConfig {
    uint32_t network_id = 0;
    std::string network_name;
    std::string cidr;
    uint16_t mtu = NetworkConstants::DEFAULT_TUN_MTU;
};

// ============================================================================
// Peer Information (received from Controller)
// ============================================================================
struct PeerInfo {
    uint32_t node_id = 0;
    std::string hostname;
    std::string virtual_ip;
    std::array<uint8_t, 32> node_key_pub;
    bool online = false;
    std::vector<std::string> endpoints;
    std::vector<std::string> allowed_subnets;
    std::chrono::system_clock::time_point last_seen;
};

// ============================================================================
// Relay Server Info (received from Controller)
// ============================================================================
struct RelayServerInfo {
    uint32_t id = 0;
    std::string name;
    std::string region;
    std::string url;
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
    std::string secondary_ip;
};

// ============================================================================
// Subnet Route (advertised by gateway nodes)
// ============================================================================
struct SubnetRouteInfo {
    std::string cidr;
    uint32_t via_node_id = 0;
    std::string gateway_ip;
    uint16_t priority = 100;
    uint16_t weight = 100;
    uint32_t metric = 0;
    uint8_t flags = 0;
    bool gateway_online = false;
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
// Control Channel State
// ============================================================================
using ControlChannelState = WsClientCoro::State;

// ============================================================================
// Control Channel - Coroutine-based WebSocket connection to Controller
// ============================================================================
class ControlChannelCoro : public WsClientCoro {
public:
    using State = ControlChannelState;

    ControlChannelCoro(
        net::io_context& ioc,
        const std::string& controller_url,
        const std::array<uint8_t, 32>& machine_key_pub,
        const std::array<uint8_t, 64>& machine_key_priv,
        const std::array<uint8_t, 32>& node_key_pub,
        const std::array<uint8_t, 32>& node_key_priv,
        const std::string& auth_key = ""
    );

    ~ControlChannelCoro() override;

    // Non-copyable
    ControlChannelCoro(const ControlChannelCoro&) = delete;
    ControlChannelCoro& operator=(const ControlChannelCoro&) = delete;

    // Set callbacks
    void set_control_callbacks(ControlCallbacks callbacks);

    // ========================================================================
    // Control Messages
    // ========================================================================

    // Report latency measurements
    void report_latency(uint32_t peer_node_id, uint32_t relay_id, uint32_t latency_ms);

    struct LatencyMeasurement {
        std::string dst_type;
        uint32_t dst_id = 0;
        uint32_t rtt_ms = 0;
    };
    void report_latency_batch(const std::vector<LatencyMeasurement>& measurements);

    void report_endpoints(const std::vector<wire::Endpoint>& endpoints);
    void request_peer_endpoints(uint32_t peer_node_id);
    void report_p2p_status(uint32_t peer_node_id, bool connected,
                           const std::string& endpoint_ip, uint16_t endpoint_port,
                           uint32_t rtt_ms);
    void report_key_rotation(const std::array<uint8_t, 32>& new_pubkey,
                             const std::array<uint8_t, 64>& signature);
    void announce_route(const std::string& prefix, uint8_t prefix_len,
                        uint16_t priority, uint16_t weight, uint8_t flags);
    void withdraw_route(const std::string& prefix, uint8_t prefix_len);
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
    // WsClientCoro interface
    net::awaitable<void> on_connected() override;
    net::awaitable<std::optional<wire::Frame>> create_auth_frame() override;
    net::awaitable<bool> handle_auth_response(const wire::Frame& frame) override;
    net::awaitable<void> process_frame(const wire::Frame& frame) override;
    net::awaitable<void> on_disconnected(const std::string& reason) override;

private:
    // Message handling
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

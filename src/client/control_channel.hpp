#pragma once

#include <boost/asio.hpp>

#include "client/control_channel_types.hpp"
#include "common/ws_client.hpp"

namespace edgelink::client {

namespace net = boost::asio;

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

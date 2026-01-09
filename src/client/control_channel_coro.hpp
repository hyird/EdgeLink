#pragma once

#include <optional>

#include <boost/asio.hpp>

#include "client/control_channel_types.hpp"
#include "common/ws_client_coro.hpp"

namespace edgelink::client {

namespace net = boost::asio;

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

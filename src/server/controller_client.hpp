#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/ws_client.hpp"
#include "common/config.hpp"

#include <boost/asio.hpp>

#include <memory>
#include <functional>
#include <atomic>
#include <string>
#include <vector>

namespace edgelink {

namespace net = boost::asio;

// Forward declarations
class WsRelayServerCoro;

// ============================================================================
// ControllerClient - WebSocket client to connect relay to controller
// Inherits from WsClient for common WebSocket functionality
// ============================================================================
class ControllerClient : public WsClient {
public:
    using ConnectCallback = std::function<void(bool success, const std::string& error)>;
    using DisconnectCallback = std::function<void(const std::string& reason)>;

    // Callback for node location updates
    using NodeLocCallback = std::function<void(const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>&)>;

    // Callback for relay list updates
    using RelayListCallback = std::function<void(const std::vector<wire::RelayInfo>&)>;

    // Callback for token blacklist updates
    using BlacklistCallback = std::function<void(bool full_sync, const std::vector<std::pair<std::string, int64_t>>&)>;

    ControllerClient(net::io_context& ioc, WsRelayServerCoro& server, const ServerConfig& config);
    ~ControllerClient() override = default;

    // Non-copyable
    ControllerClient(const ControllerClient&) = delete;
    ControllerClient& operator=(const ControllerClient&) = delete;

    // Set callbacks
    void set_connect_callback(ConnectCallback cb) { connect_callback_ = std::move(cb); }
    void set_disconnect_callback(DisconnectCallback cb) { disconnect_callback_ = std::move(cb); }
    void set_node_loc_callback(NodeLocCallback cb) { node_loc_callback_ = std::move(cb); }
    void set_relay_list_callback(RelayListCallback cb) { relay_list_callback_ = std::move(cb); }
    void set_blacklist_callback(BlacklistCallback cb) { blacklist_callback_ = std::move(cb); }

    // Send latency report to controller
    void send_latency_report(const std::vector<std::tuple<std::string, uint32_t, uint32_t>>& entries);

    // Send heartbeat with stats
    void send_heartbeat();

    // Get server ID (assigned by controller)
    uint32_t server_id() const { return server_id_; }
    bool is_registered() const { return registered_.load(); }

protected:
    // Override WsClient methods
    void do_authenticate() override;
    void process_frame(const wire::Frame& frame) override;

private:
    // Message handlers
    void handle_register_response(const wire::Frame& frame);
    void handle_node_loc(const wire::Frame& frame);
    void handle_relay_list(const wire::Frame& frame);
    void handle_blacklist(const wire::Frame& frame);
    void handle_error(const wire::Frame& frame);

    // References
    WsRelayServerCoro& server_;
    const ServerConfig& config_;

    // Server info
    uint32_t server_id_{0};
    std::atomic<bool> registered_{false};

    // Callbacks
    ConnectCallback connect_callback_;
    DisconnectCallback disconnect_callback_;
    NodeLocCallback node_loc_callback_;
    RelayListCallback relay_list_callback_;
    BlacklistCallback blacklist_callback_;
};

} // namespace edgelink

#pragma once

#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/url.hpp>

#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <variant>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;

using tcp = asio::ip::tcp;

namespace edgelink::client {

// ============================================================================
// Channel 类型定义（替代回调）
// ============================================================================
namespace channels {

// Control Channel 事件通道
using AuthResponseChannel = asio::experimental::channel<
    void(boost::system::error_code, AuthResponse)>;
using ConfigChannel = asio::experimental::channel<
    void(boost::system::error_code, Config)>;
using ConfigUpdateChannel = asio::experimental::channel<
    void(boost::system::error_code, ConfigUpdate)>;
using RouteUpdateChannel = asio::experimental::channel<
    void(boost::system::error_code, RouteUpdate)>;
using PeerRoutingUpdateChannel = asio::experimental::channel<
    void(boost::system::error_code, PeerRoutingUpdate)>;
using P2PEndpointMsgChannel = asio::experimental::channel<
    void(boost::system::error_code, P2PEndpointMsg)>;
using ControlErrorChannel = asio::experimental::channel<
    void(boost::system::error_code, uint16_t, std::string)>;
using ControlConnectedChannel = asio::experimental::channel<
    void(boost::system::error_code)>;
using ControlDisconnectedChannel = asio::experimental::channel<
    void(boost::system::error_code)>;

// Relay Channel 事件通道
using RelayDataChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, std::vector<uint8_t>)>;
using RelayConnectedChannel = asio::experimental::channel<
    void(boost::system::error_code)>;
using RelayDisconnectedChannel = asio::experimental::channel<
    void(boost::system::error_code)>;

}  // namespace channels

// Control Channel 事件结构体（替代 ControlChannelCallbacks）
struct ControlChannelEvents {
    channels::AuthResponseChannel* auth_response = nullptr;
    channels::ConfigChannel* config = nullptr;
    channels::ConfigUpdateChannel* config_update = nullptr;
    channels::RouteUpdateChannel* route_update = nullptr;
    channels::PeerRoutingUpdateChannel* peer_routing_update = nullptr;
    channels::P2PEndpointMsgChannel* p2p_endpoint = nullptr;
    channels::ControlErrorChannel* error = nullptr;
    channels::ControlConnectedChannel* connected = nullptr;
    channels::ControlDisconnectedChannel* disconnected = nullptr;
};

// Relay Channel 事件结构体（替代 RelayChannelCallbacks）
struct RelayChannelEvents {
    channels::RelayDataChannel* data = nullptr;
    channels::RelayConnectedChannel* connected = nullptr;
    channels::RelayDisconnectedChannel* disconnected = nullptr;
    std::function<void(uint16_t rtt_ms)> on_pong = nullptr;
};

// Client 对外事件通道（替代 ClientCallbacks）
namespace channels {
using ClientConnectedChannel = asio::experimental::channel<void(boost::system::error_code)>;
using ClientDisconnectedChannel = asio::experimental::channel<void(boost::system::error_code)>;
using ClientDataChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, std::vector<uint8_t>)>;
using ClientErrorChannel = asio::experimental::channel<
    void(boost::system::error_code, uint16_t, std::string)>;
using ShutdownRequestChannel = asio::experimental::channel<void(boost::system::error_code)>;
}  // namespace channels

// Client 事件结构体（替代 ClientCallbacks）
struct ClientEvents {
    channels::ClientConnectedChannel* connected = nullptr;
    channels::ClientDisconnectedChannel* disconnected = nullptr;
    channels::ClientDataChannel* data_received = nullptr;
    channels::ClientErrorChannel* error = nullptr;
    channels::ShutdownRequestChannel* shutdown_requested = nullptr;
};

// Channel state
enum class ChannelState {
    DISCONNECTED,
    CONNECTING,
    AUTHENTICATING,
    CONNECTED,
    RECONNECTING,
};

const char* channel_state_name(ChannelState state);

// WebSocket stream types
using TlsWsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
using PlainWsStream = websocket::stream<beast::tcp_stream>;

// Legacy alias
using WsStream = TlsWsStream;

// Forward declaration
class Client;

// ============================================================================
// ControlChannel - Connection to Controller's /api/v1/control
// ============================================================================

class ControlChannel : public std::enable_shared_from_this<ControlChannel> {
public:
    ControlChannel(asio::io_context& ioc, ssl::context& ssl_ctx,
                   CryptoEngine& crypto, const std::string& url, bool use_tls);

    // Connect and authenticate
    asio::awaitable<bool> connect(const std::string& authkey);

    // Reconnect with existing credentials
    asio::awaitable<bool> reconnect();

    // Disconnect
    asio::awaitable<void> close();

    // Send CONFIG_ACK
    asio::awaitable<void> send_config_ack(uint64_t version, ConfigAckStatus status);

    // Send PING
    asio::awaitable<void> send_ping();

    // Send LATENCY_REPORT
    asio::awaitable<void> send_latency_report(const LatencyReport& report);

    // Send ROUTE_ANNOUNCE (announce subnets this node can route)
    asio::awaitable<void> send_route_announce(const std::vector<RouteInfo>& routes);

    // Send ROUTE_WITHDRAW (withdraw previously announced routes)
    asio::awaitable<void> send_route_withdraw(const std::vector<RouteInfo>& routes);

    // Send P2P_INIT (request peer endpoints from Controller)
    asio::awaitable<void> send_p2p_init(const P2PInit& init);

    // Send ENDPOINT_UPDATE (report our endpoints to Controller)
    // Returns request_id for tracking acknowledgement
    asio::awaitable<uint32_t> send_endpoint_update(const std::vector<Endpoint>& endpoints);

    // Send ENDPOINT_UPDATE and wait for ACK (with timeout)
    // Returns true if ACK received, false on timeout
    asio::awaitable<bool> send_endpoint_update_and_wait_ack(
        const std::vector<Endpoint>& endpoints,
        uint32_t timeout_ms = 5000);

    // Check if last endpoint update was acknowledged
    bool is_endpoint_ack_pending() const { return endpoint_ack_pending_; }

    // Get last reported endpoints (for resend on reconnect)
    const std::vector<Endpoint>& pending_endpoints() const { return pending_endpoints_; }

    // Resend pending endpoints (called after reconnect)
    asio::awaitable<void> resend_pending_endpoints();

    // Set event channels
    void set_channels(ControlChannelEvents channels);

    // State
    ChannelState state() const { return state_; }
    bool is_connected() const { return state_ == ChannelState::CONNECTED; }
    const std::string& url() const { return url_; }

    // Auth info (after successful authentication)
    NodeId node_id() const { return node_id_; }
    NetworkId network_id() const { return network_id_; }
    IPv4Address virtual_ip() const { return virtual_ip_; }
    uint8_t subnet_mask() const { return subnet_mask_; }
    const std::vector<uint8_t>& relay_token() const { return relay_token_; }

private:
    asio::awaitable<void> read_loop();
    asio::awaitable<void> write_loop();
    asio::awaitable<void> handle_frame(const Frame& frame);
    asio::awaitable<void> handle_auth_response(const Frame& frame);
    asio::awaitable<void> handle_config(const Frame& frame);
    asio::awaitable<void> handle_config_update(const Frame& frame);
    asio::awaitable<void> handle_route_update(const Frame& frame);
    asio::awaitable<void> handle_route_ack(const Frame& frame);
    asio::awaitable<void> handle_peer_routing_update(const Frame& frame);
    asio::awaitable<void> handle_p2p_endpoint(const Frame& frame);
    asio::awaitable<void> handle_endpoint_ack(const Frame& frame);
    asio::awaitable<void> handle_pong(const Frame& frame);
    asio::awaitable<void> handle_error(const Frame& frame);

    asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload);
    asio::awaitable<void> send_raw(std::span<const uint8_t> data);

    // Helper to check if stream is open
    bool is_ws_open() const;

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    std::string url_;
    std::string authkey_;
    bool use_tls_;

    // WebSocket stream (either TLS or plain)
    std::unique_ptr<TlsWsStream> tls_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;
    ChannelState state_ = ChannelState::DISCONNECTED;

    // Write queue
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // Auth state
    NodeId node_id_ = 0;
    NetworkId network_id_ = 0;
    IPv4Address virtual_ip_{};
    uint8_t subnet_mask_ = 16;  // Default /16
    std::vector<uint8_t> auth_token_;
    std::vector<uint8_t> relay_token_;

    // Ping tracking
    uint32_t ping_seq_ = 0;
    uint64_t last_ping_time_ = 0;

    // Route request tracking
    uint32_t route_request_id_ = 0;

    // Endpoint update tracking
    std::atomic<uint32_t> endpoint_request_id_{0};  // 下一个请求 ID
    uint32_t pending_endpoint_request_id_ = 0;       // 待确认的请求 ID
    std::atomic<bool> endpoint_ack_pending_{false};  // 是否有待确认的请求
    std::vector<Endpoint> pending_endpoints_;        // 最后上报的端点（用于重发）
    std::unique_ptr<asio::steady_timer> endpoint_ack_timer_;  // ACK 等待通知定时器

    ControlChannelEvents channels_;
};

// ============================================================================
// RelayChannel - Connection to Controller's /api/v1/relay (built-in relay)
// ============================================================================

class RelayChannel : public std::enable_shared_from_this<RelayChannel> {
public:
    RelayChannel(asio::io_context& ioc, ssl::context& ssl_ctx,
                 CryptoEngine& crypto, PeerManager& peers, const std::string& url, bool use_tls);

    // Connect and authenticate with relay token
    asio::awaitable<bool> connect(const std::vector<uint8_t>& relay_token);

    // Disconnect
    asio::awaitable<void> close();

    // Send encrypted DATA to peer
    asio::awaitable<bool> send_data(NodeId peer_id, std::span<const uint8_t> plaintext);

    // Send PING to measure RTT
    asio::awaitable<void> send_ping();

    // Set event channels
    void set_channels(RelayChannelEvents channels);

    // State
    ChannelState state() const { return state_; }
    bool is_connected() const { return state_ == ChannelState::CONNECTED; }
    const std::string& url() const { return url_; }

private:
    asio::awaitable<void> read_loop();
    asio::awaitable<void> write_loop();
    asio::awaitable<void> handle_frame(const Frame& frame);
    asio::awaitable<void> handle_relay_auth_resp(const Frame& frame);
    asio::awaitable<void> handle_data(const Frame& frame);
    asio::awaitable<void> handle_pong(const Frame& frame);

    asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload);
    asio::awaitable<void> send_raw(std::span<const uint8_t> data);

    // Helper to check if stream is open
    bool is_ws_open() const;

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    std::string url_;
    bool use_tls_;

    // WebSocket stream (either TLS or plain)
    std::unique_ptr<TlsWsStream> tls_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;
    ChannelState state_ = ChannelState::DISCONNECTED;

    // Write queue
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // Ping tracking
    uint32_t ping_seq_ = 0;
    uint64_t last_ping_time_ = 0;

    RelayChannelEvents channels_;
};

} // namespace edgelink::client

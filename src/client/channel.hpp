#pragma once

#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include "common/events.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"

#include <boost/asio.hpp>
#include <boost/cobalt.hpp>
#include <boost/cobalt/channel.hpp>
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
namespace cobalt = boost::cobalt;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;

using tcp = asio::ip::tcp;

namespace edgelink::client {

// ============================================================================
// Channel 类型定义
// ============================================================================

// 多参数 channel 包装结构体
struct ClientDataEvent {
    NodeId src_node;
    std::vector<uint8_t> data;
};

struct ClientErrorEvent {
    uint16_t code;
    std::string message;
};

// Client 对外事件通道（替代 ClientCallbacks）
namespace channels {
using ClientConnectedChannel = cobalt::channel<void>;
using ClientDisconnectedChannel = cobalt::channel<void>;
using ClientDataChannel = cobalt::channel<ClientDataEvent>;
using ClientErrorChannel = cobalt::channel<ClientErrorEvent>;
using ShutdownRequestChannel = cobalt::channel<void>;
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
    cobalt::task<bool> connect(const std::string& authkey);

    // Reconnect with existing credentials
    cobalt::task<bool> reconnect();

    // Disconnect
    cobalt::task<void> close();

    // Send CONFIG_ACK
    cobalt::task<void> send_config_ack(uint64_t version, ConfigAckStatus status);

    // Send PING
    cobalt::task<void> send_ping();

    // Send LATENCY_REPORT
    cobalt::task<void> send_latency_report(const LatencyReport& report);

    // Send RELAY_LATENCY_REPORT (report latency to each relay)
    cobalt::task<void> send_relay_latency_report(const RelayLatencyReport& report);

    // Send ROUTE_ANNOUNCE (announce subnets this node can route)
    cobalt::task<void> send_route_announce(const std::vector<RouteInfo>& routes);

    // Send ROUTE_WITHDRAW (withdraw previously announced routes)
    cobalt::task<void> send_route_withdraw(const std::vector<RouteInfo>& routes);

    // Send P2P_INIT (request peer endpoints from Controller)
    cobalt::task<void> send_p2p_init(const P2PInit& init);

    // Send P2P_STATUS (report P2P connection status to Controller)
    cobalt::task<void> send_p2p_status(const P2PStatusMsg& status);

    // Send ENDPOINT_UPDATE (report our endpoints to Controller)
    // Returns request_id for tracking acknowledgement
    cobalt::task<uint32_t> send_endpoint_update(const std::vector<Endpoint>& endpoints);

    // Send ENDPOINT_UPDATE and wait for ACK (with timeout)
    // Returns true if ACK received, false on timeout
    cobalt::task<bool> send_endpoint_update_and_wait_ack(
        const std::vector<Endpoint>& endpoints,
        uint32_t timeout_ms = 5000);

    // Check if last endpoint update was acknowledged
    bool is_endpoint_ack_pending() const { return endpoint_ack_pending_; }

    // Get last reported endpoints (for resend on reconnect)
    const std::vector<Endpoint>& pending_endpoints() const { return pending_endpoints_; }

    // Resend pending endpoints (called after reconnect)
    cobalt::task<void> resend_pending_endpoints();

    // Set event channel (unified variant channel)
    void set_event_channel(events::CtrlEventChannel* ch);

    // State
    ChannelState state() const { return state_; }
    bool is_connected() const { return state_ == ChannelState::CONNECTED; }
    const std::string& url() const { return url_; }

    // Set exit node capability (before connect)
    void set_exit_node(bool value) { exit_node_ = value; }

    // Auth info (after successful authentication)
    NodeId node_id() const { return node_id_; }
    NetworkId network_id() const { return network_id_; }
    IPv4Address virtual_ip() const { return virtual_ip_; }
    uint8_t subnet_mask() const { return subnet_mask_; }
    const std::vector<uint8_t>& relay_token() const { return relay_token_; }

private:
    cobalt::task<void> read_loop();
    cobalt::task<void> write_loop();
    cobalt::task<void> handle_frame(const Frame& frame);
    cobalt::task<void> handle_auth_response(const Frame& frame);
    cobalt::task<void> handle_config(const Frame& frame);
    cobalt::task<void> handle_config_update(const Frame& frame);
    cobalt::task<void> handle_route_update(const Frame& frame);
    cobalt::task<void> handle_route_ack(const Frame& frame);
    cobalt::task<void> handle_peer_routing_update(const Frame& frame);
    cobalt::task<void> handle_p2p_endpoint(const Frame& frame);
    cobalt::task<void> handle_endpoint_ack(const Frame& frame);
    cobalt::task<void> handle_pong(const Frame& frame);
    cobalt::task<void> handle_error(const Frame& frame);

    void send_frame(FrameType type, std::span<const uint8_t> payload);
    void send_raw(std::span<const uint8_t> data);

    // Helper to check if stream is open
    bool is_ws_open() const;

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    std::string url_;
    std::string authkey_;
    bool use_tls_;
    bool exit_node_ = false;  // 声明自己可作为出口节点

    // WebSocket stream (either TLS or plain)
    std::unique_ptr<TlsWsStream> tls_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;
    ChannelState state_ = ChannelState::DISCONNECTED;

    // Write queue (仅在 io_context 线程内访问 —— send_raw 和 write_loop 均在同一线程，无需 mutex)
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
    uint64_t last_ping_time_ = 0;  // system_clock ms (发送给对端的时间戳)
    std::chrono::steady_clock::time_point last_ping_steady_;  // 本地 RTT 计算用

    // Route request tracking
    uint32_t route_request_id_ = 0;

    // Endpoint update tracking
    std::atomic<uint32_t> endpoint_request_id_{0};  // 下一个请求 ID
    uint32_t pending_endpoint_request_id_ = 0;       // 待确认的请求 ID
    std::atomic<bool> endpoint_ack_pending_{false};  // 是否有待确认的请求
    std::vector<Endpoint> pending_endpoints_;        // 最后上报的端点（用于重发）
    std::unique_ptr<asio::steady_timer> endpoint_ack_timer_;  // ACK 等待通知定时器

    events::CtrlEventChannel* event_ch_ = nullptr;
};

// ============================================================================
// RelayChannel - Connection to Controller's /api/v1/relay (built-in relay)
// ============================================================================

class RelayChannel : public std::enable_shared_from_this<RelayChannel> {
public:
    // host_override: 用于 CDN 场景，URL 中是 IP 地址但需要正确的 Host 头
    RelayChannel(asio::io_context& ioc, ssl::context& ssl_ctx,
                 CryptoEngine& crypto, PeerManager& peers, const std::string& url, bool use_tls,
                 const std::string& host_override = "");

    // Connect and authenticate with relay token
    cobalt::task<bool> connect(const std::vector<uint8_t>& relay_token);

    // Disconnect
    cobalt::task<void> close();

    // Send encrypted DATA to peer
    cobalt::task<bool> send_data(NodeId peer_id, std::span<const uint8_t> plaintext);

    // Send PING to measure RTT
    cobalt::task<void> send_ping();

    // Set event channel (unified variant channel)
    void set_event_channel(events::RelayEventChannel* ch);

    // Set optional per-connection RTT callback (for relay pool RTT tracking)
    void set_pong_callback(std::function<void(uint16_t rtt_ms)> cb) { on_pong_ = std::move(cb); }

    // State
    ChannelState state() const { return state_; }
    bool is_connected() const { return state_ == ChannelState::CONNECTED; }
    const std::string& url() const { return url_; }

private:
    cobalt::task<void> read_loop();
    cobalt::task<void> write_loop();
    cobalt::task<void> handle_frame(const Frame& frame);
    cobalt::task<void> handle_relay_auth_resp(const Frame& frame);
    cobalt::task<void> handle_data(const Frame& frame);
    cobalt::task<void> handle_pong(const Frame& frame);

    void send_frame(FrameType type, std::span<const uint8_t> payload);
    void send_raw(std::span<const uint8_t> data);

    // Helper to check if stream is open
    bool is_ws_open() const;

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    std::string url_;
    bool use_tls_;
    std::string host_override_;  // CDN 场景下的 Host 头覆盖

    // WebSocket stream (either TLS or plain)
    std::unique_ptr<TlsWsStream> tls_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;
    ChannelState state_ = ChannelState::DISCONNECTED;

    // Write queue (仅在 io_context 线程内访问 —— send_raw 和 write_loop 均在同一线程，无需 mutex)
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // Ping tracking
    uint32_t ping_seq_ = 0;
    uint64_t last_ping_time_ = 0;  // system_clock ms (发送给对端的时间戳)
    std::chrono::steady_clock::time_point last_ping_steady_;  // 本地 RTT 计算用

    events::RelayEventChannel* event_ch_ = nullptr;
    std::function<void(uint16_t rtt_ms)> on_pong_;
};

} // namespace edgelink::client

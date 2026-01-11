#pragma once

#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"

#include <boost/asio.hpp>
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

// Callbacks for control channel events
struct ControlChannelCallbacks {
    std::function<void(const AuthResponse&)> on_auth_response;
    std::function<void(const Config&)> on_config;
    std::function<void(const ConfigUpdate&)> on_config_update;
    std::function<void(const RouteUpdate&)> on_route_update;
    std::function<void(uint16_t code, const std::string& msg)> on_error;
    std::function<void()> on_connected;
    std::function<void()> on_disconnected;
};

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

    // Set callbacks
    void set_callbacks(ControlChannelCallbacks callbacks);

    // State
    ChannelState state() const { return state_; }
    bool is_connected() const { return state_ == ChannelState::CONNECTED; }

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

    ControlChannelCallbacks callbacks_;
};

// ============================================================================
// RelayChannel - Connection to Controller's /api/v1/relay (built-in relay)
// ============================================================================

// Callbacks for relay channel events
struct RelayChannelCallbacks {
    std::function<void(NodeId src, std::span<const uint8_t> plaintext)> on_data;
    std::function<void()> on_connected;
    std::function<void()> on_disconnected;
};

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

    // Set callbacks
    void set_callbacks(RelayChannelCallbacks callbacks);

    // State
    ChannelState state() const { return state_; }
    bool is_connected() const { return state_ == ChannelState::CONNECTED; }

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

    RelayChannelCallbacks callbacks_;
};

} // namespace edgelink::client

#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/url.hpp>

#include <memory>
#include <functional>
#include <atomic>
#include <queue>
#include <mutex>
#include <chrono>
#include <optional>

namespace edgelink {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// ============================================================================
// WebSocket Client State
// ============================================================================
enum class WsClientState : uint8_t {
    INIT = 0,
    CONNECTING,
    AUTHENTICATING,
    CONNECTED,
    RECONNECTING,
    DISABLED
};

constexpr std::string_view ws_client_state_to_string(WsClientState state) {
    switch (state) {
        case WsClientState::INIT:           return "INIT";
        case WsClientState::CONNECTING:     return "CONNECTING";
        case WsClientState::AUTHENTICATING: return "AUTHENTICATING";
        case WsClientState::CONNECTED:      return "CONNECTED";
        case WsClientState::RECONNECTING:   return "RECONNECTING";
        case WsClientState::DISABLED:       return "DISABLED";
        default:                            return "UNKNOWN";
    }
}

// ============================================================================
// URL Components
// ============================================================================
struct WsUrlComponents {
    std::string host;
    std::string port;
    std::string path;
    bool use_ssl = false;

    static std::optional<WsUrlComponents> parse(const std::string& url) {
        try {
            boost::urls::url_view parsed(url);
            WsUrlComponents result;
            result.host = parsed.host();
            result.use_ssl = (parsed.scheme() == "wss" || parsed.scheme() == "https");
            result.port = parsed.has_port() ? std::string(parsed.port()) : (result.use_ssl ? "443" : "80");
            result.path = parsed.path().empty() ? "/" : std::string(parsed.path());
            return result;
        } catch (...) {
            return std::nullopt;
        }
    }
};

// ============================================================================
// WebSocket Client Callbacks
// ============================================================================
struct WsClientCallbacks {
    std::function<void()> on_connected;
    std::function<void(const std::string& reason)> on_disconnected;
    std::function<void(WsClientState)> on_state_changed;
    std::function<void(const wire::Frame&)> on_frame_received;
    std::function<wire::Frame()> create_auth_frame;  // Creates auth frame to send
};

// ============================================================================
// WebSocket Client Base Class
// ============================================================================
// Provides common WebSocket connection management:
// - DNS resolution, TCP connect, SSL handshake, WS handshake
// - Automatic reconnection with exponential backoff
// - Frame-based read/write with queueing
// - Heartbeat ping/pong
// ============================================================================
class WsClient : public std::enable_shared_from_this<WsClient> {
public:
    using State = WsClientState;

    WsClient(net::io_context& ioc, const std::string& url, const std::string& name = "WsClient");
    virtual ~WsClient();

    // Non-copyable
    WsClient(const WsClient&) = delete;
    WsClient& operator=(const WsClient&) = delete;

    // Connection management
    void connect();
    void disconnect();
    void enable();
    void disable();

    // State
    State state() const { return state_.load(); }
    bool is_connected() const { return state_ == State::CONNECTED; }

    // Callbacks
    void set_callbacks(WsClientCallbacks callbacks);

    // Send a frame
    void send_frame(const wire::Frame& frame);

    // Send ping (for manual heartbeat control)
    void send_ping();

    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint64_t> frames_sent{0};
        std::atomic<uint64_t> frames_received{0};
    };
    const Stats& stats() const { return stats_; }

    // Getters
    const std::string& url() const { return url_; }
    const std::string& name() const { return name_; }

protected:
    // Override for custom auth handling after WS handshake
    virtual void do_authenticate();

    // Override for custom frame processing
    virtual void process_frame(const wire::Frame& frame);

    // Called when auth is complete (sets state to CONNECTED)
    void auth_complete();

    // Called when auth fails
    void auth_failed(const std::string& reason);

    // State transition
    void transition_to(State new_state);

    // Access to stream for derived classes
    websocket::stream<ssl::stream<tcp::socket>>* wss_stream() { return wss_.get(); }
    websocket::stream<tcp::socket>* ws_stream() { return ws_.get(); }
    bool use_ssl() const { return url_parts_.use_ssl; }

    // IO context
    net::io_context& ioc_;

private:
    void do_resolve();
    void do_connect(tcp::resolver::results_type results);
    void do_ssl_handshake();
    void do_ws_handshake();
    void do_read();
    void do_write();
    void queue_write(std::vector<uint8_t> data);

    void start_heartbeat();
    void schedule_reconnect();
    void close_streams();

    // Connection info
    std::string url_;
    std::string name_;
    WsUrlComponents url_parts_;

    // SSL context
    ssl::context ssl_ctx_{ssl::context::tlsv12_client};
    tcp::resolver resolver_;

    // WebSocket streams (only one is used based on SSL)
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> wss_;
    std::unique_ptr<websocket::stream<tcp::socket>> ws_;

    // State
    std::atomic<State> state_{State::INIT};
    std::atomic<bool> shutdown_{false};

    // Read buffer
    beast::flat_buffer read_buffer_;

    // Write queue
    std::mutex write_mutex_;
    std::queue<std::vector<uint8_t>> write_queue_;
    std::atomic<bool> writing_{false};

    // Heartbeat
    net::steady_timer heartbeat_timer_;
    std::chrono::steady_clock::time_point last_pong_{std::chrono::steady_clock::now()};
    uint32_t missed_pongs_ = 0;
    static constexpr uint32_t MAX_MISSED_PONGS = 3;
    static constexpr uint32_t HEARTBEAT_INTERVAL_SEC = 30;

    // Reconnection
    net::steady_timer reconnect_timer_;
    uint32_t reconnect_attempts_ = 0;
    static constexpr uint32_t MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr uint32_t BASE_RECONNECT_DELAY_MS = 1000;
    static constexpr uint32_t MAX_RECONNECT_DELAY_MS = 60000;

    // Callbacks
    WsClientCallbacks callbacks_;

    // Stats
    Stats stats_;
};

} // namespace edgelink

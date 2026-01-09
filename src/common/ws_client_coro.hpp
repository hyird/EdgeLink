#pragma once

#include "frame.hpp"
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <memory>
#include <string>
#include <queue>
#include <atomic>
#include <chrono>

namespace edgelink {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

/**
 * WsClientCoro - Coroutine-based WebSocket Client Base Class
 *
 * This is the base class for WebSocket client connections using
 * the coroutine-based concurrency model.
 *
 * Features:
 * - Automatic reconnection with exponential backoff
 * - Heartbeat/keepalive support
 * - SSL/TLS support
 * - Thread-safe send operations
 *
 * Design (per architecture.md Section 8.5):
 * - All IO operations use co_await
 * - No blocking calls allowed
 */
class WsClientCoro : public std::enable_shared_from_this<WsClientCoro> {
public:
    /**
     * Client states.
     */
    enum class State {
        INIT,
        CONNECTING,
        AUTHENTICATING,
        CONNECTED,
        RECONNECTING,
        DISCONNECTED,
        STOPPED
    };

    /**
     * Create a client.
     * @param ioc The io_context to run on
     * @param url WebSocket URL (ws:// or wss://)
     * @param name Client name for logging
     */
    WsClientCoro(net::io_context& ioc, const std::string& url, const std::string& name = "WsClient");

    virtual ~WsClientCoro();

    // Non-copyable
    WsClientCoro(const WsClientCoro&) = delete;
    WsClientCoro& operator=(const WsClientCoro&) = delete;

    /**
     * Start the client and connect.
     */
    void connect();

    /**
     * Disconnect and stop.
     */
    void disconnect();

    /**
     * Send binary data.
     * Thread-safe.
     */
    void send_binary(std::vector<uint8_t> data);

    /**
     * Send a wire frame.
     * Thread-safe.
     */
    void send_frame(const wire::Frame& frame);

    /**
     * Send text data.
     * Thread-safe.
     */
    void send_text(std::string text);

    // State information
    State state() const { return state_.load(std::memory_order_acquire); }
    bool is_connected() const { return state() == State::CONNECTED; }
    const std::string& url() const { return url_; }
    const std::string& name() const { return name_; }

    /**
     * Get connection statistics.
     */
    struct Stats {
        uint64_t bytes_sent{0};
        uint64_t bytes_received{0};
        uint64_t frames_sent{0};
        uint64_t frames_received{0};
        uint32_t reconnect_count{0};
        std::chrono::steady_clock::time_point connected_at;
        std::chrono::milliseconds last_rtt{0};
    };
    Stats stats() const;

protected:
    /**
     * Called after WebSocket handshake and authentication.
     */
    virtual net::awaitable<void> on_connected() = 0;

    /**
     * Called for each received frame.
     */
    virtual net::awaitable<void> process_frame(const wire::Frame& frame) = 0;

    /**
     * Called when disconnected.
     * @param reason Disconnect reason
     */
    virtual net::awaitable<void> on_disconnected(const std::string& reason) = 0;

    /**
     * Create the authentication frame.
     * Called after WebSocket handshake to authenticate.
     * @return Authentication frame to send, or std::nullopt to skip auth
     */
    virtual net::awaitable<std::optional<wire::Frame>> create_auth_frame() = 0;

    /**
     * Handle authentication response.
     * @param frame Response frame from server
     * @return true if authentication succeeded
     */
    virtual net::awaitable<bool> handle_auth_response(const wire::Frame& frame) = 0;

    /**
     * Set the state.
     */
    void set_state(State new_state);

    net::io_context& ioc_;

private:
    // URL components
    struct UrlComponents {
        std::string host;
        std::string port;
        std::string path;
        bool use_ssl{false};
    };
    static std::optional<UrlComponents> parse_url(const std::string& url);

    // Main connection coroutine
    net::awaitable<void> run_connection();

    // Connection phases
    net::awaitable<void> do_connect();
    net::awaitable<void> do_authenticate();

    // Reader and writer coroutines
    net::awaitable<void> reader();
    net::awaitable<void> writer();
    net::awaitable<void> heartbeat();

    // Reconnection logic
    net::awaitable<void> wait_for_reconnect();
    void reset_reconnect_delay();

    // Enqueue data for sending
    void enqueue_send(std::vector<uint8_t> data, bool is_text);

    std::string url_;
    std::string name_;
    UrlComponents url_parts_;

    // SSL context
    ssl::context ssl_ctx_{ssl::context::tlsv12_client};

    // WebSocket streams (one active at a time)
    using WssStream = websocket::stream<ssl::stream<tcp::socket>>;
    using WsStream = websocket::stream<tcp::socket>;
    std::unique_ptr<WssStream> wss_;
    std::unique_ptr<WsStream> ws_;

    // Write queue
    struct WriteItem {
        std::vector<uint8_t> data;
        bool is_text{false};
    };
    std::queue<WriteItem> write_queue_;
    net::steady_timer write_signal_;

    // State
    std::atomic<State> state_{State::INIT};
    std::atomic<bool> shutdown_{false};

    // Reconnection
    std::chrono::milliseconds reconnect_delay_{1000};
    static constexpr std::chrono::milliseconds kMaxReconnectDelay{60000};
    static constexpr std::chrono::milliseconds kBaseReconnectDelay{1000};

    // Heartbeat
    static constexpr std::chrono::seconds kHeartbeatInterval{30};
    static constexpr uint32_t kMaxMissedPongs{3};
    std::atomic<uint32_t> missed_pongs_{0};
    std::chrono::steady_clock::time_point last_ping_sent_;
    std::chrono::steady_clock::time_point last_pong_received_;

    // Statistics
    mutable std::atomic<uint64_t> bytes_sent_{0};
    mutable std::atomic<uint64_t> bytes_received_{0};
    mutable std::atomic<uint64_t> frames_sent_{0};
    mutable std::atomic<uint64_t> frames_received_{0};
    mutable std::atomic<uint32_t> reconnect_count_{0};
    std::chrono::steady_clock::time_point connected_at_;
    std::atomic<int64_t> last_rtt_ms_{0};
};

} // namespace edgelink

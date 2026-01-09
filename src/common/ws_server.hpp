#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>

#include <memory>
#include <functional>
#include <atomic>
#include <queue>
#include <mutex>
#include <unordered_map>
#include <shared_mutex>
#include <string>
#include <chrono>

namespace edgelink {

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Forward declarations
class WsServerSession;
class WsServer;

// ============================================================================
// WebSocket Session State
// ============================================================================
enum class WsSessionState : uint8_t {
    INIT = 0,
    HTTP_READING,
    UPGRADING,
    AUTHENTICATING,
    CONNECTED,
    CLOSING
};

// ============================================================================
// WebSocket Session Callbacks
// ============================================================================
struct WsSessionCallbacks {
    std::function<void(const wire::Frame&)> on_frame_received;
    std::function<void()> on_connected;
    std::function<void(const std::string& reason)> on_disconnected;
    std::function<bool(const http::request<http::string_body>&)> on_http_request;  // Return true to upgrade
};

// ============================================================================
// WebSocket Server Session Base Class
// ============================================================================
class WsServerSession : public std::enable_shared_from_this<WsServerSession> {
public:
    using State = WsSessionState;

    WsServerSession(net::io_context& ioc, tcp::socket socket, bool use_ssl,
                    ssl::context* ssl_ctx, const std::string& name = "WsSession");
    virtual ~WsServerSession();

    // Non-copyable
    WsServerSession(const WsServerSession&) = delete;
    WsServerSession& operator=(const WsServerSession&) = delete;

    // Start the session (call after construction)
    void start();

    // Close the session
    void close(const std::string& reason = "");

    // State
    State state() const { return state_.load(); }
    bool is_connected() const { return state_ == State::CONNECTED; }

    // Send a frame
    void send_frame(const wire::Frame& frame);

    // Set callbacks
    void set_callbacks(WsSessionCallbacks callbacks);

    // Session info
    const std::string& name() const { return name_; }
    uint64_t session_id() const { return session_id_; }

    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
        std::atomic<uint64_t> frames_sent{0};
        std::atomic<uint64_t> frames_received{0};
    };
    const Stats& stats() const { return stats_; }

    // HTTP request (available after HTTP reading)
    const http::request<http::string_body>& http_request() const { return http_request_; }
    const std::string& path() const { return std::string(http_request_.target()); }

protected:
    // Override for custom auth handling
    virtual void do_authenticate();

    // Override for custom frame processing
    virtual void process_frame(const wire::Frame& frame);

    // Called when auth is complete
    void auth_complete();

    // Called when auth fails
    void auth_failed(const std::string& reason);

    // State transition
    void transition_to(State new_state);

    // IO context
    net::io_context& ioc_;

private:
    void do_ssl_handshake();
    void do_read_http();
    void do_ws_accept();
    void do_read();
    void do_write();
    void queue_write(std::vector<uint8_t> data);

    // Connection info
    std::string name_;
    uint64_t session_id_;
    bool use_ssl_;
    static std::atomic<uint64_t> next_session_id_;

    // SSL context (borrowed, not owned)
    ssl::context* ssl_ctx_;

    // Streams
    std::unique_ptr<ssl::stream<tcp::socket>> ssl_stream_;
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> wss_;
    std::unique_ptr<websocket::stream<tcp::socket>> ws_;
    tcp::socket socket_;  // Moved to ssl_stream or ws

    // State
    std::atomic<State> state_{State::INIT};
    std::atomic<bool> closed_{false};

    // HTTP request
    http::request<http::string_body> http_request_;
    beast::flat_buffer http_buffer_;

    // Read buffer
    beast::flat_buffer read_buffer_;

    // Write queue
    std::mutex write_mutex_;
    std::queue<std::vector<uint8_t>> write_queue_;
    std::atomic<bool> writing_{false};

    // Callbacks
    WsSessionCallbacks callbacks_;

    // Stats
    Stats stats_;
};

// ============================================================================
// WebSocket Server Session Manager
// ============================================================================
template<typename SessionType>
class WsSessionManager {
public:
    void add(uint64_t id, std::shared_ptr<SessionType> session) {
        std::unique_lock lock(mutex_);
        sessions_[id] = session;
    }

    void remove(uint64_t id) {
        std::unique_lock lock(mutex_);
        sessions_.erase(id);
    }

    std::shared_ptr<SessionType> get(uint64_t id) const {
        std::shared_lock lock(mutex_);
        auto it = sessions_.find(id);
        return it != sessions_.end() ? it->second : nullptr;
    }

    size_t count() const {
        std::shared_lock lock(mutex_);
        return sessions_.size();
    }

    template<typename Func>
    void for_each(Func&& func) {
        std::shared_lock lock(mutex_);
        for (auto& [id, session] : sessions_) {
            func(id, session);
        }
    }

    void clear() {
        std::unique_lock lock(mutex_);
        sessions_.clear();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<SessionType>> sessions_;
};

// ============================================================================
// WebSocket Server Base Class
// ============================================================================
class WsServer {
public:
    WsServer(net::io_context& ioc, const std::string& address, uint16_t port,
             bool use_ssl = false, const std::string& name = "WsServer");
    virtual ~WsServer();

    // Non-copyable
    WsServer(const WsServer&) = delete;
    WsServer& operator=(const WsServer&) = delete;

    // Start/stop server
    void start();
    void stop();

    bool is_running() const { return running_.load(); }

    // SSL configuration (call before start)
    void set_ssl_context(ssl::context* ctx) { ssl_ctx_ = ctx; }

    // Statistics
    struct Stats {
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> connections_active{0};
        std::atomic<uint64_t> bytes_sent{0};
        std::atomic<uint64_t> bytes_received{0};
    };
    const Stats& stats() const { return stats_; }

protected:
    // Override to create custom session type
    virtual std::shared_ptr<WsServerSession> create_session(tcp::socket socket);

    // Override to handle new sessions
    virtual void on_session_created(std::shared_ptr<WsServerSession> session);

    // IO context
    net::io_context& ioc_;

    // SSL context (owned externally)
    ssl::context* ssl_ctx_ = nullptr;
    bool use_ssl_;

private:
    void do_accept();

    std::string address_;
    uint16_t port_;
    std::string name_;

    std::unique_ptr<tcp::acceptor> acceptor_;
    std::atomic<bool> running_{false};

    Stats stats_;
};

} // namespace edgelink

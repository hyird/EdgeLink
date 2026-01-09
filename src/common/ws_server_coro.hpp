#pragma once

#include "io_context_pool.hpp"
#include "ws_session_coro.hpp"
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>
#include <string>
#include <atomic>
#include <functional>

namespace edgelink {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

/**
 * WsServerCoro - Coroutine-based WebSocket Server
 *
 * Accepts WebSocket connections and distributes them across threads
 * using round-robin via IOContextPool.
 *
 * Design (per architecture.md Section 8.1):
 * - Uses IOContextPool for thread-per-core model
 * - New connections distributed via round-robin
 * - Each connection stays on its assigned thread
 * - HTTP routing to different WebSocket endpoints
 */
class WsServerCoro {
public:
    /**
     * Session factory function type.
     * Called to create a session for an accepted connection.
     *
     * @param ioc The io_context the session will run on
     * @param socket The accepted TCP socket
     * @param path The requested WebSocket path
     * @return Session object, or nullptr to reject
     */
    using SessionFactory = std::function<std::shared_ptr<WsSessionCoro>(
        net::io_context& ioc,
        tcp::socket socket,
        const std::string& path)>;

    /**
     * Create a server.
     * @param pool IOContextPool for thread distribution
     * @param address Listen address (e.g., "0.0.0.0")
     * @param port Listen port
     */
    WsServerCoro(IOContextPool& pool, const std::string& address, uint16_t port);

    virtual ~WsServerCoro();

    // Non-copyable
    WsServerCoro(const WsServerCoro&) = delete;
    WsServerCoro& operator=(const WsServerCoro&) = delete;

    /**
     * Set the session factory.
     * Must be called before start().
     */
    void set_session_factory(SessionFactory factory);

    /**
     * Enable TLS.
     * @param cert_path Path to certificate file
     * @param key_path Path to private key file
     */
    void enable_tls(const std::string& cert_path, const std::string& key_path);

    /**
     * Start accepting connections.
     */
    void start();

    /**
     * Stop accepting connections.
     */
    void stop();

    /**
     * Check if server is running.
     */
    bool running() const { return running_.load(std::memory_order_acquire); }

    /**
     * Get statistics.
     */
    struct Stats {
        uint64_t connections_accepted{0};
        uint64_t connections_rejected{0};
        uint64_t active_sessions{0};
    };
    Stats get_stats() const;

protected:
    /**
     * Override to create sessions (alternative to factory function).
     * Default implementation uses the session factory.
     */
    virtual std::shared_ptr<WsSessionCoro> create_session(
        net::io_context& ioc,
        tcp::socket socket,
        const std::string& path);

private:
    // Accept loop coroutine (runs on thread 0)
    net::awaitable<void> accept_loop();

    // Handle an accepted connection
    net::awaitable<void> handle_connection(tcp::socket socket, size_t target_thread);

    IOContextPool& pool_;
    std::string address_;
    uint16_t port_;

    std::unique_ptr<tcp::acceptor> acceptor_;
    SessionFactory session_factory_;

    // TLS
    bool tls_enabled_{false};
    ssl::context ssl_ctx_{ssl::context::tlsv12_server};

    std::atomic<bool> running_{false};
    std::atomic<uint64_t> connections_accepted_{0};
    std::atomic<uint64_t> connections_rejected_{0};
    std::atomic<uint64_t> active_sessions_{0};
};

} // namespace edgelink

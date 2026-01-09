#pragma once

#include "frame.hpp"
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>
#include <string>
#include <queue>
#include <atomic>
#include <cstdint>

namespace edgelink {

namespace net = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
using tcp = boost::asio::ip::tcp;

/**
 * WsSessionCoro - Coroutine-based WebSocket Session Base Class
 *
 * This is the base class for all server-side WebSocket sessions using
 * the coroutine-based concurrency model.
 *
 * Design (per architecture.md Section 8.5):
 * - All IO operations use co_await
 * - No blocking calls allowed
 * - Each session runs as a coroutine on its assigned thread
 * - Session lifetime bound to thread (no migration)
 *
 * Subclasses implement:
 * - on_connected(): Called after WebSocket handshake
 * - process_frame(): Called for each received frame
 * - on_disconnected(): Called before cleanup
 */
class WsSessionCoro : public std::enable_shared_from_this<WsSessionCoro> {
public:
    /**
     * Create a session.
     * @param ioc The io_context this session runs on
     * @param socket Already-accepted TCP socket
     */
    WsSessionCoro(net::io_context& ioc, tcp::socket socket);

    virtual ~WsSessionCoro();

    // Non-copyable
    WsSessionCoro(const WsSessionCoro&) = delete;
    WsSessionCoro& operator=(const WsSessionCoro&) = delete;

    /**
     * Start the session.
     * Spawns the main coroutine which handles the WebSocket lifecycle.
     */
    void start();

    /**
     * Request graceful close.
     * The session will complete current operations then close.
     */
    void close();

    /**
     * Send binary data.
     * Thread-safe: Can be called from any thread.
     * @param data Data to send (moved or copied as needed)
     */
    void send_binary(std::vector<uint8_t> data);

    /**
     * Send a wire frame.
     * Thread-safe: Can be called from any thread.
     */
    void send_frame(const wire::Frame& frame);

    /**
     * Send text data.
     * Thread-safe: Can be called from any thread.
     */
    void send_text(std::string text);

    // Session information
    uint32_t node_id() const { return node_id_; }
    uint32_t network_id() const { return network_id_; }
    size_t thread_index() const { return thread_index_; }
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    bool is_authenticated() const { return authenticated_.load(std::memory_order_acquire); }

    /**
     * Get the io_context this session runs on.
     */
    net::io_context& get_io_context() { return ioc_; }

protected:
    /**
     * Called after WebSocket handshake succeeds.
     * Subclasses can perform initial setup here.
     */
    virtual net::awaitable<void> on_connected() = 0;

    /**
     * Called for each received frame.
     * @param frame The received frame
     */
    virtual net::awaitable<void> process_frame(const wire::Frame& frame) = 0;

    /**
     * Called before session cleanup.
     * @param reason Reason for disconnection
     */
    virtual net::awaitable<void> on_disconnected(const std::string& reason) = 0;

    /**
     * Set authentication state.
     * Call this when authentication succeeds.
     */
    void set_authenticated(uint32_t node_id, uint32_t network_id);

    /**
     * Get remote endpoint address.
     */
    std::string remote_address() const;

    net::io_context& ioc_;

private:
    // Main session coroutine
    net::awaitable<void> run_session();

    // Reader coroutine - reads frames from WebSocket
    net::awaitable<void> reader();

    // Writer coroutine - writes queued data to WebSocket
    net::awaitable<void> writer();

    // Enqueue data for sending (internal, called from send_* methods)
    void enqueue_send(std::vector<uint8_t> data, bool is_text);

    // WebSocket stream
    websocket::stream<tcp::socket> ws_;

    // Write queue
    struct WriteItem {
        std::vector<uint8_t> data;
        bool is_text{false};
    };
    std::queue<WriteItem> write_queue_;
    net::steady_timer write_signal_;  // Used to wake up writer coroutine

    // Session state
    std::atomic<bool> running_{false};
    std::atomic<bool> close_requested_{false};
    std::atomic<bool> authenticated_{false};

    uint32_t node_id_{0};
    uint32_t network_id_{0};
    size_t thread_index_{0};
};

} // namespace edgelink

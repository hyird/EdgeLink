#pragma once

#include "common/ws_session_coro.hpp"
#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/jwt.hpp"

#include <boost/json.hpp>
#include <memory>
#include <string>
#include <atomic>

namespace edgelink {

// Forward declarations
class WsRelayServerCoro;

/**
 * WsRelaySessionCoro - Coroutine-based relay client session
 *
 * Handles a single client's relay WebSocket connection using coroutines.
 * Each session is bound to a specific thread and uses no global locks
 * for its own state management.
 */
class WsRelaySessionCoro : public WsSessionCoro {
public:
    WsRelaySessionCoro(net::io_context& ioc, tcp::socket socket, WsRelayServerCoro* server);

    ~WsRelaySessionCoro() override;

    // Get the session's virtual IP
    const std::string& virtual_ip() const { return virtual_ip_; }

protected:
    // WsSessionCoro interface
    net::awaitable<void> on_connected() override;
    net::awaitable<void> process_frame(const wire::Frame& frame) override;
    net::awaitable<void> on_disconnected(const std::string& reason) override;

private:
    // Frame handlers
    net::awaitable<void> handle_relay_auth(const wire::Frame& frame);
    net::awaitable<void> handle_data(const wire::Frame& frame);
    net::awaitable<void> handle_ping(const wire::Frame& frame);
    net::awaitable<void> handle_mesh_forward(const wire::Frame& frame);
    net::awaitable<void> handle_mesh_hello(const wire::Frame& frame);
    net::awaitable<void> handle_mesh_ping(const wire::Frame& frame);

    // Response senders
    void send_auth_response(bool success, uint32_t node_id, const std::string& error = "");
    void send_pong(uint64_t timestamp);
    void send_mesh_pong(uint64_t timestamp, uint32_t sequence);
    void send_mesh_hello_ack(bool success, const std::string& error = "");
    void send_error(const std::string& code, const std::string& message);

    WsRelayServerCoro* server_;
    std::string virtual_ip_;

    // Mesh session tracking (if this is a mesh peer connection)
    bool is_mesh_session_{false};
    uint32_t peer_server_id_{0};
};

} // namespace edgelink

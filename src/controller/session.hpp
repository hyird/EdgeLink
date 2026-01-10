#pragma once

#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <functional>
#include <memory>
#include <queue>
#include <string>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;

using tcp = asio::ip::tcp;

namespace edgelink::controller {

class SessionManager;

// WebSocket stream type (SSL)
using WsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;

// Base session class
class Session : public std::enable_shared_from_this<Session> {
public:
    virtual ~Session() = default;

    // Send a frame
    asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload,
                                     FrameFlags flags = FrameFlags::NONE);

    // Send raw bytes
    asio::awaitable<void> send_raw(std::span<const uint8_t> data);

    // Close the session
    asio::awaitable<void> close();

    // Get session info
    bool is_authenticated() const { return authenticated_; }
    NodeId node_id() const { return node_id_; }
    NetworkId network_id() const { return network_id_; }

protected:
    Session(WsStream&& ws, SessionManager& manager);

    // Run the session (to be implemented by subclasses)
    virtual asio::awaitable<void> run() = 0;

    // Handle a received frame (to be implemented by subclasses)
    virtual asio::awaitable<void> handle_frame(const Frame& frame) = 0;

    // Read loop
    asio::awaitable<void> read_loop();

    // Write loop
    asio::awaitable<void> write_loop();

    // Send error response
    asio::awaitable<void> send_error(uint16_t code, const std::string& message,
                                     FrameType request_type = FrameType::ERROR,
                                     uint32_t request_id = 0);

    WsStream ws_;
    SessionManager& manager_;

    bool authenticated_ = false;
    NodeId node_id_ = 0;
    NetworkId network_id_ = 0;

    // Write queue
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // Read buffer
    beast::flat_buffer read_buffer_;
};

// Control channel session (/api/v1/control)
class ControlSession : public Session {
public:
    ControlSession(WsStream&& ws, SessionManager& manager);

    static asio::awaitable<void> start(WsStream ws, SessionManager& manager);

protected:
    asio::awaitable<void> run() override;
    asio::awaitable<void> handle_frame(const Frame& frame) override;

private:
    asio::awaitable<void> handle_auth_request(const Frame& frame);
    asio::awaitable<void> handle_config_ack(const Frame& frame);
    asio::awaitable<void> handle_ping(const Frame& frame);

    // Send CONFIG to this client
    asio::awaitable<void> send_config();

    uint64_t config_version_ = 0;
};

// Relay channel session (/api/v1/relay)
class RelaySession : public Session {
public:
    RelaySession(WsStream&& ws, SessionManager& manager);

    static asio::awaitable<void> start(WsStream ws, SessionManager& manager);

protected:
    asio::awaitable<void> run() override;
    asio::awaitable<void> handle_frame(const Frame& frame) override;

private:
    asio::awaitable<void> handle_relay_auth(const Frame& frame);
    asio::awaitable<void> handle_data(const Frame& frame);
    asio::awaitable<void> handle_ping(const Frame& frame);
};

} // namespace edgelink::controller

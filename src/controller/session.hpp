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

// WebSocket stream types
using TlsWsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
using PlainWsStream = websocket::stream<beast::tcp_stream>;

// Legacy alias for compatibility
using WsStream = TlsWsStream;

// ============================================================================
// Session interface (type-erased base for session storage)
// ============================================================================

class ISession {
public:
    virtual ~ISession() = default;

    // Send raw bytes (for relay forwarding)
    virtual asio::awaitable<void> send_raw(std::span<const uint8_t> data) = 0;

    // Send a frame
    virtual asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload,
                                              FrameFlags flags = FrameFlags::NONE) = 0;

    // Close the session
    virtual asio::awaitable<void> close() = 0;

    // Get session info
    virtual bool is_authenticated() const = 0;
    virtual NodeId node_id() const = 0;
    virtual NetworkId network_id() const = 0;
};

// ============================================================================
// Base session template
// ============================================================================

template<typename StreamType>
class SessionBase : public ISession, public std::enable_shared_from_this<SessionBase<StreamType>> {
public:
    virtual ~SessionBase() = default;

    // Send a frame (ISession interface)
    asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload,
                                     FrameFlags flags = FrameFlags::NONE) override;

    // Send raw bytes (ISession interface)
    asio::awaitable<void> send_raw(std::span<const uint8_t> data) override;

    // Close the session (ISession interface)
    asio::awaitable<void> close() override;

    // Get session info (ISession interface)
    bool is_authenticated() const override { return authenticated_; }
    NodeId node_id() const override { return node_id_; }
    NetworkId network_id() const override { return network_id_; }

protected:
    SessionBase(StreamType&& ws, SessionManager& manager);

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
                                     FrameType request_type = FrameType::FRAME_ERROR,
                                     uint32_t request_id = 0);

    StreamType ws_;
    SessionManager& manager_;

    bool authenticated_ = false;
    NodeId node_id_ = 0;
    NetworkId network_id_ = 0;

    // Write queue (protected by mutex_)
    std::mutex mutex_;
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // Read buffer
    beast::flat_buffer read_buffer_;
};

// ============================================================================
// Control channel session template (/api/v1/control)
// ============================================================================

template<typename StreamType>
class ControlSessionImpl : public SessionBase<StreamType> {
public:
    ControlSessionImpl(StreamType&& ws, SessionManager& manager);

    static asio::awaitable<void> start(StreamType ws, SessionManager& manager);

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

// ============================================================================
// Relay channel session template (/api/v1/relay)
// ============================================================================

template<typename StreamType>
class RelaySessionImpl : public SessionBase<StreamType> {
public:
    RelaySessionImpl(StreamType&& ws, SessionManager& manager);

    static asio::awaitable<void> start(StreamType ws, SessionManager& manager);

protected:
    asio::awaitable<void> run() override;
    asio::awaitable<void> handle_frame(const Frame& frame) override;

private:
    asio::awaitable<void> handle_relay_auth(const Frame& frame);
    asio::awaitable<void> handle_data(const Frame& frame);
    asio::awaitable<void> handle_ping(const Frame& frame);
};

// ============================================================================
// Type aliases for TLS and Plain sessions
// ============================================================================

// TLS sessions (original)
using Session = SessionBase<TlsWsStream>;
using ControlSession = ControlSessionImpl<TlsWsStream>;
using RelaySession = RelaySessionImpl<TlsWsStream>;

// Plain sessions (non-TLS)
using PlainSession = SessionBase<PlainWsStream>;
using PlainControlSession = ControlSessionImpl<PlainWsStream>;
using PlainRelaySession = RelaySessionImpl<PlainWsStream>;

} // namespace edgelink::controller

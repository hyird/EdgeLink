#pragma once

#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include <boost/asio.hpp>
#include <boost/cobalt.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include "common/cross_thread_channel.hpp"
#include <functional>
#include <memory>
#include <string>

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;
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
    virtual cobalt::task<void> send_raw(std::span<const uint8_t> data) = 0;

    // Send a frame
    virtual cobalt::task<void> send_frame(FrameType type, std::span<const uint8_t> payload,
                                              FrameFlags flags = FrameFlags::NONE) = 0;

    // Close the session
    virtual cobalt::task<void> close() = 0;

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
    cobalt::task<void> send_frame(FrameType type, std::span<const uint8_t> payload,
                                     FrameFlags flags = FrameFlags::NONE) override;

    // Send raw bytes (ISession interface)
    cobalt::task<void> send_raw(std::span<const uint8_t> data) override;

    // Close the session (ISession interface)
    cobalt::task<void> close() override;

    // Get session info (ISession interface)
    bool is_authenticated() const override { return authenticated_; }
    NodeId node_id() const override { return node_id_; }
    NetworkId network_id() const override { return network_id_; }

protected:
    SessionBase(StreamType&& ws, SessionManager& manager);

    // Run the session (to be implemented by subclasses)
    virtual cobalt::task<void> run() = 0;

    // Handle a received frame (to be implemented by subclasses)
    virtual cobalt::task<void> handle_frame(const Frame& frame) = 0;

    // Read loop
    cobalt::task<void> read_loop();

    // Write loop
    cobalt::task<void> write_loop();

    // Send error response
    cobalt::task<void> send_error(uint16_t code, const std::string& message,
                                     FrameType request_type = FrameType::FRAME_ERROR,
                                     uint32_t request_id = 0);

    StreamType ws_;
    SessionManager& manager_;

    bool authenticated_ = false;
    NodeId node_id_ = 0;
    NetworkId network_id_ = 0;

    // Write channel (thread-safe)
    using WriteChannel = edgelink::CrossThreadChannel<std::vector<uint8_t>>;
    WriteChannel write_channel_;

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

    static cobalt::task<void> start(StreamType ws, SessionManager& manager);

protected:
    cobalt::task<void> run() override;
    cobalt::task<void> handle_frame(const Frame& frame) override;

private:
    cobalt::task<void> handle_auth_request(const Frame& frame);
    cobalt::task<void> handle_config_ack(const Frame& frame);
    cobalt::task<void> handle_ping(const Frame& frame);
    cobalt::task<void> handle_latency_report(const Frame& frame);
    cobalt::task<void> handle_peer_path_report(const Frame& frame);
    cobalt::task<void> handle_relay_latency_report(const Frame& frame);
    cobalt::task<void> handle_route_announce(const Frame& frame);
    cobalt::task<void> handle_route_withdraw(const Frame& frame);
    cobalt::task<void> handle_p2p_init(const Frame& frame);
    cobalt::task<void> handle_endpoint_update(const Frame& frame);

    // Send CONFIG to this client
    cobalt::task<void> send_config();

    // Send ROUTE_ACK to this client
    cobalt::task<void> send_route_ack(uint32_t request_id, bool success,
                                         uint16_t error_code = 0,
                                         const std::string& error_msg = "");

    uint64_t config_version_ = 0;
};

// ============================================================================
// Relay channel session template (/api/v1/relay)
// ============================================================================

template<typename StreamType>
class RelaySessionImpl : public SessionBase<StreamType> {
public:
    RelaySessionImpl(StreamType&& ws, SessionManager& manager);

    static cobalt::task<void> start(StreamType ws, SessionManager& manager);

protected:
    cobalt::task<void> run() override;
    cobalt::task<void> handle_frame(const Frame& frame) override;

private:
    cobalt::task<void> handle_relay_auth(const Frame& frame);
    cobalt::task<void> handle_data(const Frame& frame);
    cobalt::task<void> handle_ping(const Frame& frame);
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

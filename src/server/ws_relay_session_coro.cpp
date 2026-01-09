#include "ws_relay_session_coro.hpp"
#include "ws_relay_server_coro.hpp"
#include "common/log.hpp"

namespace edgelink {

WsRelaySessionCoro::WsRelaySessionCoro(net::io_context& ioc, tcp::socket socket,
                                         WsRelayServerCoro* server)
    : WsSessionCoro(ioc, std::move(socket))
    , server_(server)
{}

WsRelaySessionCoro::~WsRelaySessionCoro() = default;

net::awaitable<void> WsRelaySessionCoro::on_connected() {
    LOG_DEBUG("WsRelaySessionCoro: Connection established from {}", remote_address());
    server_->stats().connections_total++;
    server_->stats().connections_active++;
    co_return;
}

net::awaitable<void> WsRelaySessionCoro::process_frame(const wire::Frame& frame) {
    switch (frame.header.type) {
        case wire::MessageType::RELAY_AUTH:
            co_await handle_relay_auth(frame);
            break;

        case wire::MessageType::DATA:
            if (is_authenticated()) {
                co_await handle_data(frame);
            } else {
                send_error("AUTH_REQUIRED", "Authentication required");
            }
            break;

        case wire::MessageType::PING:
            co_await handle_ping(frame);
            break;

        case wire::MessageType::MESH_FORWARD:
            co_await handle_mesh_forward(frame);
            break;

        case wire::MessageType::MESH_HELLO:
            co_await handle_mesh_hello(frame);
            break;

        case wire::MessageType::MESH_PING:
            co_await handle_mesh_ping(frame);
            break;

        default:
            LOG_DEBUG("WsRelaySessionCoro: Unhandled message type: {} (0x{:02x})",
                      wire::message_type_to_string(frame.header.type),
                      static_cast<int>(frame.header.type));
            break;
    }
    co_return;
}

net::awaitable<void> WsRelaySessionCoro::on_disconnected(const std::string& reason) {
    LOG_DEBUG("WsRelaySessionCoro: Disconnected (node {}, reason: {})", node_id(), reason);

    server_->stats().connections_active--;

    // Remove from session registry
    if (is_authenticated() && node_id() > 0) {
        server_->remove_client_session(node_id());
    }

    // If this was a mesh session, remove from mesh registry
    if (is_mesh_session_ && peer_server_id_ > 0) {
        server_->remove_mesh_session(peer_server_id_);
    }

    co_return;
}

net::awaitable<void> WsRelaySessionCoro::handle_relay_auth(const wire::Frame& frame) {
    if (is_authenticated()) {
        send_error("ALREADY_AUTH", "Already authenticated");
        co_return;
    }

    auto result = wire::RelayAuthPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsRelaySessionCoro: Failed to parse RELAY_AUTH: error={}",
                 static_cast<int>(result.error()));
        send_auth_response(false, 0, "Invalid payload");
        server_->stats().auth_failures++;
        co_return;
    }

    uint32_t node_id = 0;
    std::string virtual_ip;

    if (!server_->validate_relay_token(result->relay_token, node_id, virtual_ip)) {
        send_auth_response(false, 0, "Invalid token");
        server_->stats().auth_failures++;
        co_return;
    }

    // Set authenticated state
    set_authenticated(node_id, 0);  // network_id not used here
    virtual_ip_ = virtual_ip;

    // Register session with server
    server_->add_client_session(node_id, shared_from_this());

    send_auth_response(true, node_id);
    LOG_INFO("WsRelaySessionCoro: Node {} authenticated ({})", node_id, virtual_ip_);

    co_return;
}

net::awaitable<void> WsRelaySessionCoro::handle_data(const wire::Frame& frame) {
    // Parse DATA payload to get destination
    auto data_result = wire::DataPayload::deserialize(frame.payload);
    if (!data_result) {
        LOG_WARN("WsRelaySessionCoro: Invalid DATA payload from node {}", node_id());
        co_return;
    }

    uint32_t dst_node = data_result->dst_node_id;

    // Forward to destination
    server_->forward_data(node_id(), dst_node, frame.serialize());

    co_return;
}

net::awaitable<void> WsRelaySessionCoro::handle_ping(const wire::Frame& frame) {
    uint64_t timestamp = 0;

    auto result = wire::MeshPingPayload::deserialize_binary(frame.payload);
    if (result) {
        timestamp = result->timestamp;
    }
    send_pong(timestamp);
    co_return;
}

net::awaitable<void> WsRelaySessionCoro::handle_mesh_forward(const wire::Frame& frame) {
    // Parse MESH_FORWARD payload
    auto result = wire::MeshForwardPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsRelaySessionCoro: Invalid MESH_FORWARD payload");
        co_return;
    }

    const auto& mesh_payload = *result;

    // Check TTL
    if (mesh_payload.ttl == 0) {
        LOG_DEBUG("WsRelaySessionCoro: MESH_FORWARD TTL expired for node {}",
                  mesh_payload.dst_node_id);
        co_return;
    }

    // Forward via server
    server_->handle_mesh_forward(mesh_payload);

    co_return;
}

net::awaitable<void> WsRelaySessionCoro::handle_mesh_hello(const wire::Frame& frame) {
    auto result = wire::MeshHelloPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsRelaySessionCoro: Failed to parse MESH_HELLO: error={}",
                 static_cast<int>(result.error()));
        send_mesh_hello_ack(false, "Invalid payload");
        co_return;
    }

    const auto& hello = *result;

    LOG_INFO("WsRelaySessionCoro: MESH_HELLO from server {} (region: {})",
             hello.server_id, hello.region);

    // Mark this as a mesh session
    is_mesh_session_ = true;
    peer_server_id_ = hello.server_id;

    // Register mesh session
    server_->add_mesh_session(hello.server_id, shared_from_this());

    // Send acknowledgment
    send_mesh_hello_ack(true);

    co_return;
}

net::awaitable<void> WsRelaySessionCoro::handle_mesh_ping(const wire::Frame& frame) {
    auto result = wire::MeshPingPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsRelaySessionCoro: Failed to parse MESH_PING: error={}",
                 static_cast<int>(result.error()));
        co_return;
    }

    send_mesh_pong(result->timestamp, result->sequence);
    co_return;
}

void WsRelaySessionCoro::send_auth_response(bool success, uint32_t node_id, const std::string& error) {
    wire::AuthResponsePayload payload;
    payload.success = success;
    payload.node_id = node_id;
    payload.error_message = error;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::AUTH_RESPONSE, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("WsRelaySessionCoro: AUTH_RESPONSE sent (success={}, {} bytes)", success, frame.payload.size());
}

void WsRelaySessionCoro::send_pong(uint64_t timestamp) {
    wire::PongPayload payload;
    payload.timestamp = timestamp;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::PONG, std::move(binary));
    send_frame(frame);
}

void WsRelaySessionCoro::send_mesh_pong(uint64_t timestamp, uint32_t sequence) {
    wire::MeshPingPayload pong_payload;
    pong_payload.timestamp = timestamp;
    pong_payload.sequence = sequence;

    auto payload_bytes = pong_payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::MESH_PONG, std::move(payload_bytes));
    send_frame(frame);
}

void WsRelaySessionCoro::send_mesh_hello_ack(bool success, const std::string& error) {
    wire::MeshHelloAckPayload ack;
    ack.success = success;
    ack.server_id = server_->server_id();
    ack.region = "default";  // TODO: Get from config
    ack.capabilities = wire::ServerCapability::RELAY;
    ack.error_message = error;

    auto payload_bytes = ack.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::MESH_HELLO_ACK, std::move(payload_bytes));
    send_frame(frame);
}

void WsRelaySessionCoro::send_error(const std::string& code, const std::string& message) {
    LOG_DEBUG("WsRelaySessionCoro: Sending ERROR (code={}, msg={})", code, message);

    wire::ErrorPayload payload;
    // Convert string code to int (hash or use known codes)
    if (code == "AUTH_REQUIRED") {
        payload.code = static_cast<uint16_t>(wire::ErrorCode::NODE_NOT_AUTHORIZED);
    } else if (code == "ALREADY_AUTH") {
        payload.code = static_cast<uint16_t>(wire::ErrorCode::INVALID_MESSAGE);
    } else {
        payload.code = static_cast<uint16_t>(wire::ErrorCode::INTERNAL_ERROR);
    }
    payload.message = message;
    payload.details = code;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::ERROR_MSG, std::move(binary));
    send_frame(frame);
}

} // namespace edgelink

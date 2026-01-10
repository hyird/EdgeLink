#include "controller/session.hpp"
#include "controller/session_manager.hpp"
#include "common/crypto.hpp"
#include <spdlog/spdlog.h>

namespace edgelink::controller {

// ============================================================================
// Session base implementation
// ============================================================================

Session::Session(WsStream&& ws, SessionManager& manager)
    : ws_(std::move(ws))
    , manager_(manager)
    , write_timer_(ws_.get_executor()) {
    write_timer_.expires_at(std::chrono::steady_clock::time_point::max());
}

asio::awaitable<void> Session::send_frame(FrameType type, std::span<const uint8_t> payload,
                                          FrameFlags flags) {
    auto data = FrameCodec::encode(type, payload, flags);
    co_await send_raw(data);
}

asio::awaitable<void> Session::send_raw(std::span<const uint8_t> data) {
    std::vector<uint8_t> copy(data.begin(), data.end());
    write_queue_.push(std::move(copy));

    if (!writing_) {
        write_timer_.cancel();
    }
    co_return;
}

asio::awaitable<void> Session::close() {
    try {
        co_await ws_.async_close(websocket::close_code::normal, asio::use_awaitable);
    } catch (...) {
        // Ignore close errors
    }
}

asio::awaitable<void> Session::read_loop() {
    try {
        while (true) {
            read_buffer_.clear();
            auto bytes = co_await ws_.async_read(read_buffer_, asio::use_awaitable);
            (void)bytes;

            auto data = read_buffer_.data();
            std::span<const uint8_t> buffer(
                static_cast<const uint8_t*>(data.data()), data.size());

            // Decode frame
            auto result = FrameCodec::decode(buffer);
            if (!result) {
                spdlog::warn("Failed to decode frame: {}", frame_error_message(result.error()));
                continue;
            }

            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            spdlog::debug("Session read error: {}", e.what());
        }
    }
}

asio::awaitable<void> Session::write_loop() {
    try {
        while (true) {
            if (write_queue_.empty()) {
                writing_ = false;
                co_await write_timer_.async_wait(asio::use_awaitable);
            }

            writing_ = true;
            while (!write_queue_.empty()) {
                auto data = std::move(write_queue_.front());
                write_queue_.pop();

                co_await ws_.async_write(asio::buffer(data), asio::use_awaitable);
            }
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted &&
            e.code() != websocket::error::closed) {
            spdlog::debug("Session write error: {}", e.what());
        }
    }
}

asio::awaitable<void> Session::send_error(uint16_t code, const std::string& message,
                                          FrameType request_type, uint32_t request_id) {
    ErrorPayload error;
    error.error_code = code;
    error.request_type = request_type;
    error.request_id = request_id;
    error.error_msg = message;

    co_await send_frame(FrameType::ERROR, error.serialize());
}

// ============================================================================
// ControlSession implementation
// ============================================================================

ControlSession::ControlSession(WsStream&& ws, SessionManager& manager)
    : Session(std::move(ws), manager) {}

asio::awaitable<void> ControlSession::start(WsStream ws, SessionManager& manager) {
    auto session = std::make_shared<ControlSession>(std::move(ws), manager);
    co_await session->run();
}

asio::awaitable<void> ControlSession::run() {
    spdlog::info("Control session started");

    try {
        // Run read and write loops concurrently
        co_await (read_loop() || write_loop());
    } catch (const std::exception& e) {
        spdlog::debug("Control session ended: {}", e.what());
    }

    // Cleanup
    if (authenticated_ && node_id_ != 0) {
        manager_.unregister_control_session(node_id_);
        manager_.database().update_node_online(node_id_, false);

        // Notify other nodes
        co_await manager_.broadcast_config_update(network_id_, node_id_);
        spdlog::info("Node {} disconnected from control channel", node_id_);
    }
}

asio::awaitable<void> ControlSession::handle_frame(const Frame& frame) {
    spdlog::debug("Control: received {} frame", frame_type_name(frame.header.type));

    switch (frame.header.type) {
        case FrameType::AUTH_REQUEST:
            co_await handle_auth_request(frame);
            break;

        case FrameType::CONFIG_ACK:
            co_await handle_config_ack(frame);
            break;

        case FrameType::PING:
            co_await handle_ping(frame);
            break;

        default:
            if (!authenticated_) {
                co_await send_error(1001, "Not authenticated", frame.header.type);
            } else {
                spdlog::warn("Control: unhandled frame type 0x{:02X}",
                             static_cast<uint8_t>(frame.header.type));
            }
            break;
    }
}

asio::awaitable<void> ControlSession::handle_auth_request(const Frame& frame) {
    auto request = AuthRequest::parse(frame.payload);
    if (!request) {
        co_await send_error(1002, "Invalid AUTH_REQUEST format", FrameType::AUTH_REQUEST);
        co_return;
    }

    spdlog::info("Auth request from {} (auth_type={})",
                 request->hostname, static_cast<int>(request->auth_type));

    // Verify signature
    auto sign_data = request->get_sign_data();
    if (!crypto::ed25519_verify(sign_data, request->signature, request->machine_key)) {
        co_await send_error(1003, "Invalid signature", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Handle authkey authentication
    NetworkId network_id = 0;
    if (request->auth_type == AuthType::AUTHKEY) {
        std::string authkey(request->auth_data.begin(), request->auth_data.end());
        auto key_record = manager_.database().get_authkey(authkey);

        if (!key_record) {
            co_await send_error(1004, "Invalid authkey", FrameType::AUTH_REQUEST);
            co_return;
        }

        // Check expiration
        if (key_record->expires_at > 0 && key_record->expires_at < Database::now_ms()) {
            co_await send_error(1005, "Authkey expired", FrameType::AUTH_REQUEST);
            co_return;
        }

        // Check usage limit
        if (key_record->max_uses > 0 && key_record->use_count >= key_record->max_uses) {
            co_await send_error(1006, "Authkey usage limit exceeded", FrameType::AUTH_REQUEST);
            co_return;
        }

        network_id = key_record->network_id;
        manager_.database().increment_authkey_use(authkey);

    } else if (request->auth_type == AuthType::MACHINE) {
        // Reconnection - find existing node
        auto existing = manager_.database().get_node_by_machine_key(request->machine_key);
        if (!existing) {
            co_await send_error(1007, "Unknown machine key", FrameType::AUTH_REQUEST);
            co_return;
        }
        network_id = existing->network_id;
    } else {
        co_await send_error(1008, "Unsupported auth type", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Find or create node
    auto node = manager_.database().find_or_create_node(
        network_id, request->machine_key, request->node_key,
        request->hostname, request->os, request->arch, request->version);

    if (!node) {
        co_await send_error(1009, "Failed to create node", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Update state
    authenticated_ = true;
    node_id_ = node->id;
    network_id_ = node->network_id;

    // Update node online status
    manager_.database().update_node_online(node_id_, true);

    // Register session
    manager_.register_control_session(node_id_, std::static_pointer_cast<ControlSession>(shared_from_this()));

    // Create tokens
    auto auth_token = manager_.jwt().create_auth_token(node_id_, network_id_);
    auto relay_token = manager_.jwt().create_relay_token(node_id_, network_id_);

    if (!auth_token || !relay_token) {
        co_await send_error(1010, "Failed to create tokens", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Build AUTH_RESPONSE
    AuthResponse response;
    response.success = true;
    response.node_id = node_id_;
    response.virtual_ip = node->virtual_ip;
    response.network_id = network_id_;
    response.auth_token = std::vector<uint8_t>(auth_token->begin(), auth_token->end());
    response.relay_token = std::vector<uint8_t>(relay_token->begin(), relay_token->end());
    response.error_code = 0;
    response.error_msg = "";

    co_await send_frame(FrameType::AUTH_RESPONSE, response.serialize());

    spdlog::info("Node {} authenticated: {} ({})",
                 node_id_, node->hostname, node->virtual_ip.to_string());

    // Send CONFIG
    co_await send_config();

    // Notify other nodes about new peer
    co_await manager_.broadcast_config_update(network_id_, node_id_);
}

asio::awaitable<void> ControlSession::send_config() {
    // Get all nodes in network
    auto nodes = manager_.database().get_nodes_by_network(network_id_);
    if (!nodes) {
        spdlog::error("Failed to get nodes for network {}", network_id_);
        co_return;
    }

    // Get network info
    auto network = manager_.database().get_network(network_id_);
    if (!network) {
        spdlog::error("Failed to get network {}", network_id_);
        co_return;
    }

    // Parse CIDR
    auto slash_pos = network->cidr.find('/');
    auto subnet_ip = IPv4Address::from_string(network->cidr.substr(0, slash_pos));
    uint8_t subnet_mask = static_cast<uint8_t>(std::stoi(network->cidr.substr(slash_pos + 1)));

    // Build CONFIG
    Config config;
    config.version = manager_.current_config_version();
    config.network_id = network_id_;
    config.subnet = subnet_ip;
    config.subnet_mask = subnet_mask;
    config.network_name = network->name;

    // Add peers (excluding self)
    for (const auto& node : *nodes) {
        if (node.id == node_id_) continue;

        PeerInfo peer;
        peer.node_id = node.id;
        peer.virtual_ip = node.virtual_ip;
        peer.node_key = node.node_key;
        peer.online = node.online;
        peer.name = node.hostname;
        config.peers.push_back(peer);
    }

    // Add relay info (built-in relay = this controller)
    RelayInfo relay;
    relay.server_id = 0; // Built-in relay
    relay.hostname = "builtin";
    relay.priority = 100;
    relay.region = "local";
    config.relays.push_back(relay);

    // Create new relay token
    auto relay_token = manager_.jwt().create_relay_token(node_id_, network_id_);
    if (relay_token) {
        config.relay_token = std::vector<uint8_t>(relay_token->begin(), relay_token->end());
        auto expiry = manager_.jwt().get_token_expiry(*relay_token);
        config.relay_token_expires = expiry.value_or(0) * 1000; // Convert to ms
    }

    config_version_ = config.version;
    co_await send_frame(FrameType::CONFIG, config.serialize());

    spdlog::debug("Sent CONFIG to node {} with {} peers", node_id_, config.peers.size());
}

asio::awaitable<void> ControlSession::handle_config_ack(const Frame& frame) {
    auto ack = ConfigAck::parse(frame.payload);
    if (!ack) {
        co_return;
    }

    spdlog::debug("Node {} acknowledged config version {}", node_id_, ack->version);
}

asio::awaitable<void> ControlSession::handle_ping(const Frame& frame) {
    auto ping = Ping::parse(frame.payload);
    if (!ping) {
        co_return;
    }

    // Send PONG with same timestamp and seq_num
    Pong pong;
    pong.timestamp = ping->timestamp;
    pong.seq_num = ping->seq_num;

    co_await send_frame(FrameType::PONG, pong.serialize());

    // Update last seen
    if (authenticated_) {
        manager_.database().update_node_last_seen(node_id_, Database::now_ms());
    }
}

// ============================================================================
// RelaySession implementation
// ============================================================================

RelaySession::RelaySession(WsStream&& ws, SessionManager& manager)
    : Session(std::move(ws), manager) {}

asio::awaitable<void> RelaySession::start(WsStream ws, SessionManager& manager) {
    auto session = std::make_shared<RelaySession>(std::move(ws), manager);
    co_await session->run();
}

asio::awaitable<void> RelaySession::run() {
    spdlog::info("Relay session started");

    try {
        co_await (read_loop() || write_loop());
    } catch (const std::exception& e) {
        spdlog::debug("Relay session ended: {}", e.what());
    }

    // Cleanup
    if (authenticated_ && node_id_ != 0) {
        manager_.unregister_relay_session(node_id_);
        spdlog::info("Node {} disconnected from relay channel", node_id_);
    }
}

asio::awaitable<void> RelaySession::handle_frame(const Frame& frame) {
    spdlog::debug("Relay: received {} frame", frame_type_name(frame.header.type));

    switch (frame.header.type) {
        case FrameType::RELAY_AUTH:
            co_await handle_relay_auth(frame);
            break;

        case FrameType::DATA:
            co_await handle_data(frame);
            break;

        case FrameType::PING:
            co_await handle_ping(frame);
            break;

        default:
            if (!authenticated_) {
                co_await send_error(1001, "Not authenticated", frame.header.type);
            } else {
                spdlog::warn("Relay: unhandled frame type 0x{:02X}",
                             static_cast<uint8_t>(frame.header.type));
            }
            break;
    }
}

asio::awaitable<void> RelaySession::handle_relay_auth(const Frame& frame) {
    auto auth = RelayAuth::parse(frame.payload);
    if (!auth) {
        co_await send_error(1002, "Invalid RELAY_AUTH format", FrameType::RELAY_AUTH);
        co_return;
    }

    // Verify relay token
    std::string token(auth->relay_token.begin(), auth->relay_token.end());
    auto claims = manager_.jwt().verify_relay_token(token);

    if (!claims) {
        co_await send_error(1003, jwt_error_message(claims.error()), FrameType::RELAY_AUTH);
        co_return;
    }

    // Verify node_id matches
    if (claims->node_id != auth->node_id) {
        co_await send_error(1004, "Node ID mismatch", FrameType::RELAY_AUTH);
        co_return;
    }

    // Update state
    authenticated_ = true;
    node_id_ = auth->node_id;
    network_id_ = claims->network_id;

    // Register relay session
    manager_.register_relay_session(node_id_, std::static_pointer_cast<RelaySession>(shared_from_this()));

    // Send success response
    RelayAuthResp response;
    response.success = true;
    response.error_code = 0;
    response.error_msg = "";

    co_await send_frame(FrameType::RELAY_AUTH_RESP, response.serialize());

    spdlog::info("Node {} authenticated to relay channel", node_id_);
}

asio::awaitable<void> RelaySession::handle_data(const Frame& frame) {
    if (!authenticated_) {
        co_await send_error(1001, "Not authenticated", FrameType::DATA);
        co_return;
    }

    // Parse DATA payload to get dst_node
    auto data = DataPayload::parse(frame.payload);
    if (!data) {
        co_return; // Silently drop malformed data
    }

    // Verify src_node matches authenticated node
    if (data->src_node != node_id_) {
        spdlog::warn("Node {} attempted to send DATA with src_node={}",
                     node_id_, data->src_node);
        co_return;
    }

    // Find target relay session
    auto target = manager_.get_relay_session(data->dst_node);
    if (!target) {
        // Target not connected to relay, drop silently
        spdlog::debug("DATA from {} to {} dropped: target not on relay",
                      data->src_node, data->dst_node);
        co_return;
    }

    // Forward the entire frame as-is (we don't decrypt)
    auto frame_data = FrameCodec::encode(FrameType::DATA, frame.payload);
    co_await target->send_raw(frame_data);

    spdlog::trace("Forwarded DATA from {} to {} ({} bytes)",
                  data->src_node, data->dst_node, frame.payload.size());
}

asio::awaitable<void> RelaySession::handle_ping(const Frame& frame) {
    auto ping = Ping::parse(frame.payload);
    if (!ping) {
        co_return;
    }

    Pong pong;
    pong.timestamp = ping->timestamp;
    pong.seq_num = ping->seq_num;

    co_await send_frame(FrameType::PONG, pong.serialize());
}

} // namespace edgelink::controller

#include "builtin_relay.hpp"
#include "common/log.hpp"
#include "common/ws_session_coro.hpp"

#include <boost/json.hpp>

namespace edgelink::controller {

// ============================================================================
// RelaySessionManager Implementation
// ============================================================================

RelaySessionManager::RelaySessionManager(const std::string& jwt_secret)
    : jwt_secret_(jwt_secret) {
}

void RelaySessionManager::add_session(uint32_t node_id, void* session) {
    std::unique_lock lock(sessions_mutex_);
    sessions_[node_id] = session;
    LOG_DEBUG("RelaySessionManager: Added session for node {}", node_id);
}

void RelaySessionManager::remove_session(uint32_t node_id) {
    std::unique_lock lock(sessions_mutex_);
    sessions_.erase(node_id);
    LOG_DEBUG("RelaySessionManager: Removed session for node {}", node_id);
}

void* RelaySessionManager::get_session(uint32_t node_id) {
    std::shared_lock lock(sessions_mutex_);
    auto it = sessions_.find(node_id);
    return (it != sessions_.end()) ? it->second : nullptr;
}

std::string RelaySessionManager::create_relay_token(uint32_t node_id, uint32_t network_id) {
    JWTManager jwt_manager(jwt_secret_);
    // Allow all relays for now
    std::vector<uint32_t> allowed_relays;
    return jwt_manager.create_relay_token(node_id, network_id, allowed_relays);
}

bool RelaySessionManager::validate_relay_token(const std::string& token, uint32_t& node_id,
                                               std::string& virtual_ip) {
    JWTManager jwt_manager(jwt_secret_);
    auto claims = jwt_manager.verify_relay_token(token);
    if (!claims) {
        return false;
    }

    if (claims->type != TokenType::RELAY) {
        return false;
    }

    // Check blacklist
    if (is_blacklisted(claims->jti)) {
        LOG_WARN("RelaySessionManager: Token {} is blacklisted", claims->jti);
        return false;
    }

    node_id = claims->node_id;
    virtual_ip = "";  // RelayTokenClaims doesn't have virtual_ip
    return true;
}

void RelaySessionManager::add_to_blacklist(const std::string& jti, int64_t expires_at) {
    std::unique_lock lock(blacklist_mutex_);
    token_blacklist_[jti] = expires_at;
}

bool RelaySessionManager::is_blacklisted(const std::string& jti) const {
    std::shared_lock lock(blacklist_mutex_);
    auto it = token_blacklist_.find(jti);
    if (it == token_blacklist_.end()) {
        return false;
    }

    // Check if expired
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return now < it->second;
}

size_t RelaySessionManager::session_count() const {
    std::shared_lock lock(sessions_mutex_);
    return sessions_.size();
}

// ============================================================================
// BuiltinRelay Implementation
// ============================================================================

BuiltinRelay::BuiltinRelay(net::io_context& ioc,
                           const BuiltinRelayConfig& config,
                           std::shared_ptr<Database> db,
                           const std::string& jwt_secret)
    : ioc_(ioc)
    , config_(config)
    , db_(std::move(db))
    , jwt_secret_(jwt_secret)
    , session_manager_(jwt_secret) {

    if (config_.enabled) {
        LOG_INFO("BuiltinRelay initialized (WebSocket mode)");
    }
}

BuiltinRelay::~BuiltinRelay() {
    stop();
}

void BuiltinRelay::start() {
    if (!config_.enabled) return;
    running_ = true;
    LOG_INFO("BuiltinRelay started");
}

void BuiltinRelay::stop() {
    if (!running_) return;
    running_ = false;
    LOG_INFO("BuiltinRelay stopped");
}

bool BuiltinRelay::forward_data(uint32_t dst_node_id, const std::vector<uint8_t>& data,
                                uint32_t src_node_id) {
    // Create a DATA frame
    wire::FrameHeader header;
    header.version = wire::PROTOCOL_VERSION;
    header.type = wire::MessageType::DATA;
    header.flags = 0;
    header.length = static_cast<uint16_t>(data.size() + 8);  // 4 bytes src + 4 bytes dst + payload

    // Build frame: header + src_node_id + dst_node_id + data
    std::vector<uint8_t> frame;
    frame.reserve(NetworkConstants::HEADER_SIZE + 8 + data.size());

    // Header
    frame.push_back(header.version);
    frame.push_back(static_cast<uint8_t>(header.type));
    frame.push_back(header.flags);
    frame.push_back(static_cast<uint8_t>(header.length >> 8));
    frame.push_back(static_cast<uint8_t>(header.length & 0xFF));

    // Source node ID (big-endian)
    frame.push_back(static_cast<uint8_t>(src_node_id >> 24));
    frame.push_back(static_cast<uint8_t>(src_node_id >> 16));
    frame.push_back(static_cast<uint8_t>(src_node_id >> 8));
    frame.push_back(static_cast<uint8_t>(src_node_id));

    // Destination node ID (big-endian)
    frame.push_back(static_cast<uint8_t>(dst_node_id >> 24));
    frame.push_back(static_cast<uint8_t>(dst_node_id >> 16));
    frame.push_back(static_cast<uint8_t>(dst_node_id >> 8));
    frame.push_back(static_cast<uint8_t>(dst_node_id));

    // Payload
    frame.insert(frame.end(), data.begin(), data.end());

    if (send_to_node(dst_node_id, frame)) {
        stats_.packets_forwarded++;
        stats_.bytes_forwarded += data.size();
        return true;
    }

    return false;
}

bool BuiltinRelay::send_to_node(uint32_t node_id, const std::vector<uint8_t>& frame_data) {
    void* session_ptr = session_manager_.get_session(node_id);
    if (!session_ptr) {
        LOG_DEBUG("BuiltinRelay: Node {} not connected", node_id);
        return false;
    }

    // Cast to WsSessionCoro - works with WsBuiltinRelaySessionCoro
    auto* session = static_cast<WsSessionCoro*>(session_ptr);
    session->send_binary(frame_data);
    return true;
}

// ============================================================================
// WsRelaySession Implementation
// ============================================================================

WsRelaySession::WsRelaySession(tcp::socket&& socket, BuiltinRelay* relay)
    : ws_(std::move(socket))
    , relay_(relay) {
}

void WsRelaySession::run() {
    // Set suggested timeout settings for the websocket
    ws_.set_option(websocket::stream_base::timeout::suggested(
        beast::role_type::server));

    // Set a decorator to change the Server field
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(beast::http::field::server, "EdgeLink-Relay/1.0");
        }));

    do_accept();
}

void WsRelaySession::send(const std::vector<uint8_t>& data) {
    // Post to strand to ensure thread safety
    net::post(ws_.get_executor(),
        [self = shared_from_this(), data]() {
            self->write_queue_.push_back(data);
            if (!self->writing_) {
                self->do_write();
            }
        });
}

void WsRelaySession::close() {
    beast::error_code ec;
    ws_.close(websocket::close_code::normal, ec);
}

void WsRelaySession::do_accept() {
    ws_.async_accept(
        beast::bind_front_handler(
            &WsRelaySession::on_accept,
            shared_from_this()));
}

void WsRelaySession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_WARN("WsRelaySession: Accept failed: {}", ec.message());
        return;
    }

    relay_->stats().connections_total++;
    relay_->stats().connections_active++;

    // Set binary mode for all messages
    ws_.binary(true);

    do_read();
}

void WsRelaySession::do_read() {
    buffer_.consume(buffer_.size());

    ws_.async_read(
        buffer_,
        beast::bind_front_handler(
            &WsRelaySession::on_read,
            shared_from_this()));
}

void WsRelaySession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec == websocket::error::closed) {
        LOG_DEBUG("WsRelaySession: Connection closed");
        goto cleanup;
    }

    if (ec) {
        LOG_WARN("WsRelaySession: Read error: {}", ec.message());
        goto cleanup;
    }

    {
        // Process the message
        auto data = buffer_.data();
        std::vector<uint8_t> message(
            static_cast<const uint8_t*>(data.data()),
            static_cast<const uint8_t*>(data.data()) + data.size());

        handle_message(message);
    }

    do_read();
    return;

cleanup:
    if (authenticated_ && node_id_ > 0) {
        relay_->session_manager()->remove_session(node_id_);
    }
    relay_->stats().connections_active--;
}

void WsRelaySession::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }

    writing_ = true;
    auto& data = write_queue_.front();

    ws_.async_write(
        net::buffer(data),
        beast::bind_front_handler(
            &WsRelaySession::on_write,
            shared_from_this()));
}

void WsRelaySession::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        LOG_WARN("WsRelaySession: Write error: {}", ec.message());
        writing_ = false;
        return;
    }

    write_queue_.erase(write_queue_.begin());
    do_write();
}

void WsRelaySession::handle_message(const std::vector<uint8_t>& data) {
    if (data.size() < NetworkConstants::HEADER_SIZE) {
        LOG_WARN("WsRelaySession: Message too short");
        return;
    }

    // Parse frame header
    wire::FrameHeader header;
    header.version = data[0];
    header.type = static_cast<wire::MessageType>(data[1]);
    header.flags = data[2];
    header.length = (static_cast<uint16_t>(data[3]) << 8) | data[4];

    // Verify version
    if (header.version != wire::PROTOCOL_VERSION) {
        LOG_WARN("WsRelaySession: Invalid protocol version: {}", header.version);
        send_error("invalid_version", "Unsupported protocol version");
        return;
    }

    std::span<const uint8_t> payload(data.data() + NetworkConstants::HEADER_SIZE,
                                      data.size() - NetworkConstants::HEADER_SIZE);

    switch (header.type) {
        case wire::MessageType::RELAY_AUTH: {
            // Parse JSON payload
            try {
                std::string json_str(payload.begin(), payload.end());
                auto json = boost::json::parse(json_str);
                handle_relay_auth(json.as_object());
            } catch (const std::exception& e) {
                LOG_ERROR("WsRelaySession: Failed to parse RELAY_AUTH: {}", e.what());
                send_error("parse_error", "Invalid JSON payload");
            }
            break;
        }

        case wire::MessageType::DATA:
            handle_data_frame(header, payload);
            break;

        case wire::MessageType::PING: {
            // Parse JSON payload for timestamp
            try {
                std::string json_str(payload.begin(), payload.end());
                auto json = boost::json::parse(json_str);
                handle_ping(json.as_object());
            } catch (...) {
                // Simple ping without payload
                send_pong(0);
            }
            break;
        }

        default:
            LOG_WARN("WsRelaySession: Unknown message type: {}",
                     static_cast<int>(header.type));
            break;
    }
}

void WsRelaySession::handle_relay_auth(const boost::json::object& payload) {
    std::string token;
    if (payload.contains("relay_token")) {
        token = payload.at("relay_token").as_string().c_str();
    } else if (payload.contains("token")) {
        token = payload.at("token").as_string().c_str();
    }

    if (token.empty()) {
        LOG_WARN("WsRelaySession: Missing relay token");
        send_auth_response(false, 0, "Missing relay token");
        relay_->stats().auth_failures++;
        return;
    }

    uint32_t node_id = 0;
    std::string virtual_ip;

    if (!relay_->session_manager()->validate_relay_token(token, node_id, virtual_ip)) {
        LOG_WARN("WsRelaySession: Invalid relay token");
        send_auth_response(false, 0, "Invalid relay token");
        relay_->stats().auth_failures++;
        return;
    }

    node_id_ = node_id;
    virtual_ip_ = virtual_ip;
    authenticated_ = true;

    // Register session
    relay_->session_manager()->add_session(node_id_, this);

    LOG_INFO("WsRelaySession: Node {} authenticated", node_id_);
    send_auth_response(true, node_id_);
}

void WsRelaySession::handle_data_frame(const wire::FrameHeader& header,
                                        std::span<const uint8_t> payload) {
    if (!authenticated_) {
        LOG_WARN("WsRelaySession: Data from unauthenticated session");
        return;
    }

    if (payload.size() < 8) {
        LOG_WARN("WsRelaySession: Data frame too short");
        return;
    }

    // Parse node IDs (big-endian)
    uint32_t src_node_id = (static_cast<uint32_t>(payload[0]) << 24) |
                           (static_cast<uint32_t>(payload[1]) << 16) |
                           (static_cast<uint32_t>(payload[2]) << 8) |
                           static_cast<uint32_t>(payload[3]);

    uint32_t dst_node_id = (static_cast<uint32_t>(payload[4]) << 24) |
                           (static_cast<uint32_t>(payload[5]) << 16) |
                           (static_cast<uint32_t>(payload[6]) << 8) |
                           static_cast<uint32_t>(payload[7]);

    // Verify sender
    if (src_node_id != node_id_) {
        LOG_WARN("WsRelaySession: Spoofed src_node_id {} from node {}",
                 src_node_id, node_id_);
        return;
    }

    // Extract actual data
    std::vector<uint8_t> data(payload.begin() + 8, payload.end());

    // Forward to destination
    if (!relay_->forward_data(dst_node_id, data, src_node_id)) {
        LOG_DEBUG("WsRelaySession: Failed to forward to node {} (offline?)",
                  dst_node_id);
    }

    if (data_callback_) {
        data_callback_(src_node_id, dst_node_id, data);
    }
}

void WsRelaySession::handle_ping(const boost::json::object& payload) {
    uint64_t timestamp = 0;
    if (payload.contains("timestamp")) {
        timestamp = payload.at("timestamp").as_int64();
    }
    send_pong(timestamp);
}

void WsRelaySession::send_auth_response(bool success, uint32_t node_id, const std::string& error) {
    wire::AuthResponsePayload payload;
    payload.success = success;
    payload.node_id = node_id;
    payload.error_message = error;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::RELAY_AUTH_RESP, std::move(binary));
    send(frame.serialize());
}

void WsRelaySession::send_pong(uint64_t timestamp) {
    wire::PongPayload payload;
    payload.timestamp = timestamp;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::PONG, std::move(binary));
    send(frame.serialize());
}

void WsRelaySession::send_error(const std::string& code, const std::string& message) {
    wire::ErrorPayload payload;
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
    send(frame.serialize());
}

} // namespace edgelink::controller

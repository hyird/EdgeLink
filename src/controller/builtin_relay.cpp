#include "builtin_relay.hpp"
#include "common/log.hpp"

#include <boost/asio/dispatch.hpp>

namespace edgelink::controller {

// ============================================================================
// BuiltinRelaySession Implementation
// ============================================================================

BuiltinRelaySession::BuiltinRelaySession(tcp::socket socket,
                                         BuiltinRelay* relay,
                                         const std::string& jwt_secret)
    : ws_(std::move(socket))
    , relay_(relay)
    , jwt_manager_(jwt_secret) {
}

void BuiltinRelaySession::run(boost::beast::http::request<boost::beast::http::string_body> req) {
    // Set WebSocket options
    ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
        res.set(boost::beast::http::field::server, "edgelink-builtin-relay/1.0");
    }));
    
    // Accept the WebSocket handshake with the original HTTP request
    ws_.async_accept(req, [self = shared_from_this()](beast::error_code ec) {
        self->on_accept(ec);
    });
}

void BuiltinRelaySession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("BuiltinRelay accept error: {}", ec.message());
        return;
    }
    
    LOG_DEBUG("BuiltinRelay: New connection accepted");
    do_read();
}

void BuiltinRelaySession::do_read() {
    ws_.async_read(buffer_, [self = shared_from_this()](beast::error_code ec, std::size_t bytes) {
        self->on_read(ec, bytes);
    });
}

void BuiltinRelaySession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        if (ec != websocket::error::closed && ec != net::error::operation_aborted) {
            LOG_ERROR("BuiltinRelay read error: {}", ec.message());
        }
        
        // Unregister session
        if (authenticated_ && node_id_ > 0) {
            relay_->unregister_session(node_id_);
        }
        return;
    }
    
    // Process the received frame
    const auto* data = static_cast<const uint8_t*>(buffer_.data().data());
    process_frame(data, bytes_transferred);
    
    // Clear buffer and continue reading
    buffer_.consume(bytes_transferred);
    do_read();
}

void BuiltinRelaySession::process_frame(const uint8_t* data, size_t size) {
    Frame frame;
    if (!frame.parse(std::span<const uint8_t>(data, size))) {
        LOG_WARN("BuiltinRelay: Invalid frame received");
        return;
    }
    
    switch (frame.type) {
        case MessageType::RELAY_AUTH:
            handle_auth(frame);
            break;
            
        case MessageType::DATA:
            handle_data(frame);
            break;
            
        case MessageType::PING:
            handle_ping(frame);
            break;
            
        default:
            LOG_WARN("BuiltinRelay: Unknown frame type: {}", static_cast<int>(frame.type));
            break;
    }
}

void BuiltinRelaySession::handle_auth(const Frame& frame) {
    // Parse auth request - expecting relay_token in payload
    if (frame.payload.empty()) {
        LOG_WARN("BuiltinRelay: Empty auth request");
        return;
    }
    
    std::string token(frame.payload.begin(), frame.payload.end());
    
    // Verify JWT token
    auto claims = jwt_manager_.verify_relay_token(token);
    if (!claims) {
        LOG_WARN("BuiltinRelay: Invalid token");
        
        // Send error response
        ErrorPayload error;
        error.code = static_cast<int>(ErrorCode::INVALID_TOKEN);
        error.message = "Invalid token";
        
        auto response = create_json_frame(MessageType::ERROR_MSG, error.to_json());
        auto data = response.serialize();
        send(data);
        return;
    }
    
    // Check token type
    if (claims->type != TokenType::RELAY) {
        LOG_WARN("BuiltinRelay: Wrong token type");
        return;
    }
    
    // Extract node_id and network_id
    node_id_ = claims->node_id;
    network_id_ = claims->network_id;
    authenticated_ = true;
    
    // Register session
    relay_->register_session(node_id_, shared_from_this());
    
    LOG_INFO("BuiltinRelay: Node {} authenticated (network {})", node_id_, network_id_);
    
    // Send success response
    boost::json::object success_obj;
    success_obj["success"] = true;
    
    auto response = create_json_frame(MessageType::RELAY_AUTH_RESP, success_obj);
    auto data = response.serialize();
    send(data);
}

void BuiltinRelaySession::handle_data(const Frame& frame) {
    if (!authenticated_) {
        LOG_WARN("BuiltinRelay: Data from unauthenticated session");
        return;
    }
    
    // Parse DATA payload to get destination
    if (frame.payload.size() < 8) {
        LOG_WARN("BuiltinRelay: DATA payload too small");
        return;
    }
    
    // Extract src_node_id (4 bytes) and dst_node_id (4 bytes)
    uint32_t src_node_id = 0, dst_node_id = 0;
    src_node_id |= static_cast<uint32_t>(frame.payload[0]) << 24;
    src_node_id |= static_cast<uint32_t>(frame.payload[1]) << 16;
    src_node_id |= static_cast<uint32_t>(frame.payload[2]) << 8;
    src_node_id |= static_cast<uint32_t>(frame.payload[3]);
    
    dst_node_id |= static_cast<uint32_t>(frame.payload[4]) << 24;
    dst_node_id |= static_cast<uint32_t>(frame.payload[5]) << 16;
    dst_node_id |= static_cast<uint32_t>(frame.payload[6]) << 8;
    dst_node_id |= static_cast<uint32_t>(frame.payload[7]);
    
    // Verify sender
    if (src_node_id != node_id_) {
        LOG_WARN("BuiltinRelay: Spoofed src_node_id {} from node {}", src_node_id, node_id_);
        return;
    }
    
    // Forward to destination
    auto serialized = frame.serialize();
    if (!relay_->forward_data(dst_node_id, serialized)) {
        LOG_DEBUG("BuiltinRelay: Failed to forward to node {} (offline?)", dst_node_id);
    }
}

void BuiltinRelaySession::handle_ping(const Frame& frame) {
    // Respond with PONG
    Frame pong = Frame::create(MessageType::PONG, frame.payload);
    auto data = pong.serialize();
    send(data);
}

void BuiltinRelaySession::send(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    
    write_queue_.push(data);
    
    if (!writing_) {
        writing_ = true;
        auto& front = write_queue_.front();
        ws_.async_write(net::buffer(front), [self = shared_from_this()](beast::error_code ec, std::size_t bytes) {
            self->on_write(ec, bytes);
        });
    }
}

void BuiltinRelaySession::on_write(beast::error_code ec, std::size_t /*bytes_transferred*/) {
    std::lock_guard<std::mutex> lock(write_mutex_);
    
    if (ec) {
        LOG_ERROR("BuiltinRelay write error: {}", ec.message());
        writing_ = false;
        return;
    }
    
    write_queue_.pop();
    
    if (!write_queue_.empty()) {
        auto& front = write_queue_.front();
        ws_.async_write(net::buffer(front), [self = shared_from_this()](beast::error_code ec, std::size_t bytes) {
            self->on_write(ec, bytes);
        });
    } else {
        writing_ = false;
    }
}

void BuiltinRelaySession::close() {
    beast::error_code ec;
    ws_.close(websocket::close_code::normal, ec);
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
    , jwt_secret_(jwt_secret) {
    
    if (config_.enabled) {
        LOG_INFO("BuiltinRelay initialized (data: {}, mesh: {})", 
                 paths::WS_DATA, paths::WS_MESH);
    }
}

BuiltinRelay::~BuiltinRelay() = default;

void BuiltinRelay::handle_upgrade(tcp::socket socket, boost::beast::http::request<boost::beast::http::string_body> req) {
    if (!config_.enabled) {
        LOG_WARN("BuiltinRelay: Received connection but relay is disabled");
        return;
    }
    
    stats_.connections_total++;
    stats_.connections_active++;
    
    auto session = std::make_shared<BuiltinRelaySession>(
        std::move(socket), this, jwt_secret_);
    session->run(std::move(req));
}

void BuiltinRelay::register_session(uint32_t node_id, std::shared_ptr<BuiltinRelaySession> session) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_[node_id] = session;
    LOG_DEBUG("BuiltinRelay: Registered session for node {}", node_id);
}

void BuiltinRelay::unregister_session(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.erase(node_id);
    stats_.connections_active--;
    LOG_DEBUG("BuiltinRelay: Unregistered session for node {}", node_id);
}

bool BuiltinRelay::forward_data(uint32_t dst_node_id, const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(dst_node_id);
    if (it == sessions_.end()) {
        return false;
    }
    
    auto session = it->second.lock();
    if (!session) {
        sessions_.erase(it);
        return false;
    }
    
    session->send(data);
    stats_.packets_forwarded++;
    stats_.bytes_forwarded += data.size();
    
    return true;
}

} // namespace edgelink::controller

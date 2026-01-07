#include "relay_session.hpp"
#include "common/log.hpp"

#include <boost/asio/strand.hpp>

namespace edgelink {

// ============================================================================
// RelaySession Implementation
// ============================================================================

RelaySession::RelaySession(tcp::socket socket, RelaySessionManager& manager)
    : manager_(manager)
    , use_ssl_(false)
    , ws_plain_(std::make_unique<websocket::stream<tcp::socket>>(std::move(socket)))
{
    // Get observed IP/port from socket
    try {
        auto endpoint = ws_plain_->next_layer().remote_endpoint();
        observed_ip_ = endpoint.address().to_string();
        observed_port_ = endpoint.port();
    } catch (...) {
        LOG_WARN("Failed to get remote endpoint");
    }
    
    LOG_DEBUG("RelaySession created (plain) from {}:{}", observed_ip_, observed_port_);
}

RelaySession::RelaySession(tcp::socket socket, ssl::context& ssl_ctx, RelaySessionManager& manager)
    : manager_(manager)
    , use_ssl_(true)
    , ws_ssl_(std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(std::move(socket), ssl_ctx))
{
    // Get observed IP/port from socket
    try {
        auto endpoint = ws_ssl_->next_layer().next_layer().remote_endpoint();
        observed_ip_ = endpoint.address().to_string();
        observed_port_ = endpoint.port();
    } catch (...) {
        LOG_WARN("Failed to get remote endpoint");
    }
    
    LOG_DEBUG("RelaySession created (SSL) from {}:{}", observed_ip_, observed_port_);
}

RelaySession::RelaySession(RelaySessionManager& manager)
    : manager_(manager)
    , use_ssl_(false)
{
    // This constructor is for wrapper classes that manage their own WebSocket stream
    LOG_DEBUG("RelaySession created (wrapper mode)");
}

RelaySession::~RelaySession() {
    LOG_DEBUG("RelaySession destroyed for node {}", node_id_);
}

void RelaySession::start() {
    // Set WebSocket options
    if (use_ssl_) {
        ws_ssl_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_ssl_->set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(beast::http::field::server, "edgelink-relay/1.0");
        }));
        
        // First do SSL handshake, then WebSocket accept
        ws_ssl_->next_layer().async_handshake(
            ssl::stream_base::server,
            [self = shared_from_this()](beast::error_code ec) {
                if (ec) {
                    LOG_WARN("SSL handshake failed: {}", ec.message());
                    return;
                }
                self->do_accept();
            });
    } else {
        ws_plain_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_plain_->set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(beast::http::field::server, "edgelink-relay/1.0");
        }));
        do_accept();
    }
}

void RelaySession::do_accept() {
    if (use_ssl_) {
        ws_ssl_->async_accept(
            beast::bind_front_handler(&RelaySession::on_accept, shared_from_this()));
    } else {
        ws_plain_->async_accept(
            beast::bind_front_handler(&RelaySession::on_accept, shared_from_this()));
    }
}

void RelaySession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_WARN("WebSocket accept failed from {}:{}: {}", observed_ip_, observed_port_, ec.message());
        return;
    }
    
    LOG_INFO("WebSocket connection accepted from {}:{}", observed_ip_, observed_port_);
    
    // Start reading
    do_read();
}

void RelaySession::do_read() {
    if (use_ssl_) {
        ws_ssl_->async_read(
            read_buffer_,
            beast::bind_front_handler(&RelaySession::on_read, shared_from_this()));
    } else {
        ws_plain_->async_read(
            read_buffer_,
            beast::bind_front_handler(&RelaySession::on_read, shared_from_this()));
    }
}

void RelaySession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        if (ec != websocket::error::closed && ec != asio::error::operation_aborted) {
            LOG_DEBUG("WebSocket read error for node {}: {}", node_id_, ec.message());
        }
        
        // Notify close
        if (close_callback_) {
            close_callback_(shared_from_this());
        }
        return;
    }
    
    // Parse frame
    auto data = static_cast<const uint8_t*>(read_buffer_.data().data());
    std::span<const uint8_t> span(data, bytes_transferred);
    
    auto frame_result = Frame::deserialize(span);
    if (!frame_result) {
        LOG_WARN("Invalid frame from {}:{}", observed_ip_, observed_port_);
        read_buffer_.consume(bytes_transferred);
        do_read();
        return;
    }
    
    // Process frame
    process_frame(*frame_result);
    
    // Clear buffer and continue reading
    read_buffer_.consume(bytes_transferred);
    do_read();
}

void RelaySession::process_frame(const Frame& frame) {
    // Forward to callback
    if (message_callback_) {
        message_callback_(shared_from_this(), frame);
    }
}

void RelaySession::send(const Frame& frame) {
    send(frame.serialize());
}

void RelaySession::send(std::vector<uint8_t> data) {
    // Add to write queue
    bool need_write = write_queue_.empty();
    write_queue_.push(std::move(data));
    
    if (need_write && !writing_) {
        do_write();
    }
}

void RelaySession::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }
    
    writing_ = true;
    auto& data = write_queue_.front();
    
    if (use_ssl_) {
        ws_ssl_->binary(true);
        ws_ssl_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&RelaySession::on_write, shared_from_this()));
    } else {
        ws_plain_->binary(true);
        ws_plain_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&RelaySession::on_write, shared_from_this()));
    }
}

void RelaySession::on_write(beast::error_code ec, std::size_t /*bytes_transferred*/) {
    if (ec) {
        LOG_DEBUG("WebSocket write error for node {}: {}", node_id_, ec.message());
        writing_ = false;
        return;
    }
    
    // Remove sent message from queue
    write_queue_.pop();
    
    // Send next message if any
    do_write();
}

void RelaySession::close() {
    if (use_ssl_) {
        ws_ssl_->async_close(
            websocket::close_code::normal,
            [self = shared_from_this()](beast::error_code /*ec*/) {
                LOG_DEBUG("Session closed for node {}", self->node_id_);
            });
    } else {
        ws_plain_->async_close(
            websocket::close_code::normal,
            [self = shared_from_this()](beast::error_code /*ec*/) {
                LOG_DEBUG("Session closed for node {}", self->node_id_);
            });
    }
}

void RelaySession::set_authenticated(uint32_t node_id, const std::string& virtual_ip) {
    node_id_ = node_id;
    virtual_ip_ = virtual_ip;
    authenticated_ = true;
    LOG_INFO("Node {} authenticated with virtual IP {}", node_id_, virtual_ip_);
}

// ============================================================================
// RelaySessionManager Implementation
// ============================================================================

RelaySessionManager::RelaySessionManager(JWTManager& jwt_manager)
    : jwt_manager_(jwt_manager)
{
}

RelaySessionManager::~RelaySessionManager() = default;

void RelaySessionManager::add_session(std::shared_ptr<RelaySession> session) {
    std::unique_lock lock(sessions_mutex_);
    all_sessions_.insert(session);
    
    if (session->is_authenticated() && session->node_id() != 0) {
        sessions_by_node_id_[session->node_id()] = session;
    }
    
    LOG_DEBUG("Session added, total sessions: {}", all_sessions_.size());
}

void RelaySessionManager::remove_session(std::shared_ptr<RelaySession> session) {
    std::unique_lock lock(sessions_mutex_);
    
    all_sessions_.erase(session);
    
    if (session->node_id() != 0) {
        sessions_by_node_id_.erase(session->node_id());
    }
    
    LOG_DEBUG("Session removed, total sessions: {}", all_sessions_.size());
}

std::shared_ptr<RelaySession> RelaySessionManager::get_session_by_node_id(uint32_t node_id) {
    std::shared_lock lock(sessions_mutex_);
    
    auto it = sessions_by_node_id_.find(node_id);
    if (it != sessions_by_node_id_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

std::vector<std::shared_ptr<RelaySession>> RelaySessionManager::get_all_sessions() {
    std::shared_lock lock(sessions_mutex_);
    return std::vector<std::shared_ptr<RelaySession>>(all_sessions_.begin(), all_sessions_.end());
}

size_t RelaySessionManager::session_count() const {
    std::shared_lock lock(sessions_mutex_);
    return all_sessions_.size();
}

bool RelaySessionManager::validate_relay_token(const std::string& token, uint32_t& node_id, 
                                                std::string& virtual_ip, std::vector<uint32_t>& allowed_relays) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        
        // Check if blacklisted
        {
            std::shared_lock lock(blacklist_mutex_);
            auto jti = decoded.get_id();
            if (token_blacklist_.count(jti) > 0) {
                LOG_WARN("Token {} is blacklisted", jti);
                return false;
            }
        }
        
        // Verify with JWT manager
        auto verifier = jwt::verify<json_traits>()
            .allow_algorithm(jwt::algorithm::hs256{jwt_manager_.secret()})
            .with_issuer("edgelink");
        
        verifier.verify(decoded);
        
        // Check token type
        auto type = decoded.get_payload_claim("type").as_string();
        if (type != "relay") {
            LOG_WARN("Invalid token type: {}", type);
            return false;
        }
        
        // Check expiration
        auto exp = decoded.get_expires_at();
        if (std::chrono::system_clock::now() > exp) {
            LOG_WARN("Relay token expired");
            return false;
        }
        
        // Extract claims
        node_id = static_cast<uint32_t>(decoded.get_payload_claim("node_id").as_integer());
        virtual_ip = decoded.get_payload_claim("virtual_ip").as_string();
        
        // Extract allowed relays
        if (decoded.has_payload_claim("allowed_relays")) {
            auto relays_claim = decoded.get_payload_claim("allowed_relays");
            auto relays_json = relays_claim.to_json();
            if (relays_json.is_array()) {
                for (const auto& r : relays_json) {
                    if (r.is_number_integer()) {
                        allowed_relays.push_back(static_cast<uint32_t>(r.get<int64_t>()));
                    }
                }
            }
        }
        
        return true;
    } catch (const std::exception& e) {
        LOG_WARN("Token validation failed: {}", e.what());
        return false;
    }
}

void RelaySessionManager::add_to_blacklist(const std::string& jti, int64_t expires_at) {
    std::unique_lock lock(blacklist_mutex_);
    token_blacklist_[jti] = expires_at;
    LOG_DEBUG("Added token {} to blacklist", jti);
}

void RelaySessionManager::set_blacklist(const std::vector<std::pair<std::string, int64_t>>& entries) {
    std::unique_lock lock(blacklist_mutex_);
    token_blacklist_.clear();
    for (const auto& [jti, expires_at] : entries) {
        token_blacklist_[jti] = expires_at;
    }
    LOG_INFO("Blacklist synchronized with {} entries", entries.size());
}

void RelaySessionManager::update_node_locations(const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations) {
    std::unique_lock lock(locations_mutex_);
    node_locations_.clear();
    for (const auto& [node_id, relay_ids] : locations) {
        node_locations_[node_id] = relay_ids;
    }
    LOG_DEBUG("Node locations updated with {} entries", locations.size());
}

std::vector<uint32_t> RelaySessionManager::get_node_relay_locations(uint32_t node_id) const {
    std::shared_lock lock(locations_mutex_);
    auto it = node_locations_.find(node_id);
    if (it != node_locations_.end()) {
        return it->second;
    }
    return {};
}

} // namespace edgelink

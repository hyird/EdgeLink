#include "ws_relay_server.hpp"
#include "controller_client.hpp"
#include "common/log.hpp"

#include <chrono>

namespace edgelink {

// ============================================================================
// WsRelaySessionManager Implementation
// ============================================================================

WsRelaySessionManager::WsRelaySessionManager(const std::string& jwt_secret)
    : jwt_secret_(jwt_secret)
{}

void WsRelaySessionManager::add_client_session(uint32_t node_id, void* session) {
    std::unique_lock lock(client_mutex_);
    client_sessions_[node_id] = session;
    LOG_DEBUG("WsRelaySessionManager: Added client session for node {}", node_id);
}

void WsRelaySessionManager::remove_client_session(uint32_t node_id) {
    std::unique_lock lock(client_mutex_);
    client_sessions_.erase(node_id);
    LOG_DEBUG("WsRelaySessionManager: Removed client session for node {}", node_id);
}

void* WsRelaySessionManager::get_client_session(uint32_t node_id) {
    std::shared_lock lock(client_mutex_);
    auto it = client_sessions_.find(node_id);
    return (it != client_sessions_.end()) ? it->second : nullptr;
}

void WsRelaySessionManager::add_mesh_session(uint32_t server_id, void* session) {
    std::unique_lock lock(mesh_mutex_);
    mesh_sessions_[server_id] = session;
    LOG_DEBUG("WsRelaySessionManager: Added mesh session for server {}", server_id);
}

void WsRelaySessionManager::remove_mesh_session(uint32_t server_id) {
    std::unique_lock lock(mesh_mutex_);
    mesh_sessions_.erase(server_id);
    LOG_DEBUG("WsRelaySessionManager: Removed mesh session for server {}", server_id);
}

void* WsRelaySessionManager::get_mesh_session(uint32_t server_id) {
    std::shared_lock lock(mesh_mutex_);
    auto it = mesh_sessions_.find(server_id);
    return (it != mesh_sessions_.end()) ? it->second : nullptr;
}

bool WsRelaySessionManager::validate_relay_token(const std::string& token, uint32_t& node_id,
                                                  std::string& virtual_ip) {
    auto result = jwt::validate_token(token, jwt_secret_);
    if (!result) {
        LOG_DEBUG("WsRelaySessionManager: Token validation failed");
        return false;
    }

    // Check if token is in blacklist
    {
        std::shared_lock lock(blacklist_mutex_);
        auto it = token_blacklist_.find(result->jti);
        if (it != token_blacklist_.end()) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (now < it->second) {
                LOG_DEBUG("WsRelaySessionManager: Token {} is blacklisted", result->jti);
                return false;
            }
        }
    }

    // Check token type
    if (result->type != "relay") {
        LOG_DEBUG("WsRelaySessionManager: Invalid token type: {}", result->type);
        return false;
    }

    node_id = result->node_id;
    virtual_ip = result->virtual_ip;
    return true;
}

void WsRelaySessionManager::update_node_locations(
    const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations) {
    std::unique_lock lock(locations_mutex_);
    for (const auto& [node_id, relay_ids] : locations) {
        node_locations_[node_id] = relay_ids;
    }
    LOG_DEBUG("WsRelaySessionManager: Updated {} node locations", locations.size());
}

std::vector<uint32_t> WsRelaySessionManager::get_node_relay_locations(uint32_t node_id) const {
    std::shared_lock lock(locations_mutex_);
    auto it = node_locations_.find(node_id);
    if (it != node_locations_.end()) {
        return it->second;
    }
    return {};
}

void WsRelaySessionManager::add_to_blacklist(const std::string& jti, int64_t expires_at) {
    std::unique_lock lock(blacklist_mutex_);
    token_blacklist_[jti] = expires_at;
    LOG_DEBUG("WsRelaySessionManager: Added {} to token blacklist", jti);
}

size_t WsRelaySessionManager::client_count() const {
    std::shared_lock lock(client_mutex_);
    return client_sessions_.size();
}

size_t WsRelaySessionManager::mesh_count() const {
    std::shared_lock lock(mesh_mutex_);
    return mesh_sessions_.size();
}

// ============================================================================
// WsRelayClientSession - Handles one client's relay WebSocket connection
// ============================================================================

class WsRelayClientSession : public std::enable_shared_from_this<WsRelayClientSession> {
public:
    WsRelayClientSession(tcp::socket&& socket, WsRelayServer* server, ssl::context& ssl_ctx, bool use_ssl);

    void run();
    void send(const std::vector<uint8_t>& data);
    void close();

    uint32_t node_id() const { return node_id_; }
    bool is_authenticated() const { return authenticated_; }

private:
    void do_ssl_handshake();
    void do_accept();
    void on_accept(beast::error_code ec);
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);

    void handle_frame(const wire::Frame& frame);
    void handle_relay_auth(const boost::json::object& payload);
    void handle_data(const wire::Frame& frame);
    void handle_ping(const boost::json::object& payload);

    void send_auth_response(bool success, uint32_t node_id, const std::string& error = "");
    void send_pong(uint64_t timestamp);
    void send_error(const std::string& code, const std::string& message);

    WsRelayServer* server_;
    bool use_ssl_;

    // Non-SSL WebSocket stream
    std::unique_ptr<websocket::stream<tcp::socket>> ws_;
    // SSL WebSocket stream
    std::unique_ptr<websocket::stream<ssl::stream<tcp::socket>>> wss_;

    // Original socket (moved to one of the streams above)
    tcp::socket socket_;
    ssl::context& ssl_ctx_;

    beast::flat_buffer buffer_;
    std::vector<std::vector<uint8_t>> write_queue_;
    bool writing_{false};

    bool authenticated_{false};
    uint32_t node_id_{0};
    std::string virtual_ip_;
};

WsRelayClientSession::WsRelayClientSession(tcp::socket&& socket, WsRelayServer* server,
                                            ssl::context& ssl_ctx, bool use_ssl)
    : server_(server)
    , use_ssl_(use_ssl)
    , socket_(std::move(socket))
    , ssl_ctx_(ssl_ctx)
{}

void WsRelayClientSession::run() {
    if (use_ssl_) {
        do_ssl_handshake();
    } else {
        ws_ = std::make_unique<websocket::stream<tcp::socket>>(std::move(socket_));
        do_accept();
    }
}

void WsRelayClientSession::do_ssl_handshake() {
    auto ssl_stream = std::make_unique<ssl::stream<tcp::socket>>(std::move(socket_), ssl_ctx_);

    ssl_stream->async_handshake(
        ssl::stream_base::server,
        [self = shared_from_this(), ssl_stream = std::move(ssl_stream)](beast::error_code ec) mutable {
            if (ec) {
                LOG_WARN("WsRelayClientSession: SSL handshake failed: {}", ec.message());
                return;
            }
            self->wss_ = std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(std::move(*ssl_stream));
            self->do_accept();
        });
}

void WsRelayClientSession::do_accept() {
    auto accept_handler = [self = shared_from_this()](beast::error_code ec) {
        self->on_accept(ec);
    };

    if (use_ssl_ && wss_) {
        wss_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        wss_->set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server, "EdgeLink-Relay/1.0");
            }));
        wss_->async_accept(accept_handler);
    } else if (ws_) {
        ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_->set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server, "EdgeLink-Relay/1.0");
            }));
        ws_->async_accept(accept_handler);
    }
}

void WsRelayClientSession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_WARN("WsRelayClientSession: Accept failed: {}", ec.message());
        return;
    }

    LOG_DEBUG("WsRelayClientSession: Connection accepted");
    server_->stats().connections_total++;
    server_->stats().connections_active++;

    // Set binary mode for relay traffic
    if (use_ssl_ && wss_) {
        wss_->binary(true);
    } else if (ws_) {
        ws_->binary(true);
    }

    do_read();
}

void WsRelayClientSession::do_read() {
    buffer_.consume(buffer_.size());

    auto read_handler = [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
        self->on_read(ec, bytes_transferred);
    };

    if (use_ssl_ && wss_) {
        wss_->async_read(buffer_, read_handler);
    } else if (ws_) {
        ws_->async_read(buffer_, read_handler);
    }
}

void WsRelayClientSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec == websocket::error::closed) {
        LOG_DEBUG("WsRelayClientSession: Connection closed (node {})", node_id_);
        goto cleanup;
    }

    if (ec) {
        LOG_WARN("WsRelayClientSession: Read error: {}", ec.message());
        goto cleanup;
    }

    {
        auto data = static_cast<const uint8_t*>(buffer_.data().data());
        std::span<const uint8_t> span(data, buffer_.size());

        auto frame_result = wire::Frame::deserialize(span);
        if (frame_result) {
            handle_frame(*frame_result);
        } else {
            LOG_WARN("WsRelayClientSession: Invalid frame received");
        }
    }

    do_read();
    return;

cleanup:
    server_->stats().connections_active--;
    if (authenticated_ && node_id_ > 0) {
        server_->session_manager()->remove_client_session(node_id_);
    }
}

void WsRelayClientSession::handle_frame(const wire::Frame& frame) {
    switch (frame.header.type) {
        case wire::MessageType::RELAY_AUTH: {
            auto json_result = wire::parse_json_payload(frame);
            if (json_result) {
                handle_relay_auth(json_result->as_object());
            }
            break;
        }

        case wire::MessageType::DATA:
            if (authenticated_) {
                handle_data(frame);
            } else {
                send_error("AUTH_REQUIRED", "Authentication required");
            }
            break;

        case wire::MessageType::PING: {
            auto json_result = wire::parse_json_payload(frame);
            if (json_result) {
                handle_ping(json_result->as_object());
            }
            break;
        }

        default:
            LOG_DEBUG("WsRelayClientSession: Unhandled message type: {}",
                      static_cast<int>(frame.header.type));
            break;
    }
}

void WsRelayClientSession::handle_relay_auth(const boost::json::object& payload) {
    if (authenticated_) {
        send_error("ALREADY_AUTH", "Already authenticated");
        return;
    }

    if (!payload.contains("relay_token")) {
        send_auth_response(false, 0, "Missing relay_token");
        server_->stats().auth_failures++;
        return;
    }

    std::string token = payload.at("relay_token").as_string().c_str();

    uint32_t node_id = 0;
    std::string virtual_ip;

    if (!server_->session_manager()->validate_relay_token(token, node_id, virtual_ip)) {
        send_auth_response(false, 0, "Invalid token");
        server_->stats().auth_failures++;
        return;
    }

    authenticated_ = true;
    node_id_ = node_id;
    virtual_ip_ = virtual_ip;

    // Register session
    server_->session_manager()->add_client_session(node_id_, this);

    send_auth_response(true, node_id_);
    LOG_INFO("WsRelayClientSession: Node {} authenticated ({})", node_id_, virtual_ip_);
}

void WsRelayClientSession::handle_data(const wire::Frame& frame) {
    // Parse DATA payload to get destination
    auto data_result = wire::DataPayload::deserialize(frame.payload);
    if (!data_result) {
        LOG_WARN("WsRelayClientSession: Invalid DATA payload from node {}", node_id_);
        return;
    }

    uint32_t dst_node = data_result->dst_node_id;

    // Forward to destination
    server_->forward_data(node_id_, dst_node, frame.serialize());
}

void WsRelayClientSession::handle_ping(const boost::json::object& payload) {
    uint64_t timestamp = 0;
    if (payload.contains("timestamp")) {
        timestamp = static_cast<uint64_t>(payload.at("timestamp").as_int64());
    }
    send_pong(timestamp);
}

void WsRelayClientSession::send(const std::vector<uint8_t>& data) {
    auto exec = use_ssl_ && wss_
        ? wss_->get_executor()
        : ws_->get_executor();

    net::post(exec,
        [self = shared_from_this(), data]() {
            self->write_queue_.push_back(data);
            if (!self->writing_) {
                self->do_write();
            }
        });
}

void WsRelayClientSession::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }

    writing_ = true;
    auto& data = write_queue_.front();

    auto write_handler = [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
        self->on_write(ec, bytes_transferred);
    };

    if (use_ssl_ && wss_) {
        wss_->async_write(net::buffer(data), write_handler);
    } else if (ws_) {
        ws_->async_write(net::buffer(data), write_handler);
    }
}

void WsRelayClientSession::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        LOG_WARN("WsRelayClientSession: Write error: {}", ec.message());
        writing_ = false;
        return;
    }

    write_queue_.erase(write_queue_.begin());
    do_write();
}

void WsRelayClientSession::send_auth_response(bool success, uint32_t node_id, const std::string& error) {
    boost::json::object payload;
    payload["success"] = success;
    if (success) {
        payload["node_id"] = node_id;
    } else {
        payload["error_message"] = error;
    }

    auto frame = wire::create_json_frame(wire::MessageType::AUTH_RESPONSE, payload);
    send(frame.serialize());
}

void WsRelayClientSession::send_pong(uint64_t timestamp) {
    boost::json::object payload;
    payload["timestamp"] = static_cast<int64_t>(timestamp);

    auto frame = wire::create_json_frame(wire::MessageType::PONG, payload);
    send(frame.serialize());
}

void WsRelayClientSession::send_error(const std::string& code, const std::string& message) {
    boost::json::object payload;
    payload["code"] = code;
    payload["message"] = message;

    auto frame = wire::create_json_frame(wire::MessageType::ERROR_MSG, payload);
    send(frame.serialize());
}

void WsRelayClientSession::close() {
    beast::error_code ec;
    if (use_ssl_ && wss_) {
        wss_->close(websocket::close_code::normal, ec);
    } else if (ws_) {
        ws_->close(websocket::close_code::normal, ec);
    }
}

// ============================================================================
// WsRelayServer Implementation
// ============================================================================

WsRelayServer::WsRelayServer(net::io_context& ioc, const ServerConfig& config)
    : ioc_(ioc)
    , config_(config)
    , session_manager_(config.controller.jwt_secret.empty() ? "default-secret" : config.controller.jwt_secret)
{}

WsRelayServer::~WsRelayServer() {
    stop();
}

void WsRelayServer::start() {
    if (running_.exchange(true)) {
        return;  // Already running
    }

    try {
        // Setup SSL if enabled
        if (config_.relay.tls.enabled) {
            if (!config_.relay.tls.cert_file.empty()) {
                ssl_ctx_.use_certificate_chain_file(config_.relay.tls.cert_file);
            }
            if (!config_.relay.tls.key_file.empty()) {
                ssl_ctx_.use_private_key_file(config_.relay.tls.key_file, ssl::context::pem);
            }
            LOG_INFO("WsRelayServer: TLS enabled");
        }

        // Create acceptor
        auto address = net::ip::make_address(config_.relay.listen_address);
        tcp::endpoint endpoint{address, config_.relay.listen_port};

        acceptor_ = std::make_unique<tcp::acceptor>(ioc_);
        acceptor_->open(endpoint.protocol());
        acceptor_->set_option(net::socket_base::reuse_address(true));
        acceptor_->bind(endpoint);
        acceptor_->listen(net::socket_base::max_listen_connections);

        do_accept();

        LOG_INFO("WsRelayServer: Listening on {}:{}", config_.relay.listen_address, config_.relay.listen_port);
    } catch (const std::exception& e) {
        LOG_ERROR("WsRelayServer: Failed to start: {}", e.what());
        running_ = false;
        throw;
    }
}

void WsRelayServer::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (acceptor_ && acceptor_->is_open()) {
        beast::error_code ec;
        acceptor_->close(ec);
    }

    LOG_INFO("WsRelayServer: Stopped");
}

void WsRelayServer::set_controller_client(std::shared_ptr<ControllerClient> client) {
    controller_client_ = client;
}

void WsRelayServer::do_accept() {
    if (!running_) return;

    acceptor_->async_accept(
        net::make_strand(ioc_),
        [this](beast::error_code ec, tcp::socket socket) {
            if (ec) {
                if (ec != net::error::operation_aborted) {
                    LOG_WARN("WsRelayServer: Accept error: {}", ec.message());
                }
            } else {
                LOG_DEBUG("WsRelayServer: New connection from {}",
                          socket.remote_endpoint().address().to_string());

                // Create client session
                std::make_shared<WsRelayClientSession>(
                    std::move(socket), this, ssl_ctx_, config_.relay.tls.enabled)->run();
            }

            if (running_) {
                do_accept();
            }
        });
}

bool WsRelayServer::forward_data(uint32_t src_node, uint32_t dst_node,
                                  const std::vector<uint8_t>& data) {
    // First check if destination is connected locally
    void* session_ptr = session_manager_.get_client_session(dst_node);

    if (session_ptr) {
        auto* session = static_cast<WsRelayClientSession*>(session_ptr);
        session->send(data);
        stats_.bytes_forwarded += data.size();
        stats_.packets_forwarded++;
        return true;
    }

    // Check if we know which relay the destination is connected to
    auto relay_ids = session_manager_.get_node_relay_locations(dst_node);
    if (!relay_ids.empty()) {
        // Forward via mesh to another relay
        // TODO: Implement mesh forwarding
        LOG_DEBUG("WsRelayServer: Node {} is on relay {}, mesh forwarding not yet implemented",
                  dst_node, relay_ids[0]);
    }

    LOG_DEBUG("WsRelayServer: Cannot forward to node {} - not found", dst_node);
    return false;
}

} // namespace edgelink

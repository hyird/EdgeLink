#include "controller/api/ws_server.hpp"
#include "controller/builtin_relay.hpp"
#include "common/log.hpp"
#include "common/jwt.hpp"

#include <fstream>

namespace edgelink::controller {

// ============================================================================
// WsSessionManager Implementation
// ============================================================================

void WsSessionManager::add_control_session(uint32_t node_id, uint32_t network_id, void* session) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    control_sessions_[node_id] = {session, network_id};
    LOG_DEBUG("WsSessionManager: Added control session for node {} (network {})",
              node_id, network_id);
}

void WsSessionManager::remove_control_session(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    control_sessions_.erase(node_id);
    LOG_DEBUG("WsSessionManager: Removed control session for node {}", node_id);
}

void* WsSessionManager::get_control_session(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    auto it = control_sessions_.find(node_id);
    return (it != control_sessions_.end()) ? it->second.session : nullptr;
}

void WsSessionManager::add_server_session(uint32_t server_id, void* session) {
    std::lock_guard<std::mutex> lock(server_mutex_);
    server_sessions_[server_id] = {session};
    LOG_DEBUG("WsSessionManager: Added server session for server {}", server_id);
}

void WsSessionManager::remove_server_session(uint32_t server_id) {
    std::lock_guard<std::mutex> lock(server_mutex_);
    server_sessions_.erase(server_id);
    LOG_DEBUG("WsSessionManager: Removed server session for server {}", server_id);
}

void* WsSessionManager::get_server_session(uint32_t server_id) {
    std::lock_guard<std::mutex> lock(server_mutex_);
    auto it = server_sessions_.find(server_id);
    return (it != server_sessions_.end()) ? it->second.session : nullptr;
}

void WsSessionManager::broadcast_to_network(uint32_t network_id, const std::string& text) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    for (const auto& [node_id, session_info] : control_sessions_) {
        if (session_info.network_id == network_id) {
            auto* session = static_cast<WsControlSession*>(session_info.session);
            if (session) {
                session->send_text(text);
            }
        }
    }
}

size_t WsSessionManager::node_count() const {
    std::lock_guard<std::mutex> lock(control_mutex_);
    return control_sessions_.size();
}

size_t WsSessionManager::server_count() const {
    std::lock_guard<std::mutex> lock(server_mutex_);
    return server_sessions_.size();
}

std::vector<uint32_t> WsSessionManager::get_connected_nodes() const {
    std::lock_guard<std::mutex> lock(control_mutex_);
    std::vector<uint32_t> nodes;
    nodes.reserve(control_sessions_.size());
    for (const auto& [node_id, session_info] : control_sessions_) {
        nodes.push_back(node_id);
    }
    return nodes;
}

// ============================================================================
// WsServer Implementation
// ============================================================================

WsServer::WsServer(net::io_context& ioc,
                   const ControllerConfig& config,
                   std::shared_ptr<Database> db)
    : ioc_(ioc)
    , config_(config)
    , db_(db)
    , path_service_(std::make_shared<PathService>(db))
{}

WsServer::~WsServer() {
    stop();
}

void WsServer::start() {
    if (running_) return;

    try {
        // Setup SSL if enabled
        if (config_.http.enable_tls && config_.tls.is_valid()) {
            ssl_ctx_.use_certificate_chain_file(config_.tls.cert_path);
            ssl_ctx_.use_private_key_file(config_.tls.key_path, ssl::context::pem);
            LOG_INFO("WsServer: TLS enabled");
        }

        // Create acceptor
        auto address = net::ip::make_address(config_.http.listen_address);
        auto endpoint = tcp::endpoint{address, static_cast<uint16_t>(config_.http.listen_port)};

        acceptor_ = std::make_unique<tcp::acceptor>(ioc_);
        acceptor_->open(endpoint.protocol());
        acceptor_->set_option(net::socket_base::reuse_address(true));
        acceptor_->bind(endpoint);
        acceptor_->listen(net::socket_base::max_listen_connections);

        running_ = true;
        do_accept();

        LOG_INFO("WsServer: Listening on {}:{}", config_.http.listen_address, config_.http.listen_port);
    } catch (const std::exception& e) {
        LOG_ERROR("WsServer: Failed to start: {}", e.what());
    }
}

void WsServer::stop() {
    if (!running_) return;

    running_ = false;

    if (acceptor_ && acceptor_->is_open()) {
        beast::error_code ec;
        acceptor_->close(ec);
    }

    LOG_INFO("WsServer: Stopped");
}

void WsServer::do_accept() {
    if (!running_) return;

    acceptor_->async_accept(
        net::make_strand(ioc_),
        beast::bind_front_handler(
            &WsServer::on_accept,
            this));
}

void WsServer::on_accept(beast::error_code ec, tcp::socket socket) {
    if (ec) {
        if (ec != net::error::operation_aborted) {
            LOG_WARN("WsServer: Accept error: {}", ec.message());
        }
    } else {
        LOG_DEBUG("WsServer: New connection from {}",
                  socket.remote_endpoint().address().to_string());

        // Create HTTP session to handle routing
        std::make_shared<HttpSession>(std::move(socket), this)->run();
    }

    if (running_) {
        do_accept();
    }
}

// ============================================================================
// HttpSession Implementation
// ============================================================================

HttpSession::HttpSession(tcp::socket&& socket, WsServer* server)
    : socket_(std::move(socket))
    , server_(server) {
}

void HttpSession::run() {
    do_read();
}

void HttpSession::do_read() {
    req_ = {};

    http::async_read(socket_, buffer_, req_,
        beast::bind_front_handler(
            &HttpSession::on_read,
            shared_from_this()));
}

void HttpSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec == http::error::end_of_stream) {
        socket_.shutdown(tcp::socket::shutdown_send, ec);
        return;
    }

    if (ec) {
        LOG_WARN("HttpSession: Read error: {}", ec.message());
        return;
    }

    // Check if this is a WebSocket upgrade request
    if (websocket::is_upgrade(req_)) {
        std::string target = std::string(req_.target());

        // Remove query string for path matching
        auto query_pos = target.find('?');
        std::string path = (query_pos != std::string::npos)
            ? target.substr(0, query_pos)
            : target;

        LOG_DEBUG("HttpSession: WebSocket upgrade request for path: {}", path);

        if (path == paths::WS_CONTROL) {
            handle_control_upgrade();
        } else if (path == paths::WS_SERVER) {
            handle_server_upgrade();
        } else if (path == paths::WS_RELAY) {
            handle_relay_upgrade();
        } else {
            LOG_WARN("HttpSession: Unknown WebSocket path: {}", path);
            send_not_found();
        }
    } else {
        // Regular HTTP request - return 404 for now
        send_not_found();
    }
}

void HttpSession::handle_control_upgrade() {
    std::make_shared<WsControlSession>(
        std::move(socket_), server_, std::move(req_))->run();
}

void HttpSession::handle_server_upgrade() {
    std::make_shared<WsServerSession>(
        std::move(socket_), server_, std::move(req_))->run();
}

void HttpSession::handle_relay_upgrade() {
    // Use built-in relay if available
    if (auto* relay = server_->get_builtin_relay()) {
        std::make_shared<WsRelaySession>(
            std::move(socket_), relay)->run();
    } else {
        LOG_WARN("HttpSession: Relay not enabled");
        send_not_found();
    }
}

void HttpSession::send_not_found() {
    http::response<http::string_body> res{http::status::not_found, req_.version()};
    res.set(http::field::server, "EdgeLink/1.0");
    res.set(http::field::content_type, "text/plain");
    res.keep_alive(req_.keep_alive());
    res.body() = "Not Found";
    res.prepare_payload();

    auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));

    http::async_write(socket_, *sp,
        [self = shared_from_this(), sp](beast::error_code ec, std::size_t) {
            self->socket_.shutdown(tcp::socket::shutdown_send, ec);
        });
}

// ============================================================================
// WsControlSession Implementation
// ============================================================================

WsControlSession::WsControlSession(tcp::socket&& socket,
                                   WsServer* server,
                                   http::request<http::string_body>&& req)
    : ws_(std::move(socket))
    , server_(server)
    , req_(std::move(req)) {
}

void WsControlSession::run() {
    // Set suggested timeout settings
    ws_.set_option(websocket::stream_base::timeout::suggested(
        beast::role_type::server));

    // Set a decorator
    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server, "EdgeLink-Controller/1.0");
        }));

    // Create protocol handler
    handler_ = std::make_unique<ControlProtocolHandler>(
        server_->get_database(),
        server_->get_config().jwt.secret,
        server_->get_path_service());

    do_accept();
}

void WsControlSession::send(const std::vector<uint8_t>& data) {
    // Post to strand
    net::post(ws_.get_executor(),
        [self = shared_from_this(), data]() {
            std::string text(data.begin(), data.end());
            self->write_queue_.push_back(text);
            if (!self->writing_) {
                self->do_write();
            }
        });
}

void WsControlSession::send_text(const std::string& text) {
    net::post(ws_.get_executor(),
        [self = shared_from_this(), text]() {
            self->write_queue_.push_back(text);
            if (!self->writing_) {
                self->do_write();
            }
        });
}

void WsControlSession::close() {
    beast::error_code ec;
    ws_.close(websocket::close_code::normal, ec);
}

void WsControlSession::do_accept() {
    ws_.async_accept(
        req_,
        beast::bind_front_handler(
            &WsControlSession::on_accept,
            shared_from_this()));
}

void WsControlSession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_WARN("WsControlSession: Accept failed: {}", ec.message());
        return;
    }

    LOG_DEBUG("WsControlSession: Connection accepted");

    // Text mode for JSON control messages
    ws_.text(true);

    // Extract query string
    std::string target = std::string(req_.target());
    std::string query_string;
    auto query_pos = target.find('?');
    if (query_pos != std::string::npos) {
        query_string = target.substr(query_pos + 1);
    }

    // Initialize handler with empty message to extract machine key from query
    std::string response = handler_->handle_message("", query_string);
    if (!response.empty()) {
        send_text(response);
    }

    do_read();
}

void WsControlSession::do_read() {
    buffer_.consume(buffer_.size());

    ws_.async_read(
        buffer_,
        beast::bind_front_handler(
            &WsControlSession::on_read,
            shared_from_this()));
}

void WsControlSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec == websocket::error::closed) {
        LOG_DEBUG("WsControlSession: Connection closed");
        goto cleanup;
    }

    if (ec) {
        LOG_WARN("WsControlSession: Read error: {}", ec.message());
        goto cleanup;
    }

    {
        std::string text = beast::buffers_to_string(buffer_.data());
        handle_message(text);
    }

    do_read();
    return;

cleanup:
    if (authenticated_ && node_id_ > 0) {
        server_->get_session_manager()->remove_control_session(node_id_);
        server_->get_database()->set_node_online(node_id_, false);
    }
}

void WsControlSession::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }

    writing_ = true;
    auto& text = write_queue_.front();

    ws_.async_write(
        net::buffer(text),
        beast::bind_front_handler(
            &WsControlSession::on_write,
            shared_from_this()));
}

void WsControlSession::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        LOG_WARN("WsControlSession: Write error: {}", ec.message());
        writing_ = false;
        return;
    }

    write_queue_.erase(write_queue_.begin());
    do_write();
}

void WsControlSession::handle_message(const std::string& text) {
    std::string target = std::string(req_.target());
    std::string query_string;
    auto query_pos = target.find('?');
    if (query_pos != std::string::npos) {
        query_string = target.substr(query_pos + 1);
    }

    std::string response = handler_->handle_message(text, query_string);

    // Check if just authenticated
    if (!authenticated_ && handler_->is_authenticated()) {
        on_authenticated(handler_->get_node_id(), handler_->get_network_id());
    }

    if (!response.empty()) {
        send_text(response);
    }
}

void WsControlSession::on_authenticated(uint32_t node_id, uint32_t network_id) {
    authenticated_ = true;
    node_id_ = node_id;
    network_id_ = network_id;

    // Register with session manager
    server_->get_session_manager()->add_control_session(node_id_, network_id_, this);

    LOG_INFO("WsControlSession: Node {} authenticated (network {})", node_id_, network_id_);
}

// ============================================================================
// WsServerSession Implementation
// ============================================================================

WsServerSession::WsServerSession(tcp::socket&& socket,
                                 WsServer* server,
                                 http::request<http::string_body>&& req)
    : ws_(std::move(socket))
    , server_(server)
    , req_(std::move(req)) {
}

void WsServerSession::run() {
    ws_.set_option(websocket::stream_base::timeout::suggested(
        beast::role_type::server));

    ws_.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server, "EdgeLink-Controller/1.0");
        }));

    // Create protocol handler
    handler_ = std::make_unique<ServerProtocolHandler>(
        server_->get_database(),
        server_->get_config().jwt.secret,
        server_->get_config().server_token);

    // Set mesh forward callback
    handler_->set_mesh_forward_callback([this](uint32_t relay_id, const std::string& message) {
        // Forward message to another relay
        void* session_ptr = server_->get_session_manager()->get_server_session(relay_id);
        if (session_ptr) {
            auto* relay_session = static_cast<WsServerSession*>(session_ptr);
            relay_session->send_text(message);
        }
    });

    do_accept();
}

void WsServerSession::send(const std::vector<uint8_t>& data) {
    net::post(ws_.get_executor(),
        [self = shared_from_this(), data]() {
            std::string text(data.begin(), data.end());
            self->write_queue_.push_back(text);
            if (!self->writing_) {
                self->do_write();
            }
        });
}

void WsServerSession::send_text(const std::string& text) {
    net::post(ws_.get_executor(),
        [self = shared_from_this(), text]() {
            self->write_queue_.push_back(text);
            if (!self->writing_) {
                self->do_write();
            }
        });
}

void WsServerSession::close() {
    beast::error_code ec;
    ws_.close(websocket::close_code::normal, ec);
}

void WsServerSession::do_accept() {
    ws_.async_accept(
        req_,
        beast::bind_front_handler(
            &WsServerSession::on_accept,
            shared_from_this()));
}

void WsServerSession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_WARN("WsServerSession: Accept failed: {}", ec.message());
        return;
    }

    LOG_DEBUG("WsServerSession: Connection accepted");

    ws_.text(true);
    do_read();
}

void WsServerSession::do_read() {
    buffer_.consume(buffer_.size());

    ws_.async_read(
        buffer_,
        beast::bind_front_handler(
            &WsServerSession::on_read,
            shared_from_this()));
}

void WsServerSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec == websocket::error::closed) {
        LOG_DEBUG("WsServerSession: Connection closed");
        goto cleanup;
    }

    if (ec) {
        LOG_WARN("WsServerSession: Read error: {}", ec.message());
        goto cleanup;
    }

    {
        std::string text = beast::buffers_to_string(buffer_.data());
        handle_message(text);
    }

    do_read();
    return;

cleanup:
    if (authenticated_ && server_id_ > 0) {
        server_->get_session_manager()->remove_server_session(server_id_);
    }
}

void WsServerSession::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }

    writing_ = true;
    auto& text = write_queue_.front();

    ws_.async_write(
        net::buffer(text),
        beast::bind_front_handler(
            &WsServerSession::on_write,
            shared_from_this()));
}

void WsServerSession::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        LOG_WARN("WsServerSession: Write error: {}", ec.message());
        writing_ = false;
        return;
    }

    write_queue_.erase(write_queue_.begin());
    do_write();
}

void WsServerSession::handle_message(const std::string& text) {
    std::string target = std::string(req_.target());
    std::string query_string;
    auto query_pos = target.find('?');
    if (query_pos != std::string::npos) {
        query_string = target.substr(query_pos + 1);
    }

    std::string response = handler_->handle_message(text, query_string);

    // Check if just authenticated
    if (!authenticated_ && handler_->is_authenticated()) {
        on_authenticated(handler_->get_server_id());
    }

    if (!response.empty()) {
        send_text(response);
    }
}

void WsServerSession::on_authenticated(uint32_t server_id) {
    authenticated_ = true;
    server_id_ = server_id;

    // Register with session manager
    server_->get_session_manager()->add_server_session(server_id_, this);

    LOG_INFO("WsServerSession: Server {} authenticated", server_id_);
}

} // namespace edgelink::controller

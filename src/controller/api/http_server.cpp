#include "http_server.hpp"
#include "services.hpp"
#include "control_handler.hpp"
#include "controller/services/path_service.hpp"
#include "controller/builtin_relay.hpp"
#include "common/log.hpp"
#include "common/protocol.hpp"
#include <nlohmann/json.hpp>
#include <regex>
#include <fstream>
#include <queue>

namespace edgelink::controller {

using json = nlohmann::json;

// ============================================================================
// JSON Response Helpers
// ============================================================================

HttpResponse make_json_response(http::status status, const std::string& body) {
    HttpResponse res{status, 11};
    res.set(http::field::content_type, "application/json");
    res.set(http::field::access_control_allow_origin, "*");
    res.body() = body;
    res.prepare_payload();
    return res;
}

HttpResponse make_error_response(http::status status, const std::string& error, const std::string& message) {
    json j;
    j["error"] = error;
    j["message"] = message;
    return make_json_response(status, j.dump());
}

HttpResponse make_success_response(const std::string& body) {
    return make_json_response(http::status::ok, body);
}

// ============================================================================
// HttpRouter Implementation
// ============================================================================

void HttpRouter::add_route(const std::string& method, const std::string& path, RouteHandler handler) {
    Route route;
    route.method = method;
    route.pattern = path;
    route.handler = std::move(handler);
    route.is_pattern = path.find(':') != std::string::npos;
    routes_.push_back(std::move(route));
}

std::pair<RouteHandler, std::string> HttpRouter::find_route(
    const std::string& method, const std::string& path) const {
    
    for (const auto& route : routes_) {
        if (route.method != method && route.method != "*") continue;
        
        if (route.is_pattern) {
            std::string param;
            if (match_pattern(route.pattern, path, param)) {
                return {route.handler, param};
            }
        } else if (route.pattern == path) {
            return {route.handler, ""};
        }
    }
    
    return {nullptr, ""};
}

bool HttpRouter::match_pattern(const std::string& pattern, const std::string& path, std::string& param) const {
    // Simple pattern matching: /api/nodes/:id -> /api/nodes/123
    size_t colon_pos = pattern.find(':');
    if (colon_pos == std::string::npos) return false;
    
    std::string prefix = pattern.substr(0, colon_pos);
    if (path.substr(0, prefix.length()) != prefix) return false;
    
    // Extract parameter value
    std::string remaining = path.substr(prefix.length());
    size_t slash_pos = remaining.find('/');
    if (slash_pos != std::string::npos) {
        // Check suffix matches
        std::string suffix = pattern.substr(pattern.find('/', colon_pos));
        if (remaining.substr(slash_pos) != suffix) return false;
        param = remaining.substr(0, slash_pos);
    } else {
        param = remaining;
    }
    
    return !param.empty();
}

// ============================================================================
// WebSocketManager Implementation
// ============================================================================

void WebSocketManager::add_session(std::shared_ptr<WebSocketSession> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (session->get_type() == WSSessionType::CONTROL) {
        node_sessions_[session->get_node_id()] = session;
    } else {
        server_sessions_[session->get_server_id()] = session;
    }
}

void WebSocketManager::remove_session(std::shared_ptr<WebSocketSession> session) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (session->get_type() == WSSessionType::CONTROL) {
        node_sessions_.erase(session->get_node_id());
    } else {
        server_sessions_.erase(session->get_server_id());
    }
}

void WebSocketManager::send_to_node(uint32_t node_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = node_sessions_.find(node_id);
    if (it != node_sessions_.end()) {
        it->second->send(message);
    }
}

void WebSocketManager::send_to_server(uint32_t server_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = server_sessions_.find(server_id);
    if (it != server_sessions_.end()) {
        it->second->send(message);
    }
}

void WebSocketManager::broadcast_to_network(uint32_t network_id, const std::string& message, uint32_t exclude_node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // TODO: Filter by network_id - for now broadcast to all
    for (auto& [id, session] : node_sessions_) {
        if (id != exclude_node_id) {
            session->send(message);
        }
    }
}

void WebSocketManager::broadcast_to_servers(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [id, session] : server_sessions_) {
        session->send(message);
    }
}

void WebSocketManager::push_config_update(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = node_sessions_.find(node_id);
    if (it != node_sessions_.end()) {
        it->second->send_config_update();
    }
}

void WebSocketManager::push_config_update_to_network(uint32_t network_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [id, session] : node_sessions_) {
        if (session->get_network_id() == network_id) {
            session->send_config_update();
        }
    }
}

// ============================================================================
// HttpServer Implementation
// ============================================================================

HttpServer::HttpServer(net::io_context& ioc,
                       const ControllerConfig& config,
                       std::shared_ptr<Database> db)
    : ioc_(ioc)
    , acceptor_(ioc)
    , config_(config)
    , router_(std::make_shared<HttpRouter>())
    , ws_manager_(std::make_shared<WebSocketManager>())
    , db_(std::move(db)) {
    
    // Initialize services
    auth_service_ = std::make_shared<AuthService>(db_, config_.jwt);
    node_service_ = std::make_shared<NodeService>(db_);
    config_service_ = std::make_shared<ConfigService>(db_);
    
    // Setup SSL if enabled
    if (config_.http.enable_tls) {
        setup_ssl_context();
    }
    
    // Setup routes
    setup_routes();
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    beast::error_code ec;
    
    // Parse endpoint
    auto const address = net::ip::make_address(config_.http.listen_address, ec);
    if (ec) {
        LOG_ERROR("Invalid listen address: {}", ec.message());
        return;
    }
    
    auto endpoint = tcp::endpoint{address, config_.http.listen_port};
    
    // Open acceptor
    acceptor_.open(endpoint.protocol(), ec);
    if (ec) {
        LOG_ERROR("Failed to open acceptor: {}", ec.message());
        return;
    }
    
    // Allow address reuse
    acceptor_.set_option(net::socket_base::reuse_address(true), ec);
    
    // Bind
    acceptor_.bind(endpoint, ec);
    if (ec) {
        LOG_ERROR("Failed to bind: {}", ec.message());
        return;
    }
    
    // Listen
    acceptor_.listen(net::socket_base::max_listen_connections, ec);
    if (ec) {
        LOG_ERROR("Failed to listen: {}", ec.message());
        return;
    }
    
    running_ = true;
    LOG_INFO("HTTP server listening on {}:{}", 
             config_.http.listen_address, config_.http.listen_port);
    
    do_accept();
}

void HttpServer::stop() {
    if (!running_) return;
    
    running_ = false;
    beast::error_code ec;
    acceptor_.close(ec);
    
    LOG_INFO("HTTP server stopped");
}

void HttpServer::do_accept() {
    acceptor_.async_accept(
        net::make_strand(ioc_),
        beast::bind_front_handler(&HttpServer::on_accept, this)
    );
}

void HttpServer::on_accept(beast::error_code ec, tcp::socket socket) {
    if (ec) {
        if (running_) {
            LOG_ERROR("Accept error: {}", ec.message());
        }
        return;
    }
    
    // Create session
    auto session = std::make_shared<HttpSession>(
        std::move(socket),
        ssl_ctx_,
        router_,
        db_,
        config_.jwt.secret,
        config_.http.enable_tls,
        ws_manager_.get(),
        builtin_relay_,
        config_.server_token
    );
    session->run();
    
    // Accept next connection
    if (running_) {
        do_accept();
    }
}

void HttpServer::setup_ssl_context() {
    ssl_ctx_.set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2 |
        ssl::context::no_sslv3 |
        ssl::context::single_dh_use
    );
    
    if (!config_.tls.cert_path.empty()) {
        ssl_ctx_.use_certificate_chain_file(config_.tls.cert_path);
    }
    if (!config_.tls.key_path.empty()) {
        ssl_ctx_.use_private_key_file(config_.tls.key_path, ssl::context::pem);
    }
}

void HttpServer::setup_routes() {
    // Health check
    router_->add_route("GET", "/health", [](const HttpRequest&, const std::string&) {
        return make_success_response(R"({"status":"ok"})");
    });
    
    // API version
    router_->add_route("GET", "/api/v1/version", [](const HttpRequest&, const std::string&) {
        json j;
        j["version"] = "1.0.0";
        j["protocol_version"] = PROTOCOL_VERSION;
        return make_success_response(j.dump());
    });
    
    // Network management
    router_->add_route("GET", "/api/v1/networks", [this](const HttpRequest&, const std::string&) {
        auto networks = db_->list_networks();
        json j = json::array();
        for (const auto& n : networks) {
            json net;
            net["id"] = n.id;
            net["name"] = n.name;
            net["subnet"] = n.subnet;
            net["description"] = n.description;
            j.push_back(net);
        }
        return make_success_response(j.dump());
    });
    
    router_->add_route("POST", "/api/v1/networks", [this](const HttpRequest& req, const std::string&) {
        try {
            auto body = json::parse(req.body());
            Network network;
            network.name = body["name"].get<std::string>();
            network.subnet = body["subnet"].get<std::string>();
            network.description = body.value("description", "");
            
            uint32_t id = db_->create_network(network);
            if (id == 0) {
                return make_error_response(http::status::internal_server_error,
                                          "creation_failed", "Failed to create network");
            }
            
            json j;
            j["id"] = id;
            j["name"] = network.name;
            j["subnet"] = network.subnet;
            return make_json_response(http::status::created, j.dump());
        } catch (const std::exception& e) {
            return make_error_response(http::status::bad_request,
                                      "invalid_request", e.what());
        }
    });
    
    // Node management
    router_->add_route("GET", "/api/v1/nodes", [this](const HttpRequest& req, const std::string&) {
        // Parse query params
        uint32_t network_id = 0;
        auto target = req.target();
        auto query_pos = target.find('?');
        if (query_pos != std::string::npos) {
            // Simple query parsing
            std::string query(target.substr(query_pos + 1));
            if (query.find("network_id=") == 0) {
                network_id = std::stoul(query.substr(11));
            }
        }
        
        auto nodes = node_service_->list_nodes(network_id);
        json j = json::array();
        for (const auto& n : nodes) {
            json node;
            node["id"] = n.id;
            node["network_id"] = n.network_id;
            node["name"] = n.name;
            node["virtual_ip"] = n.virtual_ip;
            node["hostname"] = n.hostname;
            node["os"] = n.os;
            node["arch"] = n.arch;
            node["version"] = n.version;
            node["nat_type"] = n.nat_type;
            node["online"] = n.online;
            node["authorized"] = n.authorized;
            node["last_seen"] = n.last_seen;
            j.push_back(node);
        }
        return make_success_response(j.dump());
    });
    
    router_->add_route("GET", "/api/v1/nodes/:id", [this](const HttpRequest&, const std::string& param) {
        uint32_t id = std::stoul(param);
        auto node = node_service_->get_node(id);
        if (!node) {
            return make_error_response(http::status::not_found,
                                      "not_found", "Node not found");
        }
        
        json j;
        j["id"] = node->id;
        j["network_id"] = node->network_id;
        j["name"] = node->name;
        j["machine_key_pub"] = node->machine_key_pub;
        j["node_key_pub"] = node->node_key_pub;
        j["virtual_ip"] = node->virtual_ip;
        j["hostname"] = node->hostname;
        j["os"] = node->os;
        j["arch"] = node->arch;
        j["version"] = node->version;
        j["nat_type"] = node->nat_type;
        j["online"] = node->online;
        j["authorized"] = node->authorized;
        j["last_seen"] = node->last_seen;
        
        // Include endpoints
        auto endpoints = db_->get_node_endpoints(id);
        j["endpoints"] = json::array();
        for (const auto& ep : endpoints) {
            json e;
            e["type"] = ep.type;
            e["ip"] = ep.ip;
            e["port"] = ep.port;
            e["priority"] = ep.priority;
            j["endpoints"].push_back(e);
        }
        
        // Include routes
        auto routes = node_service_->get_node_routes(id);
        j["routes"] = json::array();
        for (const auto& r : routes) {
            json route;
            route["id"] = r.id;
            route["cidr"] = r.cidr;
            route["priority"] = r.priority;
            route["weight"] = r.weight;
            route["enabled"] = r.enabled;
            j["routes"].push_back(route);
        }
        
        return make_success_response(j.dump());
    });
    
    router_->add_route("POST", "/api/v1/nodes/:id/authorize", [this](const HttpRequest&, const std::string& param) {
        uint32_t id = std::stoul(param);
        if (auth_service_->authorize_node(id)) {
            return make_success_response(R"({"status":"authorized"})");
        }
        return make_error_response(http::status::not_found, "not_found", "Node not found");
    });
    
    router_->add_route("POST", "/api/v1/nodes/:id/deauthorize", [this](const HttpRequest&, const std::string& param) {
        uint32_t id = std::stoul(param);
        if (auth_service_->deauthorize_node(id)) {
            return make_success_response(R"({"status":"deauthorized"})");
        }
        return make_error_response(http::status::not_found, "not_found", "Node not found");
    });
    
    router_->add_route("DELETE", "/api/v1/nodes/:id", [this](const HttpRequest&, const std::string& param) {
        uint32_t id = std::stoul(param);
        if (node_service_->delete_node(id)) {
            return make_json_response(http::status::no_content, "");
        }
        return make_error_response(http::status::not_found, "not_found", "Node not found");
    });
    
    // Server management
    router_->add_route("GET", "/api/v1/servers", [this](const HttpRequest&, const std::string&) {
        auto servers = db_->list_servers();
        json j = json::array();
        for (const auto& s : servers) {
            json srv;
            srv["id"] = s.id;
            srv["name"] = s.name;
            srv["type"] = s.type;
            srv["url"] = s.url;
            srv["region"] = s.region;
            srv["capabilities"] = json::parse(s.capabilities);
            srv["stun_ip"] = s.stun_ip;
            srv["stun_ip2"] = s.stun_ip2;
            srv["stun_port"] = s.stun_port;
            srv["enabled"] = s.enabled;
            srv["last_heartbeat"] = s.last_heartbeat;
            j.push_back(srv);
        }
        return make_success_response(j.dump());
    });
    
    router_->add_route("POST", "/api/v1/servers", [this](const HttpRequest& req, const std::string&) {
        try {
            auto body = json::parse(req.body());
            
            auto result = auth_service_->register_server(
                body["name"].get<std::string>(),
                body.value("type", "external"),
                body["url"].get<std::string>(),
                body.value("region", ""),
                body.value("capabilities", std::vector<std::string>{}),
                body.value("stun_ip", ""),
                body.value("stun_ip2", ""),
                body.value("stun_port", 3478)
            );
            
            if (!result.success) {
                return make_error_response(http::status::bad_request,
                                          result.error, "Server registration failed");
            }
            
            json j;
            j["id"] = result.server_id;
            j["server_token"] = result.server_token;
            return make_json_response(http::status::created, j.dump());
        } catch (const std::exception& e) {
            return make_error_response(http::status::bad_request,
                                      "invalid_request", e.what());
        }
    });
    
    // Node registration endpoint (for new nodes)
    router_->add_route("POST", "/api/v1/register", [this](const HttpRequest& req, const std::string&) {
        try {
            auto body = json::parse(req.body());
            
            NodeRegistrationRequest reg;
            reg.machine_key_pub = body["machine_key_pub"].get<std::string>();
            reg.node_key_pub = body["node_key_pub"].get<std::string>();
            reg.hostname = body.value("hostname", "");
            reg.os = body.value("os", "");
            reg.arch = body.value("arch", "");
            reg.version = body.value("version", "");
            reg.network_id = body.value("network_id", 1u);
            
            auto result = node_service_->register_node(reg);
            
            if (!result.success) {
                return make_error_response(http::status::bad_request,
                                          result.error, "Registration failed");
            }
            
            json j;
            j["node_id"] = result.node_id;
            j["virtual_ip"] = result.virtual_ip;
            j["pending_authorization"] = result.pending_authorization;
            return make_json_response(http::status::created, j.dump());
        } catch (const std::exception& e) {
            return make_error_response(http::status::bad_request,
                                      "invalid_request", e.what());
        }
    });
    
    // Stats endpoint
    router_->add_route("GET", "/api/v1/stats", [this](const HttpRequest&, const std::string&) {
        json j;
        j["nodes_online"] = node_service_->list_online_nodes().size();
        j["nodes_total"] = node_service_->list_nodes().size();
        j["servers_total"] = db_->list_servers().size();
        j["ws_nodes"] = ws_manager_->node_count();
        j["ws_servers"] = ws_manager_->server_count();
        return make_success_response(j.dump());
    });
    
    // CORS preflight
    router_->add_route("OPTIONS", "*", [](const HttpRequest&, const std::string&) {
        HttpResponse res{http::status::no_content, 11};
        res.set(http::field::access_control_allow_origin, "*");
        res.set(http::field::access_control_allow_methods, "GET, POST, PUT, DELETE, OPTIONS");
        res.set(http::field::access_control_allow_headers, "Content-Type, Authorization");
        res.prepare_payload();
        return res;
    });
    
    LOG_INFO("API routes configured");
}

// ============================================================================
// HttpSession Implementation (simplified - non-SSL only for now)
// ============================================================================

HttpSession::HttpSession(tcp::socket socket,
                         ssl::context& ctx,
                         std::shared_ptr<HttpRouter> router,
                         std::shared_ptr<Database> db,
                         const std::string& jwt_secret,
                         bool use_ssl,
                         WebSocketManager* ws_manager,
                         BuiltinRelay* builtin_relay,
                         const std::string& server_token)
    : router_(std::move(router))
    , db_(std::move(db))
    , jwt_secret_(jwt_secret)
    , server_token_(server_token)
    , use_ssl_(use_ssl)
    , ws_manager_(ws_manager)
    , builtin_relay_(builtin_relay)
    , stream_(std::move(socket))
    , ssl_ctx_(ctx) {
}

void HttpSession::run() {
    if (use_ssl_) {
        do_handshake();
    } else {
        do_read();
    }
}

void HttpSession::do_handshake() {
    // SSL handshake would go here
    // For simplicity, just proceed with read
    do_read();
}

void HttpSession::do_read() {
    request_ = {};
    buffer_.consume(buffer_.size());
    
    // Read request
    std::visit([this](auto& stream) {
        http::async_read(
            stream,
            buffer_,
            request_,
            beast::bind_front_handler(&HttpSession::on_read, shared_from_this())
        );
    }, stream_);
}

void HttpSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    
    if (ec == http::error::end_of_stream) {
        do_close();
        return;
    }
    
    if (ec) {
        LOG_ERROR("Read error: {}", ec.message());
        return;
    }
    
    // Check for WebSocket upgrade
    if (should_upgrade_websocket()) {
        upgrade_to_websocket();
        return;
    }
    
    handle_request();
}

bool HttpSession::should_upgrade_websocket() {
    return websocket::is_upgrade(request_);
}

void HttpSession::upgrade_to_websocket() {
    // Determine session type from path
    auto target = std::string(request_.target());
    
    // Handle /ws/data - forward to BuiltinRelay
    if (target.find("/ws/data") == 0) {
        if (builtin_relay_ && builtin_relay_->is_enabled()) {
            std::visit([this](auto& stream) {
                using StreamType = std::decay_t<decltype(stream)>;
                if constexpr (std::is_same_v<StreamType, tcp::socket>) {
                    builtin_relay_->handle_upgrade(std::move(stream), std::move(request_));
                }
            }, stream_);
        } else {
            send_response(make_error_response(http::status::service_unavailable,
                                             "relay_disabled", "Built-in relay is not enabled"));
        }
        return;
    }
    
    WSSessionType type;
    if (target.find("/ws/control") == 0) {
        type = WSSessionType::CONTROL;
    } else if (target.find("/ws/server") == 0) {
        type = WSSessionType::SERVER;
    } else {
        // Invalid WS path
        send_response(make_error_response(http::status::bad_request,
                                         "invalid_path", "Invalid WebSocket path"));
        return;
    }
    
    // Create WebSocket session
    std::visit([this, type](auto& stream) {
        using StreamType = std::decay_t<decltype(stream)>;
        if constexpr (std::is_same_v<StreamType, tcp::socket>) {
            auto ws_session = std::make_shared<WebSocketSession>(
                std::move(stream),
                ssl_ctx_,
                type,
                db_,
                jwt_secret_,
                use_ssl_,
                ws_manager_,
                server_token_
            );
            ws_session->run(std::move(request_));
        }
    }, stream_);
}

void HttpSession::handle_request() {
    std::string method = std::string(request_.method_string());
    std::string path = std::string(request_.target());
    
    // Remove query string for routing
    auto query_pos = path.find('?');
    std::string route_path = (query_pos != std::string::npos) ? path.substr(0, query_pos) : path;
    
    auto [handler, param] = router_->find_route(method, route_path);
    
    HttpResponse response;
    if (handler) {
        try {
            response = handler(request_, param);
        } catch (const std::exception& e) {
            response = make_error_response(http::status::internal_server_error,
                                          "internal_error", e.what());
        }
    } else {
        response = make_error_response(http::status::not_found,
                                      "not_found", "Route not found");
    }
    
    send_response(std::move(response));
}

void HttpSession::send_response(HttpResponse&& response) {
    response_ = std::make_shared<HttpResponse>(std::move(response));
    
    std::visit([this](auto& stream) {
        http::async_write(
            stream,
            *response_,
            beast::bind_front_handler(&HttpSession::on_write, shared_from_this(),
                                     response_->need_eof())
        );
    }, stream_);
}

void HttpSession::on_write(bool close, beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    
    if (ec) {
        LOG_ERROR("Write error: {}", ec.message());
        return;
    }
    
    if (close) {
        do_close();
        return;
    }
    
    response_ = nullptr;
    do_read();
}

void HttpSession::do_close() {
    std::visit([](auto& stream) {
        beast::error_code ec;
        using StreamType = std::decay_t<decltype(stream)>;
        if constexpr (std::is_same_v<StreamType, tcp::socket>) {
            stream.shutdown(tcp::socket::shutdown_send, ec);
        }
    }, stream_);
}

// ============================================================================
// WebSocketSession Implementation (simplified)
// ============================================================================

WebSocketSession::WebSocketSession(tcp::socket socket,
                                   ssl::context& ctx,
                                   WSSessionType type,
                                   std::shared_ptr<Database> db,
                                   const std::string& jwt_secret,
                                   bool use_ssl,
                                   WebSocketManager* ws_manager,
                                   const std::string& server_token)
    : type_(type)
    , use_ssl_(use_ssl)
    , db_(std::move(db))
    , jwt_secret_(jwt_secret)
    , server_token_(server_token)
    , ws_manager_(ws_manager)
    , ws_(websocket::stream<tcp::socket>(std::move(socket)))
    , ssl_ctx_(ctx) {
}

void WebSocketSession::run(HttpRequest req) {
    // Save query string for authentication
    auto target = std::string(req.target());
    auto pos = target.find('?');
    if (pos != std::string::npos) {
        query_string_ = target.substr(pos + 1);
    }
    
    // Accept the WebSocket handshake
    std::visit([this, &req](auto& ws) {
        ws.async_accept(
            req,
            beast::bind_front_handler(&WebSocketSession::on_accept, shared_from_this())
        );
    }, ws_);
}

void WebSocketSession::on_accept(beast::error_code ec) {
    if (ec) {
        fail(ec, "accept");
        return;
    }
    
    // Send initial message to trigger auth from query string
    process_message("");
    
    do_read();
}

void WebSocketSession::do_read() {
    std::visit([this](auto& ws) {
        ws.async_read(
            buffer_,
            beast::bind_front_handler(&WebSocketSession::on_read, shared_from_this())
        );
    }, ws_);
}

void WebSocketSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    
    if (ec == websocket::error::closed) {
        if (close_callback_) {
            close_callback_(shared_from_this());
        }
        return;
    }
    
    if (ec) {
        fail(ec, "read");
        return;
    }
    
    // Process message
    std::string message = beast::buffers_to_string(buffer_.data());
    buffer_.consume(buffer_.size());
    
    // Use internal handler or callback
    process_message(message);
    
    if (message_callback_) {
        message_callback_(shared_from_this(), message);
    }
    
    do_read();
}

void WebSocketSession::send(const std::string& message) {
    write_queue_.push(message);
    
    if (writing_) return;
    
    writing_ = true;
    std::visit([this](auto& ws) {
        ws.async_write(
            net::buffer(write_queue_.front()),
            beast::bind_front_handler(&WebSocketSession::on_write, shared_from_this())
        );
    }, ws_);
}

void WebSocketSession::send_config_update() {
    if (type_ != WSSessionType::CONTROL || !control_handler_ || !authenticated_) {
        return;
    }
    
    try {
        std::string config_update = control_handler_->generate_config_update();
        if (!config_update.empty()) {
            send(config_update);
            LOG_DEBUG("Pushed config update to node {}", node_id_);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to generate config update for node {}: {}", node_id_, e.what());
    }
}

void WebSocketSession::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    
    if (ec) {
        fail(ec, "write");
        return;
    }
    
    write_queue_.pop();
    
    if (!write_queue_.empty()) {
        std::visit([this](auto& ws) {
            ws.async_write(
                net::buffer(write_queue_.front()),
                beast::bind_front_handler(&WebSocketSession::on_write, shared_from_this())
            );
        }, ws_);
    } else {
        writing_ = false;
    }
}

void WebSocketSession::close() {
    std::visit([](auto& ws) {
        beast::error_code ec;
        ws.close(websocket::close_code::normal, ec);
    }, ws_);
}

void WebSocketSession::fail(beast::error_code ec, const char* what) {
    LOG_ERROR("WebSocket {}: {}", what, ec.message());
    
    // Notify peers about offline status
    if (type_ == WSSessionType::CONTROL && authenticated_) {
        notify_peer_status(false);
        
        // Update database
        if (node_id_ > 0) {
            db_->set_node_online(node_id_, false);
        }
    }
    
    // Remove from manager
    if (ws_manager_ && registered_) {
        ws_manager_->remove_session(shared_from_this());
        registered_ = false;
    }
    
    if (close_callback_) {
        close_callback_(shared_from_this());
    }
}

void WebSocketSession::process_message(const std::string& message) {
    std::string response;
    
    if (type_ == WSSessionType::CONTROL) {
        // Client node connection - use per-session handler
        if (!control_handler_) {
            control_handler_ = std::make_unique<ControlProtocolHandler>(db_, jwt_secret_, path_service_);
        }
        
        response = control_handler_->handle_message(message, query_string_);
        
        // Update session state from handler
        if (control_handler_->is_authenticated() && !authenticated_) {
            authenticated_ = true;
            node_id_ = control_handler_->get_node_id();
            network_id_ = control_handler_->get_network_id();
            LOG_INFO("WebSocket: Node {} authenticated", node_id_);
            
            // Register session and notify peers
            register_with_manager();
            notify_peer_status(true);
        }
    } else if (type_ == WSSessionType::SERVER) {
        // Relay server connection - use per-session handler
        if (!server_handler_) {
            server_handler_ = std::make_unique<ServerProtocolHandler>(db_, jwt_secret_, server_token_);
            
            // Set mesh forward callback to route data between relays
            server_handler_->set_mesh_forward_callback(
                [this](uint32_t relay_id, const std::string& message) {
                    if (ws_manager_) {
                        ws_manager_->send_to_server(relay_id, message);
                    }
                }
            );
        }
        
        response = server_handler_->handle_message(message, query_string_);
        
        // Update session state from handler
        if (server_handler_->is_authenticated() && !authenticated_) {
            authenticated_ = true;
            server_id_ = server_handler_->get_server_id();
            LOG_INFO("WebSocket: Server {} authenticated", server_id_);
            
            // Register session
            register_with_manager();
        }
    }
    
    // Send response if any
    if (!response.empty()) {
        send(response);
    }
}

void WebSocketSession::register_with_manager() {
    if (ws_manager_ && !registered_) {
        ws_manager_->add_session(shared_from_this());
        registered_ = true;
    }
}

void WebSocketSession::notify_peer_status(bool online) {
    if (!ws_manager_ || type_ != WSSessionType::CONTROL || node_id_ == 0) {
        return;
    }
    
    // Get node info from database
    auto node_opt = db_->get_node(node_id_);
    if (!node_opt) {
        return;
    }
    
    // Build peer status message
    nlohmann::json msg;
    msg["type"] = online ? "peer_online" : "peer_offline";
    msg["node_id"] = node_id_;
    msg["hostname"] = node_opt->hostname;
    msg["virtual_ip"] = node_opt->virtual_ip;
    
    std::string payload = msg.dump();
    
    // Broadcast to all nodes in the same network
    ws_manager_->broadcast_to_network(network_id_, payload, node_id_);
}

void WebSocketSession::set_path_service(std::shared_ptr<PathService> path_service) {
    path_service_ = std::move(path_service);
    if (control_handler_) {
        control_handler_->set_path_service(path_service_);
    }
}

} // namespace edgelink::controller

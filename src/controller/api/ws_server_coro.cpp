#include "controller/api/ws_server_coro.hpp"
#include "controller/builtin_relay.hpp"
#include "common/log.hpp"
#include "common/frame.hpp"

#include <regex>
#include <chrono>
#include <sodium.h>

namespace {
// Helper function for base64 encoding
std::string base64_encode(const uint8_t* data, size_t len) {
    size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string result(b64_len, '\0');
    sodium_bin2base64(result.data(), b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    // Remove null terminator if present
    if (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }
    return result;
}
} // anonymous namespace

namespace edgelink::controller {

// ============================================================================
// WsSessionManagerCoro Implementation
// ============================================================================

void WsSessionManagerCoro::add_control_session(uint32_t node_id, uint32_t network_id,
                                                std::weak_ptr<WsSessionCoro> session) {
    std::unique_lock lock(control_mutex_);
    control_sessions_[node_id] = {session, network_id};
    LOG_DEBUG("WsSessionManagerCoro: Added control session for node {} (network {})",
              node_id, network_id);
}

void WsSessionManagerCoro::remove_control_session(uint32_t node_id) {
    std::unique_lock lock(control_mutex_);
    control_sessions_.erase(node_id);
    LOG_DEBUG("WsSessionManagerCoro: Removed control session for node {}", node_id);
}

std::shared_ptr<WsSessionCoro> WsSessionManagerCoro::get_control_session(uint32_t node_id) {
    std::shared_lock lock(control_mutex_);
    auto it = control_sessions_.find(node_id);
    if (it != control_sessions_.end()) {
        return it->second.session.lock();
    }
    return nullptr;
}

void WsSessionManagerCoro::add_server_session(uint32_t server_id, std::weak_ptr<WsSessionCoro> session) {
    std::unique_lock lock(server_mutex_);
    server_sessions_[server_id] = session;
    LOG_DEBUG("WsSessionManagerCoro: Added server session for server {}", server_id);
}

void WsSessionManagerCoro::remove_server_session(uint32_t server_id) {
    std::unique_lock lock(server_mutex_);
    server_sessions_.erase(server_id);
    LOG_DEBUG("WsSessionManagerCoro: Removed server session for server {}", server_id);
}

std::shared_ptr<WsSessionCoro> WsSessionManagerCoro::get_server_session(uint32_t server_id) {
    std::shared_lock lock(server_mutex_);
    auto it = server_sessions_.find(server_id);
    if (it != server_sessions_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

void WsSessionManagerCoro::broadcast_to_network(uint32_t network_id, const std::string& text) {
    std::shared_lock lock(control_mutex_);
    for (const auto& [node_id, info] : control_sessions_) {
        if (info.network_id == network_id) {
            if (auto session = info.session.lock()) {
                session->send_text(text);
            }
        }
    }
}

size_t WsSessionManagerCoro::node_count() const {
    std::shared_lock lock(control_mutex_);
    return control_sessions_.size();
}

size_t WsSessionManagerCoro::server_count() const {
    std::shared_lock lock(server_mutex_);
    return server_sessions_.size();
}

std::vector<uint32_t> WsSessionManagerCoro::get_connected_nodes() const {
    std::shared_lock lock(control_mutex_);
    std::vector<uint32_t> nodes;
    nodes.reserve(control_sessions_.size());
    for (const auto& [node_id, info] : control_sessions_) {
        nodes.push_back(node_id);
    }
    return nodes;
}

// ============================================================================
// WsControllerServerCoro Implementation
// ============================================================================

WsControllerServerCoro::WsControllerServerCoro(IOContextPool& pool,
                                                 const ControllerConfig& config,
                                                 std::shared_ptr<Database> db)
    : WsServerCoro(pool, config.http.listen_address, static_cast<uint16_t>(config.http.listen_port))
    , config_(config)
    , db_(db)
    , path_service_(std::make_shared<PathService>(db))
{
    // Enable TLS if configured
    if (config.http.enable_tls && config.tls.is_valid()) {
        enable_tls(config.tls.cert_path, config.tls.key_path);
    }

    // Set up session factory
    set_session_factory([this](net::io_context& ioc, tcp::socket socket, const std::string& path)
        -> std::shared_ptr<WsSessionCoro> {
        return create_session(ioc, std::move(socket), path);
    });
}

WsControllerServerCoro::~WsControllerServerCoro() {
    stop();
}

std::shared_ptr<WsSessionCoro> WsControllerServerCoro::create_session(
    net::io_context& ioc,
    tcp::socket socket,
    const std::string& path) {

    // Extract query string from path
    std::string base_path = path;
    std::string query_string;
    auto query_pos = path.find('?');
    if (query_pos != std::string::npos) {
        base_path = path.substr(0, query_pos);
        query_string = path.substr(query_pos + 1);
    }

    LOG_DEBUG("WsControllerServerCoro: Creating session for path: {}", base_path);

    if (base_path == paths::WS_CONTROL) {
        return std::make_shared<WsControlSessionCoro>(ioc, std::move(socket), this, query_string);
    } else if (base_path == paths::WS_SERVER) {
        return std::make_shared<WsServerSessionCoro>(ioc, std::move(socket), this, query_string);
    } else if (base_path == paths::WS_RELAY) {
        // Built-in relay - TODO: implement WsRelaySessionCoro for controller
        // For now, return nullptr to reject
        LOG_DEBUG("WsControllerServerCoro: Relay path not yet implemented in coro mode");
        return nullptr;
    }

    LOG_DEBUG("WsControllerServerCoro: Unknown path: {}", base_path);
    return nullptr;
}

// ============================================================================
// WsControlSessionCoro Implementation
// ============================================================================

WsControlSessionCoro::WsControlSessionCoro(net::io_context& ioc, tcp::socket socket,
                                             WsControllerServerCoro* server,
                                             const std::string& query_string)
    : WsSessionCoro(ioc, std::move(socket))
    , server_(server)
    , query_string_(query_string)
{
    // Extract machine key from query string if present
    std::regex key_regex(R"(key=([^&]+))");
    std::smatch match;
    if (std::regex_search(query_string_, match, key_regex)) {
        machine_key_ = match[1].str();
    }
}

WsControlSessionCoro::~WsControlSessionCoro() = default;

net::awaitable<void> WsControlSessionCoro::on_connected() {
    LOG_DEBUG("WsControlSessionCoro: Connection established from {}", remote_address());
    co_return;
}

net::awaitable<void> WsControlSessionCoro::process_frame(const wire::Frame& frame) {
    // Dispatch based on frame type
    switch (frame.header.type) {
        case wire::MessageType::AUTH_REQUEST:
            handle_auth_request(frame);
            break;

        case wire::MessageType::PING:
            handle_ping(frame);
            break;

        case wire::MessageType::LATENCY_REPORT:
            handle_latency_report(frame);
            break;

        case wire::MessageType::P2P_INIT:
            handle_p2p_request(frame);
            break;

        case wire::MessageType::P2P_STATUS:
            handle_endpoint_report(frame);
            break;

        case wire::MessageType::CONFIG_ACK:
            handle_config_ack(frame);
            break;

        case wire::MessageType::ROUTE_ANNOUNCE:
            handle_route_announce(frame);
            break;

        case wire::MessageType::ROUTE_WITHDRAW:
            handle_route_withdraw(frame);
            break;

        default:
            LOG_DEBUG("WsControlSessionCoro: Unhandled message type: {} (0x{:02x})",
                      wire::message_type_to_string(frame.header.type),
                      static_cast<int>(frame.header.type));
            break;
    }
    co_return;
}

net::awaitable<void> WsControlSessionCoro::on_disconnected(const std::string& reason) {
    LOG_DEBUG("WsControlSessionCoro: Disconnected (node {}, reason: {})", node_id(), reason);

    if (control_authenticated_ && node_id() > 0) {
        server_->get_session_manager()->remove_control_session(node_id());
        server_->get_database()->set_node_online(node_id(), false);
    }

    co_return;
}

void WsControlSessionCoro::handle_auth_request(const wire::Frame& frame) {
    auto db = server_->get_database();
    auto& config = server_->get_config();

    std::string key;
    std::string auth_key;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;

    // Try binary deserialization first
    auto binary_result = wire::AuthRequestPayload::deserialize_binary(frame.payload);
    if (binary_result) {
        const auto& payload = *binary_result;
        // Convert raw bytes to base64 for database lookup
        key = base64_encode(payload.machine_key.data(), payload.machine_key.size());
        auth_key = payload.auth_key;
        hostname = payload.hostname;
        os = payload.os;
        arch = payload.arch;
        version = payload.version;
        LOG_DEBUG("WsControlSessionCoro: Parsed binary AUTH_REQUEST (auth_type={}, hostname={})",
                  static_cast<int>(payload.auth_type), hostname);
    } else {
        // Fall back to JSON
        auto json = frame.payload_json();
        if (json.is_null()) {
            LOG_WARN("WsControlSessionCoro: Invalid AUTH_REQUEST - not binary (error={}) and not JSON",
                     static_cast<int>(binary_result.error()));
            send_error(wire::ErrorCode::INVALID_MESSAGE, "Invalid auth request payload");
            return;
        }

        // Get machine key from JSON or query string
        key = machine_key_;
        if (json.as_object().contains("machine_key")) {
            key = std::string(json.at("machine_key").as_string());
        } else if (json.as_object().contains("machine_key_pub")) {
            key = std::string(json.at("machine_key_pub").as_string());
        }
        if (json.as_object().contains("auth_key")) {
            auth_key = std::string(json.at("auth_key").as_string());
        }
        if (json.as_object().contains("hostname")) {
            hostname = std::string(json.at("hostname").as_string());
        }
        if (json.as_object().contains("os")) {
            os = std::string(json.at("os").as_string());
        }
        if (json.as_object().contains("arch")) {
            arch = std::string(json.at("arch").as_string());
        }
        if (json.as_object().contains("version")) {
            version = std::string(json.at("version").as_string());
        }
        LOG_DEBUG("WsControlSessionCoro: Parsed JSON AUTH_REQUEST (hostname={})", hostname);
    }

    if (key.empty()) {
        LOG_WARN("WsControlSessionCoro: AUTH_REQUEST missing machine_key from {}", remote_address());
        send_error(wire::ErrorCode::INVALID_CREDENTIALS, "Machine key required");
        return;
    }

    machine_key_ = key;

    LOG_DEBUG("WsControlSessionCoro: Auth request - machine_key: {}..., auth_key: {}",
              key.substr(0, 10), auth_key.empty() ? "(empty)" : auth_key.substr(0, 8) + "...");

    try {

        // Look up node by machine key
        auto node_opt = db->get_node_by_machine_key(key);

        if (!node_opt) {
            // Node not registered - need auth_key to register
            if (auth_key.empty()) {
                LOG_WARN("WsControlSessionCoro: Unknown machine key without auth_key");
                send_error(wire::ErrorCode::NODE_NOT_AUTHORIZED, "Node not registered. Provide auth_key to register.");
                return;
            }

            // Validate auth_key
            auto auth_key_opt = db->get_auth_key_by_key(auth_key);
            if (!auth_key_opt || !db->is_auth_key_valid(*auth_key_opt)) {
                send_error(wire::ErrorCode::AUTHKEY_EXPIRED, "Invalid or expired auth key");
                return;
            }

            // Register new node
            Node new_node;
            new_node.network_id = auth_key_opt->network_id;
            new_node.machine_key_pub = key;
            new_node.hostname = hostname;
            new_node.name = hostname;
            new_node.os = os;
            new_node.arch = arch;
            new_node.version = version;

            new_node.authorized = true;
            new_node.online = true;

            // Allocate virtual IP
            new_node.virtual_ip = db->allocate_virtual_ip(auth_key_opt->network_id);
            if (new_node.virtual_ip.empty()) {
                send_error(wire::ErrorCode::INTERNAL_ERROR, "No available IP addresses");
                return;
            }

            uint32_t new_node_id = db->create_node(new_node);
            if (new_node_id == 0) {
                send_error(wire::ErrorCode::INTERNAL_ERROR, "Failed to register node");
                return;
            }

            db->increment_auth_key_usage(auth_key_opt->id);

            LOG_INFO("WsControlSessionCoro: Registered new node {} ({})", new_node_id, new_node.hostname);

            on_authenticated(new_node_id, auth_key_opt->network_id);
            virtual_ip_ = new_node.virtual_ip;
            send_config_update();
            return;
        }

        const Node& node = *node_opt;

        // Check authorization
        if (!node.authorized) {
            if (!auth_key.empty()) {
                auto auth_key_opt = db->get_auth_key_by_key(auth_key);
                if (auth_key_opt && db->is_auth_key_valid(*auth_key_opt) &&
                    auth_key_opt->network_id == node.network_id) {
                    Node updated_node = node;
                    updated_node.authorized = true;
                    db->update_node(updated_node);
                    db->increment_auth_key_usage(auth_key_opt->id);
                    LOG_INFO("WsControlSessionCoro: Node {} authorized via auth_key", node.id);
                } else {
                    send_error(wire::ErrorCode::AUTHKEY_EXPIRED, "Invalid auth key for this network");
                    return;
                }
            } else {
                send_error(wire::ErrorCode::NODE_NOT_AUTHORIZED, "Node pending authorization");
                return;
            }
        }

        // Authentication successful
        on_authenticated(node.id, node.network_id);
        virtual_ip_ = node.virtual_ip;

        // Update last seen and online status
        {
            Node updated_node = node;
            updated_node.online = true;
            updated_node.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            db->update_node(updated_node);
        }

        LOG_INFO("WsControlSessionCoro: Node {} ({}) authenticated", node.id, node.hostname);
        send_config_update();

    } catch (const std::exception& e) {
        LOG_ERROR("WsControlSessionCoro: Auth error: {}", e.what());
        send_error(wire::ErrorCode::INTERNAL_ERROR, e.what());
    }
}

void WsControlSessionCoro::handle_ping(const wire::Frame& frame) {
    if (!control_authenticated_) {
        send_error(wire::ErrorCode::NODE_NOT_AUTHORIZED, "Authentication required");
        return;
    }

    auto db = server_->get_database();

    // Update last seen
    auto node_opt = db->get_node(node_id());
    if (node_opt) {
        Node node = *node_opt;
        node.online = true;
        node.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        db->update_node(node);
    }

    // Send pong response
    boost::json::object pong_json;
    pong_json["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto pong_frame = wire::create_json_frame(wire::MessageType::PONG, pong_json);
    send_frame(pong_frame);
}

void WsControlSessionCoro::handle_latency_report(const wire::Frame& frame) {
    if (!control_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    auto db = server_->get_database();
    auto path_service = server_->get_path_service();

    try {
        auto entries = json.at("entries").as_array();
        LOG_DEBUG("WsControlSessionCoro: Node {} reported {} latency measurements",
                  node_id(), entries.size());

        for (const auto& entry : entries) {
            std::string dst_type = std::string(entry.at("dst_type").as_string());
            uint32_t dst_id = static_cast<uint32_t>(entry.at("dst_id").as_int64());
            uint32_t rtt_ms = static_cast<uint32_t>(entry.at("rtt_ms").as_int64());

            if (path_service && dst_type == "relay") {
                path_service->update_node_relay_latency(node_id(), dst_id, rtt_ms);
            }
            db->update_latency("node", node_id(), dst_type, dst_id, rtt_ms);
        }
    } catch (const std::exception& e) {
        LOG_DEBUG("WsControlSessionCoro: Failed to parse latency report: {}", e.what());
    }
}

void WsControlSessionCoro::handle_endpoint_report(const wire::Frame& frame) {
    if (!control_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    auto db = server_->get_database();

    try {
        if (!json.as_object().contains("endpoints")) return;

        auto endpoints_json = json.at("endpoints").as_array();
        LOG_DEBUG("WsControlSessionCoro: Node {} reported {} endpoints",
                  node_id(), endpoints_json.size());

        std::vector<NodeEndpoint> endpoints;
        for (const auto& ep : endpoints_json) {
            NodeEndpoint nep;
            nep.node_id = node_id();
            nep.ip = std::string(ep.at("ip").as_string());
            nep.port = static_cast<uint16_t>(ep.at("port").as_int64());
            nep.type = ep.as_object().contains("type") ?
                       std::string(ep.at("type").as_string()) : "stun";
            endpoints.push_back(nep);
        }

        if (!endpoints.empty()) {
            db->update_node_endpoints(node_id(), endpoints);
        }
    } catch (const std::exception& e) {
        LOG_DEBUG("WsControlSessionCoro: Failed to parse endpoint report: {}", e.what());
    }
}

void WsControlSessionCoro::handle_p2p_request(const wire::Frame& frame) {
    if (!control_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    auto db = server_->get_database();

    try {
        uint32_t peer_node_id = static_cast<uint32_t>(json.at("peer_node_id").as_int64());

        LOG_INFO("WsControlSessionCoro: Node {} requesting P2P to peer {}",
                 node_id(), peer_node_id);

        auto peer_endpoints = db->get_node_endpoints(peer_node_id);

        boost::json::object response;
        response["peer_node_id"] = peer_node_id;

        if (peer_endpoints.empty()) {
            response["success"] = false;
            response["error"] = "no_endpoints";
        } else {
            response["success"] = true;
            boost::json::array ep_array;
            for (const auto& ep : peer_endpoints) {
                boost::json::object ep_obj;
                ep_obj["ip"] = ep.ip;
                ep_obj["port"] = ep.port;
                ep_obj["type"] = ep.type;
                ep_array.push_back(ep_obj);
            }
            response["endpoints"] = ep_array;
            response["nat_type"] = static_cast<int>(wire::NATType::UNKNOWN);
        }

        auto resp_frame = wire::create_json_frame(wire::MessageType::P2P_ENDPOINT, response);
        send_frame(resp_frame);

    } catch (const std::exception& e) {
        LOG_DEBUG("WsControlSessionCoro: Failed to parse P2P request: {}", e.what());
    }
}

void WsControlSessionCoro::handle_config_ack(const wire::Frame& frame) {
    if (!control_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    try {
        uint64_t version = static_cast<uint64_t>(json.at("version").as_int64());
        LOG_DEBUG("WsControlSessionCoro: Node {} acknowledged config version {}",
                  node_id(), version);
    } catch (const std::exception& e) {
        LOG_DEBUG("WsControlSessionCoro: Failed to parse config ack: {}", e.what());
    }
}

void WsControlSessionCoro::handle_route_announce(const wire::Frame& frame) {
    if (!control_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    LOG_DEBUG("WsControlSessionCoro: Node {} announcing route", node_id());
    // TODO: Process route announcement
}

void WsControlSessionCoro::handle_route_withdraw(const wire::Frame& frame) {
    if (!control_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    LOG_DEBUG("WsControlSessionCoro: Node {} withdrawing route", node_id());
    // TODO: Process route withdrawal
}

void WsControlSessionCoro::on_authenticated(uint32_t node_id, uint32_t network_id) {
    control_authenticated_ = true;
    set_authenticated(node_id, network_id);

    // Register with session manager
    server_->get_session_manager()->add_control_session(node_id, network_id,
        std::dynamic_pointer_cast<WsSessionCoro>(shared_from_this()));

    LOG_INFO("WsControlSessionCoro: Node {} authenticated (network {})", node_id, network_id);
}

void WsControlSessionCoro::send_error(wire::ErrorCode code, const std::string& message) {
    LOG_DEBUG("WsControlSessionCoro: Sending AUTH_RESPONSE error (code={}, msg={})",
              static_cast<int>(code), message);

    wire::AuthResponsePayload payload;
    payload.success = false;
    payload.error_code = static_cast<uint16_t>(code);
    payload.error_message = message;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::AUTH_RESPONSE, std::move(binary));
    send_frame(frame);

    LOG_DEBUG("WsControlSessionCoro: AUTH_RESPONSE error sent ({} bytes)", frame.payload.size());
}

void WsControlSessionCoro::send_config_update() {
    auto db = server_->get_database();
    auto path_service = server_->get_path_service();
    uint32_t nid = node_id();
    uint32_t netid = network_id();

    LOG_DEBUG("WsControlSessionCoro: Preparing config update for node {} (network {})", nid, netid);

    // --- Step 1: Send AUTH_RESPONSE with success ---
    {
        wire::AuthResponsePayload auth_resp;
        auth_resp.success = true;
        auth_resp.node_id = nid;
        auth_resp.network_id = netid;

        // Convert virtual_ip string to uint32_t
        struct in_addr addr;
        if (inet_pton(AF_INET, virtual_ip_.c_str(), &addr) == 1) {
            auth_resp.virtual_ip_int = addr.s_addr;  // Already in network byte order
        }
        auth_resp.virtual_ip = virtual_ip_;

        // Generate tokens
        auto now = std::chrono::system_clock::now();
        auto exp = now + std::chrono::hours(24);
        int64_t exp_ts = std::chrono::duration_cast<std::chrono::seconds>(exp.time_since_epoch()).count();

        auth_resp.auth_token = "auth." + std::to_string(nid) + "." + std::to_string(exp_ts);
        auth_resp.relay_token = "relay." + std::to_string(nid) + "." + std::to_string(exp_ts);

        auto auth_binary = auth_resp.serialize_binary();
        auto auth_frame = wire::Frame::create(wire::MessageType::AUTH_RESPONSE, std::move(auth_binary));
        send_frame(auth_frame);

        LOG_DEBUG("WsControlSessionCoro: AUTH_RESPONSE sent (node={}, ip={}, {} bytes)",
                  nid, virtual_ip_, auth_frame.payload.size());
    }

    // --- Step 2: Send CONFIG with network data ---
    {
        wire::ConfigPayload config;
        config.version = 1;
        config.network_id = netid;

        // Get network info
        auto network_opt = db->get_network(netid);
        if (network_opt) {
            const Network& net = *network_opt;
            config.network_name = net.name;
            config.subnet = net.subnet;

            // Parse subnet CIDR
            auto slash_pos = net.subnet.find('/');
            if (slash_pos != std::string::npos) {
                std::string subnet_ip = net.subnet.substr(0, slash_pos);
                struct in_addr subnet_addr;
                if (inet_pton(AF_INET, subnet_ip.c_str(), &subnet_addr) == 1) {
                    config.subnet_ip = subnet_addr.s_addr;
                }
                config.subnet_mask = static_cast<uint8_t>(std::stoi(net.subnet.substr(slash_pos + 1)));
            }
        }

        // Get relay servers
        auto servers = db->list_enabled_servers();
        for (const auto& s : servers) {
            wire::RelayInfo relay;
            relay.server_id = s.id;
            relay.name = s.name;
            relay.region = s.region;
            relay.url = s.url;
            config.relays.push_back(relay);
        }

        // Get peer list
        auto nodes = db->list_nodes(netid);
        for (const auto& n : nodes) {
            if (n.id == nid) continue;
            if (!n.authorized) continue;

            wire::PeerInfo peer;
            peer.node_id = n.id;
            peer.name = n.hostname;
            peer.virtual_ip = n.virtual_ip;
            peer.node_key_pub = n.node_key_pub;
            peer.online = n.online;
            config.peers.push_back(peer);
        }

        // Get subnet routes
        auto all_routes = db->get_all_routes(netid);
        for (const auto& route : all_routes) {
            if (!route.enabled) continue;

            wire::RouteInfo ri;
            ri.from_cidr(route.cidr);
            ri.gateway_node_id = route.node_id;
            ri.priority = static_cast<uint16_t>(route.priority);
            ri.weight = static_cast<uint16_t>(route.weight);
            ri.enabled = route.enabled;
            config.routes.push_back(ri);
        }

        auto config_binary = config.serialize_binary();
        auto config_frame = wire::Frame::create(wire::MessageType::CONFIG, std::move(config_binary));
        send_frame(config_frame);

        LOG_DEBUG("WsControlSessionCoro: CONFIG sent ({} peers, {} relays, {} routes, {} bytes)",
                  config.peers.size(), config.relays.size(), config.routes.size(),
                  config_frame.payload.size());
    }
}

// ============================================================================
// WsServerSessionCoro Implementation
// ============================================================================

WsServerSessionCoro::WsServerSessionCoro(net::io_context& ioc, tcp::socket socket,
                                           WsControllerServerCoro* server,
                                           const std::string& query_string)
    : WsSessionCoro(ioc, std::move(socket))
    , server_(server)
    , query_string_(query_string)
{}

WsServerSessionCoro::~WsServerSessionCoro() = default;

net::awaitable<void> WsServerSessionCoro::on_connected() {
    LOG_DEBUG("WsServerSessionCoro: Connection established from {}", remote_address());
    co_return;
}

net::awaitable<void> WsServerSessionCoro::process_frame(const wire::Frame& frame) {
    // Dispatch based on frame type
    switch (frame.header.type) {
        case wire::MessageType::SERVER_REGISTER:
            handle_server_register(frame);
            break;

        case wire::MessageType::PING:
        case wire::MessageType::SERVER_HEARTBEAT:
            handle_ping(frame);
            break;

        case wire::MessageType::SERVER_LATENCY_REPORT:
            handle_stats_report(frame);
            break;

        case wire::MessageType::MESH_FORWARD:
            handle_mesh_forward(frame);
            break;

        default:
            LOG_DEBUG("WsServerSessionCoro: Unhandled message type: {} (0x{:02x})",
                      wire::message_type_to_string(frame.header.type),
                      static_cast<int>(frame.header.type));
            break;
    }
    co_return;
}

net::awaitable<void> WsServerSessionCoro::on_disconnected(const std::string& reason) {
    LOG_DEBUG("WsServerSessionCoro: Disconnected (server {}, reason: {})", server_id_, reason);

    if (server_authenticated_ && server_id_ > 0) {
        server_->get_session_manager()->remove_server_session(server_id_);
    }

    co_return;
}

void WsServerSessionCoro::handle_server_register(const wire::Frame& frame) {
    auto json = frame.payload_json();
    if (json.is_null()) {
        send_error(wire::ErrorCode::INVALID_MESSAGE, "Invalid register payload");
        return;
    }

    auto db = server_->get_database();
    const auto& config = server_->get_config();

    try {
        // Verify server token
        std::string token;
        if (json.as_object().contains("token")) {
            token = std::string(json.at("token").as_string());
        } else if (json.as_object().contains("server_token")) {
            token = std::string(json.at("server_token").as_string());
        }

        if (!config.server_token.empty() && token != config.server_token) {
            LOG_WARN("WsServerSessionCoro: Invalid server token");
            send_error(wire::ErrorCode::INVALID_TOKEN, "Invalid server token");
            return;
        }

        server_name_ = json.as_object().contains("name") ?
                       std::string(json.at("name").as_string()) : "unknown";
        std::string region = json.as_object().contains("region") ?
                             std::string(json.at("region").as_string()) : "unknown";

        std::string url;
        if (json.as_object().contains("url")) {
            url = std::string(json.at("url").as_string());
        } else if (json.as_object().contains("relay_url")) {
            url = std::string(json.at("relay_url").as_string());
        } else if (json.as_object().contains("external_url")) {
            url = std::string(json.at("external_url").as_string());
        }

        std::string stun_ip;
        uint16_t stun_port = 3478;
        if (json.as_object().contains("stun_ip")) {
            stun_ip = std::string(json.at("stun_ip").as_string());
        }
        if (json.as_object().contains("stun_port")) {
            stun_port = static_cast<uint16_t>(json.at("stun_port").as_int64());
        }

        LOG_INFO("WsServerSessionCoro: Server '{}' registering from region '{}'",
                 server_name_, region);

        // Check if server already exists by name
        bool found = false;
        auto servers = db->list_servers();
        for (const auto& s : servers) {
            if (s.name == server_name_) {
                server_id_ = s.id;
                found = true;
                break;
            }
        }

        Server server;
        server.name = server_name_;
        server.region = region;
        server.url = url;
        server.stun_ip = stun_ip;
        server.stun_port = stun_port;
        server.enabled = true;
        server.type = "builtin";

        if (found) {
            server.id = server_id_;
            db->update_server(server);
        } else {
            server_id_ = db->create_server(server);
        }

        on_server_authenticated(server_id_);

        LOG_INFO("WsServerSessionCoro: Server '{}' registered with ID {}",
                 server_name_, server_id_);

        // Send response
        boost::json::object response;
        response["success"] = true;
        response["server_id"] = server_id_;

        auto resp_frame = wire::create_json_frame(wire::MessageType::SERVER_REGISTER_RESP, response);
        send_frame(resp_frame);

    } catch (const std::exception& e) {
        LOG_ERROR("WsServerSessionCoro: Register error: {}", e.what());
        send_error(wire::ErrorCode::INTERNAL_ERROR, e.what());
    }
}

void WsServerSessionCoro::handle_ping(const wire::Frame& frame) {
    if (!server_authenticated_) {
        return;
    }

    auto db = server_->get_database();
    db->update_server_heartbeat(server_id_);

    boost::json::object pong_json;
    pong_json["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto pong_frame = wire::create_json_frame(wire::MessageType::PONG, pong_json);
    send_frame(pong_frame);
}

void WsServerSessionCoro::handle_stats_report(const wire::Frame& frame) {
    if (!server_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    try {
        uint32_t active_connections = 0;
        uint64_t bytes_relayed = 0;

        if (json.as_object().contains("active_connections")) {
            active_connections = static_cast<uint32_t>(json.at("active_connections").as_int64());
        }
        if (json.as_object().contains("bytes_relayed")) {
            bytes_relayed = static_cast<uint64_t>(json.at("bytes_relayed").as_int64());
        }

        LOG_DEBUG("WsServerSessionCoro: Server {} stats: {} connections, {} bytes",
                  server_id_, active_connections, bytes_relayed);
        // TODO: Store stats
    } catch (const std::exception& e) {
        LOG_DEBUG("WsServerSessionCoro: Failed to parse stats: {}", e.what());
    }
}

void WsServerSessionCoro::handle_mesh_forward(const wire::Frame& frame) {
    if (!server_authenticated_) {
        return;
    }

    auto json = frame.payload_json();
    if (json.is_null()) return;

    try {
        uint32_t src_node_id = static_cast<uint32_t>(json.at("src_node_id").as_int64());
        uint32_t dst_node_id = static_cast<uint32_t>(json.at("dst_node_id").as_int64());

        if (src_node_id == 0 || dst_node_id == 0) {
            LOG_WARN("WsServerSessionCoro: Invalid mesh_forward - missing node IDs");
            return;
        }

        if (!json.as_object().contains("target_relays")) {
            LOG_DEBUG("WsServerSessionCoro: No target relays for mesh_forward");
            return;
        }

        auto target_relays = json.at("target_relays").as_array();
        auto payload = json.as_object().contains("payload") ?
                       json.at("payload") : boost::json::value{};

        // Build forward message for target relay
        boost::json::object forward_json;
        forward_json["src_node_id"] = src_node_id;
        forward_json["dst_node_id"] = dst_node_id;
        forward_json["from_relay_id"] = server_id_;
        forward_json["payload"] = payload;

        auto forward_frame = wire::create_json_frame(wire::MessageType::MESH_FORWARD, forward_json);

        int forwarded = 0;
        for (const auto& relay : target_relays) {
            uint32_t relay_id = static_cast<uint32_t>(relay.as_int64());
            auto session = server_->get_session_manager()->get_server_session(relay_id);
            if (session) {
                session->send_frame(forward_frame);
                forwarded++;
            }
        }

        LOG_DEBUG("WsServerSessionCoro: Mesh forwarded {} -> {} via {} relays",
                  src_node_id, dst_node_id, forwarded);

    } catch (const std::exception& e) {
        LOG_DEBUG("WsServerSessionCoro: Failed to parse mesh_forward: {}", e.what());
    }
}

void WsServerSessionCoro::on_server_authenticated(uint32_t server_id) {
    server_authenticated_ = true;
    server_id_ = server_id;

    // Register with session manager
    server_->get_session_manager()->add_server_session(server_id,
        std::dynamic_pointer_cast<WsSessionCoro>(shared_from_this()));

    LOG_INFO("WsServerSessionCoro: Server {} authenticated", server_id);
}

void WsServerSessionCoro::send_error(wire::ErrorCode code, const std::string& message) {
    boost::json::object error_json;
    error_json["success"] = false;
    error_json["error_code"] = static_cast<int>(code);
    error_json["error_message"] = message;

    auto frame = wire::create_json_frame(wire::MessageType::ERROR_MSG, error_json);
    send_frame(frame);
}

} // namespace edgelink::controller

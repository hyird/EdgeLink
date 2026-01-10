#include "controller/api/ws_server_coro.hpp"
#include "controller/builtin_relay.hpp"
#include "common/log.hpp"
#include "common/frame.hpp"
#include "common/binary_codec.hpp"

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

void WsSessionManagerCoro::broadcast_to_network(uint32_t network_id, const std::vector<uint8_t>& data) {
    std::shared_lock lock(control_mutex_);
    for (const auto& [node_id, info] : control_sessions_) {
        if (info.network_id == network_id) {
            if (auto session = info.session.lock()) {
                session->send_binary(data);
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
        // Built-in relay session
        if (builtin_relay_ && builtin_relay_->is_enabled()) {
            LOG_DEBUG("WsControllerServerCoro: Creating relay session");
            return std::make_shared<WsBuiltinRelaySessionCoro>(ioc, std::move(socket), this);
        } else {
            LOG_WARN("WsControllerServerCoro: Relay path requested but built-in relay not enabled");
            return nullptr;
        }
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

    auto result = wire::AuthRequestPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid AUTH_REQUEST: error={}",
                 static_cast<int>(result.error()));
        send_error(wire::ErrorCode::INVALID_MESSAGE, "Invalid auth request payload");
        return;
    }

    const auto& payload = *result;
    // Convert raw bytes to base64 for database lookup
    std::string key = base64_encode(payload.machine_key.data(), payload.machine_key.size());
    std::string auth_key = payload.auth_key;
    std::string hostname = payload.hostname;
    std::string os = payload.os;
    std::string arch = payload.arch;
    std::string version = payload.version;
    LOG_DEBUG("WsControlSessionCoro: Parsed AUTH_REQUEST (auth_type={}, hostname={})",
              static_cast<int>(payload.auth_type), hostname);

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

    // Send pong response (binary)
    wire::PongPayload pong;
    pong.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    auto binary = pong.serialize_binary();
    auto pong_frame = wire::Frame::create(wire::MessageType::PONG, std::move(binary));
    send_frame(pong_frame);
    LOG_DEBUG("WsControlSessionCoro: PONG sent to node {}", node_id());
}

void WsControlSessionCoro::handle_latency_report(const wire::Frame& frame) {
    if (!control_authenticated_) {
        LOG_WARN("WsControlSessionCoro: LATENCY_REPORT received but not authenticated");
        return;
    }

    auto db = server_->get_database();
    auto path_service = server_->get_path_service();

    auto result = wire::LatencyReportPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid LATENCY_REPORT: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    const auto& payload = *result;
    LOG_DEBUG("WsControlSessionCoro: Node {} reported {} latency measurements",
              node_id(), payload.entries.size());

    for (const auto& entry : payload.entries) {
        std::string dst_type = (entry.dst_type == 0) ? "relay" : "node";
        if (path_service && entry.dst_type == 0) {
            path_service->update_node_relay_latency(node_id(), entry.dst_id, entry.rtt_ms);
        }
        db->update_latency("node", node_id(), dst_type, entry.dst_id, entry.rtt_ms);
    }
}

void WsControlSessionCoro::handle_endpoint_report(const wire::Frame& frame) {
    if (!control_authenticated_) {
        LOG_WARN("WsControlSessionCoro: P2P_STATUS received but not authenticated");
        return;
    }

    auto db = server_->get_database();

    auto result = wire::P2PStatusPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid P2P_STATUS: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    const auto& payload = *result;
    LOG_DEBUG("WsControlSessionCoro: Node {} reported P2P status: peer={}, connected={}, rtt={}ms",
              node_id(), payload.peer_node_id, payload.connected, payload.rtt_ms);

    // Store endpoint for this peer
    if (payload.endpoint_ip != 0) {
        std::vector<NodeEndpoint> endpoints;
        NodeEndpoint nep;
        nep.node_id = node_id();
        // Convert IP from network byte order to string
        struct in_addr addr;
        addr.s_addr = payload.endpoint_ip;
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            nep.ip = buf;
        }
        nep.port = payload.endpoint_port;
        nep.type = "p2p";
        endpoints.push_back(nep);
        db->update_node_endpoints(node_id(), endpoints);
    }
}

void WsControlSessionCoro::handle_p2p_request(const wire::Frame& frame) {
    if (!control_authenticated_) {
        LOG_WARN("WsControlSessionCoro: P2P_INIT received but not authenticated");
        return;
    }

    auto db = server_->get_database();

    auto result = wire::P2PInitPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid P2P_INIT: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    uint32_t peer_node_id = result->peer_node_id;
    LOG_INFO("WsControlSessionCoro: Node {} requesting P2P to peer {}",
             node_id(), peer_node_id);

    // Build binary response
    wire::P2PEndpointPayload response;
    response.peer_node_id = peer_node_id;
    response.nat_type = wire::NATType::UNKNOWN;

    auto peer_endpoints = db->get_node_endpoints(peer_node_id);
    if (peer_endpoints.empty()) {
        LOG_DEBUG("WsControlSessionCoro: P2P_ENDPOINT response - peer {} has no endpoints", peer_node_id);
        // Send empty endpoint list
    } else {
        for (const auto& ep : peer_endpoints) {
            wire::Endpoint wire_ep;
            wire_ep.ip = ep.ip;
            wire_ep.port = ep.port;
            wire_ep.type = wire::EndpointType::STUN;  // Default type
            wire_ep.priority = 10;
            response.endpoints.push_back(wire_ep);
        }
        LOG_DEBUG("WsControlSessionCoro: P2P_ENDPOINT response - peer {} has {} endpoints",
                  peer_node_id, response.endpoints.size());
    }

    auto binary = response.serialize_binary();
    auto resp_frame = wire::Frame::create(wire::MessageType::P2P_ENDPOINT, std::move(binary));
    send_frame(resp_frame);
    LOG_DEBUG("WsControlSessionCoro: P2P_ENDPOINT sent ({} bytes)", resp_frame.payload.size());
}

void WsControlSessionCoro::handle_config_ack(const wire::Frame& frame) {
    if (!control_authenticated_) {
        LOG_WARN("WsControlSessionCoro: CONFIG_ACK received but not authenticated");
        return;
    }

    auto result = wire::ConfigAckPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid CONFIG_ACK: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    LOG_DEBUG("WsControlSessionCoro: Node {} acknowledged config version {}",
              node_id(), result->version);
}

void WsControlSessionCoro::handle_route_announce(const wire::Frame& frame) {
    if (!control_authenticated_) {
        LOG_WARN("WsControlSessionCoro: ROUTE_ANNOUNCE received but not authenticated");
        return;
    }

    auto result = wire::RouteAnnouncePayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid ROUTE_ANNOUNCE: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    LOG_DEBUG("WsControlSessionCoro: Node {} announcing {} routes from gateway={}",
              node_id(), result->routes.size(), result->gateway_node_id);
    // TODO: Process route announcement
}

void WsControlSessionCoro::handle_route_withdraw(const wire::Frame& frame) {
    if (!control_authenticated_) {
        LOG_WARN("WsControlSessionCoro: ROUTE_WITHDRAW received but not authenticated");
        return;
    }

    // Uses RouteAnnouncePayload format
    auto result = wire::RouteAnnouncePayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsControlSessionCoro: Invalid ROUTE_WITHDRAW: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    LOG_DEBUG("WsControlSessionCoro: Node {} withdrawing {} routes from gateway={}",
              node_id(), result->routes.size(), result->gateway_node_id);
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

        // Generate proper JWT relay token via BuiltinRelay
        auto* builtin_relay = server_->get_builtin_relay();
        if (builtin_relay) {
            auth_resp.relay_token = builtin_relay->session_manager()->create_relay_token(nid, netid);
        } else {
            // Fallback if no builtin relay (shouldn't happen in normal operation)
            auth_resp.relay_token = "relay." + std::to_string(nid) + "." + std::to_string(exp_ts);
        }

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

            // Parse subnet CIDR using binary_codec helper
            auto cidr_result = wire::parse_cidr_v4(net.subnet);
            if (cidr_result) {
                config.subnet_ip = cidr_result->prefix;
                config.subnet_mask = cidr_result->prefix_len;
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
    auto db = server_->get_database();
    const auto& config = server_->get_config();

    auto result = wire::ServerRegisterPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsServerSessionCoro: Invalid SERVER_REGISTER: error={}",
                 static_cast<int>(result.error()));
        send_error(wire::ErrorCode::INVALID_MESSAGE, "Invalid register payload");
        return;
    }

    const auto& payload = *result;
    std::string token = payload.server_token;
    std::string name = payload.name;
    std::string region = payload.region;
    std::string url = payload.relay_url;
    std::string stun_ip = payload.stun_ip;
    uint16_t stun_port = payload.stun_port;
    LOG_DEBUG("WsServerSessionCoro: Parsed SERVER_REGISTER (name={}, region={})", name, region);

    // Verify server token
    if (!config.server_token.empty() && token != config.server_token) {
        LOG_WARN("WsServerSessionCoro: Invalid server token from {}", remote_address());
        send_error(wire::ErrorCode::INVALID_TOKEN, "Invalid server token");
        return;
    }

    server_name_ = name;
    LOG_INFO("WsServerSessionCoro: Server '{}' registering from region '{}'", name, region);

    // Check if server already exists by name
    bool found = false;
    auto servers = db->list_servers();
    for (const auto& s : servers) {
        if (s.name == name) {
            server_id_ = s.id;
            found = true;
            break;
        }
    }

    Server server;
    server.name = name;
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

    LOG_INFO("WsServerSessionCoro: Server '{}' registered with ID {}", name, server_id_);

    // Send binary response
    wire::ServerRegisterRespPayload response;
    response.success = true;
    response.server_id = server_id_;

    auto binary = response.serialize_binary();
    auto resp_frame = wire::Frame::create(wire::MessageType::SERVER_REGISTER_RESP, std::move(binary));
    send_frame(resp_frame);
    LOG_DEBUG("WsServerSessionCoro: SERVER_REGISTER_RESP sent ({} bytes)", resp_frame.payload.size());
}

void WsServerSessionCoro::handle_ping(const wire::Frame& frame) {
    if (!server_authenticated_) {
        LOG_WARN("WsServerSessionCoro: PING received but not authenticated");
        return;
    }

    auto db = server_->get_database();
    db->update_server_heartbeat(server_id_);

    // Send binary pong response
    wire::PongPayload pong;
    pong.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    auto binary = pong.serialize_binary();
    auto pong_frame = wire::Frame::create(wire::MessageType::PONG, std::move(binary));
    send_frame(pong_frame);
    LOG_DEBUG("WsServerSessionCoro: PONG sent to server {}", server_id_);
}

void WsServerSessionCoro::handle_stats_report(const wire::Frame& frame) {
    if (!server_authenticated_) {
        LOG_WARN("WsServerSessionCoro: SERVER_LATENCY_REPORT received but not authenticated");
        return;
    }

    auto result = wire::ServerStatsPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsServerSessionCoro: Invalid SERVER_LATENCY_REPORT: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    LOG_DEBUG("WsServerSessionCoro: Server {} stats: {} connections, {} bytes",
              server_id_, result->active_connections, result->bytes_relayed);

    // TODO: Store stats
}

void WsServerSessionCoro::handle_mesh_forward(const wire::Frame& frame) {
    if (!server_authenticated_) {
        LOG_WARN("WsServerSessionCoro: MESH_FORWARD received but not authenticated");
        return;
    }

    auto result = wire::MeshForwardPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsServerSessionCoro: Invalid MESH_FORWARD: error={}",
                 static_cast<int>(result.error()));
        return;
    }

    const auto& payload = *result;
    LOG_DEBUG("WsServerSessionCoro: MESH_FORWARD from relay {}: dst_node={}, ttl={}",
              payload.src_relay_id, payload.dst_node_id, payload.ttl);

    // Forward to target relay - for now, just log
    // TODO: Implement actual mesh forwarding logic
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
    LOG_DEBUG("WsServerSessionCoro: Sending ERROR (code={}, msg={})",
              static_cast<int>(code), message);

    wire::ErrorPayload error;
    error.code = static_cast<uint16_t>(code);
    error.message = message;

    auto binary = error.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::ERROR_MSG, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("WsServerSessionCoro: ERROR sent ({} bytes)", frame.payload.size());
}

// ============================================================================
// WsBuiltinRelaySessionCoro Implementation
// ============================================================================

WsBuiltinRelaySessionCoro::WsBuiltinRelaySessionCoro(net::io_context& ioc, tcp::socket socket,
                                                       WsControllerServerCoro* server)
    : WsSessionCoro(ioc, std::move(socket))
    , server_(server)
{}

WsBuiltinRelaySessionCoro::~WsBuiltinRelaySessionCoro() = default;

net::awaitable<void> WsBuiltinRelaySessionCoro::on_connected() {
    LOG_DEBUG("WsBuiltinRelaySessionCoro: Connection established from {}", remote_address());

    auto* relay = server_->get_builtin_relay();
    if (relay) {
        relay->stats().connections_total++;
        relay->stats().connections_active++;
    }

    co_return;
}

net::awaitable<void> WsBuiltinRelaySessionCoro::process_frame(const wire::Frame& frame) {
    switch (frame.header.type) {
        case wire::MessageType::RELAY_AUTH:
            co_await handle_relay_auth(frame);
            break;

        case wire::MessageType::DATA:
            co_await handle_data(frame);
            break;

        case wire::MessageType::PING:
            co_await handle_ping(frame);
            break;

        default:
            LOG_DEBUG("WsBuiltinRelaySessionCoro: Unhandled message type: {} (0x{:02x})",
                      wire::message_type_to_string(frame.header.type),
                      static_cast<int>(frame.header.type));
            break;
    }
    co_return;
}

net::awaitable<void> WsBuiltinRelaySessionCoro::on_disconnected(const std::string& reason) {
    LOG_DEBUG("WsBuiltinRelaySessionCoro: Disconnected (node {}, reason: {})", node_id(), reason);

    auto* relay = server_->get_builtin_relay();
    if (relay) {
        if (relay_authenticated_ && node_id() > 0) {
            relay->session_manager()->remove_session(node_id());
        }
        relay->stats().connections_active--;
    }

    co_return;
}

net::awaitable<void> WsBuiltinRelaySessionCoro::handle_relay_auth(const wire::Frame& frame) {
    auto* relay = server_->get_builtin_relay();
    if (!relay) {
        send_error("NO_RELAY", "Built-in relay not available");
        co_return;
    }

    auto result = wire::RelayAuthPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("WsBuiltinRelaySessionCoro: Invalid RELAY_AUTH: error={}",
                 static_cast<int>(result.error()));
        send_auth_response(false, 0, "Invalid auth payload");
        relay->stats().auth_failures++;
        co_return;
    }

    std::string token = result->relay_token;
    LOG_DEBUG("WsBuiltinRelaySessionCoro: Parsed RELAY_AUTH");

    if (token.empty()) {
        LOG_WARN("WsBuiltinRelaySessionCoro: Missing relay token");
        send_auth_response(false, 0, "Missing relay token");
        relay->stats().auth_failures++;
        co_return;
    }

    uint32_t nid = 0;
    std::string vip;

    if (!relay->session_manager()->validate_relay_token(token, nid, vip)) {
        LOG_WARN("WsBuiltinRelaySessionCoro: Invalid relay token");
        send_auth_response(false, 0, "Invalid relay token");
        relay->stats().auth_failures++;
        co_return;
    }

    // Authentication successful
    relay_authenticated_ = true;
    virtual_ip_ = vip;
    set_authenticated(nid, 0);  // network_id not tracked for relay sessions

    // Register with session manager - store pointer to this session
    relay->session_manager()->add_session(nid, this);

    LOG_INFO("WsBuiltinRelaySessionCoro: Node {} authenticated for relay", nid);
    send_auth_response(true, nid);

    co_return;
}

net::awaitable<void> WsBuiltinRelaySessionCoro::handle_data(const wire::Frame& frame) {
    if (!relay_authenticated_) {
        LOG_WARN("WsBuiltinRelaySessionCoro: DATA received but not authenticated");
        co_return;
    }

    auto* relay = server_->get_builtin_relay();
    if (!relay) {
        co_return;
    }

    // Parse DATA frame - expects: src_node_id(4) + dst_node_id(4) + payload
    if (frame.payload.size() < 8) {
        LOG_WARN("WsBuiltinRelaySessionCoro: DATA frame too short ({} bytes)", frame.payload.size());
        co_return;
    }

    // Parse node IDs (big-endian)
    uint32_t src_node_id = (static_cast<uint32_t>(frame.payload[0]) << 24) |
                           (static_cast<uint32_t>(frame.payload[1]) << 16) |
                           (static_cast<uint32_t>(frame.payload[2]) << 8) |
                           static_cast<uint32_t>(frame.payload[3]);

    uint32_t dst_node_id = (static_cast<uint32_t>(frame.payload[4]) << 24) |
                           (static_cast<uint32_t>(frame.payload[5]) << 16) |
                           (static_cast<uint32_t>(frame.payload[6]) << 8) |
                           static_cast<uint32_t>(frame.payload[7]);

    // Verify sender
    if (src_node_id != node_id()) {
        LOG_WARN("WsBuiltinRelaySessionCoro: Spoofed src_node_id {} from node {}",
                 src_node_id, node_id());
        co_return;
    }

    // Extract actual data payload
    std::vector<uint8_t> data(frame.payload.begin() + 8, frame.payload.end());

    // Forward to destination
    if (!relay->forward_data(dst_node_id, data, src_node_id)) {
        LOG_DEBUG("WsBuiltinRelaySessionCoro: Failed to forward to node {} (offline?)", dst_node_id);
    }

    co_return;
}

net::awaitable<void> WsBuiltinRelaySessionCoro::handle_ping(const wire::Frame& frame) {
    uint64_t timestamp = 0;

    // MeshPingPayload has timestamp field
    auto result = wire::MeshPingPayload::deserialize_binary(frame.payload);
    if (result) {
        timestamp = result->timestamp;
    }

    send_pong(timestamp);
    co_return;
}

void WsBuiltinRelaySessionCoro::send_auth_response(bool success, uint32_t nid, const std::string& error) {
    wire::AuthResponsePayload payload;
    payload.success = success;
    payload.node_id = nid;
    payload.error_message = error;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::RELAY_AUTH_RESP, std::move(binary));
    send_frame(frame);

    LOG_DEBUG("WsBuiltinRelaySessionCoro: RELAY_AUTH_RESP sent (success={}, node={}, {} bytes)",
              success, nid, frame.payload.size());
}

void WsBuiltinRelaySessionCoro::send_pong(uint64_t timestamp) {
    wire::PongPayload payload;
    payload.timestamp = timestamp;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::PONG, std::move(binary));
    send_frame(frame);

    LOG_DEBUG("WsBuiltinRelaySessionCoro: PONG sent");
}

void WsBuiltinRelaySessionCoro::send_error(const std::string& code, const std::string& message) {
    wire::ErrorPayload payload;
    if (code == "AUTH_REQUIRED") {
        payload.code = static_cast<uint16_t>(wire::ErrorCode::NODE_NOT_AUTHORIZED);
    } else if (code == "NO_RELAY") {
        payload.code = static_cast<uint16_t>(wire::ErrorCode::INTERNAL_ERROR);
    } else {
        payload.code = static_cast<uint16_t>(wire::ErrorCode::INTERNAL_ERROR);
    }
    payload.message = message;
    payload.details = code;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::ERROR_MSG, std::move(binary));
    send_frame(frame);

    LOG_DEBUG("WsBuiltinRelaySessionCoro: ERROR sent (code={}, msg={})", code, message);
}

} // namespace edgelink::controller

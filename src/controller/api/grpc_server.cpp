#include "controller/api/grpc_server.hpp"
#include "controller/builtin_relay.hpp"
#include "common/log.hpp"
#include "common/jwt.hpp"

#include <fstream>

namespace edgelink::controller {

// ============================================================================
// Control Stream Handler Implementation
// ============================================================================

ControlStreamHandler::ControlStreamHandler(
    grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream,
    std::shared_ptr<Database> db,
    const std::string& jwt_secret,
    GrpcSessionManager* session_manager)
    : stream_(stream)
    , db_(db)
    , jwt_secret_(jwt_secret)
    , session_manager_(session_manager)
{}

void ControlStreamHandler::run() {
    edgelink::ControlMessage msg;

    while (stream_->Read(&msg)) {
        switch (msg.message_case()) {
            case edgelink::ControlMessage::kAuthRequest:
                handle_auth_request(msg.auth_request());
                break;
            case edgelink::ControlMessage::kLatencyReport:
                handle_latency_report(msg.latency_report());
                break;
            case edgelink::ControlMessage::kP2PInit:
                handle_p2p_init(msg.p2p_init());
                break;
            case edgelink::ControlMessage::kP2PStatus:
                handle_p2p_status(msg.p2p_status());
                break;
            case edgelink::ControlMessage::kPing:
                handle_ping(msg.ping());
                break;
            default:
                LOG_WARN("ControlStreamHandler: Unknown message type: {}",
                         static_cast<int>(msg.message_case()));
                break;
        }
    }

    // Stream ended, clean up
    if (authenticated_ && node_id_ > 0) {
        session_manager_->remove_control_session(node_id_);

        // Mark node as offline
        db_->execute("UPDATE nodes SET online = 0, last_seen = datetime('now') WHERE id = ?",
                     node_id_);

        LOG_INFO("ControlStreamHandler: Node {} disconnected", node_id_);
    }
}

void ControlStreamHandler::handle_auth_request(const edgelink::AuthRequest& req) {
    LOG_INFO("ControlStreamHandler: Auth request from {}", req.hostname());

    machine_key_ = req.machine_key_pub();
    std::string auth_key = req.auth_key();

    // Look up node by machine key
    auto result = db_->query(
        "SELECT n.id, n.network_id, n.virtual_ip, n.authorized "
        "FROM nodes n WHERE n.machine_key_pub = ?",
        machine_key_);

    if (result.empty()) {
        // New node - need auth_key to register
        if (auth_key.empty()) {
            LOG_WARN("ControlStreamHandler: Unknown machine key without auth_key");
            send_auth_response(false, 0, "", "", "", "Node not registered. Provide auth_key to register.");
            return;
        }

        // Validate auth_key
        auto auth_key_opt = db_->get_auth_key_by_key(auth_key);
        if (!auth_key_opt) {
            LOG_WARN("ControlStreamHandler: Invalid auth_key");
            send_auth_response(false, 0, "", "", "", "Invalid auth key");
            return;
        }

        if (!db_->is_auth_key_valid(*auth_key_opt)) {
            LOG_WARN("ControlStreamHandler: Expired or exhausted auth_key");
            send_auth_response(false, 0, "", "", "", "Auth key expired or exhausted");
            return;
        }

        // Auto-register the new node
        uint32_t net_id = auth_key_opt->network_id;
        std::string virtual_ip = db_->allocate_virtual_ip(net_id);
        if (virtual_ip.empty()) {
            LOG_ERROR("ControlStreamHandler: Failed to allocate virtual IP");
            send_auth_response(false, 0, "", "", "", "Failed to allocate IP address");
            return;
        }

        Node new_node;
        new_node.network_id = net_id;
        new_node.name = req.hostname();
        new_node.machine_key_pub = req.machine_key_pub();
        new_node.node_key_pub = req.node_key_pub();
        new_node.virtual_ip = virtual_ip;
        new_node.hostname = req.hostname();
        new_node.os = req.os();
        new_node.arch = req.arch();
        new_node.version = req.version();
        new_node.authorized = !auth_key_opt->ephemeral;  // Ephemeral keys don't auto-authorize

        uint32_t new_node_id = db_->create_node(new_node);
        if (new_node_id == 0) {
            LOG_ERROR("ControlStreamHandler: Failed to create node");
            send_auth_response(false, 0, "", "", "", "Failed to register node");
            return;
        }

        // Increment auth key usage
        db_->increment_auth_key_usage(auth_key_opt->id);

        LOG_INFO("ControlStreamHandler: Auto-registered node {} ({}) with IP {}",
                 new_node_id, req.hostname(), virtual_ip);

        // Re-query to get the new node data
        result = db_->query(
            "SELECT n.id, n.network_id, n.virtual_ip, n.authorized "
            "FROM nodes n WHERE n.machine_key_pub = ?",
            machine_key_);

        if (result.empty()) {
            send_auth_response(false, 0, "", "", "", "Registration failed");
            return;
        }
    }

    auto& row = result[0];
    try {
        node_id_ = static_cast<uint32_t>(std::get<int64_t>(row.at("id")));
        network_id_ = static_cast<uint32_t>(std::get<int64_t>(row.at("network_id")));
    } catch (const std::exception& e) {
        LOG_ERROR("ControlStreamHandler: Database type error: {}", e.what());
        send_auth_response(false, 0, "", "", "", "Internal error");
        return;
    }
    std::string virtual_ip = std::get<std::string>(row["virtual_ip"]);
    bool authorized = std::get<int64_t>(row["authorized"]) != 0;

    if (!authorized) {
        send_auth_response(false, 0, "", "", "", "Node not authorized");
        return;
    }

    // Generate tokens
    std::string auth_token = edgelink::generate_jwt(jwt_secret_, {
        {"node_id", std::to_string(node_id_)},
        {"network_id", std::to_string(network_id_)},
        {"type", "auth"}
    }, 24 * 60);  // 24 hours

    std::string relay_token = edgelink::generate_jwt(jwt_secret_, {
        {"node_id", std::to_string(node_id_)},
        {"network_id", std::to_string(network_id_)},
        {"type", "relay"}
    }, 90);  // 1.5 hours

    // Update node status
    db_->execute(
        "UPDATE nodes SET online = 1, last_seen = datetime('now'), "
        "hostname = ?, os = ?, arch = ?, version = ? WHERE id = ?",
        req.hostname(), req.os(), req.arch(), req.version(), node_id_);

    authenticated_ = true;

    // Register with session manager (include network_id for broadcast)
    session_manager_->add_control_session(node_id_, network_id_, stream_);

    // Send success response
    send_auth_response(true, node_id_, virtual_ip, auth_token, relay_token);

    // Send initial config
    send_config();

    LOG_INFO("ControlStreamHandler: Node {} ({}) authenticated", node_id_, virtual_ip);
}

void ControlStreamHandler::handle_latency_report(const edgelink::LatencyReport& report) {
    if (!authenticated_) return;

    for (const auto& entry : report.entries()) {
        LOG_DEBUG("ControlStreamHandler: Node {} latency to {} {}: {}ms",
                  node_id_, entry.dst_type(), entry.dst_id(), entry.rtt_ms());

        // Store latency measurement
        db_->execute(
            "INSERT OR REPLACE INTO latency_reports "
            "(node_id, dst_type, dst_id, rtt_ms, reported_at) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            node_id_, entry.dst_type(), entry.dst_id(), entry.rtt_ms());
    }
}

void ControlStreamHandler::handle_p2p_init(const edgelink::P2PInit& init) {
    if (!authenticated_) return;

    uint32_t peer_id = init.peer_node_id();
    LOG_DEBUG("ControlStreamHandler: Node {} requesting P2P with peer {}", node_id_, peer_id);

    // Get peer's endpoints
    auto result = db_->query(
        "SELECT n.id, n.virtual_ip, n.node_key_pub, n.online, "
        "e.type, e.address, e.port "
        "FROM nodes n "
        "LEFT JOIN endpoints e ON n.id = e.node_id "
        "WHERE n.id = ? AND n.network_id = ?",
        peer_id, network_id_);

    if (result.empty()) {
        send_error(edgelink::ERROR_PEER_NOT_FOUND, "Peer not found");
        return;
    }

    // Build P2P endpoint response
    edgelink::ControlMessage msg;
    auto* endpoint = msg.mutable_p2p_endpoint();
    endpoint->set_peer_node_id(peer_id);

    for (const auto& row : result) {
        if (row.count("address") && std::holds_alternative<std::string>(row.at("address"))) {
            auto* ep = endpoint->add_endpoints();
            std::string type_str = std::get<std::string>(row.at("type"));
            if (type_str == "lan") ep->set_type(edgelink::ENDPOINT_LAN);
            else if (type_str == "stun") ep->set_type(edgelink::ENDPOINT_STUN);
            else if (type_str == "relay") ep->set_type(edgelink::ENDPOINT_RELAY);
            ep->set_ip(std::get<std::string>(row.at("address")));
            ep->set_port(std::get<int64_t>(row.at("port")));
        }
    }

    stream_->Write(msg);

    // Also notify peer about this node's interest in P2P
    edgelink::ControlMessage peer_msg;
    auto* peer_endpoint = peer_msg.mutable_p2p_endpoint();
    peer_endpoint->set_peer_node_id(node_id_);
    session_manager_->send_to_node(peer_id, peer_msg);
}

void ControlStreamHandler::handle_p2p_status(const edgelink::P2PStatus& status) {
    if (!authenticated_) return;

    LOG_DEBUG("ControlStreamHandler: Node {} P2P status with peer {}: {}",
              node_id_, status.peer_node_id(), status.connected() ? "connected" : "disconnected");

    // Update P2P connection status in database
    if (status.connected()) {
        db_->execute(
            "INSERT OR REPLACE INTO p2p_connections "
            "(node_id, peer_id, endpoint_ip, endpoint_port, rtt_ms, connected_at) "
            "VALUES (?, ?, ?, ?, ?, datetime('now'))",
            node_id_, status.peer_node_id(),
            status.endpoint_ip(), status.endpoint_port(), status.rtt_ms());
    } else {
        db_->execute(
            "DELETE FROM p2p_connections WHERE node_id = ? AND peer_id = ?",
            node_id_, status.peer_node_id());
    }
}

void ControlStreamHandler::handle_ping(const edgelink::Ping& ping) {
    send_pong(ping.timestamp());
}

void ControlStreamHandler::send_auth_response(bool success, uint32_t node_id,
                                               const std::string& virtual_ip,
                                               const std::string& auth_token,
                                               const std::string& relay_token,
                                               const std::string& error_msg) {
    edgelink::ControlMessage msg;
    auto* resp = msg.mutable_auth_response();
    resp->set_success(success);
    resp->set_node_id(node_id);
    resp->set_virtual_ip(virtual_ip);
    resp->set_auth_token(auth_token);
    resp->set_relay_token(relay_token);
    resp->set_error_message(error_msg);
    stream_->Write(msg);
}

void ControlStreamHandler::send_config() {
    if (!authenticated_) return;

    // Get network config
    auto network_result = db_->query(
        "SELECT id, name, subnet FROM networks WHERE id = ?", network_id_);

    if (network_result.empty()) {
        send_error(edgelink::ERROR_INTERNAL, "Network not found");
        return;
    }

    auto& network = network_result[0];

    edgelink::ControlMessage msg;
    auto* config = msg.mutable_config();
    config->set_network_id(std::get<int64_t>(network["id"]));
    config->set_network_name(std::get<std::string>(network["name"]));
    config->set_subnet(std::get<std::string>(network["subnet"]));

    // Get peers
    auto peers_result = db_->query(
        "SELECT id, hostname, virtual_ip, node_key_pub, online "
        "FROM nodes WHERE network_id = ? AND id != ?",
        network_id_, node_id_);

    for (const auto& row : peers_result) {
        auto* peer = config->add_peers();
        peer->set_node_id(std::get<int64_t>(row.at("id")));
        peer->set_name(std::get<std::string>(row.at("hostname")));
        peer->set_virtual_ip(std::get<std::string>(row.at("virtual_ip")));
        peer->set_node_key_pub(std::get<std::string>(row.at("node_key_pub")));
        peer->set_online(std::get<int64_t>(row.at("online")) != 0);
    }

    // Get relays
    auto relays_result = db_->query(
        "SELECT id, name, url, region FROM servers WHERE capabilities & 1 != 0");

    for (const auto& row : relays_result) {
        auto* relay = config->add_relays();
        relay->set_server_id(std::get<int64_t>(row.at("id")));
        relay->set_name(std::get<std::string>(row.at("name")));
        relay->set_url(std::get<std::string>(row.at("url")));
        relay->set_region(std::get<std::string>(row.at("region")));
    }

    // Get STUN servers
    auto stun_result = db_->query(
        "SELECT id, name, stun_ip, stun_port, stun_ip2 "
        "FROM servers WHERE capabilities & 2 != 0");

    for (const auto& row : stun_result) {
        auto* stun = config->add_stun_servers();
        stun->set_server_id(std::get<int64_t>(row.at("id")));
        stun->set_name(std::get<std::string>(row.at("name")));
        stun->set_ip(std::get<std::string>(row.at("stun_ip")));
        stun->set_port(std::get<int64_t>(row.at("stun_port")));
        if (row.count("stun_ip2")) {
            stun->set_secondary_ip(std::get<std::string>(row.at("stun_ip2")));
        }
    }

    // Get routes
    auto routes_result = db_->query(
        "SELECT cidr, via_node_id, priority, weight, enabled "
        "FROM routes WHERE network_id = ?",
        network_id_);

    for (const auto& row : routes_result) {
        auto* route = config->add_routes();
        route->set_cidr(std::get<std::string>(row.at("cidr")));
        route->set_gateway_node_id(std::get<int64_t>(row.at("via_node_id")));
        route->set_priority(std::get<int64_t>(row.at("priority")));
        route->set_weight(std::get<int64_t>(row.at("weight")));
        route->set_enabled(std::get<int64_t>(row.at("enabled")) != 0);
    }

    stream_->Write(msg);
}

void ControlStreamHandler::send_config_update() {
    // Called when config changes - send delta update
    send_config();  // For now, just resend full config
}

void ControlStreamHandler::send_pong(uint64_t timestamp) {
    edgelink::ControlMessage msg;
    auto* pong = msg.mutable_pong();
    pong->set_timestamp(timestamp);
    stream_->Write(msg);
}

void ControlStreamHandler::send_error(edgelink::ErrorCode code, const std::string& message) {
    edgelink::ControlMessage msg;
    auto* error = msg.mutable_error();
    error->set_code(code);
    error->set_message(message);
    stream_->Write(msg);
}

// ============================================================================
// Server Stream Handler Implementation
// ============================================================================

ServerStreamHandler::ServerStreamHandler(
    grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream,
    std::shared_ptr<Database> db,
    const std::string& server_token,
    GrpcSessionManager* session_manager)
    : stream_(stream)
    , db_(db)
    , server_token_(server_token)
    , session_manager_(session_manager)
{}

void ServerStreamHandler::run() {
    edgelink::ServerMessage msg;

    while (stream_->Read(&msg)) {
        switch (msg.message_case()) {
            case edgelink::ServerMessage::kServerRegister:
                handle_server_register(msg.server_register());
                break;
            case edgelink::ServerMessage::kServerHeartbeat:
                handle_server_heartbeat(msg.server_heartbeat());
                break;
            case edgelink::ServerMessage::kServerLatencyReport:
                handle_server_latency_report(msg.server_latency_report());
                break;
            case edgelink::ServerMessage::kPing:
                handle_ping(msg.ping());
                break;
            default:
                LOG_WARN("ServerStreamHandler: Unknown message type: {}",
                         static_cast<int>(msg.message_case()));
                break;
        }
    }

    // Stream ended, clean up
    if (authenticated_ && server_id_ > 0) {
        session_manager_->remove_server_session(server_id_);

        // Mark server as offline
        db_->execute("UPDATE servers SET online = 0 WHERE id = ?", server_id_);

        LOG_INFO("ServerStreamHandler: Server {} disconnected", server_name_);
    }
}

void ServerStreamHandler::handle_server_register(const edgelink::ServerRegister& req) {
    LOG_INFO("ServerStreamHandler: Server registration from {}", req.name());

    // Verify server token
    if (req.server_token() != server_token_) {
        send_register_response(false, 0, "Invalid server token");
        return;
    }

    server_name_ = req.name();

    // Check if server exists
    auto result = db_->query("SELECT id FROM servers WHERE name = ?", server_name_);

    if (result.empty()) {
        // Register new server
        db_->execute(
            "INSERT INTO servers (name, capabilities, region, url, stun_ip, stun_port, stun_ip2, online) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            server_name_, req.capabilities(), req.region(),
            req.relay_url(), req.stun_ip(), req.stun_port(), req.stun_ip2());

        result = db_->query("SELECT id FROM servers WHERE name = ?", server_name_);
    } else {
        // Update existing server
        db_->execute(
            "UPDATE servers SET capabilities = ?, region = ?, url = ?, "
            "stun_ip = ?, stun_port = ?, stun_ip2 = ?, online = 1 WHERE name = ?",
            req.capabilities(), req.region(), req.relay_url(),
            req.stun_ip(), req.stun_port(), req.stun_ip2(), server_name_);
    }

    server_id_ = std::get<int64_t>(result[0]["id"]);
    authenticated_ = true;

    // Register with session manager
    session_manager_->add_server_session(server_id_, stream_);

    // Send success response
    send_register_response(true, server_id_);

    // Send initial data
    send_node_locations();
    send_relay_list();

    LOG_INFO("ServerStreamHandler: Server {} registered with ID {}", server_name_, server_id_);
}

void ServerStreamHandler::handle_server_heartbeat(const edgelink::ServerHeartbeat& hb) {
    if (!authenticated_) return;

    // Update server stats
    db_->execute(
        "UPDATE servers SET connected_clients = ?, last_heartbeat = datetime('now') WHERE id = ?",
        hb.connected_clients(), server_id_);
}

void ServerStreamHandler::handle_server_latency_report(const edgelink::ServerLatencyReport& report) {
    if (!authenticated_) return;

    for (const auto& entry : report.entries()) {
        db_->execute(
            "INSERT OR REPLACE INTO mesh_latency "
            "(server_id, target_server_id, rtt_ms, measured_at) "
            "VALUES (?, ?, ?, datetime('now'))",
            server_id_, entry.target_server_id(), entry.rtt_ms());
    }
}

void ServerStreamHandler::handle_ping(const edgelink::Ping& ping) {
    send_pong(ping.timestamp());
}

void ServerStreamHandler::send_register_response(bool success, uint32_t server_id,
                                                  const std::string& error_msg) {
    edgelink::ServerMessage msg;
    auto* resp = msg.mutable_server_register_response();
    resp->set_success(success);
    resp->set_server_id(server_id);
    resp->set_error_message(error_msg);
    stream_->Write(msg);
}

void ServerStreamHandler::send_node_locations() {
    if (!authenticated_) return;

    // Get node-to-relay mappings
    auto result = db_->query(
        "SELECT node_id, server_id FROM node_relay_connections WHERE server_id != ?",
        server_id_);

    edgelink::ServerMessage msg;
    auto* node_loc = msg.mutable_server_node_loc();

    std::unordered_map<uint32_t, std::vector<uint32_t>> node_relays;
    for (const auto& row : result) {
        uint32_t node_id = std::get<int64_t>(row.at("node_id"));
        uint32_t relay_id = std::get<int64_t>(row.at("server_id"));
        node_relays[node_id].push_back(relay_id);
    }

    for (const auto& [node_id, relay_ids] : node_relays) {
        auto* loc = node_loc->add_nodes();
        loc->set_node_id(node_id);
        for (uint32_t relay_id : relay_ids) {
            loc->add_connected_relay_ids(relay_id);
        }
    }

    stream_->Write(msg);
}

void ServerStreamHandler::send_relay_list() {
    if (!authenticated_) return;

    // Get list of other relays for mesh
    auto result = db_->query(
        "SELECT id, name, url, region FROM servers "
        "WHERE capabilities & 1 != 0 AND id != ? AND online = 1",
        server_id_);

    edgelink::ServerMessage msg;
    auto* relay_list = msg.mutable_server_relay_list();

    for (const auto& row : result) {
        auto* relay = relay_list->add_relays();
        relay->set_server_id(std::get<int64_t>(row.at("id")));
        relay->set_name(std::get<std::string>(row.at("name")));
        relay->set_url(std::get<std::string>(row.at("url")));
        relay->set_region(std::get<std::string>(row.at("region")));
    }

    stream_->Write(msg);
}

void ServerStreamHandler::send_pong(uint64_t timestamp) {
    edgelink::ServerMessage msg;
    auto* pong = msg.mutable_pong();
    pong->set_timestamp(timestamp);
    stream_->Write(msg);
}

void ServerStreamHandler::send_error(edgelink::ErrorCode code, const std::string& message) {
    edgelink::ServerMessage msg;
    auto* error = msg.mutable_error();
    error->set_code(code);
    error->set_message(message);
    stream_->Write(msg);
}

// ============================================================================
// GrpcSessionManager Implementation
// ============================================================================

void GrpcSessionManager::add_control_session(uint32_t node_id, uint32_t network_id,
    grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    control_sessions_[node_id] = {stream, network_id};
}

void GrpcSessionManager::remove_control_session(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    control_sessions_.erase(node_id);
}

void GrpcSessionManager::add_server_session(uint32_t server_id,
    grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream) {
    std::lock_guard<std::mutex> lock(server_mutex_);
    server_sessions_[server_id] = {stream};
}

void GrpcSessionManager::remove_server_session(uint32_t server_id) {
    std::lock_guard<std::mutex> lock(server_mutex_);
    server_sessions_.erase(server_id);
}

void GrpcSessionManager::send_to_node(uint32_t node_id, const edgelink::ControlMessage& msg) {
    grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream = nullptr;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_sessions_.find(node_id);
        if (it != control_sessions_.end()) {
            stream = it->second.stream;
        }
    }
    // Write outside of lock to avoid blocking
    if (stream) {
        stream->Write(msg);
    }
}

void GrpcSessionManager::send_to_server(uint32_t server_id, const edgelink::ServerMessage& msg) {
    grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream = nullptr;
    {
        std::lock_guard<std::mutex> lock(server_mutex_);
        auto it = server_sessions_.find(server_id);
        if (it != server_sessions_.end()) {
            stream = it->second.stream;
        }
    }
    // Write outside of lock to avoid blocking
    if (stream) {
        stream->Write(msg);
    }
}

void GrpcSessionManager::broadcast_to_network(uint32_t network_id,
                                               const edgelink::ControlMessage& msg,
                                               uint32_t exclude_node_id) {
    // Collect streams under lock, then write outside
    std::vector<grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>*> streams;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        for (auto& [node_id, session] : control_sessions_) {
            if (node_id != exclude_node_id && session.network_id == network_id) {
                streams.push_back(session.stream);
            }
        }
    }
    // Write outside of lock to avoid blocking
    for (auto* stream : streams) {
        stream->Write(msg);
    }
}

void GrpcSessionManager::broadcast_to_servers(const edgelink::ServerMessage& msg) {
    // Collect streams under lock, then write outside
    std::vector<grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>*> streams;
    {
        std::lock_guard<std::mutex> lock(server_mutex_);
        for (auto& [server_id, session] : server_sessions_) {
            streams.push_back(session.stream);
        }
    }
    // Write outside of lock to avoid blocking
    for (auto* stream : streams) {
        stream->Write(msg);
    }
}

void GrpcSessionManager::push_config_update(uint32_t node_id) {
    // This would trigger a config resend
    edgelink::ControlMessage msg;
    msg.mutable_config();  // Empty config triggers refresh
    send_to_node(node_id, msg);
}

size_t GrpcSessionManager::node_count() const {
    std::lock_guard<std::mutex> lock(control_mutex_);
    return control_sessions_.size();
}

size_t GrpcSessionManager::server_count() const {
    std::lock_guard<std::mutex> lock(server_mutex_);
    return server_sessions_.size();
}

// ============================================================================
// ControlServiceImpl
// ============================================================================

ControlServiceImpl::ControlServiceImpl(std::shared_ptr<Database> db,
                                       const std::string& jwt_secret,
                                       GrpcSessionManager* session_manager)
    : db_(db)
    , jwt_secret_(jwt_secret)
    , session_manager_(session_manager)
{}

grpc::Status ControlServiceImpl::Control(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream) {

    LOG_INFO("ControlServiceImpl: New control connection from {}",
             context->peer());

    ControlStreamHandler handler(stream, db_, jwt_secret_, session_manager_);
    handler.run();

    return grpc::Status::OK;
}

// ============================================================================
// ServerServiceImpl
// ============================================================================

ServerServiceImpl::ServerServiceImpl(std::shared_ptr<Database> db,
                                     const std::string& server_token,
                                     GrpcSessionManager* session_manager)
    : db_(db)
    , server_token_(server_token)
    , session_manager_(session_manager)
{}

grpc::Status ServerServiceImpl::ServerChannel(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream) {

    LOG_INFO("ServerServiceImpl: New server connection from {}",
             context->peer());

    ServerStreamHandler handler(stream, db_, server_token_, session_manager_);
    handler.run();

    return grpc::Status::OK;
}

// ============================================================================
// AdminServiceImpl
// ============================================================================

AdminServiceImpl::AdminServiceImpl(std::shared_ptr<Database> db,
                                   GrpcSessionManager* session_manager)
    : db_(db)
    , session_manager_(session_manager)
{}

grpc::Status AdminServiceImpl::Health(grpc::ServerContext* context,
                                       const edgelink::HealthRequest* request,
                                       edgelink::HealthResponse* response) {
    response->set_healthy(true);
    response->set_version("1.0.0");
    response->set_protocol_version(1);
    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::ListNetworks(grpc::ServerContext* context,
                                             const edgelink::ListNetworksRequest* request,
                                             edgelink::ListNetworksResponse* response) {
    auto result = db_->query("SELECT id, name, subnet, description FROM networks");

    for (const auto& row : result) {
        auto* network = response->add_networks();
        network->set_id(std::get<int64_t>(row.at("id")));
        network->set_name(std::get<std::string>(row.at("name")));
        network->set_subnet(std::get<std::string>(row.at("subnet")));
        if (row.count("description") && std::holds_alternative<std::string>(row.at("description"))) {
            network->set_description(std::get<std::string>(row.at("description")));
        }
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::CreateNetwork(grpc::ServerContext* context,
                                              const edgelink::CreateNetworkRequest* request,
                                              edgelink::CreateNetworkResponse* response) {
    try {
        db_->execute(
            "INSERT INTO networks (name, subnet, description) VALUES (?, ?, ?)",
            request->name(), request->subnet(), request->description());

        auto result = db_->query("SELECT last_insert_rowid() as id");
        if (!result.empty()) {
            response->set_success(true);
            response->set_network_id(std::get<int64_t>(result[0]["id"]));
        }
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::DeleteNetwork(grpc::ServerContext* context,
                                              const edgelink::DeleteNetworkRequest* request,
                                              edgelink::DeleteNetworkResponse* response) {
    try {
        db_->execute("DELETE FROM networks WHERE id = ?", request->network_id());
        response->set_success(true);
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::ListNodes(grpc::ServerContext* context,
                                          const edgelink::ListNodesRequest* request,
                                          edgelink::ListNodesResponse* response) {
    std::string sql = "SELECT id, network_id, hostname, virtual_ip, hostname, "
                      "os, arch, version, nat_type, online, authorized, last_seen, machine_key_pub "
                      "FROM nodes";

    std::vector<Database::Row> result;
    if (request->has_network_id()) {
        result = db_->query(sql + " WHERE network_id = ?", request->network_id());
    } else {
        result = db_->query(sql);
    }

    for (const auto& row : result) {
        auto* node = response->add_nodes();
        node->set_id(std::get<int64_t>(row.at("id")));
        node->set_network_id(std::get<int64_t>(row.at("network_id")));
        node->set_hostname(std::get<std::string>(row.at("hostname")));
        node->set_virtual_ip(std::get<std::string>(row.at("virtual_ip")));
        node->set_name(std::get<std::string>(row.at("hostname")));
        if (row.count("os") && std::holds_alternative<std::string>(row.at("os"))) {
            node->set_os(std::get<std::string>(row.at("os")));
        }
        if (row.count("arch") && std::holds_alternative<std::string>(row.at("arch"))) {
            node->set_arch(std::get<std::string>(row.at("arch")));
        }
        if (row.count("version") && std::holds_alternative<std::string>(row.at("version"))) {
            node->set_version(std::get<std::string>(row.at("version")));
        }
        node->set_online(std::get<int64_t>(row.at("online")) != 0);
        node->set_authorized(std::get<int64_t>(row.at("authorized")) != 0);
        if (row.count("last_seen") && std::holds_alternative<std::string>(row.at("last_seen"))) {
            node->set_last_seen(std::get<std::string>(row.at("last_seen")));
        }
        if (row.count("machine_key_pub") && std::holds_alternative<std::string>(row.at("machine_key_pub"))) {
            node->set_machine_key_pub(std::get<std::string>(row.at("machine_key_pub")));
        }
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::GetNode(grpc::ServerContext* context,
                                        const edgelink::GetNodeRequest* request,
                                        edgelink::GetNodeResponse* response) {
    auto result = db_->query(
        "SELECT id, network_id, hostname, virtual_ip, hostname, "
        "os, arch, version, nat_type, online, authorized, last_seen, machine_key_pub "
        "FROM nodes WHERE id = ?",
        request->node_id());

    if (result.empty()) {
        response->set_found(false);
        return grpc::Status::OK;
    }

    response->set_found(true);
    auto& row = result[0];
    auto* node = response->mutable_node();
    node->set_id(std::get<int64_t>(row.at("id")));
    node->set_network_id(std::get<int64_t>(row.at("network_id")));
    node->set_hostname(std::get<std::string>(row.at("hostname")));
    node->set_virtual_ip(std::get<std::string>(row.at("virtual_ip")));
    node->set_name(std::get<std::string>(row.at("hostname")));
    if (row.count("os") && std::holds_alternative<std::string>(row.at("os"))) {
        node->set_os(std::get<std::string>(row.at("os")));
    }
    if (row.count("arch") && std::holds_alternative<std::string>(row.at("arch"))) {
        node->set_arch(std::get<std::string>(row.at("arch")));
    }
    if (row.count("version") && std::holds_alternative<std::string>(row.at("version"))) {
        node->set_version(std::get<std::string>(row.at("version")));
    }
    node->set_online(std::get<int64_t>(row.at("online")) != 0);
    node->set_authorized(std::get<int64_t>(row.at("authorized")) != 0);
    if (row.count("last_seen") && std::holds_alternative<std::string>(row.at("last_seen"))) {
        node->set_last_seen(std::get<std::string>(row.at("last_seen")));
    }
    if (row.count("machine_key_pub") && std::holds_alternative<std::string>(row.at("machine_key_pub"))) {
        node->set_machine_key_pub(std::get<std::string>(row.at("machine_key_pub")));
    }

    // Get endpoints
    auto endpoints = db_->query(
        "SELECT type, address, port FROM endpoints WHERE node_id = ?",
        request->node_id());

    for (const auto& ep_row : endpoints) {
        auto* ep = node->add_endpoints();
        std::string type_str = std::get<std::string>(ep_row.at("type"));
        if (type_str == "lan") ep->set_type(edgelink::ENDPOINT_LAN);
        else if (type_str == "stun") ep->set_type(edgelink::ENDPOINT_STUN);
        else if (type_str == "relay") ep->set_type(edgelink::ENDPOINT_RELAY);
        ep->set_ip(std::get<std::string>(ep_row.at("address")));
        ep->set_port(std::get<int64_t>(ep_row.at("port")));
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::AuthorizeNode(grpc::ServerContext* context,
                                              const edgelink::AuthorizeNodeRequest* request,
                                              edgelink::AuthorizeNodeResponse* response) {
    try {
        db_->execute("UPDATE nodes SET authorized = 1 WHERE id = ?", request->node_id());
        response->set_success(true);

        // Push config update to the node if online
        session_manager_->push_config_update(request->node_id());
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::DeauthorizeNode(grpc::ServerContext* context,
                                                const edgelink::DeauthorizeNodeRequest* request,
                                                edgelink::DeauthorizeNodeResponse* response) {
    try {
        db_->execute("UPDATE nodes SET authorized = 0 WHERE id = ?", request->node_id());
        response->set_success(true);
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::DeleteNode(grpc::ServerContext* context,
                                           const edgelink::DeleteNodeRequest* request,
                                           edgelink::DeleteNodeResponse* response) {
    try {
        db_->execute("DELETE FROM nodes WHERE id = ?", request->node_id());
        response->set_success(true);
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::UpdateNodeIP(grpc::ServerContext* context,
                                             const edgelink::UpdateNodeIPRequest* request,
                                             edgelink::UpdateNodeIPResponse* response) {
    // Get old IP
    auto result = db_->query("SELECT virtual_ip, network_id FROM nodes WHERE id = ?",
                             request->node_id());

    if (result.empty()) {
        response->set_success(false);
        response->set_error("Node not found");
        return grpc::Status::OK;
    }

    std::string old_ip = std::get<std::string>(result[0]["virtual_ip"]);
    uint32_t network_id = std::get<int64_t>(result[0]["network_id"]);

    try {
        db_->execute("UPDATE nodes SET virtual_ip = ? WHERE id = ?",
                     request->new_virtual_ip(), request->node_id());

        response->set_success(true);
        response->set_old_ip(old_ip);
        response->set_new_ip(request->new_virtual_ip());

        // Push IP change to the node
        edgelink::ControlMessage msg;
        auto* config_update = msg.mutable_config_update();
        auto* ip_change = config_update->mutable_ip_change();
        ip_change->set_old_ip(old_ip);
        ip_change->set_new_ip(request->new_virtual_ip());
        ip_change->set_reason(request->reason());

        session_manager_->send_to_node(request->node_id(), msg);

        // Notify peers in the network about the change
        edgelink::ControlMessage peer_msg;
        auto* peer_update = peer_msg.mutable_config_update();
        auto* peer_change = peer_update->add_peer_updates();
        peer_change->set_action(edgelink::ACTION_UPDATE);
        peer_change->mutable_peer()->set_node_id(request->node_id());
        peer_change->mutable_peer()->set_virtual_ip(request->new_virtual_ip());

        session_manager_->broadcast_to_network(network_id, peer_msg, request->node_id());

        LOG_INFO("AdminService: Updated node {} IP from {} to {}",
                 request->node_id(), old_ip, request->new_virtual_ip());
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::ListServers(grpc::ServerContext* context,
                                            const edgelink::ListServersRequest* request,
                                            edgelink::ListServersResponse* response) {
    auto result = db_->query(
        "SELECT id, name, url, region, capabilities, stun_ip, stun_ip2, stun_port, "
        "online, last_heartbeat, connected_clients FROM servers");

    for (const auto& row : result) {
        auto* server = response->add_servers();
        server->set_id(std::get<int64_t>(row.at("id")));
        server->set_name(std::get<std::string>(row.at("name")));
        if (row.count("url") && std::holds_alternative<std::string>(row.at("url"))) {
            server->set_url(std::get<std::string>(row.at("url")));
        }
        if (row.count("region") && std::holds_alternative<std::string>(row.at("region"))) {
            server->set_region(std::get<std::string>(row.at("region")));
        }
        server->set_capabilities(std::get<int64_t>(row.at("capabilities")));
        if (row.count("stun_ip") && std::holds_alternative<std::string>(row.at("stun_ip"))) {
            server->set_stun_ip(std::get<std::string>(row.at("stun_ip")));
        }
        if (row.count("stun_ip2") && std::holds_alternative<std::string>(row.at("stun_ip2"))) {
            server->set_stun_ip2(std::get<std::string>(row.at("stun_ip2")));
        }
        server->set_stun_port(std::get<int64_t>(row.at("stun_port")));
        server->set_enabled(std::get<int64_t>(row.at("online")) != 0);
        if (row.count("last_heartbeat") && std::holds_alternative<std::string>(row.at("last_heartbeat"))) {
            server->set_last_heartbeat(std::get<std::string>(row.at("last_heartbeat")));
        }
        server->set_connected_clients(std::get<int64_t>(row.at("connected_clients")));

        // Determine type
        uint32_t caps = std::get<int64_t>(row.at("capabilities"));
        if (caps & 1) server->set_type("relay");
        else if (caps & 2) server->set_type("stun");
        else server->set_type("unknown");
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::RegisterServer(grpc::ServerContext* context,
                                               const edgelink::RegisterServerRequest* request,
                                               edgelink::RegisterServerResponse* response) {
    try {
        db_->execute(
            "INSERT INTO servers (name, capabilities, region, url, stun_ip, stun_port, stun_ip2, online) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            request->name(), request->capabilities(), request->region(),
            request->url(), request->stun_ip(), request->stun_port(), request->stun_ip2());

        auto result = db_->query("SELECT last_insert_rowid() as id");
        if (!result.empty()) {
            response->set_success(true);
            response->set_server_id(std::get<int64_t>(result[0]["id"]));
            // Generate a server token (in production, use proper token generation)
            response->set_server_token("server_" + std::to_string(response->server_id()));
        }
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::DeleteServer(grpc::ServerContext* context,
                                             const edgelink::DeleteServerRequest* request,
                                             edgelink::DeleteServerResponse* response) {
    try {
        db_->execute("DELETE FROM servers WHERE id = ?", request->server_id());
        response->set_success(true);
    } catch (const std::exception& e) {
        response->set_success(false);
        response->set_error(e.what());
    }

    return grpc::Status::OK;
}

grpc::Status AdminServiceImpl::GetStats(grpc::ServerContext* context,
                                         const edgelink::StatsRequest* request,
                                         edgelink::StatsResponse* response) {
    // Get node counts
    auto node_result = db_->query("SELECT COUNT(*) as total, SUM(online) as online FROM nodes");
    if (!node_result.empty()) {
        response->set_nodes_total(std::get<int64_t>(node_result[0]["total"]));
        response->set_nodes_online(std::get<int64_t>(node_result[0]["online"]));
    }

    // Get server counts
    auto server_result = db_->query("SELECT COUNT(*) as total, SUM(online) as online FROM servers");
    if (!server_result.empty()) {
        response->set_servers_total(std::get<int64_t>(server_result[0]["total"]));
        response->set_servers_online(std::get<int64_t>(server_result[0]["online"]));
    }

    // Get network count
    auto network_result = db_->query("SELECT COUNT(*) as total FROM networks");
    if (!network_result.empty()) {
        response->set_networks_total(std::get<int64_t>(network_result[0]["total"]));
    }

    return grpc::Status::OK;
}

// ============================================================================
// GrpcServer Implementation
// ============================================================================

GrpcServer::GrpcServer(const ControllerConfig& config,
                       std::shared_ptr<Database> db)
    : config_(config)
    , db_(db)
{}

GrpcServer::~GrpcServer() {
    stop();
}

void GrpcServer::start() {
    if (running_) return;

    setup_ssl_credentials();

    std::string address = config_.http.listen_address + ":" +
                          std::to_string(config_.http.listen_port);

    control_service_ = std::make_unique<ControlServiceImpl>(
        db_, config_.jwt.secret, &session_manager_);
    server_service_ = std::make_unique<ServerServiceImpl>(
        db_, config_.server_token, &session_manager_);
    admin_service_ = std::make_unique<AdminServiceImpl>(
        db_, &session_manager_);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(address, credentials_);
    builder.RegisterService(control_service_.get());
    builder.RegisterService(server_service_.get());
    builder.RegisterService(admin_service_.get());

    // Register builtin relay service if available
    if (builtin_relay_) {
        builder.RegisterService(builtin_relay_->get_service());
        LOG_INFO("GrpcServer: Builtin relay service registered");
    }

    // Configure keepalive - server side
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);  // Server sends ping every 60s
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
    // Allow clients to send pings without rate limiting
    builder.AddChannelArgument(GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS, 1);  // No limit
    builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);  // Unlimited pings

    server_ = builder.BuildAndStart();

    if (!server_) {
        LOG_ERROR("GrpcServer: Failed to start on {}", address);
        return;
    }

    running_ = true;
    LOG_INFO("GrpcServer: Listening on {}", address);

    // Block until shutdown
    server_->Wait();
}

void GrpcServer::stop() {
    if (!running_) return;

    if (server_) {
        server_->Shutdown();
        server_.reset();
    }

    running_ = false;
    LOG_INFO("GrpcServer: Stopped");
}

void GrpcServer::setup_ssl_credentials() {
    if (config_.http.enable_tls && config_.tls.is_valid()) {
        // Read certificate file
        std::ifstream cert_file(config_.tls.cert_path);
        if (!cert_file.is_open()) {
            LOG_ERROR("GrpcServer: Failed to open cert file: {}", config_.tls.cert_path);
            credentials_ = grpc::InsecureServerCredentials();
            return;
        }
        std::string cert((std::istreambuf_iterator<char>(cert_file)),
                         std::istreambuf_iterator<char>());

        // Read key file
        std::ifstream key_file(config_.tls.key_path);
        if (!key_file.is_open()) {
            LOG_ERROR("GrpcServer: Failed to open key file: {}", config_.tls.key_path);
            credentials_ = grpc::InsecureServerCredentials();
            return;
        }
        std::string key((std::istreambuf_iterator<char>(key_file)),
                        std::istreambuf_iterator<char>());

        grpc::SslServerCredentialsOptions ssl_opts;
        ssl_opts.pem_key_cert_pairs.push_back({key, cert});

        if (!config_.tls.ca_path.empty()) {
            std::ifstream ca_file(config_.tls.ca_path);
            if (ca_file.is_open()) {
                std::string ca((std::istreambuf_iterator<char>(ca_file)),
                               std::istreambuf_iterator<char>());
                ssl_opts.pem_root_certs = ca;
            } else {
                LOG_WARN("GrpcServer: Failed to open CA file: {}", config_.tls.ca_path);
            }
        }

        credentials_ = grpc::SslServerCredentials(ssl_opts);
        LOG_INFO("GrpcServer: Using TLS");
    } else {
        credentials_ = grpc::InsecureServerCredentials();
        LOG_WARN("GrpcServer: Using insecure credentials (no TLS)");
    }
}

} // namespace edgelink::controller

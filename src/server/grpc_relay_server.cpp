#include "server/grpc_relay_server.hpp"
#include "common/log.hpp"

#include <fstream>

namespace edgelink {

// ============================================================================
// RelayStreamHandler Implementation
// ============================================================================

RelayStreamHandler::RelayStreamHandler(
    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream,
    GrpcRelaySessionManager* session_manager,
    const std::string& jwt_secret)
    : stream_(stream)
    , session_manager_(session_manager)
    , jwt_secret_(jwt_secret)
{}

void RelayStreamHandler::run() {
    edgelink::RelayMessage msg;

    while (stream_->Read(&msg)) {
        switch (msg.message_case()) {
            case edgelink::RelayMessage::kRelayAuth:
                handle_relay_auth(msg.relay_auth());
                break;
            case edgelink::RelayMessage::kData:
                handle_data(msg.data());
                break;
            case edgelink::RelayMessage::kPing:
                handle_ping(msg.ping());
                break;
            default:
                LOG_WARN("RelayStreamHandler: Unknown message type: {}",
                         static_cast<int>(msg.message_case()));
                break;
        }
    }

    // Stream ended, cleanup
    if (authenticated_ && node_id_ > 0) {
        session_manager_->remove_client_session(node_id_);
        if (close_callback_) {
            close_callback_(node_id_);
        }
        LOG_INFO("RelayStreamHandler: Node {} disconnected", node_id_);
    }
}

void RelayStreamHandler::handle_relay_auth(const edgelink::RelayAuth& auth) {
    LOG_DEBUG("RelayStreamHandler: Auth request with token");

    uint32_t node_id;
    std::string virtual_ip;

    if (!session_manager_->validate_relay_token(auth.relay_token(), node_id, virtual_ip)) {
        send_auth_response(false, 0, "Invalid relay token");
        LOG_WARN("RelayStreamHandler: Auth failed - invalid token");
        return;
    }

    node_id_ = node_id;
    virtual_ip_ = virtual_ip;
    authenticated_ = true;

    // Register with session manager
    session_manager_->add_client_session(node_id_, stream_);

    send_auth_response(true, node_id_);
    LOG_INFO("RelayStreamHandler: Node {} ({}) authenticated", node_id_, virtual_ip_);
}

void RelayStreamHandler::handle_data(const edgelink::DataPacket& packet) {
    if (!authenticated_) {
        send_error(edgelink::ERROR_NOT_AUTHORIZED, "Not authenticated");
        return;
    }

    // Verify source node ID
    if (packet.src_node_id() != node_id_) {
        send_error(edgelink::ERROR_INVALID_ARGUMENT, "Invalid source node ID");
        return;
    }

    uint32_t dst_node_id = packet.dst_node_id();

    // Try to deliver locally first
    if (session_manager_->send_to_node(dst_node_id, packet)) {
        LOG_DEBUG("RelayStreamHandler: Forwarded data {} -> {} (local)",
                  node_id_, dst_node_id);
        return;
    }

    // Check if destination is on another relay
    auto locations = session_manager_->get_node_relay_locations(dst_node_id);
    if (!locations.empty()) {
        // Forward through mesh
        edgelink::MeshForward forward;
        forward.set_src_server_id(0);  // Will be set by mesh
        forward.set_dst_server_id(locations[0]);
        *forward.mutable_data() = packet;

        if (session_manager_->forward_through_mesh(locations[0], forward)) {
            LOG_DEBUG("RelayStreamHandler: Forwarded data {} -> {} via mesh to relay {}",
                      node_id_, dst_node_id, locations[0]);
            return;
        }
    }

    LOG_DEBUG("RelayStreamHandler: Cannot deliver to node {} - not found", dst_node_id);

    if (data_callback_) {
        std::vector<uint8_t> data(packet.encrypted_data().begin(),
                                   packet.encrypted_data().end());
        data_callback_(node_id_, dst_node_id, data);
    }
}

void RelayStreamHandler::handle_ping(const edgelink::Ping& ping) {
    send_pong(ping.timestamp());
}

bool RelayStreamHandler::send_data(const edgelink::DataPacket& packet) {
    edgelink::RelayMessage msg;
    *msg.mutable_relay_data() = packet;
    return stream_->Write(msg);
}

void RelayStreamHandler::send_auth_response(bool success, uint32_t node_id,
                                             const std::string& error) {
    edgelink::RelayMessage msg;
    auto* resp = msg.mutable_relay_auth_response();
    resp->set_success(success);
    resp->set_node_id(node_id);
    resp->set_error_message(error);
    stream_->Write(msg);
}

void RelayStreamHandler::send_pong(uint64_t timestamp) {
    edgelink::RelayMessage msg;
    msg.mutable_pong()->set_timestamp(timestamp);
    stream_->Write(msg);
}

void RelayStreamHandler::send_error(edgelink::ErrorCode code, const std::string& message) {
    edgelink::RelayMessage msg;
    auto* error = msg.mutable_error();
    error->set_code(code);
    error->set_message(message);
    stream_->Write(msg);
}

// ============================================================================
// MeshStreamHandler Implementation
// ============================================================================

MeshStreamHandler::MeshStreamHandler(
    grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream,
    GrpcRelaySessionManager* session_manager,
    const std::string& server_token,
    uint32_t local_server_id)
    : stream_(stream)
    , session_manager_(session_manager)
    , server_token_(server_token)
    , local_server_id_(local_server_id)
{}

void MeshStreamHandler::run() {
    edgelink::MeshMessage msg;

    while (stream_->Read(&msg)) {
        switch (msg.message_case()) {
            case edgelink::MeshMessage::kMeshHello:
                handle_mesh_hello(msg.mesh_hello());
                break;
            case edgelink::MeshMessage::kMeshForward:
                handle_mesh_forward(msg.mesh_forward());
                break;
            case edgelink::MeshMessage::kMeshPing:
                handle_mesh_ping(msg.mesh_ping());
                break;
            default:
                LOG_WARN("MeshStreamHandler: Unknown message type: {}",
                         static_cast<int>(msg.message_case()));
                break;
        }
    }

    // Cleanup
    if (authenticated_ && peer_server_id_ > 0) {
        session_manager_->remove_mesh_session(peer_server_id_);
        LOG_INFO("MeshStreamHandler: Peer server {} disconnected", peer_server_id_);
    }
}

void MeshStreamHandler::handle_mesh_hello(const edgelink::MeshHello& hello) {
    LOG_DEBUG("MeshStreamHandler: Hello from server {}", hello.server_id());

    // Verify token
    if (hello.server_token() != server_token_) {
        send_hello_ack(false, "Invalid server token");
        LOG_WARN("MeshStreamHandler: Auth failed - invalid token");
        return;
    }

    peer_server_id_ = hello.server_id();
    authenticated_ = true;

    // Register with session manager
    session_manager_->add_mesh_session(peer_server_id_, stream_);

    send_hello_ack(true);
    LOG_INFO("MeshStreamHandler: Peer server {} authenticated", peer_server_id_);
}

void MeshStreamHandler::handle_mesh_forward(const edgelink::MeshForward& forward) {
    if (!authenticated_) return;

    uint32_t dst_node_id = forward.data().dst_node_id();

    // Try to deliver to local node
    if (session_manager_->send_to_node(dst_node_id, forward.data())) {
        LOG_DEBUG("MeshStreamHandler: Delivered mesh data to node {}", dst_node_id);
    } else {
        LOG_DEBUG("MeshStreamHandler: Node {} not connected locally", dst_node_id);
    }
}

void MeshStreamHandler::handle_mesh_ping(const edgelink::MeshPing& ping) {
    send_pong(ping.timestamp());
}

bool MeshStreamHandler::forward_data(const edgelink::MeshForward& forward) {
    edgelink::MeshMessage msg;
    *msg.mutable_mesh_forward() = forward;
    return stream_->Write(msg);
}

void MeshStreamHandler::send_hello_ack(bool success, const std::string& error) {
    edgelink::MeshMessage msg;
    auto* ack = msg.mutable_mesh_hello_ack();
    ack->set_success(success);
    ack->set_server_id(local_server_id_);
    ack->set_error_message(error);
    stream_->Write(msg);
}

void MeshStreamHandler::send_pong(uint64_t timestamp) {
    edgelink::MeshMessage msg;
    auto* pong = msg.mutable_mesh_pong();
    pong->set_server_id(local_server_id_);
    pong->set_timestamp(timestamp);
    stream_->Write(msg);
}

// ============================================================================
// GrpcRelaySessionManager Implementation
// ============================================================================

GrpcRelaySessionManager::GrpcRelaySessionManager(const std::string& jwt_secret)
    : jwt_secret_(jwt_secret)
{}

void GrpcRelaySessionManager::add_client_session(uint32_t node_id,
    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream) {
    std::unique_lock lock(client_mutex_);
    client_sessions_[node_id] = stream;
}

void GrpcRelaySessionManager::remove_client_session(uint32_t node_id) {
    std::unique_lock lock(client_mutex_);
    client_sessions_.erase(node_id);
}

void GrpcRelaySessionManager::add_mesh_session(uint32_t server_id,
    grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream) {
    std::unique_lock lock(mesh_mutex_);
    mesh_sessions_[server_id] = stream;
}

void GrpcRelaySessionManager::remove_mesh_session(uint32_t server_id) {
    std::unique_lock lock(mesh_mutex_);
    mesh_sessions_.erase(server_id);
}

bool GrpcRelaySessionManager::send_to_node(uint32_t node_id,
                                            const edgelink::DataPacket& packet) {
    std::shared_lock lock(client_mutex_);
    auto it = client_sessions_.find(node_id);
    if (it == client_sessions_.end()) {
        return false;
    }

    edgelink::RelayMessage msg;
    *msg.mutable_relay_data() = packet;
    return it->second->Write(msg);
}

bool GrpcRelaySessionManager::forward_through_mesh(uint32_t target_server_id,
                                                    const edgelink::MeshForward& forward) {
    std::shared_lock lock(mesh_mutex_);
    auto it = mesh_sessions_.find(target_server_id);
    if (it == mesh_sessions_.end()) {
        return false;
    }

    edgelink::MeshMessage msg;
    *msg.mutable_mesh_forward() = forward;
    return it->second->Write(msg);
}

bool GrpcRelaySessionManager::validate_relay_token(const std::string& token,
                                                    uint32_t& node_id,
                                                    std::string& virtual_ip) {
    try {
        auto claims = verify_jwt(jwt_secret_, token);

        // Check token type
        if (claims.count("type") == 0 || claims.at("type") != "relay") {
            return false;
        }

        // Check blacklist
        if (claims.count("jti")) {
            std::shared_lock lock(blacklist_mutex_);
            if (token_blacklist_.count(claims.at("jti"))) {
                return false;
            }
        }

        node_id = std::stoul(claims.at("node_id"));
        virtual_ip = claims.count("virtual_ip") ? claims.at("virtual_ip") : "";

        return true;
    } catch (const std::exception& e) {
        LOG_DEBUG("GrpcRelaySessionManager: Token validation failed: {}", e.what());
        return false;
    }
}

void GrpcRelaySessionManager::update_node_locations(
    const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations) {
    std::unique_lock lock(locations_mutex_);
    node_locations_.clear();
    for (const auto& [node_id, relay_ids] : locations) {
        node_locations_[node_id] = relay_ids;
    }
}

std::vector<uint32_t> GrpcRelaySessionManager::get_node_relay_locations(
    uint32_t node_id) const {
    std::shared_lock lock(locations_mutex_);
    auto it = node_locations_.find(node_id);
    if (it != node_locations_.end()) {
        return it->second;
    }
    return {};
}

void GrpcRelaySessionManager::add_to_blacklist(const std::string& jti,
                                                int64_t expires_at) {
    std::unique_lock lock(blacklist_mutex_);
    token_blacklist_[jti] = expires_at;
}

size_t GrpcRelaySessionManager::client_count() const {
    std::shared_lock lock(client_mutex_);
    return client_sessions_.size();
}

size_t GrpcRelaySessionManager::mesh_count() const {
    std::shared_lock lock(mesh_mutex_);
    return mesh_sessions_.size();
}

// ============================================================================
// RelayServiceImpl
// ============================================================================

RelayServiceImpl::RelayServiceImpl(GrpcRelaySessionManager* session_manager,
                                   const std::string& jwt_secret)
    : session_manager_(session_manager)
    , jwt_secret_(jwt_secret)
{}

grpc::Status RelayServiceImpl::Relay(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream) {

    LOG_INFO("RelayServiceImpl: New client connection from {}", context->peer());

    RelayStreamHandler handler(stream, session_manager_, jwt_secret_);
    handler.run();

    return grpc::Status::OK;
}

// ============================================================================
// MeshServiceImpl
// ============================================================================

MeshServiceImpl::MeshServiceImpl(GrpcRelaySessionManager* session_manager,
                                 const std::string& server_token,
                                 uint32_t server_id)
    : session_manager_(session_manager)
    , server_token_(server_token)
    , server_id_(server_id)
{}

grpc::Status MeshServiceImpl::Mesh(
    grpc::ServerContext* context,
    grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream) {

    LOG_INFO("MeshServiceImpl: New mesh connection from {}", context->peer());

    MeshStreamHandler handler(stream, session_manager_, server_token_, server_id_);
    handler.run();

    return grpc::Status::OK;
}

// ============================================================================
// GrpcRelayServer Implementation
// ============================================================================

GrpcRelayServer::GrpcRelayServer(const ServerConfig& config)
    : config_(config)
    , session_manager_("")  // JWT secret set later
{}

GrpcRelayServer::~GrpcRelayServer() {
    stop();
}

void GrpcRelayServer::start() {
    if (running_) return;

    setup_ssl_credentials();

    std::string address = config_.relay.listen_address + ":" +
                          std::to_string(config_.relay.listen_port);

    relay_service_ = std::make_unique<RelayServiceImpl>(
        &session_manager_, config_.controller.token);
    mesh_service_ = std::make_unique<MeshServiceImpl>(
        &session_manager_, config_.controller.token, server_id_);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(address, credentials_);
    builder.RegisterService(relay_service_.get());
    builder.RegisterService(mesh_service_.get());

    // Configure for high throughput
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, 30000);
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 10000);
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
    builder.SetMaxReceiveMessageSize(64 * 1024);  // 64KB max message

    server_ = builder.BuildAndStart();

    if (!server_) {
        LOG_ERROR("GrpcRelayServer: Failed to start on {}", address);
        return;
    }

    running_ = true;
    LOG_INFO("GrpcRelayServer: Listening on {}", address);
}

void GrpcRelayServer::stop() {
    if (!running_) return;

    if (server_) {
        server_->Shutdown();
        server_.reset();
    }

    running_ = false;
    LOG_INFO("GrpcRelayServer: Stopped");
}

void GrpcRelayServer::set_controller_client(std::shared_ptr<ControllerClient> client) {
    controller_client_ = std::move(client);
}

bool GrpcRelayServer::forward_data(uint32_t src_node, uint32_t dst_node,
                                    const std::vector<uint8_t>& data) {
    edgelink::DataPacket packet;
    packet.set_src_node_id(src_node);
    packet.set_dst_node_id(dst_node);
    packet.set_encrypted_data(data.data(), data.size());

    // Try local delivery
    if (session_manager_.send_to_node(dst_node, packet)) {
        stats_.packets_forwarded++;
        stats_.bytes_forwarded += data.size();
        return true;
    }

    // Try mesh forwarding
    auto locations = session_manager_.get_node_relay_locations(dst_node);
    if (!locations.empty()) {
        edgelink::MeshForward forward;
        forward.set_src_server_id(server_id_);
        forward.set_dst_server_id(locations[0]);
        *forward.mutable_data() = packet;

        if (session_manager_.forward_through_mesh(locations[0], forward)) {
            stats_.packets_forwarded++;
            stats_.bytes_forwarded += data.size();
            return true;
        }
    }

    return false;
}

void GrpcRelayServer::setup_ssl_credentials() {
    if (config_.relay.tls.enabled) {
        std::ifstream cert_file(config_.relay.tls.cert_file);
        std::string cert((std::istreambuf_iterator<char>(cert_file)),
                         std::istreambuf_iterator<char>());

        std::ifstream key_file(config_.relay.tls.key_file);
        std::string key((std::istreambuf_iterator<char>(key_file)),
                        std::istreambuf_iterator<char>());

        grpc::SslServerCredentialsOptions ssl_opts;
        ssl_opts.pem_key_cert_pairs.push_back({key, cert});

        credentials_ = grpc::SslServerCredentials(ssl_opts);
        LOG_INFO("GrpcRelayServer: Using TLS");
    } else {
        credentials_ = grpc::InsecureServerCredentials();
        LOG_WARN("GrpcRelayServer: Using insecure credentials (no TLS)");
    }
}

} // namespace edgelink

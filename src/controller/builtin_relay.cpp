#include "builtin_relay.hpp"
#include "common/log.hpp"

namespace edgelink::controller {

// ============================================================================
// RelaySessionManager Implementation
// ============================================================================

RelaySessionManager::RelaySessionManager(const std::string& jwt_secret)
    : jwt_secret_(jwt_secret) {
}

void RelaySessionManager::add_session(uint32_t node_id,
    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream) {
    std::unique_lock lock(sessions_mutex_);
    sessions_[node_id] = stream;
    LOG_DEBUG("RelaySessionManager: Added session for node {}", node_id);
}

void RelaySessionManager::remove_session(uint32_t node_id) {
    std::unique_lock lock(sessions_mutex_);
    sessions_.erase(node_id);
    LOG_DEBUG("RelaySessionManager: Removed session for node {}", node_id);
}

bool RelaySessionManager::send_to_node(uint32_t node_id, const edgelink::DataPacket& packet) {
    std::shared_lock lock(sessions_mutex_);

    auto it = sessions_.find(node_id);
    if (it == sessions_.end()) {
        return false;
    }

    edgelink::RelayMessage msg;
    *msg.mutable_data() = packet;

    return it->second->Write(msg);
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

    node_id = claims->node_id;
    // RelayTokenClaims doesn't have virtual_ip - it's only in AuthTokenClaims
    virtual_ip = "";
    return true;
}

size_t RelaySessionManager::session_count() const {
    std::shared_lock lock(sessions_mutex_);
    return sessions_.size();
}

// ============================================================================
// RelayStreamHandler Implementation
// ============================================================================

RelayStreamHandler::RelayStreamHandler(
    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream,
    RelaySessionManager* session_manager)
    : stream_(stream)
    , session_manager_(session_manager) {
}

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
                LOG_WARN("RelayStreamHandler: Unknown message type");
                break;
        }
    }

    // Connection closed
    if (authenticated_ && node_id_ > 0) {
        session_manager_->remove_session(node_id_);
        if (close_callback_) {
            close_callback_(node_id_);
        }
    }
}

void RelayStreamHandler::handle_relay_auth(const edgelink::RelayAuth& auth) {
    uint32_t node_id = 0;
    std::string virtual_ip;

    if (!session_manager_->validate_relay_token(auth.relay_token(), node_id, virtual_ip)) {
        LOG_WARN("RelayStreamHandler: Invalid relay token");
        send_auth_response(false, 0, "Invalid relay token");
        return;
    }

    node_id_ = node_id;
    virtual_ip_ = virtual_ip;
    authenticated_ = true;

    // Register session
    session_manager_->add_session(node_id_, stream_);

    LOG_INFO("RelayStreamHandler: Node {} authenticated", node_id_);
    send_auth_response(true, node_id_);
}

void RelayStreamHandler::handle_data(const edgelink::DataPacket& packet) {
    if (!authenticated_) {
        LOG_WARN("RelayStreamHandler: Data from unauthenticated session");
        return;
    }

    // Verify sender
    if (packet.src_node_id() != node_id_) {
        LOG_WARN("RelayStreamHandler: Spoofed src_node_id {} from node {}",
                 packet.src_node_id(), node_id_);
        return;
    }

    // Forward to destination
    if (!session_manager_->send_to_node(packet.dst_node_id(), packet)) {
        LOG_DEBUG("RelayStreamHandler: Failed to forward to node {} (offline?)",
                  packet.dst_node_id());
    }

    if (data_callback_) {
        std::vector<uint8_t> data(packet.encrypted_data().begin(),
                                  packet.encrypted_data().end());
        data_callback_(packet.src_node_id(), packet.dst_node_id(), data);
    }
}

void RelayStreamHandler::handle_ping(const edgelink::Ping& ping) {
    send_pong(ping.timestamp());
}

void RelayStreamHandler::send_auth_response(bool success, uint32_t node_id, const std::string& error) {
    edgelink::RelayMessage msg;
    auto* resp = msg.mutable_relay_auth_response();
    resp->set_success(success);
    resp->set_node_id(node_id);
    if (!error.empty()) {
        resp->set_error_message(error);
    }
    stream_->Write(msg);
}

void RelayStreamHandler::send_pong(uint64_t timestamp) {
    edgelink::RelayMessage msg;
    msg.mutable_pong()->set_timestamp(timestamp);
    stream_->Write(msg);
}

void RelayStreamHandler::send_error(edgelink::ErrorCode code, const std::string& message) {
    edgelink::RelayMessage msg;
    auto* err = msg.mutable_error();
    err->set_code(code);
    err->set_message(message);
    stream_->Write(msg);
}

// ============================================================================
// BuiltinRelayServiceImpl Implementation
// ============================================================================

BuiltinRelayServiceImpl::BuiltinRelayServiceImpl(RelaySessionManager* session_manager,
                                                 std::shared_ptr<Database> db)
    : session_manager_(session_manager)
    , db_(std::move(db)) {
}

grpc::Status BuiltinRelayServiceImpl::Relay(
    grpc::ServerContext* /*context*/,
    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream) {

    RelayStreamHandler handler(stream, session_manager_);
    handler.run();

    return grpc::Status::OK;
}

// ============================================================================
// BuiltinRelay Implementation
// ============================================================================

BuiltinRelay::BuiltinRelay(const BuiltinRelayConfig& config,
                           std::shared_ptr<Database> db,
                           const std::string& jwt_secret)
    : config_(config)
    , db_(std::move(db))
    , jwt_secret_(jwt_secret)
    , session_manager_(jwt_secret) {

    relay_service_ = std::make_unique<BuiltinRelayServiceImpl>(&session_manager_, db_);

    if (config_.enabled) {
        LOG_INFO("BuiltinRelay initialized (gRPC mode)");
    }
}

BuiltinRelay::~BuiltinRelay() = default;

bool BuiltinRelay::forward_data(uint32_t dst_node_id, const std::vector<uint8_t>& data,
                                uint32_t src_node_id) {
    edgelink::DataPacket packet;
    packet.set_src_node_id(src_node_id);
    packet.set_dst_node_id(dst_node_id);
    packet.set_encrypted_data(data.data(), data.size());

    if (session_manager_.send_to_node(dst_node_id, packet)) {
        stats_.packets_forwarded++;
        stats_.bytes_forwarded += data.size();
        return true;
    }

    return false;
}

} // namespace edgelink::controller

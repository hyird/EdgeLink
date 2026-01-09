#include "ws_relay_server_coro.hpp"
#include "ws_relay_session_coro.hpp"
#include "common/log.hpp"

#include <chrono>

namespace edgelink {

WsRelayServerCoro::WsRelayServerCoro(IOContextPool& pool, const ServerConfig& config)
    : WsServerCoro(pool, config.relay.listen_address, config.relay.listen_port)
    , config_(config)
    , jwt_manager_(std::make_unique<JWTManager>(jwt_secret_))
    , data_forwarder_(pool)
{
    // Enable TLS if configured
    if (config.relay.tls.enabled &&
        !config.relay.tls.cert_file.empty() &&
        !config.relay.tls.key_file.empty()) {
        enable_tls(config.relay.tls.cert_file, config.relay.tls.key_file);
    }

    // Initialize the data forwarder (sets up per-thread inboxes and session managers)
    data_forwarder_.initialize();

    // Set up session factory
    set_session_factory([this](net::io_context& ioc, tcp::socket socket, const std::string& path)
        -> std::shared_ptr<WsSessionCoro> {
        return create_session(ioc, std::move(socket), path);
    });
}

WsRelayServerCoro::~WsRelayServerCoro() {
    stop();
}

void WsRelayServerCoro::set_server_id(uint32_t id) {
    server_id_ = id;
    LOG_INFO("WsRelayServerCoro: Server ID set to {}", id);
}

void WsRelayServerCoro::set_controller_client(std::shared_ptr<ControllerClient> client) {
    controller_client_ = client;
}

void WsRelayServerCoro::set_jwt_secret(const std::string& secret) {
    std::unique_lock lock(jwt_mutex_);
    jwt_secret_ = secret;
    jwt_manager_ = std::make_unique<JWTManager>(secret);
    LOG_DEBUG("WsRelayServerCoro: JWT secret updated");
}

bool WsRelayServerCoro::validate_relay_token(const std::string& token, uint32_t& node_id,
                                              std::string& virtual_ip) {
    std::shared_lock jwt_lock(jwt_mutex_);

    auto result = jwt_manager_->verify_relay_token(token);
    if (!result) {
        LOG_DEBUG("WsRelayServerCoro: Token validation failed");
        return false;
    }

    // Check if token is in blacklist
    {
        std::shared_lock bl_lock(blacklist_mutex_);
        auto it = token_blacklist_.find(result->jti);
        if (it != token_blacklist_.end()) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (now < it->second) {
                LOG_DEBUG("WsRelayServerCoro: Token {} is blacklisted", result->jti);
                return false;
            }
        }
    }

    node_id = result->node_id;
    virtual_ip = std::to_string(result->network_id);  // Use network_id as placeholder
    return true;
}

void WsRelayServerCoro::add_to_blacklist(const std::string& jti, int64_t expires_at) {
    std::unique_lock lock(blacklist_mutex_);
    token_blacklist_[jti] = expires_at;
    LOG_DEBUG("WsRelayServerCoro: Added {} to token blacklist", jti);
}

void WsRelayServerCoro::update_node_locations(
    const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations) {
    std::unique_lock lock(locations_mutex_);
    for (const auto& [node_id, relay_ids] : locations) {
        node_locations_[node_id] = relay_ids;
    }
    LOG_DEBUG("WsRelayServerCoro: Updated {} node locations", locations.size());
}

std::vector<uint32_t> WsRelayServerCoro::get_node_relay_locations(uint32_t node_id) const {
    std::shared_lock lock(locations_mutex_);
    auto it = node_locations_.find(node_id);
    if (it != node_locations_.end()) {
        return it->second;
    }
    return {};
}

void WsRelayServerCoro::add_client_session(uint32_t node_id, std::shared_ptr<WsSessionCoro> session) {
    // Register node location in global directory
    size_t thread_idx = session->thread_index();
    GlobalSessionDirectory::instance().register_node(node_id, thread_idx);

    // Add to thread-local session manager
    auto* local_mgr = data_forwarder_.get_local_manager(thread_idx);
    if (local_mgr) {
        local_mgr->add_session(node_id, session->network_id(), session, "");
    }

    LOG_DEBUG("WsRelayServerCoro: Added client session for node {} on thread {}", node_id, thread_idx);
}

void WsRelayServerCoro::remove_client_session(uint32_t node_id) {
    // Get thread index before unregistering
    auto thread_opt = GlobalSessionDirectory::instance().get_node_thread(node_id);

    // Unregister from global directory
    GlobalSessionDirectory::instance().unregister_node(node_id);

    // Remove from thread-local session manager
    if (thread_opt) {
        auto* local_mgr = data_forwarder_.get_local_manager(*thread_opt);
        if (local_mgr) {
            local_mgr->remove_session(node_id);
        }
    }

    LOG_DEBUG("WsRelayServerCoro: Removed client session for node {}", node_id);
}

void WsRelayServerCoro::add_mesh_session(uint32_t server_id, std::shared_ptr<WsSessionCoro> session) {
    std::unique_lock lock(mesh_mutex_);
    mesh_sessions_[server_id] = session;
    LOG_DEBUG("WsRelayServerCoro: Added mesh session for server {}", server_id);
}

void WsRelayServerCoro::remove_mesh_session(uint32_t server_id) {
    std::unique_lock lock(mesh_mutex_);
    mesh_sessions_.erase(server_id);
    LOG_DEBUG("WsRelayServerCoro: Removed mesh session for server {}", server_id);
}

std::shared_ptr<WsSessionCoro> WsRelayServerCoro::get_mesh_session(uint32_t server_id) {
    std::shared_lock lock(mesh_mutex_);
    auto it = mesh_sessions_.find(server_id);
    if (it != mesh_sessions_.end()) {
        return it->second.lock();
    }
    return nullptr;
}

bool WsRelayServerCoro::forward_data(uint32_t src_node, uint32_t dst_node, std::vector<uint8_t> data) {
    // Try local forwarding first via DataForwarder
    if (data_forwarder_.forward(src_node, dst_node, std::move(data))) {
        stats_.bytes_forwarded += data.size();
        stats_.packets_forwarded++;
        return true;
    }

    // Check if we know which relay the destination is connected to
    auto relay_ids = get_node_relay_locations(dst_node);
    if (!relay_ids.empty()) {
        // Forward via mesh to another relay
        for (uint32_t relay_id : relay_ids) {
            // Don't forward to ourselves
            if (relay_id == server_id_) continue;

            auto mesh_session = get_mesh_session(relay_id);
            if (mesh_session) {
                // Create MESH_FORWARD frame
                wire::MeshForwardPayload mesh_payload;
                mesh_payload.src_relay_id = server_id_;
                mesh_payload.dst_node_id = dst_node;
                mesh_payload.ttl = 3;  // Max 3 hops
                mesh_payload.data = std::move(data);

                auto payload_bytes = mesh_payload.serialize_binary();
                auto frame = wire::Frame::create(
                    wire::MessageType::MESH_FORWARD,
                    std::move(payload_bytes));

                mesh_session->send_frame(frame);

                stats_.bytes_forwarded += data.size();
                stats_.packets_forwarded++;

                LOG_DEBUG("WsRelayServerCoro: Forwarded data for node {} via mesh to relay {}",
                          dst_node, relay_id);
                return true;
            }
        }

        LOG_DEBUG("WsRelayServerCoro: Node {} is on relay {} but no mesh connection available",
                  dst_node, relay_ids[0]);
    }

    LOG_DEBUG("WsRelayServerCoro: Cannot forward to node {} - not found", dst_node);
    return false;
}

void WsRelayServerCoro::handle_mesh_forward(const wire::MeshForwardPayload& payload) {
    // Check TTL
    if (payload.ttl == 0) {
        LOG_DEBUG("WsRelayServerCoro: MESH_FORWARD TTL expired for node {}", payload.dst_node_id);
        return;
    }

    // Try to deliver locally
    if (data_forwarder_.forward(0, payload.dst_node_id, std::vector<uint8_t>(payload.data))) {
        stats_.bytes_forwarded += payload.data.size();
        stats_.packets_forwarded++;
        LOG_DEBUG("WsRelayServerCoro: Delivered MESH_FORWARD to local node {}", payload.dst_node_id);
        return;
    }

    // Need to forward to another relay
    auto relay_ids = get_node_relay_locations(payload.dst_node_id);
    for (uint32_t relay_id : relay_ids) {
        // Don't forward to source relay or ourselves
        if (relay_id == payload.src_relay_id || relay_id == server_id_) continue;

        auto mesh_session = get_mesh_session(relay_id);
        if (mesh_session) {
            // Create new MESH_FORWARD with decremented TTL
            wire::MeshForwardPayload fwd_payload;
            fwd_payload.src_relay_id = server_id_;
            fwd_payload.dst_node_id = payload.dst_node_id;
            fwd_payload.ttl = payload.ttl - 1;
            fwd_payload.data = payload.data;

            auto payload_bytes = fwd_payload.serialize_binary();
            auto frame = wire::Frame::create(
                wire::MessageType::MESH_FORWARD,
                std::move(payload_bytes));

            mesh_session->send_frame(frame);

            LOG_DEBUG("WsRelayServerCoro: Re-forwarded MESH_FORWARD to relay {} (TTL={})",
                      relay_id, fwd_payload.ttl);
            return;
        }
    }

    LOG_DEBUG("WsRelayServerCoro: Cannot forward MESH_FORWARD for node {} - no route",
              payload.dst_node_id);
}

size_t WsRelayServerCoro::client_count() const {
    // Count nodes across all threads
    // This is approximate since we're reading from multiple thread-local managers
    return GlobalSessionDirectory::instance().total_node_count();
}

size_t WsRelayServerCoro::mesh_count() const {
    std::shared_lock lock(mesh_mutex_);
    return mesh_sessions_.size();
}

std::shared_ptr<WsSessionCoro> WsRelayServerCoro::create_session(
    net::io_context& ioc,
    tcp::socket socket,
    const std::string& path) {

    // Only accept relay connections on /api/v1/relay path
    if (path != "/api/v1/relay" && path != "/relay") {
        LOG_DEBUG("WsRelayServerCoro: Rejected connection for path: {}", path);
        return nullptr;
    }

    return std::make_shared<WsRelaySessionCoro>(ioc, std::move(socket), this);
}

} // namespace edgelink

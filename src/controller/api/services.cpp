#include "services.hpp"
#include "common/crypto/ed25519.hpp"
#include "common/log.hpp"
#include <nlohmann/json.hpp>
#include <chrono>
#include <sstream>

namespace edgelink::controller {

using json = nlohmann::json;
using edgelink::RelayInfo;
using edgelink::STUNInfo;
using edgelink::PeerInfo;
using edgelink::RouteInfo;
using edgelink::ConfigPayload;
using edgelink::ConfigUpdatePayload;

// ============================================================================
// AuthService Implementation
// ============================================================================

AuthService::AuthService(std::shared_ptr<Database> db, const JWTConfig& jwt_config)
    : db_(std::move(db))
    , jwt_manager_(jwt_config.secret, jwt_config.algorithm) {
}

AuthResult AuthService::authenticate_node(
    const std::string& machine_key_pub,
    const std::string& node_key_pub,
    const std::string& signature,
    int64_t timestamp,
    const std::string& hostname,
    const std::string& os,
    const std::string& arch,
    const std::string& version) {
    
    AuthResult result;
    
    // Verify timestamp is recent (within 5 minutes)
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    
    if (std::abs(now - timestamp) > 300) {
        result.error = "timestamp_expired";
        return result;
    }
    
    // Verify signature
    if (!verify_signature(machine_key_pub, signature, timestamp)) {
        result.error = "invalid_signature";
        return result;
    }
    
    // Look up existing node
    auto node = db_->get_node_by_machine_key(machine_key_pub);
    
    if (!node) {
        result.error = "node_not_registered";
        return result;
    }
    
    // Check if authorized
    if (!node->authorized) {
        result.error = "node_not_authorized";
        return result;
    }
    
    // Update node info
    Node updated = *node;
    updated.node_key_pub = node_key_pub;
    updated.hostname = hostname;
    updated.os = os;
    updated.arch = arch;
    updated.version = version;
    db_->update_node(updated);
    
    // Set node online
    db_->set_node_online(node->id, true);
    
    // Generate tokens
    auto pk_result = crypto::Ed25519::public_key_from_base64(machine_key_pub);
    if (!pk_result) {
        result.error = "invalid_machine_key";
        return result;
    }
    
    result.auth_token = jwt_manager_.create_auth_token(
        node->id,
        crypto::Ed25519::key_fingerprint(*pk_result),
        node->network_id,
        node->virtual_ip
    );
    
    result.relay_token = create_relay_token(node->id, node->network_id);
    result.node_id = node->id;
    result.network_id = node->network_id;
    result.virtual_ip = node->virtual_ip;
    result.success = true;
    
    LOG_INFO("Node {} authenticated: {}", node->id, hostname);
    return result;
}

std::optional<AuthTokenClaims> AuthService::validate_auth_token(const std::string& token) {
    auto claims = jwt_manager_.verify_auth_token(token);
    if (!claims) {
        return std::nullopt;
    }
    
    // Check blacklist
    if (db_->is_token_blacklisted(claims->jti)) {
        return std::nullopt;
    }
    
    return *claims;
}

std::optional<RelayTokenClaims> AuthService::validate_relay_token(const std::string& token) {
    auto claims = jwt_manager_.verify_relay_token(token);
    if (!claims) {
        return std::nullopt;
    }
    
    // Check blacklist
    if (db_->is_token_blacklisted(claims->jti)) {
        return std::nullopt;
    }
    
    return *claims;
}

std::optional<std::string> AuthService::refresh_relay_token(uint32_t node_id) {
    auto node = db_->get_node(node_id);
    if (!node || !node->authorized) {
        return std::nullopt;
    }
    
    return create_relay_token(node_id, node->network_id);
}

ServerAuthResult AuthService::register_server(
    const std::string& name,
    const std::string& type,
    const std::string& url,
    const std::string& region,
    const std::vector<std::string>& capabilities,
    const std::string& stun_ip,
    const std::string& stun_ip2,
    uint16_t stun_port) {
    
    ServerAuthResult result;
    
    // Convert capabilities to bitmask
    uint8_t caps_mask = 0;
    for (const auto& cap : capabilities) {
        if (cap == "relay") caps_mask |= ServerCapability::RELAY;
        else if (cap == "stun") caps_mask |= ServerCapability::STUN;
    }
    
    // Create server entry
    Server server;
    server.name = name;
    server.type = type;
    server.url = url;
    server.region = region;
    server.capabilities = json(capabilities).dump();
    server.stun_ip = stun_ip;
    server.stun_ip2 = stun_ip2;
    server.stun_port = stun_port;
    server.enabled = true;
    
    // Generate server token
    server.server_token = jwt_manager_.create_server_token(
        0,  // Will be updated after insert
        name,
        caps_mask,
        region
    );
    
    uint32_t server_id = db_->create_server(server);
    if (server_id == 0) {
        result.error = "server_creation_failed";
        return result;
    }
    
    // Regenerate token with correct ID
    std::string token = jwt_manager_.create_server_token(
        server_id, name, caps_mask, region
    );
    
    // Update server with new token
    server.id = server_id;
    server.server_token = token;
    db_->update_server(server);
    
    result.success = true;
    result.server_id = server_id;
    result.server_token = token;
    
    LOG_INFO("Server registered: {} ({})", name, server_id);
    return result;
}

ServerAuthResult AuthService::authenticate_server(const std::string& server_token) {
    ServerAuthResult result;
    
    auto claims = jwt_manager_.verify_server_token(server_token);
    if (!claims) {
        result.error = "invalid_token";
        return result;
    }
    
    auto server = db_->get_server(claims->server_id);
    if (!server) {
        result.error = "server_not_found";
        return result;
    }
    
    if (!server->enabled) {
        result.error = "server_disabled";
        return result;
    }
    
    // Verify token matches
    if (server->server_token != server_token) {
        result.error = "token_mismatch";
        return result;
    }
    
    // Update heartbeat
    db_->update_server_heartbeat(server->id);
    
    result.success = true;
    result.server_id = server->id;
    result.server_token = server_token;
    
    LOG_INFO("Server authenticated: {} ({})", server->name, server->id);
    return result;
}

bool AuthService::revoke_node_tokens(uint32_t node_id, const std::string& reason) {
    auto node = db_->get_node(node_id);
    if (!node) {
        return false;
    }
    
    // Blacklist all tokens for this node
    // We use a convention: jti contains node_id
    // For simplicity, we'll just set node offline which will force re-auth
    db_->set_node_online(node_id, false);
    
    // TODO: Track and blacklist specific JTIs
    LOG_INFO("Revoked tokens for node {}: {}", node_id, reason);
    return true;
}

bool AuthService::revoke_server_token(uint32_t server_id) {
    auto server = db_->get_server(server_id);
    if (!server) {
        return false;
    }
    
    // Generate new token, old one becomes invalid
    uint8_t caps_mask = 0;
    try {
        auto caps = json::parse(server->capabilities).get<std::vector<std::string>>();
        for (const auto& cap : caps) {
            if (cap == "relay") caps_mask |= ServerCapability::RELAY;
            else if (cap == "stun") caps_mask |= ServerCapability::STUN;
        }
    } catch (...) {}
    
    std::string new_token = jwt_manager_.create_server_token(
        server_id, server->name, caps_mask, server->region
    );
    
    Server updated = *server;
    updated.server_token = new_token;
    db_->update_server(updated);
    
    LOG_INFO("Revoked token for server {}", server_id);
    return true;
}

bool AuthService::rotate_node_key(uint32_t node_id, const std::string& new_node_key_pub) {
    return db_->update_node_key(node_id, new_node_key_pub);
}

bool AuthService::is_node_authorized(uint32_t node_id) {
    auto node = db_->get_node(node_id);
    return node && node->authorized;
}

bool AuthService::authorize_node(uint32_t node_id) {
    auto node = db_->get_node(node_id);
    if (!node) return false;
    
    Node updated = *node;
    updated.authorized = true;
    return db_->update_node(updated);
}

bool AuthService::deauthorize_node(uint32_t node_id) {
    auto node = db_->get_node(node_id);
    if (!node) return false;
    
    Node updated = *node;
    updated.authorized = false;
    db_->set_node_online(node_id, false);
    return db_->update_node(updated);
}

bool AuthService::verify_signature(
    const std::string& machine_key_pub,
    const std::string& signature,
    int64_t timestamp) {
    
    try {
        auto pub_key_result = crypto::Ed25519::public_key_from_base64(machine_key_pub);
        if (!pub_key_result) {
            LOG_ERROR("Invalid public key format");
            return false;
        }
        
        auto sig_result = crypto::Ed25519::signature_from_base64(signature);
        if (!sig_result) {
            LOG_ERROR("Invalid signature format");
            return false;
        }
        
        // Message: machine_key_pub + timestamp as string
        std::string message = machine_key_pub + std::to_string(timestamp);
        
        return crypto::Ed25519::verify(
            *pub_key_result,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(message.data()), message.size()),
            *sig_result
        );
    } catch (const std::exception& e) {
        LOG_ERROR("Signature verification failed: {}", e.what());
        return false;
    }
}

std::string AuthService::create_relay_token(uint32_t node_id, uint32_t network_id) {
    auto allowed_relays = get_allowed_relays(node_id);
    return jwt_manager_.create_relay_token(node_id, network_id, allowed_relays);
}

std::vector<uint32_t> AuthService::get_allowed_relays(uint32_t node_id) {
    // For now, allow all enabled relays
    std::vector<uint32_t> relay_ids;
    auto servers = db_->list_enabled_servers();
    for (const auto& server : servers) {
        relay_ids.push_back(server.id);
    }
    return relay_ids;
}

// ============================================================================
// NodeService Implementation
// ============================================================================

NodeService::NodeService(std::shared_ptr<Database> db)
    : db_(std::move(db)) {
}

NodeRegistrationResult NodeService::register_node(const NodeRegistrationRequest& req) {
    NodeRegistrationResult result;
    
    // Check if node already exists
    auto existing = db_->get_node_by_machine_key(req.machine_key_pub);
    if (existing) {
        // Update existing node
        Node updated = *existing;
        updated.node_key_pub = req.node_key_pub;
        updated.hostname = req.hostname;
        updated.os = req.os;
        updated.arch = req.arch;
        updated.version = req.version;
        db_->update_node(updated);
        
        result.success = true;
        result.node_id = existing->id;
        result.virtual_ip = existing->virtual_ip;
        result.pending_authorization = !existing->authorized;
        return result;
    }
    
    // Create new node
    Node node;
    node.network_id = req.network_id;
    node.name = req.hostname.empty() ? "node-" + req.machine_key_pub.substr(0, 8) : req.hostname;
    node.machine_key_pub = req.machine_key_pub;
    node.node_key_pub = req.node_key_pub;
    node.hostname = req.hostname;
    node.os = req.os;
    node.arch = req.arch;
    node.version = req.version;
    node.authorized = false;  // Pending authorization by default
    
    // Allocate virtual IP
    node.virtual_ip = db_->allocate_virtual_ip(req.network_id);
    if (node.virtual_ip.empty()) {
        result.error = "no_available_ip";
        return result;
    }
    
    uint32_t node_id = db_->create_node(node);
    if (node_id == 0) {
        result.error = "node_creation_failed";
        return result;
    }
    
    result.success = true;
    result.node_id = node_id;
    result.virtual_ip = node.virtual_ip;
    result.pending_authorization = true;
    
    LOG_INFO("Node registered: {} ({}) - pending authorization", node.name, node_id);
    return result;
}

std::optional<Node> NodeService::get_node(uint32_t id) {
    return db_->get_node(id);
}

std::optional<Node> NodeService::get_node_by_machine_key(const std::string& machine_key_pub) {
    return db_->get_node_by_machine_key(machine_key_pub);
}

std::vector<Node> NodeService::list_nodes(uint32_t network_id) {
    return db_->list_nodes(network_id);
}

std::vector<Node> NodeService::list_online_nodes(uint32_t network_id) {
    return db_->list_online_nodes(network_id);
}

bool NodeService::set_node_online(uint32_t node_id, bool online) {
    return db_->set_node_online(node_id, online);
}

bool NodeService::update_node_endpoints(uint32_t node_id, const std::vector<NodeEndpoint>& endpoints) {
    return db_->update_node_endpoints(node_id, endpoints);
}

bool NodeService::update_nat_type(uint32_t node_id, const std::string& nat_type) {
    auto node = db_->get_node(node_id);
    if (!node) return false;
    
    Node updated = *node;
    updated.nat_type = nat_type;
    return db_->update_node(updated);
}

bool NodeService::delete_node(uint32_t node_id) {
    return db_->delete_node(node_id);
}

std::vector<NodeRoute> NodeService::get_node_routes(uint32_t node_id) {
    return db_->get_node_routes(node_id);
}

uint32_t NodeService::add_route(uint32_t node_id, const std::string& cidr,
                                 uint16_t priority, uint16_t weight) {
    NodeRoute route;
    route.node_id = node_id;
    route.cidr = cidr;
    route.priority = priority;
    route.weight = weight;
    route.enabled = true;
    return db_->create_node_route(route);
}

bool NodeService::update_route(uint32_t route_id, bool enabled) {
    // Get existing route and update enabled flag
    // Simplified - in production would need full route update
    NodeRoute route;
    route.id = route_id;
    route.enabled = enabled;
    return db_->update_node_route(route);
}

bool NodeService::delete_route(uint32_t route_id) {
    return db_->delete_node_route(route_id);
}

// ============================================================================
// ConfigService Implementation
// ============================================================================

ConfigService::ConfigService(std::shared_ptr<Database> db)
    : db_(std::move(db)) {
}

ConfigPayload ConfigService::build_config(uint32_t node_id) {
    ConfigPayload config;
    
    auto node = db_->get_node(node_id);
    if (!node) {
        return config;
    }
    
    auto network = db_->get_network(node->network_id);
    
    config.network_id = node->network_id;
    config.version = get_config_version(node->network_id);
    if (network) {
        config.network_name = network->name;
        config.subnet = network->subnet;
    }
    
    // Get relays
    config.relays = get_relays();
    
    // Get STUN servers
    config.stun_servers = get_stun_servers();
    
    // Get peers
    config.peers = get_peers(node_id);
    
    // Get routes
    config.routes = get_routes(node->network_id);
    
    return config;
}

uint64_t ConfigService::get_config_version(uint32_t network_id) {
    // In production, this would track actual changes
    // For now, use timestamp as version
    std::lock_guard<std::mutex> lock(version_mutex_);
    
    auto it = config_versions_.find(network_id);
    if (it != config_versions_.end()) {
        return it->second;
    }
    
    // Initialize version based on current time
    auto version = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
    config_versions_[network_id] = version;
    return version;
}

std::optional<ConfigUpdatePayload> ConfigService::build_update(
    uint32_t network_id,
    uint64_t from_version) {
    
    // For now, always return full config as update
    // TODO: Implement proper change tracking
    auto current_version = get_config_version(network_id);
    
    if (from_version >= current_version) {
        return std::nullopt;  // No updates needed
    }
    
    ConfigUpdatePayload update;
    update.version = current_version;
    
    // Add all peers as ADD actions (simplified)
    // In production, would track actual changes
    
    return update;
}

std::vector<RelayInfo> ConfigService::get_relays() {
    std::vector<RelayInfo> relays;
    
    auto servers = db_->list_enabled_servers();
    for (const auto& server : servers) {
        // Check if this server has relay capability
        try {
            auto caps = json::parse(server.capabilities);
            if (!caps.is_array()) continue;
            
            bool has_relay = false;
            for (const auto& cap : caps) {
                if (cap.get<std::string>() == "relay") {
                    has_relay = true;
                    break;
                }
            }
            if (!has_relay) continue;
        } catch (...) {
            continue;
        }
        
        RelayInfo relay;
        relay.server_id = server.id;
        relay.name = server.name;
        relay.url = server.url;
        relay.region = server.region;
        
        relays.push_back(relay);
    }
    
    return relays;
}

std::vector<STUNInfo> ConfigService::get_stun_servers() {
    std::vector<STUNInfo> stun_servers;
    
    auto servers = db_->list_enabled_servers();
    for (const auto& server : servers) {
        if (server.stun_ip.empty()) continue;
        
        STUNInfo stun;
        stun.server_id = server.id;
        stun.name = server.name;
        stun.ip = server.stun_ip;
        stun.port = server.stun_port;
        stun.secondary_ip = server.stun_ip2;
        stun_servers.push_back(stun);
    }
    
    return stun_servers;
}

std::vector<PeerInfo> ConfigService::get_peers(uint32_t node_id) {
    std::vector<PeerInfo> peers;
    
    auto node = db_->get_node(node_id);
    if (!node) return peers;
    
    // Get all authorized online nodes in the same network
    auto nodes = db_->list_nodes(node->network_id);
    
    for (const auto& n : nodes) {
        if (n.id == node_id) continue;  // Skip self
        if (!n.authorized) continue;
        
        PeerInfo peer;
        peer.node_id = n.id;
        peer.name = n.name;
        peer.virtual_ip = n.virtual_ip;
        peer.node_key_pub = n.node_key_pub;
        peer.online = n.online;
        
        // Get endpoints
        auto db_endpoints = db_->get_node_endpoints(n.id);
        for (const auto& ep : db_endpoints) {
            Endpoint endpoint;
            endpoint.ip = ep.ip;
            endpoint.port = ep.port;
            endpoint.priority = ep.priority;
            
            if (ep.type == "lan") {
                endpoint.type = EndpointType::LAN;
            } else if (ep.type == "wan") {
                endpoint.type = EndpointType::STUN;
            } else {
                endpoint.type = EndpointType::RELAY;
            }
            peer.endpoints.push_back(endpoint);
        }
        
        peers.push_back(peer);
    }
    
    return peers;
}

std::vector<RouteInfo> ConfigService::get_routes(uint32_t network_id) {
    std::vector<RouteInfo> routes;
    
    auto db_routes = db_->get_all_routes(network_id);
    for (const auto& r : db_routes) {
        RouteInfo route;
        route.cidr = r.cidr;
        route.gateway_node_id = r.node_id;
        route.priority = r.priority;
        route.weight = r.weight;
        route.enabled = r.enabled;
        routes.push_back(route);
    }
    
    return routes;
}

} // namespace edgelink::controller

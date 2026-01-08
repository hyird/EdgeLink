#pragma once

#include "controller/db/database.hpp"
#include "common/jwt.hpp"
#include "common/protocol.hpp"
#include "common/frame.hpp"
#include <memory>
#include <string>
#include <optional>

namespace edgelink::controller {

// Import wire types from frame.hpp and protocol.hpp (in wire:: namespace to avoid proto conflicts)
using edgelink::wire::RelayInfo;
using edgelink::wire::STUNInfo;
using edgelink::wire::PeerInfo;
using edgelink::wire::RouteInfo;
using edgelink::wire::ConfigPayload;
using edgelink::wire::ConfigUpdatePayload;
using edgelink::wire::Endpoint;
using edgelink::wire::EndpointType;

// ============================================================================
// Authentication Result
// ============================================================================

struct AuthResult {
    bool success{false};
    std::string error;
    std::string auth_token;
    std::string relay_token;
    uint32_t node_id{0};
    uint32_t network_id{0};
    std::string virtual_ip;
};

struct ServerAuthResult {
    bool success{false};
    std::string error;
    uint32_t server_id{0};
    std::string server_token;
};

// ============================================================================
// Authentication Service
// ============================================================================

class AuthService {
public:
    AuthService(std::shared_ptr<Database> db, const JWTConfig& jwt_config);
    
    // Node authentication (called when node connects)
    AuthResult authenticate_node(
        const std::string& machine_key_pub,
        const std::string& node_key_pub,
        const std::string& signature,      // Signs machine_key_pub + timestamp
        int64_t timestamp,
        const std::string& hostname,
        const std::string& os,
        const std::string& arch,
        const std::string& version
    );
    
    // Validate existing auth token
    std::optional<AuthTokenClaims> validate_auth_token(const std::string& token);
    
    // Validate relay token
    std::optional<RelayTokenClaims> validate_relay_token(const std::string& token);
    
    // Refresh relay token (returns new relay token)
    std::optional<std::string> refresh_relay_token(uint32_t node_id);
    
    // Server registration
    ServerAuthResult register_server(
        const std::string& name,
        const std::string& type,
        const std::string& url,
        const std::string& region,
        const std::vector<std::string>& capabilities,
        const std::string& stun_ip,
        const std::string& stun_ip2,
        uint16_t stun_port
    );
    
    // Server authentication (when server connects)
    ServerAuthResult authenticate_server(const std::string& server_token);
    
    // Token revocation
    bool revoke_node_tokens(uint32_t node_id, const std::string& reason);
    bool revoke_server_token(uint32_t server_id);
    
    // Key rotation
    bool rotate_node_key(uint32_t node_id, const std::string& new_node_key_pub);
    
    // Authorization check (is node authorized to connect?)
    bool is_node_authorized(uint32_t node_id);
    
    // Authorize/deauthorize node
    bool authorize_node(uint32_t node_id);
    bool deauthorize_node(uint32_t node_id);
    
    // Get JWT manager for direct access
    JWTManager& get_jwt_manager() { return jwt_manager_; }
    
private:
    std::shared_ptr<Database> db_;
    JWTManager jwt_manager_;
    
    // Verify Ed25519 signature
    bool verify_signature(
        const std::string& machine_key_pub,
        const std::string& signature,
        int64_t timestamp
    );
    
    // Generate relay token for a node
    std::string create_relay_token(uint32_t node_id, uint32_t network_id);
    
    // Get list of allowed relays for a node
    std::vector<uint32_t> get_allowed_relays(uint32_t node_id);
};

// ============================================================================
// Node Registration
// ============================================================================

struct NodeRegistrationRequest {
    std::string machine_key_pub;
    std::string node_key_pub;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;
    uint32_t network_id{1};  // Default network
};

struct NodeRegistrationResult {
    bool success{false};
    std::string error;
    uint32_t node_id{0};
    std::string virtual_ip;
    bool pending_authorization{false};
};

class NodeService {
public:
    NodeService(std::shared_ptr<Database> db);
    
    // Register a new node (or update existing)
    NodeRegistrationResult register_node(const NodeRegistrationRequest& req);
    
    // Get node by ID
    std::optional<Node> get_node(uint32_t id);
    
    // Get node by machine key
    std::optional<Node> get_node_by_machine_key(const std::string& machine_key_pub);
    
    // List all nodes in a network
    std::vector<Node> list_nodes(uint32_t network_id = 0);
    
    // List online nodes
    std::vector<Node> list_online_nodes(uint32_t network_id = 0);
    
    // Update node status
    bool set_node_online(uint32_t node_id, bool online);
    
    // Update node endpoints (reported by node)
    bool update_node_endpoints(uint32_t node_id, const std::vector<NodeEndpoint>& endpoints);
    
    // Update NAT type (detected via STUN)
    bool update_nat_type(uint32_t node_id, const std::string& nat_type);
    
    // Delete node
    bool delete_node(uint32_t node_id);
    
    // Get routes advertised by a node
    std::vector<NodeRoute> get_node_routes(uint32_t node_id);
    
    // Add/update route
    uint32_t add_route(uint32_t node_id, const std::string& cidr, 
                       uint16_t priority = 100, uint16_t weight = 100);
    bool update_route(uint32_t route_id, bool enabled);
    bool delete_route(uint32_t route_id);
    
private:
    std::shared_ptr<Database> db_;
};

// ============================================================================
// Configuration Service (builds and distributes config)
// ============================================================================

class ConfigService {
public:
    ConfigService(std::shared_ptr<Database> db);
    
    // Build full configuration for a node
    ConfigPayload build_config(uint32_t node_id);
    
    // Get current config version for a network
    uint64_t get_config_version(uint32_t network_id);
    
    // Build incremental update from old_version to current
    std::optional<ConfigUpdatePayload> build_update(
        uint32_t network_id,
        uint64_t from_version
    );
    
    // Get relay info list
    std::vector<RelayInfo> get_relays();
    
    // Get STUN info list
    std::vector<STUNInfo> get_stun_servers();
    
    // Get peer info for a specific node
    std::vector<PeerInfo> get_peers(uint32_t node_id);
    
    // Get route info for a network
    std::vector<RouteInfo> get_routes(uint32_t network_id);
    
private:
    std::shared_ptr<Database> db_;
    
    // Cache config versions per network
    mutable std::mutex version_mutex_;
    std::unordered_map<uint32_t, uint64_t> config_versions_;
};

} // namespace edgelink::controller

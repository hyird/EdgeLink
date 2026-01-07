#pragma once

#include "common/config.hpp"
#include "common/protocol.hpp"
#include <sqlite3.h>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <mutex>

namespace edgelink::controller {

// ============================================================================
// Database Models
// ============================================================================

struct Network {
    uint32_t id{0};
    std::string name;
    std::string subnet;
    std::string description;
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct Node {
    uint32_t id{0};
    uint32_t network_id{0};
    std::string name;
    std::string machine_key_pub;
    std::string node_key_pub;
    int64_t node_key_updated_at{0};
    std::string virtual_ip;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;
    std::string nat_type;
    bool online{false};
    int64_t last_seen{0};
    bool authorized{false};
    int64_t created_at{0};
    int64_t updated_at{0};
};

struct NodeEndpoint {
    uint32_t id{0};
    uint32_t node_id{0};
    std::string type;
    std::string ip;
    uint16_t port{0};
    uint8_t priority{2};
    int64_t updated_at{0};
};

struct NodeRoute {
    uint32_t id{0};
    uint32_t node_id{0};
    std::string cidr;
    uint16_t priority{100};
    uint16_t weight{100};
    bool enabled{true};
    int64_t created_at{0};
};

struct Server {
    uint32_t id{0};
    std::string name;
    std::string type;           // "builtin" or "external"
    std::string url;            // Relay WSS URL
    std::string region;
    std::string capabilities;   // JSON array
    std::string stun_ip;
    std::string stun_ip2;
    uint16_t stun_port{3478};
    bool enabled{true};
    std::string server_token;
    int64_t last_heartbeat{0};
    int64_t created_at{0};
};

struct LatencyRecord {
    uint32_t id{0};
    std::string src_type;
    uint32_t src_id{0};
    std::string dst_type;
    uint32_t dst_id{0};
    uint32_t rtt_ms{0};
    int64_t recorded_at{0};
};

struct TokenBlacklistEntry {
    std::string jti;
    uint32_t node_id{0};
    std::string reason;
    int64_t expires_at{0};
    int64_t created_at{0};
};

struct Setting {
    std::string key;
    std::string value;
    int64_t updated_at{0};
};

struct AuthKey {
    uint32_t id{0};
    std::string key;           // The auth key string
    uint32_t network_id{0};
    std::string description;
    bool reusable{false};      // Can be used multiple times
    bool ephemeral{false};     // Node will be removed when offline
    int max_uses{-1};          // -1 = unlimited (if reusable)
    int used_count{0};
    int64_t expires_at{0};     // 0 = never expires
    int64_t created_at{0};
    std::string created_by;
};

// ============================================================================
// Database Class
// ============================================================================

class Database {
public:
    explicit Database(const DatabaseConfig& config);
    ~Database();
    
    // Disable copy
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    
    // Initialize database (run migrations)
    bool initialize();
    
    // ========================================================================
    // Network Operations
    // ========================================================================
    std::optional<Network> get_network(uint32_t id);
    std::optional<Network> get_network_by_name(const std::string& name);
    std::vector<Network> list_networks();
    uint32_t create_network(const Network& network);
    bool update_network(const Network& network);
    bool delete_network(uint32_t id);
    
    // ========================================================================
    // Node Operations
    // ========================================================================
    std::optional<Node> get_node(uint32_t id);
    std::optional<Node> get_node_by_machine_key(const std::string& machine_key_pub);
    std::vector<Node> list_nodes(uint32_t network_id = 0);
    std::vector<Node> list_online_nodes(uint32_t network_id = 0);
    uint32_t create_node(const Node& node);
    bool update_node(const Node& node);
    bool delete_node(uint32_t id);
    bool set_node_online(uint32_t id, bool online);
    bool update_node_key(uint32_t id, const std::string& node_key_pub);
    std::string allocate_virtual_ip(uint32_t network_id);
    
    // ========================================================================
    // Auth Key Operations
    // ========================================================================
    std::optional<AuthKey> get_auth_key(uint32_t id);
    std::optional<AuthKey> get_auth_key_by_key(const std::string& key);
    std::vector<AuthKey> list_auth_keys(uint32_t network_id = 0);
    uint32_t create_auth_key(const AuthKey& auth_key);
    bool delete_auth_key(uint32_t id);
    bool increment_auth_key_usage(uint32_t id);
    bool is_auth_key_valid(const AuthKey& key);
    
    // ========================================================================
    // Node Endpoint Operations
    // ========================================================================
    std::vector<NodeEndpoint> get_node_endpoints(uint32_t node_id);
    bool update_node_endpoints(uint32_t node_id, const std::vector<NodeEndpoint>& endpoints);
    
    // ========================================================================
    // Node Route Operations
    // ========================================================================
    std::vector<NodeRoute> get_node_routes(uint32_t node_id);
    std::vector<NodeRoute> get_all_routes(uint32_t network_id = 0);
    uint32_t create_node_route(const NodeRoute& route);
    bool update_node_route(const NodeRoute& route);
    bool delete_node_route(uint32_t id);
    
    // ========================================================================
    // Server Operations
    // ========================================================================
    std::optional<Server> get_server(uint32_t id);
    std::vector<Server> list_servers();
    std::vector<Server> list_enabled_servers();
    uint32_t create_server(const Server& server);
    bool update_server(const Server& server);
    bool delete_server(uint32_t id);
    bool update_server_heartbeat(uint32_t id);
    
    // ========================================================================
    // Latency Operations
    // ========================================================================
    bool update_latency(const std::string& src_type, uint32_t src_id,
                        const std::string& dst_type, uint32_t dst_id,
                        uint32_t rtt_ms);
    std::vector<LatencyRecord> get_latencies();
    std::optional<uint32_t> get_latency(const std::string& src_type, uint32_t src_id,
                                         const std::string& dst_type, uint32_t dst_id);
    
    // ========================================================================
    // Token Blacklist Operations
    // ========================================================================
    bool blacklist_token(const std::string& jti, uint32_t node_id, 
                         const std::string& reason, int64_t expires_at);
    bool is_token_blacklisted(const std::string& jti);
    std::vector<TokenBlacklistEntry> get_blacklist();
    bool cleanup_blacklist();
    
    // ========================================================================
    // Settings Operations
    // ========================================================================
    std::optional<std::string> get_setting(const std::string& key);
    bool set_setting(const std::string& key, const std::string& value);
    
    // ========================================================================
    // Node-Server Connection Operations
    // ========================================================================
    bool update_node_server_connection(uint32_t node_id, uint32_t server_id);
    bool remove_node_server_connection(uint32_t node_id, uint32_t server_id);
    std::vector<uint32_t> get_node_connected_servers(uint32_t node_id);
    std::vector<uint32_t> get_server_connected_nodes(uint32_t server_id);

private:
    sqlite3* db_{nullptr};
    std::mutex mutex_;
    DatabaseConfig config_;
    
    bool execute(const std::string& sql);
    bool execute(const std::string& sql, const std::vector<std::string>& params);
};

} // namespace edgelink::controller

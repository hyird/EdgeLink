#pragma once

#include <string>
#include <vector>
#include <optional>
#include <boost/json.hpp>
#include <filesystem>

namespace edgelink {

// ============================================================================
// TLS Configuration
// ============================================================================
struct TLSConfig {
    std::string cert_path;
    std::string key_path;
    std::string ca_path;            // Optional CA for client certs
    bool verify_client{false};
    
    bool is_valid() const {
        return !cert_path.empty() && !key_path.empty();
    }
};

// ============================================================================
// HTTP Server Configuration
// ============================================================================
struct HttpConfig {
    std::string listen_address{"0.0.0.0"};
    uint16_t listen_port{443};
    bool enable_tls{true};
};

// ============================================================================
// Database Configuration
// ============================================================================
struct DatabaseConfig {
    std::string type{"sqlite"};     // "sqlite" or "mariadb"
    std::string path;               // For SQLite: database file path
    std::string host;               // For MariaDB
    uint16_t port{3306};
    std::string user;
    std::string password;
    std::string database;
    uint32_t pool_size{10};
    
    std::string connection_string() const;
};

// ============================================================================
// JWT Configuration
// ============================================================================
struct JWTConfig {
    std::string secret;
    std::string algorithm{"HS256"};
    double auth_expire_hours{24.0};
    double relay_expire_hours{1.5};
};

// ============================================================================
// Built-in Relay Configuration
// ============================================================================
struct BuiltinRelayConfig {
    bool enabled{false};
    std::string external_url;  // External URL for clients (e.g., "wss://vpn.example.com")
                               // If empty, uses http listen address
};

// ============================================================================
// Built-in STUN Configuration
// ============================================================================
struct BuiltinSTUNConfig {
    bool enabled{false};
    std::string listen{"0.0.0.0:3478"};
    std::string external_ip;        // Required: server's public IP
    std::string secondary_ip;       // Optional: for full NAT detection
};

// ============================================================================
// Controller Configuration
// ============================================================================

// gRPC service names (for reference)
namespace services {
    constexpr const char* CONTROL_SERVICE = "edgelink.ControlService";   // Client -> Controller
    constexpr const char* SERVER_SERVICE = "edgelink.ServerService";     // Server -> Controller
    constexpr const char* RELAY_SERVICE = "edgelink.RelayService";       // Client -> Relay (data)
    constexpr const char* MESH_SERVICE = "edgelink.MeshService";         // Relay <-> Relay (mesh)
}

// Legacy WebSocket paths (deprecated, kept for backwards compatibility during migration)
namespace paths {
    constexpr const char* WS_CONTROL = "/ws/control";  // Client -> Controller (deprecated)
    constexpr const char* WS_SERVER = "/ws/server";    // Server -> Controller (deprecated)
    constexpr const char* WS_DATA = "/ws/data";        // Client -> Relay (deprecated)
    constexpr const char* WS_MESH = "/ws/mesh";        // Relay <-> Relay (deprecated)
}

struct ControllerConfig {
    // HTTP settings
    HttpConfig http;
    
    // TLS
    TLSConfig tls;
    
    // Database
    DatabaseConfig database;
    
    // JWT
    JWTConfig jwt;
    
    // Security
    double node_key_rotate_hours{24.0};
    bool require_authorization{true};
    std::string server_token;  // Token for relay server registration
    
    // Built-in services
    BuiltinRelayConfig builtin_relay;
    BuiltinSTUNConfig builtin_stun;
    
    // Load from JSON file
    static std::optional<ControllerConfig> load(const std::filesystem::path& path);
    
    // Save to JSON file
    bool save(const std::filesystem::path& path) const;
    
    // Convert to/from JSON
    boost::json::object to_json() const;
    static std::optional<ControllerConfig> from_json(const boost::json::value& v);
};

// ============================================================================
// Server (Relay/STUN) Configuration
// ============================================================================
struct ServerConfig {
    // Server name
    std::string name{"relay-server"};
    
    // Controller connection
    struct ControllerConnection {
        std::string url;     // e.g., "wss://controller.example.com/ws/server"
        std::string token;   // Server authentication token
    } controller;
    
    // Relay configuration
    struct RelayConfig {
        bool enabled{true};
        std::string listen_address{"0.0.0.0"};
        uint16_t listen_port{443};
        std::string external_url;  // e.g., "wss://relay1.example.com:443"
        std::string region{"default"};
        struct TLS {
            bool enabled{false};
            std::string cert_file;
            std::string key_file;
        } tls;
    } relay;
    
    // STUN configuration
    struct STUNConfig {
        bool enabled{true};
        std::string listen_address{"0.0.0.0"};
        uint16_t listen_port{3478};
        uint16_t external_port{3478};
        std::string external_ip;
        std::string external_ip2;  // For full NAT detection
    } stun;
    
    // Mesh configuration
    struct MeshConfig {
        std::vector<std::string> peers;  // Static peer URLs (e.g., "wss://relay2.example.com/ws/mesh")
        bool auto_connect{true};         // Auto-connect to peers from controller
    } mesh;
    
    // Legacy: mesh_peers (moved to mesh.peers)
    std::vector<std::string> mesh_peers;
    
    static std::optional<ServerConfig> load(const std::filesystem::path& path);
    bool save(const std::filesystem::path& path) const;
    boost::json::object to_json() const;
    static std::optional<ServerConfig> from_json(const boost::json::value& v);
};

// ============================================================================
// Client Configuration
// ============================================================================
struct ClientConfig {
    // Controller connection
    std::string controller_url;     // e.g., "grpc://controller.example.com:8080"
    std::string auth_key;           // Pre-shared key for node registration

    // Identity
    std::string hostname;
    std::string key_file{"~/.edgelink/keys.json"};
    
    // TUN device
    struct TUNConfig {
        std::string name{"edgelink0"};
        uint16_t mtu{1400};
    } tun;
    
    // Route advertisement
    struct RouteAd {
        std::string cidr;
        uint16_t priority{100};
        uint16_t weight{100};
    };
    std::vector<RouteAd> advertise_routes;
    bool accept_routes{true};
    
    // P2P settings
    struct P2PConfig {
        bool enabled{true};
        uint32_t keepalive_interval_sec{25};
    } p2p;
    
    // Relay settings
    struct RelaySettings {
        bool connect_all{true};
        uint32_t latency_report_interval_sec{30};
    } relay;
    
    static std::optional<ClientConfig> load(const std::filesystem::path& path);
    bool save(const std::filesystem::path& path) const;
    boost::json::object to_json() const;
    static std::optional<ClientConfig> from_json(const boost::json::value& v);
};

// ============================================================================
// Key Storage (for client)
// ============================================================================
struct KeyStorage {
    std::string machine_key_pub;    // Base64 Ed25519 public key
    std::string machine_key_sec;    // Base64 Ed25519 secret key (encrypted)
    std::string node_key_pub;       // Base64 X25519 public key
    std::string node_key_sec;       // Base64 X25519 secret key (encrypted)
    int64_t node_key_created_at{0};
    
    static std::optional<KeyStorage> load(const std::filesystem::path& path);
    bool save(const std::filesystem::path& path) const;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Expand ~ in paths
std::filesystem::path expand_path(const std::string& path);

// Ensure parent directory exists
bool ensure_parent_dir(const std::filesystem::path& path);

} // namespace edgelink

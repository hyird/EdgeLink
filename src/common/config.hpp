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
    bool enabled{false};
    std::string cert_path;
    std::string key_path;
    std::string ca_path;            // Optional CA for client certs
    bool verify_client{false};

    bool is_valid() const {
        return !cert_path.empty() && !key_path.empty();
    }
};

// ============================================================================
// HTTP Server Configuration (per design doc 11.1)
// ============================================================================
struct HttpConfig {
    std::string listen_address{"0.0.0.0"};
    uint16_t listen_port{8080};         // Default 8080 per design doc
    bool enable_tls{false};             // Default false per design doc
};

// ============================================================================
// Database Configuration
// ============================================================================
struct DatabaseConfig {
    std::string type{"sqlite"};         // "sqlite" or "mariadb"
    std::string path;                   // For SQLite: database file path
    std::string host;                   // For MariaDB
    uint16_t port{3306};
    std::string user;
    std::string password;
    std::string database;
    uint32_t pool_size{10};

    std::string connection_string() const;
};

// ============================================================================
// JWT Configuration (per design doc 11.1)
// ============================================================================
struct JWTConfig {
    std::string secret;
    std::string algorithm{"HS256"};
    uint32_t auth_token_ttl{1440};      // Auth Token TTL in minutes (default 24h)
    uint32_t relay_token_ttl{90};       // Relay Token TTL in minutes (default 1.5h)
};

// ============================================================================
// Built-in Relay Configuration
// ============================================================================
struct BuiltinRelayConfig {
    bool enabled{false};
    std::string external_url;           // External URL for clients
};

// ============================================================================
// Built-in STUN Configuration (per design doc 11.1)
// ============================================================================
struct BuiltinSTUNConfig {
    bool enabled{false};
    std::string listen{"0.0.0.0:3478"};
    std::string ip;                     // Server's public IP (per design doc: builtin_stun.ip)
    std::string secondary_ip;           // Optional: for full NAT detection
};

// ============================================================================
// Controller Configuration (per design doc 11.1)
// ============================================================================

// WebSocket endpoint paths
namespace paths {
    constexpr const char* WS_CONTROL = "/control";     // Client -> Controller
    constexpr const char* WS_SERVER = "/server";       // Server -> Controller
    constexpr const char* WS_RELAY = "/relay";         // Client -> Relay (data)
    constexpr const char* WS_MESH = "/mesh";           // Relay <-> Relay (mesh)
}

struct ControllerConfig {
    // HTTP settings
    HttpConfig http;

    // TLS (separate from http.enable_tls for cert paths)
    TLSConfig tls;

    // Database
    DatabaseConfig database;

    // JWT
    JWTConfig jwt;

    // Security
    double node_key_rotate_hours{24.0};
    bool require_authorization{true};
    std::string server_token;           // Token for relay server registration

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
// Server (Relay/STUN) Configuration (per design doc 11.2)
// ============================================================================
struct ServerConfig {
    // Server name
    std::string name{"relay-server"};

    // Controller connection
    struct ControllerConnection {
        std::string url;                // e.g., "wss://controller.example.com/server"
        std::string token;              // Server authentication token
    } controller;

    // Relay configuration (per design doc 11.2)
    struct RelayConfig {
        bool enabled{true};
        std::string listen_address{"0.0.0.0"};
        uint16_t listen_port{8081};     // Default 8081 per design doc
        std::string external_url;       // e.g., "wss://relay1.example.com:8081"
        std::string region{"default"};
        struct TLS {
            bool enabled{false};        // Default false per design doc
            std::string cert_file;
            std::string key_file;
        } tls;
    } relay;

    // STUN configuration (per design doc 11.2)
    struct STUNConfig {
        bool enabled{true};             // Default true per design doc
        std::string listen_address{"0.0.0.0"};
        uint16_t listen_port{3478};     // Default 3478 per design doc
        uint16_t external_port{3478};
        std::string ip;                 // Public IP (per design doc: stun.ip)
        std::string secondary_ip;       // For full NAT detection
    } stun;

    // Mesh configuration
    struct MeshConfig {
        std::vector<std::string> peers; // Static peer URLs
        bool auto_connect{true};        // Auto-connect to peers from controller
    } mesh;

    // Legacy: mesh_peers (moved to mesh.peers)
    std::vector<std::string> mesh_peers;

    static std::optional<ServerConfig> load(const std::filesystem::path& path);
    bool save(const std::filesystem::path& path) const;
    boost::json::object to_json() const;
    static std::optional<ServerConfig> from_json(const boost::json::value& v);
};

// ============================================================================
// Client Configuration (per design doc 11.3)
// ============================================================================
struct ClientConfig {
    // Controller connection
    std::string controller_url;         // Controller WSS URL

    // Authentication
    std::string auth_key;               // Pre-shared key for node registration (empty string default)

    // Data directory
    std::string data_dir;               // Data directory for keys, state, etc.

    // Logging
    std::string log_level{"info"};      // Log level: trace, debug, info, warn, error

    // Identity
    std::string hostname;
    std::string key_file{"~/.edgelink/keys.json"};

    // TUN device
    struct TUNConfig {
        std::string name{"edgelink0"};
        uint16_t mtu{1400};
    } tun;

    // Routes configuration (per design doc 11.3)
    struct RoutesConfig {
        std::vector<std::string> advertise;  // Subnets to advertise (e.g., ["192.168.1.0/24"])
        std::vector<std::string> accept;     // Subnets to accept (default: ["*"] = all)
    } routes;

    // Exit Node configuration (per design doc 11.3)
    struct ExitNodeConfig {
        bool enabled{false};            // Enable as exit node
        std::string use;                // Use specified exit node (node ID or hostname)
    } exit_node;

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
    std::string machine_key_pub;        // Base64 Ed25519 public key
    std::string machine_key_sec;        // Base64 Ed25519 secret key (encrypted)
    std::string node_key_pub;           // Base64 X25519 public key
    std::string node_key_sec;           // Base64 X25519 secret key (encrypted)
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

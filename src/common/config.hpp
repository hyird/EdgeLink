#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <chrono>
#include <expected>

namespace edgelink {

// ============================================================================
// Configuration Error
// ============================================================================

enum class ConfigError {
    FILE_NOT_FOUND,
    PARSE_ERROR,
    INVALID_VALUE,
    MISSING_REQUIRED,
};

std::string config_error_message(ConfigError error);

// ============================================================================
// Controller Configuration
// ============================================================================

struct ControllerConfig {
    // Server settings
    std::string bind_address = "0.0.0.0";
    uint16_t port = 8080;
    size_t num_threads = 0;  // 0 = auto (hardware_concurrency)
    bool tls = false;  // Enable TLS - default disabled

    // SSL settings (only used if tls = true)
    std::string cert_file;
    std::string key_file;

    // Database settings
    std::string database_path = "edgelink.db";

    // JWT settings
    std::string jwt_secret;  // Empty = auto-generate
    std::chrono::hours auth_token_validity{24};
    std::chrono::minutes relay_token_validity{90};

    // Logging
    std::string log_level = "debug";
    std::string log_file;

    // Load from TOML file
    static std::expected<ControllerConfig, ConfigError> load(const std::string& path);

    // Load from TOML string (for testing)
    static std::expected<ControllerConfig, ConfigError> parse(const std::string& toml_content);
};

// ============================================================================
// Client Configuration
// ============================================================================

struct ClientConfig {
    // Connection settings
    std::string controller_url = "ws://localhost:8080";  // Server address (path auto-appended)
    std::string authkey;
    bool tls = false;  // Enable TLS (wss://) - default disabled

    // SSL/TLS settings
    bool ssl_verify = false;            // Verify server certificate (default: false for dev)
    std::string ssl_ca_file;            // Custom CA certificate file (empty = system default)
    bool ssl_allow_self_signed = false; // Allow self-signed certificates

    // Auto-reconnect settings
    bool auto_reconnect = true;
    std::chrono::seconds reconnect_interval{5};
    std::chrono::seconds ping_interval{30};

    // Key storage
    std::string state_dir;  // Directory for storing keys, empty = auto

    // TUN device settings
    bool enable_tun = false;       // Enable TUN device for IP-level routing
    std::string tun_name;          // TUN device name (empty = auto)
    uint32_t tun_mtu = 1420;       // MTU for TUN device

    // Logging
    std::string log_level = "debug";
    std::string log_file;

    // Load from TOML file
    static std::expected<ClientConfig, ConfigError> load(const std::string& path);

    // Load from TOML string (for testing)
    static std::expected<ClientConfig, ConfigError> parse(const std::string& toml_content);
};

} // namespace edgelink

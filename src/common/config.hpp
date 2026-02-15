#pragma once

#include "client/client_config.hpp"

#include <string>
#include <optional>
#include <cstdint>
#include <chrono>
#include <expected>

namespace edgelink {

// ConfigError and ClientConfig are defined in client/client_config.hpp
// and brought into edgelink namespace via `using client::ClientConfig;`

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

    // 内置 Relay 配置
    struct BuiltinRelayConfig {
        bool enabled = true;            // 启用内置 Relay
        std::string name = "builtin";   // Relay 名称
        std::string region = "local";   // 区域标识
        uint16_t priority = 100;        // 优先级（值越小越优先）
    } builtin_relay;

    // 内置 STUN 配置
    struct BuiltinStunConfig {
        bool enabled = false;           // 启用内置 STUN
        std::string public_ip;          // 公网 IP（必填，用于 XOR-MAPPED-ADDRESS）
        uint16_t port = 3478;           // STUN 端口
    } builtin_stun;

    // Logging
    std::string log_level = "debug";
    std::string log_file;

    // Load from JSON file
    static std::expected<ControllerConfig, ConfigError> load(const std::string& path);

    // Load from JSON string (for testing)
    static std::expected<ControllerConfig, ConfigError> parse(const std::string& json_content);
};

} // namespace edgelink

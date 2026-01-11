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
    // 格式: host 或 host:port (port可省略，TLS时默认443，否则80)
    // 例如: "controller.example.com" 或 "192.168.1.100:8080"
    std::vector<std::string> controller_hosts = {"edge.a-z.xin"};  // 默认 controller
    std::string authkey;
    bool tls = true;  // Enable TLS (wss://) - default enabled
    std::chrono::milliseconds failover_timeout{5000};  // 切换到下一个Controller的超时时间

    // SSL/TLS settings
    bool ssl_verify = false;            // Verify server certificate (default: false for dev)
    std::string ssl_ca_file;            // Custom CA certificate file (empty = system default)
    bool ssl_allow_self_signed = false; // Allow self-signed certificates

    // Auto-reconnect settings
    bool auto_reconnect = true;
    std::chrono::seconds reconnect_interval{5};
    std::chrono::seconds ping_interval{5};
    std::chrono::seconds dns_refresh_interval{60};
    std::chrono::seconds latency_measure_interval{30};

    // P2P 配置
    struct P2PConfig {
        bool enabled = true;                    // 启用 P2P 直连
        uint16_t bind_port = 0;                 // UDP 绑定端口（0 = 随机）
        uint32_t keepalive_interval = 15;       // Keepalive 间隔（秒）
        uint32_t keepalive_timeout = 45;        // Keepalive 超时（秒）
        uint32_t punch_timeout = 10;            // 打洞超时（秒）
        uint32_t punch_batch_count = 5;         // 打洞批次数 (EasyTier: 5)
        uint32_t punch_batch_size = 2;          // 每批发送包数 (EasyTier: 2)
        uint32_t punch_batch_interval = 400;    // 批次间隔（毫秒, EasyTier: 400）
        uint32_t retry_interval = 60;           // 失败后重试间隔（秒）
        uint32_t stun_timeout = 5000;           // STUN 查询超时（毫秒）
        uint32_t endpoint_refresh_interval = 30; // 端点刷新间隔（秒，定期重新查询 STUN 并上报）
    } p2p;

    // 获取当前使用的controller host (格式: host:port)
    std::string current_controller_host() const {
        if (controller_hosts.empty()) return "localhost:8080";
        return controller_hosts[0];
    }

    // 解析 host:port 为规范化格式
    static std::pair<std::string, uint16_t> parse_host_port(const std::string& host_port, bool use_tls) {
        std::string host = host_port;
        uint16_t port = use_tls ? 443 : 80;

        // 查找最后一个冒号（支持IPv6，如 [::1]:8080）
        size_t colon_pos = std::string::npos;
        if (!host.empty() && host[0] == '[') {
            // IPv6 格式: [addr]:port
            auto bracket_pos = host.find(']');
            if (bracket_pos != std::string::npos && bracket_pos + 1 < host.size() && host[bracket_pos + 1] == ':') {
                colon_pos = bracket_pos + 1;
            }
        } else {
            colon_pos = host.rfind(':');
        }

        if (colon_pos != std::string::npos) {
            try {
                port = static_cast<uint16_t>(std::stoi(host.substr(colon_pos + 1)));
                host = host.substr(0, colon_pos);
            } catch (...) {
                // 解析失败，使用默认端口
            }
        }

        // 移除IPv6的方括号
        if (host.size() >= 2 && host[0] == '[' && host.back() == ']') {
            host = host.substr(1, host.size() - 2);
        }

        return {host, port};
    }

    // Key storage
    std::string state_dir;  // Directory for storing keys, empty = auto

    // TUN device settings
    bool enable_tun = false;       // Enable TUN device for IP-level routing
    std::string tun_name;          // TUN device name (empty = auto)
    uint32_t tun_mtu = 1420;       // MTU for TUN device

    // Subnet routing settings
    std::vector<std::string> advertise_routes;  // CIDR format routes to advertise
    bool exit_node = false;                     // Act as exit node (advertise 0.0.0.0/0)
    bool accept_routes = true;                  // Accept routes from other nodes and apply to system
    std::chrono::seconds route_announce_interval{30};  // 路由公告刷新间隔（0 = 仅启动时公告一次）

    // Logging
    std::string log_level = "debug";
    std::string log_file;
    std::unordered_map<std::string, std::string> module_log_levels;  // 模块级别日志配置

    // Load from TOML file
    static std::expected<ClientConfig, ConfigError> load(const std::string& path);

    // Load from TOML string (for testing)
    static std::expected<ClientConfig, ConfigError> parse(const std::string& toml_content);
};

} // namespace edgelink

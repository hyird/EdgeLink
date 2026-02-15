#pragma once

#include "common/types.hpp"

#include <chrono>
#include <cstdint>
#include <expected>
#include <string>
#include <unordered_map>
#include <vector>

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

namespace client {

// ============================================================================
// Unified Client Configuration
// ============================================================================

struct ClientConfig {
    // 线程模型设置
    size_t num_threads = 1;                    // 工作线程数（默认 1 = 单线程）
    bool separate_data_plane_thread = false;   // 是否分离数据面到独立线程（需要 num_threads >= 2）

    // 连接设置 - 格式: host 或 host:port (port可省略，TLS时默认443，否则80)
    std::string controller_url = "edge.a-z.xin";  // Controller URL
    std::string authkey;
    bool tls = true;  // Enable TLS (wss://) - default enabled
    bool auto_reconnect = true;
    std::chrono::seconds reconnect_interval{5};
    std::chrono::seconds ping_interval{5};  // Keep connection alive, avoid CDN idle timeout
    std::chrono::seconds dns_refresh_interval{60};  // DNS resolution refresh interval (0 = disabled)
    std::chrono::seconds latency_measure_interval{30};  // Peer latency measurement interval (0 = disabled)

    // 并发连接设置（Happy Eyeballs优化）
    std::chrono::seconds endpoint_connect_timeout{5};  // 单个endpoint的连接超时

    // SSL/TLS settings
    bool ssl_verify = false;            // Verify server certificate (default: false for dev)
    std::string ssl_ca_file;            // Custom CA certificate file (empty = system default)
    bool ssl_allow_self_signed = false; // Allow self-signed certificates

    // State directory for storing persistent keys
    std::string state_dir;  // Empty = platform default

    // TUN mode settings
    bool enable_tun = true;        // Enable TUN device for IP-level routing (default: enabled)
    std::string tun_name;          // TUN device name (empty = auto)
    uint32_t tun_mtu = 1420;       // MTU for TUN device

    // IPC server settings
    bool enable_ipc = true;        // Enable IPC control interface
    std::string ipc_socket_path;   // IPC socket path (empty = platform default)

    // Subnet routing settings (advertise local subnets to other peers)
    std::vector<std::string> advertise_routes;  // CIDR格式，如 "192.168.1.0/24", "10.0.0.0/8"
    bool exit_node = false;                     // 声明自己可作为出口节点（不会自动广播路由）
    std::string use_exit_node;                  // 使用指定节点作为出口（节点名称或ID）
    bool accept_routes = true;                  // 是否接受其他节点的路由并应用到系统
    std::chrono::seconds route_announce_interval{60};  // 路由公告刷新间隔

    // Logging settings (for hot-reload)
    std::string log_level = "debug";    // 日志级别
    std::string log_file;               // 日志文件路径
    std::unordered_map<std::string, std::string> module_log_levels;  // 模块级别日志配置

    // P2P 配置（使用统一的 edgelink::P2PConfig）
    edgelink::P2PConfig p2p;

    // 获取当前使用的controller url
    std::string current_controller_url() const {
        return controller_url.empty() ? "localhost:8080" : controller_url;
    }

    // 解析 host:port 为规范化格式
    static std::pair<std::string, uint16_t> parse_host_port(const std::string& host_port, bool use_tls) {
        std::string host = host_port;
        uint16_t port = use_tls ? 443 : 80;

        size_t colon_pos = std::string::npos;
        if (!host.empty() && host[0] == '[') {
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
            } catch (...) {}
        }

        if (host.size() >= 2 && host[0] == '[' && host.back() == ']') {
            host = host.substr(1, host.size() - 2);
        }

        return {host, port};
    }

    // Load from JSON file
    static std::expected<ClientConfig, ConfigError> load(const std::string& path);

    // Load from JSON string (for testing)
    static std::expected<ClientConfig, ConfigError> parse(const std::string& json_content);
};

} // namespace client

// Bring ClientConfig into edgelink namespace for backward compatibility
using client::ClientConfig;

} // namespace edgelink

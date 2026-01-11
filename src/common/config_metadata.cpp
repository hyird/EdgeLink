#include "common/config_metadata.hpp"
#include <algorithm>

namespace edgelink {

// 静态配置元数据表 - 所有配置均支持热重载
static const std::vector<ConfigMetadata> g_config_metadata = {
    // Controller 配置（热重载时重新连接）
    {"controller.url", ConfigType::String, "Controller 服务器地址", true, "localhost:8080"},
    {"controller.tls", ConfigType::Bool, "启用 TLS (wss://)", true, "false"},
    {"controller.authkey", ConfigType::String, "认证密钥", true, ""},

    // 连接配置（全部可热重载）
    {"connection.auto_reconnect", ConfigType::Bool, "断开后自动重连", true, "true"},
    {"connection.reconnect_interval", ConfigType::Int, "重连间隔（秒）", true, "5"},
    {"connection.ping_interval", ConfigType::Int, "Keepalive 间隔（秒）", true, "5"},
    {"connection.dns_refresh_interval", ConfigType::Int, "DNS 刷新间隔（秒）", true, "60"},
    {"connection.latency_measure_interval", ConfigType::Int, "延迟测量间隔（秒）", true, "30"},

    // SSL 配置（热重载时重新初始化 SSL 上下文）
    {"ssl.verify", ConfigType::Bool, "验证 SSL 证书", true, "false"},
    {"ssl.ca_file", ConfigType::String, "CA 证书文件路径", true, ""},
    {"ssl.allow_self_signed", ConfigType::Bool, "允许自签名证书", true, "false"},

    // 存储配置（state_dir 不可热重载，其他可以）
    {"storage.state_dir", ConfigType::String, "状态存储目录", false, ""},

    // TUN 配置（热重载时重新创建 TUN 设备）
    {"tun.enable", ConfigType::Bool, "启用 TUN 设备", true, "false"},
    {"tun.name", ConfigType::String, "TUN 设备名称", true, ""},
    {"tun.mtu", ConfigType::Int, "MTU", true, "1420"},

    // IPC 配置（热重载时重启 IPC 服务器）
    {"ipc.enable", ConfigType::Bool, "启用 IPC 接口", true, "true"},
    {"ipc.socket_path", ConfigType::String, "IPC 套接字路径", true, ""},

    // 路由配置（全部可热重载）
    {"routing.advertise_routes", ConfigType::StringArray, "要广播的子网路由", true, "[]"},
    {"routing.exit_node", ConfigType::Bool, "作为出口节点", true, "false"},
    {"routing.accept_routes", ConfigType::Bool, "接受其他节点的路由", true, "true"},

    // 日志配置（可热重载）
    {"log.level", ConfigType::String, "日志级别", true, "debug"},
    {"log.file", ConfigType::String, "日志文件路径", true, ""},
};

const std::vector<ConfigMetadata>& get_all_config_metadata() {
    return g_config_metadata;
}

std::optional<ConfigMetadata> get_config_metadata(const std::string& key) {
    auto it = std::find_if(g_config_metadata.begin(), g_config_metadata.end(),
                           [&key](const ConfigMetadata& m) { return m.key == key; });
    if (it != g_config_metadata.end()) {
        return *it;
    }
    return std::nullopt;
}

bool is_hot_reloadable(const std::string& key) {
    auto meta = get_config_metadata(key);
    return meta.has_value() && meta->hot_reloadable;
}

std::string config_type_to_string(ConfigType type) {
    switch (type) {
        case ConfigType::String:
            return "string";
        case ConfigType::Int:
            return "int";
        case ConfigType::Bool:
            return "bool";
        case ConfigType::StringArray:
            return "string_array";
        default:
            return "unknown";
    }
}

bool validate_config_value(const std::string& key, const std::string& value) {
    auto meta = get_config_metadata(key);
    if (!meta.has_value()) {
        return false;  // 未知配置项
    }

    switch (meta->type) {
        case ConfigType::String:
            return true;  // 字符串总是有效

        case ConfigType::Int:
            try {
                std::stoi(value);
                return true;
            } catch (...) {
                return false;
            }

        case ConfigType::Bool:
            return value == "true" || value == "false" || value == "1" || value == "0";

        case ConfigType::StringArray:
            // 简单验证：以 [ 开头，以 ] 结尾
            return value.size() >= 2 && value.front() == '[' && value.back() == ']';
    }

    return false;
}

}  // namespace edgelink

#pragma once

#include <string>
#include <vector>
#include <functional>

namespace edgelink::client {

class Client;
struct ClientConfig;

// 配置变更记录
struct ConfigChange {
    std::string key;           // 配置项路径
    std::string old_value;     // 旧值
    std::string new_value;     // 新值
    bool applied;              // 是否已应用
    bool restart_required;     // 是否需要重启
    std::string message;       // 附加信息
};

// 配置应用器 - 负责将配置变更应用到运行中的 Client
class ConfigApplier {
public:
    explicit ConfigApplier(Client& client);

    // 比较两个配置并应用差异
    std::vector<ConfigChange> apply(const ClientConfig& old_cfg, const ClientConfig& new_cfg);

    // 应用单个配置项
    ConfigChange apply_single(const std::string& key, const std::string& value);

    // 获取当前配置值（字符串形式）
    std::string get_value(const std::string& key) const;

    // 获取所有配置（JSON 格式）
    std::string get_all_config_json() const;

private:
    // 应用日志级别
    bool apply_log_level(const std::string& level);

    // 应用日志文件
    bool apply_log_file(const std::string& path);

    // 应用 ping 间隔
    bool apply_ping_interval(int seconds);

    // 应用 DNS 刷新间隔
    bool apply_dns_refresh_interval(int seconds);

    // 应用延迟测量间隔
    bool apply_latency_measure_interval(int seconds);

    // 应用重连间隔
    bool apply_reconnect_interval(int seconds);

    // 应用是否接受路由
    bool apply_accept_routes(bool accept);

    // 应用 Controller 配置（需要重新连接）
    bool apply_controller_url(const std::string& url);
    bool apply_controller_tls(bool enable);
    bool apply_controller_authkey(const std::string& authkey);

    // 应用 SSL 配置（需要重新初始化 SSL 上下文）
    bool apply_ssl_verify(bool verify);
    bool apply_ssl_ca_file(const std::string& path);
    bool apply_ssl_allow_self_signed(bool allow);

    // 应用 TUN 配置（需要重新创建 TUN 设备）
    bool apply_tun_enable(bool enable);
    bool apply_tun_name(const std::string& name);
    bool apply_tun_mtu(int mtu);

    // 应用 IPC 配置（需要重启 IPC 服务器）
    bool apply_ipc_enable(bool enable);
    bool apply_ipc_socket_path(const std::string& path);

    // 应用路由广播配置（需要重新向 Controller 公告）
    bool apply_advertise_routes(const std::vector<std::string>& routes);
    bool apply_exit_node(bool enable);
    bool apply_route_announce_interval(int seconds);

    // 应用自动重连配置
    bool apply_auto_reconnect(bool enable);

    // 应用 P2P 配置
    bool apply_p2p_enabled(bool enabled);
    bool apply_p2p_bind_port(int port);
    bool apply_p2p_keepalive_interval(int seconds);
    bool apply_p2p_keepalive_timeout(int seconds);
    bool apply_p2p_punch_timeout(int seconds);
    bool apply_p2p_punch_batch_count(int count);
    bool apply_p2p_punch_batch_size(int size);
    bool apply_p2p_punch_batch_interval(int ms);
    bool apply_p2p_retry_interval(int seconds);
    bool apply_p2p_stun_timeout(int ms);
    bool apply_p2p_endpoint_refresh_interval(int seconds);

    // 触发重新连接
    void trigger_reconnect();

    // 触发重建 TUN 设备
    void trigger_tun_rebuild();

    // 触发重启 IPC 服务器
    void trigger_ipc_restart();

    // 触发重新公告路由
    void trigger_route_reannounce();

    Client& client_;

    // 标记是否需要执行某些操作
    bool need_reconnect_ = false;
    bool need_tun_rebuild_ = false;
    bool need_ipc_restart_ = false;
    bool need_route_reannounce_ = false;
};

}  // namespace edgelink::client

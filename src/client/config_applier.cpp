#include "client/config_applier.hpp"
#include "client/client.hpp"
#include "common/config_metadata.hpp"
#include "common/logger.hpp"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace edgelink::client {

ConfigApplier::ConfigApplier(Client& client) : client_(client) {}

std::vector<ConfigChange> ConfigApplier::apply(const ClientConfig& old_cfg, const ClientConfig& new_cfg) {
    std::vector<ConfigChange> changes;

    // 重置操作标记
    need_reconnect_ = false;
    need_tun_rebuild_ = false;
    need_ipc_restart_ = false;
    need_route_reannounce_ = false;

    // ===== 日志配置 =====
    if (old_cfg.log_level != new_cfg.log_level) {
        ConfigChange change;
        change.key = "log.level";
        change.old_value = old_cfg.log_level;
        change.new_value = new_cfg.log_level;
        change.applied = apply_log_level(new_cfg.log_level);
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.log_file != new_cfg.log_file) {
        ConfigChange change;
        change.key = "log.file";
        change.old_value = old_cfg.log_file;
        change.new_value = new_cfg.log_file;
        change.applied = apply_log_file(new_cfg.log_file);
        change.restart_required = false;
        changes.push_back(change);
    }

    // ===== 连接配置 =====
    if (old_cfg.ping_interval != new_cfg.ping_interval) {
        ConfigChange change;
        change.key = "connection.ping_interval";
        change.old_value = std::to_string(old_cfg.ping_interval.count());
        change.new_value = std::to_string(new_cfg.ping_interval.count());
        change.applied = apply_ping_interval(static_cast<int>(new_cfg.ping_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.dns_refresh_interval != new_cfg.dns_refresh_interval) {
        ConfigChange change;
        change.key = "connection.dns_refresh_interval";
        change.old_value = std::to_string(old_cfg.dns_refresh_interval.count());
        change.new_value = std::to_string(new_cfg.dns_refresh_interval.count());
        change.applied = apply_dns_refresh_interval(static_cast<int>(new_cfg.dns_refresh_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.latency_measure_interval != new_cfg.latency_measure_interval) {
        ConfigChange change;
        change.key = "connection.latency_measure_interval";
        change.old_value = std::to_string(old_cfg.latency_measure_interval.count());
        change.new_value = std::to_string(new_cfg.latency_measure_interval.count());
        change.applied = apply_latency_measure_interval(static_cast<int>(new_cfg.latency_measure_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.reconnect_interval != new_cfg.reconnect_interval) {
        ConfigChange change;
        change.key = "connection.reconnect_interval";
        change.old_value = std::to_string(old_cfg.reconnect_interval.count());
        change.new_value = std::to_string(new_cfg.reconnect_interval.count());
        change.applied = apply_reconnect_interval(static_cast<int>(new_cfg.reconnect_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.auto_reconnect != new_cfg.auto_reconnect) {
        ConfigChange change;
        change.key = "connection.auto_reconnect";
        change.old_value = old_cfg.auto_reconnect ? "true" : "false";
        change.new_value = new_cfg.auto_reconnect ? "true" : "false";
        change.applied = apply_auto_reconnect(new_cfg.auto_reconnect);
        change.restart_required = false;
        changes.push_back(change);
    }

    // ===== Controller 配置（热重载时重新连接）=====
    if (old_cfg.controller_hosts != new_cfg.controller_hosts) {
        ConfigChange change;
        change.key = "controller.url";
        change.old_value = old_cfg.current_controller_host();
        change.new_value = new_cfg.current_controller_host();
        change.applied = apply_controller_url(new_cfg.current_controller_host());
        change.restart_required = false;
        change.message = "将重新连接到新的 Controller";
        changes.push_back(change);
    }

    if (old_cfg.tls != new_cfg.tls) {
        ConfigChange change;
        change.key = "controller.tls";
        change.old_value = old_cfg.tls ? "true" : "false";
        change.new_value = new_cfg.tls ? "true" : "false";
        change.applied = apply_controller_tls(new_cfg.tls);
        change.restart_required = false;
        change.message = "将重新连接以应用 TLS 设置";
        changes.push_back(change);
    }

    if (old_cfg.authkey != new_cfg.authkey) {
        ConfigChange change;
        change.key = "controller.authkey";
        change.old_value = "***";  // 不显示实际密钥
        change.new_value = "***";
        change.applied = apply_controller_authkey(new_cfg.authkey);
        change.restart_required = false;
        change.message = "将重新连接以应用新的认证密钥";
        changes.push_back(change);
    }

    // ===== SSL 配置（热重载时重新初始化 SSL 上下文并重连）=====
    if (old_cfg.ssl_verify != new_cfg.ssl_verify) {
        ConfigChange change;
        change.key = "ssl.verify";
        change.old_value = old_cfg.ssl_verify ? "true" : "false";
        change.new_value = new_cfg.ssl_verify ? "true" : "false";
        change.applied = apply_ssl_verify(new_cfg.ssl_verify);
        change.restart_required = false;
        change.message = "将重新连接以应用 SSL 验证设置";
        changes.push_back(change);
    }

    if (old_cfg.ssl_ca_file != new_cfg.ssl_ca_file) {
        ConfigChange change;
        change.key = "ssl.ca_file";
        change.old_value = old_cfg.ssl_ca_file;
        change.new_value = new_cfg.ssl_ca_file;
        change.applied = apply_ssl_ca_file(new_cfg.ssl_ca_file);
        change.restart_required = false;
        change.message = "将重新连接以应用新的 CA 证书";
        changes.push_back(change);
    }

    if (old_cfg.ssl_allow_self_signed != new_cfg.ssl_allow_self_signed) {
        ConfigChange change;
        change.key = "ssl.allow_self_signed";
        change.old_value = old_cfg.ssl_allow_self_signed ? "true" : "false";
        change.new_value = new_cfg.ssl_allow_self_signed ? "true" : "false";
        change.applied = apply_ssl_allow_self_signed(new_cfg.ssl_allow_self_signed);
        change.restart_required = false;
        change.message = "将重新连接以应用自签名证书设置";
        changes.push_back(change);
    }

    // ===== TUN 配置（热重载时重新创建 TUN 设备）=====
    if (old_cfg.enable_tun != new_cfg.enable_tun) {
        ConfigChange change;
        change.key = "tun.enable";
        change.old_value = old_cfg.enable_tun ? "true" : "false";
        change.new_value = new_cfg.enable_tun ? "true" : "false";
        change.applied = apply_tun_enable(new_cfg.enable_tun);
        change.restart_required = false;
        change.message = new_cfg.enable_tun ? "将创建 TUN 设备" : "将关闭 TUN 设备";
        changes.push_back(change);
    }

    if (old_cfg.tun_name != new_cfg.tun_name) {
        ConfigChange change;
        change.key = "tun.name";
        change.old_value = old_cfg.tun_name;
        change.new_value = new_cfg.tun_name;
        change.applied = apply_tun_name(new_cfg.tun_name);
        change.restart_required = false;
        change.message = "将重新创建 TUN 设备";
        changes.push_back(change);
    }

    if (old_cfg.tun_mtu != new_cfg.tun_mtu) {
        ConfigChange change;
        change.key = "tun.mtu";
        change.old_value = std::to_string(old_cfg.tun_mtu);
        change.new_value = std::to_string(new_cfg.tun_mtu);
        change.applied = apply_tun_mtu(static_cast<int>(new_cfg.tun_mtu));
        change.restart_required = false;
        change.message = "将重新创建 TUN 设备以应用新 MTU";
        changes.push_back(change);
    }

    // ===== IPC 配置（热重载时重启 IPC 服务器）=====
    if (old_cfg.enable_ipc != new_cfg.enable_ipc) {
        ConfigChange change;
        change.key = "ipc.enable";
        change.old_value = old_cfg.enable_ipc ? "true" : "false";
        change.new_value = new_cfg.enable_ipc ? "true" : "false";
        change.applied = apply_ipc_enable(new_cfg.enable_ipc);
        change.restart_required = false;
        change.message = new_cfg.enable_ipc ? "将启动 IPC 服务器" : "将关闭 IPC 服务器";
        changes.push_back(change);
    }

    if (old_cfg.ipc_socket_path != new_cfg.ipc_socket_path) {
        ConfigChange change;
        change.key = "ipc.socket_path";
        change.old_value = old_cfg.ipc_socket_path;
        change.new_value = new_cfg.ipc_socket_path;
        change.applied = apply_ipc_socket_path(new_cfg.ipc_socket_path);
        change.restart_required = false;
        change.message = "将重启 IPC 服务器以使用新套接字路径";
        changes.push_back(change);
    }

    // ===== 路由配置 =====
    if (old_cfg.accept_routes != new_cfg.accept_routes) {
        ConfigChange change;
        change.key = "routing.accept_routes";
        change.old_value = old_cfg.accept_routes ? "true" : "false";
        change.new_value = new_cfg.accept_routes ? "true" : "false";
        change.applied = apply_accept_routes(new_cfg.accept_routes);
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.advertise_routes != new_cfg.advertise_routes) {
        ConfigChange change;
        change.key = "routing.advertise_routes";
        // 序列化路由列表
        nlohmann::json old_routes = old_cfg.advertise_routes;
        nlohmann::json new_routes = new_cfg.advertise_routes;
        change.old_value = old_routes.dump();
        change.new_value = new_routes.dump();
        change.applied = apply_advertise_routes(new_cfg.advertise_routes);
        change.restart_required = false;
        change.message = "将重新公告路由";
        changes.push_back(change);
    }

    if (old_cfg.exit_node != new_cfg.exit_node) {
        ConfigChange change;
        change.key = "routing.exit_node";
        change.old_value = old_cfg.exit_node ? "true" : "false";
        change.new_value = new_cfg.exit_node ? "true" : "false";
        change.applied = apply_exit_node(new_cfg.exit_node);
        change.restart_required = false;
        change.message = new_cfg.exit_node ? "将公告为出口节点" : "将撤销出口节点公告";
        changes.push_back(change);
    }

    if (old_cfg.route_announce_interval != new_cfg.route_announce_interval) {
        ConfigChange change;
        change.key = "routing.announce_interval";
        change.old_value = std::to_string(old_cfg.route_announce_interval.count());
        change.new_value = std::to_string(new_cfg.route_announce_interval.count());
        change.applied = apply_route_announce_interval(static_cast<int>(new_cfg.route_announce_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    // ===== P2P 配置 =====
    if (old_cfg.p2p.enabled != new_cfg.p2p.enabled) {
        ConfigChange change;
        change.key = "p2p.enabled";
        change.old_value = old_cfg.p2p.enabled ? "true" : "false";
        change.new_value = new_cfg.p2p.enabled ? "true" : "false";
        change.applied = apply_p2p_enabled(new_cfg.p2p.enabled);
        change.restart_required = false;
        change.message = new_cfg.p2p.enabled ? "启用 P2P 直连" : "禁用 P2P 直连";
        changes.push_back(change);
    }

    if (old_cfg.p2p.bind_port != new_cfg.p2p.bind_port) {
        ConfigChange change;
        change.key = "p2p.bind_port";
        change.old_value = std::to_string(old_cfg.p2p.bind_port);
        change.new_value = std::to_string(new_cfg.p2p.bind_port);
        change.applied = apply_p2p_bind_port(new_cfg.p2p.bind_port);
        change.restart_required = true;  // 端口变更需要重启
        change.message = "P2P 绑定端口变更需要重启才能生效";
        changes.push_back(change);
    }

    if (old_cfg.p2p.keepalive_interval != new_cfg.p2p.keepalive_interval) {
        ConfigChange change;
        change.key = "p2p.keepalive_interval";
        change.old_value = std::to_string(old_cfg.p2p.keepalive_interval.count());
        change.new_value = std::to_string(new_cfg.p2p.keepalive_interval.count());
        change.applied = apply_p2p_keepalive_interval(static_cast<int>(new_cfg.p2p.keepalive_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.keepalive_timeout != new_cfg.p2p.keepalive_timeout) {
        ConfigChange change;
        change.key = "p2p.keepalive_timeout";
        change.old_value = std::to_string(old_cfg.p2p.keepalive_timeout.count());
        change.new_value = std::to_string(new_cfg.p2p.keepalive_timeout.count());
        change.applied = apply_p2p_keepalive_timeout(static_cast<int>(new_cfg.p2p.keepalive_timeout.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.punch_timeout != new_cfg.p2p.punch_timeout) {
        ConfigChange change;
        change.key = "p2p.punch_timeout";
        change.old_value = std::to_string(old_cfg.p2p.punch_timeout.count());
        change.new_value = std::to_string(new_cfg.p2p.punch_timeout.count());
        change.applied = apply_p2p_punch_timeout(static_cast<int>(new_cfg.p2p.punch_timeout.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.punch_batch_count != new_cfg.p2p.punch_batch_count) {
        ConfigChange change;
        change.key = "p2p.punch_batch_count";
        change.old_value = std::to_string(old_cfg.p2p.punch_batch_count);
        change.new_value = std::to_string(new_cfg.p2p.punch_batch_count);
        change.applied = apply_p2p_punch_batch_count(new_cfg.p2p.punch_batch_count);
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.punch_batch_size != new_cfg.p2p.punch_batch_size) {
        ConfigChange change;
        change.key = "p2p.punch_batch_size";
        change.old_value = std::to_string(old_cfg.p2p.punch_batch_size);
        change.new_value = std::to_string(new_cfg.p2p.punch_batch_size);
        change.applied = apply_p2p_punch_batch_size(new_cfg.p2p.punch_batch_size);
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.punch_batch_interval != new_cfg.p2p.punch_batch_interval) {
        ConfigChange change;
        change.key = "p2p.punch_batch_interval";
        change.old_value = std::to_string(old_cfg.p2p.punch_batch_interval.count());
        change.new_value = std::to_string(new_cfg.p2p.punch_batch_interval.count());
        change.applied = apply_p2p_punch_batch_interval(static_cast<int>(new_cfg.p2p.punch_batch_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.retry_interval != new_cfg.p2p.retry_interval) {
        ConfigChange change;
        change.key = "p2p.retry_interval";
        change.old_value = std::to_string(old_cfg.p2p.retry_interval.count());
        change.new_value = std::to_string(new_cfg.p2p.retry_interval.count());
        change.applied = apply_p2p_retry_interval(static_cast<int>(new_cfg.p2p.retry_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.stun_timeout != new_cfg.p2p.stun_timeout) {
        ConfigChange change;
        change.key = "p2p.stun_timeout";
        change.old_value = std::to_string(old_cfg.p2p.stun_timeout.count());
        change.new_value = std::to_string(new_cfg.p2p.stun_timeout.count());
        change.applied = apply_p2p_stun_timeout(static_cast<int>(new_cfg.p2p.stun_timeout.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    if (old_cfg.p2p.endpoint_refresh_interval != new_cfg.p2p.endpoint_refresh_interval) {
        ConfigChange change;
        change.key = "p2p.endpoint_refresh_interval";
        change.old_value = std::to_string(old_cfg.p2p.endpoint_refresh_interval.count());
        change.new_value = std::to_string(new_cfg.p2p.endpoint_refresh_interval.count());
        change.applied = apply_p2p_endpoint_refresh_interval(static_cast<int>(new_cfg.p2p.endpoint_refresh_interval.count()));
        change.restart_required = false;
        changes.push_back(change);
    }

    // ===== 执行需要的操作 =====
    if (need_reconnect_) {
        trigger_reconnect();
    }
    if (need_tun_rebuild_) {
        trigger_tun_rebuild();
    }
    if (need_ipc_restart_) {
        trigger_ipc_restart();
    }
    if (need_route_reannounce_) {
        trigger_route_reannounce();
    }

    return changes;
}

ConfigChange ConfigApplier::apply_single(const std::string& key, const std::string& value) {
    ConfigChange change;
    change.key = key;
    change.new_value = value;
    change.old_value = get_value(key);
    change.restart_required = false;

    // 重置操作标记
    need_reconnect_ = false;
    need_tun_rebuild_ = false;
    need_ipc_restart_ = false;
    need_route_reannounce_ = false;

    // 检查是否可热重载（只有 storage.state_dir 不可热重载）
    if (!edgelink::is_hot_reloadable(key)) {
        change.applied = false;
        change.restart_required = true;
        change.message = "此配置不支持热重载";
        return change;
    }

    // 应用配置
    if (key == "log.level") {
        change.applied = apply_log_level(value);
    } else if (key == "log.file") {
        change.applied = apply_log_file(value);
    } else if (key == "connection.ping_interval") {
        change.applied = apply_ping_interval(std::stoi(value));
    } else if (key == "connection.dns_refresh_interval") {
        change.applied = apply_dns_refresh_interval(std::stoi(value));
    } else if (key == "connection.latency_measure_interval") {
        change.applied = apply_latency_measure_interval(std::stoi(value));
    } else if (key == "connection.reconnect_interval") {
        change.applied = apply_reconnect_interval(std::stoi(value));
    } else if (key == "connection.auto_reconnect") {
        change.applied = apply_auto_reconnect(value == "true" || value == "1");
    } else if (key == "routing.accept_routes") {
        change.applied = apply_accept_routes(value == "true" || value == "1");
    } else if (key == "controller.url") {
        change.applied = apply_controller_url(value);
        change.message = "将重新连接到新的 Controller";
    } else if (key == "controller.tls") {
        change.applied = apply_controller_tls(value == "true" || value == "1");
        change.message = "将重新连接以应用 TLS 设置";
    } else if (key == "controller.authkey") {
        change.applied = apply_controller_authkey(value);
        change.message = "将重新连接以应用新的认证密钥";
    } else if (key == "ssl.verify") {
        change.applied = apply_ssl_verify(value == "true" || value == "1");
        change.message = "将重新连接以应用 SSL 验证设置";
    } else if (key == "ssl.ca_file") {
        change.applied = apply_ssl_ca_file(value);
        change.message = "将重新连接以应用新的 CA 证书";
    } else if (key == "ssl.allow_self_signed") {
        change.applied = apply_ssl_allow_self_signed(value == "true" || value == "1");
        change.message = "将重新连接以应用自签名证书设置";
    } else if (key == "tun.enable") {
        change.applied = apply_tun_enable(value == "true" || value == "1");
    } else if (key == "tun.name") {
        change.applied = apply_tun_name(value);
    } else if (key == "tun.mtu") {
        change.applied = apply_tun_mtu(std::stoi(value));
    } else if (key == "ipc.enable") {
        change.applied = apply_ipc_enable(value == "true" || value == "1");
    } else if (key == "ipc.socket_path") {
        change.applied = apply_ipc_socket_path(value);
    } else if (key == "routing.exit_node") {
        change.applied = apply_exit_node(value == "true" || value == "1");
        change.message = "将重新公告路由";
    } else if (key == "routing.advertise_routes") {
        // 解析 JSON 数组
        try {
            auto routes = nlohmann::json::parse(value).get<std::vector<std::string>>();
            change.applied = apply_advertise_routes(routes);
            change.message = "将重新公告路由";
        } catch (...) {
            change.applied = false;
            change.message = "无效的路由数组格式";
        }
    } else if (key == "routing.announce_interval") {
        change.applied = apply_route_announce_interval(std::stoi(value));
    // P2P 配置
    } else if (key == "p2p.enabled") {
        change.applied = apply_p2p_enabled(value == "true" || value == "1");
    } else if (key == "p2p.bind_port") {
        change.applied = apply_p2p_bind_port(std::stoi(value));
        change.restart_required = true;
        change.message = "P2P 绑定端口变更需要重启才能生效";
    } else if (key == "p2p.keepalive_interval") {
        change.applied = apply_p2p_keepalive_interval(std::stoi(value));
    } else if (key == "p2p.keepalive_timeout") {
        change.applied = apply_p2p_keepalive_timeout(std::stoi(value));
    } else if (key == "p2p.punch_timeout") {
        change.applied = apply_p2p_punch_timeout(std::stoi(value));
    } else if (key == "p2p.punch_batch_count") {
        change.applied = apply_p2p_punch_batch_count(std::stoi(value));
    } else if (key == "p2p.punch_batch_size") {
        change.applied = apply_p2p_punch_batch_size(std::stoi(value));
    } else if (key == "p2p.punch_batch_interval") {
        change.applied = apply_p2p_punch_batch_interval(std::stoi(value));
    } else if (key == "p2p.retry_interval") {
        change.applied = apply_p2p_retry_interval(std::stoi(value));
    } else if (key == "p2p.stun_timeout") {
        change.applied = apply_p2p_stun_timeout(std::stoi(value));
    } else if (key == "p2p.endpoint_refresh_interval") {
        change.applied = apply_p2p_endpoint_refresh_interval(std::stoi(value));
    } else {
        change.applied = false;
        change.message = "未知配置项";
    }

    // 执行需要的操作
    if (need_reconnect_) {
        trigger_reconnect();
    }
    if (need_tun_rebuild_) {
        trigger_tun_rebuild();
    }
    if (need_ipc_restart_) {
        trigger_ipc_restart();
    }
    if (need_route_reannounce_) {
        trigger_route_reannounce();
    }

    return change;
}

std::string ConfigApplier::get_value(const std::string& key) const {
    return client_.get_config_value(key);
}

std::string ConfigApplier::get_all_config_json() const {
    const auto& cfg = client_.config();
    nlohmann::json config;

    // Controller 配置
    config["controller"]["url"] = cfg.current_controller_host();
    config["controller"]["tls"] = cfg.tls;
    config["controller"]["authkey"] = "***";  // 不暴露实际密钥

    // 连接配置
    config["connection"]["auto_reconnect"] = cfg.auto_reconnect;
    config["connection"]["reconnect_interval"] = cfg.reconnect_interval.count();
    config["connection"]["ping_interval"] = cfg.ping_interval.count();
    config["connection"]["dns_refresh_interval"] = cfg.dns_refresh_interval.count();
    config["connection"]["latency_measure_interval"] = cfg.latency_measure_interval.count();

    // SSL 配置
    config["ssl"]["verify"] = cfg.ssl_verify;
    config["ssl"]["ca_file"] = cfg.ssl_ca_file;
    config["ssl"]["allow_self_signed"] = cfg.ssl_allow_self_signed;

    // 存储配置
    config["storage"]["state_dir"] = cfg.state_dir;

    // TUN 配置
    config["tun"]["enable"] = cfg.enable_tun;
    config["tun"]["name"] = cfg.tun_name;
    config["tun"]["mtu"] = cfg.tun_mtu;

    // IPC 配置
    config["ipc"]["enable"] = cfg.enable_ipc;
    config["ipc"]["socket_path"] = cfg.ipc_socket_path;

    // 路由配置
    config["routing"]["accept_routes"] = cfg.accept_routes;
    config["routing"]["advertise_routes"] = cfg.advertise_routes;
    config["routing"]["exit_node"] = cfg.exit_node;

    // 日志配置
    config["log"]["level"] = cfg.log_level;
    config["log"]["file"] = cfg.log_file;

    return config.dump();
}

// ===== 日志配置 =====

bool ConfigApplier::apply_log_level(const std::string& level) {
    try {
        spdlog::level::level_enum log_level;
        if (level == "trace") {
            log_level = spdlog::level::trace;
        } else if (level == "debug") {
            log_level = spdlog::level::debug;
        } else if (level == "info") {
            log_level = spdlog::level::info;
        } else if (level == "warn" || level == "warning") {
            log_level = spdlog::level::warn;
        } else if (level == "error") {
            log_level = spdlog::level::err;
        } else if (level == "critical") {
            log_level = spdlog::level::critical;
        } else if (level == "off") {
            log_level = spdlog::level::off;
        } else {
            LOG_WARN("client.config", "未知日志级别: {}", level);
            return false;
        }

        spdlog::set_level(log_level);
        LOG_INFO("client.config", "日志级别已更改为: {}", level);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("client.config", "应用日志级别失败: {}", e.what());
        return false;
    }
}

bool ConfigApplier::apply_log_file(const std::string& path) {
    // 日志文件更改需要更复杂的处理（重建 logger）
    // 目前仅记录日志
    LOG_INFO("client.config", "日志文件路径已更改为: {} (下次启动生效)", path);
    return true;
}

// ===== 连接配置 =====

bool ConfigApplier::apply_ping_interval(int seconds) {
    LOG_INFO("client.config", "Ping 间隔已更改为: {}秒 (下次 ping 循环生效)", seconds);
    return true;
}

bool ConfigApplier::apply_dns_refresh_interval(int seconds) {
    LOG_INFO("client.config", "DNS 刷新间隔已更改为: {}秒 (下次刷新循环生效)", seconds);
    return true;
}

bool ConfigApplier::apply_latency_measure_interval(int seconds) {
    LOG_INFO("client.config", "延迟测量间隔已更改为: {}秒 (下次测量循环生效)", seconds);
    return true;
}

bool ConfigApplier::apply_reconnect_interval(int seconds) {
    LOG_INFO("client.config", "重连间隔已更改为: {}秒", seconds);
    return true;
}

bool ConfigApplier::apply_auto_reconnect(bool enable) {
    LOG_INFO("client.config", "自动重连设置已更改为: {}", enable ? "启用" : "禁用");
    return true;
}

// ===== Controller 配置 =====

bool ConfigApplier::apply_controller_url(const std::string& url) {
    LOG_INFO("client.config", "Controller 地址已更改为: {}", url);
    need_reconnect_ = true;
    return true;
}

bool ConfigApplier::apply_controller_tls(bool enable) {
    LOG_INFO("client.config", "Controller TLS 设置已更改为: {}", enable ? "启用" : "禁用");
    need_reconnect_ = true;
    return true;
}

bool ConfigApplier::apply_controller_authkey(const std::string& authkey) {
    LOG_INFO("client.config", "Controller 认证密钥已更改");
    need_reconnect_ = true;
    return true;
}

// ===== SSL 配置 =====

bool ConfigApplier::apply_ssl_verify(bool verify) {
    LOG_INFO("client.config", "SSL 证书验证设置已更改为: {}", verify ? "启用" : "禁用");
    need_reconnect_ = true;
    return true;
}

bool ConfigApplier::apply_ssl_ca_file(const std::string& path) {
    LOG_INFO("client.config", "SSL CA 证书文件已更改为: {}", path.empty() ? "(系统默认)" : path);
    need_reconnect_ = true;
    return true;
}

bool ConfigApplier::apply_ssl_allow_self_signed(bool allow) {
    LOG_INFO("client.config", "允许自签名证书设置已更改为: {}", allow ? "是" : "否");
    need_reconnect_ = true;
    return true;
}

// ===== TUN 配置 =====

bool ConfigApplier::apply_tun_enable(bool enable) {
    LOG_INFO("client.config", "TUN 设备设置已更改为: {}", enable ? "启用" : "禁用");
    need_tun_rebuild_ = true;
    return true;
}

bool ConfigApplier::apply_tun_name(const std::string& name) {
    LOG_INFO("client.config", "TUN 设备名称已更改为: {}", name.empty() ? "(自动)" : name);
    need_tun_rebuild_ = true;
    return true;
}

bool ConfigApplier::apply_tun_mtu(int mtu) {
    LOG_INFO("client.config", "TUN MTU 已更改为: {}", mtu);
    need_tun_rebuild_ = true;
    return true;
}

// ===== IPC 配置 =====

bool ConfigApplier::apply_ipc_enable(bool enable) {
    LOG_INFO("client.config", "IPC 服务器设置已更改为: {}", enable ? "启用" : "禁用");
    need_ipc_restart_ = true;
    return true;
}

bool ConfigApplier::apply_ipc_socket_path(const std::string& path) {
    LOG_INFO("client.config", "IPC 套接字路径已更改为: {}", path.empty() ? "(默认)" : path);
    need_ipc_restart_ = true;
    return true;
}

// ===== 路由配置 =====

bool ConfigApplier::apply_accept_routes(bool accept) {
    LOG_INFO("client.config", "接受路由设置已更改为: {}", accept ? "是" : "否");
    // 如果禁用，清除已应用的路由
    if (!accept) {
        client_.clear_system_routes();
    }
    return true;
}

bool ConfigApplier::apply_advertise_routes(const std::vector<std::string>& routes) {
    LOG_INFO("client.config", "路由广播列表已更改，共 {} 条路由", routes.size());
    need_route_reannounce_ = true;
    return true;
}

bool ConfigApplier::apply_exit_node(bool enable) {
    LOG_INFO("client.config", "出口节点设置已更改为: {}", enable ? "是" : "否");
    need_route_reannounce_ = true;
    return true;
}

// ===== 触发操作 =====

void ConfigApplier::trigger_reconnect() {
    LOG_INFO("client.config", "触发重新连接到 Controller...");
    client_.request_reconnect();
}

void ConfigApplier::trigger_tun_rebuild() {
    LOG_INFO("client.config", "触发 TUN 设备重建...");
    client_.request_tun_rebuild();
}

void ConfigApplier::trigger_ipc_restart() {
    LOG_INFO("client.config", "触发 IPC 服务器重启...");
    client_.request_ipc_restart();
}

void ConfigApplier::trigger_route_reannounce() {
    LOG_INFO("client.config", "触发路由重新公告...");
    client_.request_route_reannounce();
}

bool ConfigApplier::apply_route_announce_interval(int seconds) {
    LOG_INFO("client.config", "路由公告间隔已更改为: {}秒 (下次公告循环生效)", seconds);
    return true;
}

// ===== P2P 配置 =====

bool ConfigApplier::apply_p2p_enabled(bool enabled) {
    LOG_INFO("client.config", "P2P 直连设置已更改为: {}", enabled ? "启用" : "禁用");
    // P2P 启用/禁用需要重新启动 P2P manager，目前仅记录日志
    // 完整实现需要调用 p2p_mgr_->stop() 或 p2p_mgr_->start()
    return true;
}

bool ConfigApplier::apply_p2p_bind_port(int port) {
    LOG_INFO("client.config", "P2P 绑定端口已更改为: {} (需要重启才能生效)", port);
    // 端口变更需要重启，因为 socket 已绑定
    return true;
}

bool ConfigApplier::apply_p2p_keepalive_interval(int seconds) {
    LOG_INFO("client.config", "P2P Keepalive 间隔已更改为: {}秒", seconds);
    return true;
}

bool ConfigApplier::apply_p2p_keepalive_timeout(int seconds) {
    LOG_INFO("client.config", "P2P Keepalive 超时已更改为: {}秒", seconds);
    return true;
}

bool ConfigApplier::apply_p2p_punch_timeout(int seconds) {
    LOG_INFO("client.config", "P2P 打洞超时已更改为: {}秒", seconds);
    return true;
}

bool ConfigApplier::apply_p2p_punch_batch_count(int count) {
    LOG_INFO("client.config", "P2P 打洞批次数已更改为: {}", count);
    return true;
}

bool ConfigApplier::apply_p2p_punch_batch_size(int size) {
    LOG_INFO("client.config", "P2P 每批打洞包数已更改为: {}", size);
    return true;
}

bool ConfigApplier::apply_p2p_punch_batch_interval(int ms) {
    LOG_INFO("client.config", "P2P 打洞批次间隔已更改为: {}ms", ms);
    return true;
}

bool ConfigApplier::apply_p2p_retry_interval(int seconds) {
    LOG_INFO("client.config", "P2P 重试间隔已更改为: {}秒", seconds);
    return true;
}

bool ConfigApplier::apply_p2p_stun_timeout(int ms) {
    LOG_INFO("client.config", "STUN 查询超时已更改为: {}ms", ms);
    return true;
}

bool ConfigApplier::apply_p2p_endpoint_refresh_interval(int seconds) {
    LOG_INFO("client.config", "端点刷新间隔已更改为: {}秒", seconds);
    return true;
}

}  // namespace edgelink::client

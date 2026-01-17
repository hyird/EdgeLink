#include "client/ipc_server.hpp"
#include "client/client.hpp"
#include "client/prefs_store.hpp"
#include "common/logger.hpp"
#include "common/config.hpp"
#include "common/config_metadata.hpp"
#include "common/config_writer.hpp"

#include <boost/json.hpp>
#include <filesystem>
#include <future>
#include <sstream>

namespace json = boost::json;

namespace edgelink::client {

namespace {
    auto& log() { return Logger::get("client.ipc"); }
}

// ============================================================================
// IpcServer
// ============================================================================

IpcServer::IpcServer(asio::io_context& ioc, Client& client)
    : ioc_(ioc), client_(client) {}

IpcServer::~IpcServer() {
    stop();
}

std::string IpcServer::get_default_socket_path() {
#ifdef _WIN32
    // Windows: Unix domain sockets require a file path (not named pipe format)
    // Use temp directory for the socket file
    const char* temp = std::getenv("TEMP");
    if (!temp) temp = std::getenv("TMP");
    if (temp) {
        return std::string(temp) + "\\edgelink-client.sock";
    }
    return "C:\\Windows\\Temp\\edgelink-client.sock";
#elif defined(__APPLE__)
    // macOS: use /tmp for consistency between daemon and CLI
    return "/tmp/edgelink-client.sock";
#else
    // Linux: always use /tmp for consistency between daemon (root) and CLI (user)
    // XDG_RUNTIME_DIR varies per user, causing mismatch when daemon runs as root
    return "/tmp/edgelink-client.sock";
#endif
}

bool IpcServer::start(const IpcServerConfig& config) {
    if (running_) {
        return true;
    }

    config_ = config;
    if (config_.socket_path.empty()) {
        config_.socket_path = get_default_socket_path();
    }

#ifdef _WIN32
    // Windows named pipes handled differently
    // For now, use local stream protocol which Boost.Asio maps appropriately
    try {
        // Remove existing socket file if present
        std::error_code ec;
        std::filesystem::remove(config_.socket_path, ec);

        acceptor_ = std::make_unique<asio::local::stream_protocol::acceptor>(ioc_);
        acceptor_->open();
        acceptor_->bind(asio::local::stream_protocol::endpoint(config_.socket_path));
        acceptor_->listen();

        running_ = true;
        log().info("IPC server started on: {}", config_.socket_path);

        // Start accept loop
        asio::co_spawn(ioc_, accept_loop(), asio::detached);

        return true;
    } catch (const std::exception& e) {
        log().error("Failed to start IPC server: {}", e.what());
        return false;
    }
#else
    // Unix domain socket
    try {
        // Remove existing socket file if present
        std::error_code ec;
        std::filesystem::remove(config_.socket_path, ec);

        acceptor_ = std::make_unique<asio::local::stream_protocol::acceptor>(ioc_);
        acceptor_->open();
        acceptor_->bind(asio::local::stream_protocol::endpoint(config_.socket_path));
        acceptor_->listen();

        // Set socket permissions (world read/write for daemon-CLI communication)
        // This allows non-root users to connect when daemon runs as root
        std::filesystem::permissions(config_.socket_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
            std::filesystem::perms::group_read | std::filesystem::perms::group_write |
            std::filesystem::perms::others_read | std::filesystem::perms::others_write,
            std::filesystem::perm_options::replace, ec);

        running_ = true;
        log().info("IPC server started on: {}", config_.socket_path);

        // Start accept loop
        asio::co_spawn(ioc_, accept_loop(), asio::detached);

        return true;
    } catch (const std::exception& e) {
        log().error("Failed to start IPC server: {}", e.what());
        return false;
    }
#endif
}

void IpcServer::stop() {
    if (!running_) return;

    running_ = false;

    if (acceptor_) {
        boost::system::error_code ec;
        acceptor_->close(ec);
        acceptor_.reset();
    }

    // Remove socket file
    std::error_code ec;
    std::filesystem::remove(config_.socket_path, ec);

    log().info("IPC server stopped");
}

asio::awaitable<void> IpcServer::accept_loop() {
    while (running_ && acceptor_) {
        try {
            auto socket = co_await acceptor_->async_accept(asio::use_awaitable);
            log().debug("IPC client connected");

            // Handle client in a new coroutine
            asio::co_spawn(ioc_, handle_client(std::move(socket)), asio::detached);

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted && running_) {
                log().error("IPC accept error: {}", e.what());
            }
        }
    }
}

asio::awaitable<void> IpcServer::handle_client(asio::local::stream_protocol::socket socket) {
    try {
        // Simple line-based protocol
        asio::streambuf buffer;

        while (running_) {
            // Read a line (request)
            size_t n = co_await asio::async_read_until(socket, buffer, '\n', asio::use_awaitable);

            std::istream is(&buffer);
            std::string request;
            std::getline(is, request);

            // Remove trailing CR if present (Windows compatibility)
            if (!request.empty() && request.back() == '\r') {
                request.pop_back();
            }

            log().debug("IPC request: {}", request);

            // Process request
            std::string response = process_request(request);

            // Send response (with newline)
            response += '\n';
            co_await asio::async_write(socket, asio::buffer(response), asio::use_awaitable);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::eof &&
            e.code() != asio::error::connection_reset &&
            e.code() != asio::error::broken_pipe) {
            log().debug("IPC client error: {}", e.what());
        }
    }

    log().debug("IPC client disconnected");
}

std::string IpcServer::process_request(const std::string& request) {
    try {
        // Parse JSON request
        auto jv = json::parse(request);
        auto& obj = jv.as_object();

        std::string cmd = json::value_to<std::string>(obj.at("cmd"));

        if (cmd == "status") {
            return handle_status();
        } else if (cmd == "peers") {
            bool online_only = false;
            if (obj.contains("online_only")) {
                online_only = obj.at("online_only").as_bool();
            }
            return handle_peers(online_only);
        } else if (cmd == "routes") {
            return handle_routes();
        } else if (cmd == "ping") {
            std::string target = json::value_to<std::string>(obj.at("target"));
            return handle_ping(target);
        } else if (cmd == "log_level") {
            std::string module = obj.contains("module") ?
                json::value_to<std::string>(obj.at("module")) : "";
            std::string level = obj.contains("level") ?
                json::value_to<std::string>(obj.at("level")) : "";
            return handle_log_level(module, level);
        } else if (cmd == "shutdown") {
            return handle_shutdown();
        } else if (cmd == "config_get") {
            std::string key = json::value_to<std::string>(obj.at("key"));
            return handle_config_get(key);
        } else if (cmd == "config_set") {
            std::string key = json::value_to<std::string>(obj.at("key"));
            std::string value = json::value_to<std::string>(obj.at("value"));
            return handle_config_set(key, value);
        } else if (cmd == "config_list") {
            return handle_config_list();
        } else if (cmd == "config_reload") {
            return handle_config_reload();
        } else if (cmd == "prefs_update") {
            return handle_prefs_update();
        } else {
            return encode_error(IpcStatus::INVALID_REQUEST, "Unknown command: " + cmd);
        }

    } catch (const std::exception& e) {
        return encode_error(IpcStatus::INVALID_REQUEST, std::string("Parse error: ") + e.what());
    }
}

std::string IpcServer::handle_status() {
    IpcStatusResponse data;

    data.state = client_state_name(client_.state());
    data.node_id = std::to_string(client_.node_id());
    data.virtual_ip = client_.virtual_ip().to_string();
    data.network_id = client_.network_id();
    data.peer_count = client_.peers().peer_count();
    data.online_peer_count = client_.peers().online_peer_count();
    data.tun_enabled = client_.is_tun_enabled();

    return encode_status_response(IpcStatus::OK, data);
}

std::string IpcServer::handle_peers(bool online_only) {
    std::vector<IpcPeerInfo> peers;

    auto peer_list = online_only ?
        client_.peers().get_online_peers() :
        client_.peers().get_all_peers();

    for (const auto& p : peer_list) {
        IpcPeerInfo info;
        info.node_id = std::to_string(p.info.node_id);
        info.virtual_ip = p.info.virtual_ip.to_string();
        info.name = p.info.name;
        info.online = p.info.online;

        // 从状态机获取连接状态和延迟
        auto peer_state = client_.state_machine().get_peer_state(p.info.node_id);
        if (peer_state) {
            info.latency_ms = peer_state->rtt_ms;
            switch (peer_state->data_path) {
                case PeerDataPath::P2P:
                    info.connection_status = "p2p";
                    break;
                case PeerDataPath::RELAY:
                    info.connection_status = "relay";
                    break;
                default:
                    info.connection_status = "disconnected";
                    break;
            }
        } else {
            info.latency_ms = 0;
            info.connection_status = "disconnected";
        }

        peers.push_back(std::move(info));
    }

    return encode_peers_response(IpcStatus::OK, peers);
}

std::string IpcServer::handle_routes() {
    std::vector<IpcRouteInfo> routes;

    // 获取路由列表
    auto route_list = client_.routes();

    for (const auto& r : route_list) {
        IpcRouteInfo info;

        // 格式化 prefix 为 CIDR 格式
        std::string prefix_str;
        if (r.ip_type == IpType::IPv4) {
            prefix_str = std::to_string(r.prefix[0]) + "." +
                         std::to_string(r.prefix[1]) + "." +
                         std::to_string(r.prefix[2]) + "." +
                         std::to_string(r.prefix[3]);
        } else {
            // IPv6 简化处理
            prefix_str = "ipv6";
        }
        info.prefix = prefix_str + "/" + std::to_string(r.prefix_len);

        info.gateway_node_id = std::to_string(r.gateway_node);
        info.metric = r.metric;
        info.exit_node = has_flag(r.flags, RouteFlags::EXIT_NODE);

        // 查找网关节点的信息
        auto peer = client_.peers().get_peer(r.gateway_node);
        if (peer) {
            info.gateway_ip = peer->info.virtual_ip.to_string();
            info.gateway_name = peer->info.name;
        } else {
            info.gateway_ip = "";
            info.gateway_name = "";
        }

        routes.push_back(std::move(info));
    }

    return encode_routes_response(IpcStatus::OK, routes);
}

std::string IpcServer::handle_ping(const std::string& target) {
    if (target.empty()) {
        return encode_error(IpcStatus::INVALID_REQUEST, "Target IP required");
    }

    // Parse target IP
    IPv4Address ip = IPv4Address::from_string(target);
    if (ip.to_u32() == 0) {
        return encode_error(IpcStatus::INVALID_REQUEST, "Invalid IP address: " + target);
    }

    // Find peer by IP
    auto peer = client_.peers().get_peer_by_ip(ip);
    if (!peer) {
        return encode_error(IpcStatus::PEER_NOT_FOUND, "No peer with IP: " + target);
    }

    if (!peer->info.online) {
        return encode_error(IpcStatus::PEER_NOT_FOUND, "Peer is offline: " + target);
    }

    // Execute ping synchronously using a promise - 使用 shared_from_this 保证生命周期安全
    auto promise = std::make_shared<std::promise<uint16_t>>();
    auto future = promise->get_future();

    asio::co_spawn(ioc_, [self = shared_from_this(), ip, promise]() -> asio::awaitable<void> {
        uint16_t latency = co_await self->client_.ping_ip(ip);
        promise->set_value(latency);
    }, asio::detached);

    // Wait for result with timeout (6 seconds to allow for 5s ping timeout)
    if (future.wait_for(std::chrono::seconds(6)) == std::future_status::timeout) {
        return encode_error(IpcStatus::ERROR, "Ping timeout");
    }

    uint16_t latency = future.get();
    if (latency == 0) {
        return encode_error(IpcStatus::ERROR, "Ping failed or timed out");
    }

    json::object result;
    result["status"] = "ok";
    result["target"] = target;
    result["latency_ms"] = latency;
    return json::serialize(result);
}

std::string IpcServer::handle_log_level(const std::string& module, const std::string& level) {
    if (level.empty()) {
        // Get current level
        auto& lm = LogManager::instance();
        if (module.empty()) {
            auto global_level = lm.get_global_level();
            json::object obj;
            obj["status"] = "ok";
            obj["global_level"] = std::string(log_level_to_string(global_level));

            auto module_levels = lm.get_all_module_levels();
            json::object modules;
            for (const auto& [m, l] : module_levels) {
                modules[m] = std::string(log_level_to_string(l));
            }
            obj["modules"] = modules;

            return json::serialize(obj);
        } else {
            auto mod_level = lm.get_module_level(module);
            json::object obj;
            obj["status"] = "ok";
            obj["module"] = module;
            obj["level"] = mod_level ?
                std::string(log_level_to_string(*mod_level)) : "default";
            return json::serialize(obj);
        }
    } else {
        // Set level
        auto new_level = log_level_from_string(level);
        auto& lm = LogManager::instance();

        if (module.empty()) {
            lm.set_global_level(new_level);
            log().info("Global log level set to: {}", level);
        } else {
            lm.set_module_level(module, new_level);
            log().info("Log level for '{}' set to: {}", module, level);
        }

        return encode_ok("Log level updated");
    }
}

std::string IpcServer::handle_shutdown() {
    log().info("Shutdown requested via IPC");

    if (shutdown_callback_) {
        // Post the callback to execute after response is sent
        asio::post(ioc_, [callback = shutdown_callback_]() {
            callback();
        });
    }

    return encode_ok("Shutdown initiated");
}

std::string IpcServer::handle_config_get(const std::string& key) {
    auto meta = edgelink::get_config_metadata(key);
    if (!meta.has_value()) {
        return encode_error(IpcStatus::INVALID_REQUEST, "Unknown config key: " + key);
    }

    // 获取当前值
    IpcConfigItem item;
    item.key = key;
    item.type = edgelink::config_type_to_string(meta->type);
    item.description = meta->description;
    item.hot_reloadable = meta->hot_reloadable;
    item.default_value = meta->default_value;
    item.value = client_.get_config_value(key);

    return encode_config_response(IpcStatus::OK, item);
}

std::string IpcServer::handle_config_set(const std::string& key, const std::string& value) {
    auto meta = edgelink::get_config_metadata(key);
    if (!meta.has_value()) {
        return encode_error(IpcStatus::INVALID_REQUEST, "Unknown config key: " + key);
    }

    // 验证值
    if (!edgelink::validate_config_value(key, value)) {
        return encode_error(IpcStatus::INVALID_REQUEST, "Invalid value for " + key);
    }

    IpcConfigChange change;
    change.key = key;
    change.old_value = client_.get_config_value(key);
    change.new_value = value;
    change.restart_required = !meta->hot_reloadable;

    // 如果可热重载，尝试应用
    if (meta->hot_reloadable && client_.config_applier()) {
        auto result = client_.config_applier()->apply_single(key, value);
        change.applied = result.applied;
        change.message = result.message;
        change.restart_required = result.restart_required;
    } else if (!meta->hot_reloadable) {
        change.applied = false;
        change.message = "此配置需要重启才能生效";
    }

    // 写入配置文件
    const auto& config_path = client_.config_path();
    if (!config_path.empty()) {
        edgelink::TomlConfigWriter writer(config_path);
        if (writer.load()) {
            writer.set_value(key, value);
            if (writer.save()) {
                log().info("Config saved to file: {} = {}", key, value);
            } else {
                log().warn("Failed to save config to file");
            }
        }
    }

    return encode_config_change_response(IpcStatus::OK, change);
}

std::string IpcServer::handle_config_list() {
    std::vector<IpcConfigItem> items;

    for (const auto& meta : edgelink::get_all_config_metadata()) {
        IpcConfigItem item;
        item.key = meta.key;
        item.type = edgelink::config_type_to_string(meta.type);
        item.description = meta.description;
        item.hot_reloadable = meta.hot_reloadable;
        item.default_value = meta.default_value;
        item.value = client_.get_config_value(meta.key);
        items.push_back(std::move(item));
    }

    return encode_config_list_response(IpcStatus::OK, items);
}

std::string IpcServer::handle_config_reload() {
    std::vector<IpcConfigChange> changes;

    log().info("Config reload requested via IPC");

    // 调用 ConfigWatcher 的 reload 方法
    auto* watcher = client_.config_watcher();
    if (watcher) {
        if (watcher->reload()) {
            // ConfigWatcher 的 reload 会触发回调，配置会自动应用
            // 但我们无法直接获取变更列表，所以返回空列表
            log().info("Config reloaded from file");
        } else {
            return encode_error(IpcStatus::ERROR, "Failed to reload config");
        }
    } else {
        // 没有 ConfigWatcher，尝试手动加载
        const auto& config_path = client_.config_path();
        if (config_path.empty()) {
            return encode_error(IpcStatus::ERROR, "Config path not set");
        }

        auto result = edgelink::ClientConfig::load(config_path);
        if (!result.has_value()) {
            return encode_error(IpcStatus::ERROR, "Failed to load config: " +
                edgelink::config_error_message(result.error()));
        }

        // 转换并应用配置
        ClientConfig new_config;
        new_config.controller_url = result->controller_url;
        new_config.authkey = result->authkey;
        new_config.tls = result->tls;
        new_config.auto_reconnect = result->auto_reconnect;
        new_config.reconnect_interval = result->reconnect_interval;
        new_config.ping_interval = result->ping_interval;
        new_config.dns_refresh_interval = result->dns_refresh_interval;
        new_config.latency_measure_interval = result->latency_measure_interval;
        new_config.ssl_verify = result->ssl_verify;
        new_config.ssl_ca_file = result->ssl_ca_file;
        new_config.ssl_allow_self_signed = result->ssl_allow_self_signed;
        new_config.state_dir = result->state_dir;
        new_config.enable_tun = result->enable_tun;
        new_config.tun_name = result->tun_name;
        new_config.tun_mtu = result->tun_mtu;
        new_config.advertise_routes = result->advertise_routes;
        new_config.exit_node = result->exit_node;
        new_config.accept_routes = result->accept_routes;
        new_config.log_level = result->log_level;
        new_config.log_file = result->log_file;

        if (client_.config_applier()) {
            auto applied_changes = client_.config_applier()->apply(client_.config(), new_config);
            for (const auto& c : applied_changes) {
                IpcConfigChange ipc_change;
                ipc_change.key = c.key;
                ipc_change.old_value = c.old_value;
                ipc_change.new_value = c.new_value;
                ipc_change.applied = c.applied;
                ipc_change.restart_required = c.restart_required;
                ipc_change.message = c.message;
                changes.push_back(std::move(ipc_change));
            }
            // 更新配置
            client_.config() = new_config;
        }
    }

    return encode_config_reload_response(IpcStatus::OK, changes);
}

std::string IpcServer::handle_prefs_update() {
    log().info("Prefs update requested via IPC");

    try {
        // 加载最新的 prefs.toml
        auto state_dir = get_state_dir();
        PrefsStore prefs(state_dir);

        if (!prefs.load()) {
            return encode_error(IpcStatus::ERROR, "Failed to load prefs: " + prefs.last_error());
        }

        // 应用到当前配置
        ClientConfig& cfg = client_.config();
        prefs.apply_to(cfg);

        // 如果有配置应用器，通知它配置已更改
        if (client_.config_applier()) {
            // 创建一个包含 prefs 相关配置的变更列表
            std::vector<ConfigChange> changes;

            // exit_node 变更
            if (prefs.exit_node()) {
                ConfigChange change;
                change.key = "routing.use_exit_node";
                change.new_value = *prefs.exit_node();
                change.applied = true;
                changes.push_back(change);
            }

            // advertise_exit_node 变更
            {
                ConfigChange change;
                change.key = "routing.exit_node";
                change.new_value = prefs.advertise_exit_node() ? "true" : "false";
                change.applied = true;
                changes.push_back(change);
            }

            // advertise_routes 变更
            {
                ConfigChange change;
                change.key = "routing.advertise_routes";
                std::string routes_str;
                for (const auto& r : prefs.advertise_routes()) {
                    if (!routes_str.empty()) routes_str += ",";
                    routes_str += r;
                }
                change.new_value = routes_str;
                change.applied = true;
                changes.push_back(change);
            }

            // accept_routes 变更
            {
                ConfigChange change;
                change.key = "routing.accept_routes";
                change.new_value = prefs.accept_routes() ? "true" : "false";
                change.applied = true;
                changes.push_back(change);
            }

            log().info("Applied {} prefs changes", changes.size());
        }

        // 触发路由重新公告（如果需要）
        client_.request_route_reannounce();

        return encode_ok("Prefs updated successfully");
    } catch (const std::exception& e) {
        return encode_error(IpcStatus::ERROR, std::string("Failed to update prefs: ") + e.what());
    }
}

std::string IpcServer::encode_config_response(IpcStatus status, const IpcConfigItem& item) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";
    obj["key"] = item.key;
    obj["value"] = item.value;
    obj["type"] = item.type;
    obj["description"] = item.description;
    obj["hot_reloadable"] = item.hot_reloadable;
    obj["default_value"] = item.default_value;
    return json::serialize(obj);
}

std::string IpcServer::encode_config_list_response(IpcStatus status, const std::vector<IpcConfigItem>& items) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";

    json::array arr;
    for (const auto& item : items) {
        arr.push_back({
            {"key", item.key},
            {"value", item.value},
            {"type", item.type},
            {"description", item.description},
            {"hot_reloadable", item.hot_reloadable},
            {"default_value", item.default_value}
        });
    }
    obj["config"] = arr;

    // 列出可热重载的配置项
    json::array hot_reloadable;
    for (const auto& item : items) {
        if (item.hot_reloadable) {
            hot_reloadable.push_back(json::value(item.key));
        }
    }
    obj["hot_reloadable_keys"] = hot_reloadable;

    return json::serialize(obj);
}

std::string IpcServer::encode_config_change_response(IpcStatus status, const IpcConfigChange& change) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";
    obj["key"] = change.key;
    obj["old_value"] = change.old_value;
    obj["new_value"] = change.new_value;
    obj["applied"] = change.applied;
    obj["restart_required"] = change.restart_required;
    if (!change.message.empty()) {
        obj["message"] = change.message;
    }
    return json::serialize(obj);
}

std::string IpcServer::encode_config_reload_response(IpcStatus status, const std::vector<IpcConfigChange>& changes) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";

    json::array arr;
    for (const auto& c : changes) {
        arr.push_back({
            {"key", c.key},
            {"old_value", c.old_value},
            {"new_value", c.new_value},
            {"applied", c.applied},
            {"restart_required", c.restart_required},
            {"message", c.message}
        });
    }
    obj["changes"] = arr;

    return json::serialize(obj);
}

std::string IpcServer::encode_status_response(IpcStatus status, const IpcStatusResponse& data) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";
    obj["data"] = {
        {"state", data.state},
        {"node_id", data.node_id},
        {"virtual_ip", data.virtual_ip},
        {"network_id", data.network_id},
        {"peer_count", data.peer_count},
        {"online_peer_count", data.online_peer_count},
        {"tun_enabled", data.tun_enabled}
    };
    return json::serialize(obj);
}

std::string IpcServer::encode_peers_response(IpcStatus status, const std::vector<IpcPeerInfo>& peers) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";

    json::array arr;
    for (const auto& p : peers) {
        arr.push_back({
            {"node_id", p.node_id},
            {"virtual_ip", p.virtual_ip},
            {"name", p.name},
            {"online", p.online},
            {"connection_status", p.connection_status},
            {"latency_ms", p.latency_ms}
        });
    }
    obj["peers"] = arr;

    return json::serialize(obj);
}

std::string IpcServer::encode_routes_response(IpcStatus status, const std::vector<IpcRouteInfo>& routes) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";

    json::array arr;
    for (const auto& r : routes) {
        arr.push_back({
            {"prefix", r.prefix},
            {"gateway_node_id", r.gateway_node_id},
            {"gateway_ip", r.gateway_ip},
            {"gateway_name", r.gateway_name},
            {"metric", r.metric},
            {"exit_node", r.exit_node}
        });
    }
    obj["routes"] = arr;

    return json::serialize(obj);
}

std::string IpcServer::encode_error(IpcStatus status, const std::string& message) {
    json::object obj;
    obj["status"] = "error";
    obj["code"] = static_cast<int>(status);
    obj["message"] = message;
    return json::serialize(obj);
}

std::string IpcServer::encode_ok(const std::string& message) {
    json::object obj;
    obj["status"] = "ok";
    if (!message.empty()) {
        obj["message"] = message;
    }
    return json::serialize(obj);
}

// ============================================================================
// IpcClient
// ============================================================================

IpcClient::IpcClient(const std::string& socket_path)
    : socket_path_(socket_path.empty() ? IpcServer::get_default_socket_path() : socket_path) {}

IpcClient::~IpcClient() {
    if (socket_) {
        boost::system::error_code ec;
        socket_->close(ec);
    }
}

bool IpcClient::connect() {
    try {
        socket_ = std::make_unique<asio::local::stream_protocol::socket>(ioc_);
        socket_->connect(asio::local::stream_protocol::endpoint(socket_path_));
        connected_ = true;
        return true;
    } catch (const std::exception& e) {
        // Print error to stderr for debugging
        std::cerr << "IPC connect failed: " << e.what()
                  << " (socket: " << socket_path_ << ")\n";
        connected_ = false;
        return false;
    }
}

std::string IpcClient::send_request(const std::string& request) {
    if (!connected_ || !socket_) {
        return R"({"status":"error","message":"Not connected"})";
    }

    try {
        // Send request with newline
        std::string req = request + "\n";
        asio::write(*socket_, asio::buffer(req));

        // Read response
        asio::streambuf buffer;
        asio::read_until(*socket_, buffer, '\n');

        std::istream is(&buffer);
        std::string response;
        std::getline(is, response);

        // Remove trailing CR if present
        if (!response.empty() && response.back() == '\r') {
            response.pop_back();
        }

        return response;
    } catch (const std::exception& e) {
        return std::string(R"({"status":"error","message":")") + e.what() + "\"}";
    }
}

std::string IpcClient::get_status() {
    return send_request(R"({"cmd":"status"})");
}

std::string IpcClient::get_peers(bool online_only) {
    if (online_only) {
        return send_request(R"({"cmd":"peers","online_only":true})");
    }
    return send_request(R"({"cmd":"peers"})");
}

std::string IpcClient::get_routes() {
    return send_request(R"({"cmd":"routes"})");
}

std::string IpcClient::ping_peer(const std::string& target) {
    return send_request(R"({"cmd":"ping","target":")" + target + "\"}");
}

std::string IpcClient::set_log_level(const std::string& module, const std::string& level) {
    json::object obj;
    obj["cmd"] = "log_level";
    if (!module.empty()) obj["module"] = module;
    if (!level.empty()) obj["level"] = level;
    return send_request(json::serialize(obj));
}

std::string IpcClient::request_shutdown() {
    return send_request(R"({"cmd":"shutdown"})");
}

std::string IpcClient::config_get(const std::string& key) {
    json::object obj;
    obj["cmd"] = "config_get";
    obj["key"] = key;
    return send_request(json::serialize(obj));
}

std::string IpcClient::config_set(const std::string& key, const std::string& value) {
    json::object obj;
    obj["cmd"] = "config_set";
    obj["key"] = key;
    obj["value"] = value;
    return send_request(json::serialize(obj));
}

std::string IpcClient::config_list() {
    return send_request(R"({"cmd":"config_list"})");
}

std::string IpcClient::config_reload() {
    return send_request(R"({"cmd":"config_reload"})");
}

std::string IpcClient::prefs_update() {
    return send_request(R"({"cmd":"prefs_update"})");
}

} // namespace edgelink::client

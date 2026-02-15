#include "common/config.hpp"
#include "common/logger.hpp"
#include <boost/json.hpp>
#include <fstream>
#include <sstream>

namespace json = boost::json;

// Safe JSON field accessors with defaults (file-scope, used by both namespaces)
namespace {

std::string jstr(const json::object& obj, std::string_view key, const std::string& def = {}) {
    if (auto it = obj.find(key); it != obj.end() && it->value().is_string())
        return std::string(it->value().as_string());
    return def;
}

bool jbool(const json::object& obj, std::string_view key, bool def = false) {
    if (auto it = obj.find(key); it != obj.end() && it->value().is_bool())
        return it->value().as_bool();
    return def;
}

int64_t jint(const json::object& obj, std::string_view key, int64_t def = 0) {
    if (auto it = obj.find(key); it != obj.end()) {
        if (it->value().is_int64()) return it->value().as_int64();
        if (it->value().is_uint64()) return static_cast<int64_t>(it->value().as_uint64());
    }
    return def;
}

uint64_t juint(const json::object& obj, std::string_view key, uint64_t def = 0) {
    if (auto it = obj.find(key); it != obj.end()) {
        if (it->value().is_uint64()) return it->value().as_uint64();
        if (it->value().is_int64()) return static_cast<uint64_t>(it->value().as_int64());
    }
    return def;
}

const json::object* jsection(const json::object& obj, std::string_view key) {
    if (auto it = obj.find(key); it != obj.end() && it->value().is_object())
        return &it->value().as_object();
    return nullptr;
}

const json::array* jarray(const json::object& obj, std::string_view key) {
    if (auto it = obj.find(key); it != obj.end() && it->value().is_array())
        return &it->value().as_array();
    return nullptr;
}

}  // anonymous namespace

namespace edgelink {

namespace {
auto& log() { return Logger::get("common.config"); }
}  // anonymous namespace

std::string config_error_message(ConfigError error) {
    switch (error) {
        case ConfigError::FILE_NOT_FOUND: return "Configuration file not found";
        case ConfigError::PARSE_ERROR: return "Failed to parse configuration file";
        case ConfigError::INVALID_VALUE: return "Invalid configuration value";
        case ConfigError::MISSING_REQUIRED: return "Missing required configuration";
        default: return "Unknown configuration error";
    }
}

// ============================================================================
// ControllerConfig
// ============================================================================

std::expected<ControllerConfig, ConfigError> ControllerConfig::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::unexpected(ConfigError::FILE_NOT_FOUND);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse(buffer.str());
}

std::expected<ControllerConfig, ConfigError> ControllerConfig::parse(const std::string& json_content) {
    try {
        auto jv = json::parse(json_content);
        auto& root = jv.as_object();

        ControllerConfig config;

        // server section
        if (auto* server = jsection(root, "server")) {
            config.bind_address = jstr(*server, "bind", config.bind_address);
            config.port = static_cast<uint16_t>(juint(*server, "port", config.port));
            config.num_threads = static_cast<size_t>(juint(*server, "threads", config.num_threads));
            config.tls = jbool(*server, "tls", config.tls);
        }

        // ssl section
        if (auto* ssl = jsection(root, "ssl")) {
            config.cert_file = jstr(*ssl, "cert");
            config.key_file = jstr(*ssl, "key");
        }

        // database section
        if (auto* db = jsection(root, "database")) {
            config.database_path = jstr(*db, "path", config.database_path);
        }

        // jwt section
        if (auto* jwt = jsection(root, "jwt")) {
            config.jwt_secret = jstr(*jwt, "secret");
            if (auto hours = jint(*jwt, "auth_token_hours"))
                config.auth_token_validity = std::chrono::hours(hours);
            if (auto mins = jint(*jwt, "relay_token_minutes"))
                config.relay_token_validity = std::chrono::minutes(mins);
        }

        // log section
        if (auto* log_sec = jsection(root, "log")) {
            config.log_level = jstr(*log_sec, "level", config.log_level);
            config.log_file = jstr(*log_sec, "file", config.log_file);
        }

        // builtin_relay section
        if (auto* relay = jsection(root, "builtin_relay")) {
            config.builtin_relay.enabled = jbool(*relay, "enabled");
            config.builtin_relay.name = jstr(*relay, "name");
            config.builtin_relay.region = jstr(*relay, "region");
            config.builtin_relay.priority = static_cast<uint16_t>(juint(*relay, "priority"));
        }

        // builtin_stun section
        if (auto* stun = jsection(root, "builtin_stun")) {
            config.builtin_stun.enabled = jbool(*stun, "enabled");
            // 支持 public_ip 和 ip 两种写法（优先 public_ip）
            auto pip = jstr(*stun, "public_ip");
            config.builtin_stun.public_ip = pip.empty() ? jstr(*stun, "ip") : pip;
            config.builtin_stun.port = static_cast<uint16_t>(juint(*stun, "port", 3478));
        }

        return config;

    } catch (const boost::system::system_error& e) {
        log().error("JSON parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    } catch (const std::exception& e) {
        log().error("Config parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    }
}

} // namespace edgelink

// ============================================================================
// ClientConfig (in edgelink::client namespace)
// ============================================================================

namespace edgelink::client {

std::expected<ClientConfig, ConfigError> ClientConfig::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::unexpected(ConfigError::FILE_NOT_FOUND);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    return parse(buffer.str());
}

std::expected<ClientConfig, ConfigError> ClientConfig::parse(const std::string& json_content) {
    auto& logger = Logger::get("common.config");
    try {
        auto jv = json::parse(json_content);
        auto& root = jv.as_object();

        ClientConfig config;

        // controller section
        if (auto* controller = jsection(root, "controller")) {
            config.controller_url = jstr(*controller, "url");
            config.authkey = jstr(*controller, "authkey");
            config.tls = jbool(*controller, "tls", true);
        }

        // ssl section
        if (auto* ssl = jsection(root, "ssl")) {
            config.ssl_verify = jbool(*ssl, "verify", true);
            config.ssl_ca_file = jstr(*ssl, "ca_file");
            config.ssl_allow_self_signed = jbool(*ssl, "allow_self_signed");
        }

        // connection section
        if (auto* conn = jsection(root, "connection")) {
            config.auto_reconnect = jbool(*conn, "auto_reconnect", config.auto_reconnect);
            if (auto v = jint(*conn, "reconnect_interval"))
                config.reconnect_interval = std::chrono::seconds(v);
            if (auto v = jint(*conn, "ping_interval"))
                config.ping_interval = std::chrono::seconds(v);
            if (auto v = jint(*conn, "dns_refresh_interval"))
                config.dns_refresh_interval = std::chrono::seconds(v);
            if (auto v = jint(*conn, "latency_measure_interval"))
                config.latency_measure_interval = std::chrono::seconds(v);
            if (auto v = jint(*conn, "endpoint_connect_timeout"))
                config.endpoint_connect_timeout = std::chrono::seconds(v);
        }

        // storage section
        if (auto* storage = jsection(root, "storage")) {
            config.state_dir = jstr(*storage, "state_dir", config.state_dir);
        }

        // tun section
        if (auto* tun = jsection(root, "tun")) {
            config.enable_tun = jbool(*tun, "enable", config.enable_tun);
            config.tun_name = jstr(*tun, "name", config.tun_name);
            config.tun_mtu = static_cast<uint32_t>(juint(*tun, "mtu", config.tun_mtu));
        }

        // routing section
        if (auto* routing = jsection(root, "routing")) {
            if (auto* routes = jarray(*routing, "advertise_routes")) {
                for (const auto& item : *routes) {
                    if (item.is_string())
                        config.advertise_routes.emplace_back(item.as_string());
                }
            }
            config.exit_node = jbool(*routing, "exit_node", config.exit_node);
            config.use_exit_node = jstr(*routing, "use_exit_node", config.use_exit_node);
            config.accept_routes = jbool(*routing, "accept_routes", config.accept_routes);
            if (auto v = jint(*routing, "announce_interval"))
                config.route_announce_interval = std::chrono::seconds(v);
        }

        // log section
        if (auto* log_sec = jsection(root, "log")) {
            config.log_level = jstr(*log_sec, "level", config.log_level);
            config.log_file = jstr(*log_sec, "file", config.log_file);
            // log.modules - nested map
            if (auto* modules = jsection(*log_sec, "modules")) {
                for (const auto& [key, value] : *modules) {
                    if (value.is_string())
                        config.module_log_levels[std::string(key)] = std::string(value.as_string());
                }
            }
        }

        // p2p section (JSON stores integers, P2PConfig uses chrono)
        if (auto* p2p = jsection(root, "p2p")) {
            config.p2p.enabled = jbool(*p2p, "enabled", config.p2p.enabled);
            config.p2p.bind_port = static_cast<uint16_t>(juint(*p2p, "bind_port", config.p2p.bind_port));
            if (auto v = juint(*p2p, "keepalive_interval"))
                config.p2p.keepalive_interval = std::chrono::seconds(v);
            if (auto v = juint(*p2p, "keepalive_timeout"))
                config.p2p.keepalive_timeout = std::chrono::seconds(v);
            if (auto v = juint(*p2p, "punch_timeout"))
                config.p2p.punch_timeout = std::chrono::seconds(v);
            config.p2p.punch_batch_count = static_cast<uint32_t>(juint(*p2p, "punch_batch_count", config.p2p.punch_batch_count));
            config.p2p.punch_batch_size = static_cast<uint32_t>(juint(*p2p, "punch_batch_size", config.p2p.punch_batch_size));
            if (auto v = juint(*p2p, "punch_batch_interval"))
                config.p2p.punch_batch_interval = std::chrono::milliseconds(v);
            if (auto v = juint(*p2p, "retry_interval"))
                config.p2p.retry_interval = std::chrono::seconds(v);
            if (auto v = juint(*p2p, "stun_timeout"))
                config.p2p.stun_timeout = std::chrono::milliseconds(v);
            if (auto v = juint(*p2p, "endpoint_refresh_interval"))
                config.p2p.endpoint_refresh_interval = std::chrono::seconds(v);
        }

        return config;

    } catch (const boost::system::system_error& e) {
        logger.error("JSON parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    } catch (const std::exception& e) {
        logger.error("Config parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    }
}

} // namespace edgelink::client

#include "common/config.hpp"
#include "common/logger.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <fstream>
#include <sstream>

namespace edgelink {

namespace pt = boost::property_tree;

namespace {
auto& log() { return Logger::get("common.config"); }
}

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
        std::stringstream ss(json_content);
        pt::ptree tree;
        pt::read_json(ss, tree);

        ControllerConfig config;

        // server section
        if (auto server = tree.get_child_optional("server")) {
            config.bind_address = server->get<std::string>("bind", config.bind_address);
            config.port = server->get<uint16_t>("port", config.port);
            config.num_threads = server->get<size_t>("threads", config.num_threads);
            config.tls = server->get<bool>("tls", config.tls);
        }

        // ssl section
        if (auto ssl = tree.get_child_optional("ssl")) {
            config.cert_file = ssl->get<std::string>("cert", "");
            config.key_file = ssl->get<std::string>("key", "");
        }

        // database section
        if (auto db = tree.get_child_optional("database")) {
            config.database_path = db->get<std::string>("path", config.database_path);
        }

        // jwt section
        if (auto jwt = tree.get_child_optional("jwt")) {
            config.jwt_secret = jwt->get<std::string>("secret", "");
            if (auto hours = jwt->get_optional<int64_t>("auth_token_hours")) {
                config.auth_token_validity = std::chrono::hours(*hours);
            }
            if (auto mins = jwt->get_optional<int64_t>("relay_token_minutes")) {
                config.relay_token_validity = std::chrono::minutes(*mins);
            }
        }

        // log section
        if (auto log_sec = tree.get_child_optional("log")) {
            config.log_level = log_sec->get<std::string>("level", config.log_level);
            config.log_file = log_sec->get<std::string>("file", config.log_file);
        }

        // builtin_relay section
        if (auto relay = tree.get_child_optional("builtin_relay")) {
            config.builtin_relay.enabled = relay->get<bool>("enabled", false);
            config.builtin_relay.name = relay->get<std::string>("name", "");
            config.builtin_relay.region = relay->get<std::string>("region", "");
            config.builtin_relay.priority = relay->get<uint16_t>("priority", 0);
        }

        // builtin_stun section
        if (auto stun = tree.get_child_optional("builtin_stun")) {
            config.builtin_stun.enabled = stun->get<bool>("enabled", false);
            // 支持 public_ip 和 ip 两种写法（优先 public_ip）
            if (auto v = stun->get_optional<std::string>("public_ip")) {
                config.builtin_stun.public_ip = *v;
            } else if (auto v = stun->get_optional<std::string>("ip")) {
                config.builtin_stun.public_ip = *v;
            }
            config.builtin_stun.port = stun->get<uint16_t>("port", 3478);
        }

        return config;

    } catch (const pt::json_parser_error& e) {
        log().error("JSON parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    } catch (const std::exception& e) {
        log().error("Config parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    }
}

// ============================================================================
// ClientConfig
// ============================================================================

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
    try {
        std::stringstream ss(json_content);
        pt::ptree tree;
        pt::read_json(ss, tree);

        ClientConfig config;

        // controller section
        if (auto controller = tree.get_child_optional("controller")) {
            config.controller_url = controller->get<std::string>("url", "");
            config.authkey = controller->get<std::string>("authkey", "");
            config.tls = controller->get<bool>("tls", true);
        }

        // ssl section
        if (auto ssl = tree.get_child_optional("ssl")) {
            config.ssl_verify = ssl->get<bool>("verify", true);
            config.ssl_ca_file = ssl->get<std::string>("ca_file", "");
            config.ssl_allow_self_signed = ssl->get<bool>("allow_self_signed", false);
        }

        // connection section
        if (auto conn = tree.get_child_optional("connection")) {
            config.auto_reconnect = conn->get<bool>("auto_reconnect", config.auto_reconnect);
            if (auto v = conn->get_optional<int64_t>("reconnect_interval")) {
                config.reconnect_interval = std::chrono::seconds(*v);
            }
            if (auto v = conn->get_optional<int64_t>("ping_interval")) {
                config.ping_interval = std::chrono::seconds(*v);
            }
            if (auto v = conn->get_optional<int64_t>("dns_refresh_interval")) {
                config.dns_refresh_interval = std::chrono::seconds(*v);
            }
            if (auto v = conn->get_optional<int64_t>("latency_measure_interval")) {
                config.latency_measure_interval = std::chrono::seconds(*v);
            }
            if (auto v = conn->get_optional<int64_t>("endpoint_connect_timeout")) {
                config.endpoint_connect_timeout = std::chrono::seconds(*v);
            }
        }

        // storage section
        if (auto storage = tree.get_child_optional("storage")) {
            config.state_dir = storage->get<std::string>("state_dir", config.state_dir);
        }

        // tun section
        if (auto tun = tree.get_child_optional("tun")) {
            config.enable_tun = tun->get<bool>("enable", config.enable_tun);
            config.tun_name = tun->get<std::string>("name", config.tun_name);
            config.tun_mtu = tun->get<uint32_t>("mtu", config.tun_mtu);
        }

        // routing section
        if (auto routing = tree.get_child_optional("routing")) {
            if (auto routes = routing->get_child_optional("advertise_routes")) {
                for (const auto& item : *routes) {
                    config.advertise_routes.push_back(item.second.get_value<std::string>());
                }
            }
            config.exit_node = routing->get<bool>("exit_node", config.exit_node);
            config.use_exit_node = routing->get<std::string>("use_exit_node", config.use_exit_node);
            config.accept_routes = routing->get<bool>("accept_routes", config.accept_routes);
            if (auto v = routing->get_optional<int64_t>("announce_interval")) {
                config.route_announce_interval = std::chrono::seconds(*v);
            }
        }

        // log section
        if (auto log_sec = tree.get_child_optional("log")) {
            config.log_level = log_sec->get<std::string>("level", config.log_level);
            config.log_file = log_sec->get<std::string>("file", config.log_file);
            // log.modules - nested map
            if (auto modules = log_sec->get_child_optional("modules")) {
                for (const auto& [key, value] : *modules) {
                    config.module_log_levels[key] = value.get_value<std::string>();
                }
            }
        }

        // p2p section
        if (auto p2p = tree.get_child_optional("p2p")) {
            config.p2p.enabled = p2p->get<bool>("enabled", config.p2p.enabled);
            config.p2p.bind_port = p2p->get<uint16_t>("bind_port", config.p2p.bind_port);
            config.p2p.keepalive_interval = p2p->get<uint32_t>("keepalive_interval", config.p2p.keepalive_interval);
            config.p2p.keepalive_timeout = p2p->get<uint32_t>("keepalive_timeout", config.p2p.keepalive_timeout);
            config.p2p.punch_timeout = p2p->get<uint32_t>("punch_timeout", config.p2p.punch_timeout);
            config.p2p.punch_batch_count = p2p->get<uint32_t>("punch_batch_count", config.p2p.punch_batch_count);
            config.p2p.punch_batch_size = p2p->get<uint32_t>("punch_batch_size", config.p2p.punch_batch_size);
            config.p2p.punch_batch_interval = p2p->get<uint32_t>("punch_batch_interval", config.p2p.punch_batch_interval);
            config.p2p.retry_interval = p2p->get<uint32_t>("retry_interval", config.p2p.retry_interval);
            config.p2p.stun_timeout = p2p->get<uint32_t>("stun_timeout", config.p2p.stun_timeout);
            config.p2p.endpoint_refresh_interval = p2p->get<uint32_t>("endpoint_refresh_interval", config.p2p.endpoint_refresh_interval);
        }

        return config;

    } catch (const pt::json_parser_error& e) {
        log().error("JSON parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    } catch (const std::exception& e) {
        log().error("Config parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    }
}

} // namespace edgelink

#include "common/config.hpp"
#include "common/logger.hpp"
#include <toml++/toml.hpp>
#include <fstream>
#include <sstream>

namespace edgelink {

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

std::expected<ControllerConfig, ConfigError> ControllerConfig::parse(const std::string& toml_content) {
    try {
        auto tbl = toml::parse(toml_content);
        ControllerConfig config;

        // [server] section
        if (auto server = tbl["server"].as_table()) {
            if (auto v = (*server)["bind"].value<std::string>()) {
                config.bind_address = *v;
            }
            if (auto v = (*server)["port"].value<int64_t>()) {
                config.port = static_cast<uint16_t>(*v);
            }
            if (auto v = (*server)["threads"].value<int64_t>()) {
                config.num_threads = static_cast<size_t>(*v);
            }
            if (auto v = (*server)["tls"].value<bool>()) {
                config.tls = *v;
            }
        }

        // [ssl] section
        if (auto ssl = tbl["ssl"].as_table()) {
            if (auto v = (*ssl)["cert"].value<std::string>()) {
                config.cert_file = *v;
            }
            if (auto v = (*ssl)["key"].value<std::string>()) {
                config.key_file = *v;
            }
        }

        // [database] section
        if (auto db = tbl["database"].as_table()) {
            if (auto v = (*db)["path"].value<std::string>()) {
                config.database_path = *v;
            }
        }

        // [jwt] section
        if (auto jwt = tbl["jwt"].as_table()) {
            if (auto v = (*jwt)["secret"].value<std::string>()) {
                config.jwt_secret = *v;
            }
            if (auto v = (*jwt)["auth_token_hours"].value<int64_t>()) {
                config.auth_token_validity = std::chrono::hours(*v);
            }
            if (auto v = (*jwt)["relay_token_minutes"].value<int64_t>()) {
                config.relay_token_validity = std::chrono::minutes(*v);
            }
        }

        // [log] section
        if (auto log = tbl["log"].as_table()) {
            if (auto v = (*log)["level"].value<std::string>()) {
                config.log_level = *v;
            }
            if (auto v = (*log)["file"].value<std::string>()) {
                config.log_file = *v;
            }
        }

        // [builtin_relay] section
        if (auto relay = tbl["builtin_relay"].as_table()) {
            if (auto v = (*relay)["enabled"].value<bool>()) {
                config.builtin_relay.enabled = *v;
            }
            if (auto v = (*relay)["name"].value<std::string>()) {
                config.builtin_relay.name = *v;
            }
            if (auto v = (*relay)["region"].value<std::string>()) {
                config.builtin_relay.region = *v;
            }
            if (auto v = (*relay)["priority"].value<int64_t>()) {
                config.builtin_relay.priority = static_cast<uint16_t>(*v);
            }
        }

        // [builtin_stun] section
        if (auto stun = tbl["builtin_stun"].as_table()) {
            if (auto v = (*stun)["enabled"].value<bool>()) {
                config.builtin_stun.enabled = *v;
            }
            // 支持 public_ip 和 ip 两种写法（优先 public_ip）
            if (auto v = (*stun)["public_ip"].value<std::string>()) {
                config.builtin_stun.public_ip = *v;
            } else if (auto v = (*stun)["ip"].value<std::string>()) {
                config.builtin_stun.public_ip = *v;
            }
            if (auto v = (*stun)["port"].value<int64_t>()) {
                config.builtin_stun.port = static_cast<uint16_t>(*v);
            }
        }

        return config;

    } catch (const toml::parse_error& e) {
        log().error("TOML parse error: {}", e.what());
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

std::expected<ClientConfig, ConfigError> ClientConfig::parse(const std::string& toml_content) {
    try {
        auto tbl = toml::parse(toml_content);
        ClientConfig config;

        // [controller] section
        if (auto controller = tbl["controller"].as_table()) {
            // 支持单个 host 或 hosts 数组
            if (auto hosts = (*controller)["hosts"].as_array()) {
                for (const auto& h : *hosts) {
                    if (auto v = h.value<std::string>()) {
                        config.controller_hosts.push_back(*v);
                    }
                }
            } else if (auto v = (*controller)["host"].value<std::string>()) {
                config.controller_hosts.push_back(*v);
            }
            // 兼容旧的 url 格式
            if (config.controller_hosts.empty()) {
                if (auto v = (*controller)["url"].value<std::string>()) {
                    // 从 URL 中提取 host:port
                    std::string url = *v;
                    // 移除 scheme
                    if (url.substr(0, 6) == "wss://") {
                        url = url.substr(6);
                        config.tls = true;
                    } else if (url.substr(0, 5) == "ws://") {
                        url = url.substr(5);
                    } else if (url.substr(0, 8) == "https://") {
                        url = url.substr(8);
                        config.tls = true;
                    } else if (url.substr(0, 7) == "http://") {
                        url = url.substr(7);
                    }
                    // 移除路径
                    auto path_pos = url.find('/');
                    if (path_pos != std::string::npos) {
                        url = url.substr(0, path_pos);
                    }
                    config.controller_hosts.push_back(url);
                }
            }
            if (auto v = (*controller)["authkey"].value<std::string>()) {
                config.authkey = *v;
            }
            if (auto v = (*controller)["tls"].value<bool>()) {
                config.tls = *v;
            }
            if (auto v = (*controller)["failover_timeout"].value<int64_t>()) {
                config.failover_timeout = std::chrono::milliseconds(*v);
            }
        }

        // [ssl] section
        if (auto ssl = tbl["ssl"].as_table()) {
            if (auto v = (*ssl)["verify"].value<bool>()) {
                config.ssl_verify = *v;
            }
            if (auto v = (*ssl)["ca_file"].value<std::string>()) {
                config.ssl_ca_file = *v;
            }
            if (auto v = (*ssl)["allow_self_signed"].value<bool>()) {
                config.ssl_allow_self_signed = *v;
            }
        }

        // [connection] section
        if (auto conn = tbl["connection"].as_table()) {
            if (auto v = (*conn)["auto_reconnect"].value<bool>()) {
                config.auto_reconnect = *v;
            }
            if (auto v = (*conn)["reconnect_interval"].value<int64_t>()) {
                config.reconnect_interval = std::chrono::seconds(*v);
            }
            if (auto v = (*conn)["ping_interval"].value<int64_t>()) {
                config.ping_interval = std::chrono::seconds(*v);
            }
            if (auto v = (*conn)["dns_refresh_interval"].value<int64_t>()) {
                config.dns_refresh_interval = std::chrono::seconds(*v);
            }
            if (auto v = (*conn)["latency_measure_interval"].value<int64_t>()) {
                config.latency_measure_interval = std::chrono::seconds(*v);
            }
            if (auto v = (*conn)["endpoint_connect_timeout"].value<int64_t>()) {
                config.endpoint_connect_timeout = std::chrono::seconds(*v);
            }
        }

        // [storage] section
        if (auto storage = tbl["storage"].as_table()) {
            if (auto v = (*storage)["state_dir"].value<std::string>()) {
                config.state_dir = *v;
            }
        }

        // [tun] section
        if (auto tun = tbl["tun"].as_table()) {
            if (auto v = (*tun)["enable"].value<bool>()) {
                config.enable_tun = *v;
            }
            if (auto v = (*tun)["name"].value<std::string>()) {
                config.tun_name = *v;
            }
            if (auto v = (*tun)["mtu"].value<int64_t>()) {
                config.tun_mtu = static_cast<uint32_t>(*v);
            }
        }

        // [routing] section
        if (auto routing = tbl["routing"].as_table()) {
            if (auto routes = (*routing)["advertise_routes"].as_array()) {
                for (const auto& r : *routes) {
                    if (auto v = r.value<std::string>()) {
                        config.advertise_routes.push_back(*v);
                    }
                }
            }
            if (auto v = (*routing)["exit_node"].value<bool>()) {
                config.exit_node = *v;
            }
            if (auto v = (*routing)["accept_routes"].value<bool>()) {
                config.accept_routes = *v;
            }
            if (auto v = (*routing)["announce_interval"].value<int64_t>()) {
                config.route_announce_interval = std::chrono::seconds(*v);
            }
        }

        // [log] section
        if (auto log = tbl["log"].as_table()) {
            if (auto v = (*log)["level"].value<std::string>()) {
                config.log_level = *v;
            }
            if (auto v = (*log)["file"].value<std::string>()) {
                config.log_file = *v;
            }
            // [log.modules] 模块级别日志配置
            if (auto modules = (*log)["modules"].as_table()) {
                for (const auto& [key, value] : *modules) {
                    if (auto v = value.value<std::string>()) {
                        config.module_log_levels[std::string(key)] = *v;
                    }
                }
            }
        }

        // [p2p] section
        if (auto p2p = tbl["p2p"].as_table()) {
            if (auto v = (*p2p)["enabled"].value<bool>()) {
                config.p2p.enabled = *v;
            }
            if (auto v = (*p2p)["bind_port"].value<int64_t>()) {
                config.p2p.bind_port = static_cast<uint16_t>(*v);
            }
            if (auto v = (*p2p)["keepalive_interval"].value<int64_t>()) {
                config.p2p.keepalive_interval = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["keepalive_timeout"].value<int64_t>()) {
                config.p2p.keepalive_timeout = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["punch_timeout"].value<int64_t>()) {
                config.p2p.punch_timeout = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["punch_batch_count"].value<int64_t>()) {
                config.p2p.punch_batch_count = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["punch_batch_size"].value<int64_t>()) {
                config.p2p.punch_batch_size = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["punch_batch_interval"].value<int64_t>()) {
                config.p2p.punch_batch_interval = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["retry_interval"].value<int64_t>()) {
                config.p2p.retry_interval = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["stun_timeout"].value<int64_t>()) {
                config.p2p.stun_timeout = static_cast<uint32_t>(*v);
            }
            if (auto v = (*p2p)["endpoint_refresh_interval"].value<int64_t>()) {
                config.p2p.endpoint_refresh_interval = static_cast<uint32_t>(*v);
            }
        }

        return config;

    } catch (const toml::parse_error& e) {
        log().error("TOML parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    }
}

} // namespace edgelink

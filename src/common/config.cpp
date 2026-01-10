#include "common/config.hpp"
#include <toml++/toml.hpp>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

namespace edgelink {

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

        return config;

    } catch (const toml::parse_error& e) {
        spdlog::error("TOML parse error: {}", e.what());
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
            if (auto v = (*controller)["url"].value<std::string>()) {
                config.controller_url = *v;
            }
            if (auto v = (*controller)["authkey"].value<std::string>()) {
                config.authkey = *v;
            }
            if (auto v = (*controller)["tls"].value<bool>()) {
                config.tls = *v;
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

        // [log] section
        if (auto log = tbl["log"].as_table()) {
            if (auto v = (*log)["level"].value<std::string>()) {
                config.log_level = *v;
            }
            if (auto v = (*log)["file"].value<std::string>()) {
                config.log_file = *v;
            }
        }

        return config;

    } catch (const toml::parse_error& e) {
        spdlog::error("TOML parse error: {}", e.what());
        return std::unexpected(ConfigError::PARSE_ERROR);
    }
}

} // namespace edgelink

#include "common/config.hpp"
#include <fstream>
#include <sstream>

namespace edgelink {

// ============================================================================
// Utility Functions
// ============================================================================

std::filesystem::path expand_path(const std::string& path) {
    if (path.empty()) return {};
    
    std::string result = path;
    if (result[0] == '~') {
        const char* home = std::getenv("HOME");
        if (home) {
            result = std::string(home) + result.substr(1);
        }
    }
    
    return std::filesystem::path(result);
}

bool ensure_parent_dir(const std::filesystem::path& path) {
    auto parent = path.parent_path();
    if (parent.empty()) return true;
    
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    return !ec;
}

// ============================================================================
// DatabaseConfig
// ============================================================================

std::string DatabaseConfig::connection_string() const {
    if (type == "sqlite") {
        return path;
    } else if (type == "mariadb" || type == "mysql") {
        std::ostringstream oss;
        oss << "mysql://" << user;
        if (!password.empty()) oss << ":" << password;
        oss << "@" << host << ":" << port << "/" << database;
        return oss.str();
    }
    return {};
}

// ============================================================================
// ControllerConfig
// ============================================================================

std::optional<ControllerConfig> ControllerConfig::load(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    try {
        auto json = boost::json::parse(buffer.str());
        return from_json(json);
    } catch (const std::exception& e) {
        // Log parsing error for debugging
        std::cerr << "Config parse error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool ControllerConfig::save(const std::filesystem::path& path) const {
    if (!ensure_parent_dir(path)) return false;
    
    std::ofstream file(path);
    if (!file) return false;
    
    file << boost::json::serialize(to_json());
    return true;
}

boost::json::object ControllerConfig::to_json() const {
    return {
        {"http", {
            {"address", http.listen_address},
            {"port", http.listen_port},
            {"enable_tls", http.enable_tls}
        }},
        {"tls", {
            {"cert", tls.cert_path},
            {"key", tls.key_path}
        }},
        {"database", {
            {"type", database.type},
            {"path", database.path}
        }},
        {"jwt", {
            {"secret", jwt.secret},
            {"algorithm", jwt.algorithm}
        }},
        {"tokens", {
            {"auth_expire_hours", jwt.auth_expire_hours},
            {"relay_expire_hours", jwt.relay_expire_hours}
        }},
        {"security", {
            {"node_key_rotate_hours", node_key_rotate_hours},
            {"require_authorization", require_authorization},
            {"server_token", server_token}
        }},
        {"builtin_relay", {
            {"enabled", builtin_relay.enabled}
        }},
        {"builtin_stun", {
            {"enabled", builtin_stun.enabled},
            {"listen", builtin_stun.listen},
            {"external_ip", builtin_stun.external_ip},
            {"secondary_ip", builtin_stun.secondary_ip}
        }}
    };
}

std::optional<ControllerConfig> ControllerConfig::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        ControllerConfig cfg;
        
        // Helper to get number as double (handles both int and double in JSON)
        auto get_double = [](const boost::json::value& val) -> double {
            if (val.is_int64()) return static_cast<double>(val.as_int64());
            if (val.is_uint64()) return static_cast<double>(val.as_uint64());
            return val.as_double();
        };
        
        // HTTP
        if (obj.contains("http")) {
            const auto& http = obj.at("http").as_object();
            if (http.contains("address")) cfg.http.listen_address = http.at("address").as_string().c_str();
            if (http.contains("port")) cfg.http.listen_port = static_cast<uint16_t>(http.at("port").as_int64());
            if (http.contains("enable_tls")) cfg.http.enable_tls = http.at("enable_tls").as_bool();
        }
        
        // TLS
        if (obj.contains("tls")) {
            const auto& tls = obj.at("tls").as_object();
            if (tls.contains("cert")) cfg.tls.cert_path = tls.at("cert").as_string().c_str();
            if (tls.contains("key")) cfg.tls.key_path = tls.at("key").as_string().c_str();
        }
        
        // Database
        if (obj.contains("database")) {
            const auto& db = obj.at("database").as_object();
            if (db.contains("type")) cfg.database.type = db.at("type").as_string().c_str();
            if (db.contains("path")) cfg.database.path = db.at("path").as_string().c_str();
        }
        
        // JWT
        if (obj.contains("jwt")) {
            const auto& jwt = obj.at("jwt").as_object();
            if (jwt.contains("secret")) cfg.jwt.secret = jwt.at("secret").as_string().c_str();
            if (jwt.contains("algorithm")) cfg.jwt.algorithm = jwt.at("algorithm").as_string().c_str();
        }
        
        // Tokens
        if (obj.contains("tokens")) {
            const auto& tokens = obj.at("tokens").as_object();
            if (tokens.contains("auth_expire_hours")) 
                cfg.jwt.auth_expire_hours = get_double(tokens.at("auth_expire_hours"));
            if (tokens.contains("relay_expire_hours")) 
                cfg.jwt.relay_expire_hours = get_double(tokens.at("relay_expire_hours"));
        }
        
        // Security
        if (obj.contains("security")) {
            const auto& sec = obj.at("security").as_object();
            if (sec.contains("node_key_rotate_hours")) 
                cfg.node_key_rotate_hours = get_double(sec.at("node_key_rotate_hours"));
            if (sec.contains("require_authorization")) 
                cfg.require_authorization = sec.at("require_authorization").as_bool();
            if (sec.contains("server_token"))
                cfg.server_token = sec.at("server_token").as_string().c_str();
        }
        
        // Builtin Relay
        if (obj.contains("builtin_relay")) {
            const auto& relay = obj.at("builtin_relay").as_object();
            if (relay.contains("enabled")) cfg.builtin_relay.enabled = relay.at("enabled").as_bool();
        }
        
        // Builtin STUN
        if (obj.contains("builtin_stun")) {
            const auto& stun = obj.at("builtin_stun").as_object();
            if (stun.contains("enabled")) cfg.builtin_stun.enabled = stun.at("enabled").as_bool();
            if (stun.contains("listen")) cfg.builtin_stun.listen = stun.at("listen").as_string().c_str();
            if (stun.contains("external_ip")) cfg.builtin_stun.external_ip = stun.at("external_ip").as_string().c_str();
            if (stun.contains("secondary_ip")) cfg.builtin_stun.secondary_ip = stun.at("secondary_ip").as_string().c_str();
        }
        
        return cfg;
    } catch (const std::exception& e) {
        std::cerr << "Config from_json error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// ============================================================================
// ServerConfig
// ============================================================================

std::optional<ServerConfig> ServerConfig::load(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    try {
        auto json = boost::json::parse(buffer.str());
        return from_json(json);
    } catch (const std::exception& e) {
        std::cerr << "ServerConfig parse error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool ServerConfig::save(const std::filesystem::path& path) const {
    if (!ensure_parent_dir(path)) return false;
    
    std::ofstream file(path);
    if (!file) return false;
    
    file << boost::json::serialize(to_json());
    return true;
}

boost::json::object ServerConfig::to_json() const {
    boost::json::array peers;
    for (const auto& p : mesh_peers) {
        peers.push_back(boost::json::value(p));
    }
    
    return {
        {"name", name},
        {"controller", {
            {"url", controller.url},
            {"token", controller.token}
        }},
        {"relay", {
            {"enabled", relay.enabled},
            {"listen_address", relay.listen_address},
            {"listen_port", relay.listen_port},
            {"external_url", relay.external_url},
            {"region", relay.region},
            {"tls", {
                {"enabled", relay.tls.enabled},
                {"cert_file", relay.tls.cert_file},
                {"key_file", relay.tls.key_file}
            }}
        }},
        {"stun", {
            {"enabled", stun.enabled},
            {"listen_address", stun.listen_address},
            {"listen_port", stun.listen_port},
            {"external_port", stun.external_port},
            {"external_ip", stun.external_ip},
            {"external_ip2", stun.external_ip2}
        }},
        {"mesh_peers", peers}
    };
}

std::optional<ServerConfig> ServerConfig::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        ServerConfig cfg;
        
        // Name
        if (obj.contains("name")) {
            cfg.name = obj.at("name").as_string().c_str();
        }
        
        // Controller
        if (obj.contains("controller")) {
            const auto& ctrl = obj.at("controller").as_object();
            if (ctrl.contains("url")) cfg.controller.url = ctrl.at("url").as_string().c_str();
            if (ctrl.contains("token")) cfg.controller.token = ctrl.at("token").as_string().c_str();
        }
        
        // Relay
        if (obj.contains("relay")) {
            const auto& relay = obj.at("relay").as_object();
            if (relay.contains("enabled")) cfg.relay.enabled = relay.at("enabled").as_bool();
            if (relay.contains("listen_address")) cfg.relay.listen_address = relay.at("listen_address").as_string().c_str();
            if (relay.contains("listen_port")) cfg.relay.listen_port = static_cast<uint16_t>(relay.at("listen_port").as_int64());
            if (relay.contains("external_url")) cfg.relay.external_url = relay.at("external_url").as_string().c_str();
            if (relay.contains("region")) cfg.relay.region = relay.at("region").as_string().c_str();
            
            if (relay.contains("tls")) {
                const auto& tls = relay.at("tls").as_object();
                if (tls.contains("enabled")) cfg.relay.tls.enabled = tls.at("enabled").as_bool();
                if (tls.contains("cert_file")) cfg.relay.tls.cert_file = tls.at("cert_file").as_string().c_str();
                if (tls.contains("key_file")) cfg.relay.tls.key_file = tls.at("key_file").as_string().c_str();
            }
        }
        
        // STUN
        if (obj.contains("stun")) {
            const auto& stun = obj.at("stun").as_object();
            if (stun.contains("enabled")) cfg.stun.enabled = stun.at("enabled").as_bool();
            if (stun.contains("listen_address")) cfg.stun.listen_address = stun.at("listen_address").as_string().c_str();
            if (stun.contains("listen_port")) cfg.stun.listen_port = static_cast<uint16_t>(stun.at("listen_port").as_int64());
            if (stun.contains("external_port")) cfg.stun.external_port = static_cast<uint16_t>(stun.at("external_port").as_int64());
            if (stun.contains("external_ip")) cfg.stun.external_ip = stun.at("external_ip").as_string().c_str();
            if (stun.contains("external_ip2")) cfg.stun.external_ip2 = stun.at("external_ip2").as_string().c_str();
        }
        
        // Mesh peers
        if (obj.contains("mesh_peers")) {
            for (const auto& p : obj.at("mesh_peers").as_array()) {
                cfg.mesh_peers.push_back(p.as_string().c_str());
            }
        }
        
        return cfg;
    } catch (const std::exception& e) {
        std::cerr << "ServerConfig from_json error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// ============================================================================
// ClientConfig
// ============================================================================

std::optional<ClientConfig> ClientConfig::load(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) {
        return std::nullopt;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    try {
        auto json = boost::json::parse(buffer.str());
        return from_json(json);
    } catch (const std::exception& e) {
        std::cerr << "ClientConfig parse error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool ClientConfig::save(const std::filesystem::path& path) const {
    if (!ensure_parent_dir(path)) return false;
    
    std::ofstream file(path);
    if (!file) return false;
    
    file << boost::json::serialize(to_json());
    return true;
}

boost::json::object ClientConfig::to_json() const {
    boost::json::array routes;
    for (const auto& r : advertise_routes) {
        routes.push_back({
            {"cidr", r.cidr},
            {"priority", r.priority},
            {"weight", r.weight}
        });
    }
    
    return {
        {"controller", controller_url},
        {"hostname", hostname},
        {"key_file", key_file},
        {"tun", {
            {"name", tun.name},
            {"mtu", tun.mtu}
        }},
        {"advertise_routes", routes},
        {"accept_routes", accept_routes},
        {"p2p", {
            {"enabled", p2p.enabled},
            {"keepalive_interval_seconds", p2p.keepalive_interval_sec}
        }},
        {"relay", {
            {"connect_all", relay.connect_all},
            {"latency_report_interval_seconds", relay.latency_report_interval_sec}
        }}
    };
}

std::optional<ClientConfig> ClientConfig::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        ClientConfig cfg;
        
        if (obj.contains("controller")) cfg.controller_url = obj.at("controller").as_string().c_str();
        if (obj.contains("hostname")) cfg.hostname = obj.at("hostname").as_string().c_str();
        if (obj.contains("key_file")) cfg.key_file = obj.at("key_file").as_string().c_str();
        
        // TUN
        if (obj.contains("tun")) {
            const auto& tun = obj.at("tun").as_object();
            if (tun.contains("name")) cfg.tun.name = tun.at("name").as_string().c_str();
            if (tun.contains("mtu")) cfg.tun.mtu = static_cast<uint16_t>(tun.at("mtu").as_int64());
        }
        
        // Routes
        if (obj.contains("advertise_routes")) {
            for (const auto& r : obj.at("advertise_routes").as_array()) {
                const auto& route = r.as_object();
                ClientConfig::RouteAd ra;
                ra.cidr = route.at("cidr").as_string().c_str();
                if (route.contains("priority")) ra.priority = static_cast<uint16_t>(route.at("priority").as_int64());
                if (route.contains("weight")) ra.weight = static_cast<uint16_t>(route.at("weight").as_int64());
                cfg.advertise_routes.push_back(ra);
            }
        }
        
        if (obj.contains("accept_routes")) cfg.accept_routes = obj.at("accept_routes").as_bool();
        
        // P2P
        if (obj.contains("p2p")) {
            const auto& p2p = obj.at("p2p").as_object();
            if (p2p.contains("enabled")) cfg.p2p.enabled = p2p.at("enabled").as_bool();
            if (p2p.contains("keepalive_interval_seconds")) 
                cfg.p2p.keepalive_interval_sec = static_cast<uint32_t>(p2p.at("keepalive_interval_seconds").as_int64());
        }
        
        // Relay
        if (obj.contains("relay")) {
            const auto& relay = obj.at("relay").as_object();
            if (relay.contains("connect_all")) cfg.relay.connect_all = relay.at("connect_all").as_bool();
            if (relay.contains("latency_report_interval_seconds"))
                cfg.relay.latency_report_interval_sec = static_cast<uint32_t>(relay.at("latency_report_interval_seconds").as_int64());
        }
        
        return cfg;
    } catch (const std::exception& e) {
        std::cerr << "ClientConfig from_json error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

// ============================================================================
// KeyStorage
// ============================================================================

std::optional<KeyStorage> KeyStorage::load(const std::filesystem::path& path) {
    std::ifstream file(expand_path(path.string()));
    if (!file) {
        return std::nullopt;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    try {
        auto json = boost::json::parse(buffer.str());
        const auto& obj = json.as_object();
        
        KeyStorage ks;
        ks.machine_key_pub = obj.at("machine_key_pub").as_string().c_str();
        ks.machine_key_sec = obj.at("machine_key_sec").as_string().c_str();
        ks.node_key_pub = obj.at("node_key_pub").as_string().c_str();
        ks.node_key_sec = obj.at("node_key_sec").as_string().c_str();
        ks.node_key_created_at = obj.at("node_key_created_at").as_int64();
        
        return ks;
    } catch (const std::exception& e) {
        std::cerr << "KeyStorage parse error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool KeyStorage::save(const std::filesystem::path& path) const {
    auto expanded = expand_path(path.string());
    if (!ensure_parent_dir(expanded)) return false;
    
    std::ofstream file(expanded);
    if (!file) return false;
    
    boost::json::object obj = {
        {"machine_key_pub", machine_key_pub},
        {"machine_key_sec", machine_key_sec},
        {"node_key_pub", node_key_pub},
        {"node_key_sec", node_key_sec},
        {"node_key_created_at", node_key_created_at}
    };
    
    file << boost::json::serialize(obj);
    return true;
}

} // namespace edgelink

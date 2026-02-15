#include "controller/server.hpp"
#include "controller/database.hpp"
#include "controller/jwt_util.hpp"
#include "controller/session_manager.hpp"
#include "controller/stun_server.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"
#include "common/logger.hpp"

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/cobalt.hpp>

#include "common/cobalt_utils.hpp"

#include <iostream>
#include <iomanip>
#include <thread>
#include <vector>
#include <random>
#include <chrono>

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;

using namespace edgelink;
using namespace edgelink::controller;

// Version information
constexpr const char* VERSION = "1.0.0";
constexpr const char* BUILD_DATE = __DATE__;

void setup_logging(const std::string& level, const std::string& log_file) {
    LogConfig config;
    config.global_level = log_level_from_string(level);
    config.console_enabled = true;
    config.console_color = true;

    if (!log_file.empty()) {
        config.file_enabled = true;
        config.file_path = log_file;
    }

    LogManager::instance().init(config);
}

void setup_quiet_logging() {
    LogConfig config;
    config.global_level = LogLevel::ERROR;
    config.console_enabled = true;
    config.console_color = true;
    LogManager::instance().init(config);
}

// Generate random authkey
std::string generate_authkey() {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    std::string key = "tskey-";
    for (int i = 0; i < 16; ++i) {
        key += charset[dis(gen)];
    }
    return key;
}

// Format timestamp
std::string format_time(uint64_t timestamp_ms) {
    if (timestamp_ms == 0) return "never";
    auto tp = std::chrono::system_clock::time_point(std::chrono::milliseconds(timestamp_ms));
    auto time = std::chrono::system_clock::to_time_t(tp);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

void print_usage() {
    std::cout << "EdgeLink Controller - Mesh VPN Control Plane\n\n"
              << "Usage:\n"
              << "  edgelink-controller <command> [options]\n\n"
              << "Commands:\n"
              << "  serve       Start the controller server (default)\n"
              << "  authkey     Manage authentication keys\n"
              << "  node        Manage nodes\n"
              << "  user        Manage users\n"
              << "  version     Show version information\n"
              << "  help        Show this help message\n\n"
              << "Run 'edgelink-controller <command> --help' for more information.\n";
}

void print_serve_help() {
    std::cout << "EdgeLink Controller - Start server\n\n"
              << "Usage: edgelink-controller serve [options]\n\n"
              << "Options:\n"
              << "  -c, --config FILE    Load configuration from TOML file\n"
              << "  -p, --port PORT      Listen port (default: 8080)\n"
              << "  -b, --bind ADDR      Bind address (default: 0.0.0.0)\n"
              << "  -t, --threads N      Number of IO threads (default: auto)\n"
              << "  --tls                Enable TLS\n"
              << "  --cert FILE          SSL certificate file\n"
              << "  --key FILE           SSL private key file\n"
              << "  --db FILE            Database file path (default: edgelink.db)\n"
              << "  -d, --debug          Enable debug logging\n"
              << "  -v, --verbose        Enable verbose logging\n"
              << "  -h, --help           Show this help\n";
}

void print_authkey_help() {
    std::cout << "EdgeLink Controller - AuthKey management\n\n"
              << "Usage: edgelink-controller authkey <action> [options]\n\n"
              << "Actions:\n"
              << "  create      Create a new authkey\n"
              << "  list        List all authkeys\n"
              << "  revoke      Revoke (delete) an authkey\n\n"
              << "Options:\n"
              << "  --db FILE            Database file (default: edgelink.db)\n"
              << "  --key KEY            AuthKey to revoke (for 'revoke' action)\n"
              << "  --max-uses N         Maximum uses (-1 = unlimited, default: -1)\n"
              << "  --expires HOURS      Expiration in hours (0 = never, default: 0)\n"
              << "  -h, --help           Show this help\n\n"
              << "Examples:\n"
              << "  edgelink-controller authkey create\n"
              << "  edgelink-controller authkey create --max-uses 1\n"
              << "  edgelink-controller authkey list\n"
              << "  edgelink-controller authkey revoke --key tskey-abc123\n";
}

void print_node_help() {
    std::cout << "EdgeLink Controller - Node management\n\n"
              << "Usage: edgelink-controller node <action> [options]\n\n"
              << "Actions:\n"
              << "  list        List all nodes\n"
              << "  delete      Delete a node\n\n"
              << "Options:\n"
              << "  --db FILE            Database file (default: edgelink.db)\n"
              << "  --id ID              Node ID to delete (for 'delete' action)\n"
              << "  -h, --help           Show this help\n\n"
              << "Examples:\n"
              << "  edgelink-controller node list\n"
              << "  edgelink-controller node delete --id 5\n";
}

void print_user_help() {
    std::cout << "EdgeLink Controller - User management\n\n"
              << "Usage: edgelink-controller user <action> [options]\n\n"
              << "Actions:\n"
              << "  list        List all users\n"
              << "  add         Add a new user\n"
              << "  delete      Delete a user\n\n"
              << "Options:\n"
              << "  --db FILE            Database file (default: edgelink.db)\n"
              << "  --username NAME      Username (for 'add' action)\n"
              << "  --password PASS      Password (for 'add' action)\n"
              << "  --role ROLE          Role: admin or user (default: user)\n"
              << "  --id ID              User ID to delete (for 'delete' action)\n"
              << "  -h, --help           Show this help\n\n"
              << "Examples:\n"
              << "  edgelink-controller user list\n"
              << "  edgelink-controller user add --username admin --password secret --role admin\n"
              << "  edgelink-controller user delete --id 2\n";
}

// ============================================================================
// Command: version
// ============================================================================

int cmd_version() {
    std::cout << "EdgeLink Controller " << VERSION << "\n"
              << "  Build:      " << BUILD_DATE << "\n"
              << "  Language:   C++23\n"
#ifdef _WIN32
              << "  Platform:   windows/"
#elif defined(__APPLE__)
              << "  Platform:   macos/"
#else
              << "  Platform:   linux/"
#endif
#if defined(__x86_64__) || defined(_M_X64)
              << "amd64\n";
#elif defined(__aarch64__) || defined(_M_ARM64)
              << "arm64\n";
#else
              << "unknown\n";
#endif
    return 0;
}

// ============================================================================
// Command: authkey
// ============================================================================

int cmd_authkey(int argc, char* argv[]) {
    std::string db_path = "edgelink.db";
    std::string action;
    std::string key_to_revoke;
    int32_t max_uses = -1;
    uint64_t expires_hours = 0;

    // Parse arguments
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_authkey_help();
            return 0;
        } else if (arg == "--db" && i + 1 < argc) {
            db_path = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            key_to_revoke = argv[++i];
        } else if (arg == "--max-uses" && i + 1 < argc) {
            max_uses = std::stoi(argv[++i]);
        } else if (arg == "--expires" && i + 1 < argc) {
            expires_hours = std::stoul(argv[++i]);
        } else if (action.empty() && arg[0] != '-') {
            action = arg;
        }
    }

    if (action.empty()) {
        print_authkey_help();
        return 1;
    }

    // Open database
    setup_quiet_logging();
    Database db;
    auto result = db.open(db_path);
    if (!result) {
        std::cerr << "Error: Failed to open database: " << db_path << "\n";
        return 1;
    }

    // Initialize schema if needed
    auto schema_result = db.init_schema();
    if (!schema_result) {
        std::cerr << "Error: Failed to initialize database schema\n";
        return 1;
    }

    if (action == "create") {
        // Get default network
        auto network = db.get_network_by_name("default");
        if (!network) {
            std::cerr << "Error: No default network found. Run 'serve' first to initialize.\n";
            return 1;
        }

        std::string new_key = generate_authkey();
        uint64_t expires_at = expires_hours > 0 ?
            Database::now_ms() + expires_hours * 3600 * 1000 : 0;

        auto authkey = db.create_authkey(new_key, network->id, max_uses, expires_at);
        if (!authkey) {
            std::cerr << "Error: Failed to create authkey\n";
            return 1;
        }

        std::cout << "Created authkey: " << new_key << "\n";
        if (max_uses > 0) {
            std::cout << "  Max uses: " << max_uses << "\n";
        }
        if (expires_hours > 0) {
            std::cout << "  Expires: " << format_time(expires_at) << "\n";
        }
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else if (action == "list") {
        auto keys = db.list_authkeys();
        if (!keys) {
            std::cerr << "Error: Failed to list authkeys\n";
            return 1;
        }

        if (keys->empty()) {
            std::cout << "No authkeys found.\n";
            db.close();
            LogManager::instance().shutdown();
            return 0;
        }

        std::cout << std::left
                  << std::setw(28) << "KEY"
                  << std::setw(10) << "USES"
                  << std::setw(12) << "MAX_USES"
                  << std::setw(20) << "CREATED"
                  << "EXPIRES\n";
        std::cout << std::string(80, '-') << "\n";

        for (const auto& k : *keys) {
            std::string max_str = k.max_uses < 0 ? "unlimited" : std::to_string(k.max_uses);
            std::string exp_str = k.expires_at == 0 ? "never" : format_time(k.expires_at);

            std::cout << std::left
                      << std::setw(28) << k.key
                      << std::setw(10) << k.use_count
                      << std::setw(12) << max_str
                      << std::setw(20) << format_time(k.created_at)
                      << exp_str << "\n";
        }
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else if (action == "revoke") {
        if (key_to_revoke.empty()) {
            std::cerr << "Error: --key is required for revoke action\n";
            return 1;
        }

        auto result = db.delete_authkey(key_to_revoke);
        if (!result) {
            std::cerr << "Error: Failed to revoke authkey (may not exist)\n";
            return 1;
        }

        std::cout << "Revoked authkey: " << key_to_revoke << "\n";
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else {
        std::cerr << "Unknown action: " << action << "\n";
        print_authkey_help();
        return 1;
    }
}

// ============================================================================
// Command: node
// ============================================================================

int cmd_node(int argc, char* argv[]) {
    std::string db_path = "edgelink.db";
    std::string action;
    NodeId node_id = 0;

    // Parse arguments
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_node_help();
            return 0;
        } else if (arg == "--db" && i + 1 < argc) {
            db_path = argv[++i];
        } else if (arg == "--id" && i + 1 < argc) {
            node_id = static_cast<NodeId>(std::stoul(argv[++i]));
        } else if (action.empty() && arg[0] != '-') {
            action = arg;
        }
    }

    if (action.empty()) {
        print_node_help();
        return 1;
    }

    // Open database
    setup_quiet_logging();
    Database db;
    auto result = db.open(db_path);
    if (!result) {
        std::cerr << "Error: Failed to open database: " << db_path << "\n";
        return 1;
    }

    if (action == "list") {
        auto nodes = db.list_all_nodes();
        if (!nodes) {
            std::cerr << "Error: Failed to list nodes\n";
            return 1;
        }

        if (nodes->empty()) {
            std::cout << "No nodes registered.\n";
            db.close();
            LogManager::instance().shutdown();
            return 0;
        }

        std::cout << std::left
                  << std::setw(6) << "ID"
                  << std::setw(16) << "VIRTUAL_IP"
                  << std::setw(20) << "HOSTNAME"
                  << std::setw(10) << "OS"
                  << std::setw(8) << "STATUS"
                  << "LAST_SEEN\n";
        std::cout << std::string(80, '-') << "\n";

        for (const auto& n : *nodes) {
            std::string status = n.online ? "online" : "offline";
            std::string last_seen = n.last_seen > 0 ? format_time(n.last_seen) : "never";

            std::cout << std::left
                      << std::setw(6) << n.id
                      << std::setw(16) << n.virtual_ip.to_string()
                      << std::setw(20) << n.hostname
                      << std::setw(10) << n.os
                      << std::setw(8) << status
                      << last_seen << "\n";
        }
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else if (action == "delete") {
        if (node_id == 0) {
            std::cerr << "Error: --id is required for delete action\n";
            return 1;
        }

        auto result = db.delete_node(node_id);
        if (!result) {
            std::cerr << "Error: Failed to delete node " << node_id << " (may not exist)\n";
            return 1;
        }

        std::cout << "Deleted node: " << node_id << "\n";
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else {
        std::cerr << "Unknown action: " << action << "\n";
        print_node_help();
        return 1;
    }
}

// ============================================================================
// Command: user
// ============================================================================

int cmd_user(int argc, char* argv[]) {
    std::string db_path = "edgelink.db";
    std::string action;
    std::string username;
    std::string password;
    std::string role = "user";
    uint32_t user_id = 0;

    // Parse arguments
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_user_help();
            return 0;
        } else if (arg == "--db" && i + 1 < argc) {
            db_path = argv[++i];
        } else if (arg == "--username" && i + 1 < argc) {
            username = argv[++i];
        } else if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "--role" && i + 1 < argc) {
            role = argv[++i];
        } else if (arg == "--id" && i + 1 < argc) {
            user_id = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (action.empty() && arg[0] != '-') {
            action = arg;
        }
    }

    if (action.empty()) {
        print_user_help();
        return 1;
    }

    // Open database
    setup_quiet_logging();
    Database db;
    auto result = db.open(db_path);
    if (!result) {
        std::cerr << "Error: Failed to open database: " << db_path << "\n";
        return 1;
    }

    if (action == "list") {
        auto users = db.list_users();
        if (!users) {
            std::cerr << "Error: Failed to list users\n";
            return 1;
        }

        if (users->empty()) {
            std::cout << "No users found.\n";
            db.close();
            LogManager::instance().shutdown();
            return 0;
        }

        std::cout << std::left
                  << std::setw(6) << "ID"
                  << std::setw(20) << "USERNAME"
                  << std::setw(10) << "ROLE"
                  << std::setw(10) << "ENABLED"
                  << std::setw(20) << "CREATED"
                  << "LAST_LOGIN\n";
        std::cout << std::string(76, '-') << "\n";

        for (const auto& u : *users) {
            std::string enabled = u.enabled ? "yes" : "no";
            std::string last_login = u.last_login > 0 ? format_time(u.last_login) : "never";

            std::cout << std::left
                      << std::setw(6) << u.id
                      << std::setw(20) << u.username
                      << std::setw(10) << u.role
                      << std::setw(10) << enabled
                      << std::setw(20) << format_time(u.created_at)
                      << last_login << "\n";
        }
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else if (action == "add") {
        if (username.empty()) {
            std::cerr << "Error: --username is required for add action\n";
            return 1;
        }
        if (password.empty()) {
            std::cerr << "Error: --password is required for add action\n";
            return 1;
        }
        if (role != "admin" && role != "user") {
            std::cerr << "Error: --role must be 'admin' or 'user'\n";
            return 1;
        }

        auto user = db.create_user(username, password, role);
        if (!user) {
            std::cerr << "Error: Failed to create user (may already exist)\n";
            return 1;
        }

        std::cout << "Created user: " << username << "\n";
        std::cout << "  ID:   " << user->id << "\n";
        std::cout << "  Role: " << role << "\n";
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else if (action == "delete") {
        if (user_id == 0) {
            std::cerr << "Error: --id is required for delete action\n";
            return 1;
        }

        auto result = db.delete_user(user_id);
        if (!result) {
            std::cerr << "Error: Failed to delete user " << user_id << " (may not exist)\n";
            return 1;
        }

        std::cout << "Deleted user: " << user_id << "\n";
        db.close();
        LogManager::instance().shutdown();
        return 0;

    } else {
        std::cerr << "Unknown action: " << action << "\n";
        print_user_help();
        return 1;
    }
}

// ============================================================================
// Command: serve
// ============================================================================

int cmd_serve(int argc, char* argv[]) {
    ControllerConfig cfg;
    std::string config_file;

    // First pass: look for config file
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    // Load config file if specified
    if (!config_file.empty()) {
        auto result = ControllerConfig::load(config_file);
        if (!result) {
            std::cerr << "Error: " << config_error_message(result.error())
                      << ": " << config_file << std::endl;
            return 1;
        }
        cfg = *result;
        std::cout << "Loaded configuration from: " << config_file << std::endl;
    }

    // Second pass: command line overrides
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            ++i; // Already handled
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            cfg.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-b" || arg == "--bind") && i + 1 < argc) {
            cfg.bind_address = argv[++i];
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            cfg.num_threads = static_cast<size_t>(std::stoi(argv[++i]));
        } else if (arg == "--tls") {
            cfg.tls = true;
        } else if (arg == "--cert" && i + 1 < argc) {
            cfg.cert_file = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            cfg.key_file = argv[++i];
        } else if (arg == "--db" && i + 1 < argc) {
            cfg.database_path = argv[++i];
        } else if (arg == "-d" || arg == "--debug") {
            cfg.log_level = "debug";
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.log_level = "trace";
        } else if (arg == "-h" || arg == "--help") {
            print_serve_help();
            return 0;
        }
    }

    // Setup logging
    setup_logging(cfg.log_level, cfg.log_file);

    Logger::get("controller").info("EdgeLink Controller {} starting...", VERSION);

    // Initialize crypto
    if (!crypto::init()) {
        Logger::get("controller").fatal("Failed to initialize crypto library");
        return 1;
    }

    // Use auto thread count if not specified
    if (cfg.num_threads == 0) {
        cfg.num_threads = std::thread::hardware_concurrency();
        if (cfg.num_threads == 0) cfg.num_threads = 4;
    }

    try {
        // Open database
        Database db;
        auto db_result = db.open(cfg.database_path);
        if (!db_result) {
            Logger::get("controller").fatal("Failed to open database: {}", db_error_message(db_result.error()));
            return 1;
        }

        // Initialize schema
        auto schema_result = db.init_schema();
        if (!schema_result) {
            Logger::get("controller").fatal("Failed to initialize database schema: {}",
                             db_error_message(schema_result.error()));
            return 1;
        }

        // Create JWT utility
        std::string jwt_secret = cfg.jwt_secret;
        if (jwt_secret.empty()) {
            auto secret_bytes = crypto::random_bytes(32);
            jwt_secret = std::string(secret_bytes.begin(), secret_bytes.end());
            Logger::get("controller").info("JWT secret auto-generated (not persistent)");
        } else {
            Logger::get("controller").info("JWT secret loaded from config");
        }
        JwtUtil jwt(jwt_secret);

        // Create IO context
        asio::io_context ioc(static_cast<int>(cfg.num_threads));

        // Create SSL context
        ssl::context ssl_ctx = [&cfg]() {
            if (!cfg.tls) {
                return ssl_util::create_dummy_context();
            } else if (!cfg.cert_file.empty() && !cfg.key_file.empty()) {
                Logger::get("controller").info("Loading SSL certificates from files");
                return ssl_util::create_ssl_context(cfg.cert_file, cfg.key_file);
            } else {
                Logger::get("controller").warn("Using self-signed certificate (development mode)");
                return ssl_util::create_self_signed_context();
            }
        }();

        // Create session manager
        SessionManager manager(ioc, db, jwt);

        // Set builtin relay/stun config
        manager.set_builtin_relay_config(cfg.builtin_relay);
        manager.set_builtin_stun_config(cfg.builtin_stun);

        // Create server config
        ServerConfig server_cfg;
        server_cfg.bind_address = cfg.bind_address;
        server_cfg.port = cfg.port;
        server_cfg.tls = cfg.tls;
        server_cfg.num_threads = cfg.num_threads;
        server_cfg.cert_file = cfg.cert_file;
        server_cfg.key_file = cfg.key_file;

        // Create server
        Server server(ioc, ssl_ctx, manager, server_cfg);

        // Setup signal handler
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            Logger::get("controller").info("Received signal {}, shutting down...", sig);
            server.stop();
            ioc.stop();
        });

        // Start server
        cobalt_utils::spawn_task(ioc.get_executor(), server.run());

        // Start STUN server (if enabled)
        std::unique_ptr<StunServer> stun_server;
        if (cfg.builtin_stun.enabled) {
            if (cfg.builtin_stun.public_ip.empty()) {
                Logger::get("controller").error("builtin_stun.enabled=true but builtin_stun.ip is empty");
                Logger::get("controller").warn("STUN server will NOT be started");
            } else {
                // STUN 服务器必须绑定 0.0.0.0 以接收公网请求，不受主服务器 bind 配置影响
                stun_server = std::make_unique<StunServer>(
                    ioc, "0.0.0.0", cfg.builtin_stun.port);
                stun_server->set_public_ip(cfg.builtin_stun.public_ip);
                cobalt_utils::spawn_task(ioc.get_executor(), stun_server->start());
            }
        }

        std::string scheme = cfg.tls ? "wss" : "ws";
        Logger::get("controller").info("Controller ready");
        Logger::get("controller").info("  Control endpoint: {}://{}:{}/api/v1/control", scheme, cfg.bind_address, cfg.port);
        Logger::get("controller").info("  Relay endpoint:   {}://{}:{}/api/v1/relay", scheme, cfg.bind_address, cfg.port);
        if (stun_server) {
            Logger::get("controller").info("  STUN endpoint:    udp://{}:{}", cfg.builtin_stun.public_ip, cfg.builtin_stun.port);
        }
        Logger::get("controller").info("  Database: {}", cfg.database_path);
        Logger::get("controller").info("  TLS: {}", cfg.tls ? "enabled" : "disabled");
        Logger::get("controller").info("  IO threads: {}", cfg.num_threads);
        Logger::get("controller").info("  Builtin Relay: {} (name={}, region={})",
            cfg.builtin_relay.enabled ? "enabled" : "disabled",
            cfg.builtin_relay.name, cfg.builtin_relay.region);

        // Run IO threads
        std::vector<std::thread> threads;
        threads.reserve(cfg.num_threads - 1);

        for (size_t i = 1; i < cfg.num_threads; ++i) {
            threads.emplace_back([&ioc] {
                ioc.run();
            });
        }

        // Run on main thread as well
        ioc.run();

        // Wait for all threads
        for (auto& t : threads) {
            t.join();
        }

        Logger::get("controller").info("Controller stopped");

        // Explicitly shutdown LogManager to avoid shutdown race with static destructors.
        // Without this, handlers may still be logging when LogManager::~LogManager()
        // is called during exit(), causing SEGV in spdlog::shutdown().
        LogManager::instance().shutdown();

    } catch (const std::exception& e) {
        Logger::get("controller").fatal("Fatal error: {}", e.what());
        LogManager::instance().shutdown();
        return 1;
    }

    return 0;
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char* argv[]) {
    // No arguments: show help
    if (argc < 2) {
        print_usage();
        return 0;
    }

    std::string command = argv[1];

    // Handle global help
    if (command == "-h" || command == "--help" || command == "help") {
        print_usage();
        return 0;
    }

    // Handle version
    if (command == "-V" || command == "--version" || command == "version") {
        return cmd_version();
    }

    // Handle 'serve' command
    if (command == "serve") {
        return cmd_serve(argc - 2, argv + 2);
    }

    // Handle 'authkey' command
    if (command == "authkey") {
        return cmd_authkey(argc - 2, argv + 2);
    }

    // Handle 'node' command
    if (command == "node") {
        return cmd_node(argc - 2, argv + 2);
    }

    // Handle 'user' command
    if (command == "user") {
        return cmd_user(argc - 2, argv + 2);
    }

    // Legacy mode: if first arg starts with '-', treat as 'serve' command
    if (command[0] == '-') {
        return cmd_serve(argc - 1, argv + 1);
    }

    // Unknown command
    std::cerr << "Unknown command: " << command << "\n\n";
    print_usage();
    return 1;
}

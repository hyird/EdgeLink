#include "common/config.hpp"
#include "common/log.hpp"
#include "controller/db/database.hpp"
#include "controller/api/grpc_server.hpp"
#include "controller/builtin_relay.hpp"
#include "controller/builtin_stun.hpp"
#include "controller/commands.hpp"
#include <absl/log/initialize.h>
#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <atomic>

#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <unistd.h>
#endif

using namespace edgelink;
using namespace edgelink::controller;

// Get platform-specific state file path
static std::string get_state_file_path() {
#ifdef _WIN32
    // Windows: use %TEMP% directory
    const char* temp = std::getenv("TEMP");
    if (!temp) temp = std::getenv("TMP");
    if (!temp) temp = "C:\\Windows\\Temp";
    return std::string(temp) + "\\edgelink-controller.state";
#else
    // Linux/macOS: use /tmp
    return "/tmp/edgelink-controller.state";
#endif
}

void print_usage(const char* prog) {
    std::cout << "EdgeLink Controller\n\n"
              << "Usage:\n"
              << "  " << prog << " -c <config.json>           Start controller service\n"
              << "  " << prog << " <command> [args...]        Run CLI command\n\n"
              << "Commands:\n"
              << "  network <action>      Manage networks (list|create|show|delete)\n"
              << "  node <action>         Manage nodes (list|show|authorize|deauthorize|rename|delete)\n"
              << "  server <action>       Manage servers (list|add|show|enable|disable|token|delete)\n"
              << "  route <action>        Manage routes (list|add|enable|disable|delete)\n"
              << "  authkey <action>      Manage auth keys (list|create|show|delete)\n"
              << "  token <action>        Token management (generate|blacklist)\n"
              << "  status                Show system status\n"
              << "  latency               Show latency matrix\n"
              << "  init                  Generate config file\n\n"
              << "Options:\n"
              << "  -c, --config <file>   Config file (starts server)\n"
              << "  -q, --quiet           Suppress log output\n"
              << "  -h, --help            Show help\n\n"
              << "Examples:\n"
              << "  " << prog << " -c /etc/edgelink/controller.json\n"
              << "  " << prog << " node list\n"
              << "  " << prog << " node list --online\n"
              << "  " << prog << " authkey create --network 1 --reusable\n"
              << "  " << prog << " init --output /etc/edgelink/controller.json\n\n"
              << "Note: CLI commands require a running controller instance.\n"
              << std::endl;
}

// Global shutdown flag for signal handling
static std::atomic<bool> g_shutdown_requested{false};
static controller::GrpcServer* g_grpc_server = nullptr;

static void signal_handler(int sig) {
    LOG_INFO("Received signal {}, shutting down...", sig);
    g_shutdown_requested = true;
    if (g_grpc_server) {
        g_grpc_server->stop();
    }
}

int run_server(const ControllerConfig& config, std::shared_ptr<Database> db) {
    // Write state file for CLI commands
    const std::string state_file = get_state_file_path();
    {
        std::ofstream f(state_file);
        if (f) {
            f << "{\n";
            f << "  \"pid\": " << getpid() << ",\n";
            f << "  \"database\": \"" << config.database.path << "\",\n";
            f << "  \"jwt_secret\": \"" << config.jwt.secret << "\",\n";
            f << "  \"grpc_port\": " << config.http.listen_port << "\n";
            f << "}\n";
            LOG_INFO("State file written: {}", state_file);
        }
    }

    // Cleanup state file on exit
    auto cleanup_state = [&state_file]() {
        std::remove(state_file.c_str());
    };

    // Create default network if none exists
    if (db->list_networks().empty()) {
        edgelink::controller::Network network;
        network.name = "default";
        network.subnet = "10.100.0.0/16";
        network.description = "Default EdgeLink network";
        uint32_t id = db->create_network(network);
        LOG_INFO("Created default network with ID {}", id);
    }

    // Create gRPC server
    controller::GrpcServer grpc_server(config, db);
    g_grpc_server = &grpc_server;

    // Create built-in Relay if enabled
    std::unique_ptr<BuiltinRelay> builtin_relay;
    if (config.builtin_relay.enabled) {
        builtin_relay = std::make_unique<BuiltinRelay>(config.builtin_relay, db, config.jwt.secret);
        grpc_server.set_builtin_relay(builtin_relay.get());

        LOG_INFO("Built-in Relay enabled via gRPC");
    }

    // Create built-in STUN if enabled
    boost::asio::io_context stun_ioc;
    std::unique_ptr<BuiltinSTUN> builtin_stun;
    std::thread stun_thread;
    if (config.builtin_stun.enabled) {
        builtin_stun = std::make_unique<BuiltinSTUN>(stun_ioc, config.builtin_stun);
        builtin_stun->start();
        // Run STUN io_context in separate thread
        stun_thread = std::thread([&stun_ioc]() {
            stun_ioc.run();
        });

        LOG_INFO("Built-in STUN enabled ({})", config.builtin_stun.listen);
    }

    // Register or update combined built-in server in database (if relay or stun is enabled)
    if (config.builtin_relay.enabled || config.builtin_stun.enabled) {
        // Check if already exists
        auto servers = db->list_servers();
        std::optional<Server> existing;
        for (const auto& s : servers) {
            if (s.name == "builtin" && s.type == "builtin") {
                existing = s;
                break;
            }
        }

        Server srv;
        if (existing) {
            srv = *existing;  // Start with existing record
        } else {
            srv.name = "builtin";
            srv.type = "builtin";
            srv.region = "local";
            srv.enabled = true;
        }

        // Always update relay URL from config (now using gRPC URL format)
        if (config.builtin_relay.enabled) {
            if (!config.builtin_relay.external_url.empty()) {
                // Use configured external URL (for reverse proxy scenarios)
                srv.url = config.builtin_relay.external_url;
            } else {
                // Default: use gRPC listen address
                std::string scheme = config.http.enable_tls ? "grpcs" : "grpc";
                srv.url = scheme + "://localhost:" + std::to_string(config.http.listen_port);
            }
        } else {
            srv.url.clear();
        }

        // Always update STUN info from config
        if (config.builtin_stun.enabled) {
            srv.stun_ip = config.builtin_stun.external_ip;
            srv.stun_ip2 = config.builtin_stun.secondary_ip;

            uint16_t stun_port = 3478;
            auto colon_pos = config.builtin_stun.listen.find(':');
            if (colon_pos != std::string::npos) {
                stun_port = static_cast<uint16_t>(std::stoul(config.builtin_stun.listen.substr(colon_pos + 1)));
            }
            srv.stun_port = stun_port;
        } else {
            srv.stun_ip.clear();
            srv.stun_ip2.clear();
            srv.stun_port = 0;
        }

        // Update capabilities
        std::string caps = "[";
        if (config.builtin_relay.enabled) caps += "\"relay\"";
        if (config.builtin_relay.enabled && config.builtin_stun.enabled) caps += ",";
        if (config.builtin_stun.enabled) caps += "\"stun\"";
        caps += "]";
        srv.capabilities = caps;

        if (existing) {
            // Update existing record
            db->update_server(srv);
            LOG_INFO("Updated built-in server (ID: {}, URL: {}, STUN: {}:{})",
                     srv.id, srv.url, srv.stun_ip, srv.stun_port);
        } else {
            // Create new record
            uint32_t id = db->create_server(srv);
            if (id > 0) {
                LOG_INFO("Registered built-in server (ID: {}, URL: {}, STUN: {}:{})",
                         id, srv.url, srv.stun_ip, srv.stun_port);
            }
        }
    }

    // Setup signal handling
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Start gRPC server (blocking call until shutdown)
    LOG_INFO("Controller starting gRPC server on port {}...", config.http.listen_port);
    grpc_server.start();

    // Cleanup
    if (builtin_stun) {
        builtin_stun->stop();
        stun_ioc.stop();
        if (stun_thread.joinable()) {
            stun_thread.join();
        }
    }

    LOG_INFO("Controller shutdown complete");
    cleanup_state();
    g_grpc_server = nullptr;
    return 0;
}

int main(int argc, char* argv[]) {
    absl::InitializeLog();

    std::string config_file;
    bool quiet = false;
    std::string command;
    std::vector<std::string> cmd_args;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) config_file = argv[++i];
        } else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] != '-') {
            // First non-option is the command
            if (command.empty()) {
                command = arg;
            }
            cmd_args.push_back(arg);
        } else {
            cmd_args.push_back(arg);
        }
    }
    
    // Initialize logging
    if (quiet) {
        log::set_level(spdlog::level::off);
    } else {
        log::init_from_env();
    }
    
    // If -c specified without command, start server
    if (!config_file.empty() && command.empty()) {
        std::filesystem::path config_path = config_file;
        auto config_opt = ControllerConfig::load(config_path);
        if (!config_opt) {
            std::cerr << "Error: Failed to load configuration from '" << config_file << "'\n";
            return 1;
        }
        
        auto config = *config_opt;
        LOG_INFO("Configuration loaded from: {}", config_file);
        LOG_INFO("gRPC listen: {}:{}", config.http.listen_address, config.http.listen_port);
        
        // Resolve relative database path
        if (!config.database.path.empty()) {
            std::filesystem::path db_path_fs = expand_path(config.database.path);
            if (db_path_fs.is_relative()) {
                auto config_dir = std::filesystem::absolute(config_path).parent_path();
                db_path_fs = config_dir / db_path_fs;
            }
            config.database.path = db_path_fs.string();
            LOG_INFO("Database path: {}", config.database.path);
        }
        
        // Initialize database
        auto db = std::make_shared<Database>(config.database);
        if (!db->initialize()) {
            std::cerr << "Error: Failed to initialize database: " << config.database.path << "\n";
            return 1;
        }
        
        LOG_INFO("EdgeLink Controller starting...");
        return run_server(config, db);
    }
    
    // Handle init command (doesn't need running instance)
    if (command == "init") {
        ControllerCLI cli(nullptr, "");
        return cli.run(cmd_args);
    }
    
    // No command and no config - show help
    if (command.empty()) {
        print_usage(argv[0]);
        return 1;
    }
    
    // CLI commands: read state file from running instance
    const std::string state_file = get_state_file_path();
    std::string db_path;
    std::string jwt_secret;
    
    {
        std::ifstream f(state_file);
        if (!f) {
            std::cerr << "Error: Controller is not running.\n";
            std::cerr << "Start the controller first: edgelink-controller -c <config.json>\n";
            return 1;
        }
        
        // Simple JSON parsing for state file
        std::string content((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
        
        // Extract database path
        auto db_pos = content.find("\"database\":");
        if (db_pos != std::string::npos) {
            auto start = content.find('"', db_pos + 11) + 1;
            auto end = content.find('"', start);
            db_path = content.substr(start, end - start);
        }
        
        // Extract JWT secret
        auto jwt_pos = content.find("\"jwt_secret\":");
        if (jwt_pos != std::string::npos) {
            auto start = content.find('"', jwt_pos + 13) + 1;
            auto end = content.find('"', start);
            jwt_secret = content.substr(start, end - start);
        }
    }
    
    if (db_path.empty()) {
        std::cerr << "Error: Invalid state file, cannot determine database path.\n";
        return 1;
    }
    
    // Initialize database
    DatabaseConfig db_config;
    db_config.path = db_path;
    auto db = std::make_shared<Database>(db_config);
    if (!db->initialize()) {
        std::cerr << "Error: Failed to open database: " << db_path << "\n";
        return 1;
    }
    
    // Run CLI command
    ControllerCLI cli(db, jwt_secret);
    return cli.run(cmd_args);
}

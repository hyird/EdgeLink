#include "common/config.hpp"
#include "common/log.hpp"
#include "controller/db/database.hpp"
#include "controller/api/http_server.hpp"
#include "controller/builtin_relay.hpp"
#include "controller/builtin_stun.hpp"
#include "controller/commands.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <filesystem>

using namespace edgelink;
using namespace edgelink::controller;

void print_usage(const char* prog) {
    std::cout << "EdgeLink Controller\n\n"
              << "Usage: " << prog << " [options] <command> [args...]\n\n"
              << "Commands:\n"
              << "  serve                 Start controller service (default)\n"
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
              << "  -c, --config <file>   Config file (default: controller.json)\n"
              << "  --db <path>           Database path (overrides config)\n"
              << "  -q, --quiet           Suppress log output\n"
              << "  -h, --help            Show help\n\n"
              << "Examples:\n"
              << "  " << prog << " serve -c controller.json\n"
              << "  " << prog << " authkey create --network 1 --reusable\n"
              << "  " << prog << " node list --online\n"
              << std::endl;
}

int run_server(const ControllerConfig& config, std::shared_ptr<Database> db) {
    // Create default network if none exists
    if (db->list_networks().empty()) {
        Network network;
        network.name = "default";
        network.subnet = "10.100.0.0/16";
        network.description = "Default EdgeLink network";
        uint32_t id = db->create_network(network);
        LOG_INFO("Created default network with ID {}", id);
    }
    
    // Register built-in services in database
    auto register_builtin_server = [&db](const std::string& name, const std::string& type,
                                          const std::string& url, const std::string& stun_ip,
                                          uint16_t stun_port) {
        // Check if already exists
        auto servers = db->list_servers();
        for (const auto& s : servers) {
            if (s.name == name && s.type == "builtin") {
                return; // Already registered
            }
        }
        
        Server srv;
        srv.name = name;
        srv.type = "builtin";
        srv.region = "local";
        srv.url = url;
        srv.stun_ip = stun_ip;
        srv.stun_port = stun_port;
        srv.enabled = true;
        
        uint32_t id = db->create_server(srv);
        if (id > 0) {
            LOG_INFO("Registered built-in server '{}' (ID: {})", name, id);
        }
    };
    
    // Setup I/O context
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    
    boost::asio::io_context ioc{static_cast<int>(num_threads)};
    
    // Create HTTP server
    HttpServer server(ioc, config, db);
    
    // Create built-in Relay if enabled
    std::unique_ptr<BuiltinRelay> builtin_relay;
    if (config.builtin_relay.enabled) {
        builtin_relay = std::make_unique<BuiltinRelay>(
            ioc, config.builtin_relay, db, config.jwt.secret);
        server.set_builtin_relay(builtin_relay.get());
        
        // Register in database
        std::string relay_url = "ws://localhost:" + std::to_string(config.http.listen_port) + 
                                config.builtin_relay.ws_data_path;
        register_builtin_server("builtin-relay", "builtin", relay_url, "", 0);
        
        LOG_INFO("Built-in Relay enabled (path: {})", config.builtin_relay.ws_data_path);
    }
    
    // Start HTTP server after relay is set
    server.start();
    
    // Create built-in STUN if enabled
    std::unique_ptr<BuiltinSTUN> builtin_stun;
    if (config.builtin_stun.enabled) {
        builtin_stun = std::make_unique<BuiltinSTUN>(ioc, config.builtin_stun);
        builtin_stun->start();
        
        // Register in database
        uint16_t stun_port = 3478;
        auto colon_pos = config.builtin_stun.listen.find(':');
        if (colon_pos != std::string::npos) {
            stun_port = static_cast<uint16_t>(std::stoul(config.builtin_stun.listen.substr(colon_pos + 1)));
        }
        register_builtin_server("builtin-stun", "builtin", "", 
                                config.builtin_stun.external_ip, stun_port);
        
        LOG_INFO("Built-in STUN enabled ({})", config.builtin_stun.listen);
    }
    
    // Setup signal handling
    boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](beast::error_code const&, int sig) {
        LOG_INFO("Received signal {}, shutting down...", sig);
        server.stop();
        if (builtin_stun) {
            builtin_stun->stop();
        }
        ioc.stop();
    });
    
    // Run I/O threads
    std::vector<std::thread> threads;
    threads.reserve(num_threads - 1);
    
    for (unsigned int i = 0; i < num_threads - 1; ++i) {
        threads.emplace_back([&ioc] {
            ioc.run();
        });
    }
    
    LOG_INFO("Controller running with {} threads", num_threads);
    ioc.run();
    
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    
    LOG_INFO("Controller shutdown complete");
    return 0;
}

int main(int argc, char* argv[]) {
    std::string config_file = "controller.json";
    std::string db_path;
    bool quiet = false;
    std::string command = "serve";
    std::vector<std::string> cmd_args;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) config_file = argv[++i];
        } else if (arg == "--db") {
            if (i + 1 < argc) db_path = argv[++i];
        } else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if (arg[0] != '-') {
            command = arg;
            for (int j = i; j < argc; ++j) {
                cmd_args.push_back(argv[j]);
            }
            break;
        }
    }
    
    // Initialize logging
    if (quiet) {
        log::set_level(spdlog::level::off);
    } else {
        log::init_from_env();
    }
    
    // Load configuration
    ControllerConfig config;
    std::filesystem::path config_path = std::filesystem::path(config_file);
    auto config_opt = ControllerConfig::load(config_path);
    if (config_opt) {
        config = *config_opt;
        if (!quiet) LOG_INFO("Configuration loaded from: {}", config_file);
        
        // Resolve relative database path relative to config file directory
        if (!config.database.path.empty()) {
            std::filesystem::path db_path_fs = expand_path(config.database.path);
            if (db_path_fs.is_relative()) {
                // Make database path relative to config file's directory
                auto config_dir = std::filesystem::absolute(config_path).parent_path();
                db_path_fs = config_dir / db_path_fs;
            }
            config.database.path = db_path_fs.string();
            if (!quiet) LOG_INFO("Database path resolved to: {}", config.database.path);
        }
    } else {
        config.http.listen_address = "0.0.0.0";
        config.http.listen_port = 8080;
        config.database.path = "edgelink.db";
        config.jwt.secret = "change-this-secret-in-production";
    }
    
    // Override database path if specified on command line (absolute or relative to cwd)
    if (!db_path.empty()) {
        config.database.path = db_path;
    }
    
    // Handle init command before database
    if (command == "init") {
        ControllerCLI cli(nullptr, "");
        return cli.run(cmd_args);
    }
    
    // Initialize database
    if (quiet) log::set_level(spdlog::level::off);
    auto db = std::make_shared<Database>(config.database);
    if (!db->initialize()) {
        std::cerr << "Error: Failed to initialize database\n";
        return 1;
    }
    
    // Route to command
    if (command == "serve") {
        if (!quiet) LOG_INFO("EdgeLink Controller starting...");
        return run_server(config, db);
    }
    
    // CLI commands
    ControllerCLI cli(db, config.jwt.secret);
    return cli.run(cmd_args);
}

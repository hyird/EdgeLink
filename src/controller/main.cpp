#include "controller/server.hpp"
#include "controller/database.hpp"
#include "controller/jwt_util.hpp"
#include "controller/session_manager.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

#include <iostream>
#include <thread>
#include <vector>

namespace asio = boost::asio;

using namespace edgelink;
using namespace edgelink::controller;

void setup_logging(const std::string& level, const std::string& log_file) {
    std::vector<spdlog::sink_ptr> sinks;

    // Console sink
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    sinks.push_back(console_sink);

    // File sink (if specified)
    if (!log_file.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, true);
        sinks.push_back(file_sink);
    }

    auto logger = std::make_shared<spdlog::logger>("console", sinks.begin(), sinks.end());
    spdlog::set_default_logger(logger);

    // Set log level
    if (level == "trace" || level == "verbose") {
        spdlog::set_level(spdlog::level::trace);
    } else if (level == "debug") {
        spdlog::set_level(spdlog::level::debug);
    } else if (level == "warn" || level == "warning") {
        spdlog::set_level(spdlog::level::warn);
    } else if (level == "error") {
        spdlog::set_level(spdlog::level::err);
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
}

void print_help() {
    std::cout << "EdgeLink Controller\n\n"
              << "Usage: edgelink-controller [options]\n\n"
              << "Options:\n"
              << "  -c, --config FILE    Load configuration from TOML file\n"
              << "  -p, --port PORT      Listen port (default: 8443)\n"
              << "  -b, --bind ADDR      Bind address (default: 0.0.0.0)\n"
              << "  -t, --threads N      Number of IO threads (default: auto)\n"
              << "  --cert FILE          SSL certificate file\n"
              << "  --key FILE           SSL private key file\n"
              << "  --db FILE            Database file path (default: edgelink.db)\n"
              << "  -d, --debug          Enable debug logging\n"
              << "  -v, --verbose        Enable verbose (trace) logging\n"
              << "  -h, --help           Show this help\n\n"
              << "Config file takes precedence, command line overrides config file.\n";
}

int main(int argc, char* argv[]) {
    // Default configuration
    ControllerConfig cfg;
    std::string config_file;

    // First pass: look for config file
    for (int i = 1; i < argc; ++i) {
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
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            ++i; // Already handled
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            cfg.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-b" || arg == "--bind") && i + 1 < argc) {
            cfg.bind_address = argv[++i];
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            cfg.num_threads = static_cast<size_t>(std::stoi(argv[++i]));
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
            print_help();
            return 0;
        }
    }

    // Setup logging
    setup_logging(cfg.log_level, cfg.log_file);

    spdlog::info("EdgeLink Controller starting...");

    // Initialize crypto
    if (!crypto::init()) {
        spdlog::critical("Failed to initialize crypto library");
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
            spdlog::critical("Failed to open database: {}", db_error_message(db_result.error()));
            return 1;
        }

        // Initialize schema
        auto schema_result = db.init_schema();
        if (!schema_result) {
            spdlog::critical("Failed to initialize database schema: {}",
                             db_error_message(schema_result.error()));
            return 1;
        }

        // Create JWT utility
        std::string jwt_secret = cfg.jwt_secret;
        if (jwt_secret.empty()) {
            // Generate random secret if not configured
            auto secret_bytes = crypto::random_bytes(32);
            jwt_secret = std::string(secret_bytes.begin(), secret_bytes.end());
            spdlog::info("JWT secret auto-generated (not persistent)");
        } else {
            spdlog::info("JWT secret loaded from config");
        }
        JwtUtil jwt(jwt_secret);

        // Create IO context
        asio::io_context ioc(static_cast<int>(cfg.num_threads));

        // Create SSL context
        ssl::context ssl_ctx = [&cfg]() {
            if (!cfg.cert_file.empty() && !cfg.key_file.empty()) {
                spdlog::info("Loading SSL certificates from files");
                return ssl_util::create_ssl_context(cfg.cert_file, cfg.key_file);
            } else {
                spdlog::warn("Using self-signed certificate (development mode)");
                return ssl_util::create_self_signed_context();
            }
        }();

        // Create session manager
        SessionManager manager(ioc, db, jwt);

        // Create server config
        ServerConfig server_cfg;
        server_cfg.bind_address = cfg.bind_address;
        server_cfg.port = cfg.port;
        server_cfg.num_threads = cfg.num_threads;
        server_cfg.cert_file = cfg.cert_file;
        server_cfg.key_file = cfg.key_file;

        // Create server
        Server server(ioc, ssl_ctx, manager, server_cfg);

        // Setup signal handler
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            spdlog::info("Received signal {}, shutting down...", sig);
            server.stop();
            ioc.stop();
        });

        // Start server
        asio::co_spawn(ioc, server.run(), asio::detached);

        spdlog::info("Controller ready");
        spdlog::info("  Control endpoint: wss://{}:{}/api/v1/control", cfg.bind_address, cfg.port);
        spdlog::info("  Relay endpoint:   wss://{}:{}/api/v1/relay", cfg.bind_address, cfg.port);
        spdlog::info("  Database: {}", cfg.database_path);
        spdlog::info("  IO threads: {}", cfg.num_threads);

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

        spdlog::info("Controller stopped");

    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}

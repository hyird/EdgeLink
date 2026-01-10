#include "controller/server.hpp"
#include "controller/database.hpp"
#include "controller/jwt_util.hpp"
#include "controller/session_manager.hpp"
#include "common/crypto.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

#include <iostream>
#include <thread>
#include <vector>

namespace asio = boost::asio;

using namespace edgelink;
using namespace edgelink::controller;

void setup_logging() {
    auto console = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(console);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
}

int main(int argc, char* argv[]) {
    setup_logging();

    spdlog::info("EdgeLink Controller starting...");

    // Initialize crypto
    if (!crypto::init()) {
        spdlog::critical("Failed to initialize crypto library");
        return 1;
    }

    // Server configuration
    ServerConfig config;
    config.bind_address = "0.0.0.0";
    config.port = 8443;
    config.num_threads = std::thread::hardware_concurrency();

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if ((arg == "-b" || arg == "--bind") && i + 1 < argc) {
            config.bind_address = argv[++i];
        } else if ((arg == "-t" || arg == "--threads") && i + 1 < argc) {
            config.num_threads = static_cast<size_t>(std::stoi(argv[++i]));
        } else if ((arg == "-c" || arg == "--cert") && i + 1 < argc) {
            config.cert_file = argv[++i];
        } else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            config.key_file = argv[++i];
        } else if (arg == "-d" || arg == "--debug") {
            spdlog::set_level(spdlog::level::debug);
        } else if (arg == "-v" || arg == "--verbose") {
            spdlog::set_level(spdlog::level::trace);
        } else if (arg == "-h" || arg == "--help") {
            std::cout << "EdgeLink Controller\n\n"
                      << "Usage: edgelink-controller [options]\n\n"
                      << "Options:\n"
                      << "  -p, --port PORT      Listen port (default: 8443)\n"
                      << "  -b, --bind ADDR      Bind address (default: 0.0.0.0)\n"
                      << "  -t, --threads N      Number of IO threads (default: auto)\n"
                      << "  -c, --cert FILE      SSL certificate file\n"
                      << "  -k, --key FILE       SSL private key file\n"
                      << "  -d, --debug          Enable debug logging\n"
                      << "  -v, --verbose        Enable verbose (trace) logging\n"
                      << "  -h, --help           Show this help\n";
            return 0;
        }
    }

    try {
        // Open database
        Database db;
        auto db_result = db.open("edgelink.db");
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

        // Create JWT utility with random secret
        // In production, load from config or environment
        auto secret_bytes = crypto::random_bytes(32);
        std::string jwt_secret(secret_bytes.begin(), secret_bytes.end());
        JwtUtil jwt(jwt_secret);
        spdlog::info("JWT secret generated");

        // Create IO context
        asio::io_context ioc(static_cast<int>(config.num_threads));

        // Create SSL context
        ssl::context ssl_ctx = [&config]() {
            if (!config.cert_file.empty() && !config.key_file.empty()) {
                spdlog::info("Loading SSL certificates from files");
                return ssl_util::create_ssl_context(config.cert_file, config.key_file);
            } else {
                spdlog::warn("Using self-signed certificate (development mode)");
                return ssl_util::create_self_signed_context();
            }
        }();

        // Create session manager
        SessionManager manager(ioc, db, jwt);

        // Create server
        Server server(ioc, ssl_ctx, manager, config);

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
        spdlog::info("  Control endpoint: wss://{}:{}/api/v1/control", config.bind_address, config.port);
        spdlog::info("  Relay endpoint:   wss://{}:{}/api/v1/relay", config.bind_address, config.port);
        spdlog::info("  IO threads: {}", config.num_threads);

        // Run IO threads
        std::vector<std::thread> threads;
        threads.reserve(config.num_threads - 1);

        for (size_t i = 1; i < config.num_threads; ++i) {
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

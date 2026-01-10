#include "client/client.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

namespace asio = boost::asio;

using namespace edgelink;
using namespace edgelink::client;

// Version information
constexpr const char* VERSION = "1.0.0";
constexpr const char* BUILD_DATE = __DATE__;

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

void print_usage() {
    std::cout << "EdgeLink Client - Mesh VPN Client\n\n"
              << "Usage:\n"
              << "  edgelink-client <command> [options]\n\n"
              << "Commands:\n"
              << "  up          Start client and connect to network\n"
              << "  version     Show version information\n"
              << "  help        Show this help message\n\n"
              << "Run 'edgelink-client <command> --help' for more information on a command.\n";
}

void print_up_help() {
    std::cout << "EdgeLink Client - Start and connect\n\n"
              << "Usage: edgelink-client up [options]\n\n"
              << "Connection Options:\n"
              << "  -c, --config FILE     Load configuration from TOML file\n"
              << "  --controller URL      Controller server address (default: ws://localhost:8080)\n"
              << "  -a, --authkey KEY     AuthKey for authentication (required for first connection)\n"
              << "  --tls                 Enable TLS (wss://)\n\n"
              << "TUN Options:\n"
              << "  --tun                 Enable TUN device for IP-level routing\n"
              << "  --tun-name NAME       TUN device name (default: auto)\n"
              << "  --tun-mtu MTU         TUN device MTU (default: 1420)\n\n"
              << "SSL Options:\n"
              << "  --ssl-verify          Enable SSL certificate verification\n"
              << "  --ssl-ca FILE         Custom CA certificate file\n"
              << "  --ssl-allow-self-signed  Allow self-signed certificates\n\n"
              << "Logging Options:\n"
              << "  -d, --debug           Enable debug logging\n"
              << "  -v, --verbose         Enable verbose (trace) logging\n\n"
              << "Other Options:\n"
              << "  -t, --test PEER MSG   Send test message to peer IP after connecting\n"
              << "  -h, --help            Show this help\n\n"
              << "Examples:\n"
              << "  edgelink-client up -a tskey-dev-test123 --tun\n"
              << "  edgelink-client up -c client.toml\n"
              << "  edgelink-client up -a tskey-dev-test123 --tls --ssl-allow-self-signed\n";
}

// ============================================================================
// Command: version
// ============================================================================

int cmd_version() {
    std::cout << "EdgeLink Client " << VERSION << "\n"
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
// Command: up
// ============================================================================

int cmd_up(int argc, char* argv[]) {
    // Default configuration
    edgelink::ClientConfig cfg;
    std::string config_file;
    std::string test_peer_ip;
    std::string test_message;

    // First pass: look for config file
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        }
    }

    // Load config file if specified
    if (!config_file.empty()) {
        auto result = edgelink::ClientConfig::load(config_file);
        if (!result) {
            std::cerr << "Error: " << config_error_message(result.error())
                      << ": " << config_file << std::endl;
            return 1;
        }
        cfg = *result;
        std::cout << "Loaded configuration from: " << config_file << std::endl;

        // Default state_dir to config file's directory if not specified
        if (cfg.state_dir.empty()) {
            auto config_path = std::filesystem::absolute(config_file);
            cfg.state_dir = config_path.parent_path().string();
        }
    } else {
        // No config file: default state_dir to current directory
        if (cfg.state_dir.empty()) {
            cfg.state_dir = ".";
        }
    }

    // Second pass: command line overrides
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            ++i; // Already handled
        } else if (arg == "--controller" && i + 1 < argc) {
            cfg.controller_url = argv[++i];
        } else if ((arg == "-a" || arg == "--authkey") && i + 1 < argc) {
            cfg.authkey = argv[++i];
        } else if ((arg == "-t" || arg == "--test") && i + 2 < argc) {
            test_peer_ip = argv[++i];
            test_message = argv[++i];
        } else if (arg == "--tls") {
            cfg.tls = true;
        } else if (arg == "--tun") {
            cfg.enable_tun = true;
        } else if (arg == "--tun-name" && i + 1 < argc) {
            cfg.tun_name = argv[++i];
        } else if (arg == "--tun-mtu" && i + 1 < argc) {
            cfg.tun_mtu = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "-d" || arg == "--debug") {
            cfg.log_level = "debug";
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.log_level = "trace";
        } else if (arg == "--ssl-verify") {
            cfg.ssl_verify = true;
        } else if (arg == "--ssl-ca" && i + 1 < argc) {
            cfg.ssl_ca_file = argv[++i];
        } else if (arg == "--ssl-allow-self-signed") {
            cfg.ssl_allow_self_signed = true;
        } else if (arg == "-h" || arg == "--help") {
            print_up_help();
            return 0;
        }
    }

    // Setup logging
    setup_logging(cfg.log_level, cfg.log_file);

    spdlog::info("EdgeLink Client {} starting...", VERSION);

    // Initialize crypto
    if (!crypto::init()) {
        spdlog::critical("Failed to initialize crypto library");
        return 1;
    }

    if (cfg.authkey.empty()) {
        spdlog::error("AuthKey required. Use -a or --authkey option, or specify in config file.");
        print_up_help();
        return 1;
    }

    try {
        asio::io_context ioc;

        // Create client config
        client::ClientConfig client_cfg;
        client_cfg.controller_url = cfg.controller_url;
        client_cfg.authkey = cfg.authkey;
        client_cfg.tls = cfg.tls;
        client_cfg.auto_reconnect = cfg.auto_reconnect;
        client_cfg.reconnect_interval = cfg.reconnect_interval;
        client_cfg.ping_interval = cfg.ping_interval;
        client_cfg.state_dir = cfg.state_dir;
        client_cfg.enable_tun = cfg.enable_tun;
        client_cfg.tun_name = cfg.tun_name;
        client_cfg.tun_mtu = cfg.tun_mtu;
        client_cfg.ssl_verify = cfg.ssl_verify;
        client_cfg.ssl_ca_file = cfg.ssl_ca_file;
        client_cfg.ssl_allow_self_signed = cfg.ssl_allow_self_signed;

        // Create client
        auto client = std::make_shared<Client>(ioc, client_cfg);

        // Setup callbacks
        ClientCallbacks callbacks;

        callbacks.on_connected = [&]() {
            spdlog::info("Client connected and ready");
            spdlog::info("  Virtual IP: {}", client->virtual_ip().to_string());
            spdlog::info("  Peers online: {}", client->peers().online_peer_count());

            // Send test message if requested
            if (!test_peer_ip.empty() && !test_message.empty()) {
                auto peer_ip = IPv4Address::from_string(test_peer_ip);
                std::vector<uint8_t> data(test_message.begin(), test_message.end());

                asio::co_spawn(ioc, [client, peer_ip, data]() -> asio::awaitable<void> {
                    // Wait a bit for peer session key to be derived
                    asio::steady_timer timer(co_await asio::this_coro::executor);
                    timer.expires_after(std::chrono::milliseconds(500));
                    co_await timer.async_wait(asio::use_awaitable);

                    bool sent = co_await client->send_to_ip(peer_ip, data);
                    if (sent) {
                        spdlog::info("Test message sent to {}", peer_ip.to_string());
                    } else {
                        spdlog::error("Failed to send test message");
                    }
                }, asio::detached);
            }
        };

        callbacks.on_disconnected = []() {
            spdlog::warn("Client disconnected");
        };

        callbacks.on_data_received = [&client](NodeId src, std::span<const uint8_t> data) {
            auto src_ip = client->peers().get_peer_ip_str(src);
            spdlog::info("Data from {}: {} bytes", src_ip, data.size());
        };

        callbacks.on_error = [](uint16_t code, const std::string& msg) {
            spdlog::error("Error {}: {}", code, msg);
        };

        client->set_callbacks(std::move(callbacks));

        // Setup signal handler
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            spdlog::info("Received signal {}, shutting down...", sig);
            asio::co_spawn(ioc, client->stop(), asio::detached);
            ioc.stop();
        });

        // Start client
        asio::co_spawn(ioc, [client]() -> asio::awaitable<void> {
            bool success = co_await client->start();
            if (!success) {
                spdlog::error("Failed to start client");
            }
        }, asio::detached);

        spdlog::info("Client running, press Ctrl+C to stop");
        spdlog::info("  Controller: {}", cfg.controller_url);
        if (cfg.enable_tun) {
            spdlog::info("  TUN mode: enabled (MTU={})", cfg.tun_mtu);
        }

        // Run IO context
        ioc.run();

        spdlog::info("Client stopped");

    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}

// ============================================================================
// Main entry point
// ============================================================================

int main(int argc, char* argv[]) {
    // No arguments: show usage
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

    // Handle 'up' command
    if (command == "up") {
        // Pass remaining arguments (skip program name and 'up')
        return cmd_up(argc - 2, argv + 2);
    }

    // Legacy mode: if first arg starts with '-', treat as 'up' command
    // This maintains backward compatibility with old usage
    if (command[0] == '-') {
        return cmd_up(argc - 1, argv + 1);
    }

    // Unknown command
    std::cerr << "Unknown command: " << command << "\n\n";
    print_usage();
    return 1;
}

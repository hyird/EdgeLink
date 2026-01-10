#include "client/client.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

#include <iostream>
#include <string>
#include <thread>

namespace asio = boost::asio;

using namespace edgelink;
using namespace edgelink::client;

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
    std::cout << "EdgeLink Client\n\n"
              << "Usage: edgelink-client [options]\n\n"
              << "Options:\n"
              << "  -c, --config FILE     Load configuration from TOML file\n"
              << "  --controller URL      Controller server address (default: localhost:8080)\n"
              << "  -a, --authkey KEY     AuthKey for authentication\n"
              << "  --tls                 Enable TLS (wss://), default: disabled\n"
              << "  --tun                 Enable TUN device for IP-level routing\n"
              << "  --tun-name NAME       TUN device name (default: auto)\n"
              << "  --tun-mtu MTU         TUN device MTU (default: 1420)\n"
              << "  -t, --test PEER MSG   Send test message to peer IP after connecting\n"
              << "  -d, --debug           Enable debug logging\n"
              << "  -v, --verbose         Enable verbose (trace) logging\n"
              << "  -h, --help            Show this help\n\n"
              << "Example:\n"
              << "  edgelink-client -a tskey-dev-test123 --tun\n"
              << "  edgelink-client -c client.toml\n"
              << "  edgelink-client -a tskey-dev-test123 -t 10.0.0.2 \"Hello\"\n";
}

int main(int argc, char* argv[]) {
    // Default configuration
    edgelink::ClientConfig cfg;
    std::string config_file;
    std::string test_peer_ip;
    std::string test_message;

    // First pass: look for config file
    for (int i = 1; i < argc; ++i) {
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
    }

    // Second pass: command line overrides
    for (int i = 1; i < argc; ++i) {
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
        } else if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        }
    }

    // Setup logging
    setup_logging(cfg.log_level, cfg.log_file);

    spdlog::info("EdgeLink Client starting...");

    // Initialize crypto
    if (!crypto::init()) {
        spdlog::critical("Failed to initialize crypto library");
        return 1;
    }

    if (cfg.authkey.empty()) {
        spdlog::error("AuthKey required. Use -a or --authkey option, or specify in config file.");
        print_help();
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

        callbacks.on_data_received = [](NodeId src, std::span<const uint8_t> data) {
            std::string msg(data.begin(), data.end());
            spdlog::info("Message from node {}: {}", src, msg);
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

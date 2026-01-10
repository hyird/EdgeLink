#include "client/client.hpp"
#include "common/crypto.hpp"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

#include <iostream>
#include <string>
#include <thread>

namespace asio = boost::asio;

using namespace edgelink;
using namespace edgelink::client;

void setup_logging() {
    auto console = spdlog::stdout_color_mt("console");
    spdlog::set_default_logger(console);
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
}

void print_help() {
    std::cout << "EdgeLink Client\n\n"
              << "Usage: edgelink-client [options]\n\n"
              << "Options:\n"
              << "  -c, --controller URL  Controller URL (default: wss://localhost:8443/api/v1/control)\n"
              << "  -a, --authkey KEY     AuthKey for authentication\n"
              << "  -t, --test PEER MSG   Send test message to peer IP after connecting\n"
              << "  -d, --debug           Enable debug logging\n"
              << "  -v, --verbose         Enable verbose (trace) logging\n"
              << "  -h, --help            Show this help\n\n"
              << "Example:\n"
              << "  edgelink-client -a tskey-dev-test123 -t 10.0.0.2 \"Hello\"\n";
}

int main(int argc, char* argv[]) {
    setup_logging();

    spdlog::info("EdgeLink Client starting...");

    // Initialize crypto
    if (!crypto::init()) {
        spdlog::critical("Failed to initialize crypto library");
        return 1;
    }

    // Parse arguments
    ClientConfig config;
    config.controller_url = "wss://localhost:8443/api/v1/control";

    std::string test_peer_ip;
    std::string test_message;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "-c" || arg == "--controller") && i + 1 < argc) {
            config.controller_url = argv[++i];
        } else if ((arg == "-a" || arg == "--authkey") && i + 1 < argc) {
            config.authkey = argv[++i];
        } else if ((arg == "-t" || arg == "--test") && i + 2 < argc) {
            test_peer_ip = argv[++i];
            test_message = argv[++i];
        } else if (arg == "-d" || arg == "--debug") {
            spdlog::set_level(spdlog::level::debug);
        } else if (arg == "-v" || arg == "--verbose") {
            spdlog::set_level(spdlog::level::trace);
        } else if (arg == "-h" || arg == "--help") {
            print_help();
            return 0;
        }
    }

    if (config.authkey.empty()) {
        spdlog::error("AuthKey required. Use -a or --authkey option.");
        print_help();
        return 1;
    }

    try {
        asio::io_context ioc;

        // Create client
        auto client = std::make_shared<Client>(ioc, config);

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
                    asio::steady_timer timer(client->crypto().node_id() ?
                        co_await asio::this_coro::executor : co_await asio::this_coro::executor);
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

        // Run IO context
        ioc.run();

        spdlog::info("Client stopped");

    } catch (const std::exception& e) {
        spdlog::critical("Fatal error: {}", e.what());
        return 1;
    }

    return 0;
}

#include "grpc_relay_server.hpp"
#include "stun_server.hpp"
#include "controller_client.hpp"
#include "common/config.hpp"
#include "common/log.hpp"
#include <absl/log/initialize.h>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/json.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <atomic>

using namespace edgelink;

namespace {

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n"
              << "Options:\n"
              << "  -c, --config <file>   Configuration file path (default: config/server.json)\n"
              << "  -h, --help            Show this help message\n"
              << std::endl;
}

std::optional<ServerConfig> load_config(const std::string& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open config file: {}", path);
            return std::nullopt;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());

        auto json = boost::json::parse(content);

        ServerConfig config;
        auto& obj = json.as_object();

        // Server name
        if (obj.contains("name")) {
            config.name = obj["name"].as_string().c_str();
        }

        // Controller settings
        if (obj.contains("controller")) {
            auto& ctrl = obj["controller"].as_object();
            if (ctrl.contains("url")) {
                config.controller.url = ctrl["url"].as_string().c_str();
            }
            if (ctrl.contains("token")) {
                config.controller.token = ctrl["token"].as_string().c_str();
            }
        }

        // Relay settings
        if (obj.contains("relay")) {
            auto& relay = obj["relay"].as_object();
            if (relay.contains("listen_address")) {
                config.relay.listen_address = relay["listen_address"].as_string().c_str();
            }
            if (relay.contains("listen_port")) {
                config.relay.listen_port = static_cast<uint16_t>(relay["listen_port"].as_int64());
            }
            if (relay.contains("external_url")) {
                config.relay.external_url = relay["external_url"].as_string().c_str();
            }
            if (relay.contains("region")) {
                config.relay.region = relay["region"].as_string().c_str();
            }

            // TLS settings
            if (relay.contains("tls")) {
                auto& tls = relay["tls"].as_object();
                if (tls.contains("enabled")) {
                    config.relay.tls.enabled = tls["enabled"].as_bool();
                }
                if (tls.contains("cert_file")) {
                    config.relay.tls.cert_file = tls["cert_file"].as_string().c_str();
                }
                if (tls.contains("key_file")) {
                    config.relay.tls.key_file = tls["key_file"].as_string().c_str();
                }
            }
        }

        // STUN settings
        if (obj.contains("stun")) {
            auto& stun = obj["stun"].as_object();
            if (stun.contains("enabled")) {
                config.stun.enabled = stun["enabled"].as_bool();
            }
            if (stun.contains("listen_address")) {
                config.stun.listen_address = stun["listen_address"].as_string().c_str();
            }
            if (stun.contains("listen_port")) {
                config.stun.listen_port = static_cast<uint16_t>(stun["listen_port"].as_int64());
            }
            if (stun.contains("external_port")) {
                config.stun.external_port = static_cast<uint16_t>(stun["external_port"].as_int64());
            }
            if (stun.contains("external_ip")) {
                config.stun.external_ip = stun["external_ip"].as_string().c_str();
            }
            if (stun.contains("external_ip2")) {
                config.stun.external_ip2 = stun["external_ip2"].as_string().c_str();
            }
        }

        // Mesh peers (legacy)
        if (obj.contains("mesh_peers")) {
            for (const auto& peer : obj["mesh_peers"].as_array()) {
                config.mesh_peers.push_back(peer.as_string().c_str());
            }
            // Copy to new location
            config.mesh.peers = config.mesh_peers;
        }

        // Mesh configuration (new)
        if (obj.contains("mesh")) {
            auto& mesh = obj["mesh"].as_object();
            if (mesh.contains("peers")) {
                config.mesh.peers.clear();
                for (const auto& peer : mesh["peers"].as_array()) {
                    config.mesh.peers.push_back(peer.as_string().c_str());
                }
            }
            if (mesh.contains("auto_connect")) {
                config.mesh.auto_connect = mesh["auto_connect"].as_bool();
            }
        }

        LOG_INFO("Configuration loaded from {}", path);
        return config;

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to parse config file: {}", e.what());
        return std::nullopt;
    }
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    absl::InitializeLog();

    // Parse command line arguments
    std::string config_path = "config/server.json";

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_path = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    // Initialize logging
    log::init_from_env();

    // Load configuration
    auto config_opt = load_config(config_path);
    if (!config_opt) {
        std::cerr << "Error: Failed to load configuration from '" << config_path << "'\n\n";
        std::cerr << "Create a config file or specify one with -c option.\n\n";
        print_usage(argv[0]);
        return 1;
    }

    LOG_INFO("EdgeLink Relay Server starting...");
    LOG_INFO("Version: 1.0.0, Protocol: {}", static_cast<int>(PROTOCOL_VERSION));
    LOG_INFO("Configuration loaded from: {}", config_path);

    ServerConfig config = std::move(*config_opt);

    // Validate required configuration
    if (config.controller.url.empty()) {
        LOG_ERROR("Controller URL is required");
        return 1;
    }
    if (config.controller.token.empty()) {
        LOG_ERROR("Controller token is required");
        return 1;
    }

    try {
        // Shutdown flag
        std::atomic<bool> shutdown_requested{false};

        // Create gRPC relay server
        GrpcRelayServer relay_server(config);

        // Create IO context for STUN (still uses boost::asio)
        boost::asio::io_context ioc;

        // Create STUN server (if enabled)
        std::unique_ptr<STUNServer> stun_server;
        if (config.stun.enabled) {
            stun_server = std::make_unique<STUNServer>(ioc, config);
        }

        // Create controller client
        auto controller_client = std::make_shared<ControllerClient>(relay_server, config);

        // Set controller client for control plane
        relay_server.set_controller_client(controller_client);

        // Set controller client callbacks
        controller_client->set_connect_callback([](bool success, const std::string& error) {
            if (success) {
                LOG_INFO("Connected to controller successfully");
            } else {
                LOG_ERROR("Failed to connect to controller: {}", error);
            }
        });

        controller_client->set_disconnect_callback([](const std::string& reason) {
            LOG_WARN("Disconnected from controller: {}", reason);
        });

        // Setup signal handling
        boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](boost::system::error_code ec, int signal_number) {
            if (!ec) {
                LOG_INFO("Received signal {}, shutting down...", signal_number);
                shutdown_requested = true;

                // Stop services
                relay_server.stop();
                if (stun_server) {
                    stun_server->stop();
                }
                controller_client->disconnect();

                ioc.stop();
            }
        });

        // Start services
        LOG_INFO("Starting relay server...");
        relay_server.start();

        if (stun_server) {
            LOG_INFO("Starting STUN server...");
            stun_server->start();
        }

        LOG_INFO("Connecting to controller...");
        controller_client->connect();

        // Run IO context for STUN and signal handling
        LOG_INFO("Server running");

        // Run IO context (blocks for signals and STUN)
        ioc.run();

        LOG_INFO("Server stopped");
        return 0;

    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: {}", e.what());
        return 1;
    }
}

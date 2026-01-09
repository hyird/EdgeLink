#include "ws_relay_server_coro.hpp"
#include "stun_server.hpp"
#include "controller_client.hpp"
#include "common/config.hpp"
#include "common/log.hpp"
#include "common/io_context_pool.hpp"

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
            if (stun.contains("ip")) {
                config.stun.ip = stun["ip"].as_string().c_str();
            }
            if (stun.contains("secondary_ip")) {
                config.stun.secondary_ip = stun["secondary_ip"].as_string().c_str();
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
    LOG_INFO("Version: 1.0.0, Protocol: {}", static_cast<int>(wire::PROTOCOL_VERSION));
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

        // Create IO context pool (thread-per-core model)
        unsigned int num_threads = std::max(1u, std::thread::hardware_concurrency());
        IOContextPool pool(num_threads);

        // Get a reference to the first io_context for control connections
        // (STUN server and controller client don't need thread distribution)
        auto& control_ioc = pool.get_io_context(0);

        // Create WebSocket relay server (coroutine-based)
        WsRelayServerCoro relay_server(pool, config);

        // Create STUN server (if enabled) - runs on control io_context
        std::unique_ptr<STUNServer> stun_server;
        if (config.stun.enabled) {
            stun_server = std::make_unique<STUNServer>(control_ioc, config);
        }

        // Create controller client (WebSocket) - runs on control io_context
        // Note: ControllerClient still uses the old callback-based WsClient
        // TODO: Migrate to WsClientCoro in a future phase
        auto controller_client = std::make_shared<ControllerClient>(control_ioc, relay_server, config);

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

        // Node location updates
        controller_client->set_node_loc_callback([&relay_server](
            const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations) {
            relay_server.update_node_locations(locations);
        });

        // Token blacklist updates
        controller_client->set_blacklist_callback([&relay_server](
            bool full_sync, const std::vector<std::pair<std::string, int64_t>>& entries) {
            if (full_sync) {
                // Clear existing blacklist for full sync
                // Note: This could be implemented if needed
            }
            for (const auto& [jti, expires_at] : entries) {
                relay_server.add_to_blacklist(jti, expires_at);
            }
        });

        // Setup signal handling on control io_context
        boost::asio::signal_set signals(control_ioc, SIGINT, SIGTERM);
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

                pool.stop();
            }
        });

        // Start services
        LOG_INFO("Starting relay server on {}:{}...",
                 config.relay.listen_address, config.relay.listen_port);
        relay_server.start();

        if (stun_server) {
            LOG_INFO("Starting STUN server on {}:{}...",
                     config.stun.listen_address, config.stun.listen_port);
            stun_server->start();
        }

        LOG_INFO("Connecting to controller at {}...", config.controller.url);
        controller_client->connect();

        // Run IO context pool (blocks until stopped)
        LOG_INFO("Server running with {} IO threads", num_threads);
        pool.run();

        LOG_INFO("Server stopped");
        return 0;

    } catch (const std::exception& e) {
        LOG_ERROR("Fatal error: {}", e.what());
        return 1;
    }
}

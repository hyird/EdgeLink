#include "client/client.hpp"
#include "client/ipc_server.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"
#include "common/logger.hpp"

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/json.hpp>

#include <filesystem>
#include <iostream>
#include <iomanip>
#include <string>
#include <thread>

namespace asio = boost::asio;

using namespace edgelink;
using namespace edgelink::client;

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

void print_usage() {
    std::cout << "EdgeLink Client - Mesh VPN Client\n\n"
              << "Usage:\n"
              << "  edgelink-client <command> [options]\n\n"
              << "Commands:\n"
              << "  up          Start client and connect to network\n"
              << "  down        Stop the running client daemon\n"
              << "  status      Show connection status\n"
              << "  peers       List all peer nodes\n"
              << "  ping        Ping a peer node\n"
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

void print_status_help() {
    std::cout << "EdgeLink Client - Show connection status\n\n"
              << "Usage: edgelink-client status [options]\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  -h, --help    Show this help\n\n"
              << "Note: This command requires the client daemon to be running.\n"
              << "      Currently shows simulated status for testing.\n";
}

void print_peers_help() {
    std::cout << "EdgeLink Client - List peer nodes\n\n"
              << "Usage: edgelink-client peers [options]\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  --online      Only show online peers\n"
              << "  -h, --help    Show this help\n\n"
              << "Note: This command requires the client daemon to be running.\n";
}

void print_down_help() {
    std::cout << "EdgeLink Client - Stop the daemon\n\n"
              << "Usage: edgelink-client down [options]\n\n"
              << "Options:\n"
              << "  -h, --help    Show this help\n\n"
              << "Sends a shutdown signal to the running client daemon.\n";
}

void print_ping_help() {
    std::cout << "EdgeLink Client - Ping a peer\n\n"
              << "Usage: edgelink-client ping <target> [options]\n\n"
              << "Arguments:\n"
              << "  target        Target peer's virtual IP (e.g., 100.64.0.2)\n\n"
              << "Options:\n"
              << "  -c, --count N   Number of pings to send (default: 4)\n"
              << "  -h, --help      Show this help\n\n"
              << "Note: This command requires the client daemon to be running.\n";
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
// Command: status
// ============================================================================

int cmd_status(int argc, char* argv[]) {
    bool json_output = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "-h" || arg == "--help") {
            print_status_help();
            return 0;
        }
    }

    // Connect to IPC server
    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\n"
                      << "  \"status\": \"not_connected\",\n"
                      << "  \"error\": \"Cannot connect to daemon - it may not be running\"\n"
                      << "}\n";
        } else {
            std::cout << "Status: Not Connected\n\n"
                      << "Cannot connect to the client daemon.\n"
                      << "Use 'edgelink-client up' to start the client.\n";
        }
        return 1;
    }

    std::string response = ipc.get_status();

    if (json_output) {
        std::cout << response << "\n";
    } else {
        // Parse and display human-readable output
        try {
            auto jv = boost::json::parse(response);
            auto& obj = jv.as_object();

            if (obj.at("status").as_string() == "ok") {
                auto& data = obj.at("data").as_object();
                std::cout << "Status: " << data.at("state").as_string() << "\n\n"
                          << "  Node ID:      " << data.at("node_id").as_string() << "\n"
                          << "  Virtual IP:   " << data.at("virtual_ip").as_string() << "\n"
                          << "  Network ID:   " << data.at("network_id").as_int64() << "\n"
                          << "  Peers:        " << data.at("peer_count").as_int64()
                          << " (" << data.at("online_peer_count").as_int64() << " online)\n"
                          << "  TUN enabled:  " << (data.at("tun_enabled").as_bool() ? "yes" : "no") << "\n";
            } else {
                std::cerr << "Error: " << obj.at("message").as_string() << "\n";
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing response: " << e.what() << "\n";
            return 1;
        }
    }

    return 0;
}

// ============================================================================
// Command: peers
// ============================================================================

int cmd_peers(int argc, char* argv[]) {
    bool json_output = false;
    bool online_only = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "--online") {
            online_only = true;
        } else if (arg == "-h" || arg == "--help") {
            print_peers_help();
            return 0;
        }
    }

    // Connect to IPC server
    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\n"
                      << "  \"peers\": [],\n"
                      << "  \"error\": \"Cannot connect to daemon - it may not be running\"\n"
                      << "}\n";
        } else {
            std::cout << "Peers: None\n\n"
                      << "Cannot connect to the client daemon.\n"
                      << "Use 'edgelink-client up' to start the client.\n";
        }
        return 1;
    }

    std::string response = ipc.get_peers(online_only);

    if (json_output) {
        std::cout << response << "\n";
    } else {
        // Parse and display human-readable output
        try {
            auto jv = boost::json::parse(response);
            auto& obj = jv.as_object();

            if (obj.at("status").as_string() == "ok") {
                auto& peers = obj.at("peers").as_array();

                if (peers.empty()) {
                    std::cout << "No peers found.\n";
                } else {
                    std::cout << std::left
                              << std::setw(16) << "VIRTUAL_IP"
                              << std::setw(20) << "NAME"
                              << std::setw(10) << "STATUS"
                              << std::setw(12) << "CONNECTION"
                              << "LATENCY\n";
                    std::cout << std::string(70, '-') << "\n";

                    for (const auto& p : peers) {
                        auto& peer = p.as_object();
                        std::string virtual_ip(peer.at("virtual_ip").as_string());
                        std::string name(peer.at("name").as_string());
                        std::string status = peer.at("online").as_bool() ? "online" : "offline";
                        std::string connection(peer.at("connection_status").as_string());
                        std::string latency = std::to_string(peer.at("latency_ms").as_int64()) + "ms";
                        if (peer.at("latency_ms").as_int64() == 0) {
                            latency = "-";
                        }

                        std::cout << std::left
                                  << std::setw(16) << virtual_ip
                                  << std::setw(20) << name
                                  << std::setw(10) << status
                                  << std::setw(12) << connection
                                  << latency << "\n";
                    }
                }
            } else {
                std::cerr << "Error: " << obj.at("message").as_string() << "\n";
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error parsing response: " << e.what() << "\n";
            return 1;
        }
    }

    return 0;
}

// ============================================================================
// Command: ping
// ============================================================================

int cmd_ping(int argc, char* argv[]) {
    std::string target;
    int count = 4;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_ping_help();
            return 0;
        } else if ((arg == "-c" || arg == "--count") && i + 1 < argc) {
            count = std::stoi(argv[++i]);
            if (count < 1) count = 1;
            if (count > 100) count = 100;
        } else if (target.empty() && arg[0] != '-') {
            target = arg;
        }
    }

    if (target.empty()) {
        std::cerr << "Error: Target IP is required\n\n";
        print_ping_help();
        return 1;
    }

    // Connect to IPC server
    IpcClient ipc;
    if (!ipc.connect()) {
        std::cerr << "Error: Cannot connect to client daemon. Is it running?\n";
        std::cerr << "       Start the daemon with: edgelink-client up\n";
        return 1;
    }

    std::cout << "PING " << target << "\n";

    int success_count = 0;
    uint64_t total_latency = 0;
    uint16_t min_latency = 65535;
    uint16_t max_latency = 0;

    for (int i = 0; i < count; ++i) {
        std::string response = ipc.ping_peer(target);

        try {
            auto jv = boost::json::parse(response);
            auto& obj = jv.as_object();

            if (obj.at("status").as_string() == "ok") {
                uint16_t latency = static_cast<uint16_t>(obj.at("latency_ms").as_int64());
                std::cout << "Reply from " << target << ": time=" << latency << "ms\n";
                success_count++;
                total_latency += latency;
                if (latency < min_latency) min_latency = latency;
                if (latency > max_latency) max_latency = latency;
            } else {
                std::string msg(obj.at("message").as_string());
                std::cout << "Request timed out: " << msg << "\n";
            }
        } catch (const std::exception& e) {
            std::cout << "Request failed: " << e.what() << "\n";
        }

        // Sleep between pings (except for the last one)
        if (i < count - 1) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    // Print statistics
    std::cout << "\n--- " << target << " ping statistics ---\n";
    std::cout << count << " packets transmitted, " << success_count << " received, "
              << ((count - success_count) * 100 / count) << "% packet loss\n";

    if (success_count > 0) {
        uint64_t avg_latency = total_latency / success_count;
        std::cout << "rtt min/avg/max = " << min_latency << "/" << avg_latency << "/" << max_latency << " ms\n";
    }

    return success_count > 0 ? 0 : 1;
}

// ============================================================================
// Command: down
// ============================================================================

int cmd_down(int argc, char* argv[]) {
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_down_help();
            return 0;
        }
    }

    // Connect to IPC server
    IpcClient ipc;
    if (!ipc.connect()) {
        std::cout << "Client daemon is not running.\n";
        return 0;
    }

    std::string response = ipc.request_shutdown();

    try {
        auto jv = boost::json::parse(response);
        auto& obj = jv.as_object();

        if (obj.at("status").as_string() == "ok") {
            std::cout << "Shutdown signal sent to client daemon.\n";
            return 0;
        } else {
            std::cerr << "Error: " << obj.at("message").as_string() << "\n";
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error parsing response: " << e.what() << "\n";
        return 1;
    }
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

    // Setup logging with new system
    setup_logging(cfg.log_level, cfg.log_file);

    auto& log = Logger::get("client");
    log.info("EdgeLink Client {} starting...", VERSION);

    // Initialize crypto
    if (!crypto::init()) {
        log.fatal("Failed to initialize crypto library");
        return 1;
    }

    if (cfg.authkey.empty()) {
        log.error("AuthKey required. Use -a or --authkey option, or specify in config file.");
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
            log.info("Client connected and ready");
            log.info("  Virtual IP: {}", client->virtual_ip().to_string());
            log.info("  Peers online: {}", client->peers().online_peer_count());

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
                    auto& log = Logger::get("client");
                    if (sent) {
                        log.info("Test message sent to {}", peer_ip.to_string());
                    } else {
                        log.error("Failed to send test message");
                    }
                }, asio::detached);
            }
        };

        callbacks.on_disconnected = []() {
            Logger::get("client").warn("Client disconnected");
        };

        callbacks.on_data_received = [&client](NodeId src, std::span<const uint8_t> data) {
            auto src_ip = client->peers().get_peer_ip_str(src);
            Logger::get("client").debug("Data from {}: {} bytes", src_ip, data.size());
        };

        callbacks.on_error = [](uint16_t code, const std::string& msg) {
            Logger::get("client").error("Error {}: {}", code, msg);
        };

        callbacks.on_shutdown_requested = [&ioc, &client, &log]() {
            log.info("Shutdown requested via IPC, stopping...");
            asio::co_spawn(ioc, client->stop(), asio::detached);
            ioc.stop();
        };

        client->set_callbacks(std::move(callbacks));

        // Setup signal handler
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            log.info("Received signal {}, shutting down...", sig);
            asio::co_spawn(ioc, client->stop(), asio::detached);
            ioc.stop();
        });

        // Start client
        asio::co_spawn(ioc, [client, &log]() -> asio::awaitable<void> {
            bool success = co_await client->start();
            if (!success) {
                log.error("Failed to start client");
            }
        }, asio::detached);

        log.info("Client running, press Ctrl+C to stop");
        log.info("  Controller: {}", cfg.controller_url);
        if (cfg.enable_tun) {
            log.info("  TUN mode: enabled (MTU={})", cfg.tun_mtu);
        }

        // Run IO context
        ioc.run();

        log.info("Client stopped");

    } catch (const std::exception& e) {
        log.fatal("Fatal error: {}", e.what());
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

    // Handle 'down' command
    if (command == "down") {
        return cmd_down(argc - 2, argv + 2);
    }

    // Handle 'status' command
    if (command == "status") {
        return cmd_status(argc - 2, argv + 2);
    }

    // Handle 'peers' command
    if (command == "peers") {
        return cmd_peers(argc - 2, argv + 2);
    }

    // Handle 'ping' command
    if (command == "ping") {
        return cmd_ping(argc - 2, argv + 2);
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

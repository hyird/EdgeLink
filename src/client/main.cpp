#include "client/client.hpp"
#include "client/ipc_server.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"
#include "common/logger.hpp"
#include "common/performance_monitor.hpp"

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

void setup_logging(const std::string& level, const std::string& log_file,
                   const std::unordered_map<std::string, std::string>& module_levels = {}) {
    LogConfig config;
    config.global_level = log_level_from_string(level);
    config.console_enabled = true;
    config.console_color = true;

    if (!log_file.empty()) {
        config.file_enabled = true;
        config.file_path = log_file;
    }

    // 模块级别日志配置
    for (const auto& [module, module_level] : module_levels) {
        config.module_levels[module] = log_level_from_string(module_level);
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
              << "  routes      List subnet routes\n"
              << "  ping        Ping a peer node\n"
              << "  config      View and modify configuration\n"
              << "  version     Show version information\n"
              << "  help        Show this help message\n\n"
              << "Run 'edgelink-client <command> --help' for more information on a command.\n";
}

void print_up_help() {
    std::cout << "EdgeLink Client - Start and connect\n\n"
              << "Usage: edgelink-client up [options]\n\n"
              << "Connection Options:\n"
              << "  -c, --config FILE     Load configuration from TOML file\n"
              << "  --controller HOST     Controller address (host:port, port default 443 with TLS, 80 without)\n"
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

void print_routes_help() {
    std::cout << "EdgeLink Client - List subnet routes\n\n"
              << "Usage: edgelink-client routes [options]\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  -h, --help    Show this help\n\n"
              << "Shows all subnet routes advertised by peers in the network.\n"
              << "Routes allow access to private networks through gateway nodes.\n";
}

void print_config_help() {
    std::cout << "EdgeLink Client - View and modify configuration\n\n"
              << "Usage: edgelink-client config <subcommand> [options]\n\n"
              << "Subcommands:\n"
              << "  get <key>           Get a configuration value\n"
              << "  set <key> <value>   Set a configuration value\n"
              << "  list                List all configuration items\n"
              << "  reload              Reload configuration from file\n"
              << "  show                Show current configuration (alias for list)\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  -h, --help    Show this help\n\n"
              << "Hot-reloadable configuration items can be changed without restarting.\n"
              << "Changes are automatically saved to the configuration file.\n\n"
              << "Examples:\n"
              << "  edgelink-client config get log.level\n"
              << "  edgelink-client config set log.level debug\n"
              << "  edgelink-client config list --json\n"
              << "  edgelink-client config reload\n";
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
                        auto& vip = peer.at("virtual_ip").as_string();
                        auto& nm = peer.at("name").as_string();
                        auto& conn = peer.at("connection_status").as_string();
                        std::string virtual_ip(vip.data(), vip.size());
                        std::string name(nm.data(), nm.size());
                        std::string status = peer.at("online").as_bool() ? "online" : "offline";
                        std::string connection(conn.data(), conn.size());
                        int64_t lat_ms = peer.at("latency_ms").as_int64();
                        std::string latency = lat_ms > 0 ? std::to_string(lat_ms) + "ms" : "-";

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
// Command: routes
// ============================================================================

int cmd_routes(int argc, char* argv[]) {
    bool json_output = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "-h" || arg == "--help") {
            print_routes_help();
            return 0;
        }
    }

    // Connect to IPC server
    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\n"
                      << "  \"routes\": [],\n"
                      << "  \"error\": \"Cannot connect to daemon - it may not be running\"\n"
                      << "}\n";
        } else {
            std::cout << "Routes: None\n\n"
                      << "Cannot connect to the client daemon.\n"
                      << "Use 'edgelink-client up' to start the client.\n";
        }
        return 1;
    }

    std::string response = ipc.get_routes();

    if (json_output) {
        std::cout << response << "\n";
    } else {
        // Parse and display human-readable output
        try {
            auto jv = boost::json::parse(response);
            auto& obj = jv.as_object();

            if (obj.at("status").as_string() == "ok") {
                auto& routes = obj.at("routes").as_array();

                if (routes.empty()) {
                    std::cout << "No routes found.\n";
                } else {
                    std::cout << std::left
                              << std::setw(20) << "PREFIX"
                              << std::setw(16) << "GATEWAY_IP"
                              << std::setw(20) << "GATEWAY_NAME"
                              << std::setw(8) << "METRIC"
                              << "TYPE\n";
                    std::cout << std::string(75, '-') << "\n";

                    for (const auto& r : routes) {
                        auto& route = r.as_object();
                        auto& pref = route.at("prefix").as_string();
                        auto& gip = route.at("gateway_ip").as_string();
                        auto& gname = route.at("gateway_name").as_string();
                        std::string prefix(pref.data(), pref.size());
                        std::string gateway_ip(gip.data(), gip.size());
                        std::string gateway_name(gname.data(), gname.size());
                        int64_t metric = route.at("metric").as_int64();
                        bool is_exit = route.at("exit_node").as_bool();
                        std::string type = is_exit ? "exit" : "subnet";

                        std::cout << std::left
                                  << std::setw(20) << prefix
                                  << std::setw(16) << gateway_ip
                                  << std::setw(20) << gateway_name
                                  << std::setw(8) << metric
                                  << type << "\n";
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
// Command: config
// ============================================================================

int cmd_config(int argc, char* argv[]) {
    bool json_output = false;

    if (argc == 0) {
        print_config_help();
        return 0;
    }

    std::string subcommand = argv[0];

    // 检查帮助选项
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_config_help();
            return 0;
        }
        if (arg == "--json") {
            json_output = true;
        }
    }

    // 连接到 IPC 服务器
    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\"status\":\"error\",\"message\":\"Cannot connect to daemon\"}\n";
        } else {
            std::cerr << "Cannot connect to the client daemon.\n"
                      << "Use 'edgelink-client up' to start the client.\n";
        }
        return 1;
    }

    if (subcommand == "get") {
        if (argc < 2) {
            std::cerr << "Error: config get requires a key\n";
            std::cerr << "Usage: edgelink-client config get <key>\n";
            return 1;
        }
        std::string key = argv[1];
        std::string response = ipc.config_get(key);

        if (json_output) {
            std::cout << response << "\n";
        } else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();

                if (obj.at("status").as_string() == "ok") {
                    auto& k = obj.at("key").as_string();
                    auto& v = obj.at("value").as_string();
                    auto& desc = obj.at("description").as_string();
                    bool hot = obj.at("hot_reloadable").as_bool();

                    std::cout << std::string(k.data(), k.size()) << " = "
                              << std::string(v.data(), v.size()) << "\n";
                    std::cout << "  " << std::string(desc.data(), desc.size());
                    if (hot) {
                        std::cout << " [hot-reloadable]";
                    }
                    std::cout << "\n";
                } else {
                    auto& msg = obj.at("message").as_string();
                    std::cerr << "Error: " << std::string(msg.data(), msg.size()) << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n";
                return 1;
            }
        }
    } else if (subcommand == "set") {
        if (argc < 3) {
            std::cerr << "Error: config set requires a key and value\n";
            std::cerr << "Usage: edgelink-client config set <key> <value>\n";
            return 1;
        }
        std::string key = argv[1];
        std::string value = argv[2];
        std::string response = ipc.config_set(key, value);

        if (json_output) {
            std::cout << response << "\n";
        } else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();

                if (obj.at("status").as_string() == "ok") {
                    auto& k = obj.at("key").as_string();
                    auto& nv = obj.at("new_value").as_string();
                    bool applied = obj.at("applied").as_bool();
                    bool restart = obj.at("restart_required").as_bool();

                    std::cout << std::string(k.data(), k.size()) << " = "
                              << std::string(nv.data(), nv.size()) << "\n";
                    if (applied) {
                        std::cout << "  Configuration applied successfully.\n";
                    }
                    if (restart) {
                        std::cout << "  Note: Restart required for this change to take effect.\n";
                    }
                } else {
                    auto& msg = obj.at("message").as_string();
                    std::cerr << "Error: " << std::string(msg.data(), msg.size()) << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n";
                return 1;
            }
        }
    } else if (subcommand == "list" || subcommand == "show") {
        std::string response = ipc.config_list();

        if (json_output) {
            std::cout << response << "\n";
        } else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();

                if (obj.at("status").as_string() == "ok") {
                    auto& config = obj.at("config").as_array();

                    // 按 section 分组显示
                    std::string current_section;

                    std::cout << std::left;
                    for (const auto& item : config) {
                        auto& it = item.as_object();
                        auto& k = it.at("key").as_string();
                        auto& v = it.at("value").as_string();
                        bool hot = it.at("hot_reloadable").as_bool();

                        std::string key(k.data(), k.size());
                        std::string value(v.data(), v.size());

                        // 提取 section
                        size_t dot_pos = key.find('.');
                        std::string section = dot_pos != std::string::npos ?
                            key.substr(0, dot_pos) : "";

                        if (section != current_section) {
                            if (!current_section.empty()) {
                                std::cout << "\n";
                            }
                            std::cout << "[" << section << "]\n";
                            current_section = section;
                        }

                        std::string key_part = dot_pos != std::string::npos ?
                            key.substr(dot_pos + 1) : key;

                        std::cout << "  " << std::setw(30) << key_part
                                  << " = " << std::setw(20) << value;
                        if (hot) {
                            std::cout << " [*]";
                        }
                        std::cout << "\n";
                    }

                    std::cout << "\n[*] = hot-reloadable\n";
                } else {
                    auto& msg = obj.at("message").as_string();
                    std::cerr << "Error: " << std::string(msg.data(), msg.size()) << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n";
                return 1;
            }
        }
    } else if (subcommand == "reload") {
        std::string response = ipc.config_reload();

        if (json_output) {
            std::cout << response << "\n";
        } else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();

                if (obj.at("status").as_string() == "ok") {
                    auto& changes = obj.at("changes").as_array();

                    if (changes.empty()) {
                        std::cout << "Configuration reloaded (no changes detected).\n";
                    } else {
                        std::cout << "Configuration reloaded. Changes:\n";
                        for (const auto& c : changes) {
                            auto& ch = c.as_object();
                            auto& k = ch.at("key").as_string();
                            auto& ov = ch.at("old_value").as_string();
                            auto& nv = ch.at("new_value").as_string();
                            bool applied = ch.at("applied").as_bool();

                            std::cout << "  " << std::string(k.data(), k.size())
                                      << ": " << std::string(ov.data(), ov.size())
                                      << " -> " << std::string(nv.data(), nv.size());
                            if (applied) {
                                std::cout << " (applied)";
                            } else {
                                std::cout << " (requires restart)";
                            }
                            std::cout << "\n";
                        }
                    }
                } else {
                    auto& msg = obj.at("message").as_string();
                    std::cerr << "Error: " << std::string(msg.data(), msg.size()) << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n";
                return 1;
            }
        }
    } else {
        std::cerr << "Unknown config subcommand: " << subcommand << "\n\n";
        print_config_help();
        return 1;
    }

    return 0;
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
            // 清空已有的 hosts，添加命令行指定的
            cfg.controller_hosts.clear();
            cfg.controller_hosts.push_back(argv[++i]);
        } else if ((arg == "-a" || arg == "--authkey") && i + 1 < argc) {
            cfg.authkey = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.num_threads = static_cast<size_t>(std::stoul(argv[++i]));
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
    setup_logging(cfg.log_level, cfg.log_file, cfg.module_log_levels);

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
        // 确定线程数配置（默认 1 = 单线程）
        size_t num_threads = 1;
        if (cfg.num_threads > 0) {
            num_threads = cfg.num_threads;
        }

        // 创建 io_context（多线程模式需要设置 concurrency_hint）
        asio::io_context ioc(static_cast<int>(num_threads));

        // 使用 work_guard 防止 io_context.run() 在没有挂起操作时提前返回
        // 这在容器环境中特别重要，因为某些协程可能异步完成
        auto work_guard = asio::make_work_guard(ioc);

        // Create client config
        client::ClientConfig client_cfg;
        client_cfg.controller_hosts = cfg.controller_hosts;
        client_cfg.authkey = cfg.authkey;
        client_cfg.tls = cfg.tls;
        client_cfg.failover_timeout = cfg.failover_timeout;
        client_cfg.auto_reconnect = cfg.auto_reconnect;
        client_cfg.reconnect_interval = cfg.reconnect_interval;
        client_cfg.ping_interval = cfg.ping_interval;
        client_cfg.dns_refresh_interval = cfg.dns_refresh_interval;
        client_cfg.latency_measure_interval = cfg.latency_measure_interval;
        client_cfg.state_dir = cfg.state_dir;
        client_cfg.enable_tun = cfg.enable_tun;
        client_cfg.tun_name = cfg.tun_name;
        client_cfg.tun_mtu = cfg.tun_mtu;
        client_cfg.ssl_verify = cfg.ssl_verify;
        client_cfg.ssl_ca_file = cfg.ssl_ca_file;
        client_cfg.ssl_allow_self_signed = cfg.ssl_allow_self_signed;
        client_cfg.advertise_routes = cfg.advertise_routes;
        client_cfg.exit_node = cfg.exit_node;
        client_cfg.accept_routes = cfg.accept_routes;
        client_cfg.route_announce_interval = cfg.route_announce_interval;

        // P2P 配置（使用统一的转换函数）
        client_cfg.p2p = edgelink::P2PConfig::from_seconds(
            cfg.p2p.enabled,
            cfg.p2p.bind_port,
            cfg.p2p.keepalive_interval,
            cfg.p2p.keepalive_timeout,
            cfg.p2p.punch_timeout,
            cfg.p2p.punch_batch_count,
            cfg.p2p.punch_batch_size,
            cfg.p2p.punch_batch_interval,
            cfg.p2p.retry_interval,
            cfg.p2p.stun_timeout,
            cfg.p2p.endpoint_refresh_interval
        );

        // Create client
        auto client = std::make_shared<Client>(ioc, client_cfg);

        // 创建 Client 事件 channels
        auto connected_ch = std::make_unique<client::channels::ClientConnectedChannel>(ioc, 4);
        auto disconnected_ch = std::make_unique<client::channels::ClientDisconnectedChannel>(ioc, 4);
        auto data_ch = std::make_unique<client::channels::ClientDataChannel>(ioc, 64);
        auto error_ch = std::make_unique<client::channels::ClientErrorChannel>(ioc, 8);
        auto shutdown_ch = std::make_unique<client::channels::ShutdownRequestChannel>(ioc, 4);

        // 获取原始指针用于 lambda 捕获
        auto* connected_ptr = connected_ch.get();
        auto* disconnected_ptr = disconnected_ch.get();
        auto* data_ptr = data_ch.get();
        auto* error_ptr = error_ch.get();
        auto* shutdown_ptr = shutdown_ch.get();

        // 设置 Client 事件 channels
        ClientEvents events;
        events.connected = connected_ptr;
        events.disconnected = disconnected_ptr;
        events.data_received = data_ptr;
        events.error = error_ptr;
        events.shutdown_requested = shutdown_ptr;
        client->set_events(events);

        // 启动事件处理协程: on_connected
        asio::co_spawn(ioc, [&ioc, &log, client, test_peer_ip, test_message,
                             connected_ptr]() -> asio::awaitable<void> {
            while (true) {
                auto [ec] = co_await connected_ptr->async_receive(asio::as_tuple(asio::use_awaitable));
                if (ec) break;

                log.info("Client connected and ready");
                log.info("  Virtual IP: {}", client->virtual_ip().to_string());
                log.info("  Peers online: {}", client->peers().online_peer_count());

                // Send test message if requested
                if (!test_peer_ip.empty() && !test_message.empty()) {
                    auto peer_ip = IPv4Address::from_string(test_peer_ip);
                    std::vector<uint8_t> data(test_message.begin(), test_message.end());

                    asio::co_spawn(ioc, [client, peer_ip, data]() -> asio::awaitable<void> {
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
            }
        }, asio::detached);

        // 启动事件处理协程: on_disconnected
        asio::co_spawn(ioc, [disconnected_ptr]() -> asio::awaitable<void> {
            while (true) {
                auto [ec] = co_await disconnected_ptr->async_receive(asio::as_tuple(asio::use_awaitable));
                if (ec) break;
                Logger::get("client").warn("Client disconnected");
            }
        }, asio::detached);

        // 启动事件处理协程: on_data_received
        asio::co_spawn(ioc, [client, data_ptr]() -> asio::awaitable<void> {
            while (true) {
                auto [ec, src, data] = co_await data_ptr->async_receive(asio::as_tuple(asio::use_awaitable));
                if (ec) break;
                auto src_ip = client->peers().get_peer_ip_str(src);
                Logger::get("client").debug("Data from {}: {} bytes", src_ip, data.size());
            }
        }, asio::detached);

        // 启动事件处理协程: on_error
        asio::co_spawn(ioc, [error_ptr]() -> asio::awaitable<void> {
            while (true) {
                auto [ec, code, msg] = co_await error_ptr->async_receive(asio::as_tuple(asio::use_awaitable));
                if (ec) break;
                Logger::get("client").error("Error {}: {}", code, msg);
            }
        }, asio::detached);

        // 启动事件处理协程: on_shutdown_requested
        asio::co_spawn(ioc, [&ioc, &log, client, &work_guard,
                             shutdown_ptr]() -> asio::awaitable<void> {
            while (true) {
                auto [ec] = co_await shutdown_ptr->async_receive(asio::as_tuple(asio::use_awaitable));
                if (ec) break;
                log.info("Shutdown requested via IPC, stopping...");
                work_guard.reset();
                asio::co_spawn(ioc, client->stop(), asio::detached);
            }
        }, asio::detached);

        // 启动性能监控输出协程（每60秒打印一次）
        asio::co_spawn(ioc, [&ioc, &log]() -> asio::awaitable<void> {
            asio::steady_timer timer(ioc);
            while (true) {
                timer.expires_after(std::chrono::seconds(60));
                co_await timer.async_wait(asio::use_awaitable);

                // 打印性能摘要
                auto summary = edgelink::perf::PerformanceMonitor::instance().get_summary();
                log.info("{}", summary);
            }
        }, asio::detached);

        // Enable config file watching if config file was specified
        if (!config_file.empty()) {
            auto abs_config_path = std::filesystem::absolute(config_file).string();
            client->set_config_path(abs_config_path);
            client->enable_config_watch();
            log.info("Config file watching enabled: {}", abs_config_path);
        }

        // Setup signal handler with timeout protection
        // 使用独立线程实现强制超时，不依赖 io_context
        std::atomic<bool> shutdown_requested{false};
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            if (shutdown_requested.exchange(true)) {
                log.warn("Received signal {} again, force stopping immediately", sig);
                ioc.stop();
                std::exit(1);
            }

            log.info("Received signal {}, shutting down gracefully...", sig);

            // Reset work guard to allow io_context to exit when done
            work_guard.reset();

            // Start graceful shutdown
            asio::co_spawn(ioc, client->stop(), asio::detached);

            // 启动独立线程实现强制超时（5 秒）
            // 不依赖 io_context，确保超时保护一定生效
            std::thread([&ioc, &log]() {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                log.warn("Graceful shutdown timeout (5s), forcing io_context stop");
                ioc.stop();  // 强制停止所有 io_context 操作
            }).detach();
        });

        // Start client
        asio::co_spawn(ioc, [client, &log]() -> asio::awaitable<void> {
            bool success = co_await client->start();
            if (!success) {
                log.error("Failed to start client");
            }
        }, asio::detached);

        log.info("Client running, press Ctrl+C to stop");
        if (!cfg.controller_hosts.empty()) {
            log.info("  Controllers: {}", cfg.controller_hosts.size());
            for (const auto& host : cfg.controller_hosts) {
                log.info("    - {}", host);
            }
        }
        if (cfg.enable_tun) {
            log.info("  TUN mode: enabled (MTU={})", cfg.tun_mtu);
        }
        log.info("  Thread mode: {} thread(s)", num_threads);

        // 多线程模式：启动工作线程池
        std::vector<std::thread> worker_threads;
        if (num_threads > 1) {
            log.info("Starting {} worker threads...", num_threads - 1);
            worker_threads.reserve(num_threads - 1);

            for (size_t i = 1; i < num_threads; ++i) {
                worker_threads.emplace_back([&ioc, i, &log] {
                    try {
                        log.debug("Worker thread {} started", i);
                        ioc.run();
                        log.debug("Worker thread {} stopped", i);
                    } catch (const std::exception& e) {
                        log.error("Worker thread {} exception: {}", i, e.what());
                    }
                });
            }
        }

        // 主线程也参与工作
        ioc.run();

        // 等待所有工作线程结束
        for (auto& t : worker_threads) {
            if (t.joinable()) {
                t.join();
            }
        }

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

    // Handle 'routes' command
    if (command == "routes") {
        return cmd_routes(argc - 2, argv + 2);
    }

    // Handle 'config' command
    if (command == "config") {
        return cmd_config(argc - 2, argv + 2);
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

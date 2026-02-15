#include "client/client.hpp"
#include "client/ipc_server.hpp"
#include "client/prefs_store.hpp"
#include "client/service_manager.hpp"
#include "client/version.hpp"
#include "common/crypto.hpp"
#include "common/config.hpp"
#include "common/logger.hpp"
#include "common/performance_monitor.hpp"

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/cobalt.hpp>
#include <boost/json.hpp>

#include "common/cobalt_utils.hpp"

#include <filesystem>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <thread>

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;

using namespace edgelink;
using namespace edgelink::client;

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
              << "  up          Configure and start the client (like tailscale up)\n"
              << "  down        Stop the running client daemon\n"
              << "  set         Modify runtime configuration (exit node, routes, etc.)\n"
              << "  status      Show connection status\n"
              << "  peers       List all peer nodes\n"
              << "  routes      List subnet routes\n"
              << "  ping        Ping a peer node\n"
              << "  config      View and modify configuration\n"
              << "  daemon      Run daemon in foreground (for systemd/launchd)\n"
              << "  version     Show version information\n"
              << "  help        Show this help message\n\n"
              << "Run 'edgelink-client <command> --help' for more information on a command.\n";
}

void print_up_help() {
    std::cout << "EdgeLink Client - Configure and start (like tailscale up)\n\n"
              << "Usage: edgelink-client up [options]\n\n"
              << "Connection Options:\n"
              << "  --controller HOST     Controller address (default: edge.a-z.xin)\n"
              << "  -a, --authkey KEY     AuthKey for authentication (required)\n"
              << "  --tls                 Enable TLS (default: enabled)\n"
              << "  --no-tls              Disable TLS\n\n"
              << "Routing Options:\n"
              << "  --exit-node=PEER           Use PEER as exit node (name or IP)\n"
              << "  --exit-node=               Clear exit node setting\n"
              << "  --advertise-exit-node      Declare this node as an exit node\n"
              << "  --no-advertise-exit-node   Stop advertising as exit node\n"
              << "  --advertise-routes=ROUTES  Advertise comma-separated CIDR routes\n"
              << "  --accept-routes            Accept routes from other nodes\n"
              << "  --no-accept-routes         Do not accept routes from other nodes\n\n"
              << "Service Options:\n"
              << "  --install-service     Install as system service only (don't start)\n"
              << "  --uninstall-service   Uninstall system service and exit\n"
              << "  --reset               Reset all prefs to defaults\n\n"
              << "Other Options:\n"
              << "  -h, --help            Show this help\n\n"
              << "The 'up' command saves configuration to prefs.toml and starts the daemon\n"
              << "as a system service. If already running, it updates the configuration.\n\n"
              << "Examples:\n"
              << "  edgelink-client up --authkey tskey-xxx           # Minimal start\n"
              << "  edgelink-client up --authkey tskey-xxx --no-tls  # Disable TLS\n"
              << "  edgelink-client up --exit-node=gateway           # Use exit node\n"
              << "  edgelink-client up --advertise-routes=192.168.1.0/24\n";
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

void print_set_help() {
    std::cout << "EdgeLink Client - Set runtime configuration\n\n"
              << "Usage: edgelink-client set [options]\n\n"
              << "Options:\n"
              << "  --exit-node=PEER           Use PEER as exit node (name or IP)\n"
              << "  --exit-node=               Clear exit node setting\n"
              << "  --advertise-exit-node      Declare this node as an exit node\n"
              << "  --no-advertise-exit-node   Stop advertising as exit node\n"
              << "  --advertise-routes=ROUTES  Advertise comma-separated CIDR routes\n"
              << "  --accept-routes            Accept routes from other nodes\n"
              << "  --no-accept-routes         Do not accept routes from other nodes\n"
              << "  -h, --help                 Show this help\n\n"
              << "Configuration is saved to prefs.toml and applied immediately if the\n"
              << "client daemon is running.\n\n"
              << "Examples:\n"
              << "  edgelink-client set --exit-node=gateway\n"
              << "  edgelink-client set --advertise-routes=192.168.1.0/24,10.0.0.0/8\n"
              << "  edgelink-client set --advertise-exit-node\n"
              << "  edgelink-client set --exit-node= --accept-routes\n";
}

// ============================================================================
// Command: version
// ============================================================================

int cmd_version() {
    std::cout << "EdgeLink Client " << version::VERSION << "\n"
              << "  Build ID:   " << version::BUILD_ID << "\n"
              << "  Commit:     " << version::GIT_COMMIT << " (" << version::GIT_BRANCH << ")\n"
              << "  Built:      " << version::BUILD_TIMESTAMP << "\n"
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
// Command: set
// ============================================================================

// Helper function to split string by delimiter
std::vector<std::string> split_string(const std::string& str, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    while (std::getline(ss, item, delim)) {
        // Trim whitespace
        size_t start = item.find_first_not_of(" \t");
        size_t end = item.find_last_not_of(" \t");
        if (start != std::string::npos) {
            result.push_back(item.substr(start, end - start + 1));
        }
    }
    return result;
}

// Helper function to check if string starts with prefix
bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
}

int cmd_set(int argc, char* argv[]) {
    // Parse arguments
    std::optional<std::string> exit_node;
    std::optional<bool> advertise_exit_node;
    std::optional<std::vector<std::string>> advertise_routes;
    std::optional<bool> accept_routes;
    bool has_changes = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_set_help();
            return 0;
        } else if (starts_with(arg, "--exit-node=")) {
            exit_node = arg.substr(12);  // Length of "--exit-node="
            has_changes = true;
        } else if (arg == "--advertise-exit-node") {
            advertise_exit_node = true;
            has_changes = true;
        } else if (arg == "--no-advertise-exit-node") {
            advertise_exit_node = false;
            has_changes = true;
        } else if (starts_with(arg, "--advertise-routes=")) {
            std::string routes_str = arg.substr(19);  // Length of "--advertise-routes="
            advertise_routes = split_string(routes_str, ',');
            has_changes = true;
        } else if (arg == "--accept-routes") {
            accept_routes = true;
            has_changes = true;
        } else if (arg == "--no-accept-routes") {
            accept_routes = false;
            has_changes = true;
        } else {
            std::cerr << "Unknown option: " << arg << "\n\n";
            print_set_help();
            return 1;
        }
    }

    if (!has_changes) {
        std::cerr << "No configuration changes specified.\n\n";
        print_set_help();
        return 1;
    }

    // 1. Load and update prefs.toml
    auto state_dir = client::get_state_dir();
    client::PrefsStore prefs(state_dir);
    prefs.load();

    if (exit_node) {
        if (exit_node->empty()) {
            prefs.clear_exit_node();
            std::cout << "Cleared exit node setting.\n";
        } else {
            prefs.set_exit_node(*exit_node);
            std::cout << "Set exit node: " << *exit_node << "\n";
        }
    }

    if (advertise_exit_node) {
        prefs.set_advertise_exit_node(*advertise_exit_node);
        std::cout << "Advertise exit node: " << (*advertise_exit_node ? "enabled" : "disabled") << "\n";
    }

    if (advertise_routes) {
        prefs.set_advertise_routes(*advertise_routes);
        if (advertise_routes->empty()) {
            std::cout << "Cleared advertised routes.\n";
        } else {
            std::cout << "Set advertised routes: ";
            for (size_t i = 0; i < advertise_routes->size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << (*advertise_routes)[i];
            }
            std::cout << "\n";
        }
    }

    if (accept_routes) {
        prefs.set_accept_routes(*accept_routes);
        std::cout << "Accept routes: " << (*accept_routes ? "enabled" : "disabled") << "\n";
    }

    // Save prefs
    if (!prefs.save()) {
        std::cerr << "Error: Failed to save prefs: " << prefs.last_error() << "\n";
        return 1;
    }
    std::cout << "Configuration saved to: " << prefs.path().string() << "\n";

    // 2. If daemon is running, send update via IPC
    IpcClient ipc;
    if (ipc.connect()) {
        // Send prefs update request
        std::string response = ipc.prefs_update();
        try {
            auto jv = boost::json::parse(response);
            auto& obj = jv.as_object();
            if (obj.at("status").as_string() == "ok") {
                std::cout << "Configuration applied to running daemon.\n";
            } else {
                auto& msg = obj.at("message").as_string();
                std::cerr << "Warning: Daemon update failed: " << std::string(msg.data(), msg.size()) << "\n";
                std::cerr << "         Changes will take effect on next daemon start.\n";
            }
        } catch (const std::exception&) {
            // Daemon might not support PREFS_UPDATE yet
            std::cout << "Note: Daemon notified. Changes may require restart to take effect.\n";
        }
    } else {
        std::cout << "Daemon is not running. Changes will take effect on next start.\n";
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
// Command: daemon (前台运行，由 systemd/launchd 调用)
// ============================================================================

void print_daemon_help() {
    std::cout << "EdgeLink Client - Run daemon in foreground\n\n"
              << "Usage: edgelink-client daemon [options]\n\n"
              << "This command starts the EdgeLink client daemon in foreground mode.\n"
              << "It reads configuration from prefs.toml (managed by 'edgelink-client up').\n"
              << "This command is intended to be called by systemd/launchd services.\n\n"
              << "Options:\n"
              << "  -c, --config FILE     Load additional configuration from TOML file\n"
              << "  --tun                 Enable TUN device for IP-level routing\n"
              << "  --tun-name NAME       TUN device name (default: auto)\n"
              << "  --tun-mtu MTU         TUN device MTU (default: 1420)\n"
              << "  --ssl-verify          Enable SSL certificate verification\n"
              << "  --ssl-ca FILE         Custom CA certificate file\n"
              << "  --ssl-allow-self-signed  Allow self-signed certificates\n"
              << "  -d, --debug           Enable debug logging\n"
              << "  -v, --verbose         Enable verbose (trace) logging\n"
              << "  -h, --help            Show this help\n\n"
              << "Configuration is loaded from (in order of priority):\n"
              << "  1. Command line arguments\n"
              << "  2. prefs.toml (managed by 'edgelink-client up/set')\n"
              << "  3. config.toml (if specified with -c)\n"
              << "  4. Default values\n";
}

int cmd_daemon(int argc, char* argv[]) {
    // Default configuration
    edgelink::ClientConfig cfg;
    std::string config_file;

    // First pass: look for config file
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_daemon_help();
            return 0;
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
        // No config file: default state_dir to system location
        if (cfg.state_dir.empty()) {
            cfg.state_dir = client::get_state_dir().string();
        }
    }

    // Load prefs.toml and apply to config
    auto prefs_state_dir = cfg.state_dir.empty() ? client::get_state_dir() : std::filesystem::path(cfg.state_dir);
    client::PrefsStore prefs(prefs_state_dir);
    if (prefs.load()) {
        // Apply prefs to edgelink::ClientConfig (different type from client::ClientConfig)
        cfg.controller_url = prefs.controller_url().value_or(client::DEFAULT_CONTROLLER_URL);
        if (auto auth = prefs.authkey()) {
            cfg.authkey = *auth;
        }
        cfg.tls = prefs.tls().value_or(client::DEFAULT_TLS);

        // Routing config
        if (auto exit = prefs.exit_node()) {
            cfg.use_exit_node = *exit;
        }
        cfg.exit_node = prefs.advertise_exit_node();
        cfg.advertise_routes = prefs.advertise_routes();
        cfg.accept_routes = prefs.accept_routes();
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
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.num_threads = static_cast<size_t>(std::stoul(argv[++i]));
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
            print_daemon_help();
            return 0;
        }
    }

    // Setup logging with new system
    setup_logging(cfg.log_level, cfg.log_file, cfg.module_log_levels);

    auto& log = Logger::get("client");
    log.info("EdgeLink Client {} starting (daemon mode)... [build: {}]", version::VERSION, version::BUILD_ID);

    // Initialize crypto
    if (!crypto::init()) {
        log.fatal("Failed to initialize crypto library");
        return 1;
    }

    if (cfg.authkey.empty()) {
        log.error("AuthKey required. Set it with 'edgelink-client up --authkey KEY' first.");
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
        auto work_guard = asio::make_work_guard(ioc);

        // Create client config
        client::ClientConfig client_cfg;
        client_cfg.controller_url = cfg.controller_url;
        client_cfg.authkey = cfg.authkey;
        client_cfg.tls = cfg.tls;
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
        client_cfg.use_exit_node = cfg.use_exit_node;
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
        auto connected_ch = std::make_unique<client::channels::ClientConnectedChannel>(4, ioc.get_executor());
        auto disconnected_ch = std::make_unique<client::channels::ClientDisconnectedChannel>(4, ioc.get_executor());
        auto data_ch = std::make_unique<client::channels::ClientDataChannel>(64, ioc.get_executor());
        auto error_ch = std::make_unique<client::channels::ClientErrorChannel>(8, ioc.get_executor());
        auto shutdown_ch = std::make_unique<client::channels::ShutdownRequestChannel>(4, ioc.get_executor());

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
        cobalt_utils::spawn_task(ioc.get_executor(), [&ioc, &log, client,
                             connected_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec] = co_await cobalt::as_tuple(connected_ptr->read());
                if (ec) break;

                log.info("Client connected and ready");
                log.info("  Virtual IP: {}", client->virtual_ip().to_string());
                log.info("  Peers online: {}", client->peers().online_peer_count());
            }
        }());

        // 启动事件处理协程: on_disconnected
        cobalt_utils::spawn_task(ioc.get_executor(), [disconnected_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec] = co_await cobalt::as_tuple(disconnected_ptr->read());
                if (ec) break;
                Logger::get("client").warn("Client disconnected");
            }
        }());

        // 启动事件处理协程: on_data_received
        cobalt_utils::spawn_task(ioc.get_executor(), [client, data_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec, event] = co_await cobalt::as_tuple(data_ptr->read());
                if (ec) break;
                auto& src = event.src_node;
                auto& data = event.data;
                auto src_ip = client->peers().get_peer_ip_str(src);
                Logger::get("client").debug("Data from {}: {} bytes", src_ip, data.size());
            }
        }());

        // 启动事件处理协程: on_error
        cobalt_utils::spawn_task(ioc.get_executor(), [error_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec, event] = co_await cobalt::as_tuple(error_ptr->read());
                if (ec) break;
                auto& code = event.code;
                auto& msg = event.message;
                Logger::get("client").error("Error {}: {}", code, msg);
            }
        }());

        // 启动事件处理协程: on_shutdown_requested
        cobalt_utils::spawn_task(ioc.get_executor(), [&ioc, &log, client, &work_guard,
                             shutdown_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec] = co_await cobalt::as_tuple(shutdown_ptr->read());
                if (ec) break;
                log.info("Shutdown requested via IPC, stopping...");
                work_guard.reset();
                cobalt_utils::spawn_task(ioc.get_executor(), client->stop());
            }
        }());

        // 启动性能监控输出协程（每60秒打印一次）
        cobalt_utils::spawn_task(ioc.get_executor(), [&ioc, &log]() -> cobalt::task<void> {
            asio::steady_timer timer(ioc);
            while (true) {
                timer.expires_after(std::chrono::seconds(60));
                co_await timer.async_wait(cobalt::use_op);

                // 打印性能摘要
                auto summary = edgelink::perf::PerformanceMonitor::instance().get_summary();
                log.info("{}", summary);
            }
        }());

        // Enable config file watching if config file was specified
        if (!config_file.empty()) {
            auto abs_config_path = std::filesystem::absolute(config_file).string();
            client->set_config_path(abs_config_path);
            client->enable_config_watch();
            log.info("Config file watching enabled: {}", abs_config_path);
        }

        // Setup signal handler with timeout protection
        std::atomic<bool> shutdown_requested{false};
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            if (shutdown_requested.exchange(true)) {
                log.warn("Received signal {} again, force stopping immediately", sig);
                ioc.stop();
                std::exit(1);
            }

            log.info("Received signal {}, shutting down...", sig);

            // Reset work guard to allow io_context to exit when done
            work_guard.reset();

            // Start graceful shutdown
            cobalt_utils::spawn_task(ioc.get_executor(), client->stop());

            // 启动独立线程实现强制超时（2 秒）
            std::thread([&ioc, &log]() {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                log.warn("Shutdown timeout (2s), forcing exit");
                ioc.stop();

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                log.error("Hard timeout reached, force exiting process");
                std::_Exit(1);
            }).detach();
        });

        // Start client
        cobalt_utils::spawn_task(ioc.get_executor(), [client, &log]() -> cobalt::task<void> {
            bool success = co_await client->start();
            if (!success) {
                log.error("Failed to start client");
            }
        }());

        log.info("Daemon running, press Ctrl+C to stop");
        if (!cfg.controller_url.empty()) {
            log.info("  Controller: {}", cfg.controller_url);
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

        log.info("Daemon stopped");

        // Explicitly shutdown LogManager before static destructors run
        LogManager::instance().shutdown();

    } catch (const std::exception& e) {
        log.fatal("Fatal error: {}", e.what());
        LogManager::instance().shutdown();
        return 1;
    }

    return 0;
}

// ============================================================================
// Command: up (配置管理和服务启动，类似 tailscale up)
// ============================================================================

// 显示当前配置（类似 tailscale up 的输出）
void print_prefs_summary(const client::PrefsStore& prefs) {
    std::cout << "\n";
    std::cout << "# Configuration\n";

    // Connection
    auto ctrl = prefs.controller_url();
    auto auth = prefs.authkey();
    auto tls = prefs.tls();

    std::cout << "  controller-url: " << ctrl.value_or(client::DEFAULT_CONTROLLER_URL)
              << (ctrl ? "" : " (default)") << "\n";
    std::cout << "  authkey:        " << (auth ? (auth->substr(0, 8) + "...") : "(not set)") << "\n";
    std::cout << "  tls:            " << (tls.value_or(client::DEFAULT_TLS) ? "true" : "false")
              << (tls ? "" : " (default)") << "\n";

    // Routing
    auto exit = prefs.exit_node();
    bool adv_exit = prefs.advertise_exit_node();
    auto routes = prefs.advertise_routes();
    bool accept = prefs.accept_routes();

    std::cout << "\n";
    std::cout << "  exit-node:           " << (exit ? *exit : "(none)") << "\n";
    std::cout << "  advertise-exit-node: " << (adv_exit ? "true" : "false") << "\n";
    std::cout << "  advertise-routes:    ";
    if (routes.empty()) {
        std::cout << "(none)";
    } else {
        for (size_t i = 0; i < routes.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << routes[i];
        }
    }
    std::cout << "\n";
    std::cout << "  accept-routes:       " << (accept ? "true" : "false") << "\n";
    std::cout << "\n";
}

int cmd_up(int argc, char* argv[]) {
    // Parse options
    bool install_service = false;
    bool uninstall_service = false;
    bool reset = false;
    bool has_changes = false;

    // Connection config
    std::optional<std::string> controller_url;
    std::optional<std::string> authkey;
    std::optional<bool> tls;

    // Routing config
    std::optional<std::string> exit_node;
    std::optional<bool> advertise_exit_node;
    std::optional<std::vector<std::string>> advertise_routes;
    std::optional<bool> accept_routes;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_up_help();
            return 0;
        } else if (arg == "--install-service") {
            install_service = true;
        } else if (arg == "--uninstall-service") {
            uninstall_service = true;
        } else if (arg == "--reset") {
            reset = true;
        }
        // Connection options
        else if (arg == "--controller" && i + 1 < argc) {
            controller_url = argv[++i];
            has_changes = true;
        } else if ((arg == "-a" || arg == "--authkey") && i + 1 < argc) {
            authkey = argv[++i];
            has_changes = true;
        } else if (arg == "--tls") {
            tls = true;
            has_changes = true;
        } else if (arg == "--no-tls") {
            tls = false;
            has_changes = true;
        }
        // Routing options
        else if (starts_with(arg, "--exit-node=")) {
            exit_node = arg.substr(12);
            has_changes = true;
        } else if (arg == "--advertise-exit-node") {
            advertise_exit_node = true;
            has_changes = true;
        } else if (arg == "--no-advertise-exit-node") {
            advertise_exit_node = false;
            has_changes = true;
        } else if (starts_with(arg, "--advertise-routes=")) {
            std::string routes_str = arg.substr(19);
            advertise_routes = split_string(routes_str, ',');
            has_changes = true;
        } else if (arg == "--accept-routes") {
            accept_routes = true;
            has_changes = true;
        } else if (arg == "--no-accept-routes") {
            accept_routes = false;
            has_changes = true;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n\n";
            print_up_help();
            return 1;
        }
    }

    // Handle service uninstall first
    if (uninstall_service) {
        if (ServiceManager::is_running()) {
            std::cout << "Stopping service...\n";
            if (!ServiceManager::stop()) {
                std::cerr << "Warning: Failed to stop service: " << ServiceManager::last_error() << "\n";
            }
        }
        if (ServiceManager::is_installed()) {
            std::cout << "Uninstalling service...\n";
            if (ServiceManager::uninstall()) {
                std::cout << "Service uninstalled successfully.\n";
                return 0;
            } else {
                std::cerr << "Error: Failed to uninstall service: " << ServiceManager::last_error() << "\n";
                return 1;
            }
        } else {
            std::cout << "Service is not installed.\n";
            return 0;
        }
    }

    // Load existing prefs
    auto state_dir = client::get_state_dir();
    client::PrefsStore prefs(state_dir);
    if (!reset) {
        prefs.load();
    }

    // Apply connection config changes
    if (controller_url) {
        prefs.set_controller_url(*controller_url);
    }
    if (authkey) {
        prefs.set_authkey(*authkey);
    }
    if (tls) {
        prefs.set_tls(*tls);
    }

    // Apply routing config changes
    if (exit_node) {
        if (exit_node->empty()) {
            prefs.clear_exit_node();
        } else {
            prefs.set_exit_node(*exit_node);
        }
    }
    if (advertise_exit_node) {
        prefs.set_advertise_exit_node(*advertise_exit_node);
    }
    if (advertise_routes) {
        prefs.set_advertise_routes(*advertise_routes);
    }
    if (accept_routes) {
        prefs.set_accept_routes(*accept_routes);
    }

    // Validate required config
    if (!prefs.authkey()) {
        std::cerr << "Error: AuthKey is required.\n";
        std::cerr << "       Use: edgelink-client up --authkey <KEY>\n";
        return 1;
    }

    // Save prefs
    if (has_changes || reset) {
        if (!prefs.save()) {
            std::cerr << "Error: Failed to save prefs: " << prefs.last_error() << "\n";
            return 1;
        }
    }

    // Print current config (like tailscale up)
    print_prefs_summary(prefs);
    std::cout << "Prefs saved to: " << prefs.path().string() << "\n\n";

    // Handle --install-service: just install and exit
    if (install_service) {
        std::filesystem::path exe_path;
#ifdef _WIN32
        wchar_t path_buf[MAX_PATH];
        GetModuleFileNameW(nullptr, path_buf, MAX_PATH);
        exe_path = path_buf;
#else
        exe_path = std::filesystem::canonical("/proc/self/exe");
#endif
        std::cout << "Installing service from: " << exe_path.string() << "\n";
        if (ServiceManager::install(exe_path)) {
            std::cout << "Service installed successfully.\n";
            return 0;
        } else {
            std::cerr << "Error: Failed to install service: " << ServiceManager::last_error() << "\n";
            return 1;
        }
    }

    // Service mode: check if already running
    auto svc_status = ServiceManager::status();

    if (svc_status == ServiceStatus::RUNNING) {
        // Service is running, notify it about config change
        IpcClient ipc;
        if (ipc.connect()) {
            std::string response = ipc.prefs_update();
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();
                if (obj.at("status").as_string() == "ok") {
                    std::cout << "Configuration applied to running daemon.\n";
                } else {
                    auto& msg = obj.at("message").as_string();
                    std::cerr << "Warning: " << std::string(msg.data(), msg.size()) << "\n";
                }
            } catch (const std::exception&) {
                std::cout << "Daemon notified.\n";
            }
        }
        std::cout << "\n";
        std::cout << "EdgeLink client is running.\n";
        std::cout << "Use 'edgelink-client status' to view status.\n";
        std::cout << "Use 'edgelink-client down' to stop.\n";
        return 0;
    }

    // Get executable path
    std::filesystem::path exe_path;
#ifdef _WIN32
    wchar_t path_buf[MAX_PATH];
    GetModuleFileNameW(nullptr, path_buf, MAX_PATH);
    exe_path = path_buf;
#else
    exe_path = std::filesystem::canonical("/proc/self/exe");
#endif

    // Install service if not installed
    if (svc_status == ServiceStatus::NOT_INSTALLED) {
        std::cout << "Installing EdgeLink client service...\n";
        if (!ServiceManager::install(exe_path)) {
            std::cerr << "Error: Failed to install service: " << ServiceManager::last_error() << "\n";
            std::cerr << "Try running with administrator/root privileges.\n";
            return 1;
        }
        std::cout << "Service installed successfully.\n";
    }

    // Start the service
    std::cout << "Starting EdgeLink client service...\n";
    if (!ServiceManager::start()) {
        std::cerr << "Error: Failed to start service: " << ServiceManager::last_error() << "\n";
        return 1;
    }

    std::cout << "EdgeLink client service started.\n";
    std::cout << "Use 'edgelink-client status' to view status.\n";
    std::cout << "Use 'edgelink-client down' to stop.\n";
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

    // Handle 'up' command (configure and start service)
    if (command == "up") {
        return cmd_up(argc - 2, argv + 2);
    }

    // Handle 'daemon' command (run foreground daemon, called by systemd/launchd)
    if (command == "daemon") {
        return cmd_daemon(argc - 2, argv + 2);
    }

    // Handle 'down' command
    if (command == "down") {
        return cmd_down(argc - 2, argv + 2);
    }

    // Handle 'set' command
    if (command == "set") {
        return cmd_set(argc - 2, argv + 2);
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

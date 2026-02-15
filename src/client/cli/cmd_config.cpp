#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;

static void print_config_help() {
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
              << "Hot-reloadable configuration items can be changed without restarting.\n\n"
              << "Examples:\n"
              << "  edgelink-client config get log.level\n"
              << "  edgelink-client config set log.level debug\n"
              << "  edgelink-client config list --json\n"
              << "  edgelink-client config reload\n";
}

int cmd_config(int argc, char* argv[]) {
    bool json_output = false;

    if (argc == 0) { print_config_help(); return 0; }

    std::string subcommand = argv[0];

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { print_config_help(); return 0; }
        if (arg == "--json") json_output = true;
    }

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
            std::cerr << "Error: config get requires a key\nUsage: edgelink-client config get <key>\n";
            return 1;
        }
        std::string key = argv[1];
        std::string response = ipc.config_get(key);

        if (json_output) { std::cout << response << "\n"; }
        else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();
                if (obj.at("status").as_string() == "ok") {
                    std::cout << std::string(obj.at("key").as_string()) << " = "
                              << std::string(obj.at("value").as_string()) << "\n";
                    std::cout << "  " << std::string(obj.at("description").as_string());
                    if (obj.at("hot_reloadable").as_bool()) std::cout << " [hot-reloadable]";
                    std::cout << "\n";
                } else {
                    std::cerr << "Error: " << obj.at("message").as_string() << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n"; return 1;
            }
        }
    } else if (subcommand == "set") {
        if (argc < 3) {
            std::cerr << "Error: config set requires a key and value\nUsage: edgelink-client config set <key> <value>\n";
            return 1;
        }
        std::string key = argv[1];
        std::string value = argv[2];
        std::string response = ipc.config_set(key, value);

        if (json_output) { std::cout << response << "\n"; }
        else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();
                if (obj.at("status").as_string() == "ok") {
                    std::cout << std::string(obj.at("key").as_string()) << " = "
                              << std::string(obj.at("new_value").as_string()) << "\n";
                    if (obj.at("applied").as_bool())
                        std::cout << "  Configuration applied successfully.\n";
                    if (obj.at("restart_required").as_bool())
                        std::cout << "  Note: Restart required for this change to take effect.\n";
                } else {
                    std::cerr << "Error: " << obj.at("message").as_string() << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n"; return 1;
            }
        }
    } else if (subcommand == "list" || subcommand == "show") {
        std::string response = ipc.config_list();

        if (json_output) { std::cout << response << "\n"; }
        else {
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();
                if (obj.at("status").as_string() == "ok") {
                    auto& config = obj.at("config").as_array();
                    std::string current_section;
                    std::cout << std::left;

                    for (const auto& item : config) {
                        auto& it = item.as_object();
                        std::string key(it.at("key").as_string());
                        std::string value(it.at("value").as_string());
                        bool hot = it.at("hot_reloadable").as_bool();

                        size_t dot_pos = key.find('.');
                        std::string section = dot_pos != std::string::npos ? key.substr(0, dot_pos) : "";

                        if (section != current_section) {
                            if (!current_section.empty()) std::cout << "\n";
                            std::cout << "[" << section << "]\n";
                            current_section = section;
                        }

                        std::string key_part = dot_pos != std::string::npos ? key.substr(dot_pos + 1) : key;
                        std::cout << "  " << std::setw(30) << key_part << " = " << std::setw(20) << value;
                        if (hot) std::cout << " [*]";
                        std::cout << "\n";
                    }
                    std::cout << "\n[*] = hot-reloadable\n";
                } else {
                    std::cerr << "Error: " << obj.at("message").as_string() << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n"; return 1;
            }
        }
    } else if (subcommand == "reload") {
        std::string response = ipc.config_reload();

        if (json_output) { std::cout << response << "\n"; }
        else {
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
                            std::cout << "  " << std::string(ch.at("key").as_string())
                                      << ": " << std::string(ch.at("old_value").as_string())
                                      << " -> " << std::string(ch.at("new_value").as_string());
                            if (ch.at("applied").as_bool()) std::cout << " (applied)";
                            else std::cout << " (requires restart)";
                            std::cout << "\n";
                        }
                    }
                } else {
                    std::cerr << "Error: " << obj.at("message").as_string() << "\n";
                    return 1;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error parsing response: " << e.what() << "\n"; return 1;
            }
        }
    } else {
        std::cerr << "Unknown config subcommand: " << subcommand << "\n\n";
        print_config_help();
        return 1;
    }

    return 0;
}

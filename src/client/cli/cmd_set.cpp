#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;
using edgelink::client::cli::split_string;

static void print_set_help() {
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
              << "Configuration is saved to prefs.json and applied immediately if the\n"
              << "client daemon is running.\n\n"
              << "Examples:\n"
              << "  edgelink-client set --exit-node=gateway\n"
              << "  edgelink-client set --advertise-routes=192.168.1.0/24,10.0.0.0/8\n"
              << "  edgelink-client set --advertise-exit-node\n"
              << "  edgelink-client set --exit-node= --accept-routes\n";
}

int cmd_set(int argc, char* argv[]) {
    std::optional<std::string> exit_node;
    std::optional<bool> advertise_exit_node;
    std::optional<std::vector<std::string>> advertise_routes;
    std::optional<bool> accept_routes;
    bool has_changes = false;

    constexpr auto EXIT_NODE_PREFIX = "--exit-node=";
    constexpr auto ADV_ROUTES_PREFIX = "--advertise-routes=";

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") { print_set_help(); return 0; }
        else if (arg.starts_with(EXIT_NODE_PREFIX)) {
            exit_node = arg.substr(std::string_view(EXIT_NODE_PREFIX).size());
            has_changes = true;
        } else if (arg == "--advertise-exit-node") { advertise_exit_node = true; has_changes = true; }
        else if (arg == "--no-advertise-exit-node") { advertise_exit_node = false; has_changes = true; }
        else if (arg.starts_with(ADV_ROUTES_PREFIX)) {
            advertise_routes = split_string(arg.substr(std::string_view(ADV_ROUTES_PREFIX).size()), ',');
            has_changes = true;
        } else if (arg == "--accept-routes") { accept_routes = true; has_changes = true; }
        else if (arg == "--no-accept-routes") { accept_routes = false; has_changes = true; }
        else { std::cerr << "Unknown option: " << arg << "\n\n"; print_set_help(); return 1; }
    }

    if (!has_changes) {
        std::cerr << "No configuration changes specified.\n\n";
        print_set_help();
        return 1;
    }

    auto state_dir = client::get_state_dir();
    client::PrefsStore prefs(state_dir);
    prefs.load();

    if (exit_node) {
        if (exit_node->empty()) { prefs.clear_exit_node(); std::cout << "Cleared exit node setting.\n"; }
        else { prefs.set_exit_node(*exit_node); std::cout << "Set exit node: " << *exit_node << "\n"; }
    }
    if (advertise_exit_node) {
        prefs.set_advertise_exit_node(*advertise_exit_node);
        std::cout << "Advertise exit node: " << (*advertise_exit_node ? "enabled" : "disabled") << "\n";
    }
    if (advertise_routes) {
        prefs.set_advertise_routes(*advertise_routes);
        if (advertise_routes->empty()) { std::cout << "Cleared advertised routes.\n"; }
        else {
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

    if (!prefs.save()) {
        std::cerr << "Error: Failed to save prefs: " << prefs.last_error() << "\n";
        return 1;
    }
    std::cout << "Configuration saved to: " << prefs.path().string() << "\n";

    IpcClient ipc;
    if (ipc.connect()) {
        std::string response = ipc.prefs_update();
        try {
            auto jv = boost::json::parse(response);
            auto& obj = jv.as_object();
            if (obj.at("status").as_string() == "ok") {
                std::cout << "Configuration applied to running daemon.\n";
            } else {
                std::cerr << "Warning: Daemon update failed: " << obj.at("message").as_string() << "\n"
                          << "         Changes will take effect on next daemon start.\n";
            }
        } catch (const std::exception&) {
            std::cout << "Note: Daemon notified. Changes may require restart to take effect.\n";
        }
    } else {
        std::cout << "Daemon is not running. Changes will take effect on next start.\n";
    }

    return 0;
}

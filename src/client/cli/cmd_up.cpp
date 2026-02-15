#include "cli_common.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

using namespace edgelink;
using namespace edgelink::client;
using edgelink::client::cli::split_string;

static void print_up_help() {
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
              << "The 'up' command saves configuration to prefs.json and starts the daemon\n"
              << "as a system service. If already running, it updates the configuration.\n\n"
              << "Examples:\n"
              << "  edgelink-client up --authkey tskey-xxx           # Minimal start\n"
              << "  edgelink-client up --authkey tskey-xxx --no-tls  # Disable TLS\n"
              << "  edgelink-client up --exit-node=gateway           # Use exit node\n"
              << "  edgelink-client up --advertise-routes=192.168.1.0/24\n";
}

static void print_prefs_summary(const client::PrefsStore& prefs) {
    std::cout << "\n";
    std::cout << "# Configuration\n";

    auto ctrl = prefs.controller_url();
    auto auth = prefs.authkey();
    auto tls = prefs.tls();

    std::cout << "  controller-url: " << ctrl.value_or(client::DEFAULT_CONTROLLER_URL)
              << (ctrl ? "" : " (default)") << "\n";
    std::cout << "  authkey:        " << (auth ? (auth->substr(0, 8) + "...") : "(not set)") << "\n";
    std::cout << "  tls:            " << (tls.value_or(client::DEFAULT_TLS) ? "true" : "false")
              << (tls ? "" : " (default)") << "\n";

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
    bool install_service = false;
    bool uninstall_service = false;
    bool reset = false;
    bool has_changes = false;

    std::optional<std::string> controller_url;
    std::optional<std::string> authkey;
    std::optional<bool> tls;

    std::optional<std::string> exit_node;
    std::optional<bool> advertise_exit_node;
    std::optional<std::vector<std::string>> advertise_routes;
    std::optional<bool> accept_routes;

    constexpr auto EXIT_NODE_PREFIX = "--exit-node=";
    constexpr auto ADV_ROUTES_PREFIX = "--advertise-routes=";

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") { print_up_help(); return 0; }
        else if (arg == "--install-service") { install_service = true; }
        else if (arg == "--uninstall-service") { uninstall_service = true; }
        else if (arg == "--reset") { reset = true; }
        else if (arg == "--controller" && i + 1 < argc) { controller_url = argv[++i]; has_changes = true; }
        else if ((arg == "-a" || arg == "--authkey") && i + 1 < argc) { authkey = argv[++i]; has_changes = true; }
        else if (arg == "--tls") { tls = true; has_changes = true; }
        else if (arg == "--no-tls") { tls = false; has_changes = true; }
        else if (arg.starts_with(EXIT_NODE_PREFIX)) {
            exit_node = arg.substr(std::string_view(EXIT_NODE_PREFIX).size());
            has_changes = true;
        }
        else if (arg == "--advertise-exit-node") { advertise_exit_node = true; has_changes = true; }
        else if (arg == "--no-advertise-exit-node") { advertise_exit_node = false; has_changes = true; }
        else if (arg.starts_with(ADV_ROUTES_PREFIX)) {
            advertise_routes = split_string(arg.substr(std::string_view(ADV_ROUTES_PREFIX).size()), ',');
            has_changes = true;
        }
        else if (arg == "--accept-routes") { accept_routes = true; has_changes = true; }
        else if (arg == "--no-accept-routes") { accept_routes = false; has_changes = true; }
        else if (arg[0] == '-') { std::cerr << "Unknown option: " << arg << "\n\n"; print_up_help(); return 1; }
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
    if (controller_url) prefs.set_controller_url(*controller_url);
    if (authkey) prefs.set_authkey(*authkey);
    if (tls) prefs.set_tls(*tls);

    // Apply routing config changes
    if (exit_node) {
        if (exit_node->empty()) prefs.clear_exit_node();
        else prefs.set_exit_node(*exit_node);
    }
    if (advertise_exit_node) prefs.set_advertise_exit_node(*advertise_exit_node);
    if (advertise_routes) prefs.set_advertise_routes(*advertise_routes);
    if (accept_routes) prefs.set_accept_routes(*accept_routes);

    // Validate required config
    if (!prefs.authkey()) {
        std::cerr << "Error: AuthKey is required.\n"
                  << "       Use: edgelink-client up --authkey <KEY>\n";
        return 1;
    }

    // Save prefs
    if (has_changes || reset) {
        if (!prefs.save()) {
            std::cerr << "Error: Failed to save prefs: " << prefs.last_error() << "\n";
            return 1;
        }
    }

    // Print current config
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
        IpcClient ipc;
        if (ipc.connect()) {
            std::string response = ipc.prefs_update();
            try {
                auto jv = boost::json::parse(response);
                auto& obj = jv.as_object();
                if (obj.at("status").as_string() == "ok") {
                    std::cout << "Configuration applied to running daemon.\n";
                } else {
                    std::cerr << "Warning: " << obj.at("message").as_string() << "\n";
                }
            } catch (const std::exception&) {
                std::cout << "Daemon notified.\n";
            }
        }
        std::cout << "\nEdgeLink client is running.\n"
                  << "Use 'edgelink-client status' to view status.\n"
                  << "Use 'edgelink-client down' to stop.\n";
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
            std::cerr << "Error: Failed to install service: " << ServiceManager::last_error() << "\n"
                      << "Try running with administrator/root privileges.\n";
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

    std::cout << "EdgeLink client service started.\n"
              << "Use 'edgelink-client status' to view status.\n"
              << "Use 'edgelink-client down' to stop.\n";
    return 0;
}

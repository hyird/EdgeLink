#include "client/cli/cli_common.hpp"

#include <iostream>
#include <string>

static void print_usage() {
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

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    std::string command = argv[1];

    if (command == "-h" || command == "--help" || command == "help") {
        print_usage();
        return 0;
    }

    if (command == "-V" || command == "--version" || command == "version") {
        return cmd_version();
    }

    if (command == "up")     return cmd_up(argc - 2, argv + 2);
    if (command == "daemon") return cmd_daemon(argc - 2, argv + 2);
    if (command == "down")   return cmd_down(argc - 2, argv + 2);
    if (command == "set")    return cmd_set(argc - 2, argv + 2);
    if (command == "status") return cmd_status(argc - 2, argv + 2);
    if (command == "peers")  return cmd_peers(argc - 2, argv + 2);
    if (command == "ping")   return cmd_ping(argc - 2, argv + 2);
    if (command == "routes") return cmd_routes(argc - 2, argv + 2);
    if (command == "config") return cmd_config(argc - 2, argv + 2);

    // Legacy mode: if first arg starts with '-', treat as 'up' command
    if (command[0] == '-') {
        return cmd_up(argc - 1, argv + 1);
    }

    std::cerr << "Unknown command: " << command << "\n\n";
    print_usage();
    return 1;
}

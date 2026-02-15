#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;

static void print_status_help() {
    std::cout << "EdgeLink Client - Show connection status\n\n"
              << "Usage: edgelink-client status [options]\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  -h, --help    Show this help\n\n"
              << "Note: This command requires the client daemon to be running.\n";
}

int cmd_status(int argc, char* argv[]) {
    bool json_output = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") json_output = true;
        else if (arg == "-h" || arg == "--help") { print_status_help(); return 0; }
    }

    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\"status\":\"not_connected\",\"error\":\"Cannot connect to daemon\"}\n";
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

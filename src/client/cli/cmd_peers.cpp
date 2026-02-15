#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;

static void print_peers_help() {
    std::cout << "EdgeLink Client - List peer nodes\n\n"
              << "Usage: edgelink-client peers [options]\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  --online      Only show online peers\n"
              << "  -h, --help    Show this help\n\n"
              << "Note: This command requires the client daemon to be running.\n";
}

int cmd_peers(int argc, char* argv[]) {
    bool json_output = false;
    bool online_only = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") json_output = true;
        else if (arg == "--online") online_only = true;
        else if (arg == "-h" || arg == "--help") { print_peers_help(); return 0; }
    }

    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\"peers\":[],\"error\":\"Cannot connect to daemon\"}\n";
        } else {
            std::cout << "Peers: None\n\nCannot connect to the client daemon.\n"
                      << "Use 'edgelink-client up' to start the client.\n";
        }
        return 1;
    }

    std::string response = ipc.get_peers(online_only);

    if (json_output) {
        std::cout << response << "\n";
    } else {
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

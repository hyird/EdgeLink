#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;

static void print_routes_help() {
    std::cout << "EdgeLink Client - List subnet routes\n\n"
              << "Usage: edgelink-client routes [options]\n\n"
              << "Options:\n"
              << "  --json        Output in JSON format\n"
              << "  -h, --help    Show this help\n\n"
              << "Shows all subnet routes advertised by peers in the network.\n";
}

int cmd_routes(int argc, char* argv[]) {
    bool json_output = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") json_output = true;
        else if (arg == "-h" || arg == "--help") { print_routes_help(); return 0; }
    }

    IpcClient ipc;
    if (!ipc.connect()) {
        if (json_output) {
            std::cout << "{\"routes\":[],\"error\":\"Cannot connect to daemon\"}\n";
        } else {
            std::cout << "Routes: None\n\nCannot connect to the client daemon.\n"
                      << "Use 'edgelink-client up' to start the client.\n";
        }
        return 1;
    }

    std::string response = ipc.get_routes();

    if (json_output) {
        std::cout << response << "\n";
    } else {
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
                        std::string prefix(route.at("prefix").as_string());
                        std::string gateway_ip(route.at("gateway_ip").as_string());
                        std::string gateway_name(route.at("gateway_name").as_string());
                        int64_t metric = route.at("metric").as_int64();
                        std::string type = route.at("exit_node").as_bool() ? "exit" : "subnet";

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

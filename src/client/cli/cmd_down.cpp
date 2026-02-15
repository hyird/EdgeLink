#include "cli_common.hpp"

using namespace edgelink;
using namespace edgelink::client;

static void print_down_help() {
    std::cout << "EdgeLink Client - Stop the daemon\n\n"
              << "Usage: edgelink-client down [options]\n\n"
              << "Options:\n"
              << "  -h, --help    Show this help\n\n"
              << "Sends a shutdown signal to the running client daemon.\n";
}

int cmd_down(int argc, char* argv[]) {
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { print_down_help(); return 0; }
    }

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

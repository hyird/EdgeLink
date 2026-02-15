#include "cli_common.hpp"
#include <thread>
#include <chrono>

using namespace edgelink;
using namespace edgelink::client;

static void print_ping_help() {
    std::cout << "EdgeLink Client - Ping a peer\n\n"
              << "Usage: edgelink-client ping <target> [options]\n\n"
              << "Arguments:\n"
              << "  target        Target peer's virtual IP (e.g., 100.64.0.2)\n\n"
              << "Options:\n"
              << "  -c, --count N   Number of pings to send (default: 4)\n"
              << "  -h, --help      Show this help\n\n"
              << "Note: This command requires the client daemon to be running.\n";
}

int cmd_ping(int argc, char* argv[]) {
    std::string target;
    int count = 4;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") { print_ping_help(); return 0; }
        else if ((arg == "-c" || arg == "--count") && i + 1 < argc) {
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

    IpcClient ipc;
    if (!ipc.connect()) {
        std::cerr << "Error: Cannot connect to client daemon. Is it running?\n"
                  << "       Start the daemon with: edgelink-client up\n";
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

        if (i < count - 1)
            std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "\n--- " << target << " ping statistics ---\n";
    std::cout << count << " packets transmitted, " << success_count << " received, "
              << ((count - success_count) * 100 / count) << "% packet loss\n";

    if (success_count > 0) {
        uint64_t avg_latency = total_latency / success_count;
        std::cout << "rtt min/avg/max = " << min_latency << "/" << avg_latency << "/" << max_latency << " ms\n";
    }

    return success_count > 0 ? 0 : 1;
}

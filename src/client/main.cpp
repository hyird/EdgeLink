#include "client.hpp"
#include "common/log.hpp"
#include "common/crypto/ed25519.hpp"
#include "common/crypto/x25519.hpp"
#include <iostream>
#include <fstream>
#include <csignal>
#include <iomanip>
#include <ctime>

#ifdef _WIN32
    #include <io.h>
    #include <process.h>
    #include <windows.h>
    #define access _access
    #define F_OK 0
    #define getpid _getpid
#else
    #include <unistd.h>
#endif

using namespace edgelink::client;
using namespace edgelink;

void print_usage(const char* program) {
    std::cout << "EdgeLink Client\n\n"
              << "Usage: " << program << " [options] <command>\n\n"
              << "Commands:\n"
              << "  connect               Connect to network (default)\n"
              << "  status                Show connection status\n"
              << "  keygen                Generate machine key pair\n"
              << "  init                  Generate config file\n\n"
              << "Options:\n"
              << "  -c, --config <file>   Config file (default: /etc/edgelink/client.json)\n"
              << "  -u, --url <url>       Controller URL (overrides config)\n"
              << "  -a, --auth-key <key>  Auth key for registration\n"
              << "  -k, --key <key>       Machine public key (base64)\n"
              << "  -K, --priv-key <key>  Machine private key (base64)\n"
              << "  -i, --interface <n>   TUN interface name (default: wss0)\n"
              << "  -l, --log-level <l>   Log level: trace/debug/info/warn/error\n"
              << "  -d, --daemon          Run as daemon\n"
              << "  -q, --quiet           Suppress log output\n"
              << "  -h, --help            Show help\n\n"
              << "Examples:\n"
              << "  " << program << " connect -c /etc/edgelink/client.json\n"
              << "  " << program << " connect -u ws://controller:8080 --auth-key <KEY>\n"
              << "  " << program << " keygen\n"
              << "  " << program << " init --output client.json\n"
              << std::endl;
}

void setup_logging(const std::string& level, bool quiet) {
    if (quiet) {
        log::set_level(spdlog::level::off);
        return;
    }
    
    log::LogConfig config;
    if (level == "trace") config.level = spdlog::level::trace;
    else if (level == "debug") config.level = spdlog::level::debug;
    else if (level == "info") config.level = spdlog::level::info;
    else if (level == "warn") config.level = spdlog::level::warn;
    else if (level == "error") config.level = spdlog::level::err;
    
    config.console = true;
    config.file_path = "/var/log/edgelink/client.log";
    log::init(config);
}

static Client* g_client = nullptr;

void signal_handler(int sig) {
    if (g_client) {
        LOG_INFO("Received signal {}, shutting down...", sig);
        g_client->stop();
    }
}

// Generate machine key pair
int cmd_keygen(const std::vector<std::string>& args) {
    std::string output;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--output" && i + 1 < args.size()) {
            output = args[i + 1];
        }
    }
    
    // Generate Ed25519 key pair
    auto [pub_key, priv_key] = crypto::Ed25519::generate_keypair();
    std::string pub_b64 = crypto::Ed25519::to_base64(pub_key);
    std::string priv_b64 = crypto::Ed25519::to_base64(priv_key);
    
    if (!output.empty()) {
        // Save to file
        std::ofstream f(output);
        if (!f) {
            std::cerr << "Error: Cannot write to " << output << "\n";
            return 1;
        }
        f << "# EdgeLink Machine Key\n";
        f << "# Generated: " << std::time(nullptr) << "\n";
        f << "public=" << pub_b64 << "\n";
        f << "private=" << priv_b64 << "\n";
        std::cout << "Key pair saved to: " << output << "\n";
    } else {
        std::cout << "Public:  " << pub_b64 << "\n";
        std::cout << "Private: " << priv_b64 << "\n";
    }
    
    return 0;
}

// Generate config file
int cmd_init(const std::vector<std::string>& args) {
    std::string output = "client.json";
    std::string url;
    
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--output" && i + 1 < args.size()) {
            output = args[i + 1];
        } else if (args[i] == "--url" && i + 1 < args.size()) {
            url = args[i + 1];
        }
    }
    
    // Generate key pair
    auto [pub_key, priv_key] = crypto::Ed25519::generate_keypair();
    std::string pub_b64 = crypto::Ed25519::to_base64(pub_key);
    std::string priv_b64 = crypto::Ed25519::to_base64(priv_key);
    
    std::ofstream f(output);
    if (!f) {
        std::cerr << "Error: Cannot write to " << output << "\n";
        return 1;
    }
    
    f << "{\n";
    f << "  \"controller_url\": \"" << (url.empty() ? "wss://controller.example.com" : url) << "\",\n";
    f << "  \"machine_key_pub\": \"" << pub_b64 << "\",\n";
    f << "  \"machine_key_priv\": \"" << priv_b64 << "\",\n";
    f << "  \"tun_name\": \"wss0\",\n";
    f << "  \"log_level\": \"info\"\n";
    f << "}\n";
    
    std::cout << "Config created: " << output << "\n";
    std::cout << "Machine public key: " << pub_b64 << "\n";
    if (url.empty()) {
        std::cout << "Update controller_url before use!\n";
    }
    return 0;
}

// Show status (connect to running client via socket, or just check config)
int cmd_status(const std::string& config_file) {
    std::cout << "EdgeLink Client Status\n";
    std::cout << "======================\n";
    
    // Try to load config
    try {
        std::ifstream f(config_file);
        if (f.good()) {
            f.close();
            auto config = load_client_config(config_file);
            std::cout << "Config:     " << config_file << "\n";
            std::cout << "Controller: " << config.controller_url << "\n";
            std::cout << "Interface:  " << config.tun_name << "\n";
            
#ifdef _WIN32
            // On Windows, we can't easily check interface status without more complex code
            std::cout << "Status:     Unknown (check Task Manager)\n";
#else
            // Check if interface exists (Linux)
            std::string ifpath = "/sys/class/net/" + config.tun_name;
            if (access(ifpath.c_str(), F_OK) == 0) {
                std::cout << "Status:     Connected\n";
            } else {
                std::cout << "Status:     Not running\n";
            }
#endif
        } else {
            std::cout << "Config not found: " << config_file << "\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
    }
    
    return 0;
}

#ifdef _WIN32
// Check if running as Administrator on Windows
static bool is_admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}
#endif

int cmd_connect(const ClientConfig& config, bool daemon_mode) {
    // Check root/admin privileges
#ifdef _WIN32
    if (!is_admin()) {
        std::cerr << "Error: Administrator privileges required for TUN device.\n";
        std::cerr << "Please run as Administrator.\n";
        return 1;
    }
    if (daemon_mode) {
        std::cerr << "Warning: Daemon mode not supported on Windows. Running in foreground.\n";
        daemon_mode = false;
    }
#else
    if (geteuid() != 0) {
        std::cerr << "Error: Root privileges required for TUN device.\n";
        return 1;
    }
#endif
    
    // Validate
    if (config.controller_url.empty()) {
        std::cerr << "Error: Controller URL required. Use -u or config file.\n";
        return 1;
    }
    if (config.machine_key_pub.empty()) {
        std::cerr << "Error: Machine key required. Use -k or run 'keygen'.\n";
        return 1;
    }
    
#ifndef _WIN32
    // Daemon mode (POSIX only)
    if (daemon_mode) {
        pid_t pid = fork();
        if (pid < 0) {
            std::cerr << "Error: Fork failed\n";
            return 1;
        }
        if (pid > 0) {
            std::cout << "EdgeLink Client started (PID: " << pid << ")\n";
            return 0;
        }
        setsid();
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        
        std::ofstream pid_file("/var/run/edgelink-client.pid");
        if (pid_file) {
            pid_file << getpid();
        }
    }
#endif
    
    LOG_INFO("EdgeLink Client v0.1.0");
    LOG_INFO("Controller: {}", config.controller_url);
    LOG_INFO("Interface: {}", config.tun_name);
    
    try {
        Client client(config);
        g_client = &client;
        
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        if (!client.start()) {
            LOG_ERROR("Failed to start client");
            return 1;
        }
        
        client.run();
        LOG_INFO("Client stopped");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Fatal: {}", e.what());
        return 1;
    }
    
#ifndef _WIN32
    if (daemon_mode) {
        std::remove("/var/run/edgelink-client.pid");
    }
#endif
    
    return 0;
}

int main(int argc, char* argv[]) {
    std::string config_file = "/etc/edgelink/client.json";
    std::string controller_url;
    std::string machine_key_pub;
    std::string machine_key_priv;
    std::string auth_key;
    std::string tun_name;
    std::string log_level = "info";
    bool daemon_mode = false;
    bool quiet = false;
    std::string command = "connect";
    std::vector<std::string> cmd_args;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        }
        else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        }
        else if ((arg == "-u" || arg == "--url") && i + 1 < argc) {
            controller_url = argv[++i];
        }
        else if ((arg == "-a" || arg == "--auth-key") && i + 1 < argc) {
            auth_key = argv[++i];
        }
        else if ((arg == "-k" || arg == "--key") && i + 1 < argc) {
            machine_key_pub = argv[++i];
        }
        else if ((arg == "-K" || arg == "--priv-key") && i + 1 < argc) {
            machine_key_priv = argv[++i];
        }
        else if ((arg == "-i" || arg == "--interface") && i + 1 < argc) {
            tun_name = argv[++i];
        }
        else if ((arg == "-l" || arg == "--log-level") && i + 1 < argc) {
            log_level = argv[++i];
        }
        else if (arg == "-d" || arg == "--daemon") {
            daemon_mode = true;
        }
        else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        }
        else if (arg[0] != '-') {
            command = arg;
            for (int j = i + 1; j < argc; ++j) {
                cmd_args.push_back(argv[j]);
            }
            break;
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }
    }
    
    // Commands that don't need config/logging
    if (command == "keygen") {
        return cmd_keygen(cmd_args);
    }
    if (command == "init") {
        return cmd_init(cmd_args);
    }
    if (command == "status") {
        return cmd_status(config_file);
    }
    
    // Setup logging
    setup_logging(log_level, quiet);
    
    // Load config
    ClientConfig config;
    bool config_loaded = false;
    try {
        std::ifstream f(config_file);
        if (f.good()) {
            f.close();
            config = load_client_config(config_file);
            config_loaded = true;
            if (!quiet) LOG_INFO("Config loaded: {}", config_file);
        }
    } catch (const std::exception& e) {
        if (!quiet) LOG_WARN("Config load failed: {}", e.what());
    }
    
    // If no config loaded and no controller URL provided, show help
    if (!config_loaded && controller_url.empty()) {
        std::cerr << "Error: No configuration found.\n\n";
        std::cerr << "Either:\n";
        std::cerr << "  1. Create config file at " << config_file << "\n";
        std::cerr << "  2. Specify config with -c <file>\n";
        std::cerr << "  3. Provide controller URL with -u <url>\n\n";
        std::cerr << "Use 'edgelink-client init' to generate a sample config.\n\n";
        print_usage(argv[0]);
        return 1;
    }
    
    // Override with command line
    if (!controller_url.empty()) config.controller_url = controller_url;
    if (!auth_key.empty()) config.auth_key = auth_key;
    if (!machine_key_pub.empty()) config.machine_key_pub = machine_key_pub;
    if (!machine_key_priv.empty()) config.machine_key_priv = machine_key_priv;
    if (!tun_name.empty()) config.tun_name = tun_name;
    config.log_level = log_level;
    
    if (command == "connect") {
        return cmd_connect(config, daemon_mode);
    }
    
    std::cerr << "Unknown command: " << command << "\n";
    print_usage(argv[0]);
    return 1;
}

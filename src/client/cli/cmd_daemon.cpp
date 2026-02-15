#include "cli_common.hpp"
#include "client/client.hpp"
#include "common/crypto.hpp"
#include "common/logger.hpp"
#include "common/performance_monitor.hpp"
#include "common/cobalt_utils.hpp"

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/cobalt.hpp>

#include <atomic>
#include <filesystem>
#include <thread>

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;

using namespace edgelink;
using namespace edgelink::client;

static void setup_logging(const std::string& level, const std::string& log_file,
                          const std::unordered_map<std::string, std::string>& module_levels = {}) {
    LogConfig config;
    config.global_level = log_level_from_string(level);
    config.console_enabled = true;
    config.console_color = true;

    if (!log_file.empty()) {
        config.file_enabled = true;
        config.file_path = log_file;
    }

    for (const auto& [module, module_level] : module_levels) {
        config.module_levels[module] = log_level_from_string(module_level);
    }

    LogManager::instance().init(config);
}

static void print_daemon_help() {
    std::cout << "EdgeLink Client - Run daemon in foreground\n\n"
              << "Usage: edgelink-client daemon [options]\n\n"
              << "This command starts the EdgeLink client daemon in foreground mode.\n"
              << "It reads configuration from prefs.json (managed by 'edgelink-client up').\n"
              << "This command is intended to be called by systemd/launchd services.\n\n"
              << "Options:\n"
              << "  -c, --config FILE     Load additional configuration from JSON file\n"
              << "  --tun                 Enable TUN device for IP-level routing\n"
              << "  --tun-name NAME       TUN device name (default: auto)\n"
              << "  --tun-mtu MTU         TUN device MTU (default: 1420)\n"
              << "  --ssl-verify          Enable SSL certificate verification\n"
              << "  --ssl-ca FILE         Custom CA certificate file\n"
              << "  --ssl-allow-self-signed  Allow self-signed certificates\n"
              << "  -d, --debug           Enable debug logging\n"
              << "  -v, --verbose         Enable verbose (trace) logging\n"
              << "  -h, --help            Show this help\n\n"
              << "Configuration is loaded from (in order of priority):\n"
              << "  1. Command line arguments\n"
              << "  2. prefs.json (managed by 'edgelink-client up/set')\n"
              << "  3. config.json (if specified with -c)\n"
              << "  4. Default values\n";
}

int cmd_daemon(int argc, char* argv[]) {
    edgelink::ClientConfig cfg;
    std::string config_file;

    // First pass: look for config file
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            config_file = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            print_daemon_help();
            return 0;
        }
    }

    // Load config file if specified
    if (!config_file.empty()) {
        auto result = edgelink::ClientConfig::load(config_file);
        if (!result) {
            std::cerr << "Error: " << config_error_message(result.error())
                      << ": " << config_file << std::endl;
            return 1;
        }
        cfg = *result;
        std::cout << "Loaded configuration from: " << config_file << std::endl;

        if (cfg.state_dir.empty()) {
            auto config_path = std::filesystem::absolute(config_file);
            cfg.state_dir = config_path.parent_path().string();
        }
    } else {
        if (cfg.state_dir.empty()) {
            cfg.state_dir = client::get_state_dir().string();
        }
    }

    // Load prefs and apply to config
    auto prefs_state_dir = cfg.state_dir.empty() ? client::get_state_dir() : std::filesystem::path(cfg.state_dir);
    client::PrefsStore prefs(prefs_state_dir);
    if (prefs.load()) {
        prefs.apply_to(cfg);
    }

    // Second pass: command line overrides
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            ++i; // Already handled
        } else if (arg == "--controller" && i + 1 < argc) {
            cfg.controller_url = argv[++i];
        } else if ((arg == "-a" || arg == "--authkey") && i + 1 < argc) {
            cfg.authkey = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.num_threads = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (arg == "--tls") {
            cfg.tls = true;
        } else if (arg == "--tun") {
            cfg.enable_tun = true;
        } else if (arg == "--tun-name" && i + 1 < argc) {
            cfg.tun_name = argv[++i];
        } else if (arg == "--tun-mtu" && i + 1 < argc) {
            cfg.tun_mtu = static_cast<uint32_t>(std::stoul(argv[++i]));
        } else if (arg == "-d" || arg == "--debug") {
            cfg.log_level = "debug";
        } else if (arg == "-v" || arg == "--verbose") {
            cfg.log_level = "trace";
        } else if (arg == "--ssl-verify") {
            cfg.ssl_verify = true;
        } else if (arg == "--ssl-ca" && i + 1 < argc) {
            cfg.ssl_ca_file = argv[++i];
        } else if (arg == "--ssl-allow-self-signed") {
            cfg.ssl_allow_self_signed = true;
        } else if (arg == "-h" || arg == "--help") {
            print_daemon_help();
            return 0;
        }
    }

    // Setup logging
    setup_logging(cfg.log_level, cfg.log_file, cfg.module_log_levels);

    auto& log = Logger::get("client");
    log.info("EdgeLink Client {} starting (daemon mode)... [build: {}]", version::VERSION, version::BUILD_ID);

    // Initialize crypto
    if (!crypto::init()) {
        log.fatal("Failed to initialize crypto library");
        return 1;
    }

    if (cfg.authkey.empty()) {
        log.error("AuthKey required. Set it with 'edgelink-client up --authkey KEY' first.");
        return 1;
    }

    try {
        size_t num_threads = 1;
        if (cfg.num_threads > 0) {
            num_threads = cfg.num_threads;
        }

        asio::io_context ioc(static_cast<int>(num_threads));
        auto work_guard = asio::make_work_guard(ioc);

        // Create client
        auto client = std::make_shared<Client>(ioc, cfg);

        // Create event channels
        auto connected_ch = std::make_unique<client::channels::ClientConnectedChannel>(4, ioc.get_executor());
        auto disconnected_ch = std::make_unique<client::channels::ClientDisconnectedChannel>(4, ioc.get_executor());
        auto data_ch = std::make_unique<client::channels::ClientDataChannel>(64, ioc.get_executor());
        auto error_ch = std::make_unique<client::channels::ClientErrorChannel>(8, ioc.get_executor());
        auto shutdown_ch = std::make_unique<client::channels::ShutdownRequestChannel>(4, ioc.get_executor());

        auto* connected_ptr = connected_ch.get();
        auto* disconnected_ptr = disconnected_ch.get();
        auto* data_ptr = data_ch.get();
        auto* error_ptr = error_ch.get();
        auto* shutdown_ptr = shutdown_ch.get();

        ClientEvents events;
        events.connected = connected_ptr;
        events.disconnected = disconnected_ptr;
        events.data_received = data_ptr;
        events.error = error_ptr;
        events.shutdown_requested = shutdown_ptr;
        client->set_events(events);

        // Event coroutines
        cobalt_utils::spawn_task(ioc.get_executor(), [&ioc, &log, client,
                             connected_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec] = co_await cobalt::as_tuple(connected_ptr->read());
                if (ec) break;
                log.info("Client connected and ready");
                log.info("  Virtual IP: {}", client->virtual_ip().to_string());
                log.info("  Peers online: {}", client->peers().online_peer_count());
            }
        }());

        cobalt_utils::spawn_task(ioc.get_executor(), [disconnected_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec] = co_await cobalt::as_tuple(disconnected_ptr->read());
                if (ec) break;
                Logger::get("client").warn("Client disconnected");
            }
        }());

        cobalt_utils::spawn_task(ioc.get_executor(), [client, data_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec, event] = co_await cobalt::as_tuple(data_ptr->read());
                if (ec) break;
                auto& src = event.src_node;
                auto& data = event.data;
                auto src_ip = client->peers().get_peer_ip_str(src);
                Logger::get("client").debug("Data from {}: {} bytes", src_ip, data.size());
            }
        }());

        cobalt_utils::spawn_task(ioc.get_executor(), [error_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec, event] = co_await cobalt::as_tuple(error_ptr->read());
                if (ec) break;
                auto& code = event.code;
                auto& msg = event.message;
                Logger::get("client").error("Error {}: {}", code, msg);
            }
        }());

        cobalt_utils::spawn_task(ioc.get_executor(), [&ioc, &log, client, &work_guard,
                             shutdown_ptr]() -> cobalt::task<void> {
            while (true) {
                auto [ec] = co_await cobalt::as_tuple(shutdown_ptr->read());
                if (ec) break;
                log.info("Shutdown requested via IPC, stopping...");
                work_guard.reset();
                cobalt_utils::spawn_task(ioc.get_executor(), client->stop());
            }
        }());

        // Performance monitor coroutine
        cobalt_utils::spawn_task(ioc.get_executor(), [&ioc, &log]() -> cobalt::task<void> {
            asio::steady_timer timer(ioc);
            while (true) {
                timer.expires_after(std::chrono::seconds(60));
                co_await timer.async_wait(cobalt::use_op);
                auto summary = edgelink::perf::PerformanceMonitor::instance().get_summary();
                log.info("{}", summary);
            }
        }());

        // Enable config file watching
        if (!config_file.empty()) {
            auto abs_config_path = std::filesystem::absolute(config_file).string();
            client->set_config_path(abs_config_path);
            client->enable_config_watch();
            log.info("Config file watching enabled: {}", abs_config_path);
        }

        // Signal handler with timeout protection
        std::atomic<bool> shutdown_requested{false};
        asio::signal_set signals(ioc, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int sig) {
            if (shutdown_requested.exchange(true)) {
                log.warn("Received signal {} again, force stopping immediately", sig);
                ioc.stop();
                std::exit(1);
            }

            log.info("Received signal {}, shutting down...", sig);
            work_guard.reset();
            cobalt_utils::spawn_task(ioc.get_executor(), client->stop());

            std::thread([&ioc, &log]() {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                log.warn("Shutdown timeout (2s), forcing exit");
                ioc.stop();

                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                log.error("Hard timeout reached, force exiting process");
                std::_Exit(1);
            }).detach();
        });

        // Start client
        cobalt_utils::spawn_task(ioc.get_executor(), [client, &log]() -> cobalt::task<void> {
            bool success = co_await client->start();
            if (!success) {
                log.error("Failed to start client");
            }
        }());

        log.info("Daemon running, press Ctrl+C to stop");
        if (!cfg.controller_url.empty()) {
            log.info("  Controller: {}", cfg.controller_url);
        }
        if (cfg.enable_tun) {
            log.info("  TUN mode: enabled (MTU={})", cfg.tun_mtu);
        }
        log.info("  Thread mode: {} thread(s)", num_threads);

        // Multi-thread mode: start worker pool
        std::vector<std::thread> worker_threads;
        if (num_threads > 1) {
            log.info("Starting {} worker threads...", num_threads - 1);
            worker_threads.reserve(num_threads - 1);

            for (size_t i = 1; i < num_threads; ++i) {
                worker_threads.emplace_back([&ioc, i, &log] {
                    try {
                        log.debug("Worker thread {} started", i);
                        ioc.run();
                        log.debug("Worker thread {} stopped", i);
                    } catch (const std::exception& e) {
                        log.error("Worker thread {} exception: {}", i, e.what());
                    }
                });
            }
        }

        ioc.run();

        for (auto& t : worker_threads) {
            if (t.joinable()) {
                t.join();
            }
        }

        log.info("Daemon stopped");
        LogManager::instance().shutdown();

    } catch (const std::exception& e) {
        log.fatal("Fatal error: {}", e.what());
        LogManager::instance().shutdown();
        return 1;
    }

    return 0;
}

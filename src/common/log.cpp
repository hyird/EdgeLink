#include "common/log.hpp"
#include <cstdlib>
#include <unordered_map>
#include <mutex>

namespace edgelink::log {

namespace {

std::mutex g_mutex;
std::shared_ptr<spdlog::logger> g_default_logger;
std::unordered_map<std::string, std::shared_ptr<spdlog::logger>> g_loggers;
LogConfig g_config;
bool g_initialized = false;

spdlog::level::level_enum parse_level(const std::string& level) {
    if (level == "trace") return spdlog::level::trace;
    if (level == "debug") return spdlog::level::debug;
    if (level == "info") return spdlog::level::info;
    if (level == "warn" || level == "warning") return spdlog::level::warn;
    if (level == "error" || level == "err") return spdlog::level::err;
    if (level == "critical" || level == "crit") return spdlog::level::critical;
    if (level == "off") return spdlog::level::off;
    return spdlog::level::info;
}

std::shared_ptr<spdlog::logger> create_logger(const std::string& name) {
    std::vector<spdlog::sink_ptr> sinks;
    
    if (g_config.console) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(g_config.level);
        sinks.push_back(console_sink);
    }
    
    if (!g_config.file_path.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            g_config.file_path,
            g_config.max_file_size,
            g_config.max_files
        );
        file_sink->set_level(g_config.level);
        sinks.push_back(file_sink);
    }
    
    auto logger = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
    logger->set_level(g_config.level);
    logger->set_pattern(g_config.pattern);
    
    spdlog::register_logger(logger);
    
    return logger;
}

} // anonymous namespace

void init(const LogConfig& config) {
    std::lock_guard<std::mutex> lock(g_mutex);
    
    if (g_initialized) {
        return;
    }
    
    g_config = config;
    g_default_logger = create_logger(MAIN_LOGGER);
    g_loggers[MAIN_LOGGER] = g_default_logger;
    g_initialized = true;
}

void init_from_env() {
    LogConfig config;
    
    if (const char* level = std::getenv("EDGELINK_LOG_LEVEL")) {
        config.level = parse_level(level);
    }
    
    if (const char* file = std::getenv("EDGELINK_LOG_FILE")) {
        config.file_path = file;
    }
    
    init(config);
}

std::shared_ptr<spdlog::logger> get(const std::string& name) {
    std::lock_guard<std::mutex> lock(g_mutex);
    
    // Auto-initialize if needed - keep existing g_config settings
    if (!g_initialized) {
        // g_config may have been modified by set_level before initialization
        // So we don't reset it, just create the logger with current settings
        g_default_logger = create_logger(MAIN_LOGGER);
        g_loggers[MAIN_LOGGER] = g_default_logger;
        g_initialized = true;
    }
    
    // Return existing logger
    auto it = g_loggers.find(name);
    if (it != g_loggers.end()) {
        return it->second;
    }
    
    // Create new logger
    auto logger = create_logger(name);
    g_loggers[name] = logger;
    return logger;
}

void set_level(spdlog::level::level_enum level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_config.level = level;
    
    // If not initialized yet, just update g_config (it will be used when get() is called)
    // Also set spdlog's default level
    spdlog::set_level(level);
    
    for (auto& [name, logger] : g_loggers) {
        logger->set_level(level);
        // Also set sink levels
        for (auto& sink : logger->sinks()) {
            sink->set_level(level);
        }
    }
}

void flush() {
    std::lock_guard<std::mutex> lock(g_mutex);
    for (auto& [name, logger] : g_loggers) {
        logger->flush();
    }
}

void shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_loggers.clear();
    g_default_logger.reset();
    spdlog::shutdown();
    g_initialized = false;
}

} // namespace edgelink::log

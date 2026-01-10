#include "common/logger.hpp"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace edgelink {

// Thread-local trace ID storage
thread_local std::string TraceContext::current_trace_id_;

// ============================================================================
// Log Level Utilities
// ============================================================================

LogLevel log_level_from_string(std::string_view str) {
    std::string lower;
    lower.reserve(str.size());
    for (char c : str) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    if (lower == "trace" || lower == "verbose") return LogLevel::TRACE;
    if (lower == "debug") return LogLevel::DEBUG;
    if (lower == "info") return LogLevel::INFO;
    if (lower == "warn" || lower == "warning") return LogLevel::WARN;
    if (lower == "error" || lower == "err") return LogLevel::ERROR;
    if (lower == "fatal" || lower == "critical") return LogLevel::FATAL;
    if (lower == "off") return LogLevel::OFF;

    return LogLevel::INFO;  // Default
}

std::string_view log_level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "trace";
        case LogLevel::DEBUG: return "debug";
        case LogLevel::INFO:  return "info";
        case LogLevel::WARN:  return "warn";
        case LogLevel::ERROR: return "error";
        case LogLevel::FATAL: return "fatal";
        case LogLevel::OFF:   return "off";
    }
    return "info";
}

spdlog::level::level_enum to_spdlog_level(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return spdlog::level::trace;
        case LogLevel::DEBUG: return spdlog::level::debug;
        case LogLevel::INFO:  return spdlog::level::info;
        case LogLevel::WARN:  return spdlog::level::warn;
        case LogLevel::ERROR: return spdlog::level::err;
        case LogLevel::FATAL: return spdlog::level::critical;
        case LogLevel::OFF:   return spdlog::level::off;
    }
    return spdlog::level::info;
}

// ============================================================================
// TraceContext
// ============================================================================

std::string TraceContext::generate_trace_id() {
    // Generate 16 random bytes, encode as base64-like string (22 chars)
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    uint64_t hi = dis(gen);
    uint64_t lo = dis(gen);

    // Simple hex encoding (32 chars, but we'll use 16)
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(16);

    for (int i = 0; i < 8; ++i) {
        result.push_back(hex[(hi >> (60 - i * 8)) & 0xF]);
        result.push_back(hex[(hi >> (56 - i * 8)) & 0xF]);
    }

    return result;
}

void TraceContext::set_trace_id(const std::string& trace_id) {
    current_trace_id_ = trace_id;
}

const std::string& TraceContext::get_trace_id() {
    return current_trace_id_;
}

void TraceContext::clear_trace_id() {
    current_trace_id_.clear();
}

TraceContext::Scope::Scope(const std::string& trace_id)
    : previous_trace_id_(current_trace_id_) {
    if (trace_id.empty()) {
        trace_id_ = generate_trace_id();
    } else {
        trace_id_ = trace_id;
    }
    current_trace_id_ = trace_id_;
}

TraceContext::Scope::~Scope() {
    current_trace_id_ = previous_trace_id_;
}

// ============================================================================
// Logger
// ============================================================================

Logger::Logger(const std::string& module, std::shared_ptr<spdlog::logger> logger)
    : module_(module), logger_(std::move(logger)) {}

Logger& Logger::get(const std::string& module) {
    return LogManager::instance().get_logger(module);
}

void Logger::set_level(LogLevel level) {
    if (logger_) {
        logger_->set_level(to_spdlog_level(level));
    }
}

LogLevel Logger::get_level() const {
    if (!logger_) return LogLevel::OFF;

    auto level = logger_->level();
    switch (level) {
        case spdlog::level::trace: return LogLevel::TRACE;
        case spdlog::level::debug: return LogLevel::DEBUG;
        case spdlog::level::info:  return LogLevel::INFO;
        case spdlog::level::warn:  return LogLevel::WARN;
        case spdlog::level::err:   return LogLevel::ERROR;
        case spdlog::level::critical: return LogLevel::FATAL;
        case spdlog::level::off:   return LogLevel::OFF;
        default: return LogLevel::INFO;
    }
}

// ============================================================================
// LogManager
// ============================================================================

LogManager& LogManager::instance() {
    static LogManager instance;
    return instance;
}

LogManager::~LogManager() {
    shutdown();
}

void LogManager::init(const LogConfig& config) {
    std::unique_lock lock(mutex_);

    if (initialized_) {
        // Already initialized, use reload instead
        lock.unlock();
        reload_config(config);
        return;
    }

    config_ = config;
    sinks_.clear();

    // Console sink
    if (config_.console_enabled) {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        if (!config_.console_color) {
            console_sink->set_color_mode(spdlog::color_mode::never);
        }
        sinks_.push_back(console_sink);
    }

    // File sink
    if (config_.file_enabled && !config_.file_path.empty()) {
        try {
            auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                config_.file_path,
                config_.file_max_size,
                config_.file_max_files
            );
            sinks_.push_back(file_sink);
        } catch (const spdlog::spdlog_ex& ex) {
            // If file logging fails, continue with console only
            if (config_.console_enabled) {
                auto console = spdlog::get("console");
                if (console) {
                    console->error("Failed to open log file {}: {}", config_.file_path, ex.what());
                }
            }
        }
    }

    // Set global pattern
    for (auto& sink : sinks_) {
        sink->set_pattern(config_.pattern);
    }

    initialized_ = true;
}

void LogManager::reload_config(const LogConfig& config) {
    std::unique_lock lock(mutex_);

    config_.global_level = config.global_level;
    config_.module_levels = config.module_levels;

    // Update all existing loggers
    for (auto& [name, logger] : loggers_) {
        update_logger_level(name, spdlog::get(name));
    }
}

void LogManager::set_global_level(LogLevel level) {
    std::unique_lock lock(mutex_);
    config_.global_level = level;

    // Update all loggers without module-specific overrides
    for (auto& [name, logger] : loggers_) {
        if (config_.module_levels.find(name) == config_.module_levels.end()) {
            if (auto spdlogger = spdlog::get(name)) {
                spdlogger->set_level(to_spdlog_level(level));
            }
        }
    }
}

LogLevel LogManager::get_global_level() const {
    std::shared_lock lock(mutex_);
    return config_.global_level;
}

void LogManager::set_module_level(const std::string& module, LogLevel level) {
    std::unique_lock lock(mutex_);
    config_.module_levels[module] = level;

    if (auto spdlogger = spdlog::get(module)) {
        spdlogger->set_level(to_spdlog_level(level));
    }
}

std::optional<LogLevel> LogManager::get_module_level(const std::string& module) const {
    std::shared_lock lock(mutex_);
    auto it = config_.module_levels.find(module);
    if (it != config_.module_levels.end()) {
        return it->second;
    }
    return std::nullopt;
}

void LogManager::clear_module_level(const std::string& module) {
    std::unique_lock lock(mutex_);
    config_.module_levels.erase(module);

    // Reset to global level
    if (auto spdlogger = spdlog::get(module)) {
        spdlogger->set_level(to_spdlog_level(config_.global_level));
    }
}

std::unordered_map<std::string, LogLevel> LogManager::get_all_module_levels() const {
    std::shared_lock lock(mutex_);
    return config_.module_levels;
}

void LogManager::flush() {
    spdlog::apply_all([](std::shared_ptr<spdlog::logger> logger) {
        logger->flush();
    });
}

void LogManager::shutdown() {
    std::unique_lock lock(mutex_);
    if (!initialized_) return;

    flush();
    loggers_.clear();
    sinks_.clear();
    spdlog::shutdown();
    initialized_ = false;
}

Logger& LogManager::get_logger(const std::string& module) {
    // Fast path: check if logger exists
    {
        std::shared_lock lock(mutex_);
        auto it = loggers_.find(module);
        if (it != loggers_.end()) {
            return *it->second;
        }
    }

    // Slow path: create new logger
    std::unique_lock lock(mutex_);

    // Double-check after acquiring write lock
    auto it = loggers_.find(module);
    if (it != loggers_.end()) {
        return *it->second;
    }

    auto spdlogger = create_logger(module);
    auto logger = std::unique_ptr<Logger>(new Logger(module, spdlogger));
    auto& ref = *logger;
    loggers_[module] = std::move(logger);

    return ref;
}

std::shared_ptr<spdlog::logger> LogManager::create_logger(const std::string& name) {
    // Check if logger already exists in spdlog registry
    if (auto existing = spdlog::get(name)) {
        update_logger_level(name, existing);
        return existing;
    }

    // Create new logger with shared sinks
    std::shared_ptr<spdlog::logger> logger;

    if (sinks_.empty()) {
        // Not initialized yet, create with default console sink
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_pattern(config_.pattern);
        logger = std::make_shared<spdlog::logger>(name, console_sink);
    } else {
        logger = std::make_shared<spdlog::logger>(name, sinks_.begin(), sinks_.end());
    }

    update_logger_level(name, logger);
    spdlog::register_logger(logger);

    return logger;
}

void LogManager::update_logger_level(const std::string& module,
                                      std::shared_ptr<spdlog::logger> logger) {
    if (!logger) return;

    // Check for module-specific level
    auto it = config_.module_levels.find(module);
    if (it != config_.module_levels.end()) {
        logger->set_level(to_spdlog_level(it->second));
        return;
    }

    // Check for parent module level (e.g., "client.p2p" inherits from "client")
    size_t dot_pos = module.rfind('.');
    while (dot_pos != std::string::npos) {
        std::string parent = module.substr(0, dot_pos);
        auto parent_it = config_.module_levels.find(parent);
        if (parent_it != config_.module_levels.end()) {
            logger->set_level(to_spdlog_level(parent_it->second));
            return;
        }
        dot_pos = parent.rfind('.', dot_pos - 1);
    }

    // Use global level
    logger->set_level(to_spdlog_level(config_.global_level));
}

} // namespace edgelink

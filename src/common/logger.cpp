#include "common/logger.hpp"

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/text_ostream_backend.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/attributes/scoped_attribute.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>

namespace edgelink {

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace expr = boost::log::expressions;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;

// Thread-local trace ID storage
thread_local std::string TraceContext::current_trace_id_;

// Global Boost.Log logger
using boost_logger_t = src::severity_logger_mt<logging::trivial::severity_level>;
static boost_logger_t global_boost_logger;

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

static logging::trivial::severity_level to_boost_severity(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return logging::trivial::trace;
        case LogLevel::DEBUG: return logging::trivial::debug;
        case LogLevel::INFO:  return logging::trivial::info;
        case LogLevel::WARN:  return logging::trivial::warning;
        case LogLevel::ERROR: return logging::trivial::error;
        case LogLevel::FATAL: return logging::trivial::fatal;
        case LogLevel::OFF:   return logging::trivial::fatal;  // Boost.Log doesn't have "off", use fatal
    }
    return logging::trivial::info;
}

static LogLevel from_boost_severity(logging::trivial::severity_level level) {
    switch (level) {
        case logging::trivial::trace: return LogLevel::TRACE;
        case logging::trivial::debug: return LogLevel::DEBUG;
        case logging::trivial::info:  return LogLevel::INFO;
        case logging::trivial::warning: return LogLevel::WARN;
        case logging::trivial::error: return LogLevel::ERROR;
        case logging::trivial::fatal: return LogLevel::FATAL;
    }
    return LogLevel::INFO;
}

// ============================================================================
// TraceContext
// ============================================================================

std::string TraceContext::generate_trace_id() {
    static thread_local std::random_device rd;
    static thread_local std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    uint64_t hi = dis(gen);
    uint64_t lo = dis(gen);

    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(32);  // 128-bit = 32 hex chars

    // 高 64 位
    for (int i = 0; i < 8; ++i) {
        result.push_back(hex[(hi >> (60 - i * 8)) & 0xF]);
        result.push_back(hex[(hi >> (56 - i * 8)) & 0xF]);
    }
    // 低 64 位
    for (int i = 0; i < 8; ++i) {
        result.push_back(hex[(lo >> (60 - i * 8)) & 0xF]);
        result.push_back(hex[(lo >> (56 - i * 8)) & 0xF]);
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

Logger::Logger(const std::string& module)
    : module_(module),
      current_level_(LogManager::instance().resolve_module_level(module)) {}

Logger& Logger::get(const std::string& module) {
    return LogManager::instance().get_logger(module);
}

void Logger::set_level(LogLevel level) {
    current_level_ = level;
}

LogLevel Logger::get_level() const {
    return current_level_;
}

bool Logger::should_log(LogLevel level) const {
    if (current_level_ == LogLevel::OFF) return false;
    return static_cast<int>(level) >= static_cast<int>(current_level_);
}

void Logger::write_log(LogLevel level, const std::string& message) {
    auto boost_level = to_boost_severity(level);

    BOOST_LOG_SEV(global_boost_logger, boost_level)
        << "[" << module_ << "] " << message;
}

// ============================================================================
// LogManager
// ============================================================================

LogManager& LogManager::instance() {
    static LogManager instance;
    return instance;
}

LogManager::LogManager() {
    // Initialize with default console logging
    logging::add_common_attributes();
}

LogManager::~LogManager() {
    shutdown();
}

void LogManager::init(const LogConfig& config) {
    std::unique_lock lock(mutex_);

    if (initialized_) {
        lock.unlock();
        reload_config(config);
        return;
    }

    config_ = config;
    init_boost_log();
    initialized_ = true;
}

void LogManager::init_boost_log() {
    auto core = logging::core::get();

    // Remove all existing sinks
    core->remove_all_sinks();

    // Console sink
    if (config_.console_enabled) {
        auto console_sink = logging::add_console_log(
            std::cout,
            keywords::format = expr::stream
                << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f")
                << " [" << logging::trivial::severity << "] "
                << expr::smessage
        );

        console_sink->set_filter(
            logging::trivial::severity >= to_boost_severity(config_.global_level)
        );
    }

    // File sink
    if (config_.file_enabled && !config_.file_path.empty()) {
        try {
            auto file_sink = logging::add_file_log(
                keywords::file_name = config_.file_path,
                keywords::rotation_size = config_.file_max_size,
                keywords::format = expr::stream
                    << expr::format_date_time<boost::posix_time::ptime>("TimeStamp", "%Y-%m-%d %H:%M:%S.%f")
                    << " [" << logging::trivial::severity << "] "
                    << expr::smessage
            );

            file_sink->set_filter(
                logging::trivial::severity >= to_boost_severity(config_.global_level)
            );
        } catch (const std::exception& ex) {
            std::cerr << "Failed to open log file " << config_.file_path << ": " << ex.what() << std::endl;
        }
    }
}

void LogManager::reload_config(const LogConfig& config) {
    std::unique_lock lock(mutex_);

    config_.global_level = config.global_level;
    config_.module_levels = config.module_levels;

    // Update all existing loggers
    for (auto& [name, logger] : loggers_) {
        logger->set_level(resolve_module_level(name));
    }

    // Update Boost.Log core filter
    auto core = logging::core::get();
    core->set_filter(
        logging::trivial::severity >= to_boost_severity(config_.global_level)
    );
}

void LogManager::set_global_level(LogLevel level) {
    std::unique_lock lock(mutex_);
    config_.global_level = level;

    // Update all loggers without module-specific overrides
    for (auto& [name, logger] : loggers_) {
        if (config_.module_levels.find(name) == config_.module_levels.end()) {
            logger->set_level(level);
        }
    }

    // Update Boost.Log core filter
    auto core = logging::core::get();
    core->set_filter(
        logging::trivial::severity >= to_boost_severity(level)
    );
}

LogLevel LogManager::get_global_level() const {
    std::shared_lock lock(mutex_);
    return config_.global_level;
}

void LogManager::set_module_level(const std::string& module, LogLevel level) {
    std::unique_lock lock(mutex_);
    config_.module_levels[module] = level;

    auto it = loggers_.find(module);
    if (it != loggers_.end()) {
        it->second->set_level(level);
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

    auto it = loggers_.find(module);
    if (it != loggers_.end()) {
        it->second->set_level(resolve_module_level(module));
    }
}

std::unordered_map<std::string, LogLevel> LogManager::get_all_module_levels() const {
    std::shared_lock lock(mutex_);
    return config_.module_levels;
}

void LogManager::flush() {
    logging::core::get()->flush();
}

void LogManager::shutdown() {
    std::unique_lock lock(mutex_);
    if (!initialized_) return;

    flush();
    loggers_.clear();
    logging::core::get()->remove_all_sinks();
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

    auto logger = std::unique_ptr<Logger>(new Logger(module));
    auto& ref = *logger;
    loggers_[module] = std::move(logger);

    return ref;
}

LogLevel LogManager::resolve_module_level(const std::string& module) const {
    // Check for module-specific level
    auto it = config_.module_levels.find(module);
    if (it != config_.module_levels.end()) {
        return it->second;
    }

    // Check for parent module level (e.g., "client.p2p" inherits from "client")
    size_t dot_pos = module.rfind('.');
    while (dot_pos != std::string::npos) {
        std::string parent = module.substr(0, dot_pos);
        auto parent_it = config_.module_levels.find(parent);
        if (parent_it != config_.module_levels.end()) {
            return parent_it->second;
        }
        dot_pos = parent.rfind('.', dot_pos - 1);
    }

    // Use global level
    return config_.global_level;
}

} // namespace edgelink

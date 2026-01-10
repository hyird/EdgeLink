#pragma once

// Undefine Windows ERROR macro to avoid conflict with LogLevel::ERROR
#ifdef ERROR
#undef ERROR
#endif

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <random>

namespace edgelink {

// Log levels matching spdlog
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5,
    OFF = 6,
};

LogLevel log_level_from_string(std::string_view str);
std::string_view log_level_to_string(LogLevel level);
spdlog::level::level_enum to_spdlog_level(LogLevel level);

// Distributed tracing context (thread-local)
class TraceContext {
public:
    // Generate new trace ID
    static std::string generate_trace_id();

    // Set current trace ID for this thread
    static void set_trace_id(const std::string& trace_id);

    // Get current trace ID (empty if none)
    static const std::string& get_trace_id();

    // Clear current trace ID
    static void clear_trace_id();

    // RAII helper for scoped trace
    class Scope {
    public:
        explicit Scope(const std::string& trace_id = "");
        ~Scope();
        Scope(const Scope&) = delete;
        Scope& operator=(const Scope&) = delete;

        const std::string& trace_id() const { return trace_id_; }

    private:
        std::string trace_id_;
        std::string previous_trace_id_;
    };

private:
    static thread_local std::string current_trace_id_;
};

// Forward declaration
class LogManager;

// Log configuration
struct LogConfig {
    LogLevel global_level = LogLevel::INFO;

    // Console output
    bool console_enabled = true;
    bool console_color = true;

    // File output
    bool file_enabled = false;
    std::string file_path;
    size_t file_max_size = 100 * 1024 * 1024;  // 100MB
    size_t file_max_files = 10;

    // Async logging
    bool async_enabled = true;
    size_t async_queue_size = 8192;

    // Module-specific levels
    std::unordered_map<std::string, LogLevel> module_levels;

    // Log format (not used if JSON format)
    std::string pattern = "[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%n] [%t] %v";

    // JSON format output
    bool json_format = false;
};

// Logger wrapper for a specific module
class Logger {
public:
    // Get logger for a module (creates if not exists)
    static Logger& get(const std::string& module);

    // Logging methods with trace ID support
    template<typename... Args>
    void trace(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        log_impl(LogLevel::TRACE, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        log_impl(LogLevel::DEBUG, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        log_impl(LogLevel::INFO, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warn(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        log_impl(LogLevel::WARN, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        log_impl(LogLevel::ERROR, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void fatal(spdlog::format_string_t<Args...> fmt, Args&&... args) {
        log_impl(LogLevel::FATAL, fmt, std::forward<Args>(args)...);
    }

    // Set/get level for this logger
    void set_level(LogLevel level);
    LogLevel get_level() const;

    // Module name
    const std::string& module() const { return module_; }

private:
    friend class LogManager;
    Logger(const std::string& module, std::shared_ptr<spdlog::logger> logger);

    template<typename... Args>
    void log_impl(LogLevel level, spdlog::format_string_t<Args...> fmt, Args&&... args) {
        if (!logger_) return;

        auto spdlog_level = to_spdlog_level(level);
        if (!logger_->should_log(spdlog_level)) return;

        // Add trace ID prefix if present
        const auto& trace_id = TraceContext::get_trace_id();
        if (!trace_id.empty()) {
            std::string msg = fmt::format(fmt, std::forward<Args>(args)...);
            logger_->log(spdlog_level, "[trace:{}] {}", trace_id.substr(0, 8), msg);
        } else {
            logger_->log(spdlog_level, fmt, std::forward<Args>(args)...);
        }
    }

    std::string module_;
    std::shared_ptr<spdlog::logger> logger_;
};

// Global log manager
class LogManager {
public:
    // Get singleton instance
    static LogManager& instance();

    // Initialize with config
    void init(const LogConfig& config);

    // Reload config (for hot reload)
    void reload_config(const LogConfig& config);

    // Set global log level
    void set_global_level(LogLevel level);
    LogLevel get_global_level() const;

    // Set module-specific level
    void set_module_level(const std::string& module, LogLevel level);
    std::optional<LogLevel> get_module_level(const std::string& module) const;
    void clear_module_level(const std::string& module);

    // Get all module levels
    std::unordered_map<std::string, LogLevel> get_all_module_levels() const;

    // Flush all loggers
    void flush();

    // Shutdown
    void shutdown();

    // Get or create logger for module
    Logger& get_logger(const std::string& module);

    // Check if initialized
    bool is_initialized() const { return initialized_; }

private:
    LogManager() = default;
    ~LogManager();

    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;

    std::shared_ptr<spdlog::logger> create_logger(const std::string& name);
    void update_logger_level(const std::string& module, std::shared_ptr<spdlog::logger> logger);

    mutable std::shared_mutex mutex_;
    bool initialized_ = false;
    LogConfig config_;

    std::vector<spdlog::sink_ptr> sinks_;
    std::unordered_map<std::string, std::unique_ptr<Logger>> loggers_;
};

// Convenience macros that enforce using the Logger class
// Usage: LOG_INFO("module.submodule", "message {}", arg);

#define LOG_TRACE(module, ...) ::edgelink::Logger::get(module).trace(__VA_ARGS__)
#define LOG_DEBUG(module, ...) ::edgelink::Logger::get(module).debug(__VA_ARGS__)
#define LOG_INFO(module, ...)  ::edgelink::Logger::get(module).info(__VA_ARGS__)
#define LOG_WARN(module, ...)  ::edgelink::Logger::get(module).warn(__VA_ARGS__)
#define LOG_ERROR(module, ...) ::edgelink::Logger::get(module).error(__VA_ARGS__)
#define LOG_FATAL(module, ...) ::edgelink::Logger::get(module).fatal(__VA_ARGS__)

} // namespace edgelink

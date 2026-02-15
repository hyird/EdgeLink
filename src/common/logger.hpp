#pragma once

// Undefine Windows ERROR macro to avoid conflict with LogLevel::ERROR
#ifdef ERROR
#undef ERROR
#endif

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <optional>
#include <random>
#include <sstream>

namespace edgelink {

// Log levels
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
    void trace(std::format_string<Args...> fmt_str, Args&&... args) {
        log_impl(LogLevel::TRACE, fmt_str, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(std::format_string<Args...> fmt_str, Args&&... args) {
        log_impl(LogLevel::DEBUG, fmt_str, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(std::format_string<Args...> fmt_str, Args&&... args) {
        log_impl(LogLevel::INFO, fmt_str, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warn(std::format_string<Args...> fmt_str, Args&&... args) {
        log_impl(LogLevel::WARN, fmt_str, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(std::format_string<Args...> fmt_str, Args&&... args) {
        log_impl(LogLevel::ERROR, fmt_str, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void fatal(std::format_string<Args...> fmt_str, Args&&... args) {
        log_impl(LogLevel::FATAL, fmt_str, std::forward<Args>(args)...);
    }

    // Set/get level for this logger
    void set_level(LogLevel level);
    LogLevel get_level() const;

    // Module name
    const std::string& module() const { return module_; }

private:
    friend class LogManager;
    Logger(const std::string& module);

    template<typename... Args>
    void log_impl(LogLevel level, std::format_string<Args...> fmt_str, Args&&... args) {
        if (!should_log(level)) return;

        std::string msg = std::format(fmt_str, std::forward<Args>(args)...);

        // Add trace ID prefix if present
        const auto& trace_id = TraceContext::get_trace_id();
        if (!trace_id.empty()) {
            msg = std::format("[trace:{}] {}", trace_id.substr(0, 8), msg);
        }

        write_log(level, msg);
    }

    bool should_log(LogLevel level) const;
    void write_log(LogLevel level, const std::string& message);

    std::string module_;
    LogLevel current_level_;
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

    // Resolve effective log level for a module
    LogLevel resolve_module_level(const std::string& module) const;

private:
    LogManager();
    ~LogManager();

    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;
    void init_boost_log();

    mutable std::shared_mutex mutex_;
    bool initialized_ = false;
    LogConfig config_;

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

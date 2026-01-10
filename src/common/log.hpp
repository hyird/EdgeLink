#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/fmt/ostr.h>
#include <memory>
#include <string>
#include <source_location>

namespace edgelink {
namespace log {

// ============================================================================
// Logger Names
// ============================================================================
constexpr const char* MAIN_LOGGER = "edgelink";
constexpr const char* CONTROLLER_LOGGER = "controller";
constexpr const char* SERVER_LOGGER = "server";
constexpr const char* CLIENT_LOGGER = "client";
constexpr const char* CRYPTO_LOGGER = "crypto";
constexpr const char* NETWORK_LOGGER = "network";
constexpr const char* PROTOCOL_LOGGER = "protocol";
constexpr const char* RELAY_LOGGER = "relay";
constexpr const char* P2P_LOGGER = "p2p";
constexpr const char* STUN_LOGGER = "stun";

// ============================================================================
// Log Levels (runtime configurable)
// ============================================================================
enum class Level {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
    Off = 6
};

// ============================================================================
// Log Configuration
// ============================================================================
struct LogConfig {
    Level level{Level::Info};
    std::string pattern{"[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] [%t] %v"};
    bool console{true};
    std::string file_path;
    size_t max_file_size{10 * 1024 * 1024};  // 10 MB
    size_t max_files{5};
};

// ============================================================================
// Initialization
// ============================================================================

// Initialize logging with the given configuration
void init(const LogConfig& config = LogConfig{});

// Initialize logging from environment variables
// EDGELINK_LOG_LEVEL: trace, debug, info, warn, error, critical
// EDGELINK_LOG_FILE: path to log file
void init_from_env();

// Get a logger by name, creates if doesn't exist
std::shared_ptr<spdlog::logger> get(const std::string& name = MAIN_LOGGER);

// Set log level for all loggers (runtime configurable)
void set_level(Level level);

// Get current log level
Level get_level();

// Check if a level is enabled (for conditional logging)
bool is_level_enabled(Level level);

// Flush all loggers
void flush();

// Shutdown logging
void shutdown();

// Convert Level to spdlog level
spdlog::level::level_enum to_spdlog_level(Level level);

// Convert spdlog level to Level
Level from_spdlog_level(spdlog::level::level_enum level);

// ============================================================================
// Runtime Logging Functions (no macros, runtime level check)
// ============================================================================

namespace detail {

// Source location helper for logging with file/line info
struct SourceLoc {
    const char* file;
    int line;
    const char* func;

    SourceLoc(const char* f = __builtin_FILE(),
              int l = __builtin_LINE(),
              const char* fn = __builtin_FUNCTION())
        : file(f), line(l), func(fn) {}
};

// Get just the filename from a full path
inline const char* extract_filename(const char* path) {
    const char* file = path;
    while (*path) {
        if (*path == '/' || *path == '\\') {
            file = path + 1;
        }
        ++path;
    }
    return file;
}

} // namespace detail

// ============================================================================
// Template logging functions - check level at runtime
// ============================================================================

template<typename... Args>
inline void trace(fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Trace)) {
        get()->trace(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void debug(fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Debug)) {
        get()->debug(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void info(fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Info)) {
        get()->info(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void warn(fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Warn)) {
        get()->warn(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void error(fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Error)) {
        get()->error(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void critical(fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Critical)) {
        get()->critical(fmt, std::forward<Args>(args)...);
    }
}

// ============================================================================
// Named logger template functions
// ============================================================================

template<typename... Args>
inline void trace(const std::string& logger_name, fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Trace)) {
        get(logger_name)->trace(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void debug(const std::string& logger_name, fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Debug)) {
        get(logger_name)->debug(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void info(const std::string& logger_name, fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Info)) {
        get(logger_name)->info(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void warn(const std::string& logger_name, fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Warn)) {
        get(logger_name)->warn(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void error(const std::string& logger_name, fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Error)) {
        get(logger_name)->error(fmt, std::forward<Args>(args)...);
    }
}

template<typename... Args>
inline void critical(const std::string& logger_name, fmt::format_string<Args...> fmt, Args&&... args) {
    if (is_level_enabled(Level::Critical)) {
        get(logger_name)->critical(fmt, std::forward<Args>(args)...);
    }
}

// ============================================================================
// Logger class for component-specific logging
// ============================================================================

class Logger {
public:
    explicit Logger(const std::string& name) : name_(name) {}

    template<typename... Args>
    void trace(fmt::format_string<Args...> fmt, Args&&... args) const {
        if (is_level_enabled(Level::Trace)) {
            get(name_)->trace(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void debug(fmt::format_string<Args...> fmt, Args&&... args) const {
        if (is_level_enabled(Level::Debug)) {
            get(name_)->debug(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void info(fmt::format_string<Args...> fmt, Args&&... args) const {
        if (is_level_enabled(Level::Info)) {
            get(name_)->info(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void warn(fmt::format_string<Args...> fmt, Args&&... args) const {
        if (is_level_enabled(Level::Warn)) {
            get(name_)->warn(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void error(fmt::format_string<Args...> fmt, Args&&... args) const {
        if (is_level_enabled(Level::Error)) {
            get(name_)->error(fmt, std::forward<Args>(args)...);
        }
    }

    template<typename... Args>
    void critical(fmt::format_string<Args...> fmt, Args&&... args) const {
        if (is_level_enabled(Level::Critical)) {
            get(name_)->critical(fmt, std::forward<Args>(args)...);
        }
    }

    const std::string& name() const { return name_; }

private:
    std::string name_;
};

// ============================================================================
// Backward Compatibility Macros (deprecated, will be removed)
// These macros now call runtime functions
// ============================================================================

#define LOG_TRACE(...) ::edgelink::log::trace(__VA_ARGS__)
#define LOG_DEBUG(...) ::edgelink::log::debug(__VA_ARGS__)
#define LOG_INFO(...) ::edgelink::log::info(__VA_ARGS__)
#define LOG_WARN(...) ::edgelink::log::warn(__VA_ARGS__)
#define LOG_ERROR(...) ::edgelink::log::error(__VA_ARGS__)
#define LOG_CRITICAL(...) ::edgelink::log::critical(__VA_ARGS__)

#define NLOG_TRACE(name, ...) ::edgelink::log::trace(name, __VA_ARGS__)
#define NLOG_DEBUG(name, ...) ::edgelink::log::debug(name, __VA_ARGS__)
#define NLOG_INFO(name, ...) ::edgelink::log::info(name, __VA_ARGS__)
#define NLOG_WARN(name, ...) ::edgelink::log::warn(name, __VA_ARGS__)
#define NLOG_ERROR(name, ...) ::edgelink::log::error(name, __VA_ARGS__)
#define NLOG_CRITICAL(name, ...) ::edgelink::log::critical(name, __VA_ARGS__)

} // namespace log
} // namespace edgelink

#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/fmt/ostr.h>
#include <memory>
#include <string>

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

// ============================================================================
// Log Configuration
// ============================================================================
struct LogConfig {
    spdlog::level::level_enum level{spdlog::level::info};
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

// Set log level for all loggers
void set_level(spdlog::level::level_enum level);

// Flush all loggers
void flush();

// Shutdown logging
void shutdown();

// ============================================================================
// Convenience Macros
// ============================================================================

#define LOG_TRACE(...) SPDLOG_LOGGER_TRACE(::edgelink::log::get(), __VA_ARGS__)
#define LOG_DEBUG(...) SPDLOG_LOGGER_DEBUG(::edgelink::log::get(), __VA_ARGS__)
#define LOG_INFO(...) SPDLOG_LOGGER_INFO(::edgelink::log::get(), __VA_ARGS__)
#define LOG_WARN(...) SPDLOG_LOGGER_WARN(::edgelink::log::get(), __VA_ARGS__)
#define LOG_ERROR(...) SPDLOG_LOGGER_ERROR(::edgelink::log::get(), __VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_LOGGER_CRITICAL(::edgelink::log::get(), __VA_ARGS__)

// Named logger macros
#define NLOG_TRACE(name, ...) SPDLOG_LOGGER_TRACE(::edgelink::log::get(name), __VA_ARGS__)
#define NLOG_DEBUG(name, ...) SPDLOG_LOGGER_DEBUG(::edgelink::log::get(name), __VA_ARGS__)
#define NLOG_INFO(name, ...) SPDLOG_LOGGER_INFO(::edgelink::log::get(name), __VA_ARGS__)
#define NLOG_WARN(name, ...) SPDLOG_LOGGER_WARN(::edgelink::log::get(name), __VA_ARGS__)
#define NLOG_ERROR(name, ...) SPDLOG_LOGGER_ERROR(::edgelink::log::get(name), __VA_ARGS__)
#define NLOG_CRITICAL(name, ...) SPDLOG_LOGGER_CRITICAL(::edgelink::log::get(name), __VA_ARGS__)

} // namespace log
} // namespace edgelink

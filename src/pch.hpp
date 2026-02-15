#pragma once

// Windows version target (must be before any Windows/Boost includes)
// Required to match vcpkg's Boost.Log ABI namespace (v2s_mt_nt62)
#ifdef _WIN32
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0A00  // Windows 10
#  endif
#  ifndef WINVER
#    define WINVER _WIN32_WINNT
#  endif
#endif

// Boost configuration (must be before any Boost includes)
#define BOOST_USE_WINDOWS_H
#define BOOST_ATOMIC_DETAIL_WAIT_BACKEND_GENERIC

// Force Boost.WinAPI version to Win8+ to match vcpkg-built Boost.Log ABI (v2s_mt_nt62)
#ifndef BOOST_USE_WINAPI_VERSION
#  define BOOST_USE_WINAPI_VERSION 0x0A00
#endif

// Note: BOOST_LOG_NO_LIB and BOOST_LOG_STATIC_LINK are set by CMake
// via Boost::log target's INTERFACE_COMPILE_DEFINITIONS

// Standard Library
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <filesystem>
#include <format>
#include <functional>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

// Boost.Asio
#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>

// Boost.Cobalt (Coroutines)
#include <boost/cobalt.hpp>
#include <boost/cobalt/race.hpp>
#include <boost/cobalt/gather.hpp>

// Boost.Beast
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

// Boost.URL
#include <boost/url.hpp>

// Boost.JSON
#include <boost/json.hpp>

// Namespace aliases
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
namespace http = beast::http;

using tcp = asio::ip::tcp;
using error_code = boost::system::error_code;

using namespace std::chrono_literals;
using namespace asio::experimental::awaitable_operators;

// Precompiled Header for EdgeLink
// This file includes commonly used headers to speed up compilation
#pragma once

// C Standard Library
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <csignal>

// C++ Standard Library - Core
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

// Boost
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/json.hpp>

// spdlog
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

// nlohmann/json
#include <nlohmann/json.hpp>

// gRPC / Protobuf
#include <grpcpp/grpcpp.h>
#include <google/protobuf/message.h>

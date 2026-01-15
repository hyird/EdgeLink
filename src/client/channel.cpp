#include "client/channel.hpp"
#include "common/logger.hpp"
#include <chrono>
#include <optional>

#ifdef _WIN32
// winsock2.h must be included before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#ifdef __APPLE__
#include <sys/param.h>
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif
#endif
#endif

namespace edgelink::client {

namespace {

auto& log() { return Logger::get("client.channel"); }

// Get system hostname (cross-platform)
std::string get_hostname() {
#ifdef _WIN32
    char buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) {
        return std::string(buffer, size);
    }
    return "unknown";
#else
    char buffer[HOST_NAME_MAX + 1];
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        buffer[sizeof(buffer) - 1] = '\0';
        return buffer;
    }
    return "unknown";
#endif
}

// Get OS name
std::string get_os_name() {
#ifdef _WIN32
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

// Get architecture
std::string get_arch() {
#if defined(__x86_64__) || defined(_M_X64)
    return "amd64";
#elif defined(__i386__) || defined(_M_IX86)
    return "386";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "arm64";
#elif defined(__arm__) || defined(_M_ARM)
    return "arm";
#else
    return "unknown";
#endif
}

// Check if IPv6 is available on this system using a simple socket test
// This must be called BEFORE any io_context is running to avoid thread-local storage conflicts
// Returns true if the system has IPv6 support
bool is_ipv6_available() {
    static std::optional<bool> cached_result;

    // Cache the result to avoid repeated checks
    if (cached_result.has_value()) {
        return *cached_result;
    }

    // Use raw socket API to avoid io_context conflicts
    // Try to create an IPv6 socket using POSIX/Windows API
#ifdef _WIN32
    SOCKET sock = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        cached_result = false;
        log().info("IPv6 not available on this system (socket creation failed)");
        return false;
    }
    ::closesocket(sock);
#else
    int sock = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        cached_result = false;
        log().info("IPv6 not available on this system (socket creation failed)");
        return false;
    }
    ::close(sock);
#endif

    cached_result = true;
    log().debug("IPv6 is available on this system");
    return true;
}

// Happy Eyeballs连接策略：快速尝试多个endpoints
// 使用短超时顺序尝试，实现快速故障转移
// 自动过滤不可用的地址族（如 IPv6 不可用时跳过所有 IPv6 地址）
// 参数：
//   stream - TCP stream（lowest layer）
//   endpoints - DNS解析的endpoint列表
//   per_endpoint_timeout - 每个endpoint的超时时间
// 返回：成功连接的endpoint，或nullopt（全部失败）
template<typename Stream>
asio::awaitable<std::optional<tcp::endpoint>> async_connect_happy_eyeballs(
    Stream& stream,
    const tcp::resolver::results_type& endpoints,
    std::chrono::milliseconds per_endpoint_timeout) {

    bool ipv6_available = is_ipv6_available();
    size_t ipv6_skipped = 0;

    for (const auto& ep : endpoints) {
        auto endpoint = ep.endpoint();

        // Skip IPv6 addresses if IPv6 is not available
        if (!ipv6_available && endpoint.address().is_v6()) {
            ipv6_skipped++;
            continue;
        }

        try {
            log().debug("尝试连接 {} (超时{}ms)",
                       endpoint.address().to_string(),
                       per_endpoint_timeout.count());

            // Ensure socket is closed before attempting connection
            // This is critical when switching between IPv4 and IPv6
            boost::system::error_code close_ec;
            if (stream.socket().is_open()) {
                stream.socket().close(close_ec);
            }

            stream.expires_after(per_endpoint_timeout);
            co_await stream.async_connect(endpoint, asio::use_awaitable);

            log().info("成功连接到 {}", endpoint.address().to_string());
            co_return endpoint;

        } catch (const boost::system::system_error& e) {
            log().debug("连接 {} 失败: {}",
                       endpoint.address().to_string(),
                       e.what());

            // Ensure socket is closed after failure
            boost::system::error_code close_ec;
            if (stream.socket().is_open()) {
                stream.socket().close(close_ec);
            }
            // 继续尝试下一个endpoint
        } catch (...) {
            log().debug("连接 {} 失败: 未知错误",
                       endpoint.address().to_string());

            // Ensure socket is closed after failure
            boost::system::error_code close_ec;
            if (stream.socket().is_open()) {
                stream.socket().close(close_ec);
            }
        }
    }

    if (ipv6_skipped > 0) {
        log().info("Skipped {} IPv6 address(es) (IPv6 not available)", ipv6_skipped);
    }

    log().error("所有endpoint连接失败");
    co_return std::nullopt;
}

} // anonymous namespace

const char* channel_state_name(ChannelState state) {
    switch (state) {
        case ChannelState::DISCONNECTED: return "DISCONNECTED";
        case ChannelState::CONNECTING: return "CONNECTING";
        case ChannelState::AUTHENTICATING: return "AUTHENTICATING";
        case ChannelState::CONNECTED: return "CONNECTED";
        case ChannelState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// ControlChannel Implementation
// ============================================================================

ControlChannel::ControlChannel(asio::io_context& ioc, ssl::context& ssl_ctx,
                               CryptoEngine& crypto, const std::string& url, bool use_tls)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , url_(url)
    , use_tls_(use_tls)
    , write_timer_(ioc)
    , endpoint_ack_timer_(std::make_unique<asio::steady_timer>(ioc)) {
    write_timer_.expires_at(std::chrono::steady_clock::time_point::max());
}

void ControlChannel::set_channels(ControlChannelEvents channels) {
    channels_ = channels;
}

bool ControlChannel::is_ws_open() const {
    if (use_tls_) {
        return tls_ws_ && tls_ws_->is_open();
    } else {
        return plain_ws_ && plain_ws_->is_open();
    }
}

asio::awaitable<bool> ControlChannel::connect(const std::string& authkey) {
    authkey_ = authkey;

    try {
        state_ = ChannelState::CONNECTING;

        // Parse URL
        auto parsed = boost::urls::parse_uri(url_);
        if (!parsed) {
            log().error("Invalid control URL: {}", url_);
            co_return false;
        }

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls_ ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/control";

        log().info("Connecting to controller: {}:{}{} (TLS: {})",
                     host, port, target, use_tls_ ? "yes" : "no");

        // Resolve host
        auto dns_start = std::chrono::steady_clock::now();
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);
        auto dns_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - dns_start).count();

        // 记录所有解析的 endpoints
        size_t endpoint_count = 0;
        std::string endpoint_list;
        for (const auto& ep : endpoints) {
            if (endpoint_count > 0) endpoint_list += ", ";
            endpoint_list += ep.endpoint().address().to_string() + ":" + std::to_string(ep.endpoint().port());
            endpoint_count++;
        }
        log().debug("DNS resolved to {} endpoint(s): {}", endpoint_count, endpoint_list);
        log().debug("DNS resolution took {} ms", dns_elapsed);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                log().error("Failed to set SNI");
                co_return false;
            }

            // Connect TCP - 使用Happy Eyeballs策略快速尝试多个endpoint
            auto tcp_start = std::chrono::steady_clock::now();
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);

            // 每个endpoint的超时时间：5秒（比原来的30秒短得多）
            auto connected_ep = co_await async_connect_happy_eyeballs(
                tcp_stream, endpoints, std::chrono::seconds(5));

            if (!connected_ep) {
                log().error("所有 endpoint 连接失败");
                co_return false;
            }

            auto tcp_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tcp_start).count();
            log().debug("TCP connected to {} in {} ms",
                       connected_ep->address().to_string(), tcp_elapsed);

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            auto tls_start = std::chrono::steady_clock::now();
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);
            auto tls_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tls_start).count();
            log().debug("TLS handshake completed in {} ms", tls_elapsed);

            // WebSocket handshake
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            tls_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            auto ws_start = std::chrono::steady_clock::now();
            co_await tls_ws_->async_handshake(host, target, asio::use_awaitable);
            auto ws_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - ws_start).count();
            log().debug("WebSocket handshake completed in {} ms", ws_elapsed);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*tls_ws_).expires_never();
            tls_ws_->binary(true);

        } else {
            // Create plain stream
            plain_ws_ = std::make_unique<PlainWsStream>(ioc_);

            // Connect TCP - 使用Happy Eyeballs策略
            auto tcp_start = std::chrono::steady_clock::now();
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);

            auto connected_ep = co_await async_connect_happy_eyeballs(
                tcp_stream, endpoints, std::chrono::seconds(5));

            if (!connected_ep) {
                log().error("所有 endpoint 连接失败");
                co_return false;
            }

            auto tcp_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tcp_start).count();
            log().debug("TCP connected to {} in {} ms",
                       connected_ep->address().to_string(), tcp_elapsed);

            // WebSocket handshake
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            plain_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await plain_ws_->async_handshake(host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().info("WebSocket connected, authenticating...");
        state_ = ChannelState::AUTHENTICATING;

        // Build AUTH_REQUEST
        AuthRequest req;
        req.auth_type = AuthType::AUTHKEY;
        req.machine_key = crypto_.machine_key().public_key;
        req.node_key = crypto_.node_key().public_key;
        req.hostname = get_hostname();
        req.os = get_os_name();
        req.arch = get_arch();
        req.version = "1.0.0";
        req.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        req.connection_id = 0;  // Controller 连接不使用 connection_id（单连接控制通道）
        req.auth_data = std::vector<uint8_t>(authkey_.begin(), authkey_.end());

        // Sign the request
        auto sign_data = req.get_sign_data();
        auto sig = crypto_.sign(sign_data);
        if (!sig) {
            log().error("Failed to sign AUTH_REQUEST");
            co_return false;
        }
        req.signature = *sig;

        // Send AUTH_REQUEST
        auto payload = req.serialize();
        co_await send_frame(FrameType::AUTH_REQUEST, payload);

        // Start read/write loops
        asio::co_spawn(ioc_, [self = shared_from_this()]() -> asio::awaitable<void> {
            co_await self->read_loop();
        }, asio::detached);

        asio::co_spawn(ioc_, [self = shared_from_this()]() -> asio::awaitable<void> {
            co_await self->write_loop();
        }, asio::detached);

        co_return true;

    } catch (const std::exception& e) {
        log().error("Control channel connection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<bool> ControlChannel::reconnect() {
    // Reconnect using machine key authentication (for already registered nodes)
    if (node_id_ == 0) {
        log().error("Cannot reconnect: not previously authenticated");
        co_return false;
    }

    try {
        state_ = ChannelState::RECONNECTING;

        // Close existing connection if any
        try {
            if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
                co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
            } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
                co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
            }
        } catch (const std::exception& e) {
            log().debug("Failed to close WebSocket before reconnect: {}", e.what());
        } catch (...) {
            log().debug("Failed to close WebSocket before reconnect: unknown error");
        }

        // Reset stream pointers
        tls_ws_.reset();
        plain_ws_.reset();

        // Parse URL
        auto parsed = boost::urls::parse_uri(url_);
        if (!parsed) {
            log().error("Invalid control URL: {}", url_);
            state_ = ChannelState::DISCONNECTED;
            co_return false;
        }

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls_ ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/control";

        log().info("Reconnecting to controller: {}:{}{} (TLS: {})",
                     host, port, target, use_tls_ ? "yes" : "no");

        // Resolve host
        auto dns_start = std::chrono::steady_clock::now();
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);
        auto dns_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - dns_start).count();

        // 记录所有解析的 endpoints
        size_t endpoint_count = 0;
        std::string endpoint_list;
        for (const auto& ep : endpoints) {
            if (endpoint_count > 0) endpoint_list += ", ";
            endpoint_list += ep.endpoint().address().to_string() + ":" + std::to_string(ep.endpoint().port());
            endpoint_count++;
        }
        log().debug("DNS resolved to {} endpoint(s): {}", endpoint_count, endpoint_list);
        log().debug("DNS resolution took {} ms", dns_elapsed);

        // 生成此连接的唯一标识符
        ConnectionId connection_id = static_cast<ConnectionId>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFF);
        log().debug("Assigned connection_id: 0x{:08x}", connection_id);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                log().error("Failed to set SNI");
                state_ = ChannelState::DISCONNECTED;
                co_return false;
            }

            // Connect TCP - 使用Happy Eyeballs策略
            auto tcp_start = std::chrono::steady_clock::now();
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);

            auto connected_ep = co_await async_connect_happy_eyeballs(
                tcp_stream, endpoints, std::chrono::seconds(5));

            if (!connected_ep) {
                log().error("所有 endpoint 重连失败");
                state_ = ChannelState::DISCONNECTED;
                co_return false;
            }

            auto tcp_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tcp_start).count();
            log().debug("TCP reconnected to {} in {} ms",
                       connected_ep->address().to_string(), tcp_elapsed);

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            auto tls_start = std::chrono::steady_clock::now();
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);
            auto tls_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tls_start).count();
            log().debug("TLS handshake completed in {} ms", tls_elapsed);

            // WebSocket handshake
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            tls_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await tls_ws_->async_handshake(host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*tls_ws_).expires_never();
            tls_ws_->binary(true);

        } else {
            // Create plain stream
            plain_ws_ = std::make_unique<PlainWsStream>(ioc_);

            // Connect TCP - 使用Happy Eyeballs策略
            auto tcp_start = std::chrono::steady_clock::now();
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);

            auto connected_ep = co_await async_connect_happy_eyeballs(
                tcp_stream, endpoints, std::chrono::seconds(5));

            if (!connected_ep) {
                log().error("所有 endpoint 重连失败");
                state_ = ChannelState::DISCONNECTED;
                co_return false;
            }

            auto tcp_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tcp_start).count();
            log().debug("TCP reconnected to {} in {} ms",
                       connected_ep->address().to_string(), tcp_elapsed);

            // WebSocket handshake
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            plain_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await plain_ws_->async_handshake(host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().info("WebSocket reconnected, authenticating with machine key...");
        state_ = ChannelState::AUTHENTICATING;

        // Build AUTH_REQUEST with MACHINE auth type (no authkey needed)
        AuthRequest req;
        req.auth_type = AuthType::MACHINE;
        req.machine_key = crypto_.machine_key().public_key;
        req.node_key = crypto_.node_key().public_key;
        req.hostname = get_hostname();
        req.os = get_os_name();
        req.arch = get_arch();
        req.version = "1.0.0";
        req.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        req.connection_id = connection_id;  // 设置连接标识符
        // auth_data is empty for MACHINE auth type

        // Sign the request
        auto sign_data = req.get_sign_data();
        auto sig = crypto_.sign(sign_data);
        if (!sig) {
            log().error("Failed to sign AUTH_REQUEST");
            state_ = ChannelState::DISCONNECTED;
            co_return false;
        }
        req.signature = *sig;

        // Send AUTH_REQUEST
        auto payload = req.serialize();
        co_await send_frame(FrameType::AUTH_REQUEST, payload);

        // Start read/write loops
        asio::co_spawn(ioc_, [self = shared_from_this()]() -> asio::awaitable<void> {
            co_await self->read_loop();
        }, asio::detached);

        asio::co_spawn(ioc_, [self = shared_from_this()]() -> asio::awaitable<void> {
            co_await self->write_loop();
        }, asio::detached);

        co_return true;

    } catch (const std::exception& e) {
        log().error("Control channel reconnection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<void> ControlChannel::close() {
    if (state_ == ChannelState::DISCONNECTED) {
        co_return;
    }

    state_ = ChannelState::DISCONNECTED;

    // 使用超时保护的关闭操作，避免卡住
    try {
        asio::steady_timer timeout_timer(ioc_);
        timeout_timer.expires_after(std::chrono::seconds(3));

        bool closed = false;

        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            // 尝试优雅关闭，但有超时保护
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool close_completed = false;
            asio::co_spawn(ioc_, [this, &close_completed]() -> asio::awaitable<void> {
                try {
                    co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
                    close_completed = true;
                } catch (...) {}
            }, asio::detached);

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(asio::use_awaitable);
            }

            closed = close_completed;
            if (!closed) {
                // 超时，直接关闭底层连接
                log().debug("WebSocket close timeout, forcing shutdown");
                boost::system::error_code ec;
                tls_ws_->next_layer().next_layer().socket().close(ec);
            }
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool close_completed = false;
            asio::co_spawn(ioc_, [this, &close_completed]() -> asio::awaitable<void> {
                try {
                    co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
                    close_completed = true;
                } catch (...) {}
            }, asio::detached);

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(asio::use_awaitable);
            }

            closed = close_completed;
            if (!closed) {
                log().debug("WebSocket close timeout, forcing shutdown");
                boost::system::error_code ec;
                plain_ws_->next_layer().socket().close(ec);
            }
        }
    } catch (const std::exception& e) {
        log().debug("Error during control channel close: {}", e.what());
    } catch (...) {
        log().debug("Unknown error during control channel close");
    }

    if (channels_.disconnected) {
        channels_.disconnected->try_send(boost::system::error_code{});
    }
}

asio::awaitable<void> ControlChannel::send_config_ack(uint64_t version, ConfigAckStatus status) {
    ConfigAck ack;
    ack.version = version;
    ack.status = status;
    co_await send_frame(FrameType::CONFIG_ACK, ack.serialize());
}

asio::awaitable<void> ControlChannel::send_ping() {
    Ping ping;
    ping.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ping.seq_num = ++ping_seq_;
    last_ping_time_ = ping.timestamp;

    co_await send_frame(FrameType::PING, ping.serialize());
}

asio::awaitable<void> ControlChannel::send_latency_report(const LatencyReport& report) {
    co_await send_frame(FrameType::LATENCY_REPORT, report.serialize());
    log().debug("Sent latency report with {} entries", report.entries.size());
}

asio::awaitable<void> ControlChannel::send_relay_latency_report(const RelayLatencyReport& report) {
    co_await send_frame(FrameType::RELAY_LATENCY_REPORT, report.serialize());
    log().debug("Sent relay latency report with {} entries", report.entries.size());
}

asio::awaitable<void> ControlChannel::read_loop() {
    try {
        beast::flat_buffer buffer;

        while (is_ws_open()) {
            buffer.clear();

            if (use_tls_) {
                co_await tls_ws_->async_read(buffer, asio::use_awaitable);
            } else {
                co_await plain_ws_->async_read(buffer, asio::use_awaitable);
            }

            auto data = buffer.data();
            std::span<const uint8_t> span(
                static_cast<const uint8_t*>(data.data()), data.size());

            auto result = FrameCodec::decode(span);
            if (!result) {
                log().warn("Control: failed to decode frame");
                continue;
            }

            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            log().debug("Control channel read error: {}", e.what());
        }
    }

    // Only trigger callback if not already disconnected (avoid duplicate calls)
    if (state_ != ChannelState::DISCONNECTED) {
        state_ = ChannelState::DISCONNECTED;
        if (channels_.disconnected) {
            channels_.disconnected->try_send(boost::system::error_code{});
        }
    }
}

asio::awaitable<void> ControlChannel::write_loop() {
    try {
        while (is_ws_open()) {
            if (write_queue_.empty()) {
                writing_ = false;
                boost::system::error_code ec;
                co_await write_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
                // Timer cancelled means new data arrived, continue loop
                if (ec == asio::error::operation_aborted) {
                    continue;
                }
                if (ec) {
                    break;
                }
            }

            writing_ = true;
            while (!write_queue_.empty() && is_ws_open()) {
                auto data = std::move(write_queue_.front());
                write_queue_.pop();

                if (use_tls_) {
                    co_await tls_ws_->async_write(asio::buffer(data), asio::use_awaitable);
                } else {
                    co_await plain_ws_->async_write(asio::buffer(data), asio::use_awaitable);
                }
            }
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().debug("Control channel write error: {}", e.what());
        }
    }
}

asio::awaitable<void> ControlChannel::handle_frame(const Frame& frame) {
    log().debug("Control: received {} frame", frame_type_name(frame.header.type));

    switch (frame.header.type) {
        case FrameType::AUTH_RESPONSE:
            co_await handle_auth_response(frame);
            break;
        case FrameType::CONFIG:
            co_await handle_config(frame);
            break;
        case FrameType::CONFIG_UPDATE:
            co_await handle_config_update(frame);
            break;
        case FrameType::ROUTE_UPDATE:
            co_await handle_route_update(frame);
            break;
        case FrameType::ROUTE_ACK:
            co_await handle_route_ack(frame);
            break;
        case FrameType::PEER_ROUTING_UPDATE:
            co_await handle_peer_routing_update(frame);
            break;
        case FrameType::P2P_ENDPOINT:
            co_await handle_p2p_endpoint(frame);
            break;
        case FrameType::ENDPOINT_ACK:
            co_await handle_endpoint_ack(frame);
            break;
        case FrameType::PONG:
            co_await handle_pong(frame);
            break;
        case FrameType::FRAME_ERROR:
            co_await handle_error(frame);
            break;
        default:
            log().warn("Control: unhandled frame type 0x{:02X}",
                         static_cast<uint8_t>(frame.header.type));
            break;
    }
}

asio::awaitable<void> ControlChannel::handle_auth_response(const Frame& frame) {
    auto resp = AuthResponse::parse(frame.payload);
    if (!resp) {
        log().error("Failed to parse AUTH_RESPONSE");
        co_return;
    }

    if (!resp->success) {
        log().error("Authentication failed: {} (code {})", resp->error_msg, resp->error_code);
        if (channels_.error) {
            bool sent = channels_.error->try_send(boost::system::error_code{}, resp->error_code, resp->error_msg);
            if (!sent) {
                log().warn("Failed to send auth error event (channel full or closed)");
            }
        }
        co_return;
    }

    // Store auth info
    node_id_ = resp->node_id;
    network_id_ = resp->network_id;
    virtual_ip_ = resp->virtual_ip;
    auth_token_ = resp->auth_token;
    relay_token_ = resp->relay_token;

    crypto_.set_node_id(node_id_);

    log().info("Authenticated as node {} with IP {}", node_id_, virtual_ip_.to_string());

    // Note: state_ is set to CONNECTED after receiving CONFIG, not here
    // This ensures peers are populated before on_connected is called

    if (channels_.auth_response) {
        bool sent = channels_.auth_response->try_send(boost::system::error_code{}, *resp);
        if (!sent) {
            log().warn("Failed to send auth response event (channel full or closed)");
        }
    }
}

asio::awaitable<void> ControlChannel::handle_config(const Frame& frame) {
    auto config = Config::parse(frame.payload);
    if (!config) {
        log().error("Failed to parse CONFIG");
        co_return;
    }

    log().info("Received CONFIG v{} with {} peers", config->version, config->peers.size());

    // Save subnet mask for TUN configuration
    subnet_mask_ = config->subnet_mask;

    // Update relay token if present
    if (!config->relay_token.empty()) {
        relay_token_ = config->relay_token;
    }

    if (channels_.config) {
        bool sent = channels_.config->try_send(boost::system::error_code{}, *config);
        if (!sent) {
            log().warn("Failed to send config event (channel full or closed)");
        }
    }

    // Mark as connected after receiving initial CONFIG (peers are now populated)
    if (state_ != ChannelState::CONNECTED) {
        state_ = ChannelState::CONNECTED;
        if (channels_.connected) {
            bool sent = channels_.connected->try_send(boost::system::error_code{});
            if (!sent) {
                log().warn("Failed to send connected event (channel full or closed)");
            }
        }
    }

    // Send ACK
    co_await send_config_ack(config->version, ConfigAckStatus::SUCCESS);
}

asio::awaitable<void> ControlChannel::handle_config_update(const Frame& frame) {
    auto update = ConfigUpdate::parse(frame.payload);
    if (!update) {
        log().error("Failed to parse CONFIG_UPDATE");
        co_return;
    }

    log().debug("Received CONFIG_UPDATE v{}", update->version);

    // Update relay token if present
    if (has_flag(update->update_flags, ConfigUpdateFlags::TOKEN_REFRESH)) {
        relay_token_ = update->relay_token;
        log().debug("Relay token refreshed");
    }

    if (channels_.config_update) {
        bool sent = channels_.config_update->try_send(boost::system::error_code{}, *update);
        if (!sent) {
            log().warn("Failed to send config update event (channel full or closed)");
        }
    }
}

asio::awaitable<void> ControlChannel::handle_route_update(const Frame& frame) {
    auto update = RouteUpdate::parse(frame.payload);
    if (!update) {
        log().error("Failed to parse ROUTE_UPDATE");
        co_return;
    }

    log().debug("Received ROUTE_UPDATE v{}: +{} routes, -{} routes",
                update->version, update->add_routes.size(), update->del_routes.size());

    if (channels_.route_update) {
        bool sent = channels_.route_update->try_send(boost::system::error_code{}, *update);
        if (!sent) {
            log().warn("Failed to send route update event (channel full or closed)");
        }
    }
}

asio::awaitable<void> ControlChannel::handle_route_ack(const Frame& frame) {
    auto ack = RouteAck::parse(frame.payload);
    if (!ack) {
        log().error("Failed to parse ROUTE_ACK");
        co_return;
    }

    if (ack->success) {
        log().debug("Route operation {} succeeded", ack->request_id);
    } else {
        log().error("Route operation {} failed: {} (code {})",
                    ack->request_id, ack->error_msg, ack->error_code);
    }
}

asio::awaitable<void> ControlChannel::handle_peer_routing_update(const Frame& frame) {
    auto update = PeerRoutingUpdate::parse(frame.payload);
    if (!update) {
        log().error("Failed to parse PEER_ROUTING_UPDATE");
        co_return;
    }

    log().debug("Received PEER_ROUTING_UPDATE v{} with {} routes",
                update->version, update->routes.size());

    if (channels_.peer_routing_update) {
        channels_.peer_routing_update->try_send(boost::system::error_code{}, *update);
    }
}

asio::awaitable<void> ControlChannel::send_route_announce(const std::vector<RouteInfo>& routes) {
    if (routes.empty()) {
        co_return;
    }

    RouteAnnounce announce;
    announce.request_id = ++route_request_id_;
    announce.routes = routes;

    co_await send_frame(FrameType::ROUTE_ANNOUNCE, announce.serialize());
    log().info("Announced {} routes (request_id={})", routes.size(), announce.request_id);
}

asio::awaitable<void> ControlChannel::send_route_withdraw(const std::vector<RouteInfo>& routes) {
    if (routes.empty()) {
        co_return;
    }

    RouteWithdraw withdraw;
    withdraw.request_id = ++route_request_id_;
    withdraw.routes = routes;

    co_await send_frame(FrameType::ROUTE_WITHDRAW, withdraw.serialize());
    log().info("Withdrew {} routes (request_id={})", routes.size(), withdraw.request_id);
}

asio::awaitable<void> ControlChannel::send_p2p_init(const P2PInit& init) {
    co_await send_frame(FrameType::P2P_INIT, init.serialize());
    log().debug("Sent P2P_INIT: target_node={}, init_seq={}", init.target_node, init.init_seq);
}

asio::awaitable<uint32_t> ControlChannel::send_endpoint_update(const std::vector<Endpoint>& endpoints) {
    EndpointUpdate update;
    update.request_id = ++endpoint_request_id_;
    update.endpoints = endpoints;

    // 保存待确认状态
    pending_endpoint_request_id_ = update.request_id;
    pending_endpoints_ = endpoints;
    endpoint_ack_pending_ = true;

    co_await send_frame(FrameType::ENDPOINT_UPDATE, update.serialize());
    log().debug("Sent ENDPOINT_UPDATE: {} endpoints (request_id={})",
                endpoints.size(), update.request_id);

    co_return update.request_id;
}

asio::awaitable<bool> ControlChannel::send_endpoint_update_and_wait_ack(
    const std::vector<Endpoint>& endpoints,
    uint32_t timeout_ms) {

    // 发送端点更新
    uint32_t request_id = co_await send_endpoint_update(endpoints);

    // 设置超时 (timer initialized in constructor, no race)
    endpoint_ack_timer_->expires_after(std::chrono::milliseconds(timeout_ms));

    try {
        // 等待定时器：
        // - 如果 handle_endpoint_ack 收到 ACK，会取消定时器，抛出 operation_aborted
        // - 如果超时，正常返回
        co_await endpoint_ack_timer_->async_wait(asio::use_awaitable);

        // 超时了，检查是否仍在等待
        if (endpoint_ack_pending_ && pending_endpoint_request_id_ == request_id) {
            log().warn("ENDPOINT_UPDATE ACK timeout (request_id={})", request_id);
            co_return false;
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::error::operation_aborted) {
            // 定时器被取消，说明 ACK 已收到
            if (!endpoint_ack_pending_) {
                log().debug("ENDPOINT_UPDATE ACK received (request_id={})", request_id);
                co_return true;
            }
        } else {
            throw;
        }
    }

    co_return !endpoint_ack_pending_;
}

asio::awaitable<void> ControlChannel::resend_pending_endpoints() {
    if (pending_endpoints_.empty()) {
        co_return;
    }

    EndpointUpdate update;
    update.request_id = ++endpoint_request_id_;
    update.endpoints = pending_endpoints_;

    pending_endpoint_request_id_ = update.request_id;
    endpoint_ack_pending_ = true;

    co_await send_frame(FrameType::ENDPOINT_UPDATE, update.serialize());
    log().info("Resent ENDPOINT_UPDATE after reconnect: {} endpoints (request_id={})",
               update.endpoints.size(), update.request_id);
}

asio::awaitable<void> ControlChannel::handle_endpoint_ack(const Frame& frame) {
    auto ack = EndpointAck::parse(frame.payload);
    if (!ack) {
        log().error("Failed to parse ENDPOINT_ACK");
        co_return;
    }

    if (ack->request_id == pending_endpoint_request_id_) {
        endpoint_ack_pending_ = false;
        log().debug("Received ENDPOINT_ACK: request_id={}, success={}, count={}",
                    ack->request_id, ack->success, ack->endpoint_count);

        // 通知等待者 ACK 已收到（通过取消定时器）
        if (endpoint_ack_timer_) {
            endpoint_ack_timer_->cancel();
        }
    } else {
        log().debug("Received ENDPOINT_ACK with unexpected request_id={} (expected {})",
                    ack->request_id, pending_endpoint_request_id_);
    }
}

asio::awaitable<void> ControlChannel::handle_p2p_endpoint(const Frame& frame) {
    auto msg = P2PEndpointMsg::parse(frame.payload);
    if (!msg) {
        log().error("Failed to parse P2P_ENDPOINT");
        co_return;
    }

    log().debug("Received P2P_ENDPOINT: peer_node={}, init_seq={}, {} endpoints",
                msg->peer_node, msg->init_seq, msg->endpoints.size());

    if (channels_.p2p_endpoint) {
        channels_.p2p_endpoint->try_send(boost::system::error_code{}, *msg);
    }
}

asio::awaitable<void> ControlChannel::handle_pong(const Frame& frame) {
    auto pong = Pong::parse(frame.payload);
    if (!pong) {
        co_return;
    }

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t rtt = now - pong->timestamp;

    log().debug("Control PONG: RTT={}ms", rtt);
}

asio::awaitable<void> ControlChannel::handle_error(const Frame& frame) {
    auto error = ErrorPayload::parse(frame.payload);
    if (!error) {
        co_return;
    }

    log().error("Control error {}: {}", error->error_code, error->error_msg);

    if (channels_.error) {
        channels_.error->try_send(boost::system::error_code{}, error->error_code, error->error_msg);
    }
}

asio::awaitable<void> ControlChannel::send_frame(FrameType type, std::span<const uint8_t> payload) {
    auto data = FrameCodec::encode(type, payload);
    co_await send_raw(data);
}

asio::awaitable<void> ControlChannel::send_raw(std::span<const uint8_t> data) {
    write_queue_.push(std::vector<uint8_t>(data.begin(), data.end()));
    if (!writing_) {
        write_timer_.cancel();
    }
    co_return;
}

// ============================================================================
// RelayChannel Implementation
// ============================================================================

RelayChannel::RelayChannel(asio::io_context& ioc, ssl::context& ssl_ctx,
                           CryptoEngine& crypto, PeerManager& peers,
                           const std::string& url, bool use_tls,
                           const std::string& host_override)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , peers_(peers)
    , url_(url)
    , use_tls_(use_tls)
    , host_override_(host_override)
    , write_timer_(ioc) {
    write_timer_.expires_at(std::chrono::steady_clock::time_point::max());
}

void RelayChannel::set_channels(RelayChannelEvents channels) {
    channels_ = channels;
}

bool RelayChannel::is_ws_open() const {
    if (use_tls_) {
        return tls_ws_ && tls_ws_->is_open();
    } else {
        return plain_ws_ && plain_ws_->is_open();
    }
}

asio::awaitable<bool> RelayChannel::connect(const std::vector<uint8_t>& relay_token) {
    try {
        state_ = ChannelState::CONNECTING;

        // Parse URL
        auto parsed = boost::urls::parse_uri(url_);
        if (!parsed) {
            log().error("Invalid relay URL: {}", url_);
            co_return false;
        }

        std::string connect_host = std::string(parsed->host());  // 用于 TCP 连接
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls_ ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/relay";

        // 用于 SNI 和 HTTP Host 头的 hostname（CDN 需要正确的 Host 头）
        std::string ws_host = host_override_.empty() ? connect_host : host_override_;

        std::string scheme = use_tls_ ? "wss" : "ws";
        if (host_override_.empty()) {
            log().debug("Connecting to relay: {}://{}:{}", scheme, connect_host, port);
        } else {
            log().debug("Connecting to relay: {}://{} [ip:{}]", scheme, ws_host, connect_host);
        }

        // Resolve host (use connect_host for DNS, not ws_host)
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(connect_host, port, asio::use_awaitable);

        // 记录所有解析的 endpoints
        size_t endpoint_count = 0;
        std::string endpoint_list;
        for (const auto& ep : endpoints) {
            if (endpoint_count > 0) endpoint_list += ", ";
            endpoint_list += ep.endpoint().address().to_string() + ":" + std::to_string(ep.endpoint().port());
            endpoint_count++;
        }
        log().debug("DNS resolved to {} endpoint(s): {}", endpoint_count, endpoint_list);

        // 生成此连接的唯一标识符
        ConnectionId connection_id = static_cast<ConnectionId>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFF);
        log().debug("Assigned connection_id: 0x{:08x}", connection_id);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI (use ws_host for CDN compatibility)
            SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), ws_host.c_str());

            // Connect TCP - 使用Happy Eyeballs策略
            auto tcp_start = std::chrono::steady_clock::now();
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);

            auto connected_ep = co_await async_connect_happy_eyeballs(
                tcp_stream, endpoints, std::chrono::seconds(5));

            if (!connected_ep) {
                log().error("所有 relay endpoint 连接失败");
                co_return false;
            }

            auto tcp_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tcp_start).count();
            log().debug("TCP connected to relay {} in {} ms",
                       connected_ep->address().to_string(), tcp_elapsed);

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);

            // WebSocket handshake (use ws_host as Host header for CDN)
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            co_await tls_ws_->async_handshake(ws_host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*tls_ws_).expires_never();
            tls_ws_->binary(true);

        } else {
            // Create plain stream
            plain_ws_ = std::make_unique<PlainWsStream>(ioc_);

            // Connect TCP - 使用Happy Eyeballs策略
            auto tcp_start = std::chrono::steady_clock::now();
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);

            auto connected_ep = co_await async_connect_happy_eyeballs(
                tcp_stream, endpoints, std::chrono::seconds(5));

            if (!connected_ep) {
                log().error("所有 relay endpoint 连接失败");
                co_return false;
            }

            auto tcp_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - tcp_start).count();
            log().debug("TCP connected to relay {} in {} ms",
                       connected_ep->address().to_string(), tcp_elapsed);

            // WebSocket handshake (use ws_host as Host header for CDN)
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            co_await plain_ws_->async_handshake(ws_host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().debug("Relay WebSocket connected, authenticating...");
        state_ = ChannelState::AUTHENTICATING;

        // Build RELAY_AUTH
        RelayAuth auth;
        auth.relay_token = relay_token;
        auth.node_id = crypto_.node_id();
        auth.node_key = crypto_.node_key().public_key;
        auth.connection_id = connection_id;  // 设置连接标识符

        // Send RELAY_AUTH
        co_await send_frame(FrameType::RELAY_AUTH, auth.serialize());

        // Start read/write loops
        asio::co_spawn(ioc_, [self = shared_from_this()]() -> asio::awaitable<void> {
            co_await self->read_loop();
        }, asio::detached);

        asio::co_spawn(ioc_, [self = shared_from_this()]() -> asio::awaitable<void> {
            co_await self->write_loop();
        }, asio::detached);

        co_return true;

    } catch (const std::exception& e) {
        log().error("Relay channel connection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<void> RelayChannel::close() {
    if (state_ == ChannelState::DISCONNECTED) {
        co_return;
    }

    state_ = ChannelState::DISCONNECTED;

    // 使用超时保护的关闭操作，避免卡住
    try {
        asio::steady_timer timeout_timer(ioc_);
        timeout_timer.expires_after(std::chrono::seconds(3));

        bool closed = false;

        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool close_completed = false;
            asio::co_spawn(ioc_, [this, &close_completed]() -> asio::awaitable<void> {
                try {
                    co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
                    close_completed = true;
                } catch (...) {}
            }, asio::detached);

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(asio::use_awaitable);
            }

            closed = close_completed;
            if (!closed) {
                log().debug("Relay WebSocket close timeout, forcing shutdown");
                boost::system::error_code ec;
                tls_ws_->next_layer().next_layer().socket().close(ec);
            }
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool close_completed = false;
            asio::co_spawn(ioc_, [this, &close_completed]() -> asio::awaitable<void> {
                try {
                    co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
                    close_completed = true;
                } catch (...) {}
            }, asio::detached);

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(asio::use_awaitable);
            }

            closed = close_completed;
            if (!closed) {
                log().debug("Relay WebSocket close timeout, forcing shutdown");
                boost::system::error_code ec;
                plain_ws_->next_layer().socket().close(ec);
            }
        }
    } catch (const std::exception& e) {
        log().debug("Error during relay channel close: {}", e.what());
    } catch (...) {
        log().debug("Unknown error during relay channel close");
    }

    if (channels_.disconnected) {
        channels_.disconnected->try_send(boost::system::error_code{});
    }
}

asio::awaitable<bool> RelayChannel::send_data(NodeId peer_id, std::span<const uint8_t> plaintext) {
    if (state_ != ChannelState::CONNECTED) {
        log().warn("Cannot send data: relay not connected (state={})", channel_state_name(state_));
        co_return false;
    }

    if (!is_ws_open()) {
        log().warn("Cannot send data: WebSocket not open");
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }

    // Ensure session key exists
    if (!peers_.ensure_session_key(peer_id)) {
        log().warn("Cannot send data to {}: no session key", peers_.get_peer_ip_str(peer_id));
        co_return false;
    }

    // Encrypt
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    auto encrypted = crypto_.encrypt(peer_id, plaintext, nonce);
    if (!encrypted) {
        log().error("Failed to encrypt data for {}", peers_.get_peer_ip_str(peer_id));
        co_return false;
    }

    // Build DATA payload
    DataPayload data;
    data.src_node = crypto_.node_id();
    data.dst_node = peer_id;
    data.nonce = nonce;
    data.encrypted_payload = std::move(*encrypted);

    co_await send_frame(FrameType::DATA, data.serialize());

    log().debug("Queued {} bytes for {} (encrypted {} bytes)",
                  plaintext.size(), peers_.get_peer_ip_str(peer_id), data.encrypted_payload.size());
    co_return true;
}

asio::awaitable<void> RelayChannel::send_ping() {
    Ping ping;
    ping.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ping.seq_num = ++ping_seq_;
    last_ping_time_ = ping.timestamp;

    co_await send_frame(FrameType::PING, ping.serialize());
    log().debug("Sent PING seq={} to relay", ping.seq_num);
}

asio::awaitable<void> RelayChannel::read_loop() {
    try {
        beast::flat_buffer buffer;

        while (is_ws_open()) {
            buffer.clear();

            if (use_tls_) {
                co_await tls_ws_->async_read(buffer, asio::use_awaitable);
            } else {
                co_await plain_ws_->async_read(buffer, asio::use_awaitable);
            }

            auto data = buffer.data();
            std::span<const uint8_t> span(
                static_cast<const uint8_t*>(data.data()), data.size());

            log().debug("Relay read_loop: received {} bytes", span.size());

            auto result = FrameCodec::decode(span);
            if (!result) {
                log().warn("Relay: failed to decode frame ({} bytes)", span.size());
                continue;
            }

            log().debug("Relay read_loop: decoded frame type 0x{:02X}",
                         static_cast<uint8_t>(result->first.header.type));
            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            log().debug("Relay channel read error: {}", e.what());
        }
    }

    // Only trigger callback if not already disconnected (avoid duplicate calls)
    if (state_ != ChannelState::DISCONNECTED) {
        state_ = ChannelState::DISCONNECTED;
        if (channels_.disconnected) {
            channels_.disconnected->try_send(boost::system::error_code{});
        }
    }
}

asio::awaitable<void> RelayChannel::write_loop() {
    try {
        while (is_ws_open()) {
            if (write_queue_.empty()) {
                writing_ = false;
                boost::system::error_code ec;
                co_await write_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
                // Timer cancelled means new data arrived, continue loop
                if (ec == asio::error::operation_aborted) {
                    continue;
                }
                if (ec) {
                    log().debug("Relay write_loop: timer error {}", ec.message());
                    break;
                }
            }

            writing_ = true;
            while (!write_queue_.empty() && is_ws_open()) {
                auto data = std::move(write_queue_.front());
                write_queue_.pop();

                log().debug("Relay write_loop: sending {} bytes", data.size());

                if (use_tls_) {
                    co_await tls_ws_->async_write(asio::buffer(data), asio::use_awaitable);
                } else {
                    co_await plain_ws_->async_write(asio::buffer(data), asio::use_awaitable);
                }

                log().debug("Relay write_loop: sent {} bytes", data.size());
            }
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().warn("Relay channel write error: {}", e.what());
        }
    }

    // Write loop exited - WebSocket is closed
    log().warn("Relay write_loop exited, {} queued messages dropped", write_queue_.size());
    writing_ = false;

    // Clear queue to avoid memory leak
    while (!write_queue_.empty()) {
        write_queue_.pop();
    }
}

asio::awaitable<void> RelayChannel::handle_frame(const Frame& frame) {
    switch (frame.header.type) {
        case FrameType::RELAY_AUTH_RESP:
            co_await handle_relay_auth_resp(frame);
            break;
        case FrameType::DATA:
            co_await handle_data(frame);
            break;
        case FrameType::PONG:
            co_await handle_pong(frame);
            break;
        default:
            log().warn("Relay: unhandled frame type 0x{:02X}",
                         static_cast<uint8_t>(frame.header.type));
            break;
    }
}

asio::awaitable<void> RelayChannel::handle_relay_auth_resp(const Frame& frame) {
    auto resp = RelayAuthResp::parse(frame.payload);
    if (!resp) {
        log().error("Failed to parse RELAY_AUTH_RESP");
        co_return;
    }

    if (!resp->success) {
        log().error("Relay auth failed: {} (code {})", resp->error_msg, resp->error_code);
        co_return;
    }

    state_ = ChannelState::CONNECTED;
    log().debug("Relay channel connected");

    if (channels_.connected) {
        channels_.connected->try_send(boost::system::error_code{});
    }
}

asio::awaitable<void> RelayChannel::handle_data(const Frame& frame) {
    log().debug("Relay handle_data: processing {} bytes", frame.payload.size());

    auto data = DataPayload::parse(frame.payload);
    if (!data) {
        log().warn("Failed to parse DATA payload");
        co_return;
    }

    log().debug("Relay handle_data: DATA from {} to me, encrypted {} bytes",
                 peers_.get_peer_ip_str(data->src_node), data->encrypted_payload.size());

    // Ensure session key exists for sender
    if (!peers_.ensure_session_key(data->src_node)) {
        log().warn("Cannot decrypt data from {}: no session key", peers_.get_peer_ip_str(data->src_node));
        co_return;
    }

    // Decrypt
    auto peer_ip = peers_.get_peer_ip_str(data->src_node);
    auto plaintext = crypto_.decrypt(data->src_node, data->nonce, data->encrypted_payload);
    if (!plaintext) {
        log().warn("Failed to decrypt data from {}, renegotiating session key...", peer_ip);

        // Clear old session key and re-derive
        crypto_.remove_session_key(data->src_node);

        // Try to derive new session key
        if (!peers_.ensure_session_key(data->src_node)) {
            log().error("Failed to renegotiate session key for {}", peer_ip);
            co_return;
        }

        log().info("Session key renegotiated for {}", peer_ip);

        // Retry decryption with new key
        plaintext = crypto_.decrypt(data->src_node, data->nonce, data->encrypted_payload);
        if (!plaintext) {
            log().warn("Decryption still failed after renegotiation, {} may have different node_key", peer_ip);
            co_return;
        }

        log().info("Decryption succeeded after session key renegotiation for {}", peer_ip);
    }

    peers_.update_last_seen(data->src_node);

    log().debug("Relay handle_data: decrypted {} bytes from {}", plaintext->size(), peer_ip);

    if (channels_.data) {
        bool sent = channels_.data->try_send(boost::system::error_code{}, data->src_node, std::move(*plaintext));
        if (!sent) {
            log().warn("Failed to send data event for peer {} (channel full or closed)", peer_ip);
        }
    }
}

asio::awaitable<void> RelayChannel::handle_pong(const Frame& frame) {
    auto pong = Pong::parse(frame.payload);
    if (!pong) {
        log().warn("Failed to parse PONG");
        co_return;
    }

    // Calculate RTT
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (last_ping_time_ > 0) {
        uint16_t rtt_ms = static_cast<uint16_t>(now - last_ping_time_);
        log().debug("Received PONG seq={}, RTT={}ms", pong->seq_num, rtt_ms);

        // Notify via callback
        if (channels_.on_pong) {
            channels_.on_pong(rtt_ms);
        }
    }

    co_return;
}

asio::awaitable<void> RelayChannel::send_frame(FrameType type, std::span<const uint8_t> payload) {
    auto data = FrameCodec::encode(type, payload);
    co_await send_raw(data);
}

asio::awaitable<void> RelayChannel::send_raw(std::span<const uint8_t> data) {
    write_queue_.push(std::vector<uint8_t>(data.begin(), data.end()));
    if (!writing_) {
        write_timer_.cancel();
    }
    co_return;
}

} // namespace edgelink::client

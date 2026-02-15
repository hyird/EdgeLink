#include "client/channel.hpp"
#include "common/logger.hpp"
#include "common/proto_convert.hpp"  // Proto conversion helpers (includes edgelink.pb.h)
#include "common/auth_proto_helpers.hpp"  // Auth protobuf helpers
#include "common/cobalt_utils.hpp"
#include <chrono>
#include <mutex>
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

namespace cobalt = boost::cobalt;

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
    static std::once_flag flag;
    static bool result = false;

    std::call_once(flag, []() {
        // Use raw socket API to avoid io_context conflicts
#ifdef _WIN32
        SOCKET sock = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            result = false;
            log().info("IPv6 not available on this system (socket creation failed)");
            return;
        }
        ::closesocket(sock);
#else
        int sock = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            result = false;
            log().info("IPv6 not available on this system (socket creation failed)");
            return;
        }
        ::close(sock);
#endif
        result = true;
        log().trace("IPv6 is available on this system");
    });

    return result;
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
cobalt::task<std::optional<tcp::endpoint>> async_connect_happy_eyeballs(
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
            log().trace("尝试连接 {} (超时{}ms)",
                       endpoint.address().to_string(),
                       per_endpoint_timeout.count());

            // Ensure socket is closed before attempting connection
            // This is critical when switching between IPv4 and IPv6
            boost::system::error_code close_ec;
            if (stream.socket().is_open()) {
                stream.socket().close(close_ec);
            }

            stream.expires_after(per_endpoint_timeout);
            co_await stream.async_connect(endpoint, cobalt::use_op);

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

void ControlChannel::set_event_channel(events::CtrlEventChannel* ch) {
    event_ch_ = ch;
}

bool ControlChannel::is_ws_open() const {
    if (use_tls_) {
        return tls_ws_ && tls_ws_->is_open();
    } else {
        return plain_ws_ && plain_ws_->is_open();
    }
}

cobalt::task<bool> ControlChannel::connect(const std::string& authkey) {
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
        auto endpoints = co_await resolver.async_resolve(host, port, cobalt::use_op);
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
        log().debug("DNS resolved {} endpoint(s) in {}ms", endpoint_count, dns_elapsed);

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

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, cobalt::use_op);

            // WebSocket handshake
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            tls_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await tls_ws_->async_handshake(host, target, cobalt::use_op);

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

            // WebSocket handshake
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            plain_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await plain_ws_->async_handshake(host, target, cobalt::use_op);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().info("WebSocket connected, authenticating...");
        state_ = ChannelState::AUTHENTICATING;

        // Build AUTH_REQUEST
        pb::AuthRequest req;
        req.set_auth_type(pb::AUTH_TYPE_AUTHKEY);
        req.set_machine_key(crypto_.machine_key().public_key.data(),
                           crypto_.machine_key().public_key.size());
        req.set_node_key(crypto_.node_key().public_key.data(),
                        crypto_.node_key().public_key.size());
        req.set_hostname(get_hostname());
        req.set_os(get_os_name());
        req.set_arch(get_arch());
        req.set_version("1.0.0");
        req.set_timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        req.set_connection_id(0);  // Controller 连接不使用 connection_id
        req.set_exit_node(exit_node_);  // 声明出口节点能力
        req.set_auth_data(authkey_);

        // Sign the request
        auto sign_data = get_auth_sign_data(req);
        auto sig = crypto_.sign(sign_data);
        if (!sig) {
            log().error("Failed to sign AUTH_REQUEST");
            co_return false;
        }
        req.set_signature(sig->data(), sig->size());

        // Send AUTH_REQUEST
        auto result = FrameCodec::encode_protobuf(FrameType::AUTH_REQUEST, req);
        if (!result) {
            log().error("Failed to encode AUTH_REQUEST");
            co_return false;
        }
        send_raw(*result);

        // Start read/write loops
        cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this()]() -> cobalt::task<void> {
            co_await self->read_loop();
        }());

        cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this()]() -> cobalt::task<void> {
            co_await self->write_loop();
        }());

        // NOTE: 返回 true 表示 WebSocket 已连接且 AUTH_REQUEST 已发送，
        // 但认证尚未完成。状态为 AUTHENTICATING，收到 AUTH_RESPONSE + CONFIG 后才变为 CONNECTED。
        co_return true;

    } catch (const std::exception& e) {
        log().error("Control channel connection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

cobalt::task<bool> ControlChannel::reconnect() {
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
                co_await tls_ws_->async_close(websocket::close_code::normal, cobalt::use_op);
            } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
                co_await plain_ws_->async_close(websocket::close_code::normal, cobalt::use_op);
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
        auto endpoints = co_await resolver.async_resolve(host, port, cobalt::use_op);
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
        log().debug("DNS resolved {} endpoint(s) in {}ms", endpoint_count, dns_elapsed);

        // 生成此连接的唯一标识符
        ConnectionId connection_id = static_cast<ConnectionId>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFF);
        log().trace("Assigned connection_id: 0x{:08x}", connection_id);

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

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, cobalt::use_op);

            // WebSocket handshake
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            tls_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await tls_ws_->async_handshake(host, target, cobalt::use_op);

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

            // WebSocket handshake
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            plain_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await plain_ws_->async_handshake(host, target, cobalt::use_op);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().info("WebSocket reconnected, authenticating with machine key...");
        state_ = ChannelState::AUTHENTICATING;

        // Build AUTH_REQUEST with MACHINE auth type
        pb::AuthRequest req;
        req.set_auth_type(pb::AUTH_TYPE_MACHINE);
        req.set_machine_key(crypto_.machine_key().public_key.data(),
                           crypto_.machine_key().public_key.size());
        req.set_node_key(crypto_.node_key().public_key.data(),
                        crypto_.node_key().public_key.size());
        req.set_hostname(get_hostname());
        req.set_os(get_os_name());
        req.set_arch(get_arch());
        req.set_version("1.0.0");
        req.set_timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        req.set_connection_id(connection_id);  // 设置连接标识符
        req.set_exit_node(exit_node_);  // 声明出口节点能力
        // auth_data is empty for MACHINE auth type

        // Sign the request
        auto sign_data = get_auth_sign_data(req);
        auto sig = crypto_.sign(sign_data);
        if (!sig) {
            log().error("Failed to sign AUTH_REQUEST");
            state_ = ChannelState::DISCONNECTED;
            co_return false;
        }
        req.set_signature(sig->data(), sig->size());

        // Send AUTH_REQUEST
        auto result = FrameCodec::encode_protobuf(FrameType::AUTH_REQUEST, req);
        if (!result) {
            log().error("Failed to encode AUTH_REQUEST");
            state_ = ChannelState::DISCONNECTED;
            co_return false;
        }
        send_raw(*result);

        // Start read/write loops
        cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this()]() -> cobalt::task<void> {
            co_await self->read_loop();
        }());

        cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this()]() -> cobalt::task<void> {
            co_await self->write_loop();
        }());

        co_return true;

    } catch (const std::exception& e) {
        log().error("Control channel reconnection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

cobalt::task<void> ControlChannel::close() {
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
            // 用 shared_ptr<atomic<bool>> 避免 spawned task 引用已销毁的栈变量
            auto close_completed = std::make_shared<std::atomic<bool>>(false);
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, close_completed]() -> cobalt::task<void> {
                try {
                    co_await tls_ws_->async_close(websocket::close_code::normal, cobalt::use_op);
                    close_completed->store(true);
                } catch (...) {}
            }());

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed->load() && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            closed = close_completed->load();
            if (!closed) {
                // 超时，直接关闭底层连接
                log().debug("WebSocket close timeout, forcing shutdown");
                boost::system::error_code ec;
                tls_ws_->next_layer().next_layer().socket().close(ec);
            }
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            auto close_completed = std::make_shared<std::atomic<bool>>(false);
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, close_completed]() -> cobalt::task<void> {
                try {
                    co_await plain_ws_->async_close(websocket::close_code::normal, cobalt::use_op);
                    close_completed->store(true);
                } catch (...) {}
            }());

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed->load() && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            closed = close_completed->load();
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

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::Disconnected{"connection closed"}}));
    }
}

cobalt::task<void> ControlChannel::send_config_ack(uint64_t version, ConfigAckStatus status) {
    // Use protobuf ConfigAck
    pb::ConfigAck ack;
    ack.set_version(version);
    ack.set_status(to_proto_config_ack_status(status));

    auto result = FrameCodec::encode_protobuf(FrameType::CONFIG_ACK, ack);
    if (result) {
        send_raw(*result);
    }
    co_return;
}

cobalt::task<void> ControlChannel::send_ping() {
    // Use protobuf Ping message
    pb::Ping ping;
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ping.set_timestamp(now);
    ping.set_seq_num(++ping_seq_);
    last_ping_time_ = now;
    last_ping_steady_ = std::chrono::steady_clock::now();  // 本地 RTT 计算用

    auto result = FrameCodec::encode_protobuf(FrameType::PING, ping);
    if (result) {
        send_raw(*result);
    }
    co_return;
}

cobalt::task<void> ControlChannel::send_latency_report(const LatencyReport& report) {
    pb::LatencyReport pb_report;
    to_proto(report, &pb_report);
    auto result = FrameCodec::encode_protobuf(FrameType::LATENCY_REPORT, pb_report);
    if (result) {
        send_raw(*result);
    }
    log().trace("Sent latency report with {} entries", report.entries.size());
    co_return;
}

cobalt::task<void> ControlChannel::send_relay_latency_report(const RelayLatencyReport& report) {
    pb::RelayLatencyReport pb_report;
    to_proto(report, &pb_report);
    auto result = FrameCodec::encode_protobuf(FrameType::RELAY_LATENCY_REPORT, pb_report);
    if (result) {
        send_raw(*result);
    }
    log().debug("Sent relay latency report with {} entries", report.entries.size());
    co_return;
}

cobalt::task<void> ControlChannel::read_loop() {
    try {
        beast::flat_buffer buffer;

        while (is_ws_open()) {
            buffer.clear();

            if (use_tls_) {
                co_await tls_ws_->async_read(buffer, cobalt::use_op);
            } else {
                co_await plain_ws_->async_read(buffer, cobalt::use_op);
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

    // Only trigger disconnect event if not already disconnected or reconnecting
    // RECONNECTING 状态下旧 read_loop 退出是正常的，不应触发 Disconnected 事件
    if (state_ != ChannelState::DISCONNECTED && state_ != ChannelState::RECONNECTING) {
        state_ = ChannelState::DISCONNECTED;
        if (event_ch_) {
            co_await cobalt::as_tuple(event_ch_->write(
                events::ctrl::Event{events::ctrl::Disconnected{"read loop ended"}}));
        }
    }
}

cobalt::task<void> ControlChannel::write_loop() {
    try {
        while (is_ws_open()) {
            if (write_queue_.empty()) {
                writing_ = false;
                auto [ec] = co_await write_timer_.async_wait(asio::as_tuple(cobalt::use_op));
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
                    co_await tls_ws_->async_write(asio::buffer(data), cobalt::use_op);
                } else {
                    co_await plain_ws_->async_write(asio::buffer(data), cobalt::use_op);
                }
            }
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().debug("Control channel write error: {}", e.what());
        }
    }
}

cobalt::task<void> ControlChannel::handle_frame(const Frame& frame) {
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

cobalt::task<void> ControlChannel::handle_auth_response(const Frame& frame) {
    // Parse protobuf AuthResponse
    auto pb_resp = FrameCodec::decode_protobuf<pb::AuthResponse>(frame.data());
    if (!pb_resp) {
        log().error("Failed to parse AUTH_RESPONSE: {}", frame_error_message(pb_resp.error()));
        co_return;
    }

    if (!pb_resp->success()) {
        log().error("Authentication failed: {} (code {})",
                    pb_resp->error_msg(), pb_resp->error_code());

        // Error code 1007: Unknown machine key - controller database was reset
        // Fallback to authkey authentication if available
        if (pb_resp->error_code() == 1007 && !authkey_.empty()) {
            log().info("Machine key unknown, falling back to authkey re-registration...");

            // Reset node_id to allow fresh registration
            node_id_ = 0;

            // Build AUTH_REQUEST with AUTHKEY type
            pb::AuthRequest req;
            req.set_auth_type(pb::AUTH_TYPE_AUTHKEY);
            req.set_machine_key(crypto_.machine_key().public_key.data(),
                               crypto_.machine_key().public_key.size());
            req.set_node_key(crypto_.node_key().public_key.data(),
                            crypto_.node_key().public_key.size());
            req.set_hostname(get_hostname());
            req.set_os(get_os_name());
            req.set_arch(get_arch());
            req.set_version("1.0.0");
            req.set_timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            req.set_connection_id(0);
            req.set_exit_node(exit_node_);
            req.set_auth_data(authkey_);

            // Sign the request
            auto sign_data = get_auth_sign_data(req);
            auto sig = crypto_.sign(sign_data);
            if (!sig) {
                log().error("Failed to sign AUTH_REQUEST for re-registration");
                co_return;
            }
            req.set_signature(sig->data(), sig->size());

            // Send AUTH_REQUEST
            auto result = FrameCodec::encode_protobuf(FrameType::AUTH_REQUEST, req);
            if (!result) {
                log().error("Failed to encode AUTH_REQUEST for re-registration");
                co_return;
            }
            send_raw(*result);
            log().info("Re-registration request sent with authkey");
            co_return;
        }

        if (event_ch_) {
            co_await cobalt::as_tuple(event_ch_->write(
                events::ctrl::Event{events::ctrl::Error{static_cast<uint16_t>(pb_resp->error_code()), pb_resp->error_msg()}}));
        }
        co_return;
    }

    // Store auth info
    node_id_ = pb_resp->node_id();
    network_id_ = pb_resp->network_id();
    from_proto(pb_resp->virtual_ip(), &virtual_ip_);
    auth_token_ = std::vector<uint8_t>(pb_resp->auth_token().begin(), pb_resp->auth_token().end());
    relay_token_ = std::vector<uint8_t>(pb_resp->relay_token().begin(), pb_resp->relay_token().end());

    crypto_.set_node_id(node_id_);

    log().info("Authenticated as node {} with IP {}",
               node_id_, virtual_ip_.to_string());

    // Note: state_ is set to CONNECTED after receiving CONFIG, not here
    // This ensures peers are populated before on_connected is called

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::Connected{node_id_, virtual_ip_, subnet_mask_, relay_token_}}));
    }
}

cobalt::task<void> ControlChannel::handle_config(const Frame& frame) {
    // Use protobuf Config message
    auto pb_config = FrameCodec::decode_protobuf<pb::Config>(frame.data());
    if (!pb_config) {
        log().error("Failed to parse CONFIG: {}", frame_error_message(pb_config.error()));
        co_return;
    }

    // Convert to C++ Config
    Config config;
    from_proto(*pb_config, &config);

    log().info("Received CONFIG v{} with {} peers", config.version, config.peers.size());

    // Save subnet mask for TUN configuration
    subnet_mask_ = config.subnet_mask;

    // Update relay token if present
    if (!config.relay_token.empty()) {
        relay_token_ = config.relay_token;
    }

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::ConfigReceived{config}}));
    }

    // Mark as connected after receiving initial CONFIG (peers are now populated)
    if (state_ != ChannelState::CONNECTED) {
        state_ = ChannelState::CONNECTED;
    }

    // Send ACK
    co_await send_config_ack(config.version, ConfigAckStatus::SUCCESS);
}

cobalt::task<void> ControlChannel::handle_config_update(const Frame& frame) {
    // Use protobuf ConfigUpdate message
    auto pb_update = FrameCodec::decode_protobuf<pb::ConfigUpdate>(frame.data());
    if (!pb_update) {
        log().error("Failed to parse CONFIG_UPDATE: {}", frame_error_message(pb_update.error()));
        co_return;
    }

    // Convert to C++ ConfigUpdate
    ConfigUpdate update;
    from_proto(*pb_update, &update);

    log().info("Received CONFIG_UPDATE v{}: {} added peers, {} removed peers",
               update.version, update.add_peers.size(), update.del_peer_ids.size());
    for (const auto& peer : update.add_peers) {
        log().info("  + Peer: {} ({}) - {}", peer.node_id, peer.virtual_ip.to_string(),
                   peer.online ? "online" : "offline");
    }

    // Update relay token if present
    if (has_flag(update.update_flags, ConfigUpdateFlags::TOKEN_REFRESH)) {
        relay_token_ = update.relay_token;
        log().debug("Relay token refreshed");
    }

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::ConfigUpdateReceived{update}}));
    }
}

cobalt::task<void> ControlChannel::handle_route_update(const Frame& frame) {
    auto pb_update = FrameCodec::decode_protobuf<pb::RouteUpdate>(frame.data());
    if (!pb_update) {
        log().error("Failed to parse ROUTE_UPDATE: {}", frame_error_message(pb_update.error()));
        co_return;
    }
    RouteUpdate update;
    from_proto(*pb_update, &update);

    log().debug("Received ROUTE_UPDATE v{}: +{} routes, -{} routes",
                update.version, update.add_routes.size(), update.del_routes.size());

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::RouteUpdateReceived{update}}));
    }
}

cobalt::task<void> ControlChannel::handle_route_ack(const Frame& frame) {
    auto pb_ack = FrameCodec::decode_protobuf<pb::RouteAck>(frame.data());
    if (!pb_ack) {
        log().error("Failed to parse ROUTE_ACK: {}", frame_error_message(pb_ack.error()));
        co_return;
    }
    RouteAck ack;
    from_proto(*pb_ack, &ack);

    if (ack.success) {
        log().debug("Route operation {} succeeded", ack.request_id);
    } else {
        log().error("Route operation {} failed: {} (code {})",
                    ack.request_id, ack.error_msg, ack.error_code);
    }
}

cobalt::task<void> ControlChannel::handle_peer_routing_update(const Frame& frame) {
    auto pb_update = FrameCodec::decode_protobuf<pb::PeerRoutingUpdate>(frame.data());
    if (!pb_update) {
        log().error("Failed to parse PEER_ROUTING_UPDATE: {}", frame_error_message(pb_update.error()));
        co_return;
    }
    PeerRoutingUpdate update;
    from_proto(*pb_update, &update);

    log().debug("Received PEER_ROUTING_UPDATE v{} with {} routes",
                update.version, update.routes.size());

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::PeerRoutingUpdateReceived{update}}));
    }
}

cobalt::task<void> ControlChannel::send_route_announce(const std::vector<RouteInfo>& routes) {
    if (routes.empty()) {
        co_return;
    }

    RouteAnnounce announce;
    announce.request_id = ++route_request_id_;
    announce.routes = routes;

    pb::RouteAnnounce pb_announce;
    to_proto(announce, &pb_announce);
    auto result = FrameCodec::encode_protobuf(FrameType::ROUTE_ANNOUNCE, pb_announce);
    if (result) {
        send_raw(*result);
    }
    log().info("Announced {} routes (request_id={})", routes.size(), announce.request_id);
    co_return;
}

cobalt::task<void> ControlChannel::send_route_withdraw(const std::vector<RouteInfo>& routes) {
    if (routes.empty()) {
        co_return;
    }

    RouteWithdraw withdraw;
    withdraw.request_id = ++route_request_id_;
    withdraw.routes = routes;

    pb::RouteWithdraw pb_withdraw;
    to_proto(withdraw, &pb_withdraw);
    auto result = FrameCodec::encode_protobuf(FrameType::ROUTE_WITHDRAW, pb_withdraw);
    if (result) {
        send_raw(*result);
    }
    log().info("Withdrew {} routes (request_id={})", routes.size(), withdraw.request_id);
    co_return;
}

cobalt::task<void> ControlChannel::send_p2p_init(const P2PInit& init) {
    pb::P2PInit pb_init;
    to_proto(init, &pb_init);
    auto result = FrameCodec::encode_protobuf(FrameType::P2P_INIT, pb_init);
    if (result) {
        send_raw(*result);
    }
    log().debug("Sent P2P_INIT: target_node={}, init_seq={}", init.target_node, init.init_seq);
    co_return;
}

cobalt::task<void> ControlChannel::send_p2p_status(const P2PStatusMsg& status) {
    pb::P2PStatusMsg pb_status;
    to_proto(status, &pb_status);
    auto result = FrameCodec::encode_protobuf(FrameType::P2P_STATUS, pb_status);
    if (result) {
        send_raw(*result);
    }
    log().debug("Sent P2P_STATUS: peer={}, status={}, latency={}ms",
                status.peer_node, static_cast<int>(status.status), status.latency_ms);
    co_return;
}

cobalt::task<uint32_t> ControlChannel::send_endpoint_update(const std::vector<Endpoint>& endpoints) {
    EndpointUpdate update;
    update.request_id = ++endpoint_request_id_;
    update.endpoints = endpoints;

    // 保存待确认状态
    pending_endpoint_request_id_ = update.request_id;
    pending_endpoints_ = endpoints;
    endpoint_ack_pending_ = true;

    pb::EndpointUpdate pb_update;
    to_proto(update, &pb_update);
    auto result = FrameCodec::encode_protobuf(FrameType::ENDPOINT_UPDATE, pb_update);
    if (result) {
        send_raw(*result);
    }
    log().debug("Sent ENDPOINT_UPDATE: {} endpoints (request_id={})",
                endpoints.size(), update.request_id);

    co_return update.request_id;
}

cobalt::task<bool> ControlChannel::send_endpoint_update_and_wait_ack(
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
        co_await endpoint_ack_timer_->async_wait(cobalt::use_op);

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

cobalt::task<void> ControlChannel::resend_pending_endpoints() {
    if (pending_endpoints_.empty()) {
        co_return;
    }

    EndpointUpdate update;
    update.request_id = ++endpoint_request_id_;
    update.endpoints = pending_endpoints_;

    pending_endpoint_request_id_ = update.request_id;
    endpoint_ack_pending_ = true;

    pb::EndpointUpdate pb_update;
    to_proto(update, &pb_update);
    auto result = FrameCodec::encode_protobuf(FrameType::ENDPOINT_UPDATE, pb_update);
    if (result) {
        send_raw(*result);
    }
    log().info("Resent ENDPOINT_UPDATE after reconnect: {} endpoints (request_id={})",
               update.endpoints.size(), update.request_id);
    co_return;
}

cobalt::task<void> ControlChannel::handle_endpoint_ack(const Frame& frame) {
    auto pb_ack = FrameCodec::decode_protobuf<pb::EndpointAck>(frame.data());
    if (!pb_ack) {
        log().error("Failed to parse ENDPOINT_ACK: {}", frame_error_message(pb_ack.error()));
        co_return;
    }
    EndpointAck ack;
    from_proto(*pb_ack, &ack);

    if (ack.request_id == pending_endpoint_request_id_) {
        endpoint_ack_pending_ = false;
        log().debug("Received ENDPOINT_ACK: request_id={}, success={}, count={}",
                    ack.request_id, ack.success, ack.endpoint_count);

        // 通知等待者 ACK 已收到（通过取消定时器）
        if (endpoint_ack_timer_) {
            endpoint_ack_timer_->cancel();
        }
    } else {
        log().debug("Received ENDPOINT_ACK with unexpected request_id={} (expected {})",
                    ack.request_id, pending_endpoint_request_id_);
    }
}

cobalt::task<void> ControlChannel::handle_p2p_endpoint(const Frame& frame) {
    auto pb_msg = FrameCodec::decode_protobuf<pb::P2PEndpoint>(frame.data());
    if (!pb_msg) {
        log().error("Failed to parse P2P_ENDPOINT");
        co_return;
    }

    P2PEndpointMsg msg;
    from_proto(*pb_msg, &msg);

    log().debug("Received P2P_ENDPOINT: peer_node={}, init_seq={}, {} endpoints",
                msg.peer_node, msg.init_seq, msg.endpoints.size());

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::P2PEndpointReceived{msg}}));
    }
}

cobalt::task<void> ControlChannel::handle_pong(const Frame& frame) {
    // Use protobuf Pong message
    auto pong = FrameCodec::decode_protobuf<pb::Pong>(frame.data());
    if (!pong) {
        log().warn("Failed to parse PONG: {}", frame_error_message(pong.error()));
        co_return;
    }

    // 校验 seq_num 匹配当前 ping
    if (pong->seq_num() != ping_seq_) {
        log().debug("Ignoring stale PONG: seq={} (expected {})", pong->seq_num(), ping_seq_);
        co_return;
    }

    // 使用 steady_clock 计算本地 RTT，避免 system_clock 跳变
    auto now_steady = std::chrono::steady_clock::now();
    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        now_steady - last_ping_steady_).count();

    // Only log if RTT is unusually high
    if (rtt > 500) {
        log().warn("Control channel high latency: RTT={}ms", rtt);
    }
}

cobalt::task<void> ControlChannel::handle_error(const Frame& frame) {
    auto pb_error = FrameCodec::decode_protobuf<pb::FrameError>(frame.data());
    if (!pb_error) {
        log().error("Failed to parse FRAME_ERROR: {}", frame_error_message(pb_error.error()));
        co_return;
    }
    ErrorPayload error;
    from_proto(*pb_error, &error);

    log().error("Control error {}: {}", error.error_code, error.error_msg);

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::ctrl::Event{events::ctrl::Error{error.error_code, error.error_msg}}));
    }
}

void ControlChannel::send_frame(FrameType type, std::span<const uint8_t> payload) {
    auto data = FrameCodec::encode(type, payload);
    send_raw(data);
}

void ControlChannel::send_raw(std::span<const uint8_t> data) {
    write_queue_.push(std::vector<uint8_t>(data.begin(), data.end()));
    if (!writing_) {
        write_timer_.cancel();
    }
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

void RelayChannel::set_event_channel(events::RelayEventChannel* ch) {
    event_ch_ = ch;
}

bool RelayChannel::is_ws_open() const {
    if (use_tls_) {
        return tls_ws_ && tls_ws_->is_open();
    } else {
        return plain_ws_ && plain_ws_->is_open();
    }
}

cobalt::task<bool> RelayChannel::connect(const std::vector<uint8_t>& relay_token) {
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
        auto endpoints = co_await resolver.async_resolve(connect_host, port, cobalt::use_op);

        // 记录所有解析的 endpoints
        size_t endpoint_count = 0;
        std::string endpoint_list;
        for (const auto& ep : endpoints) {
            if (endpoint_count > 0) endpoint_list += ", ";
            endpoint_list += ep.endpoint().address().to_string() + ":" + std::to_string(ep.endpoint().port());
            endpoint_count++;
        }
        // 生成此连接的唯一标识符
        ConnectionId connection_id = static_cast<ConnectionId>(
            std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFF);

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

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, cobalt::use_op);

            // WebSocket handshake (use ws_host as Host header for CDN)
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            co_await tls_ws_->async_handshake(ws_host, target, cobalt::use_op);

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

            // WebSocket handshake (use ws_host as Host header for CDN)
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            co_await plain_ws_->async_handshake(ws_host, target, cobalt::use_op);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().debug("Relay WebSocket connected, authenticating...");
        state_ = ChannelState::AUTHENTICATING;

        // Build RELAY_AUTH
        pb::RelayAuth auth;
        auth.set_relay_token(relay_token.data(), relay_token.size());
        auth.set_node_id(crypto_.node_id());
        auth.set_node_key(crypto_.node_key().public_key.data(), crypto_.node_key().public_key.size());
        auth.set_connection_id(connection_id);  // 设置连接标识符

        // Send RELAY_AUTH
        auto result = FrameCodec::encode_protobuf(FrameType::RELAY_AUTH, auth);
        if (result) {
            send_raw(*result);
        }

        // Start read/write loops
        cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this()]() -> cobalt::task<void> {
            co_await self->read_loop();
        }());

        cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this()]() -> cobalt::task<void> {
            co_await self->write_loop();
        }());

        co_return true;

    } catch (const std::exception& e) {
        log().error("Relay channel connection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

cobalt::task<void> RelayChannel::close() {
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
            // 用 shared_ptr<atomic<bool>> 避免 spawned task 引用已销毁的栈变量
            auto close_completed = std::make_shared<std::atomic<bool>>(false);
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, close_completed]() -> cobalt::task<void> {
                try {
                    co_await tls_ws_->async_close(websocket::close_code::normal, cobalt::use_op);
                    close_completed->store(true);
                } catch (...) {}
            }());

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed->load() && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            closed = close_completed->load();
            if (!closed) {
                log().debug("Relay WebSocket close timeout, forcing shutdown");
                boost::system::error_code ec;
                tls_ws_->next_layer().next_layer().socket().close(ec);
            }
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            auto close_completed = std::make_shared<std::atomic<bool>>(false);
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, close_completed]() -> cobalt::task<void> {
                try {
                    co_await plain_ws_->async_close(websocket::close_code::normal, cobalt::use_op);
                    close_completed->store(true);
                } catch (...) {}
            }());

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (!close_completed->load() && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            closed = close_completed->load();
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

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::relay::Event{events::relay::Disconnected{"connection closed"}}));
    }
}

cobalt::task<bool> RelayChannel::send_data(NodeId peer_id, std::span<const uint8_t> plaintext) {
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

    // Build DATA payload using protobuf
    pb::DataPayload data;
    data.set_src_node(crypto_.node_id());
    data.set_dst_node(peer_id);
    data.set_nonce(nonce.data(), nonce.size());
    data.set_encrypted_payload(encrypted->data(), encrypted->size());

    auto result = FrameCodec::encode_protobuf(FrameType::DATA, data);
    if (result) {
        send_raw(*result);
    }

    co_return true;
}

cobalt::task<void> RelayChannel::send_ping() {
    // Use protobuf Ping message
    pb::Ping ping;
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ping.set_timestamp(now);
    ping.set_seq_num(++ping_seq_);
    last_ping_time_ = now;
    last_ping_steady_ = std::chrono::steady_clock::now();  // 本地 RTT 计算用

    auto result = FrameCodec::encode_protobuf(FrameType::PING, ping);
    if (result) {
        send_raw(*result);
    }
    co_return;
}

cobalt::task<void> RelayChannel::read_loop() {
    try {
        beast::flat_buffer buffer;

        while (is_ws_open()) {
            buffer.clear();

            if (use_tls_) {
                co_await tls_ws_->async_read(buffer, cobalt::use_op);
            } else {
                co_await plain_ws_->async_read(buffer, cobalt::use_op);
            }

            auto data = buffer.data();
            std::span<const uint8_t> span(
                static_cast<const uint8_t*>(data.data()), data.size());

            auto result = FrameCodec::decode(span);
            if (!result) {
                log().warn("Relay: failed to decode frame ({} bytes)", span.size());
                continue;
            }

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
        if (event_ch_) {
            co_await cobalt::as_tuple(event_ch_->write(
                events::relay::Event{events::relay::Disconnected{"read loop ended"}}));
        }
    }
}

cobalt::task<void> RelayChannel::write_loop() {
    try {
        while (is_ws_open()) {
            if (write_queue_.empty()) {
                writing_ = false;
                auto [ec] = co_await write_timer_.async_wait(asio::as_tuple(cobalt::use_op));
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
                    co_await tls_ws_->async_write(asio::buffer(data), cobalt::use_op);
                } else {
                    co_await plain_ws_->async_write(asio::buffer(data), cobalt::use_op);
                }
            }
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().warn("Relay channel write error: {}", e.what());
        }
    }

    // Write loop exited - WebSocket is closed
    if (!write_queue_.empty()) {
        log().warn("Relay write_loop exited, {} queued messages dropped", write_queue_.size());
    }
    writing_ = false;

    // Clear queue to avoid memory leak
    while (!write_queue_.empty()) {
        write_queue_.pop();
    }
}

cobalt::task<void> RelayChannel::handle_frame(const Frame& frame) {
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

cobalt::task<void> RelayChannel::handle_relay_auth_resp(const Frame& frame) {
    auto pb_resp = FrameCodec::decode_protobuf<pb::RelayAuthResp>(frame.data());
    if (!pb_resp) {
        log().error("Failed to parse RELAY_AUTH_RESP");
        co_return;
    }

    RelayAuthResp resp;
    from_proto(*pb_resp, &resp);

    if (!resp.success) {
        log().error("Relay auth failed: {} (code {})", resp.error_msg, resp.error_code);
        co_return;
    }

    state_ = ChannelState::CONNECTED;

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::relay::Event{events::relay::Connected{}}));
    }
}

cobalt::task<void> RelayChannel::handle_data(const Frame& frame) {
    // Use protobuf DataPayload
    auto pb_data = FrameCodec::decode_protobuf<pb::DataPayload>(frame.data());
    if (!pb_data) {
        log().warn("Failed to parse DATA payload: {}", frame_error_message(pb_data.error()));
        co_return;
    }

    // Convert to C++ DataPayload
    DataPayload data;
    from_proto(*pb_data, &data);

    // Ensure session key exists for sender
    if (!peers_.ensure_session_key(data.src_node)) {
        log().warn("Cannot decrypt data from {}: no session key", peers_.get_peer_ip_str(data.src_node));
        co_return;
    }

    // Decrypt
    auto peer_ip = peers_.get_peer_ip_str(data.src_node);
    auto plaintext = crypto_.decrypt(data.src_node, data.nonce, data.encrypted_payload);
    if (!plaintext) {
        log().warn("Failed to decrypt data from {}, renegotiating session key...", peer_ip);

        // Clear old session key and re-derive
        crypto_.remove_session_key(data.src_node);

        // Try to derive new session key
        if (!peers_.ensure_session_key(data.src_node)) {
            log().error("Failed to renegotiate session key for {}", peer_ip);
            co_return;
        }

        log().info("Session key renegotiated for {}", peer_ip);

        // Retry decryption with new key
        plaintext = crypto_.decrypt(data.src_node, data.nonce, data.encrypted_payload);
        if (!plaintext) {
            log().warn("Decryption still failed after renegotiation, {} may have different node_key", peer_ip);
            co_return;
        }

        log().info("Decryption succeeded after session key renegotiation for {}", peer_ip);
    }

    peers_.update_last_seen(data.src_node);

    if (event_ch_) {
        co_await cobalt::as_tuple(event_ch_->write(
            events::relay::Event{events::relay::DataReceived{data.src_node, std::move(*plaintext)}}));
    }
}

cobalt::task<void> RelayChannel::handle_pong(const Frame& frame) {
    // Use protobuf Pong message
    auto pong = FrameCodec::decode_protobuf<pb::Pong>(frame.data());
    if (!pong) {
        log().warn("Failed to parse PONG: {}", frame_error_message(pong.error()));
        co_return;
    }

    // 校验 seq_num 匹配当前 ping
    if (pong->seq_num() != ping_seq_) {
        log().debug("Ignoring stale relay PONG: seq={} (expected {})", pong->seq_num(), ping_seq_);
        co_return;
    }

    // 使用 steady_clock 计算本地 RTT，避免 system_clock 跳变
    if (last_ping_time_ > 0) {
        auto now_steady = std::chrono::steady_clock::now();
        uint16_t rtt_ms = static_cast<uint16_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now_steady - last_ping_steady_).count());

        // Only log if RTT is unusually high
        if (rtt_ms > 500) {
            log().warn("Relay channel high latency: RTT={}ms", rtt_ms);
        }

        // Notify via event channel
        if (event_ch_) {
            co_await cobalt::as_tuple(event_ch_->write(
                events::relay::Event{events::relay::Pong{rtt_ms}}));
        }

        // Per-connection RTT callback (for relay pool tracking)
        if (on_pong_) {
            on_pong_(rtt_ms);
        }
    }

    co_return;
}

void RelayChannel::send_frame(FrameType type, std::span<const uint8_t> payload) {
    auto data = FrameCodec::encode(type, payload);
    send_raw(data);
}

void RelayChannel::send_raw(std::span<const uint8_t> data) {
    write_queue_.push(std::vector<uint8_t>(data.begin(), data.end()));
    if (!writing_) {
        write_timer_.cancel();
    }
}

} // namespace edgelink::client

#include "client/channel.hpp"
#include "common/logger.hpp"
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
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
    , write_timer_(ioc) {
    write_timer_.expires_at(std::chrono::steady_clock::time_point::max());
}

void ControlChannel::set_callbacks(ControlChannelCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
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
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                log().error("Failed to set SNI");
                co_return false;
            }

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);

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

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

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
        } catch (...) {}

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
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                log().error("Failed to set SNI");
                state_ = ChannelState::DISCONNECTED;
                co_return false;
            }

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);

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

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

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

    try {
        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        }
    } catch (...) {}

    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
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
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected();
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
        if (callbacks_.on_error) {
            callbacks_.on_error(resp->error_code, resp->error_msg);
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

    if (callbacks_.on_auth_response) {
        callbacks_.on_auth_response(*resp);
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

    if (callbacks_.on_config) {
        callbacks_.on_config(*config);
    }

    // Mark as connected after receiving initial CONFIG (peers are now populated)
    if (state_ != ChannelState::CONNECTED) {
        state_ = ChannelState::CONNECTED;
        if (callbacks_.on_connected) {
            callbacks_.on_connected();
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

    if (callbacks_.on_config_update) {
        callbacks_.on_config_update(*update);
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

    if (callbacks_.on_error) {
        callbacks_.on_error(error->error_code, error->error_msg);
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
                           const std::string& url, bool use_tls)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , peers_(peers)
    , url_(url)
    , use_tls_(use_tls)
    , write_timer_(ioc) {
    write_timer_.expires_at(std::chrono::steady_clock::time_point::max());
}

void RelayChannel::set_callbacks(RelayChannelCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
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

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls_ ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/relay";

        log().info("Connecting to relay: {}:{}{} (TLS: {})",
                     host, port, target, use_tls_ ? "yes" : "no");

        // Resolve host
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI
            SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str());

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // SSL handshake - verification mode is set in ssl_ctx_ by Client constructor
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);

            // WebSocket handshake
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            co_await tls_ws_->async_handshake(host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*tls_ws_).expires_never();
            tls_ws_->binary(true);

        } else {
            // Create plain stream
            plain_ws_ = std::make_unique<PlainWsStream>(ioc_);

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // WebSocket handshake
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            co_await plain_ws_->async_handshake(host, target, asio::use_awaitable);

            // Disable TCP timeout - WebSocket has its own timeout
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().info("Relay WebSocket connected, authenticating...");
        state_ = ChannelState::AUTHENTICATING;

        // Build RELAY_AUTH
        RelayAuth auth;
        auth.relay_token = relay_token;
        auth.node_id = crypto_.node_id();
        auth.node_key = crypto_.node_key().public_key;

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

    try {
        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        }
    } catch (...) {}

    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
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
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected();
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
    log().info("Relay channel connected");

    if (callbacks_.on_connected) {
        callbacks_.on_connected();
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

    if (callbacks_.on_data) {
        callbacks_.on_data(data->src_node, *plaintext);
    }
}

asio::awaitable<void> RelayChannel::handle_pong(const Frame& frame) {
    // Handle PONG if needed
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

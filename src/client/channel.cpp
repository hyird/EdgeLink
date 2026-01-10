#include "client/channel.hpp"
#include <spdlog/spdlog.h>
#include <chrono>

namespace edgelink::client {

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
            spdlog::error("Invalid control URL: {}", url_);
            co_return false;
        }

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls_ ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/control";

        spdlog::info("Connecting to controller: {}:{}{} (TLS: {})",
                     host, port, target, use_tls_ ? "yes" : "no");

        // Resolve host
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        if (use_tls_) {
            // Create TLS stream
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // Set SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                spdlog::error("Failed to set SNI");
                co_return false;
            }

            // Connect TCP
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // SSL handshake
            tls_ws_->next_layer().set_verify_mode(ssl::verify_none); // TODO: proper verification
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

        spdlog::info("WebSocket connected, authenticating...");
        state_ = ChannelState::AUTHENTICATING;

        // Build AUTH_REQUEST
        AuthRequest req;
        req.auth_type = AuthType::AUTHKEY;
        req.machine_key = crypto_.machine_key().public_key;
        req.node_key = crypto_.node_key().public_key;
        req.hostname = "test-client"; // TODO: get actual hostname
        req.os = "unknown";
        req.arch = "unknown";
        req.version = "1.0.0";
        req.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        req.auth_data = std::vector<uint8_t>(authkey_.begin(), authkey_.end());

        // Sign the request
        auto sign_data = req.get_sign_data();
        auto sig = crypto_.sign(sign_data);
        if (!sig) {
            spdlog::error("Failed to sign AUTH_REQUEST");
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
        spdlog::error("Control channel connection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<bool> ControlChannel::reconnect() {
    // Use machine key auth for reconnection
    // Implementation similar to connect but with AuthType::MACHINE
    co_return false; // TODO: implement
}

asio::awaitable<void> ControlChannel::close() {
    try {
        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        }
    } catch (...) {}

    state_ = ChannelState::DISCONNECTED;

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
                spdlog::warn("Control: failed to decode frame");
                continue;
            }

            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            spdlog::debug("Control channel read error: {}", e.what());
        }
    }

    state_ = ChannelState::DISCONNECTED;
    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
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
            spdlog::debug("Control channel write error: {}", e.what());
        }
    }
}

asio::awaitable<void> ControlChannel::handle_frame(const Frame& frame) {
    spdlog::debug("Control: received {} frame", frame_type_name(frame.header.type));

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
            spdlog::warn("Control: unhandled frame type 0x{:02X}",
                         static_cast<uint8_t>(frame.header.type));
            break;
    }
}

asio::awaitable<void> ControlChannel::handle_auth_response(const Frame& frame) {
    auto resp = AuthResponse::parse(frame.payload);
    if (!resp) {
        spdlog::error("Failed to parse AUTH_RESPONSE");
        co_return;
    }

    if (!resp->success) {
        spdlog::error("Authentication failed: {} (code {})", resp->error_msg, resp->error_code);
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

    spdlog::info("Authenticated as node {} with IP {}", node_id_, virtual_ip_.to_string());

    // Note: state_ is set to CONNECTED after receiving CONFIG, not here
    // This ensures peers are populated before on_connected is called

    if (callbacks_.on_auth_response) {
        callbacks_.on_auth_response(*resp);
    }
}

asio::awaitable<void> ControlChannel::handle_config(const Frame& frame) {
    auto config = Config::parse(frame.payload);
    if (!config) {
        spdlog::error("Failed to parse CONFIG");
        co_return;
    }

    spdlog::info("Received CONFIG v{} with {} peers", config->version, config->peers.size());

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
        spdlog::error("Failed to parse CONFIG_UPDATE");
        co_return;
    }

    spdlog::debug("Received CONFIG_UPDATE v{}", update->version);

    // Update relay token if present
    if (has_flag(update->update_flags, ConfigUpdateFlags::TOKEN_REFRESH)) {
        relay_token_ = update->relay_token;
        spdlog::debug("Relay token refreshed");
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

    spdlog::debug("Control PONG: RTT={}ms", rtt);
}

asio::awaitable<void> ControlChannel::handle_error(const Frame& frame) {
    auto error = ErrorPayload::parse(frame.payload);
    if (!error) {
        co_return;
    }

    spdlog::error("Control error {}: {}", error->error_code, error->error_msg);

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
            spdlog::error("Invalid relay URL: {}", url_);
            co_return false;
        }

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls_ ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/relay";

        spdlog::info("Connecting to relay: {}:{}{} (TLS: {})",
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

            // SSL handshake
            tls_ws_->next_layer().set_verify_mode(ssl::verify_none);
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

        spdlog::info("Relay WebSocket connected, authenticating...");
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
        spdlog::error("Relay channel connection failed: {}", e.what());
        state_ = ChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<void> RelayChannel::close() {
    try {
        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
        }
    } catch (...) {}

    state_ = ChannelState::DISCONNECTED;

    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
    }
}

asio::awaitable<bool> RelayChannel::send_data(NodeId peer_id, std::span<const uint8_t> plaintext) {
    if (state_ != ChannelState::CONNECTED) {
        spdlog::warn("Cannot send data: relay not connected");
        co_return false;
    }

    // Ensure session key exists
    if (!peers_.ensure_session_key(peer_id)) {
        spdlog::warn("Cannot send data to peer {}: no session key", peer_id);
        co_return false;
    }

    // Encrypt
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    auto encrypted = crypto_.encrypt(peer_id, plaintext, nonce);
    if (!encrypted) {
        spdlog::error("Failed to encrypt data for peer {}", peer_id);
        co_return false;
    }

    // Build DATA payload
    DataPayload data;
    data.src_node = crypto_.node_id();
    data.dst_node = peer_id;
    data.nonce = nonce;
    data.encrypted_payload = std::move(*encrypted);

    co_await send_frame(FrameType::DATA, data.serialize());

    spdlog::trace("Sent {} bytes to peer {}", plaintext.size(), peer_id);
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

            spdlog::debug("Relay read_loop: received {} bytes", span.size());

            auto result = FrameCodec::decode(span);
            if (!result) {
                spdlog::warn("Relay: failed to decode frame ({} bytes)", span.size());
                continue;
            }

            spdlog::debug("Relay read_loop: decoded frame type 0x{:02X}",
                         static_cast<uint8_t>(result->first.header.type));
            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            spdlog::debug("Relay channel read error: {}", e.what());
        }
    }

    state_ = ChannelState::DISCONNECTED;
    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
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
            spdlog::debug("Relay channel write error: {}", e.what());
        }
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
            spdlog::warn("Relay: unhandled frame type 0x{:02X}",
                         static_cast<uint8_t>(frame.header.type));
            break;
    }
}

asio::awaitable<void> RelayChannel::handle_relay_auth_resp(const Frame& frame) {
    auto resp = RelayAuthResp::parse(frame.payload);
    if (!resp) {
        spdlog::error("Failed to parse RELAY_AUTH_RESP");
        co_return;
    }

    if (!resp->success) {
        spdlog::error("Relay auth failed: {} (code {})", resp->error_msg, resp->error_code);
        co_return;
    }

    state_ = ChannelState::CONNECTED;
    spdlog::info("Relay channel connected");

    if (callbacks_.on_connected) {
        callbacks_.on_connected();
    }
}

asio::awaitable<void> RelayChannel::handle_data(const Frame& frame) {
    spdlog::debug("Relay handle_data: processing {} bytes", frame.payload.size());

    auto data = DataPayload::parse(frame.payload);
    if (!data) {
        spdlog::warn("Failed to parse DATA payload");
        co_return;
    }

    spdlog::debug("Relay handle_data: DATA from {} to {}, encrypted {} bytes",
                 data->src_node, data->dst_node, data->encrypted_payload.size());

    // Ensure session key exists for sender
    if (!peers_.ensure_session_key(data->src_node)) {
        spdlog::warn("Cannot decrypt data from peer {}: no session key", data->src_node);
        co_return;
    }

    // Decrypt
    auto plaintext = crypto_.decrypt(data->src_node, data->nonce, data->encrypted_payload);
    if (!plaintext) {
        spdlog::warn("Failed to decrypt data from peer {}", data->src_node);
        co_return;
    }

    peers_.update_last_seen(data->src_node);

    spdlog::debug("Relay handle_data: decrypted {} bytes from peer {}", plaintext->size(), data->src_node);

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

// RelayChannelActor 实现

#include "client/relay_channel_actor.hpp"
#include "common/logger.hpp"
#include <chrono>

namespace edgelink::client {

namespace {

auto& log() { return Logger::get("client.relay_actor"); }

} // anonymous namespace

// ============================================================================
// 构造函数和生命周期
// ============================================================================

RelayChannelActor::RelayChannelActor(
    asio::io_context& ioc,
    ssl::context& ssl_ctx,
    CryptoEngine& crypto,
    PeerManager& peers,
    asio::experimental::concurrent_channel<void(boost::system::error_code, RelayChannelEvent)>* event_channel)
    : ActorBase(ioc, "RelayChannelActor")
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , peers_(peers)
    , event_channel_(event_channel)
    , write_timer_(ioc) {
    write_timer_.expires_at(std::chrono::steady_clock::time_point::max());
}

asio::awaitable<void> RelayChannelActor::on_start() {
    log().info("[{}] Actor started", name_);
    co_return;
}

asio::awaitable<void> RelayChannelActor::on_stop() {
    log().info("[{}] Actor stopping", name_);

    // 停止读写循环
    read_loop_running_ = false;
    write_loop_running_ = false;

    // 关闭 WebSocket 连接
    co_await close_websocket();

    log().info("[{}] Actor stopped", name_);
}

// ============================================================================
// 消息处理
// ============================================================================

asio::awaitable<void> RelayChannelActor::handle_message(RelayChannelCommand cmd) {
    if (std::holds_alternative<LifecycleMessage>(cmd)) {
        auto& lifecycle = std::get<LifecycleMessage>(cmd);
        log().debug("[{}] Received lifecycle message: type={}", name_, static_cast<int>(lifecycle.type));

        if (lifecycle.type == LifecycleType::STOP) {
            co_await on_stop();
        } else if (lifecycle.type == LifecycleType::RECONNECT) {
            // 重连逻辑：关闭后重新连接
            co_await close_websocket();
            if (!relay_token_.empty()) {
                co_await connect_websocket(url_, relay_token_, use_tls_);
            }
        }
        co_return;
    }

    auto& relay_cmd = std::get<RelayChannelCmd>(cmd);
    log().debug("[{}] Received command: type={}", name_, static_cast<int>(relay_cmd.type));

    switch (relay_cmd.type) {
        case RelayCmdType::CONNECT:
            co_await handle_connect_cmd(relay_cmd);
            break;

        case RelayCmdType::CLOSE:
            co_await handle_close_cmd();
            break;

        case RelayCmdType::SEND_DATA:
            co_await handle_send_data_cmd(relay_cmd);
            break;

        default:
            log().warn("[{}] Unhandled command type: {}", name_, static_cast<int>(relay_cmd.type));
            break;
    }
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> RelayChannelActor::handle_connect_cmd(const RelayChannelCmd& cmd) {
    log().info("[{}] Handling CONNECT command: url={}", name_, cmd.url);

    // 保存连接参数
    url_ = cmd.url;
    relay_token_ = cmd.relay_token;
    use_tls_ = cmd.use_tls;

    // 连接 WebSocket
    bool success = co_await connect_websocket(url_, relay_token_, use_tls_);

    if (!success) {
        log().error("[{}] Failed to connect to relay", name_);

        // 发送错误事件
        RelayChannelEvent event;
        event.type = RelayEventType::RELAY_ERROR;
        event.reason = "Failed to connect to relay server";
        send_event(event);
    }
}

asio::awaitable<void> RelayChannelActor::handle_close_cmd() {
    log().info("[{}] Handling CLOSE command", name_);
    co_await close_websocket();
}

asio::awaitable<void> RelayChannelActor::handle_send_data_cmd(const RelayChannelCmd& cmd) {
    if (conn_state_ != RelayChannelState::CONNECTED) {
        log().warn("[{}] Cannot send data: not connected (state={})",
                   name_, relay_channel_state_name(conn_state_));
        co_return;
    }

    if (!is_ws_open()) {
        log().warn("[{}] Cannot send data: WebSocket not open", name_);
        conn_state_ = RelayChannelState::DISCONNECTED;
        co_return;
    }

    // 确保会话密钥存在
    if (!peers_.ensure_session_key(cmd.peer_id)) {
        log().warn("[{}] Cannot send data to {}: no session key",
                   name_, peers_.get_peer_ip_str(cmd.peer_id));
        co_return;
    }

    // 加密数据
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    auto encrypted = crypto_.encrypt(cmd.peer_id, *cmd.plaintext, nonce);
    if (!encrypted) {
        log().error("[{}] Failed to encrypt data for {}",
                    name_, peers_.get_peer_ip_str(cmd.peer_id));
        co_return;
    }

    // 构建 DATA payload
    DataPayload data;
    data.src_node = crypto_.node_id();
    data.dst_node = cmd.peer_id;
    data.nonce = nonce;
    data.encrypted_payload = std::move(*encrypted);

    // 发送帧
    co_await send_frame(FrameType::DATA, data.serialize());

    log().debug("[{}] Queued {} bytes for {} (encrypted {} bytes)",
                name_, cmd.plaintext->size(),
                peers_.get_peer_ip_str(cmd.peer_id),
                data.encrypted_payload.size());
}

// ============================================================================
// WebSocket 管理
// ============================================================================

asio::awaitable<bool> RelayChannelActor::connect_websocket(
    const std::string& url,
    const std::vector<uint8_t>& relay_token,
    bool use_tls) {

    try {
        conn_state_ = RelayChannelState::CONNECTING;

        // 解析 URL
        auto parsed = boost::urls::parse_uri(url);
        if (!parsed) {
            log().error("[{}] Invalid relay URL: {}", name_, url);
            co_return false;
        }

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/relay";

        log().info("[{}] Connecting to relay: {}:{}{} (TLS: {})",
                   name_, host, port, target, use_tls ? "yes" : "no");

        // DNS 解析
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        if (use_tls) {
            // 创建 TLS WebSocket 流
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // 设置 SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                log().error("[{}] Failed to set SNI", name_);
                co_return false;
            }

            // TCP 连接
            auto& tcp_stream = beast::get_lowest_layer(*tls_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // SSL 握手
            co_await tls_ws_->next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);

            // WebSocket 握手
            tls_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            tls_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await tls_ws_->async_handshake(host, target, asio::use_awaitable);

            // 禁用 TCP 超时 - WebSocket 有自己的超时机制
            beast::get_lowest_layer(*tls_ws_).expires_never();
            tls_ws_->binary(true);

        } else {
            // 创建明文 WebSocket 流
            plain_ws_ = std::make_unique<PlainWsStream>(ioc_);

            // TCP 连接
            auto& tcp_stream = beast::get_lowest_layer(*plain_ws_);
            tcp_stream.expires_after(std::chrono::seconds(30));
            co_await tcp_stream.async_connect(endpoints, asio::use_awaitable);

            // WebSocket 握手
            plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
            plain_ws_->set_option(websocket::stream_base::decorator(
                [](websocket::request_type& req) {
                    req.set(beast::http::field::user_agent, "EdgeLink Client/1.0");
                }));

            co_await plain_ws_->async_handshake(host, target, asio::use_awaitable);

            // 禁用 TCP 超时
            beast::get_lowest_layer(*plain_ws_).expires_never();
            plain_ws_->binary(true);
        }

        log().info("[{}] WebSocket connected, authenticating...", name_);
        conn_state_ = RelayChannelState::AUTHENTICATING;

        // 构建 RELAY_AUTH
        RelayAuth auth;
        auth.relay_token = relay_token;
        auth.node_id = crypto_.node_id();
        auth.node_key = crypto_.node_key().public_key;

        // 发送 RELAY_AUTH
        co_await send_frame(FrameType::RELAY_AUTH, auth.serialize());

        // 启动读写循环
        read_loop_running_ = true;
        write_loop_running_ = true;

        asio::co_spawn(ioc_, read_loop(), asio::detached);
        asio::co_spawn(ioc_, write_loop(), asio::detached);

        co_return true;

    } catch (const std::exception& e) {
        log().error("[{}] Relay channel connection failed: {}", name_, e.what());
        conn_state_ = RelayChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<void> RelayChannelActor::close_websocket() {
    if (conn_state_ == RelayChannelState::DISCONNECTED) {
        co_return;
    }

    conn_state_ = RelayChannelState::DISCONNECTED;

    // 停止读写循环
    read_loop_running_ = false;
    write_loop_running_ = false;

    // 使用超时保护的关闭操作，避免卡住
    try {
        asio::steady_timer timeout_timer(ioc_);
        timeout_timer.expires_after(std::chrono::seconds(3));

        bool closed = false;

        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            // 尝试优雅关闭，但有超时保护
            auto result = co_await (
                tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable) ||
                timeout_timer.async_wait(asio::use_awaitable)
            );
            closed = (result.index() == 0);
            if (!closed) {
                // 超时，直接关闭底层连接
                log().debug("[{}] WebSocket close timeout, forcing shutdown", name_);
                boost::system::error_code ec;
                tls_ws_->next_layer().next_layer().socket().close(ec);
            }
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            auto result = co_await (
                plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable) ||
                timeout_timer.async_wait(asio::use_awaitable)
            );
            closed = (result.index() == 0);
            if (!closed) {
                log().debug("[{}] WebSocket close timeout, forcing shutdown", name_);
                boost::system::error_code ec;
                plain_ws_->next_layer().socket().close(ec);
            }
        }
    } catch (...) {}

    // 发送断开事件
    RelayChannelEvent event;
    event.type = RelayEventType::DISCONNECTED;
    event.reason = "Connection closed";
    send_event(event);
}

bool RelayChannelActor::is_ws_open() const {
    if (use_tls_) {
        return tls_ws_ && tls_ws_->is_open();
    } else {
        return plain_ws_ && plain_ws_->is_open();
    }
}

// ============================================================================
// WebSocket I/O 循环
// ============================================================================

asio::awaitable<void> RelayChannelActor::read_loop() {
    log().debug("[{}] Read loop started", name_);

    try {
        beast::flat_buffer buffer;

        while (read_loop_running_.load() && is_ws_open()) {
            buffer.clear();

            // 读取 WebSocket 消息
            if (use_tls_) {
                co_await tls_ws_->async_read(buffer, asio::use_awaitable);
            } else {
                co_await plain_ws_->async_read(buffer, asio::use_awaitable);
            }

            auto data = buffer.data();
            std::span<const uint8_t> span(
                static_cast<const uint8_t*>(data.data()), data.size());

            log().debug("[{}] Read {} bytes from relay", name_, span.size());

            // 解码帧
            auto result = FrameCodec::decode(span);
            if (!result) {
                log().warn("[{}] Failed to decode frame ({} bytes)", name_, span.size());
                continue;
            }

            // 处理帧
            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            log().debug("[{}] Relay channel read error: {}", name_, e.what());
        }
    }

    log().debug("[{}] Read loop exited", name_);

    // 发送断开事件（如果还未断开）
    if (conn_state_ != RelayChannelState::DISCONNECTED) {
        conn_state_ = RelayChannelState::DISCONNECTED;

        RelayChannelEvent event;
        event.type = RelayEventType::DISCONNECTED;
        event.reason = "Read loop exited";
        send_event(event);
    }
}

asio::awaitable<void> RelayChannelActor::write_loop() {
    log().debug("[{}] Write loop started", name_);

    try {
        while (write_loop_running_.load() && is_ws_open()) {
            // 如果队列为空，等待
            if (write_queue_.empty()) {
                writing_ = false;
                boost::system::error_code ec;
                co_await write_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));

                // 定时器被取消意味着有新数据到达，继续循环
                if (ec == asio::error::operation_aborted) {
                    continue;
                }
                if (ec) {
                    log().debug("[{}] Write timer error: {}", name_, ec.message());
                    break;
                }
            }

            // 从队列中批量发送
            writing_ = true;
            while (!write_queue_.empty() && is_ws_open()) {
                auto data = std::move(write_queue_.front());
                write_queue_.pop();

                log().debug("[{}] Sending {} bytes to relay", name_, data.size());

                if (use_tls_) {
                    co_await tls_ws_->async_write(asio::buffer(data), asio::use_awaitable);
                } else {
                    co_await plain_ws_->async_write(asio::buffer(data), asio::use_awaitable);
                }

                log().debug("[{}] Sent {} bytes to relay", name_, data.size());
            }
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().warn("[{}] Relay channel write error: {}", name_, e.what());
        }
    }

    log().debug("[{}] Write loop exited, {} queued messages dropped",
                name_, write_queue_.size());
    writing_ = false;

    // 清空队列避免内存泄漏
    while (!write_queue_.empty()) {
        write_queue_.pop();
    }
}

// ============================================================================
// 帧处理
// ============================================================================

asio::awaitable<void> RelayChannelActor::handle_frame(const Frame& frame) {
    log().debug("[{}] Received {} frame",
                name_, frame_type_name(frame.header.type));

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
            log().warn("[{}] Unhandled frame type 0x{:02X}",
                       name_, static_cast<uint8_t>(frame.header.type));
            break;
    }
}

asio::awaitable<void> RelayChannelActor::handle_relay_auth_resp(const Frame& frame) {
    auto resp = RelayAuthResp::parse(frame.payload);
    if (!resp) {
        log().error("[{}] Failed to parse RELAY_AUTH_RESP", name_);
        co_return;
    }

    if (!resp->success) {
        log().error("[{}] Relay auth failed: {} (code {})",
                    name_, resp->error_msg, resp->error_code);

        // 发送错误事件
        RelayChannelEvent event;
        event.type = RelayEventType::RELAY_ERROR;
        event.reason = resp->error_msg;
        send_event(event);
        co_return;
    }

    conn_state_ = RelayChannelState::CONNECTED;
    log().info("[{}] Relay channel connected", name_);

    // 发送连接成功事件
    RelayChannelEvent event;
    event.type = RelayEventType::CONNECTED;
    send_event(event);
}

asio::awaitable<void> RelayChannelActor::handle_data(const Frame& frame) {
    log().debug("[{}] Processing DATA frame ({} bytes)",
                name_, frame.payload.size());

    auto data = DataPayload::parse(frame.payload);
    if (!data) {
        log().warn("[{}] Failed to parse DATA payload", name_);
        co_return;
    }

    log().debug("[{}] DATA from {} to me, encrypted {} bytes",
                name_, peers_.get_peer_ip_str(data->src_node),
                data->encrypted_payload.size());

    // 确保发送者的会话密钥存在
    if (!peers_.ensure_session_key(data->src_node)) {
        log().warn("[{}] Cannot decrypt data from {}: no session key",
                   name_, peers_.get_peer_ip_str(data->src_node));
        co_return;
    }

    // 解密数据
    auto peer_ip = peers_.get_peer_ip_str(data->src_node);
    auto plaintext = crypto_.decrypt(data->src_node, data->nonce, data->encrypted_payload);
    if (!plaintext) {
        log().warn("[{}] Failed to decrypt data from {}, renegotiating session key...",
                   name_, peer_ip);

        // 清除旧的会话密钥并重新推导
        crypto_.remove_session_key(data->src_node);

        // 尝试推导新的会话密钥
        if (!peers_.ensure_session_key(data->src_node)) {
            log().error("[{}] Failed to renegotiate session key for {}", name_, peer_ip);
            co_return;
        }

        log().info("[{}] Session key renegotiated for {}", name_, peer_ip);

        // 使用新密钥重试解密
        plaintext = crypto_.decrypt(data->src_node, data->nonce, data->encrypted_payload);
        if (!plaintext) {
            log().warn("[{}] Decryption still failed after renegotiation, {} may have different node_key",
                       name_, peer_ip);
            co_return;
        }

        log().info("[{}] Decryption succeeded after session key renegotiation for {}",
                   name_, peer_ip);
    }

    peers_.update_last_seen(data->src_node);

    log().debug("[{}] Decrypted {} bytes from {}",
                name_, plaintext->size(), peer_ip);

    // 发送数据接收事件
    RelayChannelEvent event;
    event.type = RelayEventType::DATA_RECEIVED;
    event.src_node = data->src_node;
    event.plaintext = std::make_shared<std::vector<uint8_t>>(std::move(*plaintext));
    send_event(event);
}

asio::awaitable<void> RelayChannelActor::handle_pong(const Frame& frame) {
    // 处理 PONG（如果需要）
    log().debug("[{}] Received PONG", name_);
    co_return;
}

// ============================================================================
// 帧发送
// ============================================================================

asio::awaitable<void> RelayChannelActor::send_frame(FrameType type, std::span<const uint8_t> payload) {
    auto data = FrameCodec::encode(type, payload);
    co_await send_raw(data);
}

asio::awaitable<void> RelayChannelActor::send_raw(std::span<const uint8_t> data) {
    write_queue_.push(std::vector<uint8_t>(data.begin(), data.end()));
    if (!writing_) {
        write_timer_.cancel();
    }
    co_return;
}

// ============================================================================
// 事件发送
// ============================================================================

void RelayChannelActor::send_event(RelayChannelEvent event) {
    if (event_channel_) {
        event_channel_->try_send(boost::system::error_code{}, event);
    }
}

} // namespace edgelink::client

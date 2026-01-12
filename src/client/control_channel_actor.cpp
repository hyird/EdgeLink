// ControlChannelActor 实现

#include "client/control_channel_actor.hpp"
#include "common/logger.hpp"
#include "common/frame.hpp"

#include <chrono>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <limits.h>
#endif

namespace edgelink::client {

namespace {

// 获取系统主机名（跨平台）
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

// 获取操作系统名称
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

// 获取架构
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

// 所有消息类型已在头文件中通过 using 声明引入

// ============================================================================
// 构造函数
// ============================================================================

ControlChannelActor::ControlChannelActor(
    asio::io_context& ioc,
    ssl::context& ssl_ctx,
    CryptoEngine& crypto,
    asio::experimental::concurrent_channel<void(boost::system::error_code, messages::ControlChannelEvent)>* event_channel)
    : ActorBase(ioc, "ControlChannelActor", 64, false)  // mailbox 仍使用普通 channel（strand 内部通信）
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , event_channel_(event_channel)
    , write_timer_(ioc) {
}

// ============================================================================
// ActorBase 接口实现
// ============================================================================

asio::awaitable<void> ControlChannelActor::on_start() {
    auto& log = Logger::get("ControlChannelActor");
    log.info("[{}] Actor starting", name_);
    co_return;
}

asio::awaitable<void> ControlChannelActor::on_stop() {
    auto& log = Logger::get("ControlChannelActor");
    log.info("[{}] Actor stopping", name_);

    // 停止读写循环
    read_loop_running_ = false;
    write_loop_running_ = false;

    // 关闭 WebSocket
    co_await close_websocket();

    log.info("[{}] Actor stopped", name_);
    co_return;
}

asio::awaitable<void> ControlChannelActor::handle_message(ControlChannelCommand cmd) {
    auto& log = Logger::get("ControlChannelActor");

    co_await std::visit([this, &log](auto&& m) -> asio::awaitable<void> {
        using T = std::decay_t<decltype(m)>;

        if constexpr (std::is_same_v<T, ControlChannelCmd>) {
            // 处理控制命令
            switch (m.type) {
                case CtrlCmdType::CONNECT:
                    co_await handle_connect_cmd(m);
                    break;

                case CtrlCmdType::RECONNECT:
                    co_await handle_reconnect_cmd();
                    break;

                case CtrlCmdType::CLOSE:
                    co_await handle_close_cmd();
                    break;

                case CtrlCmdType::SEND_PING:
                    co_await handle_send_ping_cmd();
                    break;

                case CtrlCmdType::SEND_ENDPOINT_UPDATE:
                    co_await handle_send_endpoint_update_cmd(m);
                    break;

                case CtrlCmdType::SEND_P2P_INIT:
                    co_await handle_send_p2p_init_cmd(m);
                    break;

                case CtrlCmdType::SEND_ROUTE_ANNOUNCE:
                    co_await handle_send_route_announce_cmd(m);
                    break;

                default:
                    log.warn("[{}] Unknown command type", name_);
                    break;
            }
        } else if constexpr (std::is_same_v<T, LifecycleMessage>) {
            // 处理生命周期消息
            switch (m.type) {
                case LifecycleType::STOP:
                    co_await stop();
                    break;

                case LifecycleType::RESTART:
                    co_await restart();
                    break;

                default:
                    log.warn("[{}] Unknown lifecycle message", name_);
                    break;
            }
        }
    }, cmd);
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> ControlChannelActor::handle_connect_cmd(const ControlChannelCmd& cmd) {
    auto& log = Logger::get("ControlChannelActor");
    log.info("[{}] Handling CONNECT command: url={}", name_, cmd.url);

    bool success = co_await connect_websocket(cmd.url, cmd.authkey, cmd.use_tls);

    if (!success) {
        // 发送错误事件
        ControlChannelEvent event;
        event.type = CtrlEventType::CTRL_ERROR;
        event.error_code = 1001;
        event.reason = "Failed to connect to controller";
        send_event(event);
    }
}

asio::awaitable<void> ControlChannelActor::handle_reconnect_cmd() {
    auto& log = Logger::get("ControlChannelActor");
    log.info("[{}] Handling RECONNECT command", name_);

    // 关闭现有连接
    co_await close_websocket();

    // 使用保存的凭据重新连接
    bool success = co_await connect_websocket(url_, authkey_, use_tls_);

    if (!success) {
        ControlChannelEvent event;
        event.type = CtrlEventType::CTRL_ERROR;
        event.error_code = 1002;
        event.reason = "Failed to reconnect to controller";
        send_event(event);
    }
}

asio::awaitable<void> ControlChannelActor::handle_close_cmd() {
    auto& log = Logger::get("ControlChannelActor");
    log.info("[{}] Handling CLOSE command", name_);
    co_await close_websocket();
}

asio::awaitable<void> ControlChannelActor::handle_send_ping_cmd() {
    auto& log = Logger::get("ControlChannelActor");

    if (!is_connected()) {
        log.warn("[{}] Cannot send PING: not connected", name_);
        co_return;
    }

    // 构造 PING 消息
    Ping ping;
    ping.seq_num = ++ping_seq_;
    ping.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    last_ping_time_ = ping.timestamp;

    auto payload = ping.serialize();
    co_await send_frame(FrameType::PING, payload);

    log.debug("[{}] Sent PING seq={}", name_, ping.seq_num);
}

asio::awaitable<void> ControlChannelActor::handle_send_endpoint_update_cmd(const ControlChannelCmd& cmd) {
    auto& log = Logger::get("ControlChannelActor");

    if (!is_connected()) {
        log.warn("[{}] Cannot send ENDPOINT_UPDATE: not connected", name_);
        co_return;
    }

    // 构造 ENDPOINT_UPDATE 消息
    EndpointUpdate update;
    update.request_id = cmd.request_id != 0 ? cmd.request_id : ++endpoint_request_id_;
    update.endpoints = cmd.endpoints;

    // 保存待确认的端点
    pending_endpoint_request_id_ = update.request_id;
    pending_endpoints_ = cmd.endpoints;
    endpoint_ack_pending_ = true;

    auto payload = update.serialize();
    co_await send_frame(FrameType::ENDPOINT_UPDATE, payload);

    log.debug("[{}] Sent ENDPOINT_UPDATE request_id={}, {} endpoints",
              name_, update.request_id, cmd.endpoints.size());
}

asio::awaitable<void> ControlChannelActor::handle_send_p2p_init_cmd(const ControlChannelCmd& cmd) {
    auto& log = Logger::get("ControlChannelActor");

    if (!is_connected()) {
        log.warn("[{}] Cannot send P2P_INIT: not connected", name_);
        co_return;
    }

    auto payload = cmd.p2p_init.serialize();
    co_await send_frame(FrameType::P2P_INIT, payload);

    log.debug("[{}] Sent P2P_INIT to peer={}", name_, cmd.p2p_init.target_node);
}

asio::awaitable<void> ControlChannelActor::handle_send_route_announce_cmd(const ControlChannelCmd& cmd) {
    auto& log = Logger::get("ControlChannelActor");

    if (!is_connected()) {
        log.warn("[{}] Cannot send ROUTE_ANNOUNCE: not connected", name_);
        co_return;
    }

    RouteAnnounce announce;
    announce.request_id = ++route_request_id_;
    announce.routes = cmd.routes;

    auto payload = announce.serialize();
    co_await send_frame(FrameType::ROUTE_ANNOUNCE, payload);

    log.debug("[{}] Sent ROUTE_ANNOUNCE: {} routes", name_, cmd.routes.size());
}

// ============================================================================
// 事件发送
// ============================================================================

void ControlChannelActor::send_event(ControlChannelEvent event) {
    if (event_channel_) {
        event_channel_->try_send(boost::system::error_code{}, std::move(event));
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

bool ControlChannelActor::is_ws_open() const {
    if (use_tls_ && tls_ws_) {
        return tls_ws_->is_open();
    } else if (!use_tls_ && plain_ws_) {
        return plain_ws_->is_open();
    }
    return false;
}

// ============================================================================
// WebSocket 连接管理（占位实现，待完整实现）
// ============================================================================

asio::awaitable<bool> ControlChannelActor::connect_websocket(
    const std::string& url, const std::string& authkey, bool use_tls) {
    auto& log = Logger::get("ControlChannelActor");

    // 保存连接参数
    url_ = url;
    authkey_ = authkey;
    use_tls_ = use_tls;

    try {
        conn_state_ = ControlChannelState::CONNECTING;

        // 解析 URL
        auto parsed = boost::urls::parse_uri(url);
        if (!parsed) {
            log.error("[{}] Invalid control URL: {}", name_, url);
            co_return false;
        }

        std::string host = std::string(parsed->host());
        std::string port = parsed->has_port() ? std::string(parsed->port()) :
                           (use_tls ? "443" : "80");
        std::string target = std::string(parsed->path());
        if (target.empty()) target = "/api/v1/control";

        log.info("[{}] Connecting to controller: {}:{}{} (TLS: {})",
                 name_, host, port, target, use_tls ? "yes" : "no");

        // 解析主机地址
        tcp::resolver resolver(ioc_);
        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        if (use_tls) {
            // 创建 TLS WebSocket 流
            tls_ws_ = std::make_unique<TlsWsStream>(ioc_, ssl_ctx_);

            // 设置 SNI
            if (!SSL_set_tlsext_host_name(tls_ws_->next_layer().native_handle(), host.c_str())) {
                log.error("[{}] Failed to set SNI", name_);
                co_return false;
            }

            // 连接 TCP
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

            // 禁用 TCP 超时，WebSocket 有自己的超时机制
            beast::get_lowest_layer(*tls_ws_).expires_never();
            tls_ws_->binary(true);

        } else {
            // 创建明文 WebSocket 流
            plain_ws_ = std::make_unique<PlainWsStream>(ioc_);

            // 连接 TCP
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

        log.info("[{}] WebSocket connected, authenticating...", name_);
        conn_state_ = ControlChannelState::AUTHENTICATING;

        // 构造并发送 AUTH_REQUEST
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
        req.auth_data = std::vector<uint8_t>(authkey.begin(), authkey.end());

        // 签名请求
        auto sign_data = req.get_sign_data();
        auto sig = crypto_.sign(sign_data);
        if (!sig) {
            log.error("[{}] Failed to sign AUTH_REQUEST", name_);
            co_return false;
        }
        req.signature = std::move(*sig);

        // 发送认证请求
        auto payload = req.serialize();
        co_await send_frame(FrameType::AUTH_REQUEST, payload);

        // 启动读写循环
        read_loop_running_ = true;
        write_loop_running_ = true;

        asio::co_spawn(ioc_, read_loop(), asio::detached);
        asio::co_spawn(ioc_, write_loop(), asio::detached);

        log.info("[{}] Control channel initialized, waiting for AUTH_RESPONSE", name_);
        co_return true;

    } catch (const std::exception& e) {
        log.error("[{}] Connection failed: {}", name_, e.what());
        conn_state_ = ControlChannelState::DISCONNECTED;
        co_return false;
    }
}

asio::awaitable<void> ControlChannelActor::close_websocket() {
    auto& log = Logger::get("ControlChannelActor");
    log.debug("[{}] Closing WebSocket connection", name_);

    // 停止读写循环
    read_loop_running_ = false;
    write_loop_running_ = false;

    // 取消写入定时器
    write_timer_.cancel();

    try {
        if (use_tls_ && tls_ws_ && tls_ws_->is_open()) {
            // 设置超时以防止无限等待
            beast::get_lowest_layer(*tls_ws_).expires_after(std::chrono::seconds(5));
            co_await tls_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
            tls_ws_.reset();
        } else if (!use_tls_ && plain_ws_ && plain_ws_->is_open()) {
            beast::get_lowest_layer(*plain_ws_).expires_after(std::chrono::seconds(5));
            co_await plain_ws_->async_close(websocket::close_code::normal, asio::use_awaitable);
            plain_ws_.reset();
        }
    } catch (const std::exception& e) {
        log.debug("[{}] WebSocket close error (ignored): {}", name_, e.what());
    }

    conn_state_ = ControlChannelState::DISCONNECTED;
    log.info("[{}] WebSocket closed", name_);
}

asio::awaitable<void> ControlChannelActor::read_loop() {
    auto& log = Logger::get("ControlChannelActor");
    log.debug("[{}] Read loop started", name_);

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

            // 解码帧
            auto data = buffer.data();
            std::span<const uint8_t> span(
                static_cast<const uint8_t*>(data.data()), data.size());

            auto result = FrameCodec::decode(span);
            if (!result) {
                log.warn("[{}] Failed to decode frame", name_);
                continue;
            }

            // 处理帧
            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            log.debug("[{}] Read loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log.error("[{}] Read loop exception: {}", name_, e.what());
    }

    // 连接断开，发送事件
    if (conn_state_ != ControlChannelState::DISCONNECTED) {
        conn_state_ = ControlChannelState::DISCONNECTED;

        ControlChannelEvent event;
        event.type = CtrlEventType::DISCONNECTED;
        event.reason = "Connection closed";
        send_event(event);
    }

    log.debug("[{}] Read loop stopped", name_);
}

asio::awaitable<void> ControlChannelActor::write_loop() {
    auto& log = Logger::get("ControlChannelActor");
    log.debug("[{}] Write loop started", name_);

    try {
        while (write_loop_running_.load() && is_ws_open()) {
            // 如果队列为空，等待定时器
            if (write_queue_.empty()) {
                writing_ = false;
                boost::system::error_code ec;
                co_await write_timer_.async_wait(asio::redirect_error(asio::use_awaitable, ec));

                // 定时器被取消意味着有新数据到达，继续循环
                if (ec == asio::error::operation_aborted) {
                    continue;
                }
                if (ec) {
                    break;
                }
            }

            // 批量发送队列中的数据
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
            log.debug("[{}] Write loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log.error("[{}] Write loop exception: {}", name_, e.what());
    }

    log.debug("[{}] Write loop stopped", name_);
}

asio::awaitable<void> ControlChannelActor::send_frame(FrameType type, std::span<const uint8_t> payload) {
    // 编码帧
    auto encoded = FrameCodec::encode(type, payload);

    // 发送原始数据
    co_await send_raw(encoded);
}

asio::awaitable<void> ControlChannelActor::send_raw(std::span<const uint8_t> data) {
    if (!is_ws_open()) {
        co_return;
    }

    // 将数据放入写队列
    write_queue_.push(std::vector<uint8_t>(data.begin(), data.end()));

    // 如果写循环空闲，唤醒它
    if (!writing_) {
        write_timer_.cancel();
    }

    co_return;
}

asio::awaitable<void> ControlChannelActor::handle_frame(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");
    log.debug("[{}] Received {} frame", name_, frame_type_name(frame.header.type));

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
            log.warn("[{}] Unhandled frame type: {}", name_, frame_type_name(frame.header.type));
            break;
    }
}

asio::awaitable<void> ControlChannelActor::handle_auth_response(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto resp = AuthResponse::parse(frame.payload);
    if (!resp) {
        log.error("[{}] Failed to parse AUTH_RESPONSE", name_);
        co_return;
    }

    if (!resp->success) {
        log.error("[{}] Authentication failed: {} (code {})",
                  name_, resp->error_msg, resp->error_code);

        ControlChannelEvent event;
        event.type = CtrlEventType::CTRL_ERROR;
        event.error_code = resp->error_code;
        event.reason = resp->error_msg;
        send_event(event);
        co_return;
    }

    // 保存认证信息
    node_id_ = resp->node_id;
    network_id_ = resp->network_id;
    virtual_ip_ = resp->virtual_ip;
    // subnet_mask 会在 CONFIG 中获取
    auth_token_ = resp->auth_token;
    relay_token_ = resp->relay_token;

    crypto_.set_node_id(node_id_);

    log.info("[{}] Authenticated as node {} with IP {}",
             name_, node_id_, virtual_ip_.to_string());

    // 发送认证响应事件
    ControlChannelEvent event;
    event.type = CtrlEventType::AUTH_RESPONSE;
    event.node_id = node_id_;
    event.virtual_ip = virtual_ip_;
    event.relay_token = relay_token_;
    event.auth_response = *resp;
    send_event(event);
}

asio::awaitable<void> ControlChannelActor::handle_config(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto config = Config::parse(frame.payload);
    if (!config) {
        log.error("[{}] Failed to parse CONFIG", name_);
        co_return;
    }

    log.info("[{}] Received CONFIG v{} with {} peers",
             name_, config->version, config->peers.size());

    // 更新子网掩码
    subnet_mask_ = config->subnet_mask;

    // 更新 relay token（如果存在）
    if (!config->relay_token.empty()) {
        relay_token_ = config->relay_token;
    }

    // 标记为已连接
    conn_state_ = ControlChannelState::CONNECTED;

    // 发送配置接收事件
    ControlChannelEvent event;
    event.type = CtrlEventType::CONFIG_RECEIVED;
    event.config = *config;
    send_event(event);

    // 发送连接成功事件
    ControlChannelEvent connected_event;
    connected_event.type = CtrlEventType::CONNECTED;
    send_event(connected_event);
}

asio::awaitable<void> ControlChannelActor::handle_config_update(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto update = ConfigUpdate::parse(frame.payload);
    if (!update) {
        log.error("[{}] Failed to parse CONFIG_UPDATE", name_);
        co_return;
    }

    log.info("[{}] Received CONFIG_UPDATE v{} with {} added, {} removed peers",
             name_, update->version, update->add_peers.size(), update->del_peer_ids.size());

    // 发送配置更新事件
    ControlChannelEvent event;
    event.type = CtrlEventType::CONFIG_RECEIVED;  // 复用 CONFIG_RECEIVED
    // TODO: 需要在 ControlChannelEvent 中添加 config_update 字段
    send_event(event);
}

asio::awaitable<void> ControlChannelActor::handle_route_update(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto update = RouteUpdate::parse(frame.payload);
    if (!update) {
        log.error("[{}] Failed to parse ROUTE_UPDATE", name_);
        co_return;
    }

    log.info("[{}] Received ROUTE_UPDATE v{} with {} added, {} removed routes",
             name_, update->version, update->add_routes.size(), update->del_routes.size());

    // 发送路由更新事件
    ControlChannelEvent event;
    event.type = CtrlEventType::ROUTE_UPDATE;
    event.route_update = *update;
    send_event(event);
}

asio::awaitable<void> ControlChannelActor::handle_route_ack(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto ack = RouteAck::parse(frame.payload);
    if (!ack) {
        log.error("[{}] Failed to parse ROUTE_ACK", name_);
        co_return;
    }

    log.debug("[{}] Received ROUTE_ACK for request_id={}", name_, ack->request_id);
    // 路由确认不需要特殊处理
}

asio::awaitable<void> ControlChannelActor::handle_p2p_endpoint(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto msg = P2PEndpointMsg::parse(frame.payload);
    if (!msg) {
        log.error("[{}] Failed to parse P2P_ENDPOINT", name_);
        co_return;
    }

    log.info("[{}] Received P2P_ENDPOINT for peer {} with {} endpoints",
             name_, msg->peer_node, msg->endpoints.size());

    // 发送 P2P 端点事件
    ControlChannelEvent event;
    event.type = CtrlEventType::P2P_ENDPOINT;
    event.p2p_endpoint = *msg;
    send_event(event);
}

asio::awaitable<void> ControlChannelActor::handle_endpoint_ack(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto ack = EndpointAck::parse(frame.payload);
    if (!ack) {
        log.error("[{}] Failed to parse ENDPOINT_ACK", name_);
        co_return;
    }

    log.debug("[{}] Received ENDPOINT_ACK for request_id={}", name_, ack->request_id);

    // 清除待确认状态
    if (endpoint_ack_pending_.load() &&
        pending_endpoint_request_id_ == ack->request_id) {
        endpoint_ack_pending_ = false;
        log.debug("[{}] Endpoint update acknowledged", name_);
    }
}

asio::awaitable<void> ControlChannelActor::handle_pong(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto pong = Pong::parse(frame.payload);
    if (!pong) {
        log.error("[{}] Failed to parse PONG", name_);
        co_return;
    }

    // 计算延迟
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto latency = now - pong->timestamp;

    log.debug("[{}] Received PONG seq={}, latency={}ms",
              name_, pong->seq_num, latency);
}

asio::awaitable<void> ControlChannelActor::handle_error(const Frame& frame) {
    auto& log = Logger::get("ControlChannelActor");

    auto err = ErrorPayload::parse(frame.payload);
    if (!err) {
        log.error("[{}] Failed to parse FRAME_ERROR", name_);
        co_return;
    }

    log.error("[{}] Received FRAME_ERROR: {} (code {})", name_, err->error_msg, err->error_code);

    // 发送错误事件
    ControlChannelEvent event;
    event.type = CtrlEventType::CTRL_ERROR;
    event.error_code = err->error_code;
    event.reason = err->error_msg;
    send_event(event);
}

} // namespace edgelink::client

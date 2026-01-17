// P2PManagerActor 实现

#include "client/p2p_manager_actor.hpp"
#include "common/logger.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include "common/proto_convert.hpp"
#include "common/performance_monitor.hpp"

#include <chrono>

namespace edgelink::client {

namespace {

auto& log() { return Logger::get("client.p2p"); }

} // anonymous namespace

// ============================================================================
// 构造函数和析构函数
// ============================================================================

P2PManagerActor::P2PManagerActor(
    asio::io_context& ioc,
    CryptoEngine& crypto,
    PeerManager& peers,
    EndpointManager& endpoints,
    asio::experimental::concurrent_channel<void(boost::system::error_code, P2PManagerEvent)>* event_channel)
    : ActorBase(ioc, "P2PManagerActor")
    , crypto_(crypto)
    , peers_(peers)
    , endpoints_(endpoints)
    , event_channel_(event_channel)
    , keepalive_timer_(ioc)
    , endpoint_refresh_timer_(ioc) {

    log().info("[{}] Actor created", name_);
}

P2PManagerActor::~P2PManagerActor() {
    close_udp_socket();
    log().info("[{}] Actor destroyed", name_);
}

// ============================================================================
// 生命周期
// ============================================================================

asio::awaitable<void> P2PManagerActor::on_start() {
    log().info("[{}] Actor started", name_);

    // 注册性能监控（邮箱队列容量为 128）
    perf::PerformanceMonitor::instance().register_queue("P2PManager.Mailbox", 128);

    co_return;
}

asio::awaitable<void> P2PManagerActor::on_stop() {
    log().info("[{}] Actor stopping", name_);

    // 停止所有循环
    recv_loop_running_ = false;
    keepalive_loop_running_ = false;
    endpoint_refresh_loop_running_ = false;

    // 关闭定时器
    keepalive_timer_.cancel();
    endpoint_refresh_timer_.cancel();

    // 关闭 UDP Socket
    close_udp_socket();

    // 清空对端上下文
    peer_contexts_.clear();

    manager_state_ = P2PManagerState::STOPPED;
    log().info("[{}] Actor stopped", name_);
    co_return;
}

// ============================================================================
// 消息处理
// ============================================================================

asio::awaitable<void> P2PManagerActor::handle_message(P2PManagerCommand cmd) {
    if (std::holds_alternative<LifecycleMessage>(cmd)) {
        auto& lifecycle = std::get<LifecycleMessage>(cmd);
        log().debug("[{}] Received lifecycle message: type={}", name_, static_cast<int>(lifecycle.type));

        if (lifecycle.type == LifecycleType::STOP) {
            co_await handle_stop_cmd();
        } else if (lifecycle.type == LifecycleType::START) {
            co_await handle_start_cmd();
        }
        co_return;
    }

    auto& p2p_cmd = std::get<P2PManagerCmd>(cmd);
    log().debug("[{}] Received P2P command: type={}", name_, static_cast<int>(p2p_cmd.type));

    switch (p2p_cmd.type) {
        case P2PCmdType::START:
            co_await handle_start_cmd();
            break;

        case P2PCmdType::STOP:
            co_await handle_stop_cmd();
            break;

        case P2PCmdType::CONNECT_PEER:
            co_await handle_connect_peer_cmd(p2p_cmd);
            break;

        case P2PCmdType::DISCONNECT_PEER:
            co_await handle_disconnect_peer_cmd(p2p_cmd);
            break;

        case P2PCmdType::HANDLE_P2P_ENDPOINT:
            co_await handle_p2p_endpoint_cmd(p2p_cmd);
            break;

        case P2PCmdType::SEND_DATA:
            co_await handle_send_data_cmd(p2p_cmd);
            break;

        default:
            log().warn("[{}] Unhandled command type: {}", name_, static_cast<int>(p2p_cmd.type));
            break;
    }
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> P2PManagerActor::handle_start_cmd() {
    log().info("[{}] Handling START command", name_);

    if (manager_state_ != P2PManagerState::STOPPED) {
        log().warn("[{}] Already running (state={})", name_, p2p_manager_state_name(manager_state_));
        co_return;
    }

    manager_state_ = P2PManagerState::STARTING;

    // 初始化 UDP Socket
    bool success = co_await init_udp_socket();
    if (!success) {
        log().error("[{}] Failed to initialize UDP socket", name_);
        manager_state_ = P2PManagerState::STOPPED;

        // 发送错误事件
        P2PManagerEvent event;
        event.type = P2PEventType::P2P_ERROR;
        event.error_message = "Failed to initialize UDP socket";
        send_event(event);
        co_return;
    }

    manager_state_ = P2PManagerState::RUNNING;

    // 启动循环
    recv_loop_running_ = true;
    keepalive_loop_running_ = true;
    endpoint_refresh_loop_running_ = true;

    asio::co_spawn(ioc_, recv_loop(), asio::detached);
    asio::co_spawn(ioc_, keepalive_loop(), asio::detached);
    asio::co_spawn(ioc_, endpoint_refresh_loop(), asio::detached);

    log().info("[{}] P2P Manager started", name_);

    // 立即刷新端点
    co_await refresh_endpoints();
}

asio::awaitable<void> P2PManagerActor::handle_stop_cmd() {
    log().info("[{}] Handling STOP command", name_);
    co_await on_stop();
}

asio::awaitable<void> P2PManagerActor::handle_connect_peer_cmd(const P2PManagerCmd& cmd) {
    log().info("[{}] Handling CONNECT_PEER command: peer_id={}", name_, cmd.peer_id);

    if (manager_state_ != P2PManagerState::RUNNING) {
        log().warn("[{}] Cannot connect peer: not running", name_);
        co_return;
    }

    // 创建或获取对端上下文
    auto& ctx = peer_contexts_[cmd.peer_id];

    // 请求发送 P2P_INIT
    P2PManagerEvent event;
    event.type = P2PEventType::P2P_INIT_NEEDED;
    event.p2p_init.target_node = cmd.peer_id;
    event.p2p_init.init_seq = ++init_seq_;

    ctx.init_seq = event.p2p_init.init_seq;

    send_event(event);

    log().info("[{}] Requested P2P_INIT for peer {}", name_, cmd.peer_id);
}

asio::awaitable<void> P2PManagerActor::handle_disconnect_peer_cmd(const P2PManagerCmd& cmd) {
    log().info("[{}] Handling DISCONNECT_PEER command: peer_id={}", name_, cmd.peer_id);

    auto it = peer_contexts_.find(cmd.peer_id);
    if (it != peer_contexts_.end()) {
        bool was_connected = it->second.connected;
        peer_contexts_.erase(it);

        if (was_connected) {
            // 发送断开事件
            P2PManagerEvent event;
            event.type = P2PEventType::PEER_DISCONNECTED;
            event.peer_id = cmd.peer_id;
            send_event(event);
        }

        log().info("[{}] Disconnected peer {}", name_, cmd.peer_id);
    }

    co_return;
}

asio::awaitable<void> P2PManagerActor::handle_p2p_endpoint_cmd(const P2PManagerCmd& cmd) {
    log().info("[{}] Handling P2P_ENDPOINT command: peer_id={}",
               name_, cmd.p2p_endpoint.peer_node);

    NodeId peer_id = cmd.p2p_endpoint.peer_node;

    // 获取或创建对端上下文
    auto& ctx = peer_contexts_[peer_id];

    // 保存对端公钥和端点
    std::copy(cmd.p2p_endpoint.peer_key.begin(),
              cmd.p2p_endpoint.peer_key.end(),
              ctx.peer_key.begin());

    ctx.peer_endpoints = cmd.p2p_endpoint.endpoints;

    log().info("[{}] Received {} endpoints for peer {}",
               name_, ctx.peer_endpoints.size(), peer_id);

    // 开始打洞
    co_await start_punching(peer_id);
}

asio::awaitable<void> P2PManagerActor::handle_send_data_cmd(const P2PManagerCmd& cmd) {
    PERF_MEASURE_LATENCY("P2P.SendData");
    PERF_INCREMENT("P2P.PacketsSent");
    PERF_ADD("P2P.BytesSent", cmd.plaintext->size());

    auto it = peer_contexts_.find(cmd.peer_id);
    if (it == peer_contexts_.end() || !it->second.connected) {
        log().debug("[{}] Cannot send data to {}: not connected", name_, cmd.peer_id);
        PERF_INCREMENT("P2P.SendNotConnected");
        co_return;
    }

    auto& ctx = it->second;

    // 加密数据
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    auto encrypted = crypto_.encrypt(cmd.peer_id, *cmd.plaintext, nonce);
    if (!encrypted) {
        log().error("[{}] Failed to encrypt data for peer {}", name_, cmd.peer_id);
        PERF_INCREMENT("P2P.EncryptErrors");
        co_return;
    }

    // 构造 DATA 帧
    pb::DataPayload data_payload;
    data_payload.set_src_node(crypto_.node_id());
    data_payload.set_dst_node(cmd.peer_id);
    data_payload.set_nonce(nonce.data(), nonce.size());
    data_payload.set_encrypted_payload(encrypted->data(), encrypted->size());

    auto frame_result = FrameCodec::encode_protobuf(FrameType::DATA, data_payload);
    if (!frame_result) {
        log().error("[{}] Failed to encode DATA frame", name_);
        co_return;
    }
    auto& frame = *frame_result;

    // 发送
    try {
        co_await udp_socket_->async_send_to(
            asio::buffer(frame),
            ctx.active_endpoint,
            asio::use_awaitable);

        ctx.last_send_time = now_us();

        log().debug("[{}] Sent {} bytes to peer {} via P2P",
                    name_, cmd.plaintext->size(), cmd.peer_id);

    } catch (const std::exception& e) {
        log().error("[{}] Failed to send data to peer {}: {}",
                    name_, cmd.peer_id, e.what());
        PERF_INCREMENT("P2P.SendErrors");
    }
}

// ============================================================================
// UDP Socket 管理
// ============================================================================

asio::awaitable<bool> P2PManagerActor::init_udp_socket() {
    try {
        // 创建 UDP Socket（绑定到任意端口）
        udp_socket_ = std::make_unique<asio::ip::udp::socket>(ioc_);
        udp_socket_->open(asio::ip::udp::v4());
        udp_socket_->bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));

        auto local_ep = udp_socket_->local_endpoint();
        log().info("[{}] UDP socket bound to {}", name_, local_ep.port());

        co_return true;

    } catch (const std::exception& e) {
        log().error("[{}] Failed to create UDP socket: {}", name_, e.what());
        udp_socket_.reset();
        co_return false;
    }
}

void P2PManagerActor::close_udp_socket() {
    if (udp_socket_ && udp_socket_->is_open()) {
        boost::system::error_code ec;
        udp_socket_->close(ec);
        log().info("[{}] UDP socket closed", name_);
    }
    udp_socket_.reset();
}

asio::awaitable<void> P2PManagerActor::recv_loop() {
    log().info("[{}] UDP receive loop started", name_);

    while (recv_loop_running_.load() && udp_socket_ && udp_socket_->is_open()) {
        try {
            // 接收 UDP 数据包
            auto bytes_recvd = co_await udp_socket_->async_receive_from(
                asio::buffer(udp_recv_buffer_),
                udp_recv_endpoint_,
                asio::use_awaitable);

            if (bytes_recvd == 0) {
                continue;
            }

            PERF_INCREMENT("P2P.PacketsReceived");
            PERF_ADD("P2P.BytesReceived", bytes_recvd);

            // 处理数据包
            handle_udp_packet(udp_recv_endpoint_,
                              std::span<const uint8_t>(udp_recv_buffer_.data(), bytes_recvd));

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                log().info("[{}] UDP receive loop cancelled", name_);
                break;
            }

            log().error("[{}] UDP receive error: {}", name_, e.what());
            PERF_INCREMENT("P2P.RecvErrors");
            continue;

        } catch (const std::exception& e) {
            log().error("[{}] Unexpected error in receive loop: {}", name_, e.what());
            PERF_INCREMENT("P2P.RecvErrors");
            break;
        }
    }

    recv_loop_running_ = false;
    log().info("[{}] UDP receive loop stopped", name_);
}

void P2PManagerActor::handle_udp_packet(const asio::ip::udp::endpoint& from,
                                        std::span<const uint8_t> data) {
    // 解析帧
    auto frame_result = FrameCodec::decode(data);
    if (!frame_result) {
        log().debug("[{}] Failed to parse frame from {}", name_, from.address().to_string());
        return;
    }

    auto& [frame, bytes_consumed] = *frame_result;

    // 根据帧类型处理
    switch (frame.header.type) {
        case FrameType::P2P_PING: {
            auto pb_ping = FrameCodec::decode_protobuf<pb::P2PPing>(frame.data());
            if (pb_ping) {
                P2PPing ping;
                from_proto(*pb_ping, &ping);
                handle_p2p_ping(from, ping);
            }
            break;
        }

        case FrameType::P2P_PONG: {
            auto pb_pong = FrameCodec::decode_protobuf<pb::P2PPong>(frame.data());
            if (pb_pong) {
                P2PPing pong;
                from_proto_pong(*pb_pong, &pong);
                handle_p2p_pong(from, pong);
            }
            break;
        }

        case FrameType::P2P_KEEPALIVE: {
            auto pb_keepalive = FrameCodec::decode_protobuf<pb::P2PKeepalive>(frame.data());
            if (pb_keepalive) {
                P2PKeepalive keepalive;
                from_proto(*pb_keepalive, &keepalive);
                // 从 keepalive 中没有 peer_id，使用 frame 前 4 字节
                NodeId peer_id = 0;
                if (frame.payload.size() >= 4) {
                    peer_id = (static_cast<uint32_t>(frame.payload[0]) << 24) |
                              (static_cast<uint32_t>(frame.payload[1]) << 16) |
                              (static_cast<uint32_t>(frame.payload[2]) << 8) |
                              static_cast<uint32_t>(frame.payload[3]);
                }
                handle_p2p_keepalive(from, peer_id, keepalive);
            }
            break;
        }

        case FrameType::DATA: {
            // Use protobuf DataPayload
            auto pb_data = FrameCodec::decode_protobuf<pb::DataPayload>(frame.data());
            if (pb_data) {
                DataPayload data_payload;
                from_proto(*pb_data, &data_payload);
                handle_p2p_data(from, data_payload.src_node, data_payload.encrypted_payload);
            }
            break;
        }

        default:
            log().debug("[{}] Received unknown frame type from {}", name_, from.address().to_string());
            break;
    }
}

// ============================================================================
// P2P 协议处理
// ============================================================================

void P2PManagerActor::handle_p2p_ping(const asio::ip::udp::endpoint& from,
                                      const P2PPing& ping) {
    log().debug("[{}] Received P2P_PING from {}: seq={}",
                name_, from.address().to_string(), ping.seq_num);

    // 发送 PONG 响应
    send_p2p_pong(ping, from);

    // 如果这是一个我们正在尝试连接的对端的 PING，标记为已连接
    for (auto& [peer_id, ctx] : peer_contexts_) {
        if (!ctx.connected) {
            // 检查是否匹配对端端点
            bool matched = false;
            for (const auto& ep : ctx.peer_endpoints) {
                auto udp_ep = to_udp_endpoint(ep);
                if (udp_ep && *udp_ep == from) {
                    matched = true;
                    break;
                }
            }

            if (matched) {
                // 连接成功！
                ctx.connected = true;
                ctx.active_endpoint = from;
                ctx.last_recv_time = now_us();

                log().info("[{}] P2P connection established with peer {} at {}",
                           name_, peer_id, from.address().to_string());
                PERF_INCREMENT("P2P.ConnectionsEstablished");

                // 发送连接成功事件
                P2PManagerEvent event;
                event.type = P2PEventType::PEER_CONNECTED;
                event.peer_id = peer_id;
                event.udp_endpoint = from;
                send_event(event);
                break;
            }
        }
    }
}

void P2PManagerActor::handle_p2p_pong(const asio::ip::udp::endpoint& from,
                                      const P2PPing& pong) {
    log().debug("[{}] Received P2P_PONG from {}: seq={}",
                name_, from.address().to_string(), pong.seq_num);

    // 查找匹配的对端
    for (auto& [peer_id, ctx] : peer_contexts_) {
        if (ctx.ping_seq == pong.seq_num) {
            if (!ctx.connected) {
                // 连接成功！
                ctx.connected = true;
                ctx.active_endpoint = from;
                ctx.last_recv_time = now_us();

                log().info("[{}] P2P connection established with peer {} at {}",
                           name_, peer_id, from.address().to_string());

                // 发送连接成功事件
                P2PManagerEvent event;
                event.type = P2PEventType::PEER_CONNECTED;
                event.peer_id = peer_id;
                event.udp_endpoint = from;
                send_event(event);
            } else {
                // 更新接收时间
                ctx.last_recv_time = now_us();
            }
            break;
        }
    }
}

void P2PManagerActor::handle_p2p_keepalive(const asio::ip::udp::endpoint& from,
                                           NodeId peer_id,
                                           const P2PKeepalive& keepalive) {
    log().debug("[{}] Received P2P_KEEPALIVE from peer {}", name_, peer_id);

    auto it = peer_contexts_.find(peer_id);
    if (it != peer_contexts_.end()) {
        it->second.last_recv_time = now_us();

        // 如果端点变了，更新
        if (it->second.active_endpoint != from) {
            log().info("[{}] Peer {} endpoint changed: {} -> {}",
                       name_, peer_id,
                       it->second.active_endpoint.address().to_string(),
                       from.address().to_string());
            it->second.active_endpoint = from;
        }
    }
}

void P2PManagerActor::handle_p2p_data(const asio::ip::udp::endpoint& from,
                                      NodeId peer_id,
                                      std::span<const uint8_t> encrypted_data) {
    log().debug("[{}] Received P2P data from peer {}: {} bytes",
                name_, peer_id, encrypted_data.size());

    auto it = peer_contexts_.find(peer_id);
    if (it != peer_contexts_.end()) {
        it->second.last_recv_time = now_us();
    }

    // encrypted_data 是已解析的 DataPayload 的 encrypted_payload
    // 这里假设调用方在调用时已经从 Frame 中提取了 DataPayload
    // 实际上 handle_udp_packet 已经解析了 DataPayload
    // 这里需要从 DataPayload 中提取 nonce 和密文

    // 注意：这里的实现有问题，因为我们需要完整的 DataPayload
    // 暂时跳过实际解密，留给后续完善
    log().warn("[{}] P2P data decryption not fully implemented yet", name_);
}

// ============================================================================
// P2P 连接管理
// ============================================================================

asio::awaitable<void> P2PManagerActor::start_punching(NodeId peer_id) {
    log().info("[{}] Starting NAT punching for peer {}", name_, peer_id);

    auto it = peer_contexts_.find(peer_id);
    if (it == peer_contexts_.end()) {
        log().error("[{}] Peer context not found for {}", name_, peer_id);
        co_return;
    }

    auto& ctx = it->second;
    ctx.last_punch_time = now_us();
    ctx.punch_count = 0;

    // 执行分批打洞
    co_await do_punch_batches(peer_id);
}

asio::awaitable<void> P2PManagerActor::do_punch_batches(NodeId peer_id) {
    auto it = peer_contexts_.find(peer_id);
    if (it == peer_contexts_.end()) {
        co_return;
    }

    auto& ctx = it->second;

    // 分批次向所有对端端点发送 PING
    constexpr int MAX_BATCHES = 3;
    constexpr int BATCH_DELAY_MS = 200;

    for (int batch = 0; batch < MAX_BATCHES && !ctx.connected; ++batch) {
        for (const auto& ep : ctx.peer_endpoints) {
            auto udp_ep = to_udp_endpoint(ep);
            if (!udp_ep) {
                continue;
            }

            // 发送 PING
            co_await send_p2p_ping(peer_id, *udp_ep);
            ctx.punch_count++;
        }

        if (batch < MAX_BATCHES - 1) {
            // 等待一段时间再发送下一批
            asio::steady_timer timer(ioc_);
            timer.expires_after(std::chrono::milliseconds(BATCH_DELAY_MS));
            co_await timer.async_wait(asio::use_awaitable);
        }
    }

    log().info("[{}] Completed {} punch attempts for peer {}",
               name_, ctx.punch_count, peer_id);
}

asio::awaitable<void> P2PManagerActor::send_p2p_ping(NodeId peer_id,
                                                     const asio::ip::udp::endpoint& to) {
    auto it = peer_contexts_.find(peer_id);
    if (it == peer_contexts_.end()) {
        co_return;
    }

    auto& ctx = it->second;

    // 构造 PING
    P2PPing ping;
    ping.seq_num = ++ctx.ping_seq;
    ping.timestamp = now_us();

    pb::P2PPing pb_ping;
    to_proto(ping, &pb_ping);
    auto frame_result = FrameCodec::encode_protobuf(FrameType::P2P_PING, pb_ping);
    if (!frame_result) {
        co_return;
    }
    auto& frame = *frame_result;

    // 发送
    try {
        co_await udp_socket_->async_send_to(
            asio::buffer(frame),
            to,
            asio::use_awaitable);

        ctx.last_send_time = now_us();

        log().debug("[{}] Sent P2P_PING to {}: seq={}",
                    name_, to.address().to_string(), ping.seq_num);

    } catch (const std::exception& e) {
        log().error("[{}] Failed to send P2P_PING: {}", name_, e.what());
    }
}

void P2PManagerActor::send_p2p_pong(const P2PPing& ping, const asio::ip::udp::endpoint& to) {
    // 构造 PONG（使用相同的序列号）- protobuf
    P2PPing pong;
    pong.seq_num = ping.seq_num;
    pong.timestamp = now_us();

    pb::P2PPong pb_pong;
    to_proto_pong(pong, &pb_pong);
    auto frame_result = FrameCodec::encode_protobuf(FrameType::P2P_PONG, pb_pong);
    if (!frame_result) {
        return;
    }
    auto& frame = *frame_result;

    // 异步发送（不等待）
    udp_socket_->async_send_to(
        asio::buffer(frame),
        to,
        [this, to](const boost::system::error_code& ec, std::size_t /*bytes_sent*/) {
            if (ec) {
                log().error("[{}] Failed to send P2P_PONG to {}: {}",
                            name_, to.address().to_string(), ec.message());
            }
        });

    log().debug("[{}] Sent P2P_PONG to {}: seq={}",
                name_, to.address().to_string(), pong.seq_num);
}

// ============================================================================
// Keepalive 机制
// ============================================================================

asio::awaitable<void> P2PManagerActor::keepalive_loop() {
    log().info("[{}] Keepalive loop started", name_);

    constexpr auto KEEPALIVE_INTERVAL = std::chrono::seconds(30);

    while (keepalive_loop_running_.load()) {
        try {
            // 等待间隔
            keepalive_timer_.expires_after(KEEPALIVE_INTERVAL);
            co_await keepalive_timer_.async_wait(asio::use_awaitable);

            // 向所有已连接的对端发送 keepalive
            for (const auto& [peer_id, ctx] : peer_contexts_) {
                if (ctx.connected) {
                    co_await send_p2p_keepalive(peer_id);
                }
            }

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                log().info("[{}] Keepalive loop cancelled", name_);
                break;
            }
            log().error("[{}] Keepalive loop error: {}", name_, e.what());
        }
    }

    keepalive_loop_running_ = false;
    log().info("[{}] Keepalive loop stopped", name_);
}

asio::awaitable<void> P2PManagerActor::send_p2p_keepalive(NodeId peer_id) {
    auto it = peer_contexts_.find(peer_id);
    if (it == peer_contexts_.end() || !it->second.connected) {
        co_return;
    }

    auto& ctx = it->second;

    // 构造 KEEPALIVE 帧（简化：只包含 NodeId）
    std::vector<uint8_t> payload(4);
    payload[0] = (crypto_.node_id() >> 24) & 0xFF;
    payload[1] = (crypto_.node_id() >> 16) & 0xFF;
    payload[2] = (crypto_.node_id() >> 8) & 0xFF;
    payload[3] = crypto_.node_id() & 0xFF;

    auto frame = FrameCodec::encode(FrameType::P2P_KEEPALIVE, payload);

    // 发送
    try {
        co_await udp_socket_->async_send_to(
            asio::buffer(frame),
            ctx.active_endpoint,
            asio::use_awaitable);

        ctx.last_send_time = now_us();

        log().debug("[{}] Sent P2P_KEEPALIVE to peer {}", name_, peer_id);

    } catch (const std::exception& e) {
        log().error("[{}] Failed to send P2P_KEEPALIVE to peer {}: {}",
                    name_, peer_id, e.what());
    }
}

// ============================================================================
// 端点管理
// ============================================================================

asio::awaitable<void> P2PManagerActor::endpoint_refresh_loop() {
    log().info("[{}] Endpoint refresh loop started", name_);

    constexpr auto REFRESH_INTERVAL = std::chrono::minutes(5);

    while (endpoint_refresh_loop_running_.load()) {
        try {
            // 等待间隔
            endpoint_refresh_timer_.expires_after(REFRESH_INTERVAL);
            co_await endpoint_refresh_timer_.async_wait(asio::use_awaitable);

            // 刷新端点
            co_await refresh_endpoints();

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                log().info("[{}] Endpoint refresh loop cancelled", name_);
                break;
            }
            log().error("[{}] Endpoint refresh loop error: {}", name_, e.what());
        }
    }

    endpoint_refresh_loop_running_ = false;
    log().info("[{}] Endpoint refresh loop stopped", name_);
}

asio::awaitable<void> P2PManagerActor::refresh_endpoints() {
    log().info("[{}] Refreshing local endpoints", name_);

    // 从 EndpointManager 获取端点
    auto endpoints = endpoints_.get_local_endpoints();

    if (endpoints.empty()) {
        log().warn("[{}] No endpoints discovered", name_);
        co_return;
    }

    // 更新缓存
    local_endpoints_ = endpoints;

    log().info("[{}] Discovered {} local endpoints", name_, endpoints.size());

    // 发送端点就绪事件
    P2PManagerEvent event;
    event.type = P2PEventType::ENDPOINTS_READY;
    event.endpoints = std::move(endpoints);
    send_event(event);

    co_return;
}

// ============================================================================
// 事件发送
// ============================================================================

void P2PManagerActor::send_event(P2PManagerEvent event) {
    if (event_channel_) {
        event_channel_->try_send(boost::system::error_code{}, event);
    }
}

// ============================================================================
// 工具函数
// ============================================================================

void P2PManagerActor::set_config(const P2PConfig& config) {
    config_ = config;
    log().info("[{}] Configuration updated", name_);
}

uint64_t P2PManagerActor::now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::optional<asio::ip::udp::endpoint> P2PManagerActor::to_udp_endpoint(const Endpoint& ep) {
    try {
        if (ep.ip_type == IpType::IPv4) {
            // 使用前 4 字节构造 IPv4 地址
            asio::ip::address_v4::bytes_type bytes;
            std::copy_n(ep.address.begin(), 4, bytes.begin());
            auto addr = asio::ip::make_address_v4(bytes);
            return asio::ip::udp::endpoint(addr, ep.port);
        } else if (ep.ip_type == IpType::IPv6) {
            // 使用全部 16 字节构造 IPv6 地址
            asio::ip::address_v6::bytes_type bytes;
            std::copy(ep.address.begin(), ep.address.end(), bytes.begin());
            auto addr = asio::ip::make_address_v6(bytes);
            return asio::ip::udp::endpoint(addr, ep.port);
        }
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace edgelink::client

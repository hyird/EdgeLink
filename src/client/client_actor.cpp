// ClientActor 实现

#include "client/client_actor.hpp"
#include "common/logger.hpp"

namespace edgelink::client {

namespace {

auto& log() { return Logger::get("client.actor"); }

} // anonymous namespace

// ============================================================================
// 构造函数和析构函数
// ============================================================================

ClientActor::ClientActor(
    asio::io_context& ioc,
    ssl::context& ssl_ctx,
    CryptoEngine& crypto,
    PeerManager& peers,
    EndpointManager& endpoints)
    : ActorBase(ioc, "ClientActor")
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , peers_(peers)
    , endpoints_(endpoints) {

    log().info("[{}] Actor created", name_);
}

ClientActor::~ClientActor() {
    destroy_actors();
    log().info("[{}] Actor destroyed", name_);
}

// ============================================================================
// 生命周期
// ============================================================================

asio::awaitable<void> ClientActor::on_start() {
    log().info("[{}] Actor started", name_);

    // 创建子 Actor 和事件通道
    create_actors();

    co_return;
}

asio::awaitable<void> ClientActor::on_stop() {
    log().info("[{}] Actor stopping", name_);

    // 停止所有事件循环
    control_loop_running_ = false;
    relay_loop_running_ = false;
    data_plane_loop_running_ = false;
    p2p_loop_running_ = false;
    tun_loop_running_ = false;

    // 停止所有子 Actor
    if (control_actor_) {
        co_await control_actor_->stop();
    }
    if (relay_actor_) {
        co_await relay_actor_->stop();
    }
    if (data_plane_actor_) {
        co_await data_plane_actor_->stop();
    }
    if (p2p_actor_) {
        co_await p2p_actor_->stop();
    }
    if (tun_actor_) {
        co_await tun_actor_->stop();
    }

    state_ = ClientActorState::STOPPED;
    log().info("[{}] Actor stopped", name_);
    co_return;
}

// ============================================================================
// 消息处理
// ============================================================================

asio::awaitable<void> ClientActor::handle_message(ClientActorCommand cmd) {
    if (std::holds_alternative<LifecycleMessage>(cmd)) {
        auto& lifecycle = std::get<LifecycleMessage>(cmd);
        log().debug("[{}] Received lifecycle message: type={}", name_, static_cast<int>(lifecycle.type));

        if (lifecycle.type == LifecycleType::STOP) {
            co_await handle_stop_cmd();
        } else if (lifecycle.type == LifecycleType::START) {
            co_await handle_start_cmd();
        } else if (lifecycle.type == LifecycleType::RECONNECT) {
            co_await handle_reconnect_cmd();
        }
        co_return;
    }

    auto& internal_cmd = std::get<ClientInternalCmd>(cmd);
    log().debug("[{}] Received internal command: type={}", name_, static_cast<int>(internal_cmd.type));

    switch (internal_cmd.type) {
        case ClientInternalCmdType::START:
            co_await handle_start_cmd();
            break;

        case ClientInternalCmdType::STOP:
            co_await handle_stop_cmd();
            break;

        case ClientInternalCmdType::RECONNECT:
            co_await handle_reconnect_cmd();
            break;

        default:
            log().warn("[{}] Unhandled command type: {}", name_, static_cast<int>(internal_cmd.type));
            break;
    }
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> ClientActor::handle_start_cmd() {
    log().info("[{}] Handling START command", name_);
    // 实际启动逻辑在 start_client() 中
    co_return;
}

asio::awaitable<void> ClientActor::handle_stop_cmd() {
    log().info("[{}] Handling STOP command", name_);
    co_await stop_client();
}

asio::awaitable<void> ClientActor::handle_reconnect_cmd() {
    log().info("[{}] Handling RECONNECT command", name_);

    // 关闭现有连接
    if (control_actor_) {
        using edgelink::messages::ControlChannelCmd;
        using edgelink::messages::CtrlCmdType;

        ControlChannelCmd close_cmd;
        close_cmd.type = CtrlCmdType::CLOSE;
        co_await control_actor_->send_message(close_cmd);
    }

    if (relay_actor_) {
        using edgelink::messages::RelayChannelCmd;
        using edgelink::messages::RelayCmdType;

        RelayChannelCmd close_cmd;
        close_cmd.type = RelayCmdType::CLOSE;
        co_await relay_actor_->send_message(close_cmd);
    }

    // 重新连接
    co_await start_client(controller_url_, authkey_, use_tls_);
}

// ============================================================================
// 公共接口
// ============================================================================

asio::awaitable<bool> ClientActor::start_client(const std::string& controller_url,
                                                const std::string& authkey,
                                                bool use_tls) {
    log().info("[{}] Starting client: url={}, tls={}", name_, controller_url, use_tls);

    // 保存连接参数（用于重连）
    controller_url_ = controller_url;
    authkey_ = authkey;
    use_tls_ = use_tls;

    state_ = ClientActorState::STARTING;

    // 启动 DataPlane Actor
    if (data_plane_actor_) {
        using edgelink::messages::DataPlaneCmd;
        using edgelink::messages::DataPlaneCmdType;

        DataPlaneCmd start_cmd;
        start_cmd.type = DataPlaneCmdType::START;
        co_await data_plane_actor_->send_message(start_cmd);
    }

    // 连接 Control Channel
    state_ = ClientActorState::AUTHENTICATING;

    if (control_actor_) {
        using edgelink::messages::ControlChannelCmd;
        using edgelink::messages::CtrlCmdType;

        ControlChannelCmd connect_cmd;
        connect_cmd.type = CtrlCmdType::CONNECT;
        connect_cmd.url = controller_url;
        connect_cmd.authkey = authkey;
        connect_cmd.use_tls = use_tls;

        co_await control_actor_->send_message(connect_cmd);
    }

    // 注意：实际的状态转换将在事件循环中处理（收到 CONNECTED 事件后）
    co_return true;
}

asio::awaitable<void> ClientActor::stop_client() {
    log().info("[{}] Stopping client", name_);
    co_await on_stop();
}

asio::awaitable<bool> ClientActor::send_to_peer(NodeId peer_id, std::shared_ptr<std::vector<uint8_t>> data) {
    if (state_ != ClientActorState::RUNNING) {
        log().warn("[{}] Cannot send data: not running (state={})",
                   name_, client_actor_state_name(state_));
        co_return false;
    }

    if (!data_plane_actor_) {
        log().error("[{}] DataPlane actor not available", name_);
        co_return false;
    }

    using edgelink::messages::DataPlaneCmd;
    using edgelink::messages::DataPlaneCmdType;

    DataPlaneCmd send_cmd;
    send_cmd.type = DataPlaneCmdType::SEND_TO;
    send_cmd.peer_id = peer_id;
    send_cmd.data = data;

    co_await data_plane_actor_->send_message(send_cmd);
    co_return true;
}

asio::awaitable<void> ClientActor::update_routes(const std::unordered_map<NodeId, PeerDataPath>& route_table) {
    if (!data_plane_actor_) {
        log().warn("[{}] Cannot update routes: DataPlane actor not available", name_);
        co_return;
    }

    using edgelink::messages::DataPlaneCmd;
    using edgelink::messages::DataPlaneCmdType;

    DataPlaneCmd update_cmd;
    update_cmd.type = DataPlaneCmdType::UPDATE_ROUTE;
    update_cmd.route_table = route_table;

    co_await data_plane_actor_->send_message(update_cmd);
}

asio::awaitable<bool> ClientActor::open_tun(const std::string& dev_name,
                                            const IPv4Address& ip,
                                            uint32_t mtu) {
    if (!tun_actor_) {
        log().error("[{}] TUN actor not available", name_);
        co_return false;
    }

    log().info("[{}] Opening TUN device: name={}, ip={}, mtu={}",
               name_, dev_name, ip.to_string(), mtu);

    using edgelink::messages::TunMessage;
    using edgelink::messages::TunMessageType;

    TunMessage open_cmd;
    open_cmd.type = TunMessageType::OPEN;
    open_cmd.dev_name = dev_name;
    open_cmd.ip = ip;
    open_cmd.mtu = mtu;

    co_await tun_actor_->send_message(open_cmd);
    co_return true;
}

asio::awaitable<void> ClientActor::close_tun() {
    if (!tun_actor_) {
        log().warn("[{}] TUN actor not available", name_);
        co_return;
    }

    log().info("[{}] Closing TUN device", name_);

    using edgelink::messages::TunMessage;
    using edgelink::messages::TunMessageType;

    TunMessage close_cmd;
    close_cmd.type = TunMessageType::CLOSE;

    co_await tun_actor_->send_message(close_cmd);
}

asio::awaitable<bool> ClientActor::write_tun_packet(std::shared_ptr<std::vector<uint8_t>> packet) {
    if (!tun_actor_) {
        log().error("[{}] TUN actor not available", name_);
        co_return false;
    }

    using edgelink::messages::TunMessage;
    using edgelink::messages::TunMessageType;

    TunMessage write_cmd;
    write_cmd.type = TunMessageType::WRITE_PACKET;
    write_cmd.packet = packet;

    co_await tun_actor_->send_message(write_cmd);
    co_return true;
}

// ============================================================================
// 认证信息访问
// ============================================================================

NodeId ClientActor::node_id() const {
    return crypto_.node_id();
}

IPv4Address ClientActor::virtual_ip() const {
    if (control_actor_) {
        return control_actor_->virtual_ip();
    }
    return IPv4Address{};
}

NetworkId ClientActor::network_id() const {
    if (control_actor_) {
        return control_actor_->network_id();
    }
    return 0;
}

const std::vector<uint8_t>& ClientActor::relay_token() const {
    static std::vector<uint8_t> empty;
    if (control_actor_) {
        return control_actor_->relay_token();
    }
    return empty;
}

// ============================================================================
// 子 Actor 管理
// ============================================================================

void ClientActor::create_actors() {
    log().info("[{}] Creating sub-actors and event channels", name_);

    // 创建事件通道（使用 concurrent_channel 确保跨 strand 线程安全）
    // 容量根据性能配置优化：数据面通道使用更大容量
    control_event_ch_ = std::make_unique<asio::experimental::concurrent_channel<void(boost::system::error_code, ControlChannelEvent)>>(ioc_, 128);
    relay_event_ch_ = std::make_unique<asio::experimental::concurrent_channel<void(boost::system::error_code, RelayChannelEvent)>>(ioc_, 128);
    data_plane_event_ch_ = std::make_unique<asio::experimental::concurrent_channel<void(boost::system::error_code, DataPlaneEvent)>>(ioc_, 256);  // 高优先级
    p2p_event_ch_ = std::make_unique<asio::experimental::concurrent_channel<void(boost::system::error_code, P2PManagerEvent)>>(ioc_, 128);
    tun_event_ch_ = std::make_unique<asio::experimental::concurrent_channel<void(boost::system::error_code, TunEvent)>>(ioc_, 256);  // 高吞吐

    // 创建子 Actor
    control_actor_ = std::make_shared<ControlChannelActor>(ioc_, ssl_ctx_, crypto_, control_event_ch_.get());
    relay_actor_ = std::make_shared<RelayChannelActor>(ioc_, ssl_ctx_, crypto_, peers_, relay_event_ch_.get());
    data_plane_actor_ = std::make_shared<DataPlaneActor>(ioc_, crypto_, peers_, data_plane_event_ch_.get());
    p2p_actor_ = std::make_shared<P2PManagerActor>(ioc_, crypto_, peers_, endpoints_, p2p_event_ch_.get());
    tun_actor_ = std::make_shared<TunDeviceActor>(ioc_, tun_event_ch_.get());

    // 设置 DataPlane 的子 Actor 引用
    data_plane_actor_->set_relay_channel(relay_actor_.get());
    data_plane_actor_->set_p2p_manager(p2p_actor_.get());

    // 启动所有子 Actor - 使用 shared_from_this 保证生命周期安全（多线程环境）
    // 注意：需要将 ActorBase<ClientActor, ...> 转换为 ClientActor*
    auto base_self = shared_from_this();

    asio::co_spawn(ioc_, [base_self, this]() -> asio::awaitable<void> {
        co_await control_actor_->start();
    }, asio::detached);

    asio::co_spawn(ioc_, [base_self, this]() -> asio::awaitable<void> {
        co_await relay_actor_->start();
    }, asio::detached);

    asio::co_spawn(ioc_, [base_self, this]() -> asio::awaitable<void> {
        co_await data_plane_actor_->start();
    }, asio::detached);

    asio::co_spawn(ioc_, [base_self, this]() -> asio::awaitable<void> {
        co_await p2p_actor_->start();
    }, asio::detached);

    asio::co_spawn(ioc_, [base_self, this]() -> asio::awaitable<void> {
        co_await tun_actor_->start();
    }, asio::detached);

    // 启动事件循环
    control_loop_running_ = true;
    relay_loop_running_ = true;
    data_plane_loop_running_ = true;
    p2p_loop_running_ = true;
    tun_loop_running_ = true;

    asio::co_spawn(ioc_, control_event_loop(), asio::detached);
    asio::co_spawn(ioc_, relay_event_loop(), asio::detached);
    asio::co_spawn(ioc_, data_plane_event_loop(), asio::detached);
    asio::co_spawn(ioc_, p2p_event_loop(), asio::detached);
    asio::co_spawn(ioc_, tun_event_loop(), asio::detached);

    log().info("[{}] Sub-actors and event loops started", name_);
}

void ClientActor::destroy_actors() {
    log().info("[{}] Destroying sub-actors", name_);

    // 停止事件循环
    control_loop_running_ = false;
    relay_loop_running_ = false;
    data_plane_loop_running_ = false;
    p2p_loop_running_ = false;
    tun_loop_running_ = false;

    // 关闭事件通道
    if (control_event_ch_) {
        control_event_ch_->close();
    }
    if (relay_event_ch_) {
        relay_event_ch_->close();
    }
    if (data_plane_event_ch_) {
        data_plane_event_ch_->close();
    }
    if (p2p_event_ch_) {
        p2p_event_ch_->close();
    }
    if (tun_event_ch_) {
        tun_event_ch_->close();
    }

    // 销毁子 Actor
    control_actor_.reset();
    relay_actor_.reset();
    data_plane_actor_.reset();
    p2p_actor_.reset();
    tun_actor_.reset();

    log().info("[{}] Sub-actors destroyed", name_);
}

// ============================================================================
// 事件循环
// ============================================================================

asio::awaitable<void> ClientActor::control_event_loop() {
    log().debug("[{}] Control event loop started", name_);

    try {
        while (control_loop_running_.load() && control_event_ch_) {
            // 接收事件（错误会被转换为异常）
            auto event = co_await control_event_ch_->async_receive(asio::use_awaitable);

            // 处理事件
            co_await handle_control_event(event);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::experimental::error::channel_closed) {
            log().debug("[{}] Control event channel closed", name_);
        } else {
            log().error("[{}] Control event loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log().error("[{}] Control event loop exception: {}", name_, e.what());
    }

    log().debug("[{}] Control event loop exited", name_);
}

asio::awaitable<void> ClientActor::relay_event_loop() {
    log().debug("[{}] Relay event loop started", name_);

    try {
        while (relay_loop_running_.load() && relay_event_ch_) {
            // 接收事件（错误会被转换为异常）
            auto event = co_await relay_event_ch_->async_receive(asio::use_awaitable);

            // 处理事件
            co_await handle_relay_event(event);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::experimental::error::channel_closed) {
            log().debug("[{}] Relay event channel closed", name_);
        } else {
            log().error("[{}] Relay event loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log().error("[{}] Relay event loop exception: {}", name_, e.what());
    }

    log().debug("[{}] Relay event loop exited", name_);
}

asio::awaitable<void> ClientActor::data_plane_event_loop() {
    log().debug("[{}] DataPlane event loop started", name_);

    try {
        while (data_plane_loop_running_.load() && data_plane_event_ch_) {
            // 接收事件（错误会被转换为异常）
            auto event = co_await data_plane_event_ch_->async_receive(asio::use_awaitable);

            // 处理事件
            co_await handle_data_plane_event(event);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::experimental::error::channel_closed) {
            log().debug("[{}] DataPlane event channel closed", name_);
        } else {
            log().error("[{}] DataPlane event loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log().error("[{}] DataPlane event loop exception: {}", name_, e.what());
    }

    log().debug("[{}] DataPlane event loop exited", name_);
}

asio::awaitable<void> ClientActor::p2p_event_loop() {
    log().debug("[{}] P2P event loop started", name_);

    try {
        while (p2p_loop_running_.load() && p2p_event_ch_) {
            // 接收事件（错误会被转换为异常）
            auto event = co_await p2p_event_ch_->async_receive(asio::use_awaitable);

            // 处理事件
            co_await handle_p2p_event(event);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::experimental::error::channel_closed) {
            log().debug("[{}] P2P event channel closed", name_);
        } else {
            log().error("[{}] P2P event loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log().error("[{}] P2P event loop exception: {}", name_, e.what());
    }

    log().debug("[{}] P2P event loop exited", name_);
}

asio::awaitable<void> ClientActor::tun_event_loop() {
    log().debug("[{}] TUN event loop started", name_);

    try {
        while (tun_loop_running_.load() && tun_event_ch_) {
            // 接收事件（错误会被转换为异常）
            auto event = co_await tun_event_ch_->async_receive(asio::use_awaitable);

            // 处理事件
            co_await handle_tun_event(event);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::experimental::error::channel_closed) {
            log().debug("[{}] TUN event channel closed", name_);
        } else {
            log().error("[{}] TUN event loop error: {}", name_, e.what());
        }
    } catch (const std::exception& e) {
        log().error("[{}] TUN event loop exception: {}", name_, e.what());
    }

    log().debug("[{}] TUN event loop exited", name_);
}

// ============================================================================
// 事件处理
// ============================================================================

asio::awaitable<void> ClientActor::handle_control_event(const ControlChannelEvent& event) {
    using edgelink::messages::CtrlEventType;

    log().debug("[{}] Handling control event: type={}", name_, static_cast<int>(event.type));

    switch (event.type) {
        case CtrlEventType::CONNECTED:
            log().info("[{}] Control channel connected: node_id={}, virtual_ip={}",
                       name_, event.node_id, event.virtual_ip.to_string());

            // 更新状态
            state_ = ClientActorState::CONNECTING_RELAY;

            // 连接 Relay Channel
            if (relay_actor_) {
                using edgelink::messages::RelayChannelCmd;
                using edgelink::messages::RelayCmdType;

                RelayChannelCmd connect_cmd;
                connect_cmd.type = RelayCmdType::CONNECT;
                connect_cmd.url = controller_url_;  // 使用相同的 URL（路径会自动改为 /api/v1/relay）
                connect_cmd.relay_token = event.relay_token;
                connect_cmd.use_tls = use_tls_;

                co_await relay_actor_->send_message(connect_cmd);
            }
            break;

        case CtrlEventType::DISCONNECTED:
            log().warn("[{}] Control channel disconnected: {}", name_, event.reason);

            // 触发重连流程
            if (state_ == ClientActorState::RUNNING) {
                state_ = ClientActorState::RECONNECTING;
                log().info("[{}] Initiating reconnection...", name_);
                // Note: 实际重连由主 Client 类的 reconnect() 方法处理
            }
            break;

        case CtrlEventType::CONFIG_RECEIVED:
            log().info("[{}] Config received: version={}, peers={}",
                       name_, event.config.version, event.config.peers.size());

            // 路由表更新由 Client 类的 ctrl_config_handler() 处理
            // Peer 信息已通过 peers_ 引用自动更新
            break;

        case CtrlEventType::ROUTE_UPDATE:
            log().info("[{}] Route update received: version={}", name_, event.route_update.version);
            // 路由更新由 Client 类的 ctrl_route_update_handler() 处理
            break;

        case CtrlEventType::P2P_ENDPOINT:
            log().debug("[{}] P2P endpoint received for peer {}", name_, event.p2p_endpoint.peer_node);
            // 转发给 P2P Manager
            if (p2p_actor_) {
                using edgelink::messages::P2PManagerCmd;
                using edgelink::messages::P2PCmdType;

                P2PManagerCmd p2p_cmd;
                p2p_cmd.type = P2PCmdType::HANDLE_P2P_ENDPOINT;
                p2p_cmd.p2p_endpoint = event.p2p_endpoint;
                co_await p2p_actor_->send_message(p2p_cmd);
            }
            break;

        case CtrlEventType::CTRL_ERROR:
            log().error("[{}] Control channel error: code={}, msg={}",
                        name_, event.error_code, event.reason);
            break;

        default:
            log().warn("[{}] Unhandled control event type: {}", name_, static_cast<int>(event.type));
            break;
    }

    co_return;
}

asio::awaitable<void> ClientActor::handle_relay_event(const RelayChannelEvent& event) {
    using edgelink::messages::RelayEventType;

    log().debug("[{}] Handling relay event: type={}", name_, static_cast<int>(event.type));

    switch (event.type) {
        case RelayEventType::CONNECTED:
            log().info("[{}] Relay channel connected", name_);

            // 更新状态为 RUNNING
            state_ = ClientActorState::RUNNING;
            break;

        case RelayEventType::DISCONNECTED:
            log().warn("[{}] Relay channel disconnected: {}", name_, event.reason);

            // 触发重连流程
            if (state_ == ClientActorState::RUNNING) {
                state_ = ClientActorState::RECONNECTING;
                log().info("[{}] Initiating reconnection...", name_);
                // Note: 实际重连由主 Client 类的 reconnect() 方法处理
            }
            break;

        case RelayEventType::DATA_RECEIVED:
            log().debug("[{}] Data received from node {}: {} bytes",
                        name_, event.src_node, event.plaintext->size());

            // 转发到 TUN 设备
            if (tun_actor_) {
                co_await write_tun_packet(event.plaintext);
            } else {
                log().warn("[{}] Cannot forward data: TUN actor not available", name_);
            }
            break;

        case RelayEventType::RELAY_ERROR:
            log().error("[{}] Relay channel error: {}", name_, event.reason);
            break;

        default:
            log().warn("[{}] Unhandled relay event type: {}", name_, static_cast<int>(event.type));
            break;
    }

    co_return;
}

asio::awaitable<void> ClientActor::handle_data_plane_event(const DataPlaneEvent& event) {
    using edgelink::messages::DataPlaneEventType;

    log().debug("[{}] Handling data plane event: type={}", name_, static_cast<int>(event.type));

    switch (event.type) {
        case DataPlaneEventType::STARTED:
            log().info("[{}] DataPlane started", name_);
            break;

        case DataPlaneEventType::STOPPED:
            log().info("[{}] DataPlane stopped", name_);
            break;

        case DataPlaneEventType::DATA_RECEIVED:
            log().debug("[{}] DataPlane received data from {}: {} bytes",
                        name_, event.src_node, event.data->size());
            // 转发给 TUN 设备
            if (tun_actor_) {
                co_await write_tun_packet(event.data);
            }
            break;

        case DataPlaneEventType::DATA_ERROR:
            log().error("[{}] DataPlane error: {}", name_, event.error_message);
            break;

        default:
            log().warn("[{}] Unhandled data plane event type: {}", name_, static_cast<int>(event.type));
            break;
    }

    co_return;
}

asio::awaitable<void> ClientActor::handle_p2p_event(const P2PManagerEvent& event) {
    using edgelink::messages::P2PEventType;

    log().debug("[{}] Handling P2P event: type={}", name_, static_cast<int>(event.type));

    switch (event.type) {
        case P2PEventType::ENDPOINTS_READY:
            log().info("[{}] Local P2P endpoints ready: {} endpoints",
                       name_, event.endpoints.size());

            // 转发端点信息到 ControlChannel（通过控制消息报告给 Controller）
            if (control_actor_ && !event.endpoints.empty()) {
                using edgelink::messages::ControlChannelCmd;
                using edgelink::messages::CtrlCmdType;

                ControlChannelCmd cmd;
                cmd.type = CtrlCmdType::SEND_ENDPOINT_UPDATE;
                cmd.endpoints = event.endpoints;
                // request_id 默认为 0
                co_await control_actor_->send_message(cmd);
            }
            break;

        case P2PEventType::P2P_INIT_NEEDED:
            log().info("[{}] P2P init needed for peer: target={}, seq={}",
                       name_, event.p2p_init.target_node, event.p2p_init.init_seq);

            // 转发 P2P_INIT 请求到 ControlChannel（通过控制通道发送给 Controller）
            if (control_actor_) {
                using edgelink::messages::ControlChannelCmd;
                using edgelink::messages::CtrlCmdType;

                ControlChannelCmd cmd;
                cmd.type = CtrlCmdType::SEND_P2P_INIT;
                cmd.p2p_init = event.p2p_init;
                co_await control_actor_->send_message(cmd);
            }
            break;

        case P2PEventType::PEER_CONNECTED: {
            log().info("[{}] P2P peer connected: peer={}", name_, event.peer_id);

            // 更新 DataPlane 路由：将该对端切换到 P2P 路径
            std::unordered_map<NodeId, PeerDataPath> route_update;
            route_update[event.peer_id] = PeerDataPath::P2P;
            co_await update_routes(route_update);
            break;
        }

        case P2PEventType::PEER_DISCONNECTED: {
            log().warn("[{}] P2P peer disconnected: peer={}", name_, event.peer_id);

            // 更新 DataPlane 路由：将该对端切换回 Relay 路径
            std::unordered_map<NodeId, PeerDataPath> route_update;
            route_update[event.peer_id] = PeerDataPath::RELAY;
            co_await update_routes(route_update);
            break;
        }

        case P2PEventType::DATA_RECEIVED:
            log().debug("[{}] P2P data received from {}: {} bytes",
                        name_, event.peer_id, event.plaintext->size());

            // 转发数据到 TUN 设备
            if (tun_actor_) {
                co_await write_tun_packet(event.plaintext);
            } else {
                log().warn("[{}] Cannot forward P2P data: TUN actor not available", name_);
            }
            break;

        case P2PEventType::P2P_ERROR:
            log().error("[{}] P2P error: {}", name_, event.error_message);
            break;

        default:
            log().warn("[{}] Unhandled P2P event type: {}", name_, static_cast<int>(event.type));
            break;
    }

    co_return;
}

asio::awaitable<void> ClientActor::handle_tun_event(const TunEvent& event) {
    using edgelink::messages::TunEventType;

    log().debug("[{}] Handling TUN event: type={}", name_, static_cast<int>(event.type));

    switch (event.type) {
        case TunEventType::OPENED:
            log().info("[{}] TUN device opened: name={}, ip={}",
                       name_, event.dev_name, event.ip.to_string());
            break;

        case TunEventType::CLOSED:
            log().info("[{}] TUN device closed", name_);
            break;

        case TunEventType::PACKET_RECEIVED: {
            log().debug("[{}] TUN packet received: dst_ip={}, {} bytes",
                        name_, event.dst_ip.to_string(), event.packet->size());

            // 根据目标 IP 查找对端
            auto peer_opt = peers_.get_peer_by_ip(event.dst_ip);
            if (peer_opt.has_value()) {
                // 通过 DataPlane 发送数据包
                co_await send_to_peer(peer_opt->info.node_id, event.packet);
            } else {
                log().warn("[{}] No peer found for IP: {}", name_, event.dst_ip.to_string());
            }
            break;
        }

        case TunEventType::TUN_ERROR:
            log().error("[{}] TUN error: {}", name_, event.error_message);
            break;

        default:
            log().warn("[{}] Unhandled TUN event type: {}", name_, static_cast<int>(event.type));
            break;
    }

    co_return;
}

} // namespace edgelink::client

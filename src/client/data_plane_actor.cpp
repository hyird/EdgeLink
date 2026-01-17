// DataPlaneActor 实现

#include "client/data_plane_actor.hpp"
#include "client/relay_channel_actor.hpp"
#include "client/p2p_manager_actor.hpp"
#include "common/logger.hpp"
#include "common/performance_monitor.hpp"

namespace edgelink::client {

namespace {

auto& log() { return Logger::get("client.data_plane"); }

} // anonymous namespace

// ============================================================================
// 构造函数和生命周期
// ============================================================================

DataPlaneActor::DataPlaneActor(
    asio::io_context& ioc,
    CryptoEngine& crypto,
    PeerManager& peers,
    asio::experimental::concurrent_channel<void(boost::system::error_code, DataPlaneEvent)>* event_channel)
    : ActorBase(ioc, "DataPlaneActor")
    , crypto_(crypto)
    , peers_(peers)
    , event_channel_(event_channel) {
}

asio::awaitable<void> DataPlaneActor::on_start() {
    log().info("[{}] Actor started", name_);

    // 注册性能监控（邮箱队列容量为 64）
    perf::PerformanceMonitor::instance().register_queue("DataPlane.Mailbox", 64);

    co_return;
}

asio::awaitable<void> DataPlaneActor::on_stop() {
    log().info("[{}] Actor stopping", name_);
    state_ = DataPlaneState::STOPPED;

    // 清空路由表
    route_table_.clear();

    log().info("[{}] Actor stopped", name_);
    co_return;
}

// ============================================================================
// 消息处理
// ============================================================================

asio::awaitable<void> DataPlaneActor::handle_message(DataPlaneCommand cmd) {
    if (std::holds_alternative<LifecycleMessage>(cmd)) {
        auto& lifecycle = std::get<LifecycleMessage>(cmd);
        log().debug("[{}] Received lifecycle message: type={}", name_, static_cast<int>(lifecycle.type));

        if (lifecycle.type == LifecycleType::STOP) {
            co_await on_stop();
        } else if (lifecycle.type == LifecycleType::START) {
            co_await handle_start_cmd();
        }
        co_return;
    }

    auto& data_cmd = std::get<DataPlaneCmd>(cmd);
    log().debug("[{}] Received command: type={}", name_, static_cast<int>(data_cmd.type));

    switch (data_cmd.type) {
        case DataPlaneCmdType::START:
            co_await handle_start_cmd();
            break;

        case DataPlaneCmdType::STOP:
            co_await handle_stop_cmd();
            break;

        case DataPlaneCmdType::SEND_TO:
            co_await handle_send_to_cmd(data_cmd);
            break;

        case DataPlaneCmdType::UPDATE_ROUTE:
            co_await handle_update_route_cmd(data_cmd);
            break;

        default:
            log().warn("[{}] Unhandled command type: {}", name_, static_cast<int>(data_cmd.type));
            break;
    }
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> DataPlaneActor::handle_start_cmd() {
    log().info("[{}] Handling START command", name_);

    state_ = DataPlaneState::RUNNING;

    // 发送启动事件
    DataPlaneEvent event;
    event.type = DataPlaneEventType::STARTED;
    send_event(event);
    co_return;
}

asio::awaitable<void> DataPlaneActor::handle_stop_cmd() {
    log().info("[{}] Handling STOP command", name_);
    co_await on_stop();

    // 发送停止事件
    DataPlaneEvent event;
    event.type = DataPlaneEventType::STOPPED;
    send_event(event);
}

asio::awaitable<void> DataPlaneActor::handle_send_to_cmd(const DataPlaneCmd& cmd) {
    PERF_MEASURE_LATENCY("DataPlane.SendPacket");
    PERF_INCREMENT("DataPlane.PacketsSent");
    PERF_ADD("DataPlane.BytesSent", cmd.data->size());

    if (state_ != DataPlaneState::RUNNING) {
        log().warn("[{}] Cannot send data: not running (state={})",
                   name_, data_plane_state_name(state_));
        co_return;
    }

    // 获取对端的数据路径
    PeerDataPath path = get_data_path(cmd.peer_id);

    log().debug("[{}] Sending {} bytes to {} via {}",
                name_, cmd.data->size(),
                peers_.get_peer_ip_str(cmd.peer_id),
                path == PeerDataPath::P2P ? "P2P" :
                path == PeerDataPath::RELAY ? "Relay" : "None");

    if (path == PeerDataPath::NONE) {
        log().warn("[{}] No data path available for {}",
                   name_, peers_.get_peer_ip_str(cmd.peer_id));
        PERF_INCREMENT("DataPlane.NoPathErrors");

        // 发送错误事件
        DataPlaneEvent event;
        event.type = DataPlaneEventType::DATA_ERROR;
        event.error_message = "No data path available for peer";
        send_event(event);
        co_return;
    }

    // 根据路径转发数据
    try {
        if (path == PeerDataPath::P2P) {
            PERF_INCREMENT("DataPlane.PacketsViaP2P");
            // 通过 P2P Manager 发送
            if (p2p_) {
                using edgelink::messages::P2PManagerCmd;
                using edgelink::messages::P2PCmdType;

                P2PManagerCmd send_cmd;
                send_cmd.type = P2PCmdType::SEND_DATA;
                send_cmd.peer_id = cmd.peer_id;
                send_cmd.plaintext = cmd.data;
                co_await p2p_->send_message(send_cmd);
            } else {
                log().error("[{}] P2P manager not set", name_);
            }

        } else if (path == PeerDataPath::RELAY) {
            PERF_INCREMENT("DataPlane.PacketsViaRelay");
            // 通过 Relay Channel 发送
            if (relay_) {
                using edgelink::messages::RelayChannelCmd;
                using edgelink::messages::RelayCmdType;

                RelayChannelCmd send_cmd;
                send_cmd.type = RelayCmdType::SEND_DATA;
                send_cmd.peer_id = cmd.peer_id;
                send_cmd.plaintext = cmd.data;

                co_await relay_->send_message(send_cmd);
            } else {
                log().error("[{}] Relay channel not set", name_);
            }
        }
    } catch (const std::exception& e) {
        log().error("[{}] Failed to send data to {}: {}",
                    name_, peers_.get_peer_ip_str(cmd.peer_id), e.what());
        PERF_INCREMENT("DataPlane.SendErrors");

        // 发送错误事件
        DataPlaneEvent event;
        event.type = DataPlaneEventType::DATA_ERROR;
        event.error_message = e.what();
        send_event(event);
    }
}

asio::awaitable<void> DataPlaneActor::handle_update_route_cmd(const DataPlaneCmd& cmd) {
    log().info("[{}] Updating route table with {} entries",
               name_, cmd.route_table.size());

    // 更新路由表
    route_table_ = cmd.route_table;

    // 打印路由表（调试用）
    for (const auto& [node_id, path] : route_table_) {
        log().debug("[{}]   {} -> {}",
                    name_, peers_.get_peer_ip_str(node_id),
                    path == PeerDataPath::P2P ? "P2P" :
                    path == PeerDataPath::RELAY ? "Relay" : "None");
    }

    co_return;
}

// ============================================================================
// 路由逻辑
// ============================================================================

PeerDataPath DataPlaneActor::get_data_path(NodeId peer_id) const {
    auto it = route_table_.find(peer_id);
    if (it != route_table_.end()) {
        return it->second;
    }
    return PeerDataPath::NONE;
}

// ============================================================================
// 事件发送
// ============================================================================

void DataPlaneActor::send_event(DataPlaneEvent event) {
    if (event_channel_) {
        event_channel_->try_send(boost::system::error_code{}, event);
    }
}

} // namespace edgelink::client

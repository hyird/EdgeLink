// DataPlaneActor - 数据面路由 Actor
// 统一管理数据收发，根据路由表决策使用 P2P 或 Relay

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "common/types.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <memory>
#include <unordered_map>
#include <variant>

namespace asio = boost::asio;

namespace edgelink::client {

// 前向声明
class RelayChannelActor;
class P2PManagerActor;

// 导入消息类型（简化命名空间使用）
using edgelink::messages::DataPlaneCmd;
using edgelink::messages::DataPlaneEvent;
using edgelink::messages::DataPlaneCmdType;
using edgelink::messages::DataPlaneEventType;
using edgelink::messages::PeerDataPath;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;

// ============================================================================
// DataPlaneActor 状态
// ============================================================================

enum class DataPlaneState : uint8_t {
    STOPPED,   // 未启动
    RUNNING,   // 运行中
};

inline const char* data_plane_state_name(DataPlaneState state) {
    switch (state) {
        case DataPlaneState::STOPPED:  return "STOPPED";
        case DataPlaneState::RUNNING:  return "RUNNING";
        default:                       return "UNKNOWN";
    }
}

// ============================================================================
// DataPlaneActor - 数据面路由 Actor
// ============================================================================

// 命令消息类型（从 ClientActor 或外部接收）
using DataPlaneCommand = std::variant<
    DataPlaneCmd,
    LifecycleMessage
>;

class DataPlaneActor : public actor::ActorBase<DataPlaneActor, DataPlaneCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param crypto 加密引擎
    // @param peers 对端管理器
    // @param event_channel 事件输出通道（发送给 ClientActor）- 使用 concurrent_channel 确保线程安全
    DataPlaneActor(
        asio::io_context& ioc,
        CryptoEngine& crypto,
        PeerManager& peers,
        asio::experimental::concurrent_channel<void(boost::system::error_code, DataPlaneEvent)>* event_channel);

    virtual ~DataPlaneActor() = default;

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(DataPlaneCommand cmd) override;

    // 状态查询
    DataPlaneState state() const { return state_; }
    bool is_running() const { return state_ == DataPlaneState::RUNNING; }

    // 设置子 Actor 引用（用于数据转发）
    void set_relay_channel(RelayChannelActor* relay) { relay_ = relay; }
    void set_p2p_manager(P2PManagerActor* p2p) { p2p_ = p2p; }

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_start_cmd();
    asio::awaitable<void> handle_stop_cmd();
    asio::awaitable<void> handle_send_to_cmd(const DataPlaneCmd& cmd);
    asio::awaitable<void> handle_update_route_cmd(const DataPlaneCmd& cmd);

    // ========================================================================
    // 路由逻辑
    // ========================================================================

    // 根据路由表决策数据路径
    PeerDataPath get_data_path(NodeId peer_id) const;

    // ========================================================================
    // 事件发送（到 ClientActor）
    // ========================================================================

    void send_event(DataPlaneEvent event);

    // ========================================================================
    // 成员变量
    // ========================================================================

    CryptoEngine& crypto_;
    PeerManager& peers_;
    asio::experimental::concurrent_channel<void(boost::system::error_code, DataPlaneEvent)>* event_channel_;

    // 子 Actor 引用
    RelayChannelActor* relay_ = nullptr;
    P2PManagerActor* p2p_ = nullptr;

    // 运行状态
    DataPlaneState state_ = DataPlaneState::STOPPED;

    // 路由表（NodeId -> 数据路径）
    std::unordered_map<NodeId, PeerDataPath> route_table_;
};

} // namespace edgelink::client

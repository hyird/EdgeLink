// ClientActor - 顶层协调器 Actor
// 管理所有子 Actor（ControlChannel, RelayChannel, DataPlane, P2P, TUN）

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "common/types.hpp"
#include "common/performance_config.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/endpoint_manager.hpp"
#include "client/control_channel_actor.hpp"
#include "client/relay_channel_actor.hpp"
#include "client/data_plane_actor.hpp"
#include "client/p2p_manager_actor.hpp"
#include "client/tun_device_actor.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace asio = boost::asio;
namespace ssl = asio::ssl;

namespace edgelink::client {

// 导入消息类型
using edgelink::messages::ClientInternalCmd;
using edgelink::messages::ClientInternalCmdType;
using edgelink::messages::ControlChannelEvent;
using edgelink::messages::RelayChannelEvent;
using edgelink::messages::DataPlaneEvent;
using edgelink::messages::P2PManagerEvent;
using edgelink::messages::TunEvent;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;
using edgelink::messages::PeerDataPath;

// ============================================================================
// ClientActor 状态
// ============================================================================

enum class ClientActorState : uint8_t {
    STOPPED,         // 未启动
    STARTING,        // 启动中
    AUTHENTICATING,  // 认证中
    CONNECTING_RELAY,// 连接中继
    RUNNING,         // 运行中
    RECONNECTING,    // 重连中
};

inline const char* client_actor_state_name(ClientActorState state) {
    switch (state) {
        case ClientActorState::STOPPED:         return "STOPPED";
        case ClientActorState::STARTING:        return "STARTING";
        case ClientActorState::AUTHENTICATING:  return "AUTHENTICATING";
        case ClientActorState::CONNECTING_RELAY: return "CONNECTING_RELAY";
        case ClientActorState::RUNNING:         return "RUNNING";
        case ClientActorState::RECONNECTING:    return "RECONNECTING";
        default:                                return "UNKNOWN";
    }
}

// ============================================================================
// ClientActor - 客户端顶层协调器
// ============================================================================

// 命令消息类型
using ClientActorCommand = std::variant<
    ClientInternalCmd,
    LifecycleMessage
>;

class ClientActor : public actor::ActorBase<ClientActor, ClientActorCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param ssl_ctx SSL 上下文
    // @param crypto 加密引擎
    // @param peers 对端管理器
    // @param endpoints 端点管理器
    ClientActor(
        asio::io_context& ioc,
        ssl::context& ssl_ctx,
        CryptoEngine& crypto,
        PeerManager& peers,
        EndpointManager& endpoints);

    virtual ~ClientActor();

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(ClientActorCommand cmd) override;

    // 启动客户端（连接到 Controller）
    asio::awaitable<bool> start_client(const std::string& controller_url,
                                       const std::string& authkey,
                                       bool use_tls);

    // 停止客户端
    asio::awaitable<void> stop_client();

    // 发送数据到对端（通过 DataPlane）
    asio::awaitable<bool> send_to_peer(NodeId peer_id, std::shared_ptr<std::vector<uint8_t>> data);

    // 更新路由表（通知 DataPlane）
    asio::awaitable<void> update_routes(const std::unordered_map<NodeId, PeerDataPath>& route_table);

    // TUN 设备管理
    asio::awaitable<bool> open_tun(const std::string& dev_name,
                                   const IPv4Address& ip,
                                   uint32_t mtu = 1420);
    asio::awaitable<void> close_tun();
    asio::awaitable<bool> write_tun_packet(std::shared_ptr<std::vector<uint8_t>> packet);

    // 状态查询
    ClientActorState client_state() const { return state_; }
    bool is_running() const { return state_ == ClientActorState::RUNNING; }

    // 获取认证信息
    NodeId node_id() const;
    IPv4Address virtual_ip() const;
    NetworkId network_id() const;
    const std::vector<uint8_t>& relay_token() const;

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_start_cmd();
    asio::awaitable<void> handle_stop_cmd();
    asio::awaitable<void> handle_reconnect_cmd();

    // ========================================================================
    // 事件循环（处理子 Actor 事件）
    // ========================================================================

    asio::awaitable<void> control_event_loop();
    asio::awaitable<void> relay_event_loop();
    asio::awaitable<void> data_plane_event_loop();
    asio::awaitable<void> p2p_event_loop();
    asio::awaitable<void> tun_event_loop();

    // ========================================================================
    // 事件处理
    // ========================================================================

    asio::awaitable<void> handle_control_event(const ControlChannelEvent& event);
    asio::awaitable<void> handle_relay_event(const RelayChannelEvent& event);
    asio::awaitable<void> handle_data_plane_event(const DataPlaneEvent& event);
    asio::awaitable<void> handle_p2p_event(const P2PManagerEvent& event);
    asio::awaitable<void> handle_tun_event(const TunEvent& event);

    // ========================================================================
    // 子 Actor 管理
    // ========================================================================

    void create_actors();
    void destroy_actors();

    // ========================================================================
    // 成员变量
    // ========================================================================

    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    EndpointManager& endpoints_;

    // 客户端状态
    ClientActorState state_ = ClientActorState::STOPPED;

    // 连接参数（用于重连）
    std::string controller_url_;
    std::string authkey_;
    bool use_tls_ = true;

    // 子 Actor 实例
    std::shared_ptr<ControlChannelActor> control_actor_;
    std::shared_ptr<RelayChannelActor> relay_actor_;
    std::shared_ptr<DataPlaneActor> data_plane_actor_;
    std::shared_ptr<P2PManagerActor> p2p_actor_;
    std::shared_ptr<TunDeviceActor> tun_actor_;

    // 子 Actor 事件通道（使用 concurrent_channel 确保跨 strand 线程安全）
    std::unique_ptr<asio::experimental::concurrent_channel<void(boost::system::error_code, ControlChannelEvent)>> control_event_ch_;
    std::unique_ptr<asio::experimental::concurrent_channel<void(boost::system::error_code, RelayChannelEvent)>> relay_event_ch_;
    std::unique_ptr<asio::experimental::concurrent_channel<void(boost::system::error_code, DataPlaneEvent)>> data_plane_event_ch_;
    std::unique_ptr<asio::experimental::concurrent_channel<void(boost::system::error_code, P2PManagerEvent)>> p2p_event_ch_;
    std::unique_ptr<asio::experimental::concurrent_channel<void(boost::system::error_code, TunEvent)>> tun_event_ch_;

    // 事件循环控制
    std::atomic<bool> control_loop_running_{false};
    std::atomic<bool> relay_loop_running_{false};
    std::atomic<bool> data_plane_loop_running_{false};
    std::atomic<bool> p2p_loop_running_{false};
    std::atomic<bool> tun_loop_running_{false};
};

} // namespace edgelink::client

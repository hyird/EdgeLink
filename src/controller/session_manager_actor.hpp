// SessionManagerActor - SessionManager 的 Actor 包装
// 提供统一的消息接口，内部委托给现有的 SessionManager

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "controller/session_manager.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>

namespace asio = boost::asio;

namespace edgelink::controller {

// 导入消息类型
using edgelink::messages::SessionManagerCmd;
using edgelink::messages::SessionManagerEvent;
using edgelink::messages::SessionManagerCmdType;
using edgelink::messages::SessionManagerEventType;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;

// ============================================================================
// SessionManagerActor - SessionManager 的 Actor 包装
// ============================================================================

// 命令消息类型
using SessionManagerCommand = std::variant<
    SessionManagerCmd,
    LifecycleMessage
>;

class SessionManagerActor : public actor::ActorBase<SessionManagerActor, SessionManagerCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param manager SessionManager 引用（不拥有所有权）
    // @param event_channel 事件输出通道（可选，用于发送事件）
    SessionManagerActor(
        asio::io_context& ioc,
        SessionManager& manager,
        asio::experimental::concurrent_channel<void(boost::system::error_code, SessionManagerEvent)>* event_channel = nullptr);

    virtual ~SessionManagerActor();

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(SessionManagerCommand cmd) override;

    // 获取底层 SessionManager
    SessionManager& manager() { return manager_; }

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_start_cmd();
    asio::awaitable<void> handle_stop_cmd();
    asio::awaitable<void> handle_broadcast_config_update_cmd(const SessionManagerCmd& cmd);
    asio::awaitable<void> handle_broadcast_route_update_cmd(const SessionManagerCmd& cmd);
    asio::awaitable<void> handle_notify_peer_status_cmd(const SessionManagerCmd& cmd);
    asio::awaitable<void> handle_check_timeouts_cmd();

    // ========================================================================
    // 事件发送
    // ========================================================================

    void send_event(SessionManagerEvent event);

    // ========================================================================
    // 定时任务
    // ========================================================================

    // 超时检查循环
    asio::awaitable<void> timeout_check_loop();

    // ========================================================================
    // 成员变量
    // ========================================================================

    SessionManager& manager_;  // 底层 SessionManager（引用，不拥有）
    asio::experimental::concurrent_channel<void(boost::system::error_code, SessionManagerEvent)>* event_channel_;

    // 定时器
    asio::steady_timer timeout_timer_;

    // 循环控制
    std::atomic<bool> timeout_check_running_{false};
};

} // namespace edgelink::controller

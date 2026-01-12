// SessionManagerActor 实现

#include "controller/session_manager_actor.hpp"
#include "common/logger.hpp"

#include <chrono>

namespace edgelink::controller {

namespace {

auto& log() { return Logger::get("controller.session_manager_actor"); }

} // anonymous namespace

// ============================================================================
// 构造函数和生命周期
// ============================================================================

SessionManagerActor::SessionManagerActor(
    asio::io_context& ioc,
    SessionManager& manager,
    asio::experimental::concurrent_channel<void(boost::system::error_code, SessionManagerEvent)>* event_channel)
    : ActorBase(ioc, "SessionManagerActor")
    , manager_(manager)
    , event_channel_(event_channel)
    , timeout_timer_(ioc) {

    log().info("[{}] Actor created", name_);
}

SessionManagerActor::~SessionManagerActor() {
    log().info("[{}] Actor destroyed", name_);
}

asio::awaitable<void> SessionManagerActor::on_start() {
    log().info("[{}] Actor started", name_);

    // 启动超时检查循环
    timeout_check_running_ = true;
    asio::co_spawn(
        ioc_,
        [this]() -> asio::awaitable<void> {
            co_await timeout_check_loop();
        },
        asio::detached);

    // 发送启动事件
    SessionManagerEvent event;
    event.type = SessionManagerEventType::STARTED;
    send_event(event);

    co_return;
}

asio::awaitable<void> SessionManagerActor::on_stop() {
    log().info("[{}] Actor stopping", name_);

    // 停止超时检查循环
    timeout_check_running_ = false;
    timeout_timer_.cancel();

    // 发送停止事件
    SessionManagerEvent event;
    event.type = SessionManagerEventType::STOPPED;
    send_event(event);

    log().info("[{}] Actor stopped", name_);
    co_return;
}

// ============================================================================
// 消息处理
// ============================================================================

asio::awaitable<void> SessionManagerActor::handle_message(SessionManagerCommand cmd) {
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

    auto& sm_cmd = std::get<SessionManagerCmd>(cmd);
    log().debug("[{}] Received SessionManager command: type={}", name_, static_cast<int>(sm_cmd.type));

    switch (sm_cmd.type) {
        case SessionManagerCmdType::START:
            co_await handle_start_cmd();
            break;

        case SessionManagerCmdType::STOP:
            co_await handle_stop_cmd();
            break;

        case SessionManagerCmdType::BROADCAST_CONFIG_UPDATE:
            co_await handle_broadcast_config_update_cmd(sm_cmd);
            break;

        case SessionManagerCmdType::BROADCAST_ROUTE_UPDATE:
            co_await handle_broadcast_route_update_cmd(sm_cmd);
            break;

        case SessionManagerCmdType::NOTIFY_PEER_STATUS:
            co_await handle_notify_peer_status_cmd(sm_cmd);
            break;

        case SessionManagerCmdType::CHECK_TIMEOUTS:
            co_await handle_check_timeouts_cmd();
            break;

        default:
            log().warn("[{}] Unhandled command type: {}", name_, static_cast<int>(sm_cmd.type));
            break;
    }
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> SessionManagerActor::handle_start_cmd() {
    log().info("[{}] Handling START command", name_);
    // SessionManager 没有显式的 start 方法，它在构造时就已就绪
    co_return;
}

asio::awaitable<void> SessionManagerActor::handle_stop_cmd() {
    log().info("[{}] Handling STOP command", name_);
    co_await on_stop();
}

asio::awaitable<void> SessionManagerActor::handle_broadcast_config_update_cmd(const SessionManagerCmd& cmd) {
    log().debug("[{}] Broadcasting config update: network={}, except_node={}",
                name_, cmd.network_id, cmd.except_node);

    try {
        // 委托给底层 SessionManager
        co_await manager_.broadcast_config_update(cmd.network_id, cmd.except_node);

        // 发送成功事件
        SessionManagerEvent event;
        event.type = SessionManagerEventType::CONFIG_BROADCASTED;
        event.network_id = cmd.network_id;
        event.broadcast_count = manager_.get_network_control_sessions(cmd.network_id).size();
        send_event(event);

    } catch (const std::exception& e) {
        log().error("[{}] Failed to broadcast config update: {}", name_, e.what());

        SessionManagerEvent event;
        event.type = SessionManagerEventType::SESSION_ERROR;
        event.error_message = e.what();
        send_event(event);
    }
}

asio::awaitable<void> SessionManagerActor::handle_broadcast_route_update_cmd(const SessionManagerCmd& cmd) {
    log().debug("[{}] Broadcasting route update: network={}, except_node={}, add={}, del={}",
                name_, cmd.network_id, cmd.except_node, cmd.add_routes.size(), cmd.del_routes.size());

    try {
        // 委托给底层 SessionManager
        co_await manager_.broadcast_route_update(cmd.network_id, cmd.except_node,
                                                  cmd.add_routes, cmd.del_routes);

        // 发送成功事件
        SessionManagerEvent event;
        event.type = SessionManagerEventType::ROUTE_BROADCASTED;
        event.network_id = cmd.network_id;
        event.broadcast_count = manager_.get_network_control_sessions(cmd.network_id).size();
        send_event(event);

    } catch (const std::exception& e) {
        log().error("[{}] Failed to broadcast route update: {}", name_, e.what());

        SessionManagerEvent event;
        event.type = SessionManagerEventType::SESSION_ERROR;
        event.error_message = e.what();
        send_event(event);
    }
}

asio::awaitable<void> SessionManagerActor::handle_notify_peer_status_cmd(const SessionManagerCmd& cmd) {
    log().debug("[{}] Notifying peer status: target={}, peer={}, online={}",
                name_, cmd.target_node, cmd.peer_node, cmd.online);

    try {
        // 委托给底层 SessionManager
        co_await manager_.notify_peer_status(cmd.target_node, cmd.peer_node, cmd.online);

    } catch (const std::exception& e) {
        log().error("[{}] Failed to notify peer status: {}", name_, e.what());

        SessionManagerEvent event;
        event.type = SessionManagerEventType::SESSION_ERROR;
        event.error_message = e.what();
        send_event(event);
    }
}

asio::awaitable<void> SessionManagerActor::handle_check_timeouts_cmd() {
    log().trace("[{}] Checking timeouts", name_);

    try {
        // 委托给底层 SessionManager
        manager_.check_timeouts();

    } catch (const std::exception& e) {
        log().error("[{}] Failed to check timeouts: {}", name_, e.what());
    }

    co_return;
}

// ============================================================================
// 定时任务
// ============================================================================

asio::awaitable<void> SessionManagerActor::timeout_check_loop() {
    log().info("[{}] Timeout check loop started", name_);

    constexpr auto CHECK_INTERVAL = std::chrono::seconds(30);

    while (timeout_check_running_.load()) {
        try {
            // 等待定时器
            timeout_timer_.expires_after(CHECK_INTERVAL);
            co_await timeout_timer_.async_wait(asio::use_awaitable);

            // 检查超时
            if (timeout_check_running_.load()) {
                manager_.check_timeouts();
            }

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                log().debug("[{}] Timeout check loop cancelled", name_);
                break;
            }
            log().error("[{}] Timeout check loop error: {}", name_, e.what());
        } catch (const std::exception& e) {
            log().error("[{}] Timeout check loop exception: {}", name_, e.what());
        }
    }

    timeout_check_running_ = false;
    log().info("[{}] Timeout check loop stopped", name_);
}

// ============================================================================
// 事件发送
// ============================================================================

void SessionManagerActor::send_event(SessionManagerEvent event) {
    if (event_channel_) {
        event_channel_->try_send(boost::system::error_code{}, event);
    }
}

} // namespace edgelink::controller

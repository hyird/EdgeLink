// Actor 模式基础设施
// 提供 Actor 基类、邮箱抽象、生命周期管理

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <atomic>
#include <memory>
#include <string>
#include <stdexcept>

namespace asio = boost::asio;

namespace edgelink::actor {

// ============================================================================
// Actor 生命周期状态
// ============================================================================
enum class ActorState : uint8_t {
    CREATED,      // 已创建，未启动
    STARTING,     // 启动中
    RUNNING,      // 运行中
    STOPPING,     // 停止中
    STOPPED,      // 已停止
    FAILED,       // 失败状态
};

// 状态名称字符串转换
inline const char* actor_state_name(ActorState state) {
    switch (state) {
        case ActorState::CREATED:  return "CREATED";
        case ActorState::STARTING: return "STARTING";
        case ActorState::RUNNING:  return "RUNNING";
        case ActorState::STOPPING: return "STOPPING";
        case ActorState::STOPPED:  return "STOPPED";
        case ActorState::FAILED:   return "FAILED";
        default:                   return "UNKNOWN";
    }
}

// ============================================================================
// Actor 邮箱抽象（支持 channel 和 concurrent_channel）
// ============================================================================
template<typename MessageType>
class ActorMailbox {
public:
    using ChannelType = asio::experimental::channel<void(boost::system::error_code, MessageType)>;
    using ConcurrentChannelType = asio::experimental::concurrent_channel<void(boost::system::error_code, MessageType)>;

    // 构造函数
    // @param ioc io_context 引用
    // @param capacity 邮箱容量（缓冲区大小）
    // @param concurrent 是否使用线程安全的 concurrent_channel
    explicit ActorMailbox(asio::io_context& ioc, size_t capacity, bool concurrent = false)
        : concurrent_(concurrent) {
        if (concurrent_) {
            concurrent_channel_ = std::make_unique<ConcurrentChannelType>(ioc, capacity);
        } else {
            channel_ = std::make_unique<ChannelType>(ioc, capacity);
        }
    }

    // 禁止拷贝和移动
    ActorMailbox(const ActorMailbox&) = delete;
    ActorMailbox& operator=(const ActorMailbox&) = delete;
    ActorMailbox(ActorMailbox&&) = delete;
    ActorMailbox& operator=(ActorMailbox&&) = delete;

    // 发送消息（异步，会阻塞直到有空间）
    asio::awaitable<void> send(MessageType msg) {
        if (concurrent_) {
            auto [ec] = co_await concurrent_channel_->async_send(
                boost::system::error_code{}, std::move(msg), asio::as_tuple(asio::use_awaitable));
            if (ec) {
                throw boost::system::system_error(ec, "ActorMailbox::send failed");
            }
        } else {
            auto [ec] = co_await channel_->async_send(
                boost::system::error_code{}, std::move(msg), asio::as_tuple(asio::use_awaitable));
            if (ec) {
                throw boost::system::system_error(ec, "ActorMailbox::send failed");
            }
        }
    }

    // 尝试发送消息（非阻塞）
    // @return true 如果成功入队，false 如果邮箱已满
    bool try_send(MessageType msg) {
        if (concurrent_) {
            return concurrent_channel_->try_send(boost::system::error_code{}, std::move(msg));
        } else {
            return channel_->try_send(boost::system::error_code{}, std::move(msg));
        }
    }

    // 接收消息（异步，会阻塞直到有消息）
    asio::awaitable<MessageType> receive() {
        if (concurrent_) {
            auto [ec, msg] = co_await concurrent_channel_->async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec) {
                throw boost::system::system_error(ec, "ActorMailbox::receive failed");
            }
            co_return std::move(msg);
        } else {
            auto [ec, msg] = co_await channel_->async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec) {
                throw boost::system::system_error(ec, "ActorMailbox::receive failed");
            }
            co_return std::move(msg);
        }
    }

    // 关闭邮箱（停止接收新消息）
    void close() {
        if (concurrent_) {
            concurrent_channel_->close();
        } else {
            channel_->close();
        }
    }

    // 检查是否使用 concurrent_channel
    bool is_concurrent() const { return concurrent_; }

private:
    bool concurrent_;
    std::unique_ptr<ChannelType> channel_;
    std::unique_ptr<ConcurrentChannelType> concurrent_channel_;
};

// ============================================================================
// Actor 基类（CRTP 模式，避免虚函数开销）
// ============================================================================
template<typename Derived, typename MessageType>
class ActorBase : public std::enable_shared_from_this<ActorBase<Derived, MessageType>> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param name Actor 名称（用于日志和调试）
    // @param mailbox_capacity 邮箱容量
    // @param use_concurrent_mailbox 是否使用线程安全的 concurrent_channel
    explicit ActorBase(asio::io_context& ioc, const std::string& name,
                       size_t mailbox_capacity = 64, bool use_concurrent_mailbox = false)
        : ioc_(ioc)
        , strand_(asio::make_strand(ioc))
        , name_(name)
        , state_(ActorState::CREATED)
        , mailbox_(ioc, mailbox_capacity, use_concurrent_mailbox)
        , message_loop_running_(false) {
    }

    virtual ~ActorBase() = default;

    // 禁止拷贝和移动
    ActorBase(const ActorBase&) = delete;
    ActorBase& operator=(const ActorBase&) = delete;
    ActorBase(ActorBase&&) = delete;
    ActorBase& operator=(ActorBase&&) = delete;

    // ========================================================================
    // 生命周期管理
    // ========================================================================

    // 启动 Actor
    asio::awaitable<void> start() {
        ActorState expected = ActorState::CREATED;
        if (!state_.compare_exchange_strong(expected, ActorState::STARTING)) {
            // 允许从 STOPPED 状态重新启动
            expected = ActorState::STOPPED;
            if (!state_.compare_exchange_strong(expected, ActorState::STARTING)) {
                throw std::runtime_error(std::string("Actor ") + name_ + " cannot start from state " +
                                       actor_state_name(state_.load()));
            }
        }

        try {
            // 调用子类的初始化逻辑
            co_await static_cast<Derived*>(this)->on_start();

            state_ = ActorState::RUNNING;
            message_loop_running_ = true;

            // 启动消息处理循环（在 strand 中运行）
            asio::co_spawn(strand_,
                [self = this->shared_from_this()]() -> asio::awaitable<void> {
                    co_await self->message_loop();
                },
                asio::detached);

        } catch (const std::exception& e) {
            state_ = ActorState::FAILED;
            throw;
        }
    }

    // 停止 Actor
    asio::awaitable<void> stop() {
        ActorState expected = ActorState::RUNNING;
        if (!state_.compare_exchange_strong(expected, ActorState::STOPPING)) {
            // 如果已经停止或正在停止，直接返回
            ActorState current = state_.load();
            if (current == ActorState::STOPPED || current == ActorState::STOPPING) {
                co_return;
            }
            // 其他状态不允许停止
            throw std::runtime_error(std::string("Actor ") + name_ + " cannot stop from state " +
                                   actor_state_name(current));
        }

        try {
            // 停止消息循环
            message_loop_running_ = false;

            // 关闭邮箱（唤醒阻塞的 receive）
            mailbox_.close();

            // 调用子类的清理逻辑
            co_await static_cast<Derived*>(this)->on_stop();

            state_ = ActorState::STOPPED;

        } catch (const std::exception& e) {
            state_ = ActorState::FAILED;
            throw;
        }
    }

    // 重启 Actor
    asio::awaitable<void> restart() {
        co_await stop();
        co_await start();
    }

    // ========================================================================
    // 消息发送
    // ========================================================================

    // 发送消息到此 Actor（异步，会阻塞直到有空间）
    asio::awaitable<void> send_message(MessageType msg) {
        co_await mailbox_.send(std::move(msg));
    }

    // 尝试发送消息（非阻塞）
    // @return true 如果成功，false 如果邮箱已满
    bool try_send_message(MessageType msg) {
        return mailbox_.try_send(std::move(msg));
    }

    // ========================================================================
    // 状态查询
    // ========================================================================

    ActorState state() const { return state_.load(); }
    bool is_running() const { return state_.load() == ActorState::RUNNING; }
    bool is_stopped() const { return state_.load() == ActorState::STOPPED; }
    bool is_failed() const { return state_.load() == ActorState::FAILED; }
    const std::string& name() const { return name_; }
    asio::strand<asio::io_context::executor_type>& strand() { return strand_; }
    const asio::strand<asio::io_context::executor_type>& strand() const { return strand_; }

protected:
    // 子类必须实现的接口

    // Actor 启动时调用（用于初始化资源）
    virtual asio::awaitable<void> on_start() = 0;

    // Actor 停止时调用（用于清理资源）
    virtual asio::awaitable<void> on_stop() = 0;

    // 处理接收到的消息（在 strand 中串行调用）
    virtual asio::awaitable<void> handle_message(MessageType msg) = 0;

    // 消息处理循环（在 strand 中运行，保证串行化）
    asio::awaitable<void> message_loop() {
        while (message_loop_running_.load()) {
            try {
                // 阻塞等待消息
                auto msg = co_await mailbox_.receive();

                // 调用子类的消息处理逻辑（保证在 strand 中串行执行）
                co_await static_cast<Derived*>(this)->handle_message(std::move(msg));

            } catch (const boost::system::system_error& e) {
                // 邮箱关闭或其他系统错误
                if (e.code() == asio::error::operation_aborted ||
                    e.code() == asio::experimental::error::channel_closed) {
                    // 正常退出
                    break;
                }
                // 其他错误，记录但继续处理
                // 子类可以在 handle_message 中处理特定错误
            } catch (const std::exception& e) {
                // 消息处理错误，记录但继续处理下一条消息
                // 避免单条消息错误导致整个 Actor 崩溃
            }
        }
    }

    // 可访问的成员
    asio::io_context& ioc_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::string name_;
    std::atomic<ActorState> state_;
    ActorMailbox<MessageType> mailbox_;
    std::atomic<bool> message_loop_running_;
};

} // namespace edgelink::actor

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/post.hpp>
#include <boost/cobalt.hpp>
#include <atomic>
#include <mutex>
#include <queue>
#include <optional>

namespace edgelink {

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;

/// 跨线程 channel：任意线程写入，cobalt 协程读取
///
/// 基于 mutex+queue 存储 + steady_timer 唤醒，零实验性 API 依赖。
/// steady_timer 设为 time_point::max() 是 Asio 社区经典模式，
/// 相当于 async condition variable，cancel() 即唤醒。
template<typename T>
class CrossThreadChannel {
public:
    /// 构造
    /// @param capacity 队列最大容量，满时 try_send 返回 false
    /// @param ex       消费者所在的 executor
    explicit CrossThreadChannel(size_t capacity, asio::any_io_executor ex)
        : timer_(ex), capacity_(capacity) {
        timer_.expires_at(asio::steady_timer::time_point::max());
    }

    // 不可拷贝/移动（内含 timer 和 mutex）
    CrossThreadChannel(const CrossThreadChannel&) = delete;
    CrossThreadChannel& operator=(const CrossThreadChannel&) = delete;
    CrossThreadChannel(CrossThreadChannel&&) = delete;
    CrossThreadChannel& operator=(CrossThreadChannel&&) = delete;

    // ================================================================
    // 生产者侧 — 任意线程安全
    // ================================================================

    /// 非阻塞写入。返回 false 表示满或已关闭
    bool try_send(T value) {
        if (closed_.load(std::memory_order_relaxed)) return false;
        {
            std::lock_guard lock(mutex_);
            if (queue_.size() >= capacity_) return false;
            queue_.push(std::move(value));
        }
        wake();
        return true;
    }

    /// 关闭 channel（唤醒等待中的消费者）
    void close() {
        closed_.store(true, std::memory_order_release);
        wake();
    }

    /// 是否已关闭
    bool is_closed() const { return closed_.load(std::memory_order_acquire); }

    // ================================================================
    // 消费者侧 — 仅 cobalt 协程（executor 线程）
    // ================================================================

    /// 读取一个元素。channel 关闭且队列为空时返回 nullopt
    cobalt::task<std::optional<T>> read() {
        for (;;) {
            // 先尝试从队列取
            {
                std::lock_guard lock(mutex_);
                if (!queue_.empty()) {
                    T val = std::move(queue_.front());
                    queue_.pop();
                    co_return std::move(val);
                }
            }
            // 队列空，检查是否已关闭
            if (closed_.load(std::memory_order_acquire)) {
                co_return std::nullopt;
            }
            // 等待唤醒：timer 设为 max，cancel 即唤醒
            timer_.expires_at(asio::steady_timer::time_point::max());
            auto [ec] = co_await cobalt::as_tuple(
                timer_.async_wait(cobalt::use_op));
            // ec == operation_aborted 表示被 cancel 唤醒，继续循环检查队列
        }
    }

private:
    /// 唤醒消费者（通过 post 保证线程安全）
    void wake() {
        asio::post(timer_.get_executor(), [this]() {
            timer_.cancel();
        });
    }

    asio::steady_timer timer_;
    size_t capacity_;
    std::atomic<bool> closed_{false};
    std::mutex mutex_;
    std::queue<T> queue_;
};

} // namespace edgelink

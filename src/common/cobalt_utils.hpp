#pragma once

#include <boost/cobalt.hpp>
#include <boost/cobalt/channel.hpp>
#include <boost/variant2/variant.hpp>
#include <expected>
#include <chrono>

namespace edgelink::cobalt_utils {

namespace cobalt = boost::cobalt;
namespace asio = boost::asio;

// Spawn helper：将 cobalt::task 启动到 asio executor
template<typename T>
void spawn_task(asio::any_io_executor ex, cobalt::task<T>&& t) {
    cobalt::spawn(ex, std::move(t), asio::detached);
}

// ============================================================================
// fire_write: 非协程上下文向 cobalt::channel 发送数据（fire-and-forget）
// ============================================================================
template<typename T>
void fire_write(cobalt::channel<T>& ch, T value, asio::any_io_executor ex) {
    cobalt::spawn(ex, [&ch, v = std::move(value)]() mutable -> cobalt::task<void> {
        co_await cobalt::as_tuple(ch.write(std::move(v)));
    }(), asio::detached);
}

inline void fire_write(cobalt::channel<void>& ch, asio::any_io_executor ex) {
    cobalt::spawn(ex, [&ch]() -> cobalt::task<void> {
        co_await cobalt::as_tuple(ch.write());
    }(), asio::detached);
}

// ============================================================================
// consume_channel: cobalt::channel<T> 版本
// ============================================================================
template<typename T, typename Handler>
cobalt::task<void> consume_channel(cobalt::channel<T>& ch, Handler&& handler) {
    for (;;) {
        auto [ec, value] = co_await cobalt::as_tuple(ch.read());
        if (ec) co_return;  // broken_pipe (closed) or operation_aborted
        co_await handler(std::move(value));
    }
}

// 超时包装器
template<typename T>
cobalt::task<std::expected<T, std::error_code>>
with_timeout(cobalt::task<T> t, std::chrono::milliseconds timeout) {
    auto ex = co_await cobalt::this_coro::executor;
    asio::steady_timer timer(ex, timeout);

    auto result = co_await cobalt::race(
        std::move(t),
        timer.async_wait(cobalt::use_op)
    );

    // race returns boost::variant2::variant, use boost::variant2::get
    if (result.index() == 0) {
        co_return boost::variant2::get<0>(result);
    } else {
        co_return std::unexpected(std::make_error_code(std::errc::timed_out));
    }
}

// 超时执行：运行操作，超时返回 false
template<typename Func>
cobalt::task<bool> timed_op(std::chrono::milliseconds timeout, Func&& func) {
    auto ex = co_await cobalt::this_coro::executor;
    asio::steady_timer timer(ex, timeout);

    auto result = co_await cobalt::race(
        func(),
        timer.async_wait(cobalt::use_op)
    );

    co_return result.index() == 0;  // true = 操作完成, false = 超时
}

// 结构化并发：并行等待多个 task
template<typename... Ts>
cobalt::task<std::tuple<Ts...>> gather(cobalt::task<Ts>... tasks) {
    co_return co_await cobalt::gather(std::move(tasks)...);
}

} // namespace edgelink::cobalt_utils

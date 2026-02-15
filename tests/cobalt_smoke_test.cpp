#include "common/cobalt_utils.hpp"
#include <boost/asio/io_context.hpp>
#include <cassert>
#include <iostream>

namespace cobalt = boost::cobalt;
using namespace edgelink::cobalt_utils;

cobalt::task<int> simple_task() {
    co_return 42;
}

cobalt::task<std::string> delayed_task(asio::io_context& io) {
    asio::steady_timer timer(io, std::chrono::milliseconds(100));
    co_await timer.async_wait(cobalt::use_op);
    co_return "hello cobalt";
}

int main() {
    asio::io_context io;

    // Test 1: 基础 task
    cobalt::spawn(io, simple_task(),
        [](std::exception_ptr e, int result) {
            assert(result == 42);
            std::cout << "✓ Basic task test passed\n";
        });

    // Test 2: 超时
    spawn_task(io.get_executor(),
        []() -> cobalt::task<void> {
            auto result = co_await with_timeout(
                simple_task(),
                std::chrono::seconds(1)
            );
            assert(result.has_value() && *result == 42);
            std::cout << "✓ Timeout wrapper test passed\n";
        }()
    );

    io.run();
    return 0;
}

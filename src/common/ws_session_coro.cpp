#include "ws_session_coro.hpp"
#include "io_context_pool.hpp"
#include "log.hpp"
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace edgelink {

using namespace boost::asio::experimental::awaitable_operators;

WsSessionCoro::WsSessionCoro(net::io_context& ioc, tcp::socket socket)
    : ioc_(ioc)
    , ws_(std::move(socket))
    , write_signal_(ioc)
{
    // Determine thread index
    if (IOContextPool::is_pool_thread()) {
        thread_index_ = IOContextPool::current_thread_index();
    }
}

WsSessionCoro::~WsSessionCoro() {
    // Ensure cleanup
    running_.store(false, std::memory_order_release);
}

void WsSessionCoro::start() {
    // Spawn the main session coroutine
    net::co_spawn(
        ioc_,
        [self = shared_from_this()]() -> net::awaitable<void> {
            co_await self->run_session();
        },
        [](std::exception_ptr ep) {
            if (ep) {
                try {
                    std::rethrow_exception(ep);
                } catch (const std::exception& e) {
                    LOG_ERROR("WsSessionCoro: Unhandled exception: {}", e.what());
                }
            }
        });
}

void WsSessionCoro::close() {
    close_requested_.store(true, std::memory_order_release);
    write_signal_.cancel();
}

void WsSessionCoro::set_upgrade_request(HttpRequest req) {
    upgrade_request_ = std::move(req);
}

void WsSessionCoro::send_binary(std::vector<uint8_t> data) {
    enqueue_send(std::move(data), false);
}

void WsSessionCoro::send_frame(const wire::Frame& frame) {
    auto data = frame.serialize();
    enqueue_send(std::move(data), false);
}

void WsSessionCoro::send_text(std::string text) {
    std::vector<uint8_t> data(text.begin(), text.end());
    enqueue_send(std::move(data), true);
}

void WsSessionCoro::set_authenticated(uint32_t node_id, uint32_t network_id) {
    node_id_ = node_id;
    network_id_ = network_id;
    authenticated_.store(true, std::memory_order_release);
}

std::string WsSessionCoro::remote_address() const {
    try {
        return ws_.next_layer().remote_endpoint().address().to_string();
    } catch (...) {
        return "unknown";
    }
}

void WsSessionCoro::enqueue_send(std::vector<uint8_t> data, bool is_text) {
    // Post to the session's io_context to ensure thread safety
    net::post(ioc_, [self = shared_from_this(), data = std::move(data), is_text]() mutable {
        if (self->running_.load(std::memory_order_acquire)) {
            self->write_queue_.push({std::move(data), is_text});
            self->write_signal_.cancel();  // Wake up writer coroutine
        }
    });
}

net::awaitable<void> WsSessionCoro::run_session() {
    std::string disconnect_reason = "normal";

    try {
        // Set WebSocket options
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
            res.set(boost::beast::http::field::server, "EdgeLink/1.0");
        }));

        // Accept WebSocket handshake
        // If we have a pre-read HTTP request, use async_accept(req)
        // Otherwise, read the HTTP request ourselves with async_accept()
        if (upgrade_request_) {
            co_await ws_.async_accept(*upgrade_request_, net::use_awaitable);
        } else {
            co_await ws_.async_accept(net::use_awaitable);
        }

        running_.store(true, std::memory_order_release);
        LOG_DEBUG("WsSessionCoro: Connection accepted from {}", remote_address());

        // Notify subclass
        co_await on_connected();

        // Run reader and writer concurrently
        // Using || operator: when either completes (or throws), both are cancelled
        co_await (reader() || writer());

    } catch (const boost::system::system_error& e) {
        if (e.code() == websocket::error::closed) {
            disconnect_reason = "peer closed";
        } else if (e.code() == net::error::operation_aborted) {
            disconnect_reason = "operation aborted";
        } else {
            disconnect_reason = e.what();
            LOG_WARN("WsSessionCoro: Error: {}", e.what());
        }
    } catch (const std::exception& e) {
        disconnect_reason = e.what();
        LOG_ERROR("WsSessionCoro: Exception: {}", e.what());
    }

    running_.store(false, std::memory_order_release);

    // Notify subclass
    try {
        co_await on_disconnected(disconnect_reason);
    } catch (const std::exception& e) {
        LOG_ERROR("WsSessionCoro: on_disconnected exception: {}", e.what());
    }

    // Close WebSocket if still open
    if (ws_.is_open()) {
        beast::error_code ec;
        ws_.close(websocket::close_code::normal, ec);
    }

    LOG_DEBUG("WsSessionCoro: Session ended ({})", disconnect_reason);
}

net::awaitable<void> WsSessionCoro::reader() {
    beast::flat_buffer buffer;

    while (running_.load(std::memory_order_acquire) &&
           !close_requested_.load(std::memory_order_acquire)) {

        // Read a message
        auto bytes = co_await ws_.async_read(buffer, net::use_awaitable);

        if (bytes == 0) {
            continue;
        }

        // Parse the frame
        auto data = static_cast<const uint8_t*>(buffer.data().data());
        std::span<const uint8_t> span(data, buffer.size());

        auto frame_opt = wire::Frame::deserialize(span);
        if (frame_opt) {
            co_await process_frame(*frame_opt);
        } else {
            LOG_WARN("WsSessionCoro: Failed to parse frame ({} bytes)", buffer.size());
        }

        buffer.consume(buffer.size());
    }
}

net::awaitable<void> WsSessionCoro::writer() {
    while (running_.load(std::memory_order_acquire) &&
           !close_requested_.load(std::memory_order_acquire)) {

        // Wait for data or close signal
        while (write_queue_.empty() &&
               running_.load(std::memory_order_acquire) &&
               !close_requested_.load(std::memory_order_acquire)) {

            write_signal_.expires_after(std::chrono::seconds(30));

            boost::system::error_code ec;
            co_await write_signal_.async_wait(
                net::redirect_error(net::use_awaitable, ec));

            // ec will be operation_aborted if cancelled (new data or close)
        }

        // Send all queued messages
        while (!write_queue_.empty()) {
            auto item = std::move(write_queue_.front());
            write_queue_.pop();

            ws_.binary(!item.is_text);
            co_await ws_.async_write(net::buffer(item.data), net::use_awaitable);
        }
    }

    // Handle close request
    if (close_requested_.load(std::memory_order_acquire)) {
        beast::error_code ec;
        ws_.close(websocket::close_code::normal, ec);
    }
}

} // namespace edgelink

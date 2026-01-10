#include "ws_client_coro.hpp"
#include "log.hpp"
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <regex>

namespace edgelink {

using namespace boost::asio::experimental::awaitable_operators;

WsClientCoro::WsClientCoro(net::io_context& ioc, const std::string& url, const std::string& name)
    : ioc_(ioc)
    , url_(url)
    , name_(name)
    , write_signal_(ioc)
{
    auto parsed = parse_url(url);
    if (parsed) {
        url_parts_ = *parsed;
    } else {
        LOG_ERROR("{}: Invalid URL: {}", name_, url);
    }

    // Configure SSL context
    ssl_ctx_.set_default_verify_paths();
    ssl_ctx_.set_verify_mode(ssl::verify_peer);
}

WsClientCoro::~WsClientCoro() {
    shutdown_.store(true, std::memory_order_release);
}

void WsClientCoro::connect() {
    if (shutdown_.load(std::memory_order_acquire)) {
        return;
    }

    net::co_spawn(
        ioc_,
        [self = shared_from_this()]() -> net::awaitable<void> {
            co_await self->run_connection();
        },
        [this](std::exception_ptr ep) {
            if (ep) {
                try {
                    std::rethrow_exception(ep);
                } catch (const std::exception& e) {
                    LOG_ERROR("{}: Unhandled exception: {}", name_, e.what());
                }
            }
        });
}

void WsClientCoro::disconnect() {
    shutdown_.store(true, std::memory_order_release);
    write_signal_.cancel();

    // Close WebSocket
    if (wss_ && wss_->is_open()) {
        beast::error_code ec;
        wss_->close(websocket::close_code::normal, ec);
    }
    if (ws_ && ws_->is_open()) {
        beast::error_code ec;
        ws_->close(websocket::close_code::normal, ec);
    }

    set_state(State::STOPPED);
}

void WsClientCoro::send_binary(std::vector<uint8_t> data) {
    enqueue_send(std::move(data), false);
}

void WsClientCoro::send_frame(const wire::Frame& frame) {
    LOG_TRACE("{}: TX frame type={} ({}) size={} flags=0x{:02x}",
              name_, static_cast<int>(frame.header.type),
              wire::message_type_to_string(frame.header.type),
              frame.payload.size(), frame.header.flags);
    auto data = frame.serialize();
    enqueue_send(std::move(data), false);
}

void WsClientCoro::send_text(std::string text) {
    std::vector<uint8_t> data(text.begin(), text.end());
    enqueue_send(std::move(data), true);
}

WsClientCoro::Stats WsClientCoro::stats() const {
    Stats s;
    s.bytes_sent = bytes_sent_.load(std::memory_order_relaxed);
    s.bytes_received = bytes_received_.load(std::memory_order_relaxed);
    s.frames_sent = frames_sent_.load(std::memory_order_relaxed);
    s.frames_received = frames_received_.load(std::memory_order_relaxed);
    s.reconnect_count = reconnect_count_.load(std::memory_order_relaxed);
    s.connected_at = connected_at_;
    s.last_rtt = std::chrono::milliseconds(last_rtt_ms_.load(std::memory_order_relaxed));
    return s;
}

static const char* state_to_string(WsClientCoro::State s) {
    switch (s) {
        case WsClientCoro::State::INIT: return "INIT";
        case WsClientCoro::State::CONNECTING: return "CONNECTING";
        case WsClientCoro::State::AUTHENTICATING: return "AUTHENTICATING";
        case WsClientCoro::State::CONNECTED: return "CONNECTED";
        case WsClientCoro::State::RECONNECTING: return "RECONNECTING";
        case WsClientCoro::State::STOPPED: return "STOPPED";
        default: return "UNKNOWN";
    }
}

void WsClientCoro::set_state(State new_state) {
    State old_state = state_.exchange(new_state, std::memory_order_acq_rel);
    if (old_state != new_state) {
        LOG_DEBUG("{}: State {} -> {}", name_,
                  state_to_string(old_state), state_to_string(new_state));
    }
}

std::optional<WsClientCoro::UrlComponents> WsClientCoro::parse_url(const std::string& url) {
    // Pattern: wss?://host[:port][/path]
    std::regex url_regex(R"(^(wss?)://([^:/]+)(?::(\d+))?(/.*)?$)");
    std::smatch match;

    if (!std::regex_match(url, match, url_regex)) {
        return std::nullopt;
    }

    UrlComponents parts;
    parts.use_ssl = (match[1].str() == "wss");
    parts.host = match[2].str();
    parts.port = match[3].matched ? match[3].str() : (parts.use_ssl ? "443" : "80");
    parts.path = match[4].matched ? match[4].str() : "/";

    return parts;
}

void WsClientCoro::enqueue_send(std::vector<uint8_t> data, bool is_text) {
    net::post(ioc_, [self = shared_from_this(), data = std::move(data), is_text]() mutable {
        if (self->state() == State::CONNECTED) {
            self->write_queue_.push({std::move(data), is_text});
            self->write_signal_.cancel();
        }
    });
}

net::awaitable<void> WsClientCoro::run_connection() {
    while (!shutdown_.load(std::memory_order_acquire)) {
        std::string disconnect_reason = "unknown";

        try {
            // Connect
            co_await do_connect();

            // Authenticate
            co_await do_authenticate();

            set_state(State::CONNECTED);
            connected_at_ = std::chrono::steady_clock::now();
            reset_reconnect_delay();

            // Notify subclass
            co_await on_connected();

            // Run reader, writer, and heartbeat concurrently
            co_await (reader() || writer() || heartbeat());

            disconnect_reason = "session ended";

        } catch (const boost::system::system_error& e) {
            if (e.code() == websocket::error::closed) {
                disconnect_reason = "peer closed";
            } else if (e.code() == net::error::operation_aborted) {
                disconnect_reason = "operation aborted";
            } else {
                disconnect_reason = e.what();
            }
            LOG_WARN("{}: Connection error: {}", name_, disconnect_reason);
        } catch (const std::exception& e) {
            disconnect_reason = e.what();
            LOG_ERROR("{}: Exception: {}", name_, e.what());
        }

        // Cleanup current connection
        wss_.reset();
        ws_.reset();

        // Notify subclass
        try {
            co_await on_disconnected(disconnect_reason);
        } catch (...) {}

        // Check if we should reconnect
        if (shutdown_.load(std::memory_order_acquire)) {
            break;
        }

        set_state(State::RECONNECTING);
        reconnect_count_.fetch_add(1, std::memory_order_relaxed);

        co_await wait_for_reconnect();
    }

    set_state(State::STOPPED);
}

net::awaitable<void> WsClientCoro::do_connect() {
    set_state(State::CONNECTING);

    // Resolve hostname
    tcp::resolver resolver(ioc_);
    auto endpoints = co_await resolver.async_resolve(
        url_parts_.host, url_parts_.port, net::use_awaitable);

    if (url_parts_.use_ssl) {
        // SSL connection
        wss_ = std::make_unique<WssStream>(ioc_, ssl_ctx_);

        // Set SNI hostname
        if (!SSL_set_tlsext_host_name(wss_->next_layer().native_handle(),
                                       url_parts_.host.c_str())) {
            throw boost::system::system_error(
                boost::system::error_code(
                    static_cast<int>(::ERR_get_error()),
                    net::error::get_ssl_category()));
        }

        // Connect TCP
        co_await net::async_connect(
            beast::get_lowest_layer(*wss_), endpoints, net::use_awaitable);

        // SSL handshake
        co_await wss_->next_layer().async_handshake(
            ssl::stream_base::client, net::use_awaitable);

        // WebSocket handshake
        wss_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        wss_->set_option(websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(boost::beast::http::field::user_agent, "EdgeLink/1.0");
        }));

        co_await wss_->async_handshake(url_parts_.host, url_parts_.path, net::use_awaitable);

    } else {
        // Plain WebSocket
        ws_ = std::make_unique<WsStream>(ioc_);

        // Connect TCP
        co_await net::async_connect(
            beast::get_lowest_layer(*ws_), endpoints, net::use_awaitable);

        // WebSocket handshake
        ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws_->set_option(websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(boost::beast::http::field::user_agent, "EdgeLink/1.0");
        }));

        co_await ws_->async_handshake(url_parts_.host, url_parts_.path, net::use_awaitable);
    }

    LOG_INFO("{}: Connected to {}", name_, url_);
}

net::awaitable<void> WsClientCoro::do_authenticate() {
    set_state(State::AUTHENTICATING);

    // Get auth frame from subclass
    auto auth_frame_opt = co_await create_auth_frame();

    if (!auth_frame_opt) {
        // No authentication needed
        co_return;
    }

    // Send auth frame
    auto auth_data = auth_frame_opt->serialize();

    if (wss_) {
        wss_->binary(true);
        co_await wss_->async_write(net::buffer(auth_data), net::use_awaitable);
    } else {
        ws_->binary(true);
        co_await ws_->async_write(net::buffer(auth_data), net::use_awaitable);
    }

    // Wait for auth response
    beast::flat_buffer buffer;

    if (wss_) {
        co_await wss_->async_read(buffer, net::use_awaitable);
    } else {
        co_await ws_->async_read(buffer, net::use_awaitable);
    }

    // Parse response
    auto data = static_cast<const uint8_t*>(buffer.data().data());
    std::span<const uint8_t> span(data, buffer.size());

    auto response_frame = wire::Frame::deserialize(span);
    if (!response_frame) {
        throw std::runtime_error("Invalid auth response frame");
    }

    // Let subclass validate
    bool auth_ok = co_await handle_auth_response(*response_frame);
    if (!auth_ok) {
        throw std::runtime_error("Authentication failed");
    }

    LOG_INFO("{}: Authenticated", name_);
}

net::awaitable<void> WsClientCoro::reader() {
    beast::flat_buffer buffer;

    while (state() == State::CONNECTED && !shutdown_.load(std::memory_order_acquire)) {
        size_t bytes = 0;

        if (wss_) {
            bytes = co_await wss_->async_read(buffer, net::use_awaitable);
        } else {
            bytes = co_await ws_->async_read(buffer, net::use_awaitable);
        }

        bytes_received_.fetch_add(bytes, std::memory_order_relaxed);

        if (bytes > 0) {
            auto data = static_cast<const uint8_t*>(buffer.data().data());
            std::span<const uint8_t> span(data, buffer.size());

            auto frame_opt = wire::Frame::deserialize(span);
            if (frame_opt) {
                frames_received_.fetch_add(1, std::memory_order_relaxed);

                LOG_TRACE("{}: RX frame type={} ({}) size={} flags=0x{:02x}",
                          name_, static_cast<int>(frame_opt->header.type),
                          wire::message_type_to_string(frame_opt->header.type),
                          frame_opt->payload.size(), frame_opt->header.flags);

                // Handle pong specially for RTT measurement
                if (frame_opt->header.type == wire::MessageType::PONG) {
                    last_pong_received_ = std::chrono::steady_clock::now();
                    missed_pongs_.store(0, std::memory_order_relaxed);

                    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                        last_pong_received_ - last_ping_sent_);
                    last_rtt_ms_.store(rtt.count(), std::memory_order_relaxed);
                }

                co_await process_frame(*frame_opt);
            }

            buffer.consume(buffer.size());
        }
    }
}

net::awaitable<void> WsClientCoro::writer() {
    while (state() == State::CONNECTED && !shutdown_.load(std::memory_order_acquire)) {
        // Wait for data
        while (write_queue_.empty() && state() == State::CONNECTED &&
               !shutdown_.load(std::memory_order_acquire)) {
            write_signal_.expires_after(std::chrono::seconds(30));

            boost::system::error_code ec;
            co_await write_signal_.async_wait(
                net::redirect_error(net::use_awaitable, ec));
        }

        // Send all queued data
        while (!write_queue_.empty() && state() == State::CONNECTED) {
            auto item = std::move(write_queue_.front());
            write_queue_.pop();

            if (wss_) {
                wss_->binary(!item.is_text);
                co_await wss_->async_write(net::buffer(item.data), net::use_awaitable);
            } else {
                ws_->binary(!item.is_text);
                co_await ws_->async_write(net::buffer(item.data), net::use_awaitable);
            }

            bytes_sent_.fetch_add(item.data.size(), std::memory_order_relaxed);
            frames_sent_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

net::awaitable<void> WsClientCoro::heartbeat() {
    net::steady_timer timer(ioc_);

    while (state() == State::CONNECTED && !shutdown_.load(std::memory_order_acquire)) {
        timer.expires_after(kHeartbeatInterval);

        boost::system::error_code ec;
        co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

        if (ec || state() != State::CONNECTED) {
            break;
        }

        // Check for missed pongs
        if (missed_pongs_.fetch_add(1, std::memory_order_relaxed) >= kMaxMissedPongs) {
            LOG_WARN("{}: Too many missed pongs, reconnecting", name_);
            break;
        }

        // Send ping
        wire::Frame ping_frame;
        ping_frame.header.type = wire::MessageType::PING;
        ping_frame.header.length = 0;

        auto ping_data = ping_frame.serialize();
        last_ping_sent_ = std::chrono::steady_clock::now();

        if (wss_) {
            wss_->binary(true);
            co_await wss_->async_write(net::buffer(ping_data), net::use_awaitable);
        } else {
            ws_->binary(true);
            co_await ws_->async_write(net::buffer(ping_data), net::use_awaitable);
        }
    }
}

net::awaitable<void> WsClientCoro::wait_for_reconnect() {
    LOG_INFO("{}: Reconnecting in {}ms", name_, reconnect_delay_.count());

    net::steady_timer timer(ioc_);
    timer.expires_after(reconnect_delay_);

    boost::system::error_code ec;
    co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));

    // Exponential backoff
    reconnect_delay_ = std::min(reconnect_delay_ * 2, kMaxReconnectDelay);
}

void WsClientCoro::reset_reconnect_delay() {
    reconnect_delay_ = kBaseReconnectDelay;
    missed_pongs_.store(0, std::memory_order_relaxed);
}

} // namespace edgelink

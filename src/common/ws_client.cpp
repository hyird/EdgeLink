#include "common/ws_client.hpp"
#include "common/log.hpp"

namespace edgelink {

// ============================================================================
// WsClient Implementation
// ============================================================================

WsClient::WsClient(net::io_context& ioc, const std::string& url, const std::string& name)
    : ioc_(ioc)
    , url_(url)
    , name_(name)
    , resolver_(ioc)
    , heartbeat_timer_(ioc)
    , reconnect_timer_(ioc)
{
    auto parts = WsUrlComponents::parse(url);
    if (parts) {
        url_parts_ = *parts;
    } else {
        LOG_ERROR("{}: Invalid URL: {}", name_, url);
    }
}

WsClient::~WsClient() {
    disconnect();
}

void WsClient::set_callbacks(WsClientCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void WsClient::connect() {
    if (shutdown_) {
        shutdown_ = false;
    }

    if (state_ != State::INIT && state_ != State::DISABLED && state_ != State::RECONNECTING) {
        return;
    }

    if (url_parts_.host.empty()) {
        LOG_ERROR("{}: Cannot connect - invalid URL", name_);
        return;
    }

    transition_to(State::CONNECTING);
    do_resolve();
}

void WsClient::disconnect() {
    shutdown_ = true;
    heartbeat_timer_.cancel();
    reconnect_timer_.cancel();
    close_streams();
    transition_to(State::DISABLED);
}

void WsClient::enable() {
    if (shutdown_) {
        shutdown_ = false;
    }
    if (state_ == State::DISABLED) {
        transition_to(State::INIT);
        connect();
    }
}

void WsClient::disable() {
    disconnect();
}

void WsClient::transition_to(State new_state) {
    State old_state = state_.exchange(new_state);
    if (old_state != new_state) {
        LOG_DEBUG("{}: State {} -> {}", name_,
                 ws_client_state_to_string(old_state),
                 ws_client_state_to_string(new_state));
        if (callbacks_.on_state_changed) {
            callbacks_.on_state_changed(new_state);
        }
    }
}

void WsClient::close_streams() {
    beast::error_code ec;
    if (wss_) {
        beast::get_lowest_layer(*wss_).close(ec);
        wss_.reset();
    }
    if (ws_) {
        beast::get_lowest_layer(*ws_).close(ec);
        ws_.reset();
    }
}

void WsClient::do_resolve() {
    LOG_DEBUG("{}: Resolving {}:{}", name_, url_parts_.host, url_parts_.port);

    resolver_.async_resolve(
        url_parts_.host,
        url_parts_.port,
        [self = shared_from_this()](beast::error_code ec, tcp::resolver::results_type results) {
            if (ec || self->shutdown_) {
                LOG_ERROR("{}: DNS resolve failed: {}", self->name_, ec.message());
                self->schedule_reconnect();
                return;
            }
            self->do_connect(results);
        });
}

void WsClient::do_connect(tcp::resolver::results_type results) {
    if (url_parts_.use_ssl) {
        wss_ = std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(ioc_, ssl_ctx_);

        // Set SNI hostname
        if (!SSL_set_tlsext_host_name(wss_->next_layer().native_handle(),
                                      url_parts_.host.c_str())) {
            LOG_ERROR("{}: Failed to set SNI hostname", name_);
            schedule_reconnect();
            return;
        }

        net::async_connect(
            beast::get_lowest_layer(*wss_),
            results,
            [self = shared_from_this()](beast::error_code ec, const tcp::endpoint&) {
                if (ec || self->shutdown_) {
                    LOG_ERROR("{}: TCP connect failed: {}", self->name_, ec.message());
                    self->schedule_reconnect();
                    return;
                }
                self->do_ssl_handshake();
            });
    } else {
        ws_ = std::make_unique<websocket::stream<tcp::socket>>(ioc_);

        net::async_connect(
            beast::get_lowest_layer(*ws_),
            results,
            [self = shared_from_this()](beast::error_code ec, const tcp::endpoint&) {
                if (ec || self->shutdown_) {
                    LOG_ERROR("{}: TCP connect failed: {}", self->name_, ec.message());
                    self->schedule_reconnect();
                    return;
                }
                self->do_ws_handshake();
            });
    }
}

void WsClient::do_ssl_handshake() {
    wss_->next_layer().async_handshake(
        ssl::stream_base::client,
        [self = shared_from_this()](beast::error_code ec) {
            if (ec || self->shutdown_) {
                LOG_ERROR("{}: SSL handshake failed: {}", self->name_, ec.message());
                self->schedule_reconnect();
                return;
            }
            self->do_ws_handshake();
        });
}

void WsClient::do_ws_handshake() {
    auto do_handshake = [this](auto& stream) {
        stream.set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        stream.set_option(websocket::stream_base::decorator(
            [this](websocket::request_type& req) {
                req.set(beast::http::field::user_agent, "EdgeLink/1.0");
            }));

        stream.async_handshake(url_parts_.host, url_parts_.path,
            [self = shared_from_this()](beast::error_code ec) {
                if (ec || self->shutdown_) {
                    LOG_ERROR("{}: WS handshake failed: {}", self->name_, ec.message());
                    self->schedule_reconnect();
                    return;
                }

                LOG_INFO("{}: WebSocket connected to {}", self->name_, self->url_);
                self->transition_to(State::AUTHENTICATING);
                self->do_authenticate();
            });
    };

    if (url_parts_.use_ssl && wss_) {
        do_handshake(*wss_);
    } else if (ws_) {
        do_handshake(*ws_);
    }
}

void WsClient::do_authenticate() {
    // Default implementation: if callback provides auth frame, send it
    if (callbacks_.create_auth_frame) {
        auto frame = callbacks_.create_auth_frame();
        send_frame(frame);
        do_read();  // Wait for auth response
    } else {
        // No auth needed
        auth_complete();
    }
}

void WsClient::auth_complete() {
    transition_to(State::CONNECTED);
    reconnect_attempts_ = 0;
    missed_pongs_ = 0;

    if (callbacks_.on_connected) {
        callbacks_.on_connected();
    }

    start_heartbeat();
    do_read();
}

void WsClient::auth_failed(const std::string& reason) {
    LOG_ERROR("{}: Authentication failed: {}", name_, reason);
    schedule_reconnect();
}

void WsClient::do_read() {
    auto do_async_read = [this](auto& stream) {
        stream.async_read(
            read_buffer_,
            [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
                if (ec) {
                    if (ec != websocket::error::closed && ec != net::error::operation_aborted) {
                        LOG_WARN("{}: Read error: {}", self->name_, ec.message());
                    }
                    if (!self->shutdown_) {
                        if (self->callbacks_.on_disconnected) {
                            self->callbacks_.on_disconnected(ec.message());
                        }
                        self->schedule_reconnect();
                    }
                    return;
                }

                self->stats_.bytes_received += bytes_transferred;

                // Parse frame
                auto data = static_cast<const uint8_t*>(self->read_buffer_.data().data());
                std::span<const uint8_t> span(data, self->read_buffer_.size());

                auto frame_result = wire::Frame::deserialize(span);
                self->read_buffer_.consume(self->read_buffer_.size());

                if (frame_result) {
                    self->stats_.frames_received++;
                    self->process_frame(*frame_result);
                } else {
                    LOG_WARN("{}: Invalid frame received", self->name_);
                }

                // Continue reading if still connected
                if (!self->shutdown_ && self->state_ == State::CONNECTED) {
                    self->do_read();
                }
            });
    };

    if (url_parts_.use_ssl && wss_) {
        do_async_read(*wss_);
    } else if (ws_) {
        do_async_read(*ws_);
    }
}

void WsClient::process_frame(const wire::Frame& frame) {
    switch (frame.header.type) {
        case wire::MessageType::PONG:
            last_pong_ = std::chrono::steady_clock::now();
            missed_pongs_ = 0;
            break;

        case wire::MessageType::PING: {
            // Respond with PONG
            auto pong = wire::Frame::create(wire::MessageType::PONG, frame.payload);
            send_frame(pong);
            break;
        }

        default:
            // Pass to callback
            if (callbacks_.on_frame_received) {
                callbacks_.on_frame_received(frame);
            }
            break;
    }
}

void WsClient::send_frame(const wire::Frame& frame) {
    auto data = frame.serialize();
    queue_write(std::move(data));
}

void WsClient::send_ping() {
    auto frame = wire::Frame::create(wire::MessageType::PING, {});
    send_frame(frame);
}

void WsClient::queue_write(std::vector<uint8_t> data) {
    std::lock_guard<std::mutex> lock(write_mutex_);

    if (writing_) {
        write_queue_.push(std::move(data));
        return;
    }

    writing_ = true;
    auto data_ptr = std::make_shared<std::vector<uint8_t>>(std::move(data));

    auto do_async_write = [this, data_ptr](auto& stream) {
        stream.binary(true);
        stream.async_write(
            net::buffer(*data_ptr),
            [self = shared_from_this(), data_ptr](beast::error_code ec, std::size_t bytes_transferred) {
                if (ec) {
                    LOG_WARN("{}: Write error: {}", self->name_, ec.message());
                    self->writing_ = false;
                    return;
                }

                self->stats_.bytes_sent += bytes_transferred;
                self->stats_.frames_sent++;
                self->do_write();
            });
    };

    if (url_parts_.use_ssl && wss_) {
        do_async_write(*wss_);
    } else if (ws_) {
        do_async_write(*ws_);
    }
}

void WsClient::do_write() {
    std::shared_ptr<std::vector<uint8_t>> data_ptr;
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (write_queue_.empty()) {
            writing_ = false;
            return;
        }
        data_ptr = std::make_shared<std::vector<uint8_t>>(std::move(write_queue_.front()));
        write_queue_.pop();
    }

    auto do_async_write = [this, data_ptr](auto& stream) {
        stream.async_write(
            net::buffer(*data_ptr),
            [self = shared_from_this(), data_ptr](beast::error_code ec, std::size_t bytes_transferred) {
                if (ec) {
                    LOG_WARN("{}: Write error: {}", self->name_, ec.message());
                    self->writing_ = false;
                    return;
                }

                self->stats_.bytes_sent += bytes_transferred;
                self->stats_.frames_sent++;
                self->do_write();
            });
    };

    if (url_parts_.use_ssl && wss_) {
        do_async_write(*wss_);
    } else if (ws_) {
        do_async_write(*ws_);
    }
}

void WsClient::start_heartbeat() {
    if (shutdown_) return;

    heartbeat_timer_.expires_after(std::chrono::seconds(HEARTBEAT_INTERVAL_SEC));
    heartbeat_timer_.async_wait([self = shared_from_this()](beast::error_code ec) {
        if (ec || self->shutdown_ || self->state_ != State::CONNECTED) {
            return;
        }

        // Check for missed pongs
        self->missed_pongs_++;
        if (self->missed_pongs_ > MAX_MISSED_PONGS) {
            LOG_WARN("{}: Too many missed pongs, reconnecting", self->name_);
            if (self->callbacks_.on_disconnected) {
                self->callbacks_.on_disconnected("heartbeat timeout");
            }
            self->schedule_reconnect();
            return;
        }

        self->send_ping();
        self->start_heartbeat();
    });
}

void WsClient::schedule_reconnect() {
    if (shutdown_) return;

    close_streams();
    transition_to(State::RECONNECTING);

    reconnect_attempts_++;
    if (reconnect_attempts_ > MAX_RECONNECT_ATTEMPTS) {
        LOG_ERROR("{}: Max reconnect attempts exceeded", name_);
        transition_to(State::DISABLED);
        return;
    }

    // Exponential backoff
    uint32_t delay_ms = std::min(BASE_RECONNECT_DELAY_MS * (1u << reconnect_attempts_),
                                  MAX_RECONNECT_DELAY_MS);

    LOG_INFO("{}: Reconnecting in {}ms (attempt {})", name_, delay_ms, reconnect_attempts_);

    reconnect_timer_.expires_after(std::chrono::milliseconds(delay_ms));
    reconnect_timer_.async_wait([self = shared_from_this()](beast::error_code ec) {
        if (ec || self->shutdown_) {
            return;
        }
        self->connect();
    });
}

} // namespace edgelink

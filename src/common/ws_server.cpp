#include "common/ws_server.hpp"
#include "common/log.hpp"

namespace edgelink {

// Static member initialization
std::atomic<uint64_t> WsServerSession::next_session_id_{1};

// ============================================================================
// WsServerSession Implementation
// ============================================================================

WsServerSession::WsServerSession(net::io_context& ioc, tcp::socket socket, bool use_ssl,
                                 ssl::context* ssl_ctx, const std::string& name)
    : ioc_(ioc)
    , name_(name)
    , session_id_(next_session_id_++)
    , use_ssl_(use_ssl)
    , ssl_ctx_(ssl_ctx)
    , socket_(std::move(socket))
{}

WsServerSession::~WsServerSession() {
    close("destructor");
}

void WsServerSession::set_callbacks(WsSessionCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void WsServerSession::start() {
    if (use_ssl_ && ssl_ctx_) {
        do_ssl_handshake();
    } else {
        transition_to(State::HTTP_READING);
        do_read_http();
    }
}

void WsServerSession::close(const std::string& reason) {
    if (closed_.exchange(true)) {
        return;  // Already closed
    }

    beast::error_code ec;

    if (wss_ && wss_->is_open()) {
        wss_->close(websocket::close_code::normal, ec);
    }
    if (ws_ && ws_->is_open()) {
        ws_->close(websocket::close_code::normal, ec);
    }
    if (ssl_stream_) {
        beast::get_lowest_layer(*ssl_stream_).close(ec);
    }
    if (socket_.is_open()) {
        socket_.close(ec);
    }

    transition_to(State::CLOSING);

    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected(reason);
    }
}

void WsServerSession::transition_to(State new_state) {
    state_.store(new_state);
}

void WsServerSession::do_ssl_handshake() {
    ssl_stream_ = std::make_unique<ssl::stream<tcp::socket>>(std::move(socket_), *ssl_ctx_);

    ssl_stream_->async_handshake(
        ssl::stream_base::server,
        [self = shared_from_this()](beast::error_code ec) {
            if (ec) {
                LOG_WARN("{}: SSL handshake failed: {}", self->name_, ec.message());
                self->close("ssl_handshake_failed");
                return;
            }
            self->transition_to(State::HTTP_READING);
            self->do_read_http();
        });
}

void WsServerSession::do_read_http() {
    auto do_read = [this](auto& stream) {
        http::async_read(
            stream,
            http_buffer_,
            http_request_,
            [self = shared_from_this()](beast::error_code ec, std::size_t) {
                if (ec) {
                    LOG_WARN("{}: HTTP read failed: {}", self->name_, ec.message());
                    self->close("http_read_failed");
                    return;
                }

                // Check if callback wants to handle/reject the request
                if (self->callbacks_.on_http_request) {
                    if (!self->callbacks_.on_http_request(self->http_request_)) {
                        self->close("http_rejected");
                        return;
                    }
                }

                // Check if this is a WebSocket upgrade request
                if (!websocket::is_upgrade(self->http_request_)) {
                    LOG_WARN("{}: Not a WebSocket upgrade request", self->name_);
                    self->close("not_websocket");
                    return;
                }

                self->transition_to(State::UPGRADING);
                self->do_ws_accept();
            });
    };

    if (use_ssl_ && ssl_stream_) {
        do_read(*ssl_stream_);
    } else {
        do_read(socket_);
    }
}

void WsServerSession::do_ws_accept() {
    auto do_accept = [this](auto& stream) {
        stream.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        stream.set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server, "EdgeLink/1.0");
            }));

        stream.async_accept(
            http_request_,
            [self = shared_from_this()](beast::error_code ec) {
                if (ec) {
                    LOG_WARN("{}: WS accept failed: {}", self->name_, ec.message());
                    self->close("ws_accept_failed");
                    return;
                }

                LOG_DEBUG("{}: WebSocket connection established", self->name_);
                self->transition_to(State::AUTHENTICATING);
                self->do_authenticate();
            });
    };

    if (use_ssl_ && ssl_stream_) {
        wss_ = std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(std::move(*ssl_stream_));
        do_accept(*wss_);
    } else {
        ws_ = std::make_unique<websocket::stream<tcp::socket>>(std::move(socket_));
        do_accept(*ws_);
    }
}

void WsServerSession::do_authenticate() {
    // Default: no auth required, directly connected
    auth_complete();
}

void WsServerSession::auth_complete() {
    transition_to(State::CONNECTED);

    if (callbacks_.on_connected) {
        callbacks_.on_connected();
    }

    do_read();
}

void WsServerSession::auth_failed(const std::string& reason) {
    LOG_WARN("{}: Auth failed: {}", name_, reason);
    close("auth_failed: " + reason);
}

void WsServerSession::do_read() {
    if (closed_) return;

    auto do_async_read = [this](auto& stream) {
        stream.async_read(
            read_buffer_,
            [self = shared_from_this()](beast::error_code ec, std::size_t bytes_transferred) {
                if (ec) {
                    if (ec != websocket::error::closed && ec != net::error::operation_aborted) {
                        LOG_WARN("{}: Read error: {}", self->name_, ec.message());
                    }
                    self->close(ec.message());
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

                // Continue reading
                if (!self->closed_ && self->state_ == State::CONNECTED) {
                    self->do_read();
                }
            });
    };

    if (use_ssl_ && wss_) {
        do_async_read(*wss_);
    } else if (ws_) {
        do_async_read(*ws_);
    }
}

void WsServerSession::process_frame(const wire::Frame& frame) {
    // Handle ping/pong at session level
    switch (frame.header.type) {
        case wire::MessageType::PING: {
            auto pong = wire::Frame::create(wire::MessageType::PONG, frame.payload);
            send_frame(pong);
            break;
        }

        case wire::MessageType::PONG:
            // Ignore pong responses
            break;

        default:
            if (callbacks_.on_frame_received) {
                callbacks_.on_frame_received(frame);
            }
            break;
    }
}

void WsServerSession::send_frame(const wire::Frame& frame) {
    auto data = frame.serialize();
    queue_write(std::move(data));
}

void WsServerSession::queue_write(std::vector<uint8_t> data) {
    if (closed_) return;

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

    if (use_ssl_ && wss_) {
        do_async_write(*wss_);
    } else if (ws_) {
        do_async_write(*ws_);
    }
}

void WsServerSession::do_write() {
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

    if (use_ssl_ && wss_) {
        do_async_write(*wss_);
    } else if (ws_) {
        do_async_write(*ws_);
    }
}

// ============================================================================
// WsServer Implementation
// ============================================================================

WsServer::WsServer(net::io_context& ioc, const std::string& address, uint16_t port,
                   bool use_ssl, const std::string& name)
    : ioc_(ioc)
    , use_ssl_(use_ssl)
    , address_(address)
    , port_(port)
    , name_(name)
{}

WsServer::~WsServer() {
    stop();
}

void WsServer::start() {
    if (running_.exchange(true)) {
        return;  // Already running
    }

    try {
        auto address = net::ip::make_address(address_);
        tcp::endpoint endpoint{address, port_};

        acceptor_ = std::make_unique<tcp::acceptor>(ioc_);
        acceptor_->open(endpoint.protocol());
        acceptor_->set_option(net::socket_base::reuse_address(true));
        acceptor_->bind(endpoint);
        acceptor_->listen(net::socket_base::max_listen_connections);

        LOG_INFO("{}: Listening on {}:{}", name_, address_, port_);
        do_accept();
    } catch (const std::exception& e) {
        LOG_ERROR("{}: Failed to start: {}", name_, e.what());
        running_ = false;
        throw;
    }
}

void WsServer::stop() {
    if (!running_.exchange(false)) {
        return;
    }

    if (acceptor_ && acceptor_->is_open()) {
        beast::error_code ec;
        acceptor_->close(ec);
    }

    LOG_INFO("{}: Stopped", name_);
}

void WsServer::do_accept() {
    if (!running_) return;

    acceptor_->async_accept(
        [this](beast::error_code ec, tcp::socket socket) {
            if (!ec) {
                stats_.connections_total++;
                stats_.connections_active++;

                auto session = create_session(std::move(socket));
                on_session_created(session);
                session->start();
            } else if (ec != net::error::operation_aborted) {
                LOG_WARN("{}: Accept error: {}", name_, ec.message());
            }

            if (running_) {
                do_accept();
            }
        });
}

std::shared_ptr<WsServerSession> WsServer::create_session(tcp::socket socket) {
    return std::make_shared<WsServerSession>(ioc_, std::move(socket), use_ssl_, ssl_ctx_, name_ + "-Session");
}

void WsServer::on_session_created(std::shared_ptr<WsServerSession> session) {
    // Override in derived class to handle new sessions
}

} // namespace edgelink

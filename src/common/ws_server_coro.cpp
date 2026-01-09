#include "ws_server_coro.hpp"
#include "log.hpp"

namespace edgelink {

WsServerCoro::WsServerCoro(IOContextPool& pool, const std::string& address, uint16_t port)
    : pool_(pool)
    , address_(address)
    , port_(port)
{}

WsServerCoro::~WsServerCoro() {
    stop();
}

void WsServerCoro::set_session_factory(SessionFactory factory) {
    session_factory_ = std::move(factory);
}

void WsServerCoro::enable_tls(const std::string& cert_path, const std::string& key_path) {
    try {
        ssl_ctx_.use_certificate_chain_file(cert_path);
        ssl_ctx_.use_private_key_file(key_path, ssl::context::pem);
        tls_enabled_ = true;
        LOG_INFO("WsServerCoro: TLS enabled");
    } catch (const std::exception& e) {
        LOG_ERROR("WsServerCoro: Failed to load TLS certificates: {}", e.what());
        throw;
    }
}

void WsServerCoro::start() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already running
    }

    try {
        // Create acceptor on thread 0's io_context
        auto& ioc = pool_.get_io_context(0);
        auto address = net::ip::make_address(address_);
        auto endpoint = tcp::endpoint{address, port_};

        acceptor_ = std::make_unique<tcp::acceptor>(ioc);
        acceptor_->open(endpoint.protocol());
        acceptor_->set_option(net::socket_base::reuse_address(true));
        acceptor_->bind(endpoint);
        acceptor_->listen(net::socket_base::max_listen_connections);

        // Start accept loop
        net::co_spawn(
            ioc,
            [this]() -> net::awaitable<void> {
                co_await accept_loop();
            },
            [](std::exception_ptr ep) {
                if (ep) {
                    try {
                        std::rethrow_exception(ep);
                    } catch (const std::exception& e) {
                        LOG_ERROR("WsServerCoro: Accept loop exception: {}", e.what());
                    }
                }
            });

        LOG_INFO("WsServerCoro: Listening on {}:{}", address_, port_);

    } catch (const std::exception& e) {
        running_.store(false, std::memory_order_release);
        LOG_ERROR("WsServerCoro: Failed to start: {}", e.what());
        throw;
    }
}

void WsServerCoro::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Not running
    }

    if (acceptor_ && acceptor_->is_open()) {
        beast::error_code ec;
        acceptor_->close(ec);
    }

    LOG_INFO("WsServerCoro: Stopped");
}

WsServerCoro::Stats WsServerCoro::get_stats() const {
    return {
        connections_accepted_.load(std::memory_order_relaxed),
        connections_rejected_.load(std::memory_order_relaxed),
        active_sessions_.load(std::memory_order_relaxed)
    };
}

std::shared_ptr<WsSessionCoro> WsServerCoro::create_session(
    net::io_context& ioc,
    tcp::socket socket,
    const std::string& path) {

    if (session_factory_) {
        return session_factory_(ioc, std::move(socket), path);
    }
    return nullptr;
}

net::awaitable<void> WsServerCoro::accept_loop() {
    while (running_.load(std::memory_order_acquire)) {
        try {
            // Get target thread via round-robin
            size_t target_thread = 0;
            auto& target_ioc = pool_.get_io_context();

            // Find which thread this io_context belongs to
            for (size_t i = 0; i < pool_.size(); ++i) {
                if (&pool_.get_io_context(i) == &target_ioc) {
                    target_thread = i;
                    break;
                }
            }

            // Accept a connection
            tcp::socket socket(target_ioc);
            co_await acceptor_->async_accept(socket, net::use_awaitable);

            connections_accepted_.fetch_add(1, std::memory_order_relaxed);

            LOG_DEBUG("WsServerCoro: Accepted connection from {} -> thread {}",
                      socket.remote_endpoint().address().to_string(), target_thread);

            // Handle connection on target thread
            net::post(target_ioc, [this, socket = std::move(socket), target_thread]() mutable {
                // This runs on the target thread
                net::co_spawn(
                    socket.get_executor(),
                    [this, socket = std::move(socket), target_thread]() mutable -> net::awaitable<void> {
                        co_await handle_connection(std::move(socket), target_thread);
                    },
                    [](std::exception_ptr ep) {
                        if (ep) {
                            try {
                                std::rethrow_exception(ep);
                            } catch (const std::exception& e) {
                                LOG_ERROR("WsServerCoro: Connection handler exception: {}", e.what());
                            }
                        }
                    });
            });

        } catch (const boost::system::system_error& e) {
            if (e.code() == net::error::operation_aborted) {
                break;  // Server stopping
            }
            LOG_WARN("WsServerCoro: Accept error: {}", e.what());
        }
    }
}

net::awaitable<void> WsServerCoro::handle_connection(tcp::socket socket, size_t target_thread) {
    try {
        // Read HTTP request to get the path
        beast::flat_buffer buffer;
        http::request<http::string_body> req;

        co_await http::async_read(socket, buffer, req, net::use_awaitable);

        // Check if this is a WebSocket upgrade
        if (!websocket::is_upgrade(req)) {
            // Send 404 for non-WebSocket requests
            http::response<http::string_body> res{http::status::not_found, req.version()};
            res.set(http::field::server, "EdgeLink/1.0");
            res.set(http::field::content_type, "text/plain");
            res.body() = "Not Found";
            res.prepare_payload();

            co_await http::async_write(socket, res, net::use_awaitable);
            co_return;
        }

        // Extract path (without query string)
        std::string target = std::string(req.target());
        std::string path = target;
        auto query_pos = target.find('?');
        if (query_pos != std::string::npos) {
            path = target.substr(0, query_pos);
        }

        // Create session via factory
        auto& target_ioc = pool_.get_io_context(target_thread);
        auto session = create_session(target_ioc, std::move(socket), path);

        if (!session) {
            LOG_WARN("WsServerCoro: No session created for path: {}", path);
            connections_rejected_.fetch_add(1, std::memory_order_relaxed);
            co_return;
        }

        active_sessions_.fetch_add(1, std::memory_order_relaxed);

        // Start the session
        session->start();

        // Note: Session runs independently, we don't wait for it here

    } catch (const std::exception& e) {
        LOG_WARN("WsServerCoro: Connection handling error: {}", e.what());
        connections_rejected_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace edgelink

#include "controller/server.hpp"
#include "controller/session.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>

namespace edgelink::controller {

// ============================================================================
// Server implementation
// ============================================================================

Server::Server(asio::io_context& ioc, ssl::context& ssl_ctx,
               SessionManager& manager, const ServerConfig& config)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , manager_(manager)
    , config_(config)
    , acceptor_(ioc) {}

asio::awaitable<void> Server::run() {
    // Setup acceptor
    tcp::endpoint endpoint(asio::ip::make_address(config_.bind_address), config_.port);

    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(asio::socket_base::reuse_address(true));
    acceptor_.bind(endpoint);
    acceptor_.listen(asio::socket_base::max_listen_connections);

    running_ = true;
    spdlog::info("Server listening on {}:{}", config_.bind_address, config_.port);

    co_await accept_loop();
}

void Server::stop() {
    running_ = false;
    acceptor_.close();
}

asio::awaitable<void> Server::accept_loop() {
    while (running_) {
        try {
            tcp::socket socket = co_await acceptor_.async_accept(asio::use_awaitable);

            // Spawn connection handler
            asio::co_spawn(ioc_, handle_connection(std::move(socket)), asio::detached);

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                spdlog::error("Accept error: {}", e.what());
            }
        }
    }
}

asio::awaitable<void> Server::handle_connection(tcp::socket socket) {
    try {
        // Create SSL stream
        beast::ssl_stream<beast::tcp_stream> stream(std::move(socket), ssl_ctx_);

        // Perform SSL handshake
        co_await stream.async_handshake(ssl::stream_base::server, asio::use_awaitable);

        // Create HTTP session to handle upgrade
        auto session = std::make_shared<HttpSession>(std::move(stream), manager_);
        co_await session->run();

    } catch (const boost::system::system_error& e) {
        spdlog::debug("Connection error: {}", e.what());
    }
}

// ============================================================================
// HttpSession implementation
// ============================================================================

HttpSession::HttpSession(beast::ssl_stream<beast::tcp_stream>&& stream,
                         SessionManager& manager)
    : stream_(std::move(stream))
    , manager_(manager) {}

asio::awaitable<void> HttpSession::run() {
    // Set timeout
    beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

    // Read HTTP request
    http::request<http::string_body> req;
    co_await http::async_read(stream_, buffer_, req, asio::use_awaitable);

    // Check if this is a WebSocket upgrade
    if (!websocket::is_upgrade(req)) {
        // Return 400 Bad Request for non-WebSocket requests
        http::response<http::string_body> res{http::status::bad_request, req.version()};
        res.set(http::field::server, "EdgeLink Controller");
        res.set(http::field::content_type, "text/plain");
        res.body() = "WebSocket upgrade required";
        res.prepare_payload();

        co_await http::async_write(stream_, res, asio::use_awaitable);
        co_return;
    }

    // Get target path
    std::string target(req.target());
    spdlog::debug("WebSocket upgrade request for: {}", target);

    // Create WebSocket stream
    WsStream ws(std::move(stream_));

    // Set WebSocket options
    ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    ws.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server, "EdgeLink Controller");
        }));

    // Accept WebSocket handshake
    co_await ws.async_accept(req, asio::use_awaitable);

    // Route based on target path
    if (target == "/api/v1/control" || target == "/api/v1/control/") {
        // Control channel
        spdlog::info("New control channel connection");
        co_await ControlSession::start(std::move(ws), manager_);

    } else if (target == "/api/v1/relay" || target == "/api/v1/relay/") {
        // Relay channel (built-in relay)
        spdlog::info("New relay channel connection");
        co_await RelaySession::start(std::move(ws), manager_);

    } else {
        // Unknown endpoint
        spdlog::warn("Unknown WebSocket endpoint: {}", target);
        co_await ws.async_close(websocket::close_code::policy_error, asio::use_awaitable);
    }
}

// ============================================================================
// SSL utilities
// ============================================================================

namespace ssl_util {

ssl::context create_ssl_context(const std::string& cert_file,
                                const std::string& key_file) {
    ssl::context ctx(ssl::context::tlsv12);

    ctx.set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2 |
        ssl::context::no_sslv3 |
        ssl::context::single_dh_use);

    ctx.use_certificate_chain_file(cert_file);
    ctx.use_private_key_file(key_file, ssl::context::pem);

    return ctx;
}

ssl::context create_self_signed_context() {
    ssl::context ctx(ssl::context::tlsv12);

    ctx.set_options(
        ssl::context::default_workarounds |
        ssl::context::no_sslv2 |
        ssl::context::no_sslv3 |
        ssl::context::single_dh_use);

    // Self-signed certificate for testing (generated at build time or embedded)
    // In production, use proper certificates
    static const char cert[] = R"(-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpKgcKJrMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5wN8PDxtJ0MmGMLjC+kGM
4ExMGIvKVMaJ5bYhLwMKcYVbYKGGiGpqQ4fVmL7F/Qz8Z6yCFQvZb7N2M7YQnyzR
AgMBAAGjUzBRMB0GA1UdDgQWBBQzJ9Q/+Fn0/1B5yzfZnM7J8W/C7TAfBgNVHSME
GDAWgBQzJ9Q/+Fn0/1B5yzfZnM7J8W/C7TAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EA0KgkJS9V6IVrB1nk8pP0W6cE7P8M7+mhPLIVQP7Qf/0f8Qug
jF6vK8QF+DQvC9x8R8d3K6T0m4TGN1GQXQZTAQ==
-----END CERTIFICATE-----)";

    static const char key[] = R"(-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAucDfDw8bSdDJhjC4
wvpBjOBMTBiLylTGieW2IS8DCnGFW2ChhohqakOH1Zi+xf0M/GesghUL2W+zdjO2
EJ8s0QIDAQABAkBIWbIqVR+DS6iSMqyPGdN0xXgQkzlQqKM0rEoCDf7Q7j8NFGZ8
hvqBNr+XVQm5D7N8QfhLXJ8d8XMPGH8Y9N4BAiEA4kBQnDvBLqXP3zLl7BfJz3pF
yYJF4pjq6l0C8N1RWmECIQDSgYnFzhGz6W9C7L7d6Nm7N8QVx7c8F7fC5R7VY2rh
0QIgS1QnXQx/6CUc6D3Z5f8dJwGzQ7K3z7N8QVx7c8F7fCECIQCE8Q7c8F7fC5R7
VY2rh0S1QnXQx/6CUc6D3Z5f8dJwGzQRAiB3z7N8QVx7c8F7fC5R7VY2rh0S1QnX
Qx/6CUc6D3Z5f8dJwA==
-----END PRIVATE KEY-----)";

    ctx.use_certificate_chain(asio::buffer(cert, sizeof(cert)));
    ctx.use_private_key(asio::buffer(key, sizeof(key)), ssl::context::pem);

    return ctx;
}

} // namespace ssl_util

} // namespace edgelink::controller

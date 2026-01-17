#include "controller/server.hpp"
#include "controller/session.hpp"
#include "common/logger.hpp"
#include <fstream>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace edgelink::controller {

namespace {
    auto& log() { return Logger::get("controller.server"); }

    // Health check response helper
    template<typename Stream>
    asio::awaitable<void> send_health_response(
        Stream& stream,
        http::request<http::string_body>& req,
        http::status status,
        const std::string& body)
    {
        http::response<http::string_body> res{status, req.version()};
        res.set(http::field::server, "EdgeLink Controller");
        res.set(http::field::content_type, "application/json");
        res.body() = body;
        res.prepare_payload();
        co_await http::async_write(stream, res, asio::use_awaitable);
    }
}

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
    log().info("Server listening on {}:{} (TLS: {})",
                 config_.bind_address, config_.port, config_.tls ? "enabled" : "disabled");

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
                log().error("Accept error: {}", e.what());
            }
        }
    }
}

asio::awaitable<void> Server::handle_connection(tcp::socket socket) {
    if (config_.tls) {
        co_await handle_tls_connection(std::move(socket));
    } else {
        co_await handle_plain_connection(std::move(socket));
    }
}

asio::awaitable<void> Server::handle_tls_connection(tcp::socket socket) {
    try {
        // Create SSL stream
        beast::ssl_stream<beast::tcp_stream> stream(std::move(socket), ssl_ctx_);

        // Perform SSL handshake
        co_await stream.async_handshake(ssl::stream_base::server, asio::use_awaitable);

        // Create HTTP session to handle upgrade
        auto session = std::make_shared<HttpSession>(std::move(stream), manager_);
        co_await session->run();

    } catch (const boost::system::system_error& e) {
        log().debug("TLS connection error: {}", e.what());
    }
}

asio::awaitable<void> Server::handle_plain_connection(tcp::socket socket) {
    try {
        // Create plain TCP stream
        beast::tcp_stream stream(std::move(socket));

        // Create plain HTTP session to handle upgrade
        auto session = std::make_shared<PlainHttpSession>(std::move(stream), manager_);
        co_await session->run();

    } catch (const boost::system::system_error& e) {
        log().debug("Plain connection error: {}", e.what());
    }
}

// ============================================================================
// HttpSession implementation (TLS)
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

    // Get target path for routing
    std::string target(req.target());

    // Health check endpoints (non-WebSocket HTTP)
    if (target == "/health" || target == "/health/") {
        co_await send_health_response(stream_, req, http::status::ok,
            R"({"status":"healthy","service":"edgelink-controller"})");
        co_return;
    }
    if (target == "/health/live" || target == "/health/live/") {
        co_await send_health_response(stream_, req, http::status::ok,
            R"({"status":"live"})");
        co_return;
    }
    if (target == "/health/ready" || target == "/health/ready/") {
        // Check database connectivity
        if (manager_.database().is_open()) {
            co_await send_health_response(stream_, req, http::status::ok,
                R"({"status":"ready"})");
        } else {
            co_await send_health_response(stream_, req, http::status::service_unavailable,
                R"({"status":"not_ready","reason":"database not connected"})");
        }
        co_return;
    }

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

    log().debug("WebSocket upgrade request for: {}", target);

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

    // Disable the HTTP timeout on the underlying stream - WebSocket has its own timeout
    beast::get_lowest_layer(ws).expires_never();

    // Set binary mode for our binary protocol
    ws.binary(true);

    // Route based on target path
    if (target == "/api/v1/control" || target == "/api/v1/control/") {
        // Control channel
        log().info("New control channel connection (TLS)");
        co_await ControlSession::start(std::move(ws), manager_);

    } else if (target == "/api/v1/relay" || target == "/api/v1/relay/") {
        // Relay channel (built-in relay)
        log().info("New relay channel connection (TLS)");
        co_await RelaySession::start(std::move(ws), manager_);

    } else {
        // Unknown endpoint
        log().warn("Unknown WebSocket endpoint: {}", target);
        co_await ws.async_close(websocket::close_code::policy_error, asio::use_awaitable);
    }
}

// ============================================================================
// PlainHttpSession implementation (non-TLS)
// ============================================================================

PlainHttpSession::PlainHttpSession(beast::tcp_stream&& stream,
                                   SessionManager& manager)
    : stream_(std::move(stream))
    , manager_(manager) {}

asio::awaitable<void> PlainHttpSession::run() {
    // Set timeout
    stream_.expires_after(std::chrono::seconds(30));

    // Read HTTP request
    http::request<http::string_body> req;
    co_await http::async_read(stream_, buffer_, req, asio::use_awaitable);

    // Get target path for routing
    std::string target(req.target());

    // Health check endpoints (non-WebSocket HTTP)
    if (target == "/health" || target == "/health/") {
        co_await send_health_response(stream_, req, http::status::ok,
            R"({"status":"healthy","service":"edgelink-controller"})");
        co_return;
    }
    if (target == "/health/live" || target == "/health/live/") {
        co_await send_health_response(stream_, req, http::status::ok,
            R"({"status":"live"})");
        co_return;
    }
    if (target == "/health/ready" || target == "/health/ready/") {
        // Check database connectivity
        if (manager_.database().is_open()) {
            co_await send_health_response(stream_, req, http::status::ok,
                R"({"status":"ready"})");
        } else {
            co_await send_health_response(stream_, req, http::status::service_unavailable,
                R"({"status":"not_ready","reason":"database not connected"})");
        }
        co_return;
    }

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

    log().debug("WebSocket upgrade request for: {}", target);

    // Create WebSocket stream (plain)
    PlainWsStream ws(std::move(stream_));

    // Set WebSocket options
    ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    ws.set_option(websocket::stream_base::decorator(
        [](websocket::response_type& res) {
            res.set(http::field::server, "EdgeLink Controller");
        }));

    // Accept WebSocket handshake
    co_await ws.async_accept(req, asio::use_awaitable);

    // Disable the HTTP timeout on the underlying stream - WebSocket has its own timeout
    beast::get_lowest_layer(ws).expires_never();

    // Set binary mode for our binary protocol
    ws.binary(true);

    // Route based on target path
    if (target == "/api/v1/control" || target == "/api/v1/control/") {
        // Control channel
        log().info("New control channel connection (plain)");
        co_await PlainControlSession::start(std::move(ws), manager_);

    } else if (target == "/api/v1/relay" || target == "/api/v1/relay/") {
        // Relay channel (built-in relay)
        log().info("New relay channel connection (plain)");
        co_await PlainRelaySession::start(std::move(ws), manager_);

    } else {
        // Unknown endpoint
        log().warn("Unknown WebSocket endpoint: {}", target);
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

    // Generate self-signed certificate at runtime using OpenSSL
    EVP_PKEY* pkey = nullptr;
    X509* x509 = nullptr;

    // Generate RSA key pair
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (pkey_ctx) {
        if (EVP_PKEY_keygen_init(pkey_ctx) > 0 &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) > 0 &&
            EVP_PKEY_keygen(pkey_ctx, &pkey) > 0) {
            // Key generated successfully
        }
        EVP_PKEY_CTX_free(pkey_ctx);
    }

    if (!pkey) {
        throw std::runtime_error("Failed to generate RSA key");
    }

    // Create X509 certificate
    x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create X509 certificate");
    }

    // Set certificate properties
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60); // 1 year
    X509_set_pubkey(x509, pkey);

    // Set subject and issuer
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("EdgeLink Controller"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("EdgeLink"), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Self-sign the certificate
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to sign certificate");
    }

    // Convert to PEM format and load into SSL context
    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* key_bio = BIO_new(BIO_s_mem());

    PEM_write_bio_X509(cert_bio, x509);
    PEM_write_bio_PrivateKey(key_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    char* cert_data = nullptr;
    char* key_data = nullptr;
    long cert_len = BIO_get_mem_data(cert_bio, &cert_data);
    long key_len = BIO_get_mem_data(key_bio, &key_data);

    ctx.use_certificate_chain(asio::buffer(cert_data, cert_len));
    ctx.use_private_key(asio::buffer(key_data, key_len), ssl::context::pem);

    // Cleanup
    BIO_free(cert_bio);
    BIO_free(key_bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    log().info("Generated self-signed certificate for development");
    return ctx;
}

ssl::context create_dummy_context() {
    // Create a minimal SSL context for non-TLS mode
    // This context won't be used but is needed to satisfy the Server constructor
    ssl::context ctx(ssl::context::tlsv12);
    log().debug("Created dummy SSL context (TLS disabled)");
    return ctx;
}

} // namespace ssl_util

} // namespace edgelink::controller

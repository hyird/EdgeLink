#pragma once

#include "controller/session_manager.hpp"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <memory>
#include <string>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;

using tcp = asio::ip::tcp;

namespace edgelink::controller {

// Server configuration
struct ServerConfig {
    std::string bind_address = "0.0.0.0";
    uint16_t port = 8443;
    std::string cert_file;      // Path to SSL certificate
    std::string key_file;       // Path to SSL private key
    size_t num_threads = 4;     // Number of IO threads
};

// WebSocket server with dual endpoints
class Server {
public:
    Server(asio::io_context& ioc, ssl::context& ssl_ctx,
           SessionManager& manager, const ServerConfig& config);

    // Start accepting connections
    asio::awaitable<void> run();

    // Stop the server
    void stop();

private:
    // Accept loop
    asio::awaitable<void> accept_loop();

    // Handle HTTP upgrade request and route to appropriate session type
    asio::awaitable<void> handle_connection(tcp::socket socket);

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    SessionManager& manager_;
    ServerConfig config_;

    tcp::acceptor acceptor_;
    bool running_ = false;
};

// HTTP request handler for WebSocket upgrade
class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
    HttpSession(beast::ssl_stream<beast::tcp_stream>&& stream,
                SessionManager& manager);

    // Run the session (handle HTTP upgrade)
    asio::awaitable<void> run();

private:
    beast::ssl_stream<beast::tcp_stream> stream_;
    SessionManager& manager_;
    beast::flat_buffer buffer_;
};

// SSL context setup utilities
namespace ssl_util {

// Create SSL context with certificate and key
ssl::context create_ssl_context(const std::string& cert_file,
                                const std::string& key_file);

// Create self-signed certificate for testing (in-memory)
ssl::context create_self_signed_context();

} // namespace ssl_util

} // namespace edgelink::controller

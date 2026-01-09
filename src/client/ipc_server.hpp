#pragma once

#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <optional>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

namespace edgelink::client {

namespace net = boost::asio;
using local_stream = boost::asio::local::stream_protocol;

// Forward declarations
class Client;

// ============================================================================
// IPC Response types (JSON-based)
// ============================================================================

struct IPCStatusResponse {
    bool connected{false};
    std::string state;
    std::string controller_url;
    uint32_t node_id{0};
    std::string virtual_ip;
    std::string tun_interface;
    uint64_t packets_sent{0};
    uint64_t packets_received{0};
    uint64_t bytes_sent{0};
    uint64_t bytes_received{0};
    int64_t uptime_seconds{0};
};

struct IPCDisconnectResponse {
    bool success{false};
    std::string message;
};

struct IPCReconnectResponse {
    bool success{false};
    std::string message;
};

struct IPCPingResponse {
    bool success{false};
    uint32_t latency_ms{0};
    std::string error;
};

// ============================================================================
// IPC Session - Handles one client connection
// ============================================================================

class IPCSession : public std::enable_shared_from_this<IPCSession> {
public:
    IPCSession(local_stream::socket socket, Client* client);

    void start();

private:
    void do_read();
    void do_write(const std::string& response);

    std::string handle_request(const nlohmann::json& request);
    std::string handle_status();
    std::string handle_disconnect();
    std::string handle_reconnect();
    std::string handle_ping(uint32_t peer_node_id);

    local_stream::socket socket_;
    Client* client_;
    std::array<char, 8192> buffer_;
};

// ============================================================================
// IPC Server (Unix socket for POSIX, named pipe for Windows)
// ============================================================================

class IPCServer {
public:
    explicit IPCServer(net::io_context& ioc, Client* client);
    ~IPCServer();

    // Non-copyable
    IPCServer(const IPCServer&) = delete;
    IPCServer& operator=(const IPCServer&) = delete;

    // Start/stop server
    bool start();
    void stop();

    // Get socket path
    static std::string get_socket_path();

private:
    void do_accept();

    net::io_context& ioc_;
    Client* client_;
    std::unique_ptr<local_stream::acceptor> acceptor_;
    std::atomic<bool> running_{false};
};

// ============================================================================
// IPC Client (for CLI to connect to running daemon)
// ============================================================================

class IPCClient {
public:
    IPCClient();
    ~IPCClient();

    // Connect to running daemon
    bool connect();
    bool is_connected() const { return connected_; }

    // Commands
    std::optional<IPCStatusResponse> status();
    std::optional<IPCDisconnectResponse> disconnect();
    std::optional<IPCReconnectResponse> reconnect();
    std::optional<IPCPingResponse> ping(uint32_t peer_node_id = 0);

private:
    std::string send_request(const nlohmann::json& request);

    net::io_context ioc_;
    std::unique_ptr<local_stream::socket> socket_;
    bool connected_{false};
};

} // namespace edgelink::client

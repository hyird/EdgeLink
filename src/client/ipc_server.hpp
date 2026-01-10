#pragma once

// Undefine Windows ERROR macro to avoid conflict
#ifdef ERROR
#undef ERROR
#endif

#include "common/types.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace asio = boost::asio;

namespace edgelink::client {

// Forward declarations
class Client;

// IPC request types
enum class IpcRequestType {
    STATUS,         // Get client status
    PEERS,          // List all peers
    PING,           // Ping a peer
    SEND,           // Send data to a peer
    LOG_LEVEL,      // Get/set log level
    SHUTDOWN,       // Request shutdown
};

// IPC response status
enum class IpcStatus {
    OK = 0,
    ERROR = 1,
    NOT_CONNECTED = 2,
    PEER_NOT_FOUND = 3,
    INVALID_REQUEST = 4,
};

// Status response data
struct IpcStatusResponse {
    std::string state;
    std::string node_id;
    std::string virtual_ip;
    std::string controller_url;
    uint64_t network_id = 0;
    size_t peer_count = 0;
    size_t online_peer_count = 0;
    bool tun_enabled = false;
};

// Peer info for IPC response
struct IpcPeerInfo {
    std::string node_id;
    std::string virtual_ip;
    std::string name;
    bool online = false;
    std::string connection_status;  // "disconnected", "p2p", "relay"
    uint16_t latency_ms = 0;
};

// IPC Server configuration
struct IpcServerConfig {
    std::string socket_path;  // Unix socket path or Windows named pipe
    bool enabled = true;
};

// Shutdown callback type
using ShutdownCallback = std::function<void()>;

// IPC Server - provides local control interface for CLI commands
class IpcServer : public std::enable_shared_from_this<IpcServer> {
public:
    IpcServer(asio::io_context& ioc, Client& client);
    ~IpcServer();

    // Start the IPC server
    bool start(const IpcServerConfig& config);

    // Stop the server
    void stop();

    // Check if running
    bool is_running() const { return running_; }

    // Set shutdown callback (called when shutdown command received)
    void set_shutdown_callback(ShutdownCallback callback) { shutdown_callback_ = std::move(callback); }

    // Get the socket path
    const std::string& socket_path() const { return config_.socket_path; }

    // Get default socket path for this platform
    static std::string get_default_socket_path();

private:
    // Accept connections
    asio::awaitable<void> accept_loop();

    // Handle a single client connection
    asio::awaitable<void> handle_client(asio::local::stream_protocol::socket socket);

    // Process a single request line
    std::string process_request(const std::string& request);

    // Request handlers
    std::string handle_status();
    std::string handle_peers(bool online_only);
    std::string handle_ping(const std::string& target);
    std::string handle_log_level(const std::string& module, const std::string& level);
    std::string handle_shutdown();

    // JSON encoding helpers
    std::string encode_status_response(IpcStatus status, const IpcStatusResponse& data);
    std::string encode_peers_response(IpcStatus status, const std::vector<IpcPeerInfo>& peers);
    std::string encode_error(IpcStatus status, const std::string& message);
    std::string encode_ok(const std::string& message = "");

    asio::io_context& ioc_;
    Client& client_;
    IpcServerConfig config_;
    ShutdownCallback shutdown_callback_;

#ifdef _WIN32
    // Windows: use local stream (named pipe emulation via Boost.Asio)
    std::unique_ptr<asio::local::stream_protocol::acceptor> acceptor_;
#else
    // Unix: use Unix domain socket
    std::unique_ptr<asio::local::stream_protocol::acceptor> acceptor_;
#endif

    bool running_ = false;
};

// IPC Client - used by CLI commands to communicate with daemon
class IpcClient {
public:
    explicit IpcClient(const std::string& socket_path = "");
    ~IpcClient();

    // Connect to the daemon
    bool connect();

    // Check if connected
    bool is_connected() const { return connected_; }

    // Send request and get response
    std::string send_request(const std::string& request);

    // High-level commands
    std::string get_status();
    std::string get_peers(bool online_only = false);
    std::string ping_peer(const std::string& target);
    std::string set_log_level(const std::string& module, const std::string& level);
    std::string request_shutdown();

private:
    std::string socket_path_;
    bool connected_ = false;

    asio::io_context ioc_;
    std::unique_ptr<asio::local::stream_protocol::socket> socket_;
};

} // namespace edgelink::client

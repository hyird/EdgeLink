#pragma once

// Undefine Windows ERROR macro to avoid conflict
#ifdef ERROR
#undef ERROR
#endif

#include "common/types.hpp"
#include <boost/asio.hpp>
#include <boost/cobalt.hpp>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace asio = boost::asio;
namespace cobalt = boost::cobalt;

namespace edgelink::client {

// IPC protocol version — incremented when the wire format changes
constexpr int IPC_PROTOCOL_VERSION = 1;

// Forward declarations
class Client;

// IPC request types
enum class IpcRequestType {
    STATUS,         // Get client status
    PEERS,          // List all peers
    ROUTES,         // List all routes
    PING,           // Ping a peer
    SEND,           // Send data to a peer
    LOG_LEVEL,      // Get/set log level
    SHUTDOWN,       // Request shutdown
    CONFIG_GET,     // Get config value
    CONFIG_SET,     // Set config value
    CONFIG_LIST,    // List all config
    CONFIG_RELOAD,  // Reload config from file
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
    std::string controller_host;  // 当前连接的 controller (host:port)
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

// Route info for IPC response
struct IpcRouteInfo {
    std::string prefix;           // CIDR format, e.g., "192.168.1.0/24"
    std::string gateway_node_id;  // Node ID of the gateway
    std::string gateway_ip;       // Virtual IP of the gateway node
    std::string gateway_name;     // Name of the gateway node
    uint16_t metric = 100;
    bool exit_node = false;       // Is this an exit node route (0.0.0.0/0)
};

// Config item info for IPC response
struct IpcConfigItem {
    std::string key;            // 配置路径
    std::string value;          // 当前值
    std::string type;           // 类型 (string, int, bool, string_array)
    std::string description;    // 描述
    bool hot_reloadable;        // 是否可热重载
    std::string default_value;  // 默认值
};

// Config change result
struct IpcConfigChange {
    std::string key;
    std::string old_value;
    std::string new_value;
    bool applied;
    bool restart_required;
    std::string message;
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
    cobalt::task<void> accept_loop();

    // Handle a single client connection
    cobalt::task<void> handle_client(asio::local::stream_protocol::socket socket);

    // Process a single request line (coroutine - ping 等命令需要 co_await)
    cobalt::task<std::string> process_request(const std::string& request);

    // Request handlers
    std::string handle_status();
    std::string handle_peers(bool online_only);
    std::string handle_routes();
    cobalt::task<std::string> handle_ping(const std::string& target);
    std::string handle_log_level(const std::string& module, const std::string& level);
    std::string handle_shutdown();
    std::string handle_config_get(const std::string& key);
    std::string handle_config_set(const std::string& key, const std::string& value);
    std::string handle_config_list();
    std::string handle_config_reload();
    std::string handle_prefs_update();

    // JSON encoding helpers
    std::string encode_status_response(IpcStatus status, const IpcStatusResponse& data);
    std::string encode_peers_response(IpcStatus status, const std::vector<IpcPeerInfo>& peers);
    std::string encode_routes_response(IpcStatus status, const std::vector<IpcRouteInfo>& routes);
    std::string encode_config_response(IpcStatus status, const IpcConfigItem& item);
    std::string encode_config_list_response(IpcStatus status, const std::vector<IpcConfigItem>& items);
    std::string encode_config_change_response(IpcStatus status, const IpcConfigChange& change);
    std::string encode_config_reload_response(IpcStatus status, const std::vector<IpcConfigChange>& changes);
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
    std::string get_routes();
    std::string ping_peer(const std::string& target);
    std::string set_log_level(const std::string& module, const std::string& level);
    std::string request_shutdown();
    std::string config_get(const std::string& key);
    std::string config_set(const std::string& key, const std::string& value);
    std::string config_list();
    std::string config_reload();
    std::string prefs_update();

private:
    std::string socket_path_;
    bool connected_ = false;

    asio::io_context ioc_;
    std::unique_ptr<asio::local::stream_protocol::socket> socket_;
};

} // namespace edgelink::client

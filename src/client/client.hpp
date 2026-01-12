#pragma once

#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/channel.hpp"
#include "client/tun_device.hpp"
#include "client/ipc_server.hpp"
#include "client/route_manager.hpp"
#include "client/config_watcher.hpp"
#include "client/config_applier.hpp"
#include "client/endpoint_manager.hpp"
#include "client/p2p_manager.hpp"
#include "common/node_state.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace asio = boost::asio;
namespace ssl = asio::ssl;

namespace edgelink::client {

// Client configuration
struct ClientConfig {
    // 连接设置 - 格式: host 或 host:port (port可省略，TLS时默认443，否则80)
    std::vector<std::string> controller_hosts = {"edge.a-z.xin"};  // 默认 controller
    std::string authkey;
    bool tls = true;  // Enable TLS (wss://) - default enabled
    std::chrono::milliseconds failover_timeout{5000};  // 切换到下一个Controller的超时时间
    bool auto_reconnect = true;
    std::chrono::seconds reconnect_interval{5};
    std::chrono::seconds ping_interval{5};  // Keep connection alive, avoid CDN idle timeout
    std::chrono::seconds dns_refresh_interval{60};  // DNS resolution refresh interval (0 = disabled)
    std::chrono::seconds latency_measure_interval{30};  // Peer latency measurement interval (0 = disabled)

    // SSL/TLS settings
    bool ssl_verify = false;            // Verify server certificate (default: false for dev)
    std::string ssl_ca_file;            // Custom CA certificate file (empty = system default)
    bool ssl_allow_self_signed = false; // Allow self-signed certificates

    // State directory for storing persistent keys
    std::string state_dir;  // Empty = platform default

    // TUN mode settings
    bool enable_tun = false;       // Enable TUN device for IP-level routing
    std::string tun_name = "";     // TUN device name (empty = auto)
    uint32_t tun_mtu = 1420;       // MTU for TUN device

    // IPC server settings
    bool enable_ipc = true;        // Enable IPC control interface
    std::string ipc_socket_path;   // IPC socket path (empty = platform default)

    // Subnet routing settings (advertise local subnets to other peers)
    std::vector<std::string> advertise_routes;  // CIDR格式，如 "192.168.1.0/24", "10.0.0.0/8"
    bool exit_node = false;                     // 作为出口节点，公告 0.0.0.0/0
    bool accept_routes = true;                  // 是否接受其他节点的路由并应用到系统
    std::chrono::seconds route_announce_interval{60};  // 路由公告刷新间隔（秒，定期广播确保同步）

    // Logging settings (for hot-reload)
    std::string log_level = "debug";    // 日志级别
    std::string log_file;               // 日志文件路径

    // P2P 配置（使用统一的 edgelink::P2PConfig）
    edgelink::P2PConfig p2p;

    // 获取当前使用的controller host
    std::string current_controller_host() const {
        if (controller_hosts.empty()) return "localhost:8080";
        return controller_hosts[0];
    }

    // 解析 host:port 为规范化格式
    static std::pair<std::string, uint16_t> parse_host_port(const std::string& host_port, bool use_tls) {
        std::string host = host_port;
        uint16_t port = use_tls ? 443 : 80;

        size_t colon_pos = std::string::npos;
        if (!host.empty() && host[0] == '[') {
            auto bracket_pos = host.find(']');
            if (bracket_pos != std::string::npos && bracket_pos + 1 < host.size() && host[bracket_pos + 1] == ':') {
                colon_pos = bracket_pos + 1;
            }
        } else {
            colon_pos = host.rfind(':');
        }

        if (colon_pos != std::string::npos) {
            try {
                port = static_cast<uint16_t>(std::stoi(host.substr(colon_pos + 1)));
                host = host.substr(0, colon_pos);
            } catch (...) {}
        }

        if (host.size() >= 2 && host[0] == '[' && host.back() == ']') {
            host = host.substr(1, host.size() - 2);
        }

        return {host, port};
    }
};

// Client state
enum class ClientState {
    STOPPED,
    STARTING,
    AUTHENTICATING,
    CONNECTING_RELAY,
    RUNNING,
    RECONNECTING,
};

const char* client_state_name(ClientState state);

// Callbacks
struct ClientCallbacks {
    std::function<void()> on_connected;
    std::function<void()> on_disconnected;
    std::function<void(NodeId peer_id, std::span<const uint8_t> data)> on_data_received;
    std::function<void(uint16_t code, const std::string& msg)> on_error;
    std::function<void()> on_shutdown_requested;  // Called when shutdown is requested via IPC
};

// Main client coordinator
class Client : public std::enable_shared_from_this<Client> {
public:
    Client(asio::io_context& ioc, const ClientConfig& config);
    ~Client();

    // Start the client (authenticate and connect to relay)
    asio::awaitable<bool> start();

    // Stop the client
    asio::awaitable<void> stop();

    // Send data to a peer
    asio::awaitable<bool> send_to_peer(NodeId peer_id, std::span<const uint8_t> data);

    // Send data to a peer by virtual IP
    asio::awaitable<bool> send_to_ip(const IPv4Address& ip, std::span<const uint8_t> data);

    // Send raw IP packet (for TUN mode)
    asio::awaitable<bool> send_ip_packet(std::span<const uint8_t> packet);

    // Ping a peer and return latency in milliseconds (0 = timeout/error)
    asio::awaitable<uint16_t> ping_peer(NodeId peer_id, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));
    asio::awaitable<uint16_t> ping_ip(const IPv4Address& ip, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000));

    // Subnet routing - announce routes this node can forward
    asio::awaitable<void> announce_routes(const std::vector<RouteInfo>& routes);
    asio::awaitable<void> withdraw_routes(const std::vector<RouteInfo>& routes);

    // Announce configured routes from config (advertise_routes and exit_node)
    asio::awaitable<void> announce_configured_routes();

    // Set callbacks
    void set_callbacks(ClientCallbacks callbacks);

    // Accessors
    ClientState state() const { return state_; }
    bool is_running() const { return state_ == ClientState::RUNNING; }

    NodeId node_id() const { return crypto_.node_id(); }
    IPv4Address virtual_ip() const { return control_ ? control_->virtual_ip() : IPv4Address{}; }
    NetworkId network_id() const { return control_ ? control_->network_id() : 0; }

    CryptoEngine& crypto() { return crypto_; }
    PeerManager& peers() { return peers_; }
    ClientStateMachine& state_machine() { return state_machine_; }
    const ClientStateMachine& state_machine() const { return state_machine_; }

    // 统一状态机状态查询
    ConnectionPhase connection_phase() const { return state_machine_.connection_phase(); }
    bool is_online() const { return state_machine_.is_connected(); }

    // Network routes (received from controller)
    const std::vector<RouteInfo>& routes() const { return routes_; }

    // TUN device (if enabled)
    TunDevice* tun_device() { return tun_.get(); }
    bool is_tun_enabled() const { return config_.enable_tun && tun_ && tun_->is_open(); }

    // IPC server (if enabled)
    IpcServer* ipc_server() { return ipc_.get(); }
    bool is_ipc_enabled() const { return config_.enable_ipc && ipc_ && ipc_->is_running(); }

    // Configuration hot-reload support
    const ClientConfig& config() const { return config_; }
    ClientConfig& config() { return config_; }
    const std::string& config_path() const { return config_path_; }
    void set_config_path(const std::string& path) { config_path_ = path; }

    // Get config value as string (for IPC)
    std::string get_config_value(const std::string& key) const;

    // Config watcher and applier accessors
    ConfigWatcher* config_watcher() { return config_watcher_.get(); }
    ConfigApplier* config_applier() { return config_applier_.get(); }

    // Enable/disable config file watching
    void enable_config_watch();
    void disable_config_watch();

    // Hot-reload operations
    void request_reconnect();                // 请求重新连接到 Controller
    void request_tun_rebuild();              // 请求重建 TUN 设备
    void request_ipc_restart();              // 请求重启 IPC 服务器
    void request_route_reannounce();         // 请求重新公告路由
    void request_ssl_context_rebuild();      // 请求重建 SSL 上下文
    void clear_system_routes();              // 清除所有系统路由

private:
    void setup_callbacks();
    void setup_state_machine();  // 设置状态机回调

    // TUN device management
    bool setup_tun();
    void teardown_tun();
    void on_tun_packet(std::span<const uint8_t> packet);

    // IPC server management
    bool setup_ipc();
    void teardown_ipc();

    // Ping management
    void handle_ping_data(NodeId src, std::span<const uint8_t> data);
    void send_pong(NodeId peer_id, uint32_t seq_num, uint64_t timestamp);

    // Keepalive timer
    asio::awaitable<void> keepalive_loop();

    // DNS refresh loop - periodically check for DNS changes
    asio::awaitable<void> dns_refresh_loop();

    // Latency measurement loop - periodically measure peer latency
    asio::awaitable<void> latency_measure_loop();

    // Route announce loop - periodically re-announce routes
    asio::awaitable<void> route_announce_loop();

    // P2P state handler - 处理 P2P 状态变化（替代回调）
    asio::awaitable<void> p2p_state_handler();

    // P2P channel handlers
    asio::awaitable<void> p2p_endpoints_handler();
    asio::awaitable<void> p2p_init_handler();
    asio::awaitable<void> p2p_status_handler();
    asio::awaitable<void> p2p_data_handler();

    // Reconnection logic
    asio::awaitable<void> reconnect();

    asio::io_context& ioc_;
    ssl::context ssl_ctx_;
    ClientConfig config_;
    ClientState state_ = ClientState::STOPPED;

    CryptoEngine crypto_;
    PeerManager peers_;
    ClientStateMachine state_machine_;  // 客户端状态机

    std::shared_ptr<ControlChannel> control_;
    std::shared_ptr<RelayChannel> relay_;

    asio::steady_timer keepalive_timer_;
    asio::steady_timer reconnect_timer_;
    asio::steady_timer dns_refresh_timer_;
    asio::steady_timer latency_timer_;
    asio::steady_timer route_announce_timer_;

    // Cached DNS resolution results for change detection
    std::string cached_controller_endpoints_;

    // TUN device (optional)
    std::unique_ptr<TunDevice> tun_;

    // IPC server (optional)
    std::shared_ptr<IpcServer> ipc_;

    // Configuration hot-reload
    std::string config_path_;
    std::unique_ptr<ConfigWatcher> config_watcher_;
    std::unique_ptr<ConfigApplier> config_applier_;

    // Route manager (optional, requires TUN)
    std::unique_ptr<RouteManager> route_mgr_;

    // Network routes (received from controller)
    std::vector<RouteInfo> routes_;
    std::mutex routes_mutex_;

    // Pending ping state
    struct PendingPing {
        uint64_t send_time = 0;
        std::function<void(uint16_t)> callback;  // latency_ms or 0 on timeout
    };
    std::mutex ping_mutex_;
    std::unordered_map<uint64_t, PendingPing> pending_pings_;  // key = (node_id << 32) | seq_num
    uint32_t ping_seq_ = 0;

    // P2P support
    std::unique_ptr<EndpointManager> endpoint_mgr_;
    std::unique_ptr<P2PManager> p2p_mgr_;
    std::unique_ptr<channels::PeerStateChannel> peer_state_channel_;  // P2P 状态变化通道

    // P2P channels（用于异步通信）
    std::unique_ptr<P2PChannels::EndpointsReadyChannel> endpoints_ready_channel_;
    std::unique_ptr<P2PChannels::P2PInitChannel> p2p_init_channel_;
    std::unique_ptr<P2PChannels::P2PStatusChannel> p2p_status_channel_;
    std::unique_ptr<P2PChannels::DataChannel> p2p_data_channel_;

    // 保存最后上报的端点（用于重连后重发）
    std::vector<Endpoint> last_reported_endpoints_;
    std::mutex endpoints_mutex_;

    ClientCallbacks callbacks_;
};

} // namespace edgelink::client

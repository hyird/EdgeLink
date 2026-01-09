#pragma once

#include "control_channel.hpp"
#include "grpc_relay_manager.hpp"
#include "crypto_engine.hpp"
#include "tun_device.hpp"
#include "route_manager.hpp"
#include "endpoint_manager.hpp"
#include "p2p_manager.hpp"
#include "ipc_server.hpp"
#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace edgelink::client {

namespace net = boost::asio;
namespace ssl = net::ssl;

// 客户端配置
struct ClientConfig {
    // Controller连接
    std::string controller_url;     // e.g., "wss://controller.example.com"
    std::string machine_key_pub;    // Base64编码的machine公钥
    std::string machine_key_priv;   // Base64编码的machine私钥
    std::string auth_key;           // 注册用的 auth key (可选)
    
    // TUN设备
    std::string tun_name = "wss0";
    int mtu = 1400;
    
    // 本地节点信息 (Controller分配后填充)
    uint32_t node_id = 0;
    std::string virtual_ip;
    std::string node_key_priv;      // Base64编码的X25519私钥
    std::string node_key_pub;       // Base64编码的X25519公钥
    
    // 网络配置
    uint32_t network_id = 0;
    std::string network_cidr;       // e.g., "10.100.0.0/16"
    
    // 端点发现
    EndpointManagerConfig endpoint_config;
    
    // 日志级别
    std::string log_level = "info";
    
    // 配置文件路径
    std::string config_file;
};

// 客户端状态
enum class ClientState {
    STOPPED,
    STARTING,
    CONNECTING_CONTROLLER,
    WAITING_CONFIG,
    SETTING_UP_TUN,
    CONNECTING_RELAYS,
    RUNNING,
    RECONNECTING,
    STOPPING
};

/**
 * Client - WSS Mesh客户端主类
 * 
 * 整合所有组件:
 * - ControlChannel: 与Controller通信
 * - RelayManager: 管理多个Relay连接
 * - CryptoEngine: 端到端加密
 * - TunDevice: 虚拟网卡
 * - RouteManager: 路由管理
 * - EndpointManager: 端点发现
 * 
 * 数据流:
 * TUN读取 → 路由查找 → 加密 → Relay发送
 * Relay接收 → 解密 → TUN写入
 */
class Client : public std::enable_shared_from_this<Client> {
public:
    explicit Client(const ClientConfig& config);
    ~Client();
    
    // 禁止拷贝
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    
    // 启动/停止
    bool start();
    void stop();
    void run();  // 阻塞运行
    
    // 状态
    ClientState get_state() const { return state_.load(); }
    std::string get_state_string() const;
    bool is_running() const { return state_ == ClientState::RUNNING; }
    
    // 获取组件
    std::shared_ptr<ControlChannel> get_control_channel() { return control_channel_; }
    std::shared_ptr<GrpcRelayManager> get_relay_manager() { return relay_manager_; }
    std::shared_ptr<CryptoEngine> get_crypto_engine() { return crypto_engine_; }
    std::shared_ptr<TunDevice> get_tun_device() { return tun_device_; }
    std::shared_ptr<RouteManager> get_route_manager() { return route_manager_; }
    std::shared_ptr<EndpointManager> get_endpoint_manager() { return endpoint_manager_; }
    std::shared_ptr<P2PManager> get_p2p_manager() { return p2p_manager_; }
    IPCServer* get_ipc_server() { return ipc_server_.get(); }

    // 获取控制器 URL
    const std::string& get_controller_url() const { return config_.controller_url; }

    // 统计信息
    struct Stats {
        uint64_t packets_sent = 0;
        uint64_t packets_received = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_received = 0;
        uint64_t encrypt_errors = 0;
        uint64_t decrypt_errors = 0;
        uint64_t route_misses = 0;
        std::chrono::steady_clock::time_point start_time;
    };
    Stats get_stats() const;
    
private:
    // 初始化各组件
    bool init_ssl_context();
    bool init_control_channel();
    bool init_relay_manager();
    bool init_crypto_engine();
    bool init_tun_device();
    bool init_route_manager();
    bool init_endpoint_manager();
    bool init_p2p_manager();
    
    // ControlChannel回调
    void on_config_received(const ConfigUpdate& config);
    void on_connected();
    void on_disconnected(ErrorCode ec);
    void on_peer_online(uint32_t node_id, const PeerInfo& peer);
    void on_peer_offline(uint32_t node_id);
    void on_token_refresh(const std::string& auth_token, const std::string& relay_token);
    void on_ip_change(const std::string& old_ip, const std::string& new_ip,
                      const std::string& reason);
    
    // RelayManager回调
    void on_relay_data_received(uint32_t from_node_id, const std::vector<uint8_t>& data);
    void on_relay_state_changed(uint32_t relay_id, GrpcRelayConnection::State state);
    void on_latency_measured(uint32_t relay_id, uint32_t peer_id, uint32_t latency_ms);
    
    // P2PManager回调
    void on_p2p_data_received(uint32_t peer_id, const std::vector<uint8_t>& data);
    void on_p2p_state_changed(uint32_t peer_id, P2PState state);
    void on_p2p_punch_request(uint32_t peer_id);
    void on_p2p_connected(uint32_t peer_id, uint32_t rtt_ms);
    void on_p2p_disconnected(uint32_t peer_id);
    
    // TUN设备回调
    void on_tun_packet(const std::vector<uint8_t>& packet);
    
    // EndpointManager回调
    void on_endpoints_changed(const std::vector<Endpoint>& endpoints);
    
    // 数据处理
    void process_outbound_packet(const std::vector<uint8_t>& packet);
    void process_inbound_packet(uint32_t from_node_id, const std::vector<uint8_t>& data);
    
    // 状态管理
    void set_state(ClientState new_state);
    void handle_fatal_error(const std::string& error);
    
    // 配置
    ClientConfig config_;
    
    // IO上下文
    net::io_context ioc_;
    net::executor_work_guard<net::io_context::executor_type> work_guard_;
    std::vector<std::thread> io_threads_;
    
    // Strand for serializing callbacks (避免竞争条件)
    net::strand<net::io_context::executor_type> callback_strand_;
    
    // SSL上下文
    ssl::context ssl_ctx_;
    
    // 组件
    std::shared_ptr<ControlChannel> control_channel_;
    std::shared_ptr<GrpcRelayManager> relay_manager_;
    std::shared_ptr<CryptoEngine> crypto_engine_;
    std::shared_ptr<TunDevice> tun_device_;
    std::shared_ptr<RouteManager> route_manager_;
    std::shared_ptr<EndpointManager> endpoint_manager_;
    std::shared_ptr<P2PManager> p2p_manager_;
    std::unique_ptr<IPCServer> ipc_server_;

    // P2P优先标志：如果为true，优先使用P2P，否则使用Relay
    std::unordered_map<uint32_t, bool> peer_p2p_preferred_;
    
    // 状态
    std::atomic<ClientState> state_{ClientState::STOPPED};
    bool initialized_ = false;  // 是否已完成初始化
    
    // 统计
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    // 本地节点信息 (从Controller获取)
    uint32_t node_id_ = 0;
    std::string virtual_ip_;
    std::array<uint8_t, 32> node_key_priv_;
    std::array<uint8_t, 32> node_key_pub_;
    
    // Tokens
    std::string auth_token_;
    std::string relay_token_;
    
    // Latency reporting timer
    net::steady_timer latency_report_timer_;
    std::mutex latency_mutex_;
    std::vector<ControlChannel::LatencyMeasurement> pending_latency_reports_;
    static constexpr auto LATENCY_REPORT_INTERVAL = std::chrono::seconds(30);

    void start_latency_report_timer();
    void on_latency_report_timer();

    // Thread pool monitoring timer
    net::steady_timer monitor_timer_;
    static constexpr auto MONITOR_INTERVAL = std::chrono::seconds(60);

    void start_monitor_timer();
    void on_monitor_timer();
    void log_thread_stats();
};

// 从配置文件加载
ClientConfig load_client_config(const std::string& config_file);

// Base64编解码
std::string base64_encode(const std::vector<uint8_t>& data);
std::string base64_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const std::string& encoded);

} // namespace edgelink::client

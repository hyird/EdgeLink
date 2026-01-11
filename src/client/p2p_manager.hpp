#pragma once

#include "common/types.hpp"
#include "common/message.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/endpoint_manager.hpp"

#include <boost/asio.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace asio = boost::asio;

namespace edgelink::client {

// P2P 连接状态
enum class P2PState : uint8_t {
    IDLE = 0,           // 未连接
    RESOLVING = 1,      // 请求端点中 (等待 P2P_ENDPOINT)
    PUNCHING = 2,       // 打洞中 (发送 P2P_PING)
    CONNECTED = 3,      // P2P 已建立
    RELAY_ONLY = 4,     // 仅 Relay (打洞失败，稍后重试)
};

// P2P 状态名称
const char* p2p_state_name(P2PState state);

// P2P 配置
struct P2PConfig {
    bool enabled = true;
    uint16_t bind_port = 0;                     // 0 = 随机端口
    uint32_t keepalive_interval_sec = 15;       // Keepalive 间隔 (秒)
    uint32_t keepalive_timeout_sec = 45;        // Keepalive 超时 (秒)
    uint32_t punch_timeout_sec = 10;            // 打洞超时 (秒)
    uint32_t punch_batch_count = 5;             // 打洞批次数 (EasyTier: 5)
    uint32_t punch_batch_size = 2;              // 每批发送包数 (EasyTier: 2)
    uint32_t punch_batch_interval_ms = 400;     // 批次间隔 (毫秒, EasyTier: 400)
    uint32_t retry_interval_sec = 60;           // 失败后重试间隔 (秒)
    uint32_t stun_timeout_ms = 5000;            // STUN 查询超时 (毫秒)
    uint32_t endpoint_refresh_sec = 30;         // 端点刷新间隔 (秒)，定期重新查询 STUN 并上报
};

// 对端 P2P 状态
struct PeerP2PState {
    P2PState state = P2PState::IDLE;
    uint32_t init_seq = 0;                      // P2P_INIT 序列号
    std::array<uint8_t, X25519_KEY_SIZE> peer_key{};  // 对端公钥
    std::vector<Endpoint> peer_endpoints;       // 对端端点列表
    asio::ip::udp::endpoint active_endpoint;    // 当前活跃端点
    uint64_t last_punch_time = 0;               // 上次打洞时间
    uint32_t punch_count = 0;                   // 打洞次数
    uint64_t last_recv_time = 0;                // 上次收到数据时间
    uint64_t last_send_time = 0;                // 上次发送数据时间
    uint32_t ping_seq = 0;                      // Ping 序列号
    uint16_t latency_ms = 0;                    // RTT 延迟
};

// P2P 回调
struct P2PCallbacks {
    // P2P 状态变化
    std::function<void(NodeId peer_id, P2PState state)> on_state_change;
    // 收到 P2P 数据
    std::function<void(NodeId peer_id, std::span<const uint8_t> data)> on_data;
    // 请求发送 P2P_INIT (通过 Control Channel)
    std::function<void(const P2PInit& init)> on_send_p2p_init;
    // 请求发送 P2P_STATUS (通过 Control Channel)
    std::function<void(const P2PStatusMsg& status)> on_send_p2p_status;
    // 端点已就绪，需要上报给 Controller
    std::function<void(const std::vector<Endpoint>& endpoints)> on_endpoints_ready;
};

/**
 * P2PManager - P2P NAT 穿透管理器
 *
 * 职责:
 * - 管理每个对端的 P2P 连接状态机
 * - 发起和处理 UDP 打洞
 * - 维护 P2P Keepalive
 * - 发送和接收加密的 P2P 数据
 */
class P2PManager {
public:
    P2PManager(asio::io_context& ioc, CryptoEngine& crypto,
               PeerManager& peers, EndpointManager& endpoints);
    ~P2PManager();

    // ========================================================================
    // 生命周期
    // ========================================================================

    // 设置配置
    void set_config(const P2PConfig& config);

    // 设置回调
    void set_callbacks(P2PCallbacks callbacks);

    // 启动 P2P 管理器
    asio::awaitable<bool> start();

    // 停止 P2P 管理器
    asio::awaitable<void> stop();

    // 是否正在运行
    bool is_running() const { return running_.load(); }

    // ========================================================================
    // P2P 连接管理
    // ========================================================================

    // 发起 P2P 连接 (向 Controller 请求对端端点)
    void connect_peer(NodeId peer_id);

    // 断开 P2P 连接
    void disconnect_peer(NodeId peer_id);

    // 处理 Controller 返回的 P2P_ENDPOINT
    void handle_p2p_endpoint(const P2PEndpointMsg& msg);

    // 获取对端 P2P 状态
    std::optional<PeerP2PState> get_peer_state(NodeId peer_id) const;

    // 获取所有对端 P2P 状态
    std::vector<std::pair<NodeId, PeerP2PState>> get_all_peer_states() const;

    // ========================================================================
    // 数据发送
    // ========================================================================

    // 发送 P2P 数据 (如果已连接)
    // 返回 true 表示通过 P2P 发送，false 表示需要通过 Relay
    asio::awaitable<bool> send_data(NodeId peer_id, std::span<const uint8_t> data);

    // 检查是否可以通过 P2P 发送
    bool is_p2p_connected(NodeId peer_id) const;

    // ========================================================================
    // 端点信息
    // ========================================================================

    // 获取我方所有端点 (供 P2P_ENDPOINT 使用)
    std::vector<Endpoint> our_endpoints() const;

private:
    // UDP 接收循环
    asio::awaitable<void> recv_loop();

    // Keepalive 循环
    asio::awaitable<void> keepalive_loop();

    // 打洞循环 (超时检测)
    asio::awaitable<void> punch_loop();

    // 执行分批打洞 (EasyTier 风格：每批 2 个包，共 5 批，间隔 400ms)
    asio::awaitable<void> do_punch_batches(NodeId peer_id);

    // 重试循环
    asio::awaitable<void> retry_loop();

    // 端点刷新循环 (定期重新查询 STUN 并上报端点)
    asio::awaitable<void> endpoint_refresh_loop();

    // 刷新端点 (重新查询 STUN 并上报给 Controller)
    asio::awaitable<void> refresh_endpoints();

    // 处理收到的 UDP 数据
    void handle_udp_packet(const asio::ip::udp::endpoint& from,
                           std::span<const uint8_t> data);

    // 处理 P2P_PING
    void handle_p2p_ping(const asio::ip::udp::endpoint& from,
                         const P2PPing& ping);

    // 处理 P2P_PONG
    void handle_p2p_pong(const asio::ip::udp::endpoint& from,
                         const P2PPing& pong);

    // 处理 P2P_KEEPALIVE
    void handle_p2p_keepalive(const asio::ip::udp::endpoint& from,
                               NodeId peer_id,
                               const P2PKeepalive& keepalive);

    // 处理 P2P 数据
    void handle_p2p_data(const asio::ip::udp::endpoint& from,
                         NodeId peer_id,
                         std::span<const uint8_t> encrypted_data);

    // 发送 P2P_PING
    asio::awaitable<void> send_p2p_ping(NodeId peer_id,
                                         const asio::ip::udp::endpoint& to);

    // 发送 P2P_PONG
    void send_p2p_pong(const P2PPing& ping, const asio::ip::udp::endpoint& to);

    // 发送 P2P_KEEPALIVE
    asio::awaitable<void> send_p2p_keepalive(NodeId peer_id);

    // 更新对端状态
    void set_peer_state(NodeId peer_id, P2PState state);

    // 上报 P2P 状态给 Controller
    void report_p2p_status(NodeId peer_id);

    // 根据端点查找对端
    std::optional<NodeId> find_peer_by_endpoint(const asio::ip::udp::endpoint& ep) const;

    // 将 Endpoint 转换为 udp::endpoint
    static std::optional<asio::ip::udp::endpoint> to_udp_endpoint(const Endpoint& ep);

    // 获取当前时间 (微秒)
    static uint64_t now_us();

    asio::io_context& ioc_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    EndpointManager& endpoints_;

    P2PConfig config_;
    P2PCallbacks callbacks_;

    std::atomic<bool> running_{false};

    // 对端 P2P 状态
    mutable std::shared_mutex states_mutex_;
    std::unordered_map<NodeId, PeerP2PState> peer_states_;

    // 定时器
    asio::steady_timer keepalive_timer_;
    asio::steady_timer punch_timer_;
    asio::steady_timer retry_timer_;
    asio::steady_timer endpoint_refresh_timer_;

    // 端点刷新跟踪
    uint64_t last_endpoint_refresh_time_ = 0;  // 上次端点刷新时间 (微秒)

    // P2P_INIT 序列号
    std::atomic<uint32_t> init_seq_{0};
};

} // namespace edgelink::client

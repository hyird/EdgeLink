#pragma once

#include "common/types.hpp"
#include "common/message.hpp"
#include "common/connection_types.hpp"
#include "common/node_state.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/endpoint_manager.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace asio = boost::asio;

namespace edgelink::client {

// ============================================================================
// P2P 运行时上下文 - 仅用于网络操作，不代表逻辑状态
// ============================================================================
struct PeerP2PContext {
    // P2P_INIT 序列号
    uint32_t init_seq = 0;

    // 对端公钥（用于签名验证）
    std::array<uint8_t, X25519_KEY_SIZE> peer_key{};

    // 对端端点列表（从 P2P_ENDPOINT 消息获取）
    std::vector<Endpoint> peer_endpoints;

    // 当前活跃端点（P2P 连接成功后）
    asio::ip::udp::endpoint active_endpoint;

    // 打洞相关
    uint64_t last_punch_time = 0;   // 开始打洞的时间（微秒）
    uint32_t punch_count = 0;       // 已发送的打洞包数量

    // 心跳相关
    uint64_t last_recv_time = 0;    // 最后收到数据的时间（微秒）
    uint64_t last_send_time = 0;    // 最后发送数据的时间（微秒）
    uint32_t ping_seq = 0;          // Ping 序列号

    // 标记：是否正在进行打洞操作
    bool punching = false;
    // 标记：是否正在等待端点（RESOLVING）
    bool resolving = false;
};

// ============================================================================
// P2P Channels - 用于协程间通信
// ============================================================================
struct P2PChannels {
    // 端点就绪 channel（触发上报给 Controller）
    using EndpointsReadyChannel = asio::experimental::channel<
        void(boost::system::error_code, std::vector<Endpoint>)>;
    EndpointsReadyChannel* endpoints_channel = nullptr;

    // P2P_INIT 请求 channel（请求 Controller 转发）
    using P2PInitChannel = asio::experimental::channel<
        void(boost::system::error_code, P2PInit)>;
    P2PInitChannel* init_channel = nullptr;

    // P2P_STATUS 上报 channel
    using P2PStatusChannel = asio::experimental::channel<
        void(boost::system::error_code, P2PStatusMsg)>;
    P2PStatusChannel* status_channel = nullptr;

    // P2P 数据接收 channel
    using DataChannel = asio::experimental::channel<
        void(boost::system::error_code, NodeId, std::vector<uint8_t>)>;
    DataChannel* data_channel = nullptr;
};

/**
 * P2PManager - P2P NAT 穿透管理器
 *
 * 职责:
 * - 管理 UDP socket 和端点发现
 * - 执行 NAT 打洞操作
 * - 维护 P2P Keepalive
 * - 发送和接收加密的 P2P 数据
 *
 * 注意：
 * - 逻辑状态（P2PConnectionState, PeerDataPath）由 ClientStateMachine 管理
 * - P2PManager 只维护网络操作所需的运行时上下文
 * - 状态变化通过 channel 异步通知
 */
class P2PManager {
public:
    P2PManager(asio::io_context& ioc, CryptoEngine& crypto,
               PeerManager& peers, EndpointManager& endpoints,
               ClientStateMachine& state_machine);
    ~P2PManager();

    // ========================================================================
    // 生命周期
    // ========================================================================

    // 设置配置
    void set_config(const P2PConfig& config);

    // 设置 channels
    void set_channels(P2PChannels channels);

    // 启动 P2P 管理器
    asio::awaitable<bool> start();

    // 停止 P2P 管理器
    asio::awaitable<void> stop();

    // 是否正在运行
    bool is_running() const { return running_.load(); }

    // ========================================================================
    // P2P 连接管理
    // ========================================================================

    // 发起 P2P 连接（异步，需要先上报端点再发送 P2P_INIT）
    asio::awaitable<void> connect_peer(NodeId peer_id);

    // 断开 P2P 连接
    void disconnect_peer(NodeId peer_id);

    // 处理 Controller 返回的 P2P_ENDPOINT
    void handle_p2p_endpoint(const P2PEndpointMsg& msg);

    // ========================================================================
    // 数据发送
    // ========================================================================

    // 发送 P2P 数据（如果已连接）
    // 返回 true 表示通过 P2P 发送，false 表示需要通过 Relay
    asio::awaitable<bool> send_data(NodeId peer_id, std::span<const uint8_t> data);

    // 检查是否可以通过 P2P 发送
    bool is_p2p_connected(NodeId peer_id) const;

    // ========================================================================
    // 端点信息
    // ========================================================================

    // 获取我方所有端点
    std::vector<Endpoint> our_endpoints() const;

private:
    // UDP 接收循环
    asio::awaitable<void> recv_loop();

    // Keepalive 循环
    asio::awaitable<void> keepalive_loop();

    // 打洞超时检测循环
    asio::awaitable<void> punch_timeout_loop();

    // 执行分批打洞
    asio::awaitable<void> do_punch_batches(NodeId peer_id);

    // 重试循环
    asio::awaitable<void> retry_loop();

    // 端点刷新循环
    asio::awaitable<void> endpoint_refresh_loop();

    // 刷新端点
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

    // 上报 P2P 状态给 Controller（通过 channel）
    void report_p2p_status(NodeId peer_id, bool success);

    // 通知端点就绪（通过 channel）
    void notify_endpoints_ready(const std::vector<Endpoint>& endpoints);

    // 请求发送 P2P_INIT（通过 channel）
    void request_p2p_init(const P2PInit& init);

    // 将 Endpoint 转换为 udp::endpoint
    static std::optional<asio::ip::udp::endpoint> to_udp_endpoint(const Endpoint& ep);

    // 获取当前时间（微秒）
    static uint64_t now_us();

    asio::io_context& ioc_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    EndpointManager& endpoints_;
    ClientStateMachine& state_machine_;

    P2PConfig config_;
    P2PChannels channels_;

    std::atomic<bool> running_{false};
    std::atomic<bool> starting_{false};

    // 对端 P2P 运行时上下文（仅用于网络操作）
    mutable std::shared_mutex contexts_mutex_;
    std::unordered_map<NodeId, PeerP2PContext> peer_contexts_;

    // 定时器
    asio::steady_timer keepalive_timer_;
    asio::steady_timer punch_timer_;
    asio::steady_timer retry_timer_;
    asio::steady_timer endpoint_refresh_timer_;

    // P2P_INIT 序列号
    std::atomic<uint32_t> init_seq_{0};
};

} // namespace edgelink::client

// P2PManagerActor - Actor 模式的 P2P 管理器
// 管理 UDP Socket、NAT 穿透、P2P 连接和数据传输

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "common/types.hpp"
#include "common/message.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"
#include "client/endpoint_manager.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <memory>
#include <unordered_map>
#include <variant>

namespace asio = boost::asio;

namespace edgelink::client {

// 导入消息类型
using edgelink::messages::P2PManagerCmd;
using edgelink::messages::P2PManagerEvent;
using edgelink::messages::P2PCmdType;
using edgelink::messages::P2PEventType;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;

// ============================================================================
// P2PManagerActor 状态
// ============================================================================

enum class P2PManagerState : uint8_t {
    STOPPED,    // 未启动
    STARTING,   // 启动中
    RUNNING,    // 运行中
    STOPPING,   // 停止中
};

inline const char* p2p_manager_state_name(P2PManagerState state) {
    switch (state) {
        case P2PManagerState::STOPPED:  return "STOPPED";
        case P2PManagerState::STARTING: return "STARTING";
        case P2PManagerState::RUNNING:  return "RUNNING";
        case P2PManagerState::STOPPING: return "STOPPING";
        default:                        return "UNKNOWN";
    }
}

// ============================================================================
// 对端 P2P 上下文（运行时状态）
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

    // 是否已连接
    bool connected = false;
};

// ============================================================================
// P2PManagerActor - P2P 管理器 Actor
// ============================================================================

// 命令消息类型
using P2PManagerCommand = std::variant<
    P2PManagerCmd,
    LifecycleMessage
>;

class P2PManagerActor : public actor::ActorBase<P2PManagerActor, P2PManagerCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param crypto 加密引擎
    // @param peers 对端管理器
    // @param endpoints 端点管理器
    // @param event_channel 事件输出通道（发送给 ClientActor）- 使用 concurrent_channel 确保线程安全
    P2PManagerActor(
        asio::io_context& ioc,
        CryptoEngine& crypto,
        PeerManager& peers,
        EndpointManager& endpoints,
        asio::experimental::concurrent_channel<void(boost::system::error_code, P2PManagerEvent)>* event_channel);

    virtual ~P2PManagerActor();

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(P2PManagerCommand cmd) override;

    // 状态查询
    P2PManagerState manager_state() const { return manager_state_; }
    bool is_running() const { return manager_state_ == P2PManagerState::RUNNING; }

    // 设置配置
    void set_config(const P2PConfig& config);

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_start_cmd();
    asio::awaitable<void> handle_stop_cmd();
    asio::awaitable<void> handle_connect_peer_cmd(const P2PManagerCmd& cmd);
    asio::awaitable<void> handle_disconnect_peer_cmd(const P2PManagerCmd& cmd);
    asio::awaitable<void> handle_p2p_endpoint_cmd(const P2PManagerCmd& cmd);
    asio::awaitable<void> handle_send_data_cmd(const P2PManagerCmd& cmd);

    // ========================================================================
    // UDP Socket 管理
    // ========================================================================

    // 初始化 UDP Socket
    asio::awaitable<bool> init_udp_socket();

    // 关闭 UDP Socket
    void close_udp_socket();

    // UDP 接收循环
    asio::awaitable<void> recv_loop();

    // 处理收到的 UDP 数据包
    void handle_udp_packet(const asio::ip::udp::endpoint& from,
                           std::span<const uint8_t> data);

    // ========================================================================
    // P2P 协议处理
    // ========================================================================

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

    // ========================================================================
    // P2P 连接管理
    // ========================================================================

    // 开始 NAT 打洞
    asio::awaitable<void> start_punching(NodeId peer_id);

    // 执行分批打洞
    asio::awaitable<void> do_punch_batches(NodeId peer_id);

    // 发送 P2P_PING（用于打洞）
    asio::awaitable<void> send_p2p_ping(NodeId peer_id,
                                        const asio::ip::udp::endpoint& to);

    // 发送 P2P_PONG
    void send_p2p_pong(const P2PPing& ping, const asio::ip::udp::endpoint& to);

    // ========================================================================
    // Keepalive 机制
    // ========================================================================

    // Keepalive 循环
    asio::awaitable<void> keepalive_loop();

    // 发送 P2P_KEEPALIVE
    asio::awaitable<void> send_p2p_keepalive(NodeId peer_id);

    // ========================================================================
    // 端点管理
    // ========================================================================

    // 端点刷新循环
    asio::awaitable<void> endpoint_refresh_loop();

    // 刷新端点
    asio::awaitable<void> refresh_endpoints();

    // ========================================================================
    // 事件发送（到 ClientActor）
    // ========================================================================

    void send_event(P2PManagerEvent event);

    // ========================================================================
    // 工具函数
    // ========================================================================

    // 获取当前时间（微秒）
    static uint64_t now_us();

    // 将 Endpoint 转换为 udp::endpoint
    static std::optional<asio::ip::udp::endpoint> to_udp_endpoint(const Endpoint& ep);

    // ========================================================================
    // 成员变量
    // ========================================================================

    CryptoEngine& crypto_;
    PeerManager& peers_;
    EndpointManager& endpoints_;
    asio::experimental::concurrent_channel<void(boost::system::error_code, P2PManagerEvent)>* event_channel_;

    // 管理器状态
    P2PManagerState manager_state_ = P2PManagerState::STOPPED;

    // 配置
    P2PConfig config_;

    // UDP Socket
    std::unique_ptr<asio::ip::udp::socket> udp_socket_;
    asio::ip::udp::endpoint udp_recv_endpoint_;  // 接收端点（临时）
    std::array<uint8_t, 65536> udp_recv_buffer_; // 接收缓冲区

    // 对端 P2P 上下文
    std::unordered_map<NodeId, PeerP2PContext> peer_contexts_;

    // 循环控制
    std::atomic<bool> recv_loop_running_{false};
    std::atomic<bool> keepalive_loop_running_{false};
    std::atomic<bool> endpoint_refresh_loop_running_{false};

    // 定时器
    asio::steady_timer keepalive_timer_;
    asio::steady_timer endpoint_refresh_timer_;

    // P2P_INIT 序列号
    std::atomic<uint32_t> init_seq_{0};

    // 本地端点（缓存）
    std::vector<Endpoint> local_endpoints_;
};

} // namespace edgelink::client

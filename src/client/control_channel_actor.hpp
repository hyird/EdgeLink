// ControlChannelActor - Actor 模式的控制通道
// 管理与 Controller 的 WebSocket 连接，处理认证、配置、P2P 协商等

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include "client/crypto_engine.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/url.hpp>

#include <memory>
#include <queue>
#include <string>
#include <variant>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;

using tcp = asio::ip::tcp;

namespace edgelink::client {

// 导入消息类型（简化命名空间使用）
using edgelink::messages::ControlChannelCmd;
using edgelink::messages::ControlChannelEvent;
using edgelink::messages::CtrlCmdType;
using edgelink::messages::CtrlEventType;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;

// ============================================================================
// ControlChannelActor 状态
// ============================================================================

enum class ControlChannelState : uint8_t {
    DISCONNECTED,    // 未连接
    CONNECTING,      // 连接中
    AUTHENTICATING,  // 认证中
    CONNECTED,       // 已连接并认证
};

inline const char* control_channel_state_name(ControlChannelState state) {
    switch (state) {
        case ControlChannelState::DISCONNECTED:    return "DISCONNECTED";
        case ControlChannelState::CONNECTING:      return "CONNECTING";
        case ControlChannelState::AUTHENTICATING:  return "AUTHENTICATING";
        case ControlChannelState::CONNECTED:       return "CONNECTED";
        default:                                   return "UNKNOWN";
    }
}

// ============================================================================
// WebSocket 流类型
// ============================================================================

using TlsWsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
using PlainWsStream = websocket::stream<beast::tcp_stream>;

// ============================================================================
// ControlChannelActor - 控制通道 Actor
// ============================================================================

// 命令消息类型（从 ClientActor 或外部接收）
using ControlChannelCommand = std::variant<
    ControlChannelCmd,
    LifecycleMessage
>;

class ControlChannelActor : public actor::ActorBase<ControlChannelActor, ControlChannelCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param ssl_ctx SSL 上下文
    // @param crypto 加密引擎
    // @param event_channel 事件输出通道（发送给 ClientActor）- 使用 concurrent_channel 确保线程安全
    ControlChannelActor(
        asio::io_context& ioc,
        ssl::context& ssl_ctx,
        CryptoEngine& crypto,
        asio::experimental::concurrent_channel<void(boost::system::error_code, ControlChannelEvent)>* event_channel);

    virtual ~ControlChannelActor() = default;

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(ControlChannelCommand cmd) override;

    // 状态查询
    ControlChannelState connection_state() const { return conn_state_; }
    bool is_connected() const { return conn_state_ == ControlChannelState::CONNECTED; }

    // 认证信息（连接后可用）
    NodeId node_id() const { return node_id_; }
    NetworkId network_id() const { return network_id_; }
    IPv4Address virtual_ip() const { return virtual_ip_; }
    uint8_t subnet_mask() const { return subnet_mask_; }
    const std::vector<uint8_t>& relay_token() const { return relay_token_; }

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_connect_cmd(const ControlChannelCmd& cmd);
    asio::awaitable<void> handle_reconnect_cmd();
    asio::awaitable<void> handle_close_cmd();
    asio::awaitable<void> handle_send_ping_cmd();
    asio::awaitable<void> handle_send_endpoint_update_cmd(const ControlChannelCmd& cmd);
    asio::awaitable<void> handle_send_p2p_init_cmd(const ControlChannelCmd& cmd);
    asio::awaitable<void> handle_send_route_announce_cmd(const ControlChannelCmd& cmd);

    // ========================================================================
    // WebSocket 管理
    // ========================================================================

    // 建立 WebSocket 连接
    asio::awaitable<bool> connect_websocket(const std::string& url, const std::string& authkey, bool use_tls);

    // 关闭 WebSocket 连接
    asio::awaitable<void> close_websocket();

    // WebSocket I/O 循环
    asio::awaitable<void> read_loop();
    asio::awaitable<void> write_loop();

    // 检查 WebSocket 是否打开
    bool is_ws_open() const;

    // ========================================================================
    // 帧处理
    // ========================================================================

    asio::awaitable<void> handle_frame(const Frame& frame);
    asio::awaitable<void> handle_auth_response(const Frame& frame);
    asio::awaitable<void> handle_config(const Frame& frame);
    asio::awaitable<void> handle_config_update(const Frame& frame);
    asio::awaitable<void> handle_route_update(const Frame& frame);
    asio::awaitable<void> handle_route_ack(const Frame& frame);
    asio::awaitable<void> handle_p2p_endpoint(const Frame& frame);
    asio::awaitable<void> handle_endpoint_ack(const Frame& frame);
    asio::awaitable<void> handle_pong(const Frame& frame);
    asio::awaitable<void> handle_error(const Frame& frame);

    // ========================================================================
    // 帧发送
    // ========================================================================

    asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload);
    asio::awaitable<void> send_raw(std::span<const uint8_t> data);

    // ========================================================================
    // 事件发送（到 ClientActor）
    // ========================================================================

    void send_event(ControlChannelEvent event);

    // ========================================================================
    // 成员变量
    // ========================================================================

    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    asio::experimental::concurrent_channel<void(boost::system::error_code, ControlChannelEvent)>* event_channel_;

    // 连接状态
    ControlChannelState conn_state_ = ControlChannelState::DISCONNECTED;
    std::string url_;
    std::string authkey_;
    bool use_tls_ = true;

    // WebSocket 流（TLS 或明文）
    std::unique_ptr<TlsWsStream> tls_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;

    // 写队列（批量发送优化）
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // 认证状态
    NodeId node_id_ = 0;
    NetworkId network_id_ = 0;
    IPv4Address virtual_ip_{};
    uint8_t subnet_mask_ = 16;  // 默认 /16
    std::vector<uint8_t> auth_token_;
    std::vector<uint8_t> relay_token_;

    // Ping 跟踪
    uint32_t ping_seq_ = 0;
    uint64_t last_ping_time_ = 0;

    // 路由请求跟踪
    uint32_t route_request_id_ = 0;

    // 端点更新跟踪
    std::atomic<uint32_t> endpoint_request_id_{0};
    uint32_t pending_endpoint_request_id_ = 0;
    std::atomic<bool> endpoint_ack_pending_{false};
    std::vector<Endpoint> pending_endpoints_;
    std::unique_ptr<asio::steady_timer> endpoint_ack_timer_;

    // 读写循环控制
    std::atomic<bool> read_loop_running_{false};
    std::atomic<bool> write_loop_running_{false};
};

} // namespace edgelink::client

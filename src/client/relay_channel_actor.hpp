// RelayChannelActor - Actor 模式的中继通道
// 管理与 Controller 的 Relay WebSocket 连接，处理数据加密转发

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "common/types.hpp"
#include "common/frame.hpp"
#include "common/message.hpp"
#include "client/crypto_engine.hpp"
#include "client/peer_manager.hpp"

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
using edgelink::messages::RelayChannelCmd;
using edgelink::messages::RelayChannelEvent;
using edgelink::messages::RelayCmdType;
using edgelink::messages::RelayEventType;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;

// ============================================================================
// RelayChannelActor 状态
// ============================================================================

enum class RelayChannelState : uint8_t {
    DISCONNECTED,    // 未连接
    CONNECTING,      // 连接中
    AUTHENTICATING,  // 认证中
    CONNECTED,       // 已连接并认证
};

inline const char* relay_channel_state_name(RelayChannelState state) {
    switch (state) {
        case RelayChannelState::DISCONNECTED:    return "DISCONNECTED";
        case RelayChannelState::CONNECTING:      return "CONNECTING";
        case RelayChannelState::AUTHENTICATING:  return "AUTHENTICATING";
        case RelayChannelState::CONNECTED:       return "CONNECTED";
        default:                                 return "UNKNOWN";
    }
}

// ============================================================================
// WebSocket 流类型
// ============================================================================

using TlsWsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
using PlainWsStream = websocket::stream<beast::tcp_stream>;

// ============================================================================
// RelayChannelActor - 中继通道 Actor
// ============================================================================

// 命令消息类型（从 ClientActor 或外部接收）
using RelayChannelCommand = std::variant<
    RelayChannelCmd,
    LifecycleMessage
>;

class RelayChannelActor : public actor::ActorBase<RelayChannelActor, RelayChannelCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param ssl_ctx SSL 上下文
    // @param crypto 加密引擎
    // @param peers 对端管理器
    // @param event_channel 事件输出通道（发送给 ClientActor）- 使用 concurrent_channel 确保线程安全
    RelayChannelActor(
        asio::io_context& ioc,
        ssl::context& ssl_ctx,
        CryptoEngine& crypto,
        PeerManager& peers,
        asio::experimental::concurrent_channel<void(boost::system::error_code, RelayChannelEvent)>* event_channel);

    virtual ~RelayChannelActor() = default;

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(RelayChannelCommand cmd) override;

    // 状态查询
    RelayChannelState connection_state() const { return conn_state_; }
    bool is_connected() const { return conn_state_ == RelayChannelState::CONNECTED; }

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_connect_cmd(const RelayChannelCmd& cmd);
    asio::awaitable<void> handle_close_cmd();
    asio::awaitable<void> handle_send_data_cmd(const RelayChannelCmd& cmd);

    // ========================================================================
    // WebSocket 管理
    // ========================================================================

    // 建立 WebSocket 连接
    asio::awaitable<bool> connect_websocket(const std::string& url,
                                           const std::vector<uint8_t>& relay_token,
                                           bool use_tls);

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
    asio::awaitable<void> handle_relay_auth_resp(const Frame& frame);
    asio::awaitable<void> handle_data(const Frame& frame);
    asio::awaitable<void> handle_pong(const Frame& frame);

    // ========================================================================
    // 帧发送
    // ========================================================================

    asio::awaitable<void> send_frame(FrameType type, std::span<const uint8_t> payload);
    asio::awaitable<void> send_raw(std::span<const uint8_t> data);

    // ========================================================================
    // 事件发送（到 ClientActor）
    // ========================================================================

    void send_event(RelayChannelEvent event);

    // ========================================================================
    // 成员变量
    // ========================================================================

    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    asio::experimental::concurrent_channel<void(boost::system::error_code, RelayChannelEvent)>* event_channel_;

    // 连接状态
    RelayChannelState conn_state_ = RelayChannelState::DISCONNECTED;
    std::string url_;
    std::vector<uint8_t> relay_token_;
    bool use_tls_ = true;

    // WebSocket 流（TLS 或明文）
    std::unique_ptr<TlsWsStream> tls_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;

    // 写队列（批量发送优化）
    std::queue<std::vector<uint8_t>> write_queue_;
    bool writing_ = false;
    asio::steady_timer write_timer_;

    // 读写循环控制
    std::atomic<bool> read_loop_running_{false};
    std::atomic<bool> write_loop_running_{false};
};

} // namespace edgelink::client

// TunDeviceActor - Actor 模式的 TUN 设备管理
// 封装平台相关的 TUN 设备，提供异步数据包收发

#pragma once

#include "common/actor.hpp"
#include "common/actor_messages.hpp"
#include "common/types.hpp"
#include "client/tun_device.hpp"

#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>

#include <memory>
#include <variant>

namespace asio = boost::asio;

namespace edgelink::client {

// 导入消息类型
using edgelink::messages::TunMessage;
using edgelink::messages::TunEvent;
using edgelink::messages::TunMessageType;
using edgelink::messages::TunEventType;
using edgelink::messages::LifecycleMessage;
using edgelink::messages::LifecycleType;

// ============================================================================
// TunDeviceActor 状态
// ============================================================================

enum class TunDeviceState : uint8_t {
    CLOSED,      // 未打开
    OPENING,     // 打开中
    CONFIGURING, // 配置中
    OPEN,        // 已打开并配置完成
    CLOSING,     // 关闭中
};

inline const char* tun_device_state_name(TunDeviceState state) {
    switch (state) {
        case TunDeviceState::CLOSED:      return "CLOSED";
        case TunDeviceState::OPENING:     return "OPENING";
        case TunDeviceState::CONFIGURING: return "CONFIGURING";
        case TunDeviceState::OPEN:        return "OPEN";
        case TunDeviceState::CLOSING:     return "CLOSING";
        default:                          return "UNKNOWN";
    }
}

// ============================================================================
// TunDeviceActor - TUN 设备 Actor
// ============================================================================

// 命令消息类型
using TunDeviceCommand = std::variant<
    TunMessage,
    LifecycleMessage
>;

class TunDeviceActor : public actor::ActorBase<TunDeviceActor, TunDeviceCommand> {
public:
    // 构造函数
    // @param ioc io_context 引用
    // @param event_channel 事件输出通道（发送给 ClientActor）- 使用 concurrent_channel 确保线程安全
    TunDeviceActor(
        asio::io_context& ioc,
        asio::experimental::concurrent_channel<void(boost::system::error_code, TunEvent)>* event_channel);

    virtual ~TunDeviceActor() = default;

    // ActorBase 接口实现
    asio::awaitable<void> on_start() override;
    asio::awaitable<void> on_stop() override;
    asio::awaitable<void> handle_message(TunDeviceCommand cmd) override;

    // 状态查询
    TunDeviceState device_state() const { return device_state_; }
    bool is_open() const { return device_state_ == TunDeviceState::OPEN; }

    // 获取设备名称
    std::string device_name() const;

private:
    // ========================================================================
    // 命令处理
    // ========================================================================

    asio::awaitable<void> handle_open_cmd(const TunMessage& msg);
    asio::awaitable<void> handle_close_cmd();
    asio::awaitable<void> handle_write_packet_cmd(const TunMessage& msg);

    // ========================================================================
    // TUN 设备管理
    // ========================================================================

    // 打开并配置 TUN 设备
    asio::awaitable<bool> open_and_configure(
        const std::string& dev_name,
        const IPv4Address& ip,
        const IPv4Address& netmask,
        uint32_t mtu);

    // 关闭 TUN 设备
    asio::awaitable<void> close_device();

    // TUN 数据包读取循环
    asio::awaitable<void> read_loop();

    // ========================================================================
    // 事件发送（到 ClientActor）
    // ========================================================================

    void send_event(TunEvent event);

    // ========================================================================
    // 成员变量
    // ========================================================================

    asio::experimental::concurrent_channel<void(boost::system::error_code, TunEvent)>* event_channel_;

    // TUN 设备实例 - 使用 shared_ptr 以支持异步操作中的安全访问
    std::shared_ptr<TunDevice> tun_device_;

    // TUN 数据包接收通道（从 TunDevice 读取）
    std::unique_ptr<channels::TunPacketChannel> packet_channel_;

    // 设备状态
    TunDeviceState device_state_ = TunDeviceState::CLOSED;
    std::string device_name_;
    IPv4Address device_ip_;

    // 读循环控制
    std::atomic<bool> read_loop_running_{false};
};

} // namespace edgelink::client

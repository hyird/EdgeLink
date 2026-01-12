// TunDeviceActor 实现

#include "client/tun_device_actor.hpp"
#include "common/logger.hpp"
#include "common/performance_monitor.hpp"

namespace edgelink::client {

namespace {

auto& log() { return Logger::get("client.tun_device"); }

} // anonymous namespace

// ============================================================================
// 构造函数和生命周期
// ============================================================================

TunDeviceActor::TunDeviceActor(
    asio::io_context& ioc,
    asio::experimental::concurrent_channel<void(boost::system::error_code, TunEvent)>* event_channel)
    : ActorBase(ioc, "TunDeviceActor")
    , event_channel_(event_channel) {

    // 创建平台相关的 TUN 设备实例
    tun_device_ = TunDevice::create(ioc);

    // 创建数据包接收通道（容量 128）
    packet_channel_ = std::make_unique<channels::TunPacketChannel>(ioc, 128);
}

asio::awaitable<void> TunDeviceActor::on_start() {
    log().info("[{}] Actor started", name_);

    // 注册性能监控（邮箱队列容量为 64，数据包队列为 128）
    perf::PerformanceMonitor::instance().register_queue("TunDevice.Mailbox", 64);
    perf::PerformanceMonitor::instance().register_queue("TunDevice.PacketQueue", 128);

    co_return;
}

asio::awaitable<void> TunDeviceActor::on_stop() {
    log().info("[{}] Actor stopping", name_);

    // 关闭 TUN 设备
    co_await close_device();

    log().info("[{}] Actor stopped", name_);
}

// ============================================================================
// 消息处理
// ============================================================================

asio::awaitable<void> TunDeviceActor::handle_message(TunDeviceCommand cmd) {
    if (std::holds_alternative<LifecycleMessage>(cmd)) {
        auto& lifecycle = std::get<LifecycleMessage>(cmd);
        log().debug("[{}] Received lifecycle message: type={}", name_, static_cast<int>(lifecycle.type));

        if (lifecycle.type == LifecycleType::STOP) {
            co_await on_stop();
        } else if (lifecycle.type == LifecycleType::START) {
            co_await on_start();
        }
        co_return;
    }

    auto& tun_msg = std::get<TunMessage>(cmd);
    log().debug("[{}] Received TUN message: type={}", name_, static_cast<int>(tun_msg.type));

    switch (tun_msg.type) {
        case TunMessageType::OPEN:
            co_await handle_open_cmd(tun_msg);
            break;

        case TunMessageType::CLOSE:
            co_await handle_close_cmd();
            break;

        case TunMessageType::WRITE_PACKET:
            co_await handle_write_packet_cmd(tun_msg);
            break;

        default:
            log().warn("[{}] Unhandled TUN message type: {}", name_, static_cast<int>(tun_msg.type));
            break;
    }
}

// ============================================================================
// 命令处理
// ============================================================================

asio::awaitable<void> TunDeviceActor::handle_open_cmd(const TunMessage& msg) {
    log().info("[{}] Handling OPEN command: dev_name={}, ip={}, mtu={}",
               name_, msg.dev_name, msg.ip.to_string(), msg.mtu);

    if (device_state_ != TunDeviceState::CLOSED) {
        log().warn("[{}] Cannot open: already opened (state={})",
                   name_, tun_device_state_name(device_state_));

        // 发送错误事件
        TunEvent event;
        event.type = TunEventType::TUN_ERROR;
        event.error_message = "Device already opened";
        send_event(event);
        co_return;
    }

    // 计算子网掩码（简化：假设 /24 网络）
    IPv4Address netmask = IPv4Address::from_u32(0xFFFFFF00);  // 255.255.255.0

    // 打开并配置设备
    bool success = co_await open_and_configure(msg.dev_name, msg.ip, netmask, msg.mtu);

    if (success) {
        log().info("[{}] TUN device opened: name={}, ip={}",
                   name_, device_name_, device_ip_.to_string());

        // 发送成功事件
        TunEvent event;
        event.type = TunEventType::OPENED;
        event.dev_name = device_name_;
        event.ip = device_ip_;
        send_event(event);
    } else {
        log().error("[{}] Failed to open TUN device", name_);

        // 发送错误事件
        TunEvent event;
        event.type = TunEventType::TUN_ERROR;
        event.error_message = "Failed to open TUN device";
        send_event(event);
    }
}

asio::awaitable<void> TunDeviceActor::handle_close_cmd() {
    log().info("[{}] Handling CLOSE command", name_);

    co_await close_device();

    // 发送关闭事件
    TunEvent event;
    event.type = TunEventType::CLOSED;
    send_event(event);
}

asio::awaitable<void> TunDeviceActor::handle_write_packet_cmd(const TunMessage& msg) {
    PERF_MEASURE_LATENCY("TunDevice.WritePacket");

    if (device_state_ != TunDeviceState::OPEN) {
        log().warn("[{}] Cannot write packet: device not open (state={})",
                   name_, tun_device_state_name(device_state_));
        co_return;
    }

    if (!tun_device_ || !tun_device_->is_open()) {
        log().error("[{}] TUN device is not open", name_);
        co_return;
    }

    if (!msg.packet || msg.packet->empty()) {
        log().warn("[{}] Cannot write empty packet", name_);
        co_return;
    }

    // 异步写入数据包
    try {
        auto result = co_await tun_device_->async_write(*msg.packet);

        if (!result) {
            log().error("[{}] Failed to write packet: {}",
                        name_, tun_error_message(result.error()));
            PERF_INCREMENT("TunDevice.WriteErrors");

            // 发送错误事件
            TunEvent event;
            event.type = TunEventType::TUN_ERROR;
            event.error_message = tun_error_message(result.error());
            send_event(event);
        } else {
            log().debug("[{}] Packet written: {} bytes", name_, msg.packet->size());
            PERF_INCREMENT("TunDevice.PacketsWritten");
            PERF_ADD("TunDevice.BytesWritten", msg.packet->size());
        }
    } catch (const std::exception& e) {
        log().error("[{}] Exception writing packet: {}", name_, e.what());
        PERF_INCREMENT("TunDevice.WriteErrors");

        TunEvent event;
        event.type = TunEventType::TUN_ERROR;
        event.error_message = e.what();
        send_event(event);
    }
}

// ============================================================================
// TUN 设备管理
// ============================================================================

asio::awaitable<bool> TunDeviceActor::open_and_configure(
    const std::string& dev_name,
    const IPv4Address& ip,
    const IPv4Address& netmask,
    uint32_t mtu) {

    device_state_ = TunDeviceState::OPENING;

    // 打开设备
    auto open_result = tun_device_->open(dev_name);
    if (!open_result) {
        log().error("[{}] Failed to open TUN device: {}",
                    name_, tun_error_message(open_result.error()));
        device_state_ = TunDeviceState::CLOSED;
        co_return false;
    }

    device_name_ = tun_device_->name();
    log().info("[{}] TUN device opened: {}", name_, device_name_);

    device_state_ = TunDeviceState::CONFIGURING;

    // 配置 IP 地址
    auto config_result = tun_device_->configure(ip, netmask, mtu);
    if (!config_result) {
        log().error("[{}] Failed to configure TUN device: {}",
                    name_, tun_error_message(config_result.error()));
        tun_device_->close();
        device_state_ = TunDeviceState::CLOSED;
        co_return false;
    }

    device_ip_ = ip;
    log().info("[{}] TUN device configured: ip={}, netmask={}, mtu={}",
               name_, ip.to_string(), netmask.to_string(), mtu);

    device_state_ = TunDeviceState::OPEN;

    // 设置数据包通道
    tun_device_->set_packet_channel(packet_channel_.get());

    // 启动读循环
    tun_device_->start_read();
    read_loop_running_.store(true);

    // 在独立协程中启动读循环
    asio::co_spawn(
        ioc_,
        [this]() -> asio::awaitable<void> {
            co_await read_loop();
        },
        asio::detached);

    co_return true;
}

asio::awaitable<void> TunDeviceActor::close_device() {
    if (device_state_ == TunDeviceState::CLOSED) {
        co_return;
    }

    log().info("[{}] Closing TUN device: {}", name_, device_name_);
    device_state_ = TunDeviceState::CLOSING;

    // 停止读循环
    read_loop_running_.store(false);

    if (tun_device_) {
        tun_device_->stop_read();
    }

    // 关闭数据包通道
    if (packet_channel_) {
        packet_channel_->close();
    }

    // 关闭设备
    if (tun_device_ && tun_device_->is_open()) {
        tun_device_->close();
        log().info("[{}] TUN device closed: {}", name_, device_name_);
    }

    device_state_ = TunDeviceState::CLOSED;
    device_name_.clear();
    device_ip_ = IPv4Address{};

    co_return;
}

asio::awaitable<void> TunDeviceActor::read_loop() {
    log().info("[{}] TUN read loop started", name_);

    while (read_loop_running_.load() && packet_channel_) {
        try {
            // 从 TUN 设备读取数据包
            auto packet = co_await packet_channel_->async_receive(asio::use_awaitable);

            if (packet.empty()) {
                log().debug("[{}] Received empty packet, skipping", name_);
                continue;
            }

            log().debug("[{}] Received packet: {} bytes", name_, packet.size());

            // 性能统计
            PERF_INCREMENT("TunDevice.PacketsRead");
            PERF_ADD("TunDevice.BytesRead", packet.size());

            // 解析目标 IP
            IPv4Address dst_ip = ip_packet::dst_ipv4(packet);

            // 发送数据包事件
            TunEvent event;
            event.type = TunEventType::PACKET_RECEIVED;
            event.packet = std::make_shared<std::vector<uint8_t>>(std::move(packet));
            event.dst_ip = dst_ip;
            send_event(event);

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted ||
                e.code() == asio::experimental::error::channel_closed) {
                log().info("[{}] TUN read loop stopped: {}", name_, e.what());
                break;
            }

            log().error("[{}] TUN read error: {}", name_, e.what());
            PERF_INCREMENT("TunDevice.ReadErrors");

            // 发送错误事件
            TunEvent event;
            event.type = TunEventType::TUN_ERROR;
            event.error_message = e.what();
            send_event(event);

            // 继续读取（可能是临时错误）
            continue;

        } catch (const std::exception& e) {
            log().error("[{}] Unexpected error in read loop: {}", name_, e.what());
            PERF_INCREMENT("TunDevice.ReadErrors");

            TunEvent event;
            event.type = TunEventType::TUN_ERROR;
            event.error_message = e.what();
            send_event(event);

            break;
        }
    }

    read_loop_running_.store(false);
    log().info("[{}] TUN read loop stopped", name_);
    co_return;
}

// ============================================================================
// 事件发送
// ============================================================================

void TunDeviceActor::send_event(TunEvent event) {
    if (event_channel_) {
        event_channel_->try_send(boost::system::error_code{}, event);
    }
}

// ============================================================================
// 工具函数
// ============================================================================

std::string TunDeviceActor::device_name() const {
    return device_name_;
}

} // namespace edgelink::client

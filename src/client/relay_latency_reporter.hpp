#pragma once

#include "client/multi_relay_manager.hpp"
#include "common/message.hpp"
#include <memory>
#include <functional>
#include <chrono>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/cobalt.hpp>
#include <boost/cobalt/channel.hpp>

namespace cobalt = boost::cobalt;

namespace edgelink::client {

// 配置
struct RelayLatencyReporterConfig {
    std::chrono::seconds report_interval{30};  // 上报间隔
    std::chrono::seconds initial_delay{5};     // 首次上报延迟（等待连接稳定）
};

// RelayLatencyReporter - 收集并上报 Client->Relay 延迟
class RelayLatencyReporter {
public:
    using ReportCallback = std::function<void(const RelayLatencyReport&)>;

    RelayLatencyReporter(asio::io_context& ioc,
                         MultiRelayManager& relay_mgr,
                         const RelayLatencyReporterConfig& config = {});

    // 启动上报循环
    cobalt::task<void> start();

    // 停止上报循环
    cobalt::task<void> stop();

    // 设置上报回调（用于发送 RELAY_LATENCY_REPORT）
    void set_report_callback(ReportCallback callback);

    // 获取最新的测量报告
    RelayLatencyReport get_report() const;

    // 立即上报一次
    void report_now();

private:
    cobalt::task<void> report_loop();

    asio::io_context& ioc_;
    MultiRelayManager& relay_mgr_;
    RelayLatencyReporterConfig config_;
    ReportCallback report_callback_;

    bool running_ = false;
    std::unique_ptr<asio::steady_timer> report_timer_;

    // 停止同步
    using CompletionChannel = cobalt::channel<void>;
    std::unique_ptr<CompletionChannel> report_done_ch_;
};

} // namespace edgelink::client

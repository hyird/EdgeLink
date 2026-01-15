#include "client/peer_latency_measurer.hpp"
#include "common/logger.hpp"
#include "common/math_utils.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace edgelink::client {

namespace {
auto& log() {
    static auto& logger = Logger::get("latency_measurer");
    return logger;
}
} // anonymous namespace

PeerLatencyMeasurer::PeerLatencyMeasurer(
    asio::io_context& ioc,
    MultiRelayManager& relay_mgr,
    PeerManager& peers,
    const LatencyMeasureConfig& config)
    : ioc_(ioc)
    , relay_mgr_(relay_mgr)
    , peers_(peers)
    , config_(config) {
}

asio::awaitable<void> PeerLatencyMeasurer::start() {
    if (running_) {
        co_return;
    }

    running_ = true;
    measure_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    report_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    measure_done_ch_ = std::make_unique<CompletionChannel>(ioc_, 1);
    report_done_ch_ = std::make_unique<CompletionChannel>(ioc_, 1);

    log().info("Starting peer latency measurer (measure interval: {}s, report interval: {}s)",
               config_.measure_interval.count(), config_.report_interval.count());

    // 启动测量和上报循环
    asio::co_spawn(ioc_, measure_loop(), asio::detached);
    asio::co_spawn(ioc_, report_loop(), asio::detached);
}

asio::awaitable<void> PeerLatencyMeasurer::stop() {
    if (!running_) {
        co_return;
    }

    running_ = false;

    // 取消定时器并等待循环退出（添加超时保护避免卡住）
    if (measure_timer_) {
        measure_timer_->cancel();
        if (measure_done_ch_) {
            try {
                // 使用轮询方式避免 parallel_group 导致的 TLS allocator 崩溃
                asio::steady_timer timeout_timer(ioc_);
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                bool loop_stopped = false;

                while (!loop_stopped && std::chrono::steady_clock::now() < deadline) {
                    measure_done_ch_->try_receive([&](boost::system::error_code) {
                        loop_stopped = true;
                    });

                    if (loop_stopped) {
                        break;
                    }

                    timeout_timer.expires_after(std::chrono::milliseconds(50));
                    co_await timeout_timer.async_wait(asio::use_awaitable);
                }

                if (loop_stopped) {
                    log().debug("Measure loop confirmed stopped");
                } else {
                    log().warn("Measure loop stop timeout (2s), forcing shutdown");
                }
            } catch (...) {
                log().debug("Failed to wait for measure loop completion");
            }
        }
    }

    if (report_timer_) {
        report_timer_->cancel();
        if (report_done_ch_) {
            try {
                // 使用轮询方式避免 parallel_group 导致的 TLS allocator 崩溃
                asio::steady_timer timeout_timer(ioc_);
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                bool loop_stopped = false;

                while (!loop_stopped && std::chrono::steady_clock::now() < deadline) {
                    report_done_ch_->try_receive([&](boost::system::error_code) {
                        loop_stopped = true;
                    });

                    if (loop_stopped) {
                        break;
                    }

                    timeout_timer.expires_after(std::chrono::milliseconds(50));
                    co_await timeout_timer.async_wait(asio::use_awaitable);
                }

                if (loop_stopped) {
                    log().debug("Report loop confirmed stopped");
                } else {
                    log().warn("Report loop stop timeout (2s), forcing shutdown");
                }
            } catch (...) {
                log().debug("Failed to wait for report loop completion");
            }
        }
    }

    log().info("Peer latency measurer stopped");
}

void PeerLatencyMeasurer::set_report_callback(ReportCallback callback) {
    report_callback_ = std::move(callback);
}

PeerPathReport PeerLatencyMeasurer::get_report() const {
    PeerPathReport report;
    report.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::shared_lock lock(mutex_);
    report.entries.reserve(measurements_.size());

    for (const auto& [key, measurement] : measurements_) {
        PeerPathReportEntry entry;
        entry.peer_node_id = measurement.peer_node_id;
        entry.relay_id = measurement.relay_id;
        entry.connection_id = measurement.connection_id;
        entry.latency_ms = measurement.latency_ms;
        entry.packet_loss = measurement.packet_loss;
        report.entries.push_back(entry);
    }

    return report;
}

std::optional<uint16_t> PeerLatencyMeasurer::get_latency(
    NodeId peer_id, ServerId relay_id) const {

    std::shared_lock lock(mutex_);
    auto it = measurements_.find({peer_id, relay_id});
    if (it != measurements_.end()) {
        return it->second.latency_ms;
    }
    return std::nullopt;
}

void PeerLatencyMeasurer::record_pong(
    NodeId peer_id, uint32_t seq, uint64_t send_time) {

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    uint16_t rtt = static_cast<uint16_t>(std::min<uint64_t>(now - send_time, 65535));

    // 从 pending_pings_ 查找并验证这是我们的 PING
    std::lock_guard lock(ping_mutex_);
    auto it = pending_pings_.find(seq);
    if (it == pending_pings_.end()) {
        // 不是我们的 PING，可能是 Client::ping_peer() 发的
        return;
    }

    auto& pending = it->second;

    // 验证 peer_id 匹配
    if (pending.peer_id != peer_id) {
        log().warn("PONG peer_id mismatch: expected {}, got {}", pending.peer_id, peer_id);
        pending_pings_.erase(it);
        return;
    }

    // 更新延迟测量
    update_latency(pending.peer_id, pending.relay_id, pending.connection_id, rtt);

    log().trace("Recorded PONG: peer={}, relay={}, rtt={}ms",
                pending.peer_id, pending.relay_id, rtt);

    // 清理 pending ping
    pending_pings_.erase(it);
}

asio::awaitable<void> PeerLatencyMeasurer::measure_loop() {
    // 首次启动延迟 5 秒
    measure_timer_->expires_after(std::chrono::seconds(5));
    co_await measure_timer_->async_wait(asio::use_awaitable);

    while (running_) {
        try {
            co_await measure_all_paths();

            measure_timer_->expires_after(config_.measure_interval);
            co_await measure_timer_->async_wait(asio::use_awaitable);

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                break;
            }
            log().warn("Measure loop error: {}", e.what());
        }
    }

    log().debug("Measure loop stopped");

    // 通知 stop() 循环已完成
    if (measure_done_ch_) {
        measure_done_ch_->try_send(boost::system::error_code{});
    }
}

asio::awaitable<void> PeerLatencyMeasurer::report_loop() {
    // 首次启动延迟 10 秒
    report_timer_->expires_after(std::chrono::seconds(10));
    co_await report_timer_->async_wait(asio::use_awaitable);

    while (running_) {
        try {
            // 生成报告
            auto report = get_report();

            if (!report.entries.empty() && report_callback_) {
                log().info("Sending PEER_PATH_REPORT with {} entries",
                           report.entries.size());
                report_callback_(report);
            }

            report_timer_->expires_after(config_.report_interval);
            co_await report_timer_->async_wait(asio::use_awaitable);

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                break;
            }
            log().warn("Report loop error: {}", e.what());
        }
    }

    log().debug("Report loop stopped");

    // 通知 stop() 循环已完成
    if (report_done_ch_) {
        report_done_ch_->try_send(boost::system::error_code{});
    }
}

asio::awaitable<void> PeerLatencyMeasurer::measure_all_paths() {
    // 获取所有 Peer
    auto all_peers = peers_.get_all_peers();
    if (all_peers.empty()) {
        log().trace("No peers to measure");
        co_return;
    }

    // 获取所有 Relay 连接池
    auto relay_pools = relay_mgr_.all_relay_pools();
    if (relay_pools.empty()) {
        log().trace("No relay pools available");
        co_return;
    }

    log().debug("Measuring latency for {} peer(s) via {} relay(s)",
                all_peers.size(), relay_pools.size());

    // 测量所有 (peer, relay) 组合
    for (const auto& peer : all_peers) {
        for (const auto& pool : relay_pools) {
            try {
                auto latency = co_await measure_single_path(peer.info.node_id, pool);
                if (latency > 0) {
                    update_latency(peer.info.node_id, pool->relay_id(),
                                  pool->active_connection_id(), latency);
                }
            } catch (const std::exception& e) {
                log().trace("Failed to measure peer {} via relay {}: {}",
                            peer.info.node_id, pool->relay_id(), e.what());
            }
        }
    }
}

asio::awaitable<uint16_t> PeerLatencyMeasurer::measure_single_path(
    NodeId peer_id,
    std::shared_ptr<RelayConnectionPool> relay_pool) {

    // 获取活跃连接
    auto channel = relay_pool->active_connection();
    if (!channel || !channel->is_connected()) {
        co_return 0;
    }

    auto relay_id = relay_pool->relay_id();
    auto conn_id = relay_pool->active_connection_id();

    // 生成唯一的 sequence number，编码 relay_id 以便在 PONG 响应时识别
    // 格式: (relay_id << 24) | (local_seq & 0xFFFFFF)
    // 这样可以支持 16777216 个并发 ping，足够使用
    uint32_t local_seq = ++ping_seq_;
    uint32_t seq = (static_cast<uint32_t>(relay_id & 0xFF) << 24) | (local_seq & 0xFFFFFF);

    // 生成 PING 消息
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::vector<uint8_t> ping_msg(13);
    ping_msg[0] = 0xEE;  // ping request
    ping_msg[1] = (seq >> 24) & 0xFF;
    ping_msg[2] = (seq >> 16) & 0xFF;
    ping_msg[3] = (seq >> 8) & 0xFF;
    ping_msg[4] = seq & 0xFF;
    ping_msg[5] = (now >> 56) & 0xFF;
    ping_msg[6] = (now >> 48) & 0xFF;
    ping_msg[7] = (now >> 40) & 0xFF;
    ping_msg[8] = (now >> 32) & 0xFF;
    ping_msg[9] = (now >> 24) & 0xFF;
    ping_msg[10] = (now >> 16) & 0xFF;
    ping_msg[11] = (now >> 8) & 0xFF;
    ping_msg[12] = now & 0xFF;

    // 记录 pending ping
    {
        std::lock_guard lock(ping_mutex_);
        pending_pings_[seq] = PendingPing{peer_id, relay_id, conn_id, now};
    }

    // 通过指定 Relay 发送 PING
    bool sent = co_await channel->send_data(peer_id, ping_msg);
    if (!sent) {
        std::lock_guard lock(ping_mutex_);
        pending_pings_.erase(seq);
        co_return 0;
    }

    log().trace("Ping sent to peer {} via relay {} (seq={})", peer_id, relay_id, seq);

    // 等待 PONG 响应（超时时间）
    asio::steady_timer timer(ioc_);
    timer.expires_after(std::chrono::milliseconds(config_.ping_timeout_ms));

    try {
        co_await timer.async_wait(asio::use_awaitable);
    } catch (...) {
        // 超时，清理 pending ping
        std::lock_guard lock(ping_mutex_);
        pending_pings_.erase(seq);
        log().trace("Ping timeout for peer {} via relay {}", peer_id, relay_id);
        co_return 0;
    }

    // 超时后检查是否收到响应（record_pong 可能已经处理）
    {
        std::lock_guard lock(ping_mutex_);
        auto it = pending_pings_.find(seq);
        if (it != pending_pings_.end()) {
            // 未收到响应
            pending_pings_.erase(it);
            co_return 0;
        }
    }

    // 响应已收到，从 measurements_ 读取延迟
    std::shared_lock lock(mutex_);
    auto key = std::make_pair(peer_id, relay_id);
    auto it = measurements_.find(key);
    if (it != measurements_.end()) {
        co_return it->second.latency_ms;
    }

    co_return 0;
}

void PeerLatencyMeasurer::update_latency(
    NodeId peer_id, ServerId relay_id,
    ConnectionId conn_id, uint16_t latency_ms) {

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::unique_lock lock(mutex_);

    auto key = std::make_pair(peer_id, relay_id);
    auto& measurement = measurements_[key];

    measurement.peer_node_id = peer_id;
    measurement.relay_id = relay_id;
    measurement.connection_id = conn_id;
    measurement.last_update = now;
    measurement.sample_count++;


    // 使用指数移动平均更新延迟
    measurement.latency_ms = exponential_moving_average(measurement.latency_ms, latency_ms);

    log().trace("Updated latency: peer={}, relay={}, latency={}ms",
                peer_id, relay_id, measurement.latency_ms);
}

} // namespace edgelink::client

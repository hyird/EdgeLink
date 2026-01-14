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

    log().info("Starting peer latency measurer (measure interval: {}s, report interval: {}s)",
               config_.measure_interval.count(), config_.report_interval.count());

    // 启动测量和上报循环
    asio::co_spawn(ioc_, measure_loop(), asio::detached);
    asio::co_spawn(ioc_, report_loop(), asio::detached);
}

void PeerLatencyMeasurer::stop() {
    if (!running_) {
        return;
    }

    running_ = false;

    if (measure_timer_) {
        measure_timer_->cancel();
    }
    if (report_timer_) {
        report_timer_->cancel();
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
    NodeId peer_id, ServerId relay_id,
    ConnectionId conn_id, uint64_t send_time) {

    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    uint16_t rtt = static_cast<uint16_t>(now - send_time);

    update_latency(peer_id, relay_id, conn_id, rtt);

    log().trace("Recorded PONG: peer={}, relay={}, rtt={}ms",
                peer_id, relay_id, rtt);
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

    // TODO: 通过 Relay 发送 PING 给目标 Peer，等待 PONG
    // 这需要 RelayChannel 支持 peer-to-peer PING
    // 目前返回估算值（基于 Relay 连接的 RTT）

    auto stats = relay_pool->get_stats(relay_pool->active_connection_id());
    if (stats) {
        // 估算：Relay RTT * 2（A→Relay + Relay→B）
        co_return stats->avg_rtt_ms * 2;
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

#include "client/relay_latency_reporter.hpp"
#include "common/logger.hpp"
#include "common/cobalt_utils.hpp"

namespace cobalt = boost::cobalt;

namespace edgelink::client {

namespace {
auto& log() {
    static auto& logger = Logger::get("relay_latency_reporter");
    return logger;
}
} // anonymous namespace

RelayLatencyReporter::RelayLatencyReporter(
    asio::io_context& ioc,
    MultiRelayManager& relay_mgr,
    const RelayLatencyReporterConfig& config)
    : ioc_(ioc)
    , relay_mgr_(relay_mgr)
    , config_(config) {
}

cobalt::task<void> RelayLatencyReporter::start() {
    if (running_) {
        co_return;
    }

    running_ = true;
    report_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    report_done_ch_ = std::make_unique<CompletionChannel>(1, ioc_.get_executor());

    log().info("Starting relay latency reporter (interval: {}s, initial_delay: {}s)",
               config_.report_interval.count(), config_.initial_delay.count());

    cobalt_utils::spawn_task(ioc_.get_executor(), report_loop());
}

cobalt::task<void> RelayLatencyReporter::stop() {
    if (!running_) {
        co_return;
    }

    running_ = false;

    if (report_timer_) {
        report_timer_->cancel();

        if (report_done_ch_) {
            try {
                auto read_report_done = [this]() -> cobalt::task<void> {
                    auto [ec] = co_await cobalt::as_tuple(report_done_ch_->read());
                    (void)ec;
                };
                asio::steady_timer report_timeout_timer(co_await cobalt::this_coro::executor, std::chrono::seconds(2));
                co_await cobalt::race(read_report_done(), report_timeout_timer.async_wait(cobalt::use_op));
                log().debug("Report loop confirmed stopped");
            } catch (...) {
                log().debug("Failed to wait for report loop completion");
            }
        }
    }

    log().info("Relay latency reporter stopped");
}

void RelayLatencyReporter::set_report_callback(ReportCallback callback) {
    report_callback_ = std::move(callback);
}

RelayLatencyReport RelayLatencyReporter::get_report() const {
    RelayLatencyReport report;
    report.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    auto pools = relay_mgr_.all_relay_pools();
    for (const auto& pool : pools) {
        auto conn_id = pool->active_connection_id();
        if (conn_id == 0) {
            continue;
        }

        auto stats = pool->get_stats(conn_id);
        if (!stats) {
            continue;
        }

        RelayLatencyReportEntry entry;
        entry.relay_id = pool->relay_id();
        entry.connection_id = conn_id;
        entry.latency_ms = stats->avg_rtt_ms;
        entry.packet_loss = stats->packet_loss_percent;

        report.entries.push_back(entry);
    }

    return report;
}

void RelayLatencyReporter::report_now() {
    if (!report_callback_) {
        return;
    }

    auto report = get_report();
    if (!report.entries.empty()) {
        log().info("Sending RELAY_LATENCY_REPORT with {} entries", report.entries.size());
        for (const auto& entry : report.entries) {
            log().debug("  Relay {}: {}ms (conn=0x{:08x})",
                        entry.relay_id, entry.latency_ms, entry.connection_id);
        }
        report_callback_(report);
    }
}

cobalt::task<void> RelayLatencyReporter::report_loop() {
    // 首次上报延迟
    report_timer_->expires_after(config_.initial_delay);
    try {
        co_await report_timer_->async_wait(cobalt::use_op);
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::error::operation_aborted) {
            goto cleanup;
        }
    }

    while (running_) {
        try {
            // 生成并发送报告
            if (report_callback_) {
                auto report = get_report();
                if (!report.entries.empty()) {
                    log().info("Sending RELAY_LATENCY_REPORT with {} entries",
                               report.entries.size());
                    for (const auto& entry : report.entries) {
                        log().debug("  Relay {}: {}ms (conn=0x{:08x})",
                                    entry.relay_id, entry.latency_ms, entry.connection_id);
                    }
                    report_callback_(report);
                } else {
                    log().trace("No relay connections to report");
                }
            }

            report_timer_->expires_after(config_.report_interval);
            co_await report_timer_->async_wait(cobalt::use_op);

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                break;
            }
            log().warn("Report loop error: {}", e.what());
        }
    }

cleanup:
    log().debug("Report loop stopped");

    if (report_done_ch_) {
        co_await cobalt::as_tuple(report_done_ch_->write());
    }
}

} // namespace edgelink::client

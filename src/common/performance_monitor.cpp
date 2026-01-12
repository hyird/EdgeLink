// EdgeLink 性能监控实现

#include "common/performance_monitor.hpp"
#include <sstream>
#include <iomanip>

namespace edgelink::perf {

std::string PerformanceMonitor::get_summary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;

    oss << "\n=== EdgeLink Performance Summary ===\n\n";

    // 计数器
    if (!counters_.empty()) {
        oss << "Counters:\n";
        for (const auto& [name, counter] : counters_) {
            oss << "  " << std::left << std::setw(40) << name
                << ": " << counter.get() << "\n";
        }
        oss << "\n";
    }

    // 延迟统计
    if (!latencies_.empty()) {
        oss << "Latencies (microseconds):\n";
        oss << "  " << std::left << std::setw(40) << "Name"
            << std::right << std::setw(10) << "Count"
            << std::setw(12) << "Min"
            << std::setw(12) << "Avg"
            << std::setw(12) << "Max" << "\n";
        oss << "  " << std::string(86, '-') << "\n";

        for (const auto& [name, stats] : latencies_) {
            if (stats.count() > 0) {
                oss << "  " << std::left << std::setw(40) << name
                    << std::right << std::setw(10) << stats.count()
                    << std::setw(12) << stats.min_us()
                    << std::setw(12) << stats.avg_us()
                    << std::setw(12) << stats.max_us() << "\n";
            }
        }
        oss << "\n";
    }

    // 队列统计
    if (!queues_.empty()) {
        oss << "Queue Stats:\n";
        oss << "  " << std::left << std::setw(30) << "Name"
            << std::right << std::setw(10) << "Capacity"
            << std::setw(10) << "Current"
            << std::setw(10) << "Usage%"
            << std::setw(12) << "Enqueued"
            << std::setw(12) << "Dequeued"
            << std::setw(10) << "Drops"
            << std::setw(10) << "HWM Hits" << "\n";
        oss << "  " << std::string(104, '-') << "\n";

        for (const auto& [name, stats_ptr] : queues_) {
            const auto& stats = *stats_ptr;
            oss << "  " << std::left << std::setw(30) << name
                << std::right << std::setw(10) << stats.capacity
                << std::setw(10) << stats.current_size.load()
                << std::setw(9) << std::fixed << std::setprecision(1)
                << (stats.usage_ratio() * 100) << "%"
                << std::setw(12) << stats.total_enqueued.load()
                << std::setw(12) << stats.total_dequeued.load()
                << std::setw(10) << stats.drops.load()
                << std::setw(10) << stats.high_watermark_hits.load() << "\n";
        }
        oss << "\n";
    }

    oss << "====================================\n";
    return oss.str();
}

void PerformanceMonitor::reset_all() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [name, counter] : counters_) {
        counter.reset();
    }

    for (auto& [name, stats] : latencies_) {
        stats.reset();
    }

    // 队列统计不重置（保留当前状态）
}

} // namespace edgelink::perf

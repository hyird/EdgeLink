// EdgeLink 性能监控
// 跟踪关键性能指标

#pragma once

#include "common/performance_config.hpp"
#include <atomic>
#include <chrono>
#include <string>
#include <unordered_map>
#include <mutex>

namespace edgelink::perf {

// ============================================================================
// 性能计数器
// ============================================================================

class PerformanceCounter {
public:
    void increment() { count_.fetch_add(1, std::memory_order_relaxed); }
    void add(uint64_t value) { count_.fetch_add(value, std::memory_order_relaxed); }
    uint64_t get() const { return count_.load(std::memory_order_relaxed); }
    void reset() { count_.store(0, std::memory_order_relaxed); }

private:
    std::atomic<uint64_t> count_{0};
};

// ============================================================================
// 延迟统计
// ============================================================================

class LatencyStats {
public:
    void record(std::chrono::microseconds latency) {
        auto us = latency.count();
        count_.fetch_add(1, std::memory_order_relaxed);
        total_.fetch_add(us, std::memory_order_relaxed);

        // 更新最小值
        uint64_t current_min = min_.load(std::memory_order_relaxed);
        while (us < current_min) {
            if (min_.compare_exchange_weak(current_min, us, std::memory_order_relaxed)) {
                break;
            }
        }

        // 更新最大值
        uint64_t current_max = max_.load(std::memory_order_relaxed);
        while (us > current_max) {
            if (max_.compare_exchange_weak(current_max, us, std::memory_order_relaxed)) {
                break;
            }
        }
    }

    uint64_t count() const { return count_.load(std::memory_order_relaxed); }
    uint64_t min_us() const { return min_.load(std::memory_order_relaxed); }
    uint64_t max_us() const { return max_.load(std::memory_order_relaxed); }
    uint64_t avg_us() const {
        auto c = count();
        return c > 0 ? total_.load(std::memory_order_relaxed) / c : 0;
    }

    void reset() {
        count_.store(0, std::memory_order_relaxed);
        total_.store(0, std::memory_order_relaxed);
        min_.store(UINT64_MAX, std::memory_order_relaxed);
        max_.store(0, std::memory_order_relaxed);
    }

private:
    std::atomic<uint64_t> count_{0};
    std::atomic<uint64_t> total_{0};
    std::atomic<uint64_t> min_{UINT64_MAX};
    std::atomic<uint64_t> max_{0};
};

// ============================================================================
// 队列监控
// ============================================================================

struct QueueStats {
    size_t capacity;
    std::atomic<size_t> current_size{0};
    std::atomic<uint64_t> total_enqueued{0};
    std::atomic<uint64_t> total_dequeued{0};
    std::atomic<uint64_t> drops{0};
    std::atomic<uint64_t> high_watermark_hits{0};

    QueueStats(size_t cap) : capacity(cap) {}

    // 禁止拷贝和移动（因为包含原子变量）
    QueueStats(const QueueStats&) = delete;
    QueueStats& operator=(const QueueStats&) = delete;
    QueueStats(QueueStats&&) = delete;
    QueueStats& operator=(QueueStats&&) = delete;

    void on_enqueue() {
        current_size.fetch_add(1, std::memory_order_relaxed);
        total_enqueued.fetch_add(1, std::memory_order_relaxed);

        if (is_high_watermark(current_size.load(), capacity)) {
            high_watermark_hits.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void on_dequeue() {
        current_size.fetch_sub(1, std::memory_order_relaxed);
        total_dequeued.fetch_add(1, std::memory_order_relaxed);
    }

    void on_drop() {
        drops.fetch_add(1, std::memory_order_relaxed);
    }

    float usage_ratio() const {
        return queue_usage_ratio(current_size.load(), capacity);
    }
};

// ============================================================================
// 性能监控器（全局单例）
// ============================================================================

class PerformanceMonitor {
public:
    static PerformanceMonitor& instance() {
        static PerformanceMonitor monitor;
        return monitor;
    }

    // 禁止拷贝和移动
    PerformanceMonitor(const PerformanceMonitor&) = delete;
    PerformanceMonitor& operator=(const PerformanceMonitor&) = delete;

    // ========================================================================
    // 计数器
    // ========================================================================

    PerformanceCounter& counter(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        return counters_[name];
    }

    // ========================================================================
    // 延迟统计
    // ========================================================================

    LatencyStats& latency(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        return latencies_[name];
    }

    // ========================================================================
    // 队列统计
    // ========================================================================

    void register_queue(const std::string& name, size_t capacity) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queues_.find(name) == queues_.end()) {
            queues_.emplace(name, std::make_unique<QueueStats>(capacity));
        }
    }

    QueueStats* get_queue(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = queues_.find(name);
        return it != queues_.end() ? it->second.get() : nullptr;
    }

    // ========================================================================
    // 报告
    // ========================================================================

    std::string get_summary() const;
    void reset_all();

private:
    PerformanceMonitor() = default;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PerformanceCounter> counters_;
    std::unordered_map<std::string, LatencyStats> latencies_;
    std::unordered_map<std::string, std::unique_ptr<QueueStats>> queues_;
};

// ============================================================================
// RAII 延迟测量
// ============================================================================

class ScopedLatencyMeasure {
public:
    ScopedLatencyMeasure(const std::string& name)
        : name_(name), start_(std::chrono::steady_clock::now()) {}

    ~ScopedLatencyMeasure() {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_);
        PerformanceMonitor::instance().latency(name_).record(duration);
    }

private:
    std::string name_;
    std::chrono::steady_clock::time_point start_;
};

// 便捷宏
#define PERF_MEASURE_LATENCY(name) \
    edgelink::perf::ScopedLatencyMeasure _perf_measure_##__LINE__(name)

#define PERF_INCREMENT(name) \
    edgelink::perf::PerformanceMonitor::instance().counter(name).increment()

#define PERF_ADD(name, value) \
    edgelink::perf::PerformanceMonitor::instance().counter(name).add(value)

} // namespace edgelink::perf

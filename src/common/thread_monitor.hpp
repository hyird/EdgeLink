#pragma once

#include <atomic>
#include <chrono>
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace edgelink {

// ============================================================================
// Thread Pool Statistics
// ============================================================================

struct ThreadPoolStats {
    // Task counters
    std::atomic<uint64_t> tasks_submitted{0};
    std::atomic<uint64_t> tasks_completed{0};
    std::atomic<uint64_t> tasks_failed{0};

    // Queue metrics
    std::atomic<uint64_t> queue_depth{0};
    std::atomic<uint64_t> max_queue_depth{0};

    // Timing metrics (in microseconds)
    std::atomic<uint64_t> total_wait_time_us{0};
    std::atomic<uint64_t> total_exec_time_us{0};
    std::atomic<uint64_t> max_wait_time_us{0};
    std::atomic<uint64_t> max_exec_time_us{0};

    // Timeout/stall detection
    std::atomic<uint64_t> task_timeouts{0};
    std::atomic<uint64_t> slow_tasks{0};  // Tasks exceeding threshold

    // Worker thread metrics
    std::atomic<uint64_t> worker_count{0};
    std::atomic<uint64_t> active_workers{0};

    // Reset all counters
    void reset() {
        tasks_submitted = 0;
        tasks_completed = 0;
        tasks_failed = 0;
        queue_depth = 0;
        max_queue_depth = 0;
        total_wait_time_us = 0;
        total_exec_time_us = 0;
        max_wait_time_us = 0;
        max_exec_time_us = 0;
        task_timeouts = 0;
        slow_tasks = 0;
    }

    // Calculate averages
    uint64_t avg_wait_time_us() const {
        auto completed = tasks_completed.load();
        return completed > 0 ? total_wait_time_us.load() / completed : 0;
    }

    uint64_t avg_exec_time_us() const {
        auto completed = tasks_completed.load();
        return completed > 0 ? total_exec_time_us.load() / completed : 0;
    }

    uint64_t pending_tasks() const {
        return tasks_submitted.load() - tasks_completed.load() - tasks_failed.load();
    }
};

// ============================================================================
// Task Timing Helper
// ============================================================================

class TaskTimer {
public:
    explicit TaskTimer(ThreadPoolStats& stats)
        : stats_(stats)
        , submit_time_(std::chrono::steady_clock::now()) {
        stats_.tasks_submitted.fetch_add(1, std::memory_order_relaxed);
    }

    // Call when task starts executing
    void start_execution() {
        start_time_ = std::chrono::steady_clock::now();
        auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(
            start_time_ - submit_time_).count();

        stats_.total_wait_time_us.fetch_add(wait_us, std::memory_order_relaxed);

        // Update max wait time (lock-free)
        auto current_max = stats_.max_wait_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(wait_us) > current_max &&
               !stats_.max_wait_time_us.compare_exchange_weak(
                   current_max, wait_us, std::memory_order_relaxed)) {
        }
    }

    // Call when task completes successfully
    void complete() {
        record_execution_time();
        stats_.tasks_completed.fetch_add(1, std::memory_order_relaxed);
    }

    // Call when task fails
    void fail() {
        record_execution_time();
        stats_.tasks_failed.fetch_add(1, std::memory_order_relaxed);
    }

    // Mark as slow task (exceeds threshold)
    void mark_slow() {
        stats_.slow_tasks.fetch_add(1, std::memory_order_relaxed);
    }

    // Mark as timed out
    void mark_timeout() {
        stats_.task_timeouts.fetch_add(1, std::memory_order_relaxed);
    }

private:
    void record_execution_time() {
        auto end_time = std::chrono::steady_clock::now();
        auto exec_us = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time_).count();

        stats_.total_exec_time_us.fetch_add(exec_us, std::memory_order_relaxed);

        // Update max exec time (lock-free)
        auto current_max = stats_.max_exec_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(exec_us) > current_max &&
               !stats_.max_exec_time_us.compare_exchange_weak(
                   current_max, exec_us, std::memory_order_relaxed)) {
        }
    }

    ThreadPoolStats& stats_;
    std::chrono::steady_clock::time_point submit_time_;
    std::chrono::steady_clock::time_point start_time_;
};

// ============================================================================
// Queue Depth Tracker
// ============================================================================

class QueueDepthTracker {
public:
    explicit QueueDepthTracker(ThreadPoolStats& stats) : stats_(stats) {
        auto new_depth = stats_.queue_depth.fetch_add(1, std::memory_order_relaxed) + 1;

        // Update max depth (lock-free)
        auto current_max = stats_.max_queue_depth.load(std::memory_order_relaxed);
        while (new_depth > current_max &&
               !stats_.max_queue_depth.compare_exchange_weak(
                   current_max, new_depth, std::memory_order_relaxed)) {
        }
    }

    ~QueueDepthTracker() {
        stats_.queue_depth.fetch_sub(1, std::memory_order_relaxed);
    }

    QueueDepthTracker(const QueueDepthTracker&) = delete;
    QueueDepthTracker& operator=(const QueueDepthTracker&) = delete;
    QueueDepthTracker(QueueDepthTracker&&) = delete;
    QueueDepthTracker& operator=(QueueDepthTracker&&) = delete;

private:
    ThreadPoolStats& stats_;
};

// ============================================================================
// Worker Activity Tracker
// ============================================================================

class WorkerActivityTracker {
public:
    explicit WorkerActivityTracker(ThreadPoolStats& stats) : stats_(stats) {
        stats_.active_workers.fetch_add(1, std::memory_order_relaxed);
    }

    ~WorkerActivityTracker() {
        stats_.active_workers.fetch_sub(1, std::memory_order_relaxed);
    }

    WorkerActivityTracker(const WorkerActivityTracker&) = delete;
    WorkerActivityTracker& operator=(const WorkerActivityTracker&) = delete;
    WorkerActivityTracker(WorkerActivityTracker&&) = delete;
    WorkerActivityTracker& operator=(WorkerActivityTracker&&) = delete;

private:
    ThreadPoolStats& stats_;
};

// ============================================================================
// Monitor Configuration
// ============================================================================

struct MonitorConfig {
    // Thresholds
    std::chrono::microseconds slow_task_threshold{100000};  // 100ms
    std::chrono::microseconds task_timeout{5000000};        // 5s

    // Logging
    std::chrono::seconds log_interval{60};
    bool log_slow_tasks{true};
    bool log_timeouts{true};

    // Alerts
    uint64_t queue_depth_alert_threshold{1000};
    uint64_t pending_tasks_alert_threshold{500};
};

// ============================================================================
// Stats Snapshot (for reporting)
// ============================================================================

struct ThreadPoolStatsSnapshot {
    uint64_t tasks_submitted;
    uint64_t tasks_completed;
    uint64_t tasks_failed;
    uint64_t queue_depth;
    uint64_t max_queue_depth;
    uint64_t avg_wait_time_us;
    uint64_t max_wait_time_us;
    uint64_t avg_exec_time_us;
    uint64_t max_exec_time_us;
    uint64_t task_timeouts;
    uint64_t slow_tasks;
    uint64_t worker_count;
    uint64_t active_workers;
    std::chrono::steady_clock::time_point snapshot_time;

    static ThreadPoolStatsSnapshot from(const ThreadPoolStats& stats) {
        return {
            stats.tasks_submitted.load(std::memory_order_relaxed),
            stats.tasks_completed.load(std::memory_order_relaxed),
            stats.tasks_failed.load(std::memory_order_relaxed),
            stats.queue_depth.load(std::memory_order_relaxed),
            stats.max_queue_depth.load(std::memory_order_relaxed),
            stats.avg_wait_time_us(),
            stats.max_wait_time_us.load(std::memory_order_relaxed),
            stats.avg_exec_time_us(),
            stats.max_exec_time_us.load(std::memory_order_relaxed),
            stats.task_timeouts.load(std::memory_order_relaxed),
            stats.slow_tasks.load(std::memory_order_relaxed),
            stats.worker_count.load(std::memory_order_relaxed),
            stats.active_workers.load(std::memory_order_relaxed),
            std::chrono::steady_clock::now()
        };
    }
};

} // namespace edgelink

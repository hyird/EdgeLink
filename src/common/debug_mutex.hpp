#pragma once

#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <string>
#include <source_location>

#ifdef EDGELINK_DEBUG_LOCKS
#include "log.hpp"
#endif

namespace edgelink {

// ============================================================================
// Debug Lock Configuration
// ============================================================================

struct DebugLockConfig {
    // Timeout for acquiring locks (potential deadlock detection)
    std::chrono::seconds acquire_timeout{30};

    // Threshold for warning about long lock holds
    std::chrono::milliseconds hold_warning_threshold{1000};

    // Whether to abort on deadlock detection
    bool abort_on_deadlock{false};

    // Whether to log slow lock acquisitions
    bool log_slow_acquisitions{true};

    // Threshold for slow acquisition warning
    std::chrono::milliseconds slow_acquisition_threshold{100};
};

inline DebugLockConfig& global_debug_lock_config() {
    static DebugLockConfig config;
    return config;
}

// ============================================================================
// Lock Statistics
// ============================================================================

struct LockStats {
    std::atomic<uint64_t> acquisitions{0};
    std::atomic<uint64_t> contentions{0};
    std::atomic<uint64_t> timeouts{0};
    std::atomic<uint64_t> long_holds{0};
    std::atomic<uint64_t> total_hold_time_us{0};
    std::atomic<uint64_t> max_hold_time_us{0};
    std::atomic<uint64_t> total_wait_time_us{0};
    std::atomic<uint64_t> max_wait_time_us{0};
};

#ifdef EDGELINK_DEBUG_LOCKS

// ============================================================================
// Timed Mutex Wrapper (Debug Mode)
// ============================================================================

class TimedMutex {
public:
    TimedMutex() = default;
    ~TimedMutex() = default;

    TimedMutex(const TimedMutex&) = delete;
    TimedMutex& operator=(const TimedMutex&) = delete;

    void lock(const std::source_location& loc = std::source_location::current()) {
        auto start = std::chrono::steady_clock::now();
        const auto& config = global_debug_lock_config();

        // Try to acquire with timeout
        if (!mutex_.try_lock_for(config.acquire_timeout)) {
            stats_.timeouts.fetch_add(1, std::memory_order_relaxed);

            LOG_ERROR("Potential deadlock detected at {}:{} in {}",
                      loc.file_name(), loc.line(), loc.function_name());

            if (owner_thread_ != std::thread::id()) {
                // Note: Getting thread name is platform-specific
                LOG_ERROR("Lock held by thread {}",
                          std::hash<std::thread::id>{}(owner_thread_.load()));
            }

            if (lock_location_line_ > 0) {
                LOG_ERROR("Lock was acquired at line {}", lock_location_line_.load());
            }

            if (config.abort_on_deadlock) {
                std::abort();
            }

            // Block indefinitely if not aborting
            mutex_.lock();
        }

        auto end = std::chrono::steady_clock::now();
        auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        // Record stats
        stats_.acquisitions.fetch_add(1, std::memory_order_relaxed);
        stats_.total_wait_time_us.fetch_add(wait_us, std::memory_order_relaxed);

        if (wait_us > 0) {
            stats_.contentions.fetch_add(1, std::memory_order_relaxed);
        }

        // Update max wait time
        auto current_max = stats_.max_wait_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(wait_us) > current_max &&
               !stats_.max_wait_time_us.compare_exchange_weak(current_max, wait_us)) {
        }

        // Log slow acquisitions
        if (config.log_slow_acquisitions &&
            wait_us > static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    config.slow_acquisition_threshold).count())) {
            LOG_WARN("Slow lock acquisition: {} us at {}:{}",
                     wait_us, loc.file_name(), loc.line());
        }

        // Record ownership
        owner_thread_ = std::this_thread::get_id();
        lock_time_ = std::chrono::steady_clock::now();
        lock_location_line_ = loc.line();
    }

    bool try_lock(const std::source_location& loc = std::source_location::current()) {
        if (mutex_.try_lock()) {
            stats_.acquisitions.fetch_add(1, std::memory_order_relaxed);
            owner_thread_ = std::this_thread::get_id();
            lock_time_ = std::chrono::steady_clock::now();
            lock_location_line_ = loc.line();
            return true;
        }
        return false;
    }

    void unlock() {
        auto hold_time = std::chrono::steady_clock::now() - lock_time_;
        auto hold_us = std::chrono::duration_cast<std::chrono::microseconds>(hold_time).count();

        stats_.total_hold_time_us.fetch_add(hold_us, std::memory_order_relaxed);

        // Update max hold time
        auto current_max = stats_.max_hold_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(hold_us) > current_max &&
               !stats_.max_hold_time_us.compare_exchange_weak(current_max, hold_us)) {
        }

        const auto& config = global_debug_lock_config();
        if (hold_time > config.hold_warning_threshold) {
            stats_.long_holds.fetch_add(1, std::memory_order_relaxed);
            LOG_WARN("Lock held for {} ms (threshold: {} ms)",
                     std::chrono::duration_cast<std::chrono::milliseconds>(hold_time).count(),
                     config.hold_warning_threshold.count());
        }

        owner_thread_ = std::thread::id();
        lock_location_line_ = 0;
        mutex_.unlock();
    }

    const LockStats& stats() const { return stats_; }

private:
    std::timed_mutex mutex_;
    std::atomic<std::thread::id> owner_thread_;
    std::chrono::steady_clock::time_point lock_time_;
    std::atomic<uint32_t> lock_location_line_{0};
    LockStats stats_;
};

// ============================================================================
// Timed Shared Mutex Wrapper (Debug Mode)
// ============================================================================

class TimedSharedMutex {
public:
    TimedSharedMutex() = default;
    ~TimedSharedMutex() = default;

    TimedSharedMutex(const TimedSharedMutex&) = delete;
    TimedSharedMutex& operator=(const TimedSharedMutex&) = delete;

    void lock(const std::source_location& loc = std::source_location::current()) {
        auto start = std::chrono::steady_clock::now();
        const auto& config = global_debug_lock_config();

        if (!mutex_.try_lock_for(config.acquire_timeout)) {
            stats_.timeouts.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR("Potential deadlock (exclusive) at {}:{}", loc.file_name(), loc.line());

            if (config.abort_on_deadlock) {
                std::abort();
            }
            mutex_.lock();
        }

        record_acquisition(start, loc);
        owner_thread_ = std::this_thread::get_id();
        exclusive_ = true;
    }

    void unlock() {
        record_release();
        owner_thread_ = std::thread::id();
        exclusive_ = false;
        mutex_.unlock();
    }

    void lock_shared(const std::source_location& loc = std::source_location::current()) {
        auto start = std::chrono::steady_clock::now();
        const auto& config = global_debug_lock_config();

        if (!mutex_.try_lock_shared_for(config.acquire_timeout)) {
            stats_.timeouts.fetch_add(1, std::memory_order_relaxed);
            LOG_ERROR("Potential deadlock (shared) at {}:{}", loc.file_name(), loc.line());

            if (config.abort_on_deadlock) {
                std::abort();
            }
            mutex_.lock_shared();
        }

        record_acquisition(start, loc);
        shared_count_.fetch_add(1, std::memory_order_relaxed);
    }

    void unlock_shared() {
        record_release();
        shared_count_.fetch_sub(1, std::memory_order_relaxed);
        mutex_.unlock_shared();
    }

    bool try_lock() {
        if (mutex_.try_lock()) {
            stats_.acquisitions.fetch_add(1, std::memory_order_relaxed);
            owner_thread_ = std::this_thread::get_id();
            exclusive_ = true;
            lock_time_ = std::chrono::steady_clock::now();
            return true;
        }
        return false;
    }

    bool try_lock_shared() {
        if (mutex_.try_lock_shared()) {
            stats_.acquisitions.fetch_add(1, std::memory_order_relaxed);
            shared_count_.fetch_add(1, std::memory_order_relaxed);
            lock_time_ = std::chrono::steady_clock::now();
            return true;
        }
        return false;
    }

    const LockStats& stats() const { return stats_; }

private:
    void record_acquisition(std::chrono::steady_clock::time_point start,
                           const std::source_location& loc) {
        auto end = std::chrono::steady_clock::now();
        auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        stats_.acquisitions.fetch_add(1, std::memory_order_relaxed);
        stats_.total_wait_time_us.fetch_add(wait_us, std::memory_order_relaxed);

        if (wait_us > 0) {
            stats_.contentions.fetch_add(1, std::memory_order_relaxed);
        }

        const auto& config = global_debug_lock_config();
        if (config.log_slow_acquisitions &&
            wait_us > static_cast<int64_t>(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    config.slow_acquisition_threshold).count())) {
            LOG_WARN("Slow lock acquisition: {} us at {}:{}",
                     wait_us, loc.file_name(), loc.line());
        }

        lock_time_ = std::chrono::steady_clock::now();
    }

    void record_release() {
        auto hold_time = std::chrono::steady_clock::now() - lock_time_;
        auto hold_us = std::chrono::duration_cast<std::chrono::microseconds>(hold_time).count();

        stats_.total_hold_time_us.fetch_add(hold_us, std::memory_order_relaxed);

        auto current_max = stats_.max_hold_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(hold_us) > current_max &&
               !stats_.max_hold_time_us.compare_exchange_weak(current_max, hold_us)) {
        }

        const auto& config = global_debug_lock_config();
        if (hold_time > config.hold_warning_threshold) {
            stats_.long_holds.fetch_add(1, std::memory_order_relaxed);
            LOG_WARN("Lock held for {} ms",
                     std::chrono::duration_cast<std::chrono::milliseconds>(hold_time).count());
        }
    }

    std::shared_timed_mutex mutex_;
    std::atomic<std::thread::id> owner_thread_;
    std::atomic<uint32_t> shared_count_{0};
    std::atomic<bool> exclusive_{false};
    std::chrono::steady_clock::time_point lock_time_;
    LockStats stats_;
};

// Type aliases for debug mode
using DebugMutex = TimedMutex;
using DebugSharedMutex = TimedSharedMutex;

// Lock guard that works with source_location
template<typename Mutex>
class DebugLockGuard {
public:
    explicit DebugLockGuard(Mutex& m,
                           const std::source_location& loc = std::source_location::current())
        : mutex_(m) {
        mutex_.lock(loc);
    }

    ~DebugLockGuard() {
        mutex_.unlock();
    }

    DebugLockGuard(const DebugLockGuard&) = delete;
    DebugLockGuard& operator=(const DebugLockGuard&) = delete;

private:
    Mutex& mutex_;
};

template<typename Mutex>
class DebugSharedLockGuard {
public:
    explicit DebugSharedLockGuard(Mutex& m,
                                  const std::source_location& loc = std::source_location::current())
        : mutex_(m) {
        mutex_.lock_shared(loc);
    }

    ~DebugSharedLockGuard() {
        mutex_.unlock_shared();
    }

    DebugSharedLockGuard(const DebugSharedLockGuard&) = delete;
    DebugSharedLockGuard& operator=(const DebugSharedLockGuard&) = delete;

private:
    Mutex& mutex_;
};

#else  // !EDGELINK_DEBUG_LOCKS

// ============================================================================
// Production Mode - Use Standard Mutexes
// ============================================================================

using DebugMutex = std::mutex;
using DebugSharedMutex = std::shared_mutex;

template<typename Mutex>
using DebugLockGuard = std::lock_guard<Mutex>;

template<typename Mutex>
using DebugSharedLockGuard = std::shared_lock<Mutex>;

#endif  // EDGELINK_DEBUG_LOCKS

} // namespace edgelink

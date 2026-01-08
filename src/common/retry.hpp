#pragma once

#include <chrono>
#include <functional>
#include <random>
#include <thread>
#include <atomic>
#include <optional>

namespace edgelink {

// ============================================================================
// Retry Policy Configuration
// ============================================================================

struct RetryPolicy {
    // Maximum number of retry attempts (0 = infinite)
    uint32_t max_attempts{5};

    // Initial delay before first retry
    std::chrono::milliseconds initial_delay{100};

    // Maximum delay between retries
    std::chrono::milliseconds max_delay{30000};

    // Multiplier for exponential backoff
    double multiplier{2.0};

    // Add randomness to avoid thundering herd (0.0 to 1.0)
    double jitter{0.1};

    // Whether to use exponential backoff
    bool exponential{true};

    // Predefined policies
    static RetryPolicy aggressive() {
        return {10, std::chrono::milliseconds(50), std::chrono::milliseconds(5000), 1.5, 0.1, true};
    }

    static RetryPolicy standard() {
        return {5, std::chrono::milliseconds(100), std::chrono::milliseconds(30000), 2.0, 0.1, true};
    }

    static RetryPolicy conservative() {
        return {3, std::chrono::milliseconds(1000), std::chrono::milliseconds(60000), 2.0, 0.2, true};
    }

    static RetryPolicy infinite() {
        return {0, std::chrono::milliseconds(1000), std::chrono::milliseconds(60000), 2.0, 0.1, true};
    }
};

// ============================================================================
// Retry State
// ============================================================================

class RetryState {
public:
    explicit RetryState(const RetryPolicy& policy = RetryPolicy::standard())
        : policy_(policy), attempt_(0), current_delay_(policy.initial_delay) {}

    // Reset state for new operation
    void reset() {
        attempt_ = 0;
        current_delay_ = policy_.initial_delay;
    }

    // Check if we should retry
    bool should_retry() const {
        return policy_.max_attempts == 0 || attempt_ < policy_.max_attempts;
    }

    // Get current attempt number (1-based)
    uint32_t attempt() const { return attempt_; }

    // Get delay for next retry
    std::chrono::milliseconds next_delay() {
        auto delay = current_delay_;

        // Apply jitter
        if (policy_.jitter > 0) {
            static thread_local std::mt19937 rng(std::random_device{}());
            std::uniform_real_distribution<double> dist(1.0 - policy_.jitter, 1.0 + policy_.jitter);
            delay = std::chrono::milliseconds(static_cast<int64_t>(delay.count() * dist(rng)));
        }

        // Update for next call
        ++attempt_;
        if (policy_.exponential) {
            current_delay_ = std::chrono::milliseconds(
                static_cast<int64_t>(current_delay_.count() * policy_.multiplier));
            if (current_delay_ > policy_.max_delay) {
                current_delay_ = policy_.max_delay;
            }
        }

        return delay;
    }

    // Wait for the calculated delay
    void wait() {
        std::this_thread::sleep_for(next_delay());
    }

    // Wait with cancellation support
    template<typename Predicate>
    bool wait_unless(Predicate should_cancel) {
        auto delay = next_delay();
        auto end_time = std::chrono::steady_clock::now() + delay;

        while (std::chrono::steady_clock::now() < end_time) {
            if (should_cancel()) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return true;
    }

private:
    RetryPolicy policy_;
    uint32_t attempt_;
    std::chrono::milliseconds current_delay_;
};

// ============================================================================
// Retry Helper Functions
// ============================================================================

// Execute a function with retry
template<typename Func, typename... Args>
auto retry(const RetryPolicy& policy, Func&& func, Args&&... args)
    -> decltype(func(std::forward<Args>(args)...))
{
    RetryState state(policy);

    while (true) {
        try {
            return func(std::forward<Args>(args)...);
        } catch (...) {
            if (!state.should_retry()) {
                throw;
            }
            state.wait();
        }
    }
}

// Execute with retry and cancellation support
template<typename Func, typename Predicate>
auto retry_unless(const RetryPolicy& policy, Func&& func, Predicate should_cancel)
    -> std::optional<decltype(func())>
{
    RetryState state(policy);

    while (!should_cancel()) {
        try {
            return func();
        } catch (...) {
            if (!state.should_retry()) {
                throw;
            }
            if (!state.wait_unless(should_cancel)) {
                return std::nullopt;  // Cancelled
            }
        }
    }
    return std::nullopt;  // Cancelled before first attempt
}

// Execute with retry, returning success/failure instead of throwing
template<typename Func>
bool retry_bool(const RetryPolicy& policy, Func&& func) {
    RetryState state(policy);

    while (state.should_retry()) {
        if (func()) {
            return true;
        }
        state.wait();
    }
    return false;
}

// ============================================================================
// Circuit Breaker
// ============================================================================

class CircuitBreaker {
public:
    enum class State { CLOSED, OPEN, HALF_OPEN };

    struct Config {
        uint32_t failure_threshold{5};           // Failures before opening
        std::chrono::seconds reset_timeout{30};  // Time before trying again
        uint32_t success_threshold{2};           // Successes to close from half-open
    };

    explicit CircuitBreaker(const Config& config = {}) : config_(config) {}

    // Check if request is allowed
    bool allow_request() {
        auto now = std::chrono::steady_clock::now();

        switch (state_.load()) {
            case State::CLOSED:
                return true;

            case State::OPEN:
                if (now >= reset_time_) {
                    state_ = State::HALF_OPEN;
                    half_open_successes_ = 0;
                    return true;
                }
                return false;

            case State::HALF_OPEN:
                return true;
        }
        return false;
    }

    // Record a successful request
    void record_success() {
        if (state_ == State::HALF_OPEN) {
            if (++half_open_successes_ >= config_.success_threshold) {
                state_ = State::CLOSED;
                failures_ = 0;
            }
        } else {
            failures_ = 0;
        }
    }

    // Record a failed request
    void record_failure() {
        ++failures_;
        if (state_ == State::HALF_OPEN || failures_ >= config_.failure_threshold) {
            state_ = State::OPEN;
            reset_time_ = std::chrono::steady_clock::now() + config_.reset_timeout;
        }
    }

    State state() const { return state_.load(); }
    uint32_t failure_count() const { return failures_.load(); }

private:
    Config config_;
    std::atomic<State> state_{State::CLOSED};
    std::atomic<uint32_t> failures_{0};
    std::atomic<uint32_t> half_open_successes_{0};
    std::chrono::steady_clock::time_point reset_time_;
};

} // namespace edgelink

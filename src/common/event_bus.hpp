#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <typeindex>
#include <any>
#include <queue>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <chrono>
#include "thread_monitor.hpp"

namespace edgelink {

// ============================================================================
// Event Base Class
// ============================================================================

struct Event {
    virtual ~Event() = default;
    virtual std::type_index type() const = 0;
};

template<typename T>
struct TypedEvent : Event {
    std::type_index type() const override { return std::type_index(typeid(T)); }
};

// ============================================================================
// Common Events
// ============================================================================

namespace events {

// Connection events
struct Connected : TypedEvent<Connected> {
    uint32_t node_id{0};
    std::string virtual_ip;
};

struct Disconnected : TypedEvent<Disconnected> {
    int error_code{0};
    std::string reason;
};

// Peer events
struct PeerOnline : TypedEvent<PeerOnline> {
    uint32_t peer_id{0};
    std::string virtual_ip;
    std::string name;
};

struct PeerOffline : TypedEvent<PeerOffline> {
    uint32_t peer_id{0};
};

struct PeerEndpointsUpdated : TypedEvent<PeerEndpointsUpdated> {
    uint32_t peer_id{0};
};

// Data events
struct DataReceived : TypedEvent<DataReceived> {
    uint32_t from_node_id{0};
    std::vector<uint8_t> data;
    bool via_p2p{false};
};

struct PacketToSend : TypedEvent<PacketToSend> {
    uint32_t to_node_id{0};
    std::vector<uint8_t> data;
};

// P2P events
struct P2PConnected : TypedEvent<P2PConnected> {
    uint32_t peer_id{0};
    std::string endpoint_ip;
    uint16_t endpoint_port{0};
    uint32_t rtt_ms{0};
};

struct P2PDisconnected : TypedEvent<P2PDisconnected> {
    uint32_t peer_id{0};
};

struct P2PPunchRequest : TypedEvent<P2PPunchRequest> {
    uint32_t peer_id{0};
};

// Relay events
struct RelayConnected : TypedEvent<RelayConnected> {
    uint32_t relay_id{0};
    std::string name;
};

struct RelayDisconnected : TypedEvent<RelayDisconnected> {
    uint32_t relay_id{0};
};

// Config events
struct ConfigUpdated : TypedEvent<ConfigUpdated> {
    uint64_t version{0};
};

struct TokenRefreshed : TypedEvent<TokenRefreshed> {
    std::string auth_token;
    std::string relay_token;
};

struct IPChanged : TypedEvent<IPChanged> {
    std::string old_ip;
    std::string new_ip;
    std::string reason;
};

// Latency events
struct LatencyMeasured : TypedEvent<LatencyMeasured> {
    std::string target_type;  // "relay" or "peer"
    uint32_t target_id{0};
    uint32_t rtt_ms{0};
};

// Endpoint events
struct EndpointsDiscovered : TypedEvent<EndpointsDiscovered> {
    // Endpoints will be available through EndpointManager
};

} // namespace events

// ============================================================================
// Subscription Handle
// ============================================================================

class SubscriptionHandle {
public:
    SubscriptionHandle() = default;
    SubscriptionHandle(std::function<void()> unsubscribe) : unsubscribe_(std::move(unsubscribe)) {}
    ~SubscriptionHandle() { unsubscribe(); }

    SubscriptionHandle(const SubscriptionHandle&) = delete;
    SubscriptionHandle& operator=(const SubscriptionHandle&) = delete;

    SubscriptionHandle(SubscriptionHandle&& other) noexcept : unsubscribe_(std::move(other.unsubscribe_)) {
        other.unsubscribe_ = nullptr;
    }

    SubscriptionHandle& operator=(SubscriptionHandle&& other) noexcept {
        if (this != &other) {
            unsubscribe();
            unsubscribe_ = std::move(other.unsubscribe_);
            other.unsubscribe_ = nullptr;
        }
        return *this;
    }

    void unsubscribe() {
        if (unsubscribe_) {
            unsubscribe_();
            unsubscribe_ = nullptr;
        }
    }

private:
    std::function<void()> unsubscribe_;
};

// ============================================================================
// Event Bus
// ============================================================================

class EventBus {
public:
    using HandlerId = uint64_t;

    EventBus() = default;
    ~EventBus() { stop(); }

    // Start async event processing (optional - for async mode)
    void start_async(size_t thread_count = 1) {
        running_ = true;
        stats_.worker_count.store(thread_count, std::memory_order_relaxed);
        for (size_t i = 0; i < thread_count; ++i) {
            workers_.emplace_back([this] { process_events(); });
        }
    }

    void stop() {
        running_ = false;
        cv_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
        workers_.clear();
    }

    // Subscribe to an event type
    template<typename EventType>
    [[nodiscard]] SubscriptionHandle subscribe(std::function<void(const EventType&)> handler) {
        auto type = std::type_index(typeid(EventType));
        HandlerId id = next_id_++;

        auto wrapper = [handler](const Event& e) {
            handler(static_cast<const EventType&>(e));
        };

        {
            std::lock_guard<std::mutex> lock(mutex_);
            handlers_[type][id] = std::move(wrapper);
        }

        return SubscriptionHandle([this, type, id] {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = handlers_.find(type);
            if (it != handlers_.end()) {
                it->second.erase(id);
            }
        });
    }

    // Publish an event (synchronous - calls handlers immediately)
    template<typename EventType>
    void publish(const EventType& event) {
        auto type = std::type_index(typeid(EventType));

        std::vector<std::function<void(const Event&)>> handlers_copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = handlers_.find(type);
            if (it != handlers_.end()) {
                handlers_copy.reserve(it->second.size());
                for (const auto& [_, handler] : it->second) {
                    handlers_copy.push_back(handler);
                }
            }
        }

        for (const auto& handler : handlers_copy) {
            try {
                handler(event);
            } catch (...) {
                // Log error but don't propagate
            }
        }
    }

    // Queue an event for async processing
    template<typename EventType>
    void post(EventType event) {
        auto submit_time = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            event_queue_.push({std::make_unique<EventType>(std::move(event)), submit_time});

            // Update queue depth stats
            auto depth = event_queue_.size();
            stats_.queue_depth.store(depth, std::memory_order_relaxed);

            auto max_depth = stats_.max_queue_depth.load(std::memory_order_relaxed);
            while (depth > max_depth &&
                   !stats_.max_queue_depth.compare_exchange_weak(max_depth, depth)) {
            }
        }
        stats_.tasks_submitted.fetch_add(1, std::memory_order_relaxed);
        cv_.notify_one();
    }

    // Process queued events on calling thread
    void poll() {
        TimedEvent timed_event;
        while (true) {
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                if (event_queue_.empty()) break;
                timed_event = std::move(event_queue_.front());
                event_queue_.pop();
                stats_.queue_depth.store(event_queue_.size(), std::memory_order_relaxed);
            }
            dispatch_timed_event(timed_event);
        }
    }

    // Get monitoring statistics
    const ThreadPoolStats& stats() const { return stats_; }

    ThreadPoolStatsSnapshot stats_snapshot() const {
        return ThreadPoolStatsSnapshot::from(stats_);
    }

    // Reset statistics
    void reset_stats() { stats_.reset(); }

private:
    // Timed event wrapper for monitoring
    struct TimedEvent {
        std::unique_ptr<Event> event;
        std::chrono::steady_clock::time_point submit_time;
    };

    void process_events() {
        WorkerActivityTracker activity_tracker(stats_);

        while (running_) {
            TimedEvent timed_event;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                cv_.wait(lock, [this] { return !running_ || !event_queue_.empty(); });
                if (!running_ && event_queue_.empty()) break;
                if (!event_queue_.empty()) {
                    timed_event = std::move(event_queue_.front());
                    event_queue_.pop();
                    stats_.queue_depth.store(event_queue_.size(), std::memory_order_relaxed);
                }
            }
            if (timed_event.event) {
                dispatch_timed_event(timed_event);
            }
        }
    }

    void dispatch_timed_event(TimedEvent& timed_event) {
        auto start_time = std::chrono::steady_clock::now();
        auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(
            start_time - timed_event.submit_time).count();

        stats_.total_wait_time_us.fetch_add(wait_us, std::memory_order_relaxed);

        // Update max wait time
        auto max_wait = stats_.max_wait_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(wait_us) > max_wait &&
               !stats_.max_wait_time_us.compare_exchange_weak(max_wait, wait_us)) {
        }

        // Execute event
        dispatch_event(*timed_event.event);

        auto end_time = std::chrono::steady_clock::now();
        auto exec_us = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - start_time).count();

        stats_.total_exec_time_us.fetch_add(exec_us, std::memory_order_relaxed);
        stats_.tasks_completed.fetch_add(1, std::memory_order_relaxed);

        // Update max exec time
        auto max_exec = stats_.max_exec_time_us.load(std::memory_order_relaxed);
        while (static_cast<uint64_t>(exec_us) > max_exec &&
               !stats_.max_exec_time_us.compare_exchange_weak(max_exec, exec_us)) {
        }

        // Check for slow tasks (> 100ms)
        if (exec_us > 100000) {
            stats_.slow_tasks.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void dispatch_event(const Event& event) {
        auto type = event.type();

        std::vector<std::function<void(const Event&)>> handlers_copy;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = handlers_.find(type);
            if (it != handlers_.end()) {
                handlers_copy.reserve(it->second.size());
                for (const auto& [_, handler] : it->second) {
                    handlers_copy.push_back(handler);
                }
            }
        }

        for (const auto& handler : handlers_copy) {
            try {
                handler(event);
            } catch (...) {
                // Log error but don't propagate
            }
        }
    }

    std::mutex mutex_;
    std::unordered_map<std::type_index, std::unordered_map<HandlerId, std::function<void(const Event&)>>> handlers_;
    std::atomic<HandlerId> next_id_{0};

    // Async processing
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::queue<TimedEvent> event_queue_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};

    // Monitoring statistics
    mutable ThreadPoolStats stats_;
};

// ============================================================================
// Global Event Bus (optional singleton access)
// ============================================================================

inline EventBus& global_event_bus() {
    static EventBus instance;
    return instance;
}

} // namespace edgelink

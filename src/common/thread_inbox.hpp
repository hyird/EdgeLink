#pragma once

#include "mpsc_queue.hpp"
#include <boost/asio.hpp>
#include <functional>
#include <atomic>

namespace edgelink {

namespace net = boost::asio;

/**
 * ThreadInbox - Per-thread message inbox using MPSC queue
 *
 * Each worker thread has one ThreadInbox to receive messages from other threads.
 * Messages are delivered asynchronously via the thread's io_context.
 *
 * Design (per architecture.md Section 8.3):
 * - Other threads push messages via post()
 * - Owning thread polls and processes messages
 * - Uses timer-based polling with configurable interval
 */
class ThreadInbox {
public:
    using MessageHandler = std::function<void(CrossThreadMessage&&)>;

    /**
     * Create a ThreadInbox bound to an io_context.
     * @param ioc The io_context this inbox belongs to
     * @param thread_index Index of the owning thread
     */
    ThreadInbox(net::io_context& ioc, size_t thread_index);

    ~ThreadInbox();

    // Non-copyable
    ThreadInbox(const ThreadInbox&) = delete;
    ThreadInbox& operator=(const ThreadInbox&) = delete;

    /**
     * Post a message to this inbox (thread-safe, called from any thread).
     * @param msg Message to deliver
     * @return true if message was queued, false if queue is full
     */
    bool post(CrossThreadMessage&& msg);

    /**
     * Set the message handler callback.
     * Must be called before start().
     * @param handler Callback invoked for each received message
     */
    void set_handler(MessageHandler handler);

    /**
     * Start processing messages.
     * Begins polling the queue and dispatching to handler.
     */
    void start();

    /**
     * Stop processing messages.
     */
    void stop();

    /**
     * Check if inbox is running.
     */
    bool running() const { return running_.load(std::memory_order_acquire); }

    /**
     * Get approximate number of pending messages.
     */
    size_t pending_count() const { return queue_.size_approx(); }

    /**
     * Get thread index.
     */
    size_t thread_index() const { return thread_index_; }

    /**
     * Get statistics.
     */
    struct Stats {
        uint64_t messages_received{0};
        uint64_t messages_dropped{0};
        uint64_t poll_cycles{0};
    };
    Stats get_stats() const;

private:
    void schedule_poll();
    void poll_messages();

    net::io_context& ioc_;
    size_t thread_index_;
    net::steady_timer poll_timer_;

    MPSCQueue<CrossThreadMessage, 8192> queue_;
    MessageHandler handler_;

    std::atomic<bool> running_{false};
    std::atomic<uint64_t> messages_received_{0};
    std::atomic<uint64_t> messages_dropped_{0};
    std::atomic<uint64_t> poll_cycles_{0};

    // Poll interval in microseconds
    static constexpr auto kPollInterval = std::chrono::microseconds(100);
    // Maximum messages to process per poll cycle
    static constexpr size_t kMaxBatchSize = 256;
};

} // namespace edgelink

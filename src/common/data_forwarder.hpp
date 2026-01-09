#pragma once

#include "io_context_pool.hpp"
#include "thread_inbox.hpp"
#include "thread_local_session.hpp"
#include <memory>
#include <vector>
#include <atomic>

namespace edgelink {

/**
 * DataForwarder - Cross-thread data forwarding coordinator
 *
 * Handles data forwarding between sessions, automatically choosing the
 * optimal path based on thread locality:
 * - Same thread: Direct function call (fastest)
 * - Different thread: Via MPSC queue (lock-free)
 *
 * Design (per architecture.md Section 8.2, 8.3):
 * - Minimizes cross-thread communication
 * - Uses lock-free queues for cross-thread forwarding
 * - Each thread has its own inbox for receiving messages
 */
class DataForwarder {
public:
    /**
     * Create a DataForwarder.
     * @param pool IOContextPool to use
     */
    explicit DataForwarder(IOContextPool& pool);

    ~DataForwarder();

    // Non-copyable
    DataForwarder(const DataForwarder&) = delete;
    DataForwarder& operator=(const DataForwarder&) = delete;

    /**
     * Initialize the forwarder.
     * Must be called after pool.run() but before forwarding messages.
     * Sets up per-thread inboxes and local session managers.
     */
    void initialize();

    /**
     * Shutdown the forwarder.
     * Stops all inboxes and clears state.
     */
    void shutdown();

    /**
     * Forward data to a destination node.
     *
     * If the destination is on the same thread as the caller, the data is
     * delivered directly. Otherwise, it's queued for the destination thread.
     *
     * @param src_node Source node ID
     * @param dst_node Destination node ID
     * @param data Data to forward
     * @return true if the message was delivered or queued, false if destination not found
     */
    bool forward(uint32_t src_node, uint32_t dst_node, std::vector<uint8_t> data);

    /**
     * Forward data to a specific thread's session.
     * Used when you already know the target thread.
     *
     * @param dst_node Destination node ID
     * @param dst_thread Target thread index
     * @param data Data to forward
     * @return true if queued/delivered, false if destination not found
     */
    bool forward_to_thread(uint32_t dst_node, size_t dst_thread, std::vector<uint8_t> data);

    /**
     * Get the ThreadLocalSessionManager for a specific thread.
     * Must be called from the owning thread or with external synchronization.
     */
    ThreadLocalSessionManager* get_local_manager(size_t thread_index);

    /**
     * Get the ThreadInbox for a specific thread.
     */
    ThreadInbox* get_inbox(size_t thread_index);

    /**
     * Check if forwarder is initialized.
     */
    bool initialized() const { return initialized_.load(std::memory_order_acquire); }

    /**
     * Get statistics.
     */
    struct Stats {
        uint64_t direct_forwards{0};    // Same-thread forwards
        uint64_t queued_forwards{0};    // Cross-thread forwards
        uint64_t failed_forwards{0};    // Failed (destination not found)
    };
    Stats get_stats() const;

private:
    void handle_incoming_message(size_t thread_index, CrossThreadMessage&& msg);

    IOContextPool& pool_;
    std::vector<std::unique_ptr<ThreadInbox>> inboxes_;
    std::vector<std::unique_ptr<ThreadLocalSessionManager>> local_managers_;

    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> direct_forwards_{0};
    std::atomic<uint64_t> queued_forwards_{0};
    std::atomic<uint64_t> failed_forwards_{0};
};

} // namespace edgelink

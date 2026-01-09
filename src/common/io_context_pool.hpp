#pragma once

#include <boost/asio.hpp>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

namespace edgelink {

namespace net = boost::asio;

/**
 * IOContextPool - Thread-per-core IO Context Pool
 *
 * Implements the thread-per-core concurrency model where each thread has its own
 * independent io_context. New connections are distributed via round-robin to
 * achieve load balancing across threads.
 *
 * Design principles (per architecture.md Section 8):
 * - Each thread owns one io_context (no sharing)
 * - Connections are assigned to threads via round-robin
 * - Connection stays on its assigned thread for its entire lifetime
 * - Cross-thread communication uses MPSC lock-free queues (separate component)
 */
class IOContextPool {
public:
    /**
     * Create a pool with specified number of threads.
     * @param pool_size Number of threads. 0 = std::thread::hardware_concurrency()
     */
    explicit IOContextPool(size_t pool_size = 0);

    ~IOContextPool();

    // Non-copyable, non-movable
    IOContextPool(const IOContextPool&) = delete;
    IOContextPool& operator=(const IOContextPool&) = delete;
    IOContextPool(IOContextPool&&) = delete;
    IOContextPool& operator=(IOContextPool&&) = delete;

    /**
     * Start all threads running their io_contexts.
     * This is a non-blocking call.
     */
    void run();

    /**
     * Stop all io_contexts and join all threads.
     */
    void stop();

    /**
     * Get the next io_context using round-robin.
     * Used for distributing new connections across threads.
     * Thread-safe.
     */
    net::io_context& get_io_context();

    /**
     * Get io_context at specific index.
     * @param index Thread index (0 to size()-1)
     */
    net::io_context& get_io_context(size_t index);

    /**
     * Get the io_context for the current thread.
     * Only valid when called from a pool worker thread.
     * @return Reference to current thread's io_context
     * @throws std::runtime_error if called from non-pool thread
     */
    static net::io_context& current();

    /**
     * Get the thread index for the current thread.
     * Only valid when called from a pool worker thread.
     * @return Current thread's index (0 to size()-1)
     * @throws std::runtime_error if called from non-pool thread
     */
    static size_t current_thread_index();

    /**
     * Check if current thread is a pool worker thread.
     */
    static bool is_pool_thread();

    /**
     * Get the number of threads in the pool.
     */
    size_t size() const { return contexts_.size(); }

    /**
     * Check if the pool is running.
     */
    bool running() const { return running_.load(std::memory_order_acquire); }

    /**
     * Post a task to a specific thread.
     * @param thread_index Target thread index
     * @param handler Task to execute
     */
    template<typename Handler>
    void post_to(size_t thread_index, Handler&& handler) {
        if (thread_index < contexts_.size()) {
            net::post(*contexts_[thread_index].io_context, std::forward<Handler>(handler));
        }
    }

    /**
     * Post a task to all threads.
     * @param handler Task to execute (will be copied to each thread)
     */
    template<typename Handler>
    void broadcast(Handler handler) {
        for (auto& ctx : contexts_) {
            net::post(*ctx.io_context, handler);
        }
    }

    /**
     * Get the executor for a specific thread's io_context.
     */
    net::any_io_executor get_executor(size_t thread_index) {
        return contexts_[thread_index].io_context->get_executor();
    }

private:
    struct ThreadContext {
        std::unique_ptr<net::io_context> io_context;
        std::unique_ptr<net::executor_work_guard<net::io_context::executor_type>> work_guard;
        std::thread thread;
        size_t index{0};
    };

    void worker_thread(size_t index);

    std::vector<ThreadContext> contexts_;
    std::atomic<size_t> next_io_context_{0};
    std::atomic<bool> running_{false};
    std::atomic<bool> stopped_{false};

    // Thread-local storage for current thread context
    static thread_local size_t tls_thread_index_;
    static thread_local net::io_context* tls_io_context_;
    static thread_local bool tls_is_pool_thread_;
};

} // namespace edgelink

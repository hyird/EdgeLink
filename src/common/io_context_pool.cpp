#include "io_context_pool.hpp"
#include "log.hpp"
#include <stdexcept>

namespace edgelink {

// Thread-local storage definitions
thread_local size_t IOContextPool::tls_thread_index_ = 0;
thread_local net::io_context* IOContextPool::tls_io_context_ = nullptr;
thread_local bool IOContextPool::tls_is_pool_thread_ = false;

IOContextPool::IOContextPool(size_t pool_size) {
    if (pool_size == 0) {
        pool_size = std::thread::hardware_concurrency();
        if (pool_size == 0) {
            pool_size = 1;  // Fallback to single thread
        }
    }

    contexts_.reserve(pool_size);

    for (size_t i = 0; i < pool_size; ++i) {
        ThreadContext ctx;
        ctx.index = i;
        ctx.io_context = std::make_unique<net::io_context>(1);  // concurrency_hint = 1
        ctx.work_guard = std::make_unique<net::executor_work_guard<net::io_context::executor_type>>(
            net::make_work_guard(*ctx.io_context));
        contexts_.push_back(std::move(ctx));
    }

    LOG_INFO("IOContextPool: Created with {} threads", pool_size);
}

IOContextPool::~IOContextPool() {
    stop();
}

void IOContextPool::run() {
    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already running
    }

    stopped_.store(false, std::memory_order_release);

    // Start worker threads
    for (size_t i = 0; i < contexts_.size(); ++i) {
        contexts_[i].thread = std::thread(&IOContextPool::worker_thread, this, i);
    }

    LOG_INFO("IOContextPool: Started {} worker threads", contexts_.size());

    // Block until all threads complete (will happen when stop() is called)
    for (auto& ctx : contexts_) {
        if (ctx.thread.joinable()) {
            ctx.thread.join();
        }
    }

    stopped_.store(true, std::memory_order_release);
    running_.store(false, std::memory_order_release);
}

void IOContextPool::stop() {
    if (stopped_.load(std::memory_order_acquire)) {
        return;  // Already stopped
    }

    // Release work guards to allow io_contexts to finish
    for (auto& ctx : contexts_) {
        if (ctx.work_guard) {
            ctx.work_guard->reset();
        }
    }

    // Stop all io_contexts
    for (auto& ctx : contexts_) {
        if (ctx.io_context) {
            ctx.io_context->stop();
        }
    }

    // Note: threads are joined in run() - no double join needed
    LOG_INFO("IOContextPool: Stopped");
}

net::io_context& IOContextPool::get_io_context() {
    // Round-robin distribution using atomic increment
    size_t index = next_io_context_.fetch_add(1, std::memory_order_relaxed) % contexts_.size();
    return *contexts_[index].io_context;
}

net::io_context& IOContextPool::get_io_context(size_t index) {
    if (index >= contexts_.size()) {
        throw std::out_of_range("IOContextPool: Invalid thread index");
    }
    return *contexts_[index].io_context;
}

net::io_context& IOContextPool::current() {
    if (!tls_is_pool_thread_ || tls_io_context_ == nullptr) {
        throw std::runtime_error("IOContextPool::current() called from non-pool thread");
    }
    return *tls_io_context_;
}

size_t IOContextPool::current_thread_index() {
    if (!tls_is_pool_thread_) {
        throw std::runtime_error("IOContextPool::current_thread_index() called from non-pool thread");
    }
    return tls_thread_index_;
}

bool IOContextPool::is_pool_thread() {
    return tls_is_pool_thread_;
}

void IOContextPool::worker_thread(size_t index) {
    // Set thread-local storage
    tls_thread_index_ = index;
    tls_io_context_ = contexts_[index].io_context.get();
    tls_is_pool_thread_ = true;

    LOG_DEBUG("IOContextPool: Worker thread {} started", index);

    try {
        contexts_[index].io_context->run();
    } catch (const std::exception& e) {
        LOG_ERROR("IOContextPool: Worker thread {} exception: {}", index, e.what());
    }

    // Clear thread-local storage
    tls_is_pool_thread_ = false;
    tls_io_context_ = nullptr;

    LOG_DEBUG("IOContextPool: Worker thread {} stopped", index);
}

} // namespace edgelink

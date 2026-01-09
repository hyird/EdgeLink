#include "thread_inbox.hpp"
#include "log.hpp"

namespace edgelink {

ThreadInbox::ThreadInbox(net::io_context& ioc, size_t thread_index)
    : ioc_(ioc)
    , thread_index_(thread_index)
    , poll_timer_(ioc)
{}

ThreadInbox::~ThreadInbox() {
    stop();
}

bool ThreadInbox::post(CrossThreadMessage&& msg) {
    if (!running_.load(std::memory_order_acquire)) {
        messages_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    if (!queue_.try_push(std::move(msg))) {
        messages_dropped_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    return true;
}

void ThreadInbox::set_handler(MessageHandler handler) {
    handler_ = std::move(handler);
}

void ThreadInbox::start() {
    if (!handler_) {
        LOG_ERROR("ThreadInbox[{}]: Cannot start without handler", thread_index_);
        return;
    }

    if (running_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already running
    }

    LOG_DEBUG("ThreadInbox[{}]: Started", thread_index_);
    schedule_poll();
}

void ThreadInbox::stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Not running
    }

    poll_timer_.cancel();

    // Drain remaining messages
    CrossThreadMessage msg;
    while (queue_.try_pop(msg)) {
        // Discard
    }

    LOG_DEBUG("ThreadInbox[{}]: Stopped", thread_index_);
}

ThreadInbox::Stats ThreadInbox::get_stats() const {
    return {
        messages_received_.load(std::memory_order_relaxed),
        messages_dropped_.load(std::memory_order_relaxed),
        poll_cycles_.load(std::memory_order_relaxed)
    };
}

void ThreadInbox::schedule_poll() {
    if (!running_.load(std::memory_order_acquire)) {
        return;
    }

    poll_timer_.expires_after(kPollInterval);
    poll_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (!ec && running_.load(std::memory_order_acquire)) {
            poll_messages();
            schedule_poll();
        }
    });
}

void ThreadInbox::poll_messages() {
    poll_cycles_.fetch_add(1, std::memory_order_relaxed);

    std::vector<CrossThreadMessage> batch;
    batch.reserve(kMaxBatchSize);

    size_t count = queue_.pop_batch(batch, kMaxBatchSize);

    if (count > 0) {
        messages_received_.fetch_add(count, std::memory_order_relaxed);

        for (auto& msg : batch) {
            try {
                handler_(std::move(msg));
            } catch (const std::exception& e) {
                LOG_ERROR("ThreadInbox[{}]: Handler exception: {}", thread_index_, e.what());
            }
        }
    }
}

} // namespace edgelink

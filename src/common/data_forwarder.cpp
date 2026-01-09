#include "data_forwarder.hpp"
#include "ws_session_coro.hpp"
#include "log.hpp"

namespace edgelink {

DataForwarder::DataForwarder(IOContextPool& pool)
    : pool_(pool)
{}

DataForwarder::~DataForwarder() {
    shutdown();
}

void DataForwarder::initialize() {
    if (initialized_.exchange(true, std::memory_order_acq_rel)) {
        return;  // Already initialized
    }

    size_t num_threads = pool_.size();

    // Create per-thread components
    inboxes_.reserve(num_threads);
    local_managers_.reserve(num_threads);

    for (size_t i = 0; i < num_threads; ++i) {
        // Create inbox for this thread
        auto inbox = std::make_unique<ThreadInbox>(pool_.get_io_context(i), i);

        // Set message handler
        inbox->set_handler([this, i](CrossThreadMessage&& msg) {
            handle_incoming_message(i, std::move(msg));
        });

        // Create local session manager
        auto manager = std::make_unique<ThreadLocalSessionManager>(i);

        inboxes_.push_back(std::move(inbox));
        local_managers_.push_back(std::move(manager));
    }

    // Start all inboxes
    for (auto& inbox : inboxes_) {
        inbox->start();
    }

    LOG_INFO("DataForwarder: Initialized with {} threads", num_threads);
}

void DataForwarder::shutdown() {
    if (!initialized_.exchange(false, std::memory_order_acq_rel)) {
        return;  // Not initialized
    }

    // Stop all inboxes
    for (auto& inbox : inboxes_) {
        inbox->stop();
    }

    // Clear state
    inboxes_.clear();
    local_managers_.clear();

    // Clear global directory
    GlobalSessionDirectory::instance().clear();

    LOG_INFO("DataForwarder: Shutdown complete");
}

bool DataForwarder::forward(uint32_t src_node, uint32_t dst_node, std::vector<uint8_t> data) {
    // Look up destination thread
    auto dst_thread_opt = GlobalSessionDirectory::instance().get_node_thread(dst_node);
    if (!dst_thread_opt) {
        failed_forwards_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    size_t dst_thread = *dst_thread_opt;

    // Check if we're on the same thread
    if (IOContextPool::is_pool_thread()) {
        size_t current_thread = IOContextPool::current_thread_index();

        if (current_thread == dst_thread) {
            // Same thread - direct delivery
            auto session = local_managers_[dst_thread]->get_session(dst_node);
            if (session) {
                session->send_binary(std::move(data));
                direct_forwards_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
            failed_forwards_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    // Cross-thread - queue to destination thread's inbox
    CrossThreadMessage msg(src_node, dst_node, std::move(data));

    if (inboxes_[dst_thread]->post(std::move(msg))) {
        queued_forwards_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    failed_forwards_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

bool DataForwarder::forward_to_thread(uint32_t dst_node, size_t dst_thread, std::vector<uint8_t> data) {
    if (dst_thread >= inboxes_.size()) {
        failed_forwards_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Check if we're on the same thread
    if (IOContextPool::is_pool_thread() && IOContextPool::current_thread_index() == dst_thread) {
        // Same thread - direct delivery
        auto session = local_managers_[dst_thread]->get_session(dst_node);
        if (session) {
            session->send_binary(std::move(data));
            direct_forwards_.fetch_add(1, std::memory_order_relaxed);
            return true;
        }
        failed_forwards_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    // Cross-thread - queue
    CrossThreadMessage msg(0, dst_node, std::move(data));

    if (inboxes_[dst_thread]->post(std::move(msg))) {
        queued_forwards_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    failed_forwards_.fetch_add(1, std::memory_order_relaxed);
    return false;
}

ThreadLocalSessionManager* DataForwarder::get_local_manager(size_t thread_index) {
    if (thread_index < local_managers_.size()) {
        return local_managers_[thread_index].get();
    }
    return nullptr;
}

ThreadInbox* DataForwarder::get_inbox(size_t thread_index) {
    if (thread_index < inboxes_.size()) {
        return inboxes_[thread_index].get();
    }
    return nullptr;
}

DataForwarder::Stats DataForwarder::get_stats() const {
    return {
        direct_forwards_.load(std::memory_order_relaxed),
        queued_forwards_.load(std::memory_order_relaxed),
        failed_forwards_.load(std::memory_order_relaxed)
    };
}

void DataForwarder::handle_incoming_message(size_t thread_index, CrossThreadMessage&& msg) {
    // Find the destination session in this thread's local manager
    auto session = local_managers_[thread_index]->get_session(msg.dst_node_id);
    if (session) {
        session->send_binary(std::move(msg.data));
    } else {
        LOG_DEBUG("DataForwarder: Destination node {} not found on thread {}",
                  msg.dst_node_id, thread_index);
    }
}

} // namespace edgelink

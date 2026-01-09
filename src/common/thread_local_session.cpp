#include "thread_local_session.hpp"
#include "ws_session_coro.hpp"
#include "log.hpp"

namespace edgelink {

// ============================================================================
// ThreadLocalSessionManager Implementation
// ============================================================================

ThreadLocalSessionManager::ThreadLocalSessionManager(size_t thread_index)
    : thread_index_(thread_index)
{}

void ThreadLocalSessionManager::add_session(uint32_t node_id, uint32_t network_id,
                                             std::shared_ptr<WsSessionCoro> session,
                                             const std::string& virtual_ip) {
    LocalSessionInfo info;
    info.node_id = node_id;
    info.network_id = network_id;
    info.session = session;
    info.virtual_ip = virtual_ip;

    sessions_[node_id] = std::move(info);

    // Register in global directory
    GlobalSessionDirectory::instance().register_node(node_id, thread_index_);

    LOG_DEBUG("ThreadLocalSessionManager[{}]: Added session for node {} (network {})",
              thread_index_, node_id, network_id);
}

void ThreadLocalSessionManager::remove_session(uint32_t node_id) {
    auto it = sessions_.find(node_id);
    if (it != sessions_.end()) {
        sessions_.erase(it);

        // Unregister from global directory
        GlobalSessionDirectory::instance().unregister_node(node_id);

        LOG_DEBUG("ThreadLocalSessionManager[{}]: Removed session for node {}",
                  thread_index_, node_id);
    }
}

std::shared_ptr<WsSessionCoro> ThreadLocalSessionManager::get_session(uint32_t node_id) {
    auto it = sessions_.find(node_id);
    if (it != sessions_.end()) {
        if (auto session = it->second.session.lock()) {
            return session;
        }
        // Session expired, remove it
        GlobalSessionDirectory::instance().unregister_node(node_id);
        sessions_.erase(it);
    }
    return nullptr;
}

bool ThreadLocalSessionManager::has_session(uint32_t node_id) const {
    auto it = sessions_.find(node_id);
    if (it != sessions_.end()) {
        return !it->second.session.expired();
    }
    return false;
}

std::vector<uint32_t> ThreadLocalSessionManager::get_session_ids() const {
    std::vector<uint32_t> ids;
    ids.reserve(sessions_.size());
    for (const auto& [node_id, info] : sessions_) {
        if (!info.session.expired()) {
            ids.push_back(node_id);
        }
    }
    return ids;
}

std::vector<std::shared_ptr<WsSessionCoro>> ThreadLocalSessionManager::get_sessions_by_network(uint32_t network_id) {
    std::vector<std::shared_ptr<WsSessionCoro>> result;
    for (auto& [node_id, info] : sessions_) {
        if (info.network_id == network_id) {
            if (auto session = info.session.lock()) {
                result.push_back(session);
            }
        }
    }
    return result;
}

void ThreadLocalSessionManager::broadcast(const std::vector<uint8_t>& data) {
    cleanup_expired();
    for (auto& [node_id, info] : sessions_) {
        if (auto session = info.session.lock()) {
            session->send_binary(data);
        }
    }
}

void ThreadLocalSessionManager::broadcast_to_network(uint32_t network_id, const std::vector<uint8_t>& data) {
    cleanup_expired();
    for (auto& [node_id, info] : sessions_) {
        if (info.network_id == network_id) {
            if (auto session = info.session.lock()) {
                session->send_binary(data);
            }
        }
    }
}

void ThreadLocalSessionManager::cleanup_expired() {
    if (++cleanup_counter_ < kCleanupInterval) {
        return;
    }
    cleanup_counter_ = 0;

    std::vector<uint32_t> expired;
    for (const auto& [node_id, info] : sessions_) {
        if (info.session.expired()) {
            expired.push_back(node_id);
        }
    }

    for (uint32_t node_id : expired) {
        GlobalSessionDirectory::instance().unregister_node(node_id);
        sessions_.erase(node_id);
    }

    if (!expired.empty()) {
        LOG_DEBUG("ThreadLocalSessionManager[{}]: Cleaned up {} expired sessions",
                  thread_index_, expired.size());
    }
}

// ============================================================================
// GlobalSessionDirectory Implementation
// ============================================================================

GlobalSessionDirectory& GlobalSessionDirectory::instance() {
    static GlobalSessionDirectory instance;
    return instance;
}

void GlobalSessionDirectory::register_node(uint32_t node_id, size_t thread_index) {
    std::unique_lock lock(mutex_);
    node_locations_[node_id] = thread_index;
}

void GlobalSessionDirectory::unregister_node(uint32_t node_id) {
    std::unique_lock lock(mutex_);
    node_locations_.erase(node_id);
}

std::optional<size_t> GlobalSessionDirectory::get_node_thread(uint32_t node_id) const {
    std::shared_lock lock(mutex_);
    auto it = node_locations_.find(node_id);
    if (it != node_locations_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool GlobalSessionDirectory::has_node(uint32_t node_id) const {
    std::shared_lock lock(mutex_);
    return node_locations_.find(node_id) != node_locations_.end();
}

std::vector<uint32_t> GlobalSessionDirectory::get_all_nodes() const {
    std::shared_lock lock(mutex_);
    std::vector<uint32_t> nodes;
    nodes.reserve(node_locations_.size());
    for (const auto& [node_id, thread_index] : node_locations_) {
        nodes.push_back(node_id);
    }
    return nodes;
}

size_t GlobalSessionDirectory::get_node_count_on_thread(size_t thread_index) const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [node_id, idx] : node_locations_) {
        if (idx == thread_index) {
            ++count;
        }
    }
    return count;
}

size_t GlobalSessionDirectory::total_node_count() const {
    std::shared_lock lock(mutex_);
    return node_locations_.size();
}

void GlobalSessionDirectory::clear() {
    std::unique_lock lock(mutex_);
    node_locations_.clear();
}

} // namespace edgelink

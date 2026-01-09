#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <shared_mutex>
#include <atomic>
#include <functional>

namespace edgelink {

// Forward declaration
class WsSessionCoro;

/**
 * LocalSessionInfo - Information about a session stored in thread-local manager
 */
struct LocalSessionInfo {
    uint32_t node_id{0};
    uint32_t network_id{0};
    std::weak_ptr<WsSessionCoro> session;
    std::string virtual_ip;
};

/**
 * ThreadLocalSessionManager - Per-thread session management (lock-free)
 *
 * Each worker thread has one instance of this class to manage sessions
 * assigned to that thread. Since only the owning thread accesses this,
 * no synchronization is needed.
 *
 * Design (per architecture.md Section 8.2, 8.3):
 * - Thread-local data, no locking required
 * - Only the owning thread reads/writes
 * - Holds weak_ptr to sessions to avoid preventing cleanup
 */
class ThreadLocalSessionManager {
public:
    explicit ThreadLocalSessionManager(size_t thread_index);
    ~ThreadLocalSessionManager() = default;

    // Non-copyable
    ThreadLocalSessionManager(const ThreadLocalSessionManager&) = delete;
    ThreadLocalSessionManager& operator=(const ThreadLocalSessionManager&) = delete;

    /**
     * Add a session to this thread's local storage.
     * @param node_id Node ID
     * @param network_id Network ID
     * @param session Session pointer
     * @param virtual_ip Virtual IP address
     */
    void add_session(uint32_t node_id, uint32_t network_id,
                     std::shared_ptr<WsSessionCoro> session,
                     const std::string& virtual_ip = "");

    /**
     * Remove a session by node ID.
     * @param node_id Node ID to remove
     */
    void remove_session(uint32_t node_id);

    /**
     * Get a session by node ID.
     * @param node_id Node ID to look up
     * @return Session pointer, or nullptr if not found or expired
     */
    std::shared_ptr<WsSessionCoro> get_session(uint32_t node_id);

    /**
     * Check if a session exists and is valid.
     */
    bool has_session(uint32_t node_id) const;

    /**
     * Get all session node IDs in this thread.
     */
    std::vector<uint32_t> get_session_ids() const;

    /**
     * Get all sessions in a specific network.
     */
    std::vector<std::shared_ptr<WsSessionCoro>> get_sessions_by_network(uint32_t network_id);

    /**
     * Broadcast data to all sessions.
     * @param data Data to send
     */
    void broadcast(const std::vector<uint8_t>& data);

    /**
     * Broadcast data to all sessions in a network.
     * @param network_id Target network
     * @param data Data to send
     */
    void broadcast_to_network(uint32_t network_id, const std::vector<uint8_t>& data);

    /**
     * Execute a function for each session.
     * @param fn Function taking session pointer
     */
    template<typename Fn>
    void for_each(Fn&& fn) {
        cleanup_expired();
        for (auto& [node_id, info] : sessions_) {
            if (auto session = info.session.lock()) {
                fn(session);
            }
        }
    }

    /**
     * Get session count.
     */
    size_t session_count() const { return sessions_.size(); }

    /**
     * Get thread index.
     */
    size_t thread_index() const { return thread_index_; }

private:
    void cleanup_expired();

    size_t thread_index_;
    std::unordered_map<uint32_t, LocalSessionInfo> sessions_;
    size_t cleanup_counter_{0};
    static constexpr size_t kCleanupInterval = 100;  // Cleanup every N operations
};


/**
 * GlobalSessionDirectory - Global node location directory
 *
 * Tracks which thread each node is assigned to. Used for routing
 * cross-thread messages. This is the only shared data structure
 * between threads for session management.
 *
 * Design (per architecture.md Section 8.4):
 * - Uses shared_mutex for concurrent read access
 * - Write operations (register/unregister) are infrequent
 * - Read operations (lookup) are frequent and can be concurrent
 */
class GlobalSessionDirectory {
public:
    /**
     * Get the singleton instance.
     */
    static GlobalSessionDirectory& instance();

    // Non-copyable
    GlobalSessionDirectory(const GlobalSessionDirectory&) = delete;
    GlobalSessionDirectory& operator=(const GlobalSessionDirectory&) = delete;

    /**
     * Register a node's location.
     * @param node_id Node ID
     * @param thread_index Thread that owns this node's session
     */
    void register_node(uint32_t node_id, size_t thread_index);

    /**
     * Unregister a node.
     * @param node_id Node ID to remove
     */
    void unregister_node(uint32_t node_id);

    /**
     * Get the thread index for a node.
     * @param node_id Node to look up
     * @return Thread index, or std::nullopt if not found
     */
    std::optional<size_t> get_node_thread(uint32_t node_id) const;

    /**
     * Check if a node is registered.
     */
    bool has_node(uint32_t node_id) const;

    /**
     * Get all registered node IDs.
     */
    std::vector<uint32_t> get_all_nodes() const;

    /**
     * Get count of nodes on a specific thread.
     */
    size_t get_node_count_on_thread(size_t thread_index) const;

    /**
     * Get total node count.
     */
    size_t total_node_count() const;

    /**
     * Clear all entries (for testing/shutdown).
     */
    void clear();

private:
    GlobalSessionDirectory() = default;

    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, size_t> node_locations_;  // node_id -> thread_index
};

} // namespace edgelink

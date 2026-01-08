#pragma once

#include "controller/db/database.hpp"
#include <memory>
#include <vector>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <chrono>

namespace edgelink::controller {

// ============================================================================
// Path Information
// ============================================================================

struct RelayHop {
    uint32_t server_id;
    std::string server_name;
    std::string server_url;
    uint32_t latency_ms;  // Latency from previous hop to this relay
};

struct PathInfo {
    uint32_t src_node_id;
    uint32_t dst_node_id;
    uint32_t total_latency_ms;
    uint8_t hop_count;
    std::vector<RelayHop> hops;
    
    // Path types
    enum class Type {
        DIRECT_RELAY,    // Both nodes on same relay
        CROSS_RELAY,     // Nodes on different relays (relay mesh)
        P2P_POSSIBLE,    // P2P might work based on NAT types
        UNKNOWN
    };
    Type type{Type::UNKNOWN};
    
    // Comparison for sorting (prefer lower latency)
    bool operator<(const PathInfo& other) const {
        if (total_latency_ms != other.total_latency_ms) {
            return total_latency_ms < other.total_latency_ms;
        }
        return hop_count < other.hop_count;
    }
};

// ============================================================================
// Latency Cache Entry
// ============================================================================

struct LatencyCacheEntry {
    uint32_t rtt_ms;
    std::chrono::steady_clock::time_point last_update;
    bool is_stale(std::chrono::seconds max_age) const {
        return (std::chrono::steady_clock::now() - last_update) > max_age;
    }
};

// ============================================================================
// Path Service
// ============================================================================

class PathService {
public:
    explicit PathService(std::shared_ptr<Database> db);
    
    // ========================================================================
    // Latency Management
    // ========================================================================
    
    // Update node-to-relay latency
    void update_node_relay_latency(uint32_t node_id, uint32_t server_id, uint32_t rtt_ms);
    
    // Update relay-to-relay latency
    void update_relay_relay_latency(uint32_t src_server_id, uint32_t dst_server_id, uint32_t rtt_ms);
    
    // Get cached latency (returns 0 if unknown)
    uint32_t get_node_relay_latency(uint32_t node_id, uint32_t server_id) const;
    uint32_t get_relay_relay_latency(uint32_t src_server_id, uint32_t dst_server_id) const;
    
    // ========================================================================
    // Path Calculation
    // ========================================================================
    
    // Calculate best path between two nodes
    std::optional<PathInfo> calculate_best_path(uint32_t src_node_id, uint32_t dst_node_id);
    
    // Calculate all possible paths (for debugging/visualization)
    std::vector<PathInfo> calculate_all_paths(uint32_t src_node_id, uint32_t dst_node_id);
    
    // Get recommended relay for a node (lowest average latency)
    std::optional<uint32_t> get_recommended_relay(uint32_t node_id);
    
    // ========================================================================
    // Path Matrix
    // ========================================================================
    
    // Pre-calculate paths for all node pairs in a network (call periodically)
    void rebuild_path_matrix(uint32_t network_id);
    
    // Get pre-calculated path (fast lookup)
    std::optional<PathInfo> get_cached_path(uint32_t src_node_id, uint32_t dst_node_id) const;
    
    // ========================================================================
    // Configuration
    // ========================================================================
    
    // Max latency age before considered stale (default: 2 minutes)
    void set_latency_max_age(std::chrono::seconds max_age) { latency_max_age_ = max_age; }
    
    // Max path calculation depth (for relay hops)
    void set_max_hop_count(uint8_t max_hops) { max_hop_count_ = max_hops; }

private:
    std::shared_ptr<Database> db_;
    
    // Configuration
    std::chrono::seconds latency_max_age_{120};  // 2 minutes
    uint8_t max_hop_count_{2};  // Max relay hops (direct + 1 cross)
    
    // In-memory latency cache
    mutable std::mutex cache_mutex_;
    
    // Key format: "node:{node_id}:server:{server_id}"
    std::unordered_map<std::string, LatencyCacheEntry> node_relay_latency_;
    
    // Key format: "server:{src_id}:server:{dst_id}"
    std::unordered_map<std::string, LatencyCacheEntry> relay_relay_latency_;
    
    // Pre-calculated path matrix
    // Key format: "{src_node_id}:{dst_node_id}"
    std::unordered_map<std::string, PathInfo> path_matrix_;
    
    // Helper functions
    static std::string make_node_relay_key(uint32_t node_id, uint32_t server_id);
    static std::string make_relay_relay_key(uint32_t src_id, uint32_t dst_id);
    static std::string make_path_key(uint32_t src_id, uint32_t dst_id);
    
    // Get connected relays for a node
    std::vector<uint32_t> get_node_relays(uint32_t node_id) const;
    
    // Calculate single path through specific relays
    std::optional<PathInfo> calculate_path_via_relay(
        uint32_t src_node_id, uint32_t dst_node_id, uint32_t relay_id);
    
    std::optional<PathInfo> calculate_path_via_relay_pair(
        uint32_t src_node_id, uint32_t dst_node_id,
        uint32_t src_relay_id, uint32_t dst_relay_id);
};

} // namespace edgelink::controller

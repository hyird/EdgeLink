#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <optional>

#include <boost/json.hpp>

namespace edgelink {

// ============================================================================
// NodeLocationCache - Caches which nodes are connected to which relays
// 
// This cache is populated by Controller via SERVER_NODE_LOC messages.
// Relays use this to determine where to forward data for cross-relay routing.
// ============================================================================
class NodeLocationCache {
public:
    struct NodeLocation {
        uint32_t node_id;
        std::vector<uint32_t> relay_ids;  // Relays this node is connected to
        std::chrono::steady_clock::time_point updated_at;
    };
    
    NodeLocationCache() = default;
    ~NodeLocationCache() = default;
    
    // Update location for a node
    // If relay_ids is empty, the node is considered offline
    void update(uint32_t node_id, std::vector<uint32_t> relay_ids);
    
    // Add a relay to a node's location
    void add_relay(uint32_t node_id, uint32_t relay_id);
    
    // Remove a relay from a node's location
    void remove_relay(uint32_t node_id, uint32_t relay_id);
    
    // Remove a node entirely (offline)
    void remove_node(uint32_t node_id);
    
    // Get relays for a node
    std::vector<uint32_t> get_relays(uint32_t node_id) const;
    
    // Check if node is known
    bool has_node(uint32_t node_id) const;
    
    // Check if node is on a specific relay
    bool is_on_relay(uint32_t node_id, uint32_t relay_id) const;
    
    // Get all known nodes
    std::vector<uint32_t> get_all_nodes() const;
    
    // Get all nodes on a specific relay
    std::vector<uint32_t> get_nodes_on_relay(uint32_t relay_id) const;
    
    // Clear all entries
    void clear();
    
    // Process location update from controller
    // JSON format: {"updates": [{"node_id": N, "relay_ids": [...], "action": "add/remove"}]}
    void process_update(const boost::json::object& update);
    
    // Statistics
    size_t size() const;
    
private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<uint32_t, NodeLocation> locations_;
    
    // Reverse index: relay_id -> set of node_ids
    std::unordered_map<uint32_t, std::vector<uint32_t>> relay_to_nodes_;
    
    // Update reverse index
    void rebuild_reverse_index();
};

// ============================================================================
// NodeLocationUpdate - Represents a single location update
// ============================================================================
struct NodeLocationUpdate {
    uint32_t node_id;
    std::vector<uint32_t> relay_ids;
    enum class Action { ADD, REMOVE, SET } action;
    
    bool from_json(const boost::json::object& obj);
};

} // namespace edgelink

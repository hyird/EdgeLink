#include "node_location_cache.hpp"
#include "common/log.hpp"

#include <algorithm>

namespace edgelink {

// ============================================================================
// NodeLocationCache Implementation
// ============================================================================

void NodeLocationCache::update(uint32_t node_id, std::vector<uint32_t> relay_ids) {
    std::unique_lock lock(mutex_);
    
    if (relay_ids.empty()) {
        // Node offline - remove entirely
        locations_.erase(node_id);
        LOG_DEBUG("Node {} location cleared (offline)", node_id);
    } else {
        auto& loc = locations_[node_id];
        loc.node_id = node_id;
        loc.relay_ids = std::move(relay_ids);
        loc.updated_at = std::chrono::steady_clock::now();
        LOG_DEBUG("Node {} location updated: {} relays", node_id, loc.relay_ids.size());
    }
    
    rebuild_reverse_index();
}

void NodeLocationCache::add_relay(uint32_t node_id, uint32_t relay_id) {
    std::unique_lock lock(mutex_);
    
    auto& loc = locations_[node_id];
    loc.node_id = node_id;
    
    // Check if already present
    auto it = std::find(loc.relay_ids.begin(), loc.relay_ids.end(), relay_id);
    if (it == loc.relay_ids.end()) {
        loc.relay_ids.push_back(relay_id);
        loc.updated_at = std::chrono::steady_clock::now();
        
        // Update reverse index
        relay_to_nodes_[relay_id].push_back(node_id);
        
        LOG_DEBUG("Node {} added to relay {}", node_id, relay_id);
    }
}

void NodeLocationCache::remove_relay(uint32_t node_id, uint32_t relay_id) {
    std::unique_lock lock(mutex_);
    
    auto it = locations_.find(node_id);
    if (it == locations_.end()) {
        return;
    }
    
    auto& relays = it->second.relay_ids;
    relays.erase(std::remove(relays.begin(), relays.end(), relay_id), relays.end());
    it->second.updated_at = std::chrono::steady_clock::now();
    
    // If no more relays, remove the node
    if (relays.empty()) {
        locations_.erase(it);
        LOG_DEBUG("Node {} removed (no relays)", node_id);
    } else {
        LOG_DEBUG("Node {} removed from relay {}", node_id, relay_id);
    }
    
    // Update reverse index
    auto& nodes = relay_to_nodes_[relay_id];
    nodes.erase(std::remove(nodes.begin(), nodes.end(), node_id), nodes.end());
}

void NodeLocationCache::remove_node(uint32_t node_id) {
    std::unique_lock lock(mutex_);
    
    auto it = locations_.find(node_id);
    if (it != locations_.end()) {
        // Remove from reverse index
        for (uint32_t relay_id : it->second.relay_ids) {
            auto& nodes = relay_to_nodes_[relay_id];
            nodes.erase(std::remove(nodes.begin(), nodes.end(), node_id), nodes.end());
        }
        
        locations_.erase(it);
        LOG_DEBUG("Node {} removed entirely", node_id);
    }
}

std::vector<uint32_t> NodeLocationCache::get_relays(uint32_t node_id) const {
    std::shared_lock lock(mutex_);
    
    auto it = locations_.find(node_id);
    if (it != locations_.end()) {
        return it->second.relay_ids;
    }
    return {};
}

bool NodeLocationCache::has_node(uint32_t node_id) const {
    std::shared_lock lock(mutex_);
    return locations_.find(node_id) != locations_.end();
}

bool NodeLocationCache::is_on_relay(uint32_t node_id, uint32_t relay_id) const {
    std::shared_lock lock(mutex_);
    
    auto it = locations_.find(node_id);
    if (it == locations_.end()) {
        return false;
    }
    
    const auto& relays = it->second.relay_ids;
    return std::find(relays.begin(), relays.end(), relay_id) != relays.end();
}

std::vector<uint32_t> NodeLocationCache::get_all_nodes() const {
    std::shared_lock lock(mutex_);
    
    std::vector<uint32_t> nodes;
    nodes.reserve(locations_.size());
    for (const auto& [node_id, _] : locations_) {
        nodes.push_back(node_id);
    }
    return nodes;
}

std::vector<uint32_t> NodeLocationCache::get_nodes_on_relay(uint32_t relay_id) const {
    std::shared_lock lock(mutex_);
    
    auto it = relay_to_nodes_.find(relay_id);
    if (it != relay_to_nodes_.end()) {
        return it->second;
    }
    return {};
}

void NodeLocationCache::clear() {
    std::unique_lock lock(mutex_);
    locations_.clear();
    relay_to_nodes_.clear();
}

void NodeLocationCache::process_update(const boost::json::object& update) {
    if (!update.contains("updates") || !update.at("updates").is_array()) {
        LOG_WARN("Invalid node location update: missing 'updates' array");
        return;
    }
    
    const auto& updates = update.at("updates").as_array();
    
    for (const auto& item : updates) {
        if (!item.is_object()) continue;
        
        NodeLocationUpdate upd;
        if (!upd.from_json(item.as_object())) {
            continue;
        }
        
        switch (upd.action) {
            case NodeLocationUpdate::Action::SET:
                this->update(upd.node_id, std::move(upd.relay_ids));
                break;
                
            case NodeLocationUpdate::Action::ADD:
                for (uint32_t relay_id : upd.relay_ids) {
                    add_relay(upd.node_id, relay_id);
                }
                break;
                
            case NodeLocationUpdate::Action::REMOVE:
                if (upd.relay_ids.empty()) {
                    remove_node(upd.node_id);
                } else {
                    for (uint32_t relay_id : upd.relay_ids) {
                        remove_relay(upd.node_id, relay_id);
                    }
                }
                break;
        }
    }
}

size_t NodeLocationCache::size() const {
    std::shared_lock lock(mutex_);
    return locations_.size();
}

void NodeLocationCache::rebuild_reverse_index() {
    // Called with mutex already held
    relay_to_nodes_.clear();
    
    for (const auto& [node_id, loc] : locations_) {
        for (uint32_t relay_id : loc.relay_ids) {
            relay_to_nodes_[relay_id].push_back(node_id);
        }
    }
}

// ============================================================================
// NodeLocationUpdate Implementation
// ============================================================================

bool NodeLocationUpdate::from_json(const boost::json::object& obj) {
    try {
        if (!obj.contains("node_id")) {
            return false;
        }
        
        node_id = static_cast<uint32_t>(obj.at("node_id").as_int64());
        
        // Parse relay_ids
        relay_ids.clear();
        if (obj.contains("relay_ids") && obj.at("relay_ids").is_array()) {
            for (const auto& r : obj.at("relay_ids").as_array()) {
                relay_ids.push_back(static_cast<uint32_t>(r.as_int64()));
            }
        }
        
        // Parse action
        action = Action::SET;  // default
        if (obj.contains("action")) {
            std::string action_str = obj.at("action").as_string().c_str();
            if (action_str == "add") {
                action = Action::ADD;
            } else if (action_str == "remove") {
                action = Action::REMOVE;
            } else {
                action = Action::SET;
            }
        }
        
        return true;
        
    } catch (const std::exception& e) {
        LOG_WARN("Failed to parse NodeLocationUpdate: {}", e.what());
        return false;
    }
}

} // namespace edgelink

#include "path_service.hpp"
#include "common/log.hpp"
#include <algorithm>
#include <limits>

namespace edgelink::controller {

PathService::PathService(std::shared_ptr<Database> db)
    : db_(std::move(db)) {
}

// ============================================================================
// Key Generation Helpers
// ============================================================================

std::string PathService::make_node_relay_key(uint32_t node_id, uint32_t server_id) {
    return "node:" + std::to_string(node_id) + ":server:" + std::to_string(server_id);
}

std::string PathService::make_relay_relay_key(uint32_t src_id, uint32_t dst_id) {
    // Always use smaller ID first for bidirectional lookup
    if (src_id > dst_id) std::swap(src_id, dst_id);
    return "server:" + std::to_string(src_id) + ":server:" + std::to_string(dst_id);
}

std::string PathService::make_path_key(uint32_t src_id, uint32_t dst_id) {
    return std::to_string(src_id) + ":" + std::to_string(dst_id);
}

// ============================================================================
// Latency Management
// ============================================================================

void PathService::update_node_relay_latency(uint32_t node_id, uint32_t server_id, uint32_t rtt_ms) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto key = make_node_relay_key(node_id, server_id);
    node_relay_latency_[key] = LatencyCacheEntry{
        rtt_ms,
        std::chrono::steady_clock::now()
    };
    
    // Also persist to database
    db_->update_latency("node", node_id, "server", server_id, rtt_ms);
    
    LOG_DEBUG("PathService: Updated latency node {} -> server {}: {} ms",
              node_id, server_id, rtt_ms);
}

void PathService::update_relay_relay_latency(uint32_t src_server_id, uint32_t dst_server_id, uint32_t rtt_ms) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto key = make_relay_relay_key(src_server_id, dst_server_id);
    relay_relay_latency_[key] = LatencyCacheEntry{
        rtt_ms,
        std::chrono::steady_clock::now()
    };
    
    // Persist to database
    db_->update_latency("server", src_server_id, "server", dst_server_id, rtt_ms);
    
    LOG_DEBUG("PathService: Updated latency server {} <-> server {}: {} ms",
              src_server_id, dst_server_id, rtt_ms);
}

uint32_t PathService::get_node_relay_latency(uint32_t node_id, uint32_t server_id) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto key = make_node_relay_key(node_id, server_id);
    auto it = node_relay_latency_.find(key);
    
    if (it != node_relay_latency_.end() && !it->second.is_stale(latency_max_age_)) {
        return it->second.rtt_ms;
    }
    
    // Try database
    auto db_latency = db_->get_latency("node", node_id, "server", server_id);
    if (db_latency) {
        return *db_latency;
    }
    
    return 0;  // Unknown
}

uint32_t PathService::get_relay_relay_latency(uint32_t src_server_id, uint32_t dst_server_id) const {
    if (src_server_id == dst_server_id) {
        return 0;  // Same relay
    }
    
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto key = make_relay_relay_key(src_server_id, dst_server_id);
    auto it = relay_relay_latency_.find(key);
    
    if (it != relay_relay_latency_.end() && !it->second.is_stale(latency_max_age_)) {
        return it->second.rtt_ms;
    }
    
    // Try database
    auto db_latency = db_->get_latency("server", src_server_id, "server", dst_server_id);
    if (db_latency) {
        return *db_latency;
    }
    
    return 0;  // Unknown
}

// ============================================================================
// Path Calculation
// ============================================================================

std::vector<uint32_t> PathService::get_node_relays(uint32_t node_id) const {
    return db_->get_node_connected_servers(node_id);
}

std::optional<PathInfo> PathService::calculate_path_via_relay(
    uint32_t src_node_id, uint32_t dst_node_id, uint32_t relay_id) {
    
    uint32_t src_latency = get_node_relay_latency(src_node_id, relay_id);
    uint32_t dst_latency = get_node_relay_latency(dst_node_id, relay_id);
    
    // Both must have known latency
    if (src_latency == 0 || dst_latency == 0) {
        return std::nullopt;
    }
    
    auto server_opt = db_->get_server(relay_id);
    if (!server_opt) {
        return std::nullopt;
    }
    
    PathInfo path;
    path.src_node_id = src_node_id;
    path.dst_node_id = dst_node_id;
    path.total_latency_ms = src_latency + dst_latency;
    path.hop_count = 1;
    path.type = PathInfo::Type::DIRECT_RELAY;
    
    path.hops.push_back(RelayHop{
        relay_id,
        server_opt->name,
        server_opt->url,
        src_latency + dst_latency
    });
    
    return path;
}

std::optional<PathInfo> PathService::calculate_path_via_relay_pair(
    uint32_t src_node_id, uint32_t dst_node_id,
    uint32_t src_relay_id, uint32_t dst_relay_id) {
    
    if (src_relay_id == dst_relay_id) {
        return calculate_path_via_relay(src_node_id, dst_node_id, src_relay_id);
    }
    
    uint32_t src_to_relay = get_node_relay_latency(src_node_id, src_relay_id);
    uint32_t relay_to_relay = get_relay_relay_latency(src_relay_id, dst_relay_id);
    uint32_t relay_to_dst = get_node_relay_latency(dst_node_id, dst_relay_id);
    
    // All segments must have known latency
    if (src_to_relay == 0 || relay_to_relay == 0 || relay_to_dst == 0) {
        return std::nullopt;
    }
    
    auto src_server_opt = db_->get_server(src_relay_id);
    auto dst_server_opt = db_->get_server(dst_relay_id);
    
    if (!src_server_opt || !dst_server_opt) {
        return std::nullopt;
    }
    
    PathInfo path;
    path.src_node_id = src_node_id;
    path.dst_node_id = dst_node_id;
    path.total_latency_ms = src_to_relay + relay_to_relay + relay_to_dst;
    path.hop_count = 2;
    path.type = PathInfo::Type::CROSS_RELAY;
    
    path.hops.push_back(RelayHop{
        src_relay_id,
        src_server_opt->name,
        src_server_opt->url,
        src_to_relay
    });
    
    path.hops.push_back(RelayHop{
        dst_relay_id,
        dst_server_opt->name,
        dst_server_opt->url,
        relay_to_relay + relay_to_dst
    });
    
    return path;
}

std::optional<PathInfo> PathService::calculate_best_path(uint32_t src_node_id, uint32_t dst_node_id) {
    auto all_paths = calculate_all_paths(src_node_id, dst_node_id);
    
    if (all_paths.empty()) {
        return std::nullopt;
    }
    
    // Paths are already sorted by latency (lowest first)
    return all_paths.front();
}

std::vector<PathInfo> PathService::calculate_all_paths(uint32_t src_node_id, uint32_t dst_node_id) {
    std::vector<PathInfo> paths;
    
    auto src_relays = get_node_relays(src_node_id);
    auto dst_relays = get_node_relays(dst_node_id);
    
    if (src_relays.empty() || dst_relays.empty()) {
        LOG_DEBUG("PathService: No relays for nodes {} or {}", src_node_id, dst_node_id);
        return paths;
    }
    
    // Find common relays (direct path)
    std::vector<uint32_t> common_relays;
    for (uint32_t src_relay : src_relays) {
        for (uint32_t dst_relay : dst_relays) {
            if (src_relay == dst_relay) {
                common_relays.push_back(src_relay);
                break;
            }
        }
    }
    
    // Try direct paths through common relays
    for (uint32_t relay_id : common_relays) {
        auto path = calculate_path_via_relay(src_node_id, dst_node_id, relay_id);
        if (path) {
            paths.push_back(*path);
        }
    }
    
    // Try cross-relay paths (if allowed by max_hop_count)
    if (max_hop_count_ >= 2) {
        for (uint32_t src_relay : src_relays) {
            for (uint32_t dst_relay : dst_relays) {
                if (src_relay == dst_relay) continue;  // Already handled
                
                auto path = calculate_path_via_relay_pair(
                    src_node_id, dst_node_id, src_relay, dst_relay);
                if (path) {
                    paths.push_back(*path);
                }
            }
        }
    }
    
    // Sort by total latency
    std::sort(paths.begin(), paths.end());
    
    LOG_DEBUG("PathService: Found {} paths from node {} to node {}",
              paths.size(), src_node_id, dst_node_id);
    
    return paths;
}

std::optional<uint32_t> PathService::get_recommended_relay(uint32_t node_id) {
    auto relays = get_node_relays(node_id);
    
    if (relays.empty()) {
        return std::nullopt;
    }
    
    uint32_t best_relay = relays.front();
    uint32_t best_latency = std::numeric_limits<uint32_t>::max();
    
    for (uint32_t relay_id : relays) {
        uint32_t latency = get_node_relay_latency(node_id, relay_id);
        if (latency > 0 && latency < best_latency) {
            best_latency = latency;
            best_relay = relay_id;
        }
    }
    
    return best_relay;
}

// ============================================================================
// Path Matrix
// ============================================================================

void PathService::rebuild_path_matrix(uint32_t network_id) {
    LOG_INFO("PathService: Rebuilding path matrix for network {}", network_id);
    
    auto nodes = db_->list_online_nodes(network_id);
    
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    // Clear old matrix
    path_matrix_.clear();
    
    // Calculate paths for all pairs
    for (size_t i = 0; i < nodes.size(); ++i) {
        for (size_t j = i + 1; j < nodes.size(); ++j) {
            uint32_t src_id = nodes[i].id;
            uint32_t dst_id = nodes[j].id;
            
            // Calculate in both directions (might be asymmetric)
            auto path_fwd = calculate_best_path(src_id, dst_id);
            auto path_rev = calculate_best_path(dst_id, src_id);
            
            if (path_fwd) {
                path_matrix_[make_path_key(src_id, dst_id)] = *path_fwd;
            }
            if (path_rev) {
                path_matrix_[make_path_key(dst_id, src_id)] = *path_rev;
            }
        }
    }
    
    LOG_INFO("PathService: Path matrix rebuilt with {} entries", path_matrix_.size());
}

std::optional<PathInfo> PathService::get_cached_path(uint32_t src_node_id, uint32_t dst_node_id) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto key = make_path_key(src_node_id, dst_node_id);
    auto it = path_matrix_.find(key);
    
    if (it != path_matrix_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

} // namespace edgelink::controller

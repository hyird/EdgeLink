#include "client/route_manager.hpp"
#include "common/log.hpp"

#include "common/platform_net.hpp"
#include <regex>
#include <algorithm>
#include <random>

namespace edgelink::client {

// Thread-local random engine for weighted selection
static thread_local std::mt19937 rng{std::random_device{}()};

static uint32_t weighted_random() {
    return rng();
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

RouteManager::RouteManager(const std::string& tun_name)
    : tun_name_(tun_name)
{
}

RouteManager::~RouteManager() {
    (void)remove_routes();  // Ignore return value in destructor
}

// ============================================================================
// Network Configuration
// ============================================================================

void RouteManager::set_network_cidr(const std::string& cidr) {
    // Parse CIDR notation: "10.100.0.0/16"
    std::regex cidr_regex(R"((\d+\.\d+\.\d+\.\d+)/(\d+))");
    std::smatch match;
    
    if (std::regex_match(cidr, match, cidr_regex)) {
        std::string network_str = match[1].str();
        network_prefix_ = static_cast<uint8_t>(std::stoi(match[2].str()));
        network_addr_ = parse_ip(network_str);
        
        LOG_INFO("RouteManager: Network CIDR set to {}/{}", network_str, network_prefix_);
    } else {
        LOG_ERROR("RouteManager: Invalid CIDR format: {}", cidr);
    }
}

void RouteManager::set_local_ip(const std::string& ip) {
    local_ip_ = ip;
    local_ip_int_ = parse_ip(ip);
    LOG_INFO("RouteManager: Local IP set to {}", ip);
}

// ============================================================================
// Peer Routes
// ============================================================================

void RouteManager::add_peer(uint32_t node_id, const std::string& virtual_ip) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    uint32_t ip = parse_ip(virtual_ip);
    ip_to_node_[ip] = node_id;
    
    PeerRouteInfo info;
    info.node_id = node_id;
    info.virtual_ip = virtual_ip;
    info.reachable = false;
    info.has_p2p = false;
    info.primary_relay_id = 0;
    
    peer_routes_[node_id] = info;
    
    LOG_DEBUG("RouteManager: Added peer {} -> {}", virtual_ip, node_id);
}

void RouteManager::remove_peer(uint32_t node_id) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_routes_.find(node_id);
    if (it != peer_routes_.end()) {
        uint32_t ip = parse_ip(it->second.virtual_ip);
        ip_to_node_.erase(ip);
        peer_routes_.erase(it);
        LOG_DEBUG("RouteManager: Removed peer {}", node_id);
    }
}

void RouteManager::set_peer_reachable(uint32_t node_id, bool reachable) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = peer_routes_.find(node_id);
    if (it != peer_routes_.end()) {
        it->second.reachable = reachable;
    }
}

// ============================================================================
// Subnet Routes
// ============================================================================

void RouteManager::add_subnet_route(const RouteEntry& route) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    // Check if route already exists
    for (auto& existing : subnet_routes_) {
        if (existing.network == route.network && 
            existing.prefix_len == route.prefix_len &&
            existing.via_node_id == route.via_node_id) {
            // Update existing
            existing = route;
            LOG_DEBUG("RouteManager: Updated subnet route {}/{} via node {}", 
                      route.network, route.prefix_len, route.via_node_id);
            return;
        }
    }
    
    subnet_routes_.push_back(route);
    LOG_DEBUG("RouteManager: Added subnet route {}/{} via node {}", 
              route.network, route.prefix_len, route.via_node_id);
}

void RouteManager::remove_subnet_route(const std::string& network, uint8_t prefix_len, 
                                       uint32_t via_node_id) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    auto it = std::remove_if(subnet_routes_.begin(), subnet_routes_.end(),
        [&](const RouteEntry& r) {
            return r.network == network && 
                   r.prefix_len == prefix_len &&
                   r.via_node_id == via_node_id;
        });
    
    if (it != subnet_routes_.end()) {
        subnet_routes_.erase(it, subnet_routes_.end());
        LOG_DEBUG("RouteManager: Removed subnet route {}/{} via node {}", 
                  network, prefix_len, via_node_id);
    }
}

void RouteManager::update_subnet_routes(const std::vector<RouteEntry>& routes) {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    
    // Mark all as inactive
    for (auto& r : subnet_routes_) {
        r.active = false;
    }
    
    // Update/add routes from Controller
    for (const auto& route : routes) {
        bool found = false;
        for (auto& existing : subnet_routes_) {
            if (existing.network == route.network &&
                existing.prefix_len == route.prefix_len &&
                existing.via_node_id == route.via_node_id) {
                existing = route;
                existing.active = true;
                found = true;
                break;
            }
        }
        
        if (!found) {
            RouteEntry new_route = route;
            new_route.active = true;
            subnet_routes_.push_back(new_route);
        }
    }
    
    // Remove inactive routes
    auto it = std::remove_if(subnet_routes_.begin(), subnet_routes_.end(),
        [](const RouteEntry& r) { return !r.active; });
    subnet_routes_.erase(it, subnet_routes_.end());
    
    LOG_DEBUG("RouteManager: Updated {} subnet routes", routes.size());
}

// ============================================================================
// Route Lookup
// ============================================================================

uint32_t RouteManager::lookup(const std::string& dst_ip) const {
    return lookup(parse_ip(dst_ip));
}

uint32_t RouteManager::lookup(uint32_t dst_ip) const {
    // Skip if it's our own IP
    if (dst_ip == local_ip_int_) {
        return 0;
    }
    
    // First, check direct peer routes (most specific for /32)
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = ip_to_node_.find(dst_ip);
        if (it != ip_to_node_.end()) {
            // Check if peer is reachable
            auto peer_it = peer_routes_.find(it->second);
            if (peer_it != peer_routes_.end() && peer_it->second.reachable) {
                return it->second;
            }
            // Fall through to subnet routes if peer is not reachable
        }
    }
    
    // Then, check subnet routes using the algorithm from design doc:
    // 1. Find all matching routes (longest prefix match)
    // 2. Filter by highest priority
    // 3. Filter by gateway online status
    // 4. Weighted random selection among candidates
    {
        std::lock_guard<std::mutex> lock(routes_mutex_);
        
        // Step 1: Find matching routes and longest prefix
        std::vector<const RouteEntry*> matching;
        uint8_t longest_prefix = 0;
        
        for (const auto& route : subnet_routes_) {
            if (!route.active) continue;
            
            uint32_t network = parse_ip(route.network);
            if (ip_matches(dst_ip, network, route.prefix_len)) {
                if (route.prefix_len > longest_prefix) {
                    longest_prefix = route.prefix_len;
                    matching.clear();
                    matching.push_back(&route);
                } else if (route.prefix_len == longest_prefix) {
                    matching.push_back(&route);
                }
            }
        }
        
        if (matching.empty()) {
            return 0;  // No route found
        }
        
        // Step 2: Filter by highest priority
        uint16_t max_priority = 0;
        for (const auto* r : matching) {
            if (r->priority > max_priority) {
                max_priority = r->priority;
            }
        }
        
        std::vector<const RouteEntry*> priority_filtered;
        for (const auto* r : matching) {
            if (r->priority == max_priority) {
                priority_filtered.push_back(r);
            }
        }
        
        // Step 3: Filter by gateway online status
        std::vector<const RouteEntry*> online_filtered;
        {
            std::lock_guard<std::mutex> peer_lock(peers_mutex_);
            for (const auto* r : priority_filtered) {
                auto peer_it = peer_routes_.find(r->via_node_id);
                if (peer_it != peer_routes_.end() && peer_it->second.reachable) {
                    online_filtered.push_back(r);
                }
            }
        }
        
        // If no online gateways, fall back to all candidates
        if (online_filtered.empty()) {
            online_filtered = priority_filtered;
        }
        
        // Step 4: Weighted random selection
        if (online_filtered.size() == 1) {
            return online_filtered[0]->via_node_id;
        }
        
        // Calculate total weight
        uint32_t total_weight = 0;
        for (const auto* r : online_filtered) {
            total_weight += r->weight > 0 ? r->weight : 1;  // Minimum weight of 1
        }
        
        // Random selection
        uint32_t rand_val = weighted_random() % total_weight;
        uint32_t cumulative = 0;
        
        for (const auto* r : online_filtered) {
            cumulative += r->weight > 0 ? r->weight : 1;
            if (rand_val < cumulative) {
                return r->via_node_id;
            }
        }
        
        // Fallback (shouldn't reach here)
        return online_filtered[0]->via_node_id;
    }
    
    return 0;  // No route found
}

bool RouteManager::is_mesh_ip(const std::string& ip) const {
    return is_mesh_ip(parse_ip(ip));
}

bool RouteManager::is_mesh_ip(uint32_t ip) const {
    return ip_matches(ip, network_addr_, network_prefix_);
}

uint32_t RouteManager::get_node_by_ip(const std::string& ip) const {
    return get_node_by_ip(parse_ip(ip));
}

uint32_t RouteManager::get_node_by_ip(uint32_t ip) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    
    auto it = ip_to_node_.find(ip);
    if (it != ip_to_node_.end()) {
        return it->second;
    }
    return 0;
}

// ============================================================================
// System Route Management
// ============================================================================

std::expected<void, ErrorCode> RouteManager::apply_routes() {
    // First, remove existing routes
    (void)remove_routes();  // Ignore return value - best effort cleanup
    
    // Add route for entire virtual network
    if (network_addr_ != 0) {
        std::string cmd = "ip route add " + format_ip(network_addr_) + "/" + 
                         std::to_string(network_prefix_) + " dev " + tun_name_;
        
        int ret = std::system(cmd.c_str());
        if (ret != 0) {
            LOG_ERROR("RouteManager: Failed to add network route");
            return std::unexpected(ErrorCode::SYSTEM_ERROR);
        }
        
        applied_routes_.emplace_back(format_ip(network_addr_), network_prefix_);
        LOG_INFO("RouteManager: Added network route {}/{} via {}", 
                 format_ip(network_addr_), network_prefix_, tun_name_);
    }
    
    // Add subnet routes
    std::vector<RouteEntry> routes_copy;
    {
        std::lock_guard<std::mutex> lock(routes_mutex_);
        routes_copy = subnet_routes_;
    }
    
    for (const auto& route : routes_copy) {
        if (!route.active) continue;
        
        // Subnet routes are handled at the mesh level, not OS level
        // The lookup() function handles routing within the mesh
    }
    
    return {};
}

std::expected<void, ErrorCode> RouteManager::remove_routes() {
    for (const auto& [network, prefix] : applied_routes_) {
        std::string cmd = "ip route del " + network + "/" + 
                         std::to_string(prefix) + " dev " + tun_name_ + " 2>/dev/null";
        std::system(cmd.c_str());
    }
    
    applied_routes_.clear();
    return {};
}

// ============================================================================
// Status
// ============================================================================

std::vector<RouteEntry> RouteManager::get_routes() const {
    std::lock_guard<std::mutex> lock(routes_mutex_);
    return subnet_routes_;
}

std::vector<PeerRouteInfo> RouteManager::get_peer_routes() const {
    std::vector<PeerRouteInfo> result;
    
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto& [id, info] : peer_routes_) {
        result.push_back(info);
    }
    
    return result;
}

// ============================================================================
// Helper Functions
// ============================================================================

uint32_t RouteManager::parse_ip(const std::string& ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
        return ntohl(addr.s_addr);
    }
    return 0;
}

std::string RouteManager::format_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

bool RouteManager::ip_matches(uint32_t ip, uint32_t network, uint8_t prefix) {
    if (prefix == 0) return true;
    if (prefix >= 32) return ip == network;
    
    uint32_t mask = ~((1u << (32 - prefix)) - 1);
    return (ip & mask) == (network & mask);
}

uint32_t RouteManager::calculate_network(uint32_t ip, uint8_t prefix) {
    if (prefix == 0) return 0;
    if (prefix >= 32) return ip;
    
    uint32_t mask = ~((1u << (32 - prefix)) - 1);
    return ip & mask;
}

} // namespace edgelink::client

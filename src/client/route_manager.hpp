#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <expected>

#include "common/protocol.hpp"

namespace edgelink::client {

// Import wire protocol error codes to avoid conflicts with proto types
using ErrorCode = wire::ErrorCode;

// ============================================================================
// Route Entry
// ============================================================================
struct RouteEntry {
    std::string network;        // e.g., "10.100.1.0"
    uint8_t prefix_len;         // e.g., 24
    uint32_t via_node_id;       // Next hop node ID (0 = direct)
    uint16_t metric;            // Lower is better
    bool active;                // Currently active route
    
    // For subnet routes (advertised by gateway nodes)
    uint16_t weight;            // For load balancing
    uint16_t priority;          // Higher priority wins
};

// ============================================================================
// Peer Route Info (direct routes to mesh peers)
// ============================================================================
struct PeerRouteInfo {
    uint32_t node_id;
    std::string virtual_ip;
    bool reachable;
    bool has_p2p;
    uint32_t primary_relay_id;
};

// ============================================================================
// Route Manager - Manages routing table for virtual network
// ============================================================================
class RouteManager {
public:
    explicit RouteManager(const std::string& tun_name);
    ~RouteManager();
    
    // ========================================================================
    // Network Configuration
    // ========================================================================
    
    // Set the virtual network CIDR (e.g., "10.100.0.0/16")
    void set_network_cidr(const std::string& cidr);
    
    // Set local virtual IP
    void set_local_ip(const std::string& ip);
    
    // ========================================================================
    // Peer Routes (direct routes to mesh peers)
    // ========================================================================
    
    // Add or update a peer's route
    void add_peer(uint32_t node_id, const std::string& virtual_ip);
    
    // Remove a peer's route
    void remove_peer(uint32_t node_id);
    
    // Update peer reachability
    void set_peer_reachable(uint32_t node_id, bool reachable);
    
    // ========================================================================
    // Subnet Routes (routes advertised by gateway nodes)
    // ========================================================================
    
    // Add a subnet route
    void add_subnet_route(const RouteEntry& route);
    
    // Remove a subnet route
    void remove_subnet_route(const std::string& network, uint8_t prefix_len, uint32_t via_node_id);
    
    // Update subnet routes from Controller
    void update_subnet_routes(const std::vector<RouteEntry>& routes);
    
    // ========================================================================
    // Route Lookup
    // ========================================================================
    
    // Find the best route for a destination IP
    // Returns the next-hop node ID (or 0 if local/unknown)
    uint32_t lookup(const std::string& dst_ip) const;
    
    // Find the best route for a destination IP (from uint32_t)
    uint32_t lookup(uint32_t dst_ip) const;
    
    // Check if IP is within our virtual network
    bool is_mesh_ip(const std::string& ip) const;
    bool is_mesh_ip(uint32_t ip) const;
    
    // Get node ID by virtual IP
    uint32_t get_node_by_ip(const std::string& ip) const;
    uint32_t get_node_by_ip(uint32_t ip) const;
    
    // ========================================================================
    // System Route Management
    // ========================================================================
    
    // Apply routes to system routing table
    std::expected<void, ErrorCode> apply_routes();
    
    // Remove all routes from system
    std::expected<void, ErrorCode> remove_routes();
    
    // ========================================================================
    // Status
    // ========================================================================
    
    // Get all active routes
    std::vector<RouteEntry> get_routes() const;
    
    // Get peer route info
    std::vector<PeerRouteInfo> get_peer_routes() const;

private:
    // Parse IP to uint32_t
    static uint32_t parse_ip(const std::string& ip);
    
    // Format IP from uint32_t
    static std::string format_ip(uint32_t ip);
    
    // Check if IP matches network/prefix
    static bool ip_matches(uint32_t ip, uint32_t network, uint8_t prefix);
    
    // Calculate network address from IP and prefix
    static uint32_t calculate_network(uint32_t ip, uint8_t prefix);
    
    std::string tun_name_;
    std::string local_ip_;
    uint32_t local_ip_int_ = 0;
    
    // Virtual network
    uint32_t network_addr_ = 0;
    uint8_t network_prefix_ = 0;
    
    // Peer routes: virtual_ip -> node_id
    mutable std::mutex peers_mutex_;
    std::unordered_map<uint32_t, uint32_t> ip_to_node_;
    std::unordered_map<uint32_t, PeerRouteInfo> peer_routes_;
    
    // Subnet routes
    mutable std::mutex routes_mutex_;
    std::vector<RouteEntry> subnet_routes_;
    
    // Applied system routes (for cleanup)
    std::vector<std::pair<std::string, uint8_t>> applied_routes_;
};

} // namespace edgelink::client

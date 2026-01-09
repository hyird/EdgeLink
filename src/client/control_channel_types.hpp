#pragma once

#include <string>
#include <vector>
#include <array>
#include <functional>
#include <chrono>

#include "common/protocol.hpp"
#include "common/frame.hpp"

namespace edgelink::client {

// Import wire protocol error codes
using ErrorCode = wire::ErrorCode;

// Network constants
namespace NetworkConstants {
    constexpr uint16_t DEFAULT_TUN_MTU = 1400;
    constexpr uint32_t DEFAULT_HEARTBEAT_INTERVAL = 30;
    constexpr uint32_t DEFAULT_RECONNECT_INTERVAL = 5;
    constexpr uint32_t MAX_RECONNECT_INTERVAL = 300;
}

// ============================================================================
// Network Configuration (received from Controller)
// ============================================================================
struct NetworkConfig {
    uint32_t network_id = 0;
    std::string network_name;
    std::string cidr;
    uint16_t mtu = NetworkConstants::DEFAULT_TUN_MTU;
};

// ============================================================================
// Peer Information (received from Controller)
// ============================================================================
struct PeerInfo {
    uint32_t node_id = 0;
    std::string hostname;
    std::string virtual_ip;
    std::array<uint8_t, 32> node_key_pub;
    bool online = false;
    std::vector<std::string> endpoints;
    std::vector<std::string> allowed_subnets;
    std::chrono::system_clock::time_point last_seen;
};

// ============================================================================
// Relay Server Info (received from Controller)
// ============================================================================
struct RelayServerInfo {
    uint32_t id = 0;
    std::string name;
    std::string region;
    std::string url;
    uint8_t capabilities = 0;
    bool available = true;
};

// ============================================================================
// STUN Server Info
// ============================================================================
struct STUNServerInfo {
    uint32_t id = 0;
    std::string name;
    std::string ip;
    uint16_t port = 3478;
    std::string secondary_ip;
};

// ============================================================================
// Subnet Route (advertised by gateway nodes)
// ============================================================================
struct SubnetRouteInfo {
    std::string cidr;
    uint32_t via_node_id = 0;
    std::string gateway_ip;
    uint16_t priority = 100;
    uint16_t weight = 100;
    uint32_t metric = 0;
    uint8_t flags = 0;
    bool gateway_online = false;
};

// ============================================================================
// Full Configuration Update
// ============================================================================
struct ConfigUpdate {
    uint64_t version = 0;
    NetworkConfig network;
    std::vector<PeerInfo> peers;
    std::vector<RelayServerInfo> relays;
    std::vector<STUNServerInfo> stun_servers;
    std::vector<SubnetRouteInfo> subnet_routes;
    std::string auth_token;
    std::string relay_token;
    int64_t relay_token_expires_at = 0;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Control Channel Callbacks
// ============================================================================
struct ControlCallbacks {
    std::function<void(const ConfigUpdate&)> on_config_update;
    std::function<void()> on_connected;
    std::function<void(ErrorCode)> on_disconnected;
    std::function<void(uint32_t node_id, const PeerInfo&)> on_peer_online;
    std::function<void(uint32_t node_id)> on_peer_offline;
    std::function<void(const std::string& new_auth_token,
                       const std::string& new_relay_token)> on_token_refresh;
    std::function<void(uint32_t node_id,
                       const std::array<uint8_t, 32>& new_pubkey)> on_peer_key_update;
    std::function<void(uint32_t peer_id,
                       const std::vector<std::string>& endpoints,
                       wire::NATType nat_type)> on_p2p_endpoints;
    std::function<void(uint32_t peer_id,
                       const std::vector<std::string>& endpoints,
                       wire::NATType nat_type)> on_p2p_init;
    std::function<void(const std::string& old_ip,
                       const std::string& new_ip,
                       const std::string& reason)> on_ip_change;
    std::function<void(const wire::RouteUpdatePayload&)> on_route_update;
};

} // namespace edgelink::client

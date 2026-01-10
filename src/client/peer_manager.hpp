#pragma once

#include "common/types.hpp"
#include "client/crypto_engine.hpp"
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace edgelink::client {

// Extended peer info with runtime state
struct Peer {
    PeerInfo info;
    bool session_key_derived = false;
    P2PStatus connection_status = P2PStatus::DISCONNECTED;
    uint64_t last_seen = 0;
    uint16_t latency_ms = 0;
};

// Peer state change callback
using PeerChangeCallback = std::function<void(NodeId peer_id, bool online)>;

// Peer manager - manages peer info and state
class PeerManager {
public:
    explicit PeerManager(CryptoEngine& crypto);

    // ========================================================================
    // Peer Management
    // ========================================================================

    // Update peers from CONFIG
    void update_from_config(const std::vector<PeerInfo>& peers);

    // Update peer from CONFIG_UPDATE
    void add_peer(const PeerInfo& peer);
    void remove_peer(NodeId peer_id);
    void update_peer_online(NodeId peer_id, bool online);

    // Get peer info
    std::optional<Peer> get_peer(NodeId peer_id) const;
    std::vector<Peer> get_all_peers() const;
    std::vector<Peer> get_online_peers() const;

    // Get peer by virtual IP
    std::optional<Peer> get_peer_by_ip(const IPv4Address& ip) const;

    // Get peer IP by node ID (for logging)
    std::string get_peer_ip_str(NodeId peer_id) const;

    // Check if peer exists
    bool has_peer(NodeId peer_id) const;

    // ========================================================================
    // Session Key Management
    // ========================================================================

    // Ensure session key is derived for a peer (lazy derivation)
    bool ensure_session_key(NodeId peer_id);

    // ========================================================================
    // Connection Status
    // ========================================================================

    void set_connection_status(NodeId peer_id, P2PStatus status);
    void set_latency(NodeId peer_id, uint16_t latency_ms);
    void update_last_seen(NodeId peer_id);

    // ========================================================================
    // Callbacks
    // ========================================================================

    void set_peer_change_callback(PeerChangeCallback callback);

    // ========================================================================
    // Statistics
    // ========================================================================

    size_t peer_count() const;
    size_t online_peer_count() const;

private:
    CryptoEngine& crypto_;

    mutable std::shared_mutex mutex_;
    std::unordered_map<NodeId, Peer> peers_;

    // Virtual IP to node ID mapping for fast lookup
    std::unordered_map<uint32_t, NodeId> ip_to_node_;

    PeerChangeCallback on_peer_change_;
};

} // namespace edgelink::client

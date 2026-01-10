#include "client/peer_manager.hpp"
#include <spdlog/spdlog.h>
#include <chrono>

namespace edgelink::client {

PeerManager::PeerManager(CryptoEngine& crypto) : crypto_(crypto) {}

void PeerManager::update_from_config(const std::vector<PeerInfo>& peers) {
    std::unique_lock lock(mutex_);

    // Clear existing peers
    peers_.clear();
    ip_to_node_.clear();

    // Clear all session keys since peer node keys may have changed
    crypto_.clear_all_session_keys();

    // Add new peers
    for (const auto& info : peers) {
        Peer peer;
        peer.info = info;
        peer.session_key_derived = false;
        peer.connection_status = info.online ? P2PStatus::RELAY_ONLY : P2PStatus::DISCONNECTED;
        peer.last_seen = 0;
        peer.latency_ms = 0;

        peers_[info.node_id] = peer;
        ip_to_node_[info.virtual_ip.to_u32()] = info.node_id;

        spdlog::debug("Added peer {} ({}) - {}",
                      info.node_id, info.virtual_ip.to_string(),
                      info.online ? "online" : "offline");
    }

    spdlog::info("Updated {} peers from config", peers.size());
}

void PeerManager::add_peer(const PeerInfo& info) {
    bool was_new = false;
    bool status_changed = false;
    bool was_online = false;

    {
        std::unique_lock lock(mutex_);

        auto it = peers_.find(info.node_id);
        if (it == peers_.end()) {
            // New peer
            Peer peer;
            peer.info = info;
            peer.session_key_derived = false;
            peer.connection_status = info.online ? P2PStatus::RELAY_ONLY : P2PStatus::DISCONNECTED;

            peers_[info.node_id] = peer;
            ip_to_node_[info.virtual_ip.to_u32()] = info.node_id;
            was_new = true;

            spdlog::info("New peer {} ({}) - {}",
                         info.node_id, info.virtual_ip.to_string(),
                         info.online ? "online" : "offline");
        } else {
            // Update existing peer
            was_online = it->second.info.online;
            status_changed = (was_online != info.online);

            // Check if node_key changed - if so, clear session key
            if (it->second.info.node_key != info.node_key) {
                crypto_.remove_session_key(info.node_id);
                it->second.session_key_derived = false;
                spdlog::info("Peer {} node_key changed, cleared session key", info.node_id);
            }

            it->second.info = info;
            if (status_changed) {
                it->second.connection_status = info.online ? P2PStatus::RELAY_ONLY : P2PStatus::DISCONNECTED;
            }

            if (status_changed) {
                spdlog::info("Peer {} ({}) is now {}",
                             info.node_id, info.virtual_ip.to_string(),
                             info.online ? "online" : "offline");
            }
        }
    }

    // Notify callback
    if ((was_new || status_changed) && on_peer_change_) {
        on_peer_change_(info.node_id, info.online);
    }
}

void PeerManager::remove_peer(NodeId peer_id) {
    bool removed = false;

    {
        std::unique_lock lock(mutex_);

        auto it = peers_.find(peer_id);
        if (it != peers_.end()) {
            ip_to_node_.erase(it->second.info.virtual_ip.to_u32());
            peers_.erase(it);
            removed = true;

            spdlog::info("Removed peer {}", peer_id);
        }
    }

    if (removed) {
        crypto_.remove_session_key(peer_id);
        if (on_peer_change_) {
            on_peer_change_(peer_id, false);
        }
    }
}

void PeerManager::update_peer_online(NodeId peer_id, bool online) {
    bool changed = false;

    {
        std::unique_lock lock(mutex_);

        auto it = peers_.find(peer_id);
        if (it != peers_.end() && it->second.info.online != online) {
            it->second.info.online = online;
            it->second.connection_status = online ? P2PStatus::RELAY_ONLY : P2PStatus::DISCONNECTED;
            changed = true;

            spdlog::info("Peer {} is now {}", peer_id, online ? "online" : "offline");
        }
    }

    if (changed && on_peer_change_) {
        on_peer_change_(peer_id, online);
    }
}

std::optional<Peer> PeerManager::get_peer(NodeId peer_id) const {
    std::shared_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it == peers_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<Peer> PeerManager::get_all_peers() const {
    std::shared_lock lock(mutex_);

    std::vector<Peer> result;
    result.reserve(peers_.size());
    for (const auto& [_, peer] : peers_) {
        result.push_back(peer);
    }
    return result;
}

std::vector<Peer> PeerManager::get_online_peers() const {
    std::shared_lock lock(mutex_);

    std::vector<Peer> result;
    for (const auto& [_, peer] : peers_) {
        if (peer.info.online) {
            result.push_back(peer);
        }
    }
    return result;
}

std::optional<Peer> PeerManager::get_peer_by_ip(const IPv4Address& ip) const {
    std::shared_lock lock(mutex_);

    auto it = ip_to_node_.find(ip.to_u32());
    if (it == ip_to_node_.end()) {
        return std::nullopt;
    }

    auto peer_it = peers_.find(it->second);
    if (peer_it == peers_.end()) {
        return std::nullopt;
    }

    return peer_it->second;
}

bool PeerManager::has_peer(NodeId peer_id) const {
    std::shared_lock lock(mutex_);
    return peers_.find(peer_id) != peers_.end();
}

bool PeerManager::ensure_session_key(NodeId peer_id) {
    // Check if already derived
    if (crypto_.has_session_key(peer_id)) {
        return true;
    }

    // Get peer's node key
    std::array<uint8_t, X25519_KEY_SIZE> node_key;
    {
        std::shared_lock lock(mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) {
            spdlog::warn("Cannot derive session key: peer {} not found", peer_id);
            return false;
        }
        node_key = it->second.info.node_key;
    }

    // Derive session key
    auto result = crypto_.derive_session_key(peer_id, node_key);
    if (!result) {
        spdlog::error("Failed to derive session key for peer {}: {}",
                      peer_id, crypto_engine_error_message(result.error()));
        return false;
    }

    // Mark as derived
    {
        std::unique_lock lock(mutex_);
        auto it = peers_.find(peer_id);
        if (it != peers_.end()) {
            it->second.session_key_derived = true;
        }
    }

    return true;
}

void PeerManager::set_connection_status(NodeId peer_id, P2PStatus status) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        it->second.connection_status = status;
    }
}

void PeerManager::set_latency(NodeId peer_id, uint16_t latency_ms) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        it->second.latency_ms = latency_ms;
    }
}

void PeerManager::update_last_seen(NodeId peer_id) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        it->second.last_seen = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
}

void PeerManager::set_peer_change_callback(PeerChangeCallback callback) {
    on_peer_change_ = std::move(callback);
}

size_t PeerManager::peer_count() const {
    std::shared_lock lock(mutex_);
    return peers_.size();
}

size_t PeerManager::online_peer_count() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [_, peer] : peers_) {
        if (peer.info.online) {
            ++count;
        }
    }
    return count;
}

} // namespace edgelink::client

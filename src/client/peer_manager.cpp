#include "client/peer_manager.hpp"
#include "common/logger.hpp"
#include <chrono>

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("client.peer_manager"); }
}

PeerManager::PeerManager(CryptoEngine& crypto) : crypto_(crypto) {}

void PeerManager::update_from_config(const std::vector<PeerInfo>& peers) {
    std::unique_lock lock(mutex_);

    // 清空现有数据
    peers_.clear();
    ip_to_node_.clear();

    // 清除所有会话密钥（peer 的 node_key 可能已变更）
    crypto_.clear_all_session_keys();

    // 添加新 peer
    for (const auto& info : peers) {
        Peer peer;
        peer.info = info;
        peer.session_key_derived = false;
        peer.last_seen = 0;

        peers_[info.node_id] = peer;
        ip_to_node_[info.virtual_ip.to_u32()] = info.node_id;

        log().debug("添加 peer {} ({}) - {}",
                    info.node_id, info.virtual_ip.to_string(),
                    info.online ? "在线" : "离线");
    }

    log().info("从配置更新了 {} 个 peer", peers.size());
}

void PeerManager::add_peer(const PeerInfo& info) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(info.node_id);
    if (it == peers_.end()) {
        // 新 peer
        Peer peer;
        peer.info = info;
        peer.session_key_derived = false;
        peer.last_seen = 0;

        peers_[info.node_id] = peer;
        ip_to_node_[info.virtual_ip.to_u32()] = info.node_id;

        log().info("新 peer {} ({}) - {}",
                   info.node_id, info.virtual_ip.to_string(),
                   info.online ? "在线" : "离线");
    } else {
        // 更新现有 peer
        bool online_changed = (it->second.info.online != info.online);

        // 检查 node_key 是否变更 - 如果变更则清除会话密钥
        if (it->second.info.node_key != info.node_key) {
            crypto_.remove_session_key(info.node_id);
            it->second.session_key_derived = false;
            log().info("Peer {} node_key 已变更，清除会话密钥", info.node_id);
        }

        it->second.info = info;

        if (online_changed) {
            log().info("Peer {} ({}) 现在 {}",
                       info.node_id, info.virtual_ip.to_string(),
                       info.online ? "在线" : "离线");
        }
    }
}

void PeerManager::remove_peer(NodeId peer_id) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        ip_to_node_.erase(it->second.info.virtual_ip.to_u32());
        peers_.erase(it);

        // 清除会话密钥
        crypto_.remove_session_key(peer_id);

        log().info("移除 peer {}", peer_id);
    }
}

void PeerManager::update_peer_online(NodeId peer_id, bool online) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end() && it->second.info.online != online) {
        it->second.info.online = online;
        log().info("Peer {} 现在 {}", peer_id, online ? "在线" : "离线");
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

std::string PeerManager::get_peer_ip_str(NodeId peer_id) const {
    std::shared_lock lock(mutex_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) {
        return std::to_string(peer_id);  // 回退到 node ID
    }
    return it->second.info.virtual_ip.to_string();
}

std::optional<std::array<uint8_t, X25519_KEY_SIZE>> PeerManager::get_peer_node_key(NodeId peer_id) const {
    std::shared_lock lock(mutex_);
    auto it = peers_.find(peer_id);
    if (it == peers_.end()) {
        return std::nullopt;
    }
    return it->second.info.node_key;
}

bool PeerManager::ensure_session_key(NodeId peer_id) {
    // 检查是否已派生
    if (crypto_.has_session_key(peer_id)) {
        return true;
    }

    // 获取 peer 的 node key
    std::array<uint8_t, X25519_KEY_SIZE> node_key;
    {
        std::shared_lock lock(mutex_);
        auto it = peers_.find(peer_id);
        if (it == peers_.end()) {
            log().warn("无法派生会话密钥：peer {} 不存在", peer_id);
            return false;
        }
        node_key = it->second.info.node_key;
    }

    // 派生会话密钥
    auto result = crypto_.derive_session_key(peer_id, node_key);
    if (!result) {
        log().error("为 peer {} 派生会话密钥失败：{}",
                    peer_id, crypto_engine_error_message(result.error()));
        return false;
    }

    // 标记为已派生
    {
        std::unique_lock lock(mutex_);
        auto it = peers_.find(peer_id);
        if (it != peers_.end()) {
            it->second.session_key_derived = true;
        }
    }

    return true;
}

bool PeerManager::has_session_key(NodeId peer_id) const {
    return crypto_.has_session_key(peer_id);
}

void PeerManager::update_last_seen(NodeId peer_id) {
    std::unique_lock lock(mutex_);

    auto it = peers_.find(peer_id);
    if (it != peers_.end()) {
        it->second.last_seen = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
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

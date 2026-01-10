#include "client/crypto_engine.hpp"
#include <spdlog/spdlog.h>

namespace edgelink::client {

std::string crypto_engine_error_message(CryptoEngineError error) {
    switch (error) {
        case CryptoEngineError::KEY_GENERATION_FAILED: return "Key generation failed";
        case CryptoEngineError::SESSION_KEY_NOT_FOUND: return "Session key not found";
        case CryptoEngineError::ENCRYPTION_FAILED: return "Encryption failed";
        case CryptoEngineError::DECRYPTION_FAILED: return "Decryption failed";
        case CryptoEngineError::INVALID_PEER: return "Invalid peer";
        default: return "Unknown crypto engine error";
    }
}

CryptoEngine::CryptoEngine() = default;

std::expected<void, CryptoEngineError> CryptoEngine::init() {
    // Generate machine key (Ed25519)
    auto mk = crypto::generate_machine_key();
    if (!mk) {
        spdlog::error("Failed to generate machine key");
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }
    machine_key_ = *mk;

    // Generate node key (X25519)
    auto nk = crypto::generate_node_key();
    if (!nk) {
        spdlog::error("Failed to generate node key");
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }
    node_key_ = *nk;

    initialized_ = true;
    spdlog::info("Crypto engine initialized with new keys");
    spdlog::debug("Machine key: {}...", crypto::key_to_hex(machine_key_.public_key).substr(0, 16));
    spdlog::debug("Node key: {}...", crypto::key_to_hex(node_key_.public_key).substr(0, 16));

    return {};
}

std::expected<void, CryptoEngineError> CryptoEngine::load_keys(
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_pub,
    std::span<const uint8_t, ED25519_PRIVATE_KEY_SIZE> machine_priv,
    std::span<const uint8_t, X25519_KEY_SIZE> node_pub,
    std::span<const uint8_t, X25519_KEY_SIZE> node_priv) {

    std::copy(machine_pub.begin(), machine_pub.end(), machine_key_.public_key.begin());
    std::copy(machine_priv.begin(), machine_priv.end(), machine_key_.private_key.begin());
    std::copy(node_pub.begin(), node_pub.end(), node_key_.public_key.begin());
    std::copy(node_priv.begin(), node_priv.end(), node_key_.private_key.begin());

    initialized_ = true;
    spdlog::info("Crypto engine initialized with loaded keys");

    return {};
}

std::expected<std::array<uint8_t, ED25519_SIGNATURE_SIZE>, CryptoEngineError>
CryptoEngine::sign(std::span<const uint8_t> data) {
    auto result = crypto::ed25519_sign(data, machine_key_.private_key);
    if (!result) {
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }
    return *result;
}

std::expected<void, CryptoEngineError> CryptoEngine::derive_session_key(
    NodeId peer_id, std::span<const uint8_t, X25519_KEY_SIZE> peer_node_key) {

    // Check if already derived
    {
        std::shared_lock lock(sessions_mutex_);
        auto it = peer_sessions_.find(peer_id);
        if (it != peer_sessions_.end() && it->second.valid) {
            return {}; // Already have valid session key
        }
    }

    // Perform X25519 key exchange
    auto shared_secret = crypto::x25519_exchange(node_key_.private_key, peer_node_key);
    if (!shared_secret) {
        spdlog::error("X25519 key exchange failed for peer {}", peer_id);
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    // Derive session key using HKDF
    auto session_key = crypto::derive_session_key(*shared_secret, node_id_, peer_id);
    if (!session_key) {
        spdlog::error("Session key derivation failed for peer {}", peer_id);
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    // Store session
    {
        std::unique_lock lock(sessions_mutex_);
        PeerSession session;
        session.session_key = *session_key;
        session.send_counter = 0;
        session.recv_counter = 0;
        session.valid = true;
        peer_sessions_[peer_id] = session;
    }

    spdlog::debug("Derived session key for peer {}", peer_id);
    return {};
}

bool CryptoEngine::has_session_key(NodeId peer_id) const {
    std::shared_lock lock(sessions_mutex_);
    auto it = peer_sessions_.find(peer_id);
    return it != peer_sessions_.end() && it->second.valid;
}

void CryptoEngine::remove_session_key(NodeId peer_id) {
    std::unique_lock lock(sessions_mutex_);
    peer_sessions_.erase(peer_id);
    spdlog::debug("Removed session key for peer {}", peer_id);
}

void CryptoEngine::clear_all_session_keys() {
    std::unique_lock lock(sessions_mutex_);
    peer_sessions_.clear();
    spdlog::debug("Cleared all session keys");
}

uint64_t CryptoEngine::next_send_counter(NodeId peer_id) {
    std::unique_lock lock(sessions_mutex_);
    auto it = peer_sessions_.find(peer_id);
    if (it == peer_sessions_.end()) {
        return 0;
    }
    return it->second.send_counter++;
}

std::expected<std::vector<uint8_t>, CryptoEngineError> CryptoEngine::encrypt(
    NodeId peer_id, std::span<const uint8_t> plaintext,
    std::array<uint8_t, CHACHA20_NONCE_SIZE>& nonce_out) {

    PeerSession session;
    uint64_t counter;

    // Get session key and counter
    {
        std::unique_lock lock(sessions_mutex_);
        auto it = peer_sessions_.find(peer_id);
        if (it == peer_sessions_.end() || !it->second.valid) {
            return std::unexpected(CryptoEngineError::SESSION_KEY_NOT_FOUND);
        }
        session = it->second;
        counter = it->second.send_counter++;
    }

    // Construct nonce from base XOR counter
    nonce_out = crypto::xor_nonce_with_counter(session.session_key.send_nonce_base, counter);

    // Build AAD (additional authenticated data): src_node || dst_node
    std::array<uint8_t, 8> aad;
    aad[0] = (node_id_ >> 24) & 0xFF;
    aad[1] = (node_id_ >> 16) & 0xFF;
    aad[2] = (node_id_ >> 8) & 0xFF;
    aad[3] = node_id_ & 0xFF;
    aad[4] = (peer_id >> 24) & 0xFF;
    aad[5] = (peer_id >> 16) & 0xFF;
    aad[6] = (peer_id >> 8) & 0xFF;
    aad[7] = peer_id & 0xFF;

    // Encrypt
    auto result = crypto::chacha20_poly1305_encrypt(
        session.session_key.key, nonce_out, plaintext, aad);

    if (!result) {
        return std::unexpected(CryptoEngineError::ENCRYPTION_FAILED);
    }

    return *result;
}

std::expected<std::vector<uint8_t>, CryptoEngineError> CryptoEngine::decrypt(
    NodeId peer_id, std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> ciphertext) {

    PeerSession session;

    // Get session key
    {
        std::shared_lock lock(sessions_mutex_);
        auto it = peer_sessions_.find(peer_id);
        if (it == peer_sessions_.end() || !it->second.valid) {
            return std::unexpected(CryptoEngineError::SESSION_KEY_NOT_FOUND);
        }
        session = it->second;
    }

    // Build AAD: src_node || dst_node (from peer's perspective, so reversed)
    std::array<uint8_t, 8> aad;
    aad[0] = (peer_id >> 24) & 0xFF;
    aad[1] = (peer_id >> 16) & 0xFF;
    aad[2] = (peer_id >> 8) & 0xFF;
    aad[3] = peer_id & 0xFF;
    aad[4] = (node_id_ >> 24) & 0xFF;
    aad[5] = (node_id_ >> 16) & 0xFF;
    aad[6] = (node_id_ >> 8) & 0xFF;
    aad[7] = node_id_ & 0xFF;

    // Convert span to fixed-size array for the crypto function
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce_arr;
    std::copy(nonce.begin(), nonce.end(), nonce_arr.begin());

    // Decrypt
    auto result = crypto::chacha20_poly1305_decrypt(
        session.session_key.key, nonce_arr, ciphertext, aad);

    if (!result) {
        return std::unexpected(CryptoEngineError::DECRYPTION_FAILED);
    }

    return *result;
}

} // namespace edgelink::client

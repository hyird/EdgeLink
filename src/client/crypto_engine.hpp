#pragma once

#include "common/types.hpp"
#include "common/crypto.hpp"
#include <expected>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

namespace edgelink::client {

// Crypto engine error types
enum class CryptoEngineError {
    KEY_GENERATION_FAILED,
    SESSION_KEY_NOT_FOUND,
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    INVALID_PEER,
};

std::string crypto_engine_error_message(CryptoEngineError error);

// Session state for a peer
struct PeerSession {
    SessionKey session_key;
    uint64_t send_counter = 0;
    uint64_t recv_counter = 0;
    bool valid = false;
};

// Crypto engine - manages keys and encryption/decryption
class CryptoEngine {
public:
    CryptoEngine();

    // Initialize with new or existing keys
    std::expected<void, CryptoEngineError> init();

    // Load keys from storage
    std::expected<void, CryptoEngineError> load_keys(
        std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_pub,
        std::span<const uint8_t, ED25519_PRIVATE_KEY_SIZE> machine_priv,
        std::span<const uint8_t, X25519_KEY_SIZE> node_pub,
        std::span<const uint8_t, X25519_KEY_SIZE> node_priv);

    // Get keys
    const MachineKey& machine_key() const { return machine_key_; }
    const NodeKey& node_key() const { return node_key_; }

    // Set our node ID (after authentication)
    void set_node_id(NodeId id) { node_id_ = id; }
    NodeId node_id() const { return node_id_; }

    // Sign data with machine key (Ed25519)
    std::expected<std::array<uint8_t, ED25519_SIGNATURE_SIZE>, CryptoEngineError>
    sign(std::span<const uint8_t> data);

    // ========================================================================
    // Session Key Management
    // ========================================================================

    // Derive session key for a peer (lazy, cached)
    std::expected<void, CryptoEngineError> derive_session_key(
        NodeId peer_id, std::span<const uint8_t, X25519_KEY_SIZE> peer_node_key);

    // Check if we have a session key for a peer
    bool has_session_key(NodeId peer_id) const;

    // Remove session key for a peer (e.g., on key rotation)
    void remove_session_key(NodeId peer_id);

    // Clear all session keys
    void clear_all_session_keys();

    // ========================================================================
    // Encryption/Decryption
    // ========================================================================

    // Encrypt data for a peer
    // Returns: encrypted_payload (includes auth_tag)
    std::expected<std::vector<uint8_t>, CryptoEngineError> encrypt(
        NodeId peer_id, std::span<const uint8_t> plaintext,
        std::array<uint8_t, CHACHA20_NONCE_SIZE>& nonce_out);

    // Decrypt data from a peer
    std::expected<std::vector<uint8_t>, CryptoEngineError> decrypt(
        NodeId peer_id, std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
        std::span<const uint8_t> ciphertext);

    // ========================================================================
    // Utility
    // ========================================================================

    // Get next send counter for a peer
    uint64_t next_send_counter(NodeId peer_id);

private:
    MachineKey machine_key_;
    NodeKey node_key_;
    NodeId node_id_ = 0;

    // Session keys per peer
    mutable std::shared_mutex sessions_mutex_;
    std::unordered_map<NodeId, PeerSession> peer_sessions_;

    bool initialized_ = false;
};

} // namespace edgelink::client

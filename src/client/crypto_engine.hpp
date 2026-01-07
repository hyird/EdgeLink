#pragma once

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <expected>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <deque>
#include <bitset>

#include "common/protocol.hpp"

namespace edgelink::client {

// ============================================================================
// Replay Protection Window
// ============================================================================
class ReplayWindow {
public:
    static constexpr size_t WINDOW_SIZE = 2048;
    
    ReplayWindow() : mutex_(std::make_unique<std::mutex>()) {}
    
    // Allow move operations
    ReplayWindow(ReplayWindow&& other) noexcept
        : highest_counter_(other.highest_counter_)
        , window_(std::move(other.window_))
        , mutex_(std::move(other.mutex_)) {}
    
    ReplayWindow& operator=(ReplayWindow&& other) noexcept {
        if (this != &other) {
            highest_counter_ = other.highest_counter_;
            window_ = std::move(other.window_);
            mutex_ = std::move(other.mutex_);
        }
        return *this;
    }
    
    // No copy
    ReplayWindow(const ReplayWindow&) = delete;
    ReplayWindow& operator=(const ReplayWindow&) = delete;
    
    // Check if counter is valid (not replayed)
    // Returns true if counter is valid and updates window
    bool check_and_update(uint64_t counter);
    
    // Reset the window
    void reset();
    
    // Get current highest counter
    uint64_t highest_counter() const { return highest_counter_; }

private:
    uint64_t highest_counter_ = 0;
    std::bitset<WINDOW_SIZE> window_;
    mutable std::unique_ptr<std::mutex> mutex_;
};

// ============================================================================
// Session Key for peer communication
// ============================================================================
struct SessionKey {
    uint32_t peer_node_id;
    std::array<uint8_t, 32> key;           // ChaCha20-Poly1305 key
    std::array<uint8_t, 4> nonce_prefix;   // Random prefix for nonce
    uint64_t send_counter = 0;             // Send counter
    ReplayWindow recv_window;               // Receive replay window
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_used;
    
    // For key rotation
    bool marked_for_rotation = false;
    std::chrono::steady_clock::time_point rotation_deadline;
};

// ============================================================================
// Old Session Key (kept for 5 minutes after rotation)
// ============================================================================
struct OldSessionKey {
    std::array<uint8_t, 32> key;
    ReplayWindow recv_window;
    std::chrono::steady_clock::time_point expires_at;
};

// ============================================================================
// Encrypted Packet Header
// ============================================================================
struct EncryptedPacketHeader {
    uint32_t src_node_id;
    uint32_t dst_node_id;
    uint64_t counter;
    // Followed by: nonce(12) + ciphertext + auth_tag(16)
};

// ============================================================================
// Crypto Engine - Manages end-to-end encryption
// ============================================================================
class CryptoEngine {
public:
    explicit CryptoEngine(uint32_t local_node_id);
    ~CryptoEngine();
    
    // Non-copyable, non-movable
    CryptoEngine(const CryptoEngine&) = delete;
    CryptoEngine& operator=(const CryptoEngine&) = delete;
    
    // ========================================================================
    // Key Management
    // ========================================================================
    
    // Set our own X25519 key pair
    void set_local_keys(
        const std::array<uint8_t, 32>& node_priv,
        const std::array<uint8_t, 32>& node_pub
    );
    
    // Add/update a peer's public key (from Controller config)
    // This will compute the session key via X25519 ECDH + HKDF
    std::expected<void, ErrorCode> add_peer(
        uint32_t peer_node_id,
        const std::array<uint8_t, 32>& peer_node_pub
    );
    
    // Remove a peer
    void remove_peer(uint32_t peer_node_id);
    
    // Check if we have a session key for a peer
    bool has_peer(uint32_t peer_node_id) const;
    
    // Get peer's public key (for verification)
    std::expected<std::array<uint8_t, 32>, ErrorCode> get_peer_pubkey(uint32_t peer_node_id) const;
    
    // ========================================================================
    // Encryption/Decryption
    // ========================================================================
    
    // Encrypt a packet for a peer
    // Returns: encrypted payload (nonce + ciphertext + tag)
    std::expected<std::vector<uint8_t>, ErrorCode> encrypt(
        uint32_t peer_node_id,
        const std::vector<uint8_t>& plaintext
    );
    
    // Decrypt a packet from a peer
    // Input: encrypted payload (nonce + ciphertext + tag)
    // Returns: decrypted plaintext
    std::expected<std::vector<uint8_t>, ErrorCode> decrypt(
        uint32_t peer_node_id,
        const std::vector<uint8_t>& ciphertext
    );
    
    // Encrypt with full header (for relay transmission)
    std::expected<std::vector<uint8_t>, ErrorCode> encrypt_with_header(
        uint32_t dst_node_id,
        const std::vector<uint8_t>& plaintext
    );
    
    // Decrypt with header (received from relay)
    // Also returns source node ID
    struct DecryptResult {
        uint32_t src_node_id;
        std::vector<uint8_t> plaintext;
    };
    std::expected<DecryptResult, ErrorCode> decrypt_with_header(
        const std::vector<uint8_t>& data
    );
    
    // ========================================================================
    // Key Rotation
    // ========================================================================
    
    // Mark a peer's key for rotation
    void mark_key_rotation(uint32_t peer_node_id);
    
    // Rotate our local keys (generates new X25519 keypair)
    // Returns new public key
    std::expected<std::array<uint8_t, 32>, ErrorCode> rotate_local_keys();
    
    // Cleanup expired old keys
    void cleanup_old_keys();
    
    // ========================================================================
    // Statistics
    // ========================================================================
    
    struct Stats {
        uint64_t packets_encrypted = 0;
        uint64_t packets_decrypted = 0;
        uint64_t encryption_failures = 0;
        uint64_t decryption_failures = 0;
        uint64_t replay_attacks_blocked = 0;
        uint32_t active_sessions = 0;
    };
    
    Stats get_stats() const;
    
    // Get local node ID
    uint32_t local_node_id() const { return local_node_id_; }
    
    // Get local public key
    const std::array<uint8_t, 32>& local_pubkey() const { return node_pub_; }

private:
    // Derive session key from shared secret
    std::array<uint8_t, 32> derive_session_key(
        const std::array<uint8_t, 32>& shared_secret,
        uint32_t node_a_id,
        uint32_t node_b_id
    );
    
    // Generate nonce from prefix + counter
    std::array<uint8_t, 12> generate_nonce(
        const std::array<uint8_t, 4>& prefix,
        uint64_t counter
    );
    
    // Try to decrypt with old keys (during rotation period)
    std::expected<std::vector<uint8_t>, ErrorCode> try_decrypt_with_old_key(
        uint32_t peer_node_id,
        const std::vector<uint8_t>& ciphertext
    );
    
    uint32_t local_node_id_;
    std::array<uint8_t, 32> node_priv_;  // X25519 private key
    std::array<uint8_t, 32> node_pub_;   // X25519 public key
    bool keys_initialized_ = false;
    
    // Session keys: peer_node_id -> SessionKey
    mutable std::mutex sessions_mutex_;
    std::unordered_map<uint32_t, SessionKey> sessions_;
    
    // Peer public keys (for re-deriving after rotation)
    std::unordered_map<uint32_t, std::array<uint8_t, 32>> peer_pubkeys_;
    
    // Old keys kept for 5 minutes after rotation
    mutable std::mutex old_keys_mutex_;
    std::unordered_map<uint32_t, std::deque<OldSessionKey>> old_keys_;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
};

} // namespace edgelink::client

#pragma once

#include "../protocol.hpp"
#include <expected>
#include <span>
#include <vector>

namespace edgelink::crypto {

// ============================================================================
// ChaCha20-Poly1305 AEAD Encryption
// ============================================================================
// Used for end-to-end encryption of data packets

class ChaCha20Poly1305 {
public:
    // Encrypt plaintext with associated data
    // Returns: nonce || ciphertext || tag
    static std::expected<std::vector<uint8_t>, ErrorCode> encrypt(
        const SessionKey& key,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> associated_data = {}
    );
    
    // Encrypt with explicit nonce (for replay protection)
    static std::expected<std::vector<uint8_t>, ErrorCode> encrypt_with_nonce(
        const SessionKey& key,
        const Nonce& nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> associated_data = {}
    );
    
    // Decrypt ciphertext (expects: nonce || ciphertext || tag)
    static std::expected<std::vector<uint8_t>, ErrorCode> decrypt(
        const SessionKey& key,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> associated_data = {}
    );
    
    // Decrypt with explicit nonce
    static std::expected<std::vector<uint8_t>, ErrorCode> decrypt_with_nonce(
        const SessionKey& key,
        const Nonce& nonce,
        std::span<const uint8_t> ciphertext,  // ciphertext || tag
        std::span<const uint8_t> associated_data = {}
    );
    
    // Generate a random nonce
    static Nonce generate_nonce();
    
    // Create nonce from random prefix and counter
    // nonce = random_prefix (4 bytes) || counter (8 bytes)
    static Nonce create_nonce(uint32_t random_prefix, uint64_t counter);
    
    // Extract counter from nonce
    static uint64_t extract_counter(const Nonce& nonce);
};

// ============================================================================
// Replay Protection
// ============================================================================
// Sliding window to detect replay attacks

class ReplayProtection {
public:
    explicit ReplayProtection(size_t window_size = CryptoConstants::REPLAY_WINDOW_SIZE);
    
    // Check if a counter value is valid (not replayed)
    // Returns true if valid, false if replayed or too old
    bool check(uint64_t counter);
    
    // Mark a counter as seen
    void mark_seen(uint64_t counter);
    
    // Check and mark in one operation
    bool check_and_mark(uint64_t counter);
    
    // Reset the window
    void reset();
    
    // Get current window state for debugging
    uint64_t get_max_seen() const { return max_counter_; }

private:
    size_t window_size_;
    uint64_t max_counter_{0};
    std::vector<bool> window_;  // Bitmap for seen counters
    
    size_t index_of(uint64_t counter) const;
};

} // namespace edgelink::crypto

#pragma once

#include "../protocol.hpp"
#include <span>
#include <vector>

namespace edgelink::crypto {

// ============================================================================
// HKDF-SHA256 Key Derivation
// ============================================================================
// Used for deriving session keys from shared secrets

class HKDF {
public:
    // HKDF Extract + Expand
    // Derives a key of the specified length from input key material
    static std::vector<uint8_t> derive(
        std::span<const uint8_t> input_key_material,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info,
        size_t output_length
    );
    
    // Convenience function for session key derivation
    // session_key = HKDF(shared_secret, empty_salt, "edgelink-session" || node_ids, 32)
    static SessionKey derive_session_key(
        std::span<const uint8_t> shared_secret,
        uint32_t node_a_id,
        uint32_t node_b_id
    );
    
    // HKDF Extract only
    // PRK = HMAC-SHA256(salt, IKM)
    static std::array<uint8_t, 32> extract(
        std::span<const uint8_t> salt,
        std::span<const uint8_t> input_key_material
    );
    
    // HKDF Expand only
    // Output = HMAC-SHA256(PRK, info || 0x01) || HMAC-SHA256(PRK, T1 || info || 0x02) || ...
    static std::vector<uint8_t> expand(
        std::span<const uint8_t> prk,
        std::span<const uint8_t> info,
        size_t output_length
    );

private:
    // HMAC-SHA256
    static std::array<uint8_t, 32> hmac_sha256(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data
    );
};

} // namespace edgelink::crypto

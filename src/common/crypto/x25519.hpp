#pragma once

#include "../protocol.hpp"
#include <expected>
#include <string>

namespace edgelink::crypto {

// Import wire protocol error codes to avoid conflicts with proto types
using ErrorCode = wire::ErrorCode;

// ============================================================================
// X25519 ECDH Key Exchange
// ============================================================================
// Used for generating session keys between peers

class X25519 {
public:
    // Generate a new key pair
    static std::pair<X25519PublicKey, X25519PrivateKey> generate_keypair();
    
    // Compute shared secret using ECDH
    // shared = X25519(my_private, peer_public)
    static std::expected<SessionKey, ErrorCode> compute_shared_secret(
        const X25519PrivateKey& my_private,
        const X25519PublicKey& peer_public
    );
    
    // Derive session key from shared secret using HKDF
    // session_key = HKDF-SHA256(shared_secret, "edgelink-session", node_a_id || node_b_id)
    static SessionKey derive_session_key(
        const SessionKey& shared_secret,
        uint32_t node_a_id,
        uint32_t node_b_id
    );
    
    // Base64 encoding/decoding for key transport
    static std::string public_key_to_base64(const X25519PublicKey& key);
    static std::string private_key_to_base64(const X25519PrivateKey& key);
    static std::expected<X25519PublicKey, ErrorCode> public_key_from_base64(const std::string& b64);
    static std::expected<X25519PrivateKey, ErrorCode> private_key_from_base64(const std::string& b64);
    
    // Validate a public key (check if it's on the curve)
    static bool validate_public_key(const X25519PublicKey& key);
};

} // namespace edgelink::crypto

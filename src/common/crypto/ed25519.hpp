#pragma once

#include "../protocol.hpp"
#include <expected>
#include <span>
#include <vector>

namespace edgelink::crypto {

// ============================================================================
// Ed25519 Digital Signatures
// ============================================================================
// Used for machine_key identity verification

class Ed25519 {
public:
    using Signature = std::array<uint8_t, CryptoConstants::ED25519_SIG_SIZE>;
    
    // Generate a new key pair
    static std::pair<Ed25519PublicKey, Ed25519PrivateKey> generate_keypair();
    
    // Sign a message
    static Signature sign(
        const Ed25519PrivateKey& private_key,
        std::span<const uint8_t> message
    );
    
    // Verify a signature
    static bool verify(
        const Ed25519PublicKey& public_key,
        std::span<const uint8_t> message,
        const Signature& signature
    );
    
    // Base64 encoding/decoding for key transport
    static std::string to_base64(const Ed25519PublicKey& key);
    static std::string to_base64(const Ed25519PrivateKey& key);
    static std::string signature_to_base64(const Signature& sig);
    
    static std::expected<Ed25519PublicKey, ErrorCode> public_key_from_base64(const std::string& b64);
    static std::expected<Ed25519PrivateKey, ErrorCode> private_key_from_base64(const std::string& b64);
    static std::expected<Signature, ErrorCode> signature_from_base64(const std::string& b64);
    
    // Extract public key from private key
    static Ed25519PublicKey public_key_from_private(const Ed25519PrivateKey& private_key);
    
    // Compute key fingerprint (first 8 bytes of SHA256 of public key, as hex)
    static std::string key_fingerprint(const Ed25519PublicKey& public_key);
};

} // namespace edgelink::crypto

#pragma once

#include "common/types.hpp"
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

// Forward declarations for OpenSSL types
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

namespace edgelink::crypto {

// ============================================================================
// OpenSSL RAII Wrappers — 自动释放 OpenSSL 资源，消除手动 free
// ============================================================================

struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const; };
struct EvpPkeyCtxDeleter { void operator()(EVP_PKEY_CTX* p) const; };
struct EvpMdCtxDeleter { void operator()(EVP_MD_CTX* p) const; };
struct EvpCipherCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const; };

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

// Error types
enum class CryptoError {
    INIT_FAILED,
    KEY_GENERATION_FAILED,
    SIGN_FAILED,
    VERIFY_FAILED,
    ENCRYPT_FAILED,
    DECRYPT_FAILED,
    KEY_EXCHANGE_FAILED,
    HKDF_FAILED,
    INVALID_KEY_SIZE,
    INVALID_SIGNATURE_SIZE,
    BUFFER_TOO_SMALL,
};

std::string crypto_error_message(CryptoError error);

// Initialize crypto library (call once at startup)
bool init();

// ============================================================================
// Ed25519 (Signing)
// ============================================================================

// Generate a new Ed25519 key pair
std::expected<MachineKey, CryptoError> generate_machine_key();

// Sign a message with Ed25519
std::expected<std::array<uint8_t, ED25519_SIGNATURE_SIZE>, CryptoError> ed25519_sign(
    std::span<const uint8_t> message,
    std::span<const uint8_t, ED25519_PRIVATE_KEY_SIZE> private_key);

// Verify an Ed25519 signature
bool ed25519_verify(
    std::span<const uint8_t> message,
    std::span<const uint8_t, ED25519_SIGNATURE_SIZE> signature,
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> public_key);

// ============================================================================
// X25519 (Key Exchange)
// ============================================================================

// Generate a new X25519 key pair
std::expected<NodeKey, CryptoError> generate_node_key();

// Perform X25519 key exchange
std::expected<std::array<uint8_t, X25519_KEY_SIZE>, CryptoError> x25519_exchange(
    std::span<const uint8_t, X25519_KEY_SIZE> our_private_key,
    std::span<const uint8_t, X25519_KEY_SIZE> their_public_key);

// ============================================================================
// ChaCha20-Poly1305 (AEAD Encryption)
// ============================================================================

// Encrypt with ChaCha20-Poly1305
// Returns ciphertext with 16-byte auth tag appended
std::expected<std::vector<uint8_t>, CryptoError> chacha20_poly1305_encrypt(
    std::span<const uint8_t, SESSION_KEY_SIZE> key,
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data = {});

// Decrypt with ChaCha20-Poly1305
// Input is ciphertext with 16-byte auth tag appended
std::expected<std::vector<uint8_t>, CryptoError> chacha20_poly1305_decrypt(
    std::span<const uint8_t, SESSION_KEY_SIZE> key,
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> ciphertext_with_tag,
    std::span<const uint8_t> additional_data = {});

// ============================================================================
// Key Derivation (HKDF-SHA256)
// ============================================================================

// Derive key material using HKDF-SHA256
std::expected<std::vector<uint8_t>, CryptoError> hkdf_sha256(
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_length);

// Derive session key from X25519 shared secret
// Uses HKDF to derive: session_key (32B) + send_nonce_base (12B) + recv_nonce_base (12B)
std::expected<SessionKey, CryptoError> derive_session_key(
    std::span<const uint8_t, X25519_KEY_SIZE> shared_secret,
    NodeId our_node_id,
    NodeId peer_node_id);

// ============================================================================
// Nonce Management
// ============================================================================

// XOR nonce base with counter to create unique nonce
std::array<uint8_t, CHACHA20_NONCE_SIZE> xor_nonce_with_counter(
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce_base,
    uint64_t counter);

// ============================================================================
// Random Generation
// ============================================================================

// Generate cryptographically secure random bytes
void random_bytes(std::span<uint8_t> buffer);

// Generate random bytes and return as vector
std::vector<uint8_t> random_bytes(size_t length);

// Generate random 32-bit integer
uint32_t random_u32();

// Generate random 64-bit integer
uint64_t random_u64();

// ============================================================================
// Password Hashing (Argon2id)
// ============================================================================

// Hash a password using Argon2id (returns hex-encoded string)
std::string password_hash(const std::string& password);

// Verify a password against a hash
bool password_verify(const std::string& password, const std::string& hash);

// ============================================================================
// Utility Functions
// ============================================================================

// Constant-time memory comparison
bool secure_compare(std::span<const uint8_t> a, std::span<const uint8_t> b);

// Secure memory wipe
void secure_wipe(std::span<uint8_t> memory);

// Convert public key to hex string (for logging/display)
std::string key_to_hex(std::span<const uint8_t> key);

// Parse hex string to bytes
std::expected<std::vector<uint8_t>, CryptoError> hex_to_bytes(std::string_view hex);

} // namespace edgelink::crypto

#include "common/crypto.hpp"
#include <sodium.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace edgelink::crypto {

std::string crypto_error_message(CryptoError error) {
    switch (error) {
        case CryptoError::INIT_FAILED: return "Crypto initialization failed";
        case CryptoError::KEY_GENERATION_FAILED: return "Key generation failed";
        case CryptoError::SIGN_FAILED: return "Signing failed";
        case CryptoError::VERIFY_FAILED: return "Signature verification failed";
        case CryptoError::ENCRYPT_FAILED: return "Encryption failed";
        case CryptoError::DECRYPT_FAILED: return "Decryption failed";
        case CryptoError::KEY_EXCHANGE_FAILED: return "Key exchange failed";
        case CryptoError::HKDF_FAILED: return "Key derivation failed";
        case CryptoError::INVALID_KEY_SIZE: return "Invalid key size";
        case CryptoError::INVALID_SIGNATURE_SIZE: return "Invalid signature size";
        case CryptoError::BUFFER_TOO_SMALL: return "Buffer too small";
        default: return "Unknown crypto error";
    }
}

bool init() {
    return sodium_init() >= 0;
}

// ============================================================================
// Ed25519 (Signing)
// ============================================================================

std::expected<MachineKey, CryptoError> generate_machine_key() {
    MachineKey key;

    if (crypto_sign_keypair(key.public_key.data(), key.private_key.data()) != 0) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    return key;
}

std::expected<std::array<uint8_t, ED25519_SIGNATURE_SIZE>, CryptoError> ed25519_sign(
    std::span<const uint8_t> message,
    std::span<const uint8_t, ED25519_PRIVATE_KEY_SIZE> private_key) {

    std::array<uint8_t, ED25519_SIGNATURE_SIZE> signature;
    unsigned long long sig_len;

    if (crypto_sign_detached(signature.data(), &sig_len,
                             message.data(), message.size(),
                             private_key.data()) != 0) {
        return std::unexpected(CryptoError::SIGN_FAILED);
    }

    return signature;
}

bool ed25519_verify(
    std::span<const uint8_t> message,
    std::span<const uint8_t, ED25519_SIGNATURE_SIZE> signature,
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> public_key) {

    return crypto_sign_verify_detached(signature.data(),
                                       message.data(), message.size(),
                                       public_key.data()) == 0;
}

// ============================================================================
// X25519 (Key Exchange)
// ============================================================================

std::expected<NodeKey, CryptoError> generate_node_key() {
    NodeKey key;

    // Generate random private key
    randombytes_buf(key.private_key.data(), key.private_key.size());

    // Clamp private key for X25519
    key.private_key[0] &= 248;
    key.private_key[31] &= 127;
    key.private_key[31] |= 64;

    // Derive public key
    if (crypto_scalarmult_base(key.public_key.data(), key.private_key.data()) != 0) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    return key;
}

std::expected<std::array<uint8_t, X25519_KEY_SIZE>, CryptoError> x25519_exchange(
    std::span<const uint8_t, X25519_KEY_SIZE> our_private_key,
    std::span<const uint8_t, X25519_KEY_SIZE> their_public_key) {

    std::array<uint8_t, X25519_KEY_SIZE> shared_secret;

    if (crypto_scalarmult(shared_secret.data(),
                          our_private_key.data(),
                          their_public_key.data()) != 0) {
        return std::unexpected(CryptoError::KEY_EXCHANGE_FAILED);
    }

    return shared_secret;
}

// ============================================================================
// ChaCha20-Poly1305 (AEAD Encryption)
// ============================================================================

std::expected<std::vector<uint8_t>, CryptoError> chacha20_poly1305_encrypt(
    std::span<const uint8_t, SESSION_KEY_SIZE> key,
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data) {

    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            additional_data.data(), additional_data.size(),
            nullptr, // nsec (not used)
            nonce.data(),
            key.data()) != 0) {
        return std::unexpected(CryptoError::ENCRYPT_FAILED);
    }

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::expected<std::vector<uint8_t>, CryptoError> chacha20_poly1305_decrypt(
    std::span<const uint8_t, SESSION_KEY_SIZE> key,
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> ciphertext_with_tag,
    std::span<const uint8_t> additional_data) {

    if (ciphertext_with_tag.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }

    std::vector<uint8_t> plaintext(ciphertext_with_tag.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr, // nsec (not used)
            ciphertext_with_tag.data(), ciphertext_with_tag.size(),
            additional_data.data(), additional_data.size(),
            nonce.data(),
            key.data()) != 0) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }

    plaintext.resize(plaintext_len);
    return plaintext;
}

// ============================================================================
// Key Derivation (HKDF-SHA256)
// ============================================================================

std::expected<std::vector<uint8_t>, CryptoError> hkdf_sha256(
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_length) {

    // HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
    std::array<uint8_t, crypto_auth_hmacsha256_BYTES> prk;

    crypto_auth_hmacsha256_state extract_state;
    if (salt.empty()) {
        // Use zeros as salt if not provided
        std::array<uint8_t, crypto_auth_hmacsha256_KEYBYTES> zero_salt{};
        crypto_auth_hmacsha256_init(&extract_state, zero_salt.data(), zero_salt.size());
    } else {
        crypto_auth_hmacsha256_init(&extract_state, salt.data(), salt.size());
    }
    crypto_auth_hmacsha256_update(&extract_state, input_key_material.data(), input_key_material.size());
    crypto_auth_hmacsha256_final(&extract_state, prk.data());

    // HKDF-Expand
    std::vector<uint8_t> output;
    output.reserve(output_length);

    std::array<uint8_t, crypto_auth_hmacsha256_BYTES> t{};
    uint8_t counter = 1;

    while (output.size() < output_length) {
        crypto_auth_hmacsha256_state expand_state;
        crypto_auth_hmacsha256_init(&expand_state, prk.data(), prk.size());

        if (counter > 1) {
            crypto_auth_hmacsha256_update(&expand_state, t.data(), t.size());
        }
        crypto_auth_hmacsha256_update(&expand_state, info.data(), info.size());
        crypto_auth_hmacsha256_update(&expand_state, &counter, 1);
        crypto_auth_hmacsha256_final(&expand_state, t.data());

        size_t to_copy = std::min(t.size(), output_length - output.size());
        output.insert(output.end(), t.begin(), t.begin() + to_copy);
        counter++;

        if (counter == 0) {
            // Overflow - output_length is too large
            return std::unexpected(CryptoError::HKDF_FAILED);
        }
    }

    // Clear sensitive data
    sodium_memzero(prk.data(), prk.size());
    sodium_memzero(t.data(), t.size());

    return output;
}

std::expected<SessionKey, CryptoError> derive_session_key(
    std::span<const uint8_t, X25519_KEY_SIZE> shared_secret,
    NodeId our_node_id,
    NodeId peer_node_id) {

    // Create salt from node IDs (smaller ID first for consistency)
    std::array<uint8_t, 8> salt;
    if (our_node_id < peer_node_id) {
        salt[0] = (our_node_id >> 24) & 0xFF;
        salt[1] = (our_node_id >> 16) & 0xFF;
        salt[2] = (our_node_id >> 8) & 0xFF;
        salt[3] = our_node_id & 0xFF;
        salt[4] = (peer_node_id >> 24) & 0xFF;
        salt[5] = (peer_node_id >> 16) & 0xFF;
        salt[6] = (peer_node_id >> 8) & 0xFF;
        salt[7] = peer_node_id & 0xFF;
    } else {
        salt[0] = (peer_node_id >> 24) & 0xFF;
        salt[1] = (peer_node_id >> 16) & 0xFF;
        salt[2] = (peer_node_id >> 8) & 0xFF;
        salt[3] = peer_node_id & 0xFF;
        salt[4] = (our_node_id >> 24) & 0xFF;
        salt[5] = (our_node_id >> 16) & 0xFF;
        salt[6] = (our_node_id >> 8) & 0xFF;
        salt[7] = our_node_id & 0xFF;
    }

    // Info string
    constexpr std::string_view info = "edgelink-session-v2";

    // Derive 56 bytes: key(32) + send_nonce_base(12) + recv_nonce_base(12)
    auto derived = hkdf_sha256(
        shared_secret,
        salt,
        std::span(reinterpret_cast<const uint8_t*>(info.data()), info.size()),
        56);

    if (!derived) {
        return std::unexpected(derived.error());
    }

    SessionKey session_key;
    std::copy_n(derived->begin(), SESSION_KEY_SIZE, session_key.key.begin());

    // Assign nonce bases based on node ID ordering
    // Lower node ID uses first nonce base for sending
    if (our_node_id < peer_node_id) {
        std::copy_n(derived->begin() + 32, CHACHA20_NONCE_SIZE, session_key.send_nonce_base.begin());
        std::copy_n(derived->begin() + 44, CHACHA20_NONCE_SIZE, session_key.recv_nonce_base.begin());
    } else {
        std::copy_n(derived->begin() + 44, CHACHA20_NONCE_SIZE, session_key.send_nonce_base.begin());
        std::copy_n(derived->begin() + 32, CHACHA20_NONCE_SIZE, session_key.recv_nonce_base.begin());
    }

    return session_key;
}

// ============================================================================
// Nonce Management
// ============================================================================

std::array<uint8_t, CHACHA20_NONCE_SIZE> xor_nonce_with_counter(
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce_base,
    uint64_t counter) {

    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    std::copy(nonce_base.begin(), nonce_base.end(), nonce.begin());

    // XOR counter into the last 8 bytes of the nonce
    for (int i = 0; i < 8; ++i) {
        nonce[CHACHA20_NONCE_SIZE - 1 - i] ^= static_cast<uint8_t>((counter >> (i * 8)) & 0xFF);
    }

    return nonce;
}

// ============================================================================
// Random Generation
// ============================================================================

void random_bytes(std::span<uint8_t> buffer) {
    randombytes_buf(buffer.data(), buffer.size());
}

std::vector<uint8_t> random_bytes(size_t length) {
    std::vector<uint8_t> buffer(length);
    randombytes_buf(buffer.data(), length);
    return buffer;
}

uint32_t random_u32() {
    return randombytes_random();
}

uint64_t random_u64() {
    uint64_t value;
    randombytes_buf(&value, sizeof(value));
    return value;
}

// ============================================================================
// Utility Functions
// ============================================================================

bool secure_compare(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

void secure_wipe(std::span<uint8_t> memory) {
    sodium_memzero(memory.data(), memory.size());
}

std::string key_to_hex(std::span<const uint8_t> key) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : key) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::expected<std::vector<uint8_t>, CryptoError> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::unexpected(CryptoError::INVALID_KEY_SIZE);
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            byte <<= 4;
            if (c >= '0' && c <= '9') {
                byte |= (c - '0');
            } else if (c >= 'a' && c <= 'f') {
                byte |= (c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                byte |= (c - 'A' + 10);
            } else {
                return std::unexpected(CryptoError::INVALID_KEY_SIZE);
            }
        }
        bytes.push_back(byte);
    }

    return bytes;
}

} // namespace edgelink::crypto

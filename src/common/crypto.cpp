#include "common/crypto.hpp"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <argon2.h>
#include <algorithm>
#include <cstring>

// Platform-specific byte order conversion
#ifdef _WIN32
#include <stdlib.h>
#define htobe64(x) _byteswap_uint64(x)
#define be64toh(x) _byteswap_uint64(x)
#else
#include <endian.h>
#endif

namespace edgelink::crypto {

// ============================================================================
// RAII Deleter Implementations
// ============================================================================

void EvpPkeyDeleter::operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
void EvpPkeyCtxDeleter::operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); }
void EvpMdCtxDeleter::operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); }
void EvpCipherCtxDeleter::operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); }

std::string crypto_error_message(CryptoError error) {
    switch (error) {
        case CryptoError::INIT_FAILED: return "Crypto initialization failed";
        case CryptoError::KEY_GENERATION_FAILED: return "Key generation failed";
        case CryptoError::SIGN_FAILED: return "Signature generation failed";
        case CryptoError::VERIFY_FAILED: return "Signature verification failed";
        case CryptoError::ENCRYPT_FAILED: return "Encryption failed";
        case CryptoError::DECRYPT_FAILED: return "Decryption failed";
        case CryptoError::KEY_EXCHANGE_FAILED: return "Key exchange failed";
        case CryptoError::HKDF_FAILED: return "HKDF failed";
        case CryptoError::INVALID_KEY_SIZE: return "Invalid key size";
        case CryptoError::INVALID_SIGNATURE_SIZE: return "Invalid signature size";
        case CryptoError::BUFFER_TOO_SMALL: return "Buffer too small";
        default: return "Unknown crypto error";
    }
}

bool init() {
    // OpenSSL 1.1.0+ does not require explicit initialization
    return true;
}

// ============================================================================
// Ed25519 (Signing)
// ============================================================================

std::expected<MachineKey, CryptoError> generate_machine_key() {
    EVP_PKEY* raw_pkey = nullptr;
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));

    if (!ctx) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    EvpPkeyPtr pkey(raw_pkey);
    MachineKey key;

    // Extract public key
    size_t pub_len = ED25519_PUBLIC_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), key.public_key.data(), &pub_len) <= 0 ||
        pub_len != ED25519_PUBLIC_KEY_SIZE) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    // Extract private key
    size_t priv_len = ED25519_PRIVATE_KEY_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), key.private_key.data(), &priv_len) <= 0 ||
        priv_len != ED25519_PRIVATE_KEY_SIZE) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    return key;
}

std::expected<std::array<uint8_t, ED25519_SIGNATURE_SIZE>, CryptoError> ed25519_sign(
    std::span<const uint8_t> message,
    std::span<const uint8_t, ED25519_PRIVATE_KEY_SIZE> private_key) {

    EvpPkeyPtr pkey(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                   private_key.data(), private_key.size()));
    if (!pkey) {
        return std::unexpected(CryptoError::SIGN_FAILED);
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        return std::unexpected(CryptoError::SIGN_FAILED);
    }

    std::array<uint8_t, ED25519_SIGNATURE_SIZE> signature;
    size_t sig_len = signature.size();

    if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0 ||
        EVP_DigestSign(md_ctx.get(), signature.data(), &sig_len, message.data(), message.size()) <= 0 ||
        sig_len != ED25519_SIGNATURE_SIZE) {
        return std::unexpected(CryptoError::SIGN_FAILED);
    }

    return signature;
}

bool ed25519_verify(
    std::span<const uint8_t> message,
    std::span<const uint8_t, ED25519_SIGNATURE_SIZE> signature,
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> public_key) {

    EvpPkeyPtr pkey(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                  public_key.data(), public_key.size()));
    if (!pkey) {
        return false;
    }

    EvpMdCtxPtr md_ctx(EVP_MD_CTX_new());
    if (!md_ctx) {
        return false;
    }

    int result = EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey.get());
    if (result > 0) {
        result = EVP_DigestVerify(md_ctx.get(), signature.data(), signature.size(),
                                  message.data(), message.size());
    }

    return result == 1;
}

// ============================================================================
// X25519 (Key Exchange)
// ============================================================================

std::expected<NodeKey, CryptoError> generate_node_key() {
    EVP_PKEY* raw_pkey = nullptr;
    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));

    if (!ctx) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0 || EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    EvpPkeyPtr pkey(raw_pkey);
    NodeKey key;

    // Extract public key
    size_t pub_len = X25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), key.public_key.data(), &pub_len) <= 0 ||
        pub_len != X25519_KEY_SIZE) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    // Extract private key
    size_t priv_len = X25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), key.private_key.data(), &priv_len) <= 0 ||
        priv_len != X25519_KEY_SIZE) {
        return std::unexpected(CryptoError::KEY_GENERATION_FAILED);
    }

    return key;
}

std::expected<std::array<uint8_t, X25519_KEY_SIZE>, CryptoError> x25519_exchange(
    std::span<const uint8_t, X25519_KEY_SIZE> our_private_key,
    std::span<const uint8_t, X25519_KEY_SIZE> their_public_key) {

    EvpPkeyPtr our_key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                      our_private_key.data(), our_private_key.size()));
    EvpPkeyPtr their_key(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                       their_public_key.data(), their_public_key.size()));

    if (!our_key || !their_key) {
        return std::unexpected(CryptoError::KEY_EXCHANGE_FAILED);
    }

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new(our_key.get(), nullptr));
    if (!ctx) {
        return std::unexpected(CryptoError::KEY_EXCHANGE_FAILED);
    }

    std::array<uint8_t, X25519_KEY_SIZE> shared_secret;
    size_t secret_len = shared_secret.size();

    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx.get(), their_key.get()) <= 0 ||
        EVP_PKEY_derive(ctx.get(), shared_secret.data(), &secret_len) <= 0 ||
        secret_len != X25519_KEY_SIZE) {
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

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return std::unexpected(CryptoError::ENCRYPT_FAILED);
    }

    // Output: ciphertext + 16-byte tag
    std::vector<uint8_t> ciphertext(plaintext.size() + CHACHA20_TAG_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) <= 0) {
        return std::unexpected(CryptoError::ENCRYPT_FAILED);
    }

    // Set AAD if provided
    if (!additional_data.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, additional_data.data(), additional_data.size()) <= 0) {
            return std::unexpected(CryptoError::ENCRYPT_FAILED);
        }
    }

    // Encrypt
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size()) <= 0) {
        return std::unexpected(CryptoError::ENCRYPT_FAILED);
    }
    ciphertext_len = len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) <= 0) {
        return std::unexpected(CryptoError::ENCRYPT_FAILED);
    }
    ciphertext_len += len;

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, CHACHA20_TAG_SIZE,
                            ciphertext.data() + ciphertext_len) <= 0) {
        return std::unexpected(CryptoError::ENCRYPT_FAILED);
    }

    return ciphertext;
}

std::expected<std::vector<uint8_t>, CryptoError> chacha20_poly1305_decrypt(
    std::span<const uint8_t, SESSION_KEY_SIZE> key,
    std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> ciphertext_with_tag,
    std::span<const uint8_t> additional_data) {

    if (ciphertext_with_tag.size() < CHACHA20_TAG_SIZE) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }

    size_t ciphertext_len = ciphertext_with_tag.size() - CHACHA20_TAG_SIZE;
    const uint8_t* ciphertext = ciphertext_with_tag.data();
    const uint8_t* tag = ciphertext_with_tag.data() + ciphertext_len;

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }

    std::vector<uint8_t> plaintext(ciphertext_len);
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) <= 0) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, CHACHA20_TAG_SIZE,
                            const_cast<uint8_t*>(tag)) <= 0) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }

    // Set AAD if provided
    if (!additional_data.empty()) {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, additional_data.data(), additional_data.size()) <= 0) {
            return std::unexpected(CryptoError::DECRYPT_FAILED);
        }
    }

    // Decrypt
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext, ciphertext_len) <= 0) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }
    plaintext_len = len;

    // Finalize (verifies tag)
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) <= 0) {
        return std::unexpected(CryptoError::DECRYPT_FAILED);
    }
    plaintext_len += len;

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

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) {
        return std::unexpected(CryptoError::HKDF_FAILED);
    }

    std::vector<uint8_t> output(output_length);
    size_t out_len = output_length;

    if (EVP_PKEY_derive_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), input_key_material.data(), input_key_material.size()) <= 0 ||
        (salt.empty() ? 0 : EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), salt.size())) < 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), info.size()) <= 0 ||
        EVP_PKEY_derive(ctx.get(), output.data(), &out_len) <= 0) {
        return std::unexpected(CryptoError::HKDF_FAILED);
    }

    return output;
}

std::expected<SessionKey, CryptoError> derive_session_key(
    std::span<const uint8_t, X25519_KEY_SIZE> shared_secret,
    NodeId our_node_id,
    NodeId peer_node_id) {

    // Info: "EdgeLink-Session" + our_id + peer_id
    std::vector<uint8_t> info;
    const char* label = "EdgeLink-Session";
    info.insert(info.end(), label, label + std::strlen(label));

    uint64_t our_id_be = htobe64(our_node_id);
    uint64_t peer_id_be = htobe64(peer_node_id);
    info.insert(info.end(), reinterpret_cast<uint8_t*>(&our_id_be),
                reinterpret_cast<uint8_t*>(&our_id_be) + sizeof(our_id_be));
    info.insert(info.end(), reinterpret_cast<uint8_t*>(&peer_id_be),
                reinterpret_cast<uint8_t*>(&peer_id_be) + sizeof(peer_id_be));

    // Derive 56 bytes: session_key (32) + send_nonce_base (12) + recv_nonce_base (12)
    auto derived = hkdf_sha256(shared_secret, {}, info, SESSION_KEY_SIZE + CHACHA20_NONCE_SIZE * 2);
    if (!derived) {
        return std::unexpected(derived.error());
    }

    SessionKey session_key;
    std::copy_n(derived->begin(), SESSION_KEY_SIZE, session_key.key.begin());
    std::copy_n(derived->begin() + SESSION_KEY_SIZE, CHACHA20_NONCE_SIZE,
                session_key.send_nonce_base.begin());
    std::copy_n(derived->begin() + SESSION_KEY_SIZE + CHACHA20_NONCE_SIZE, CHACHA20_NONCE_SIZE,
                session_key.recv_nonce_base.begin());

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

    uint64_t counter_be = htobe64(counter);
    uint8_t* counter_bytes = reinterpret_cast<uint8_t*>(&counter_be);

    for (size_t i = 0; i < sizeof(counter_be); ++i) {
        nonce[i + (CHACHA20_NONCE_SIZE - sizeof(counter_be))] ^= counter_bytes[i];
    }

    return nonce;
}

// ============================================================================
// Random Generation
// ============================================================================

void random_bytes(std::span<uint8_t> buffer) {
    RAND_bytes(buffer.data(), buffer.size());
}

std::vector<uint8_t> random_bytes(size_t length) {
    std::vector<uint8_t> buffer(length);
    RAND_bytes(buffer.data(), length);
    return buffer;
}

uint32_t random_u32() {
    uint32_t value;
    RAND_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
    return value;
}

uint64_t random_u64() {
    uint64_t value;
    RAND_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
    return value;
}

// ============================================================================
// Password Hashing (Argon2id)
// ============================================================================

std::string password_hash(const std::string& password) {
    // Use Argon2id with moderate settings
    constexpr uint32_t t_cost = 2;      // iterations
    constexpr uint32_t m_cost = 65536;  // memory in KB (64 MB)
    constexpr uint32_t parallelism = 1; // threads
    constexpr size_t hash_len = 32;     // hash length
    constexpr size_t salt_len = 16;     // salt length

    // Generate random salt
    std::array<uint8_t, salt_len> salt;
    RAND_bytes(salt.data(), salt.size());

    std::vector<char> encoded(argon2_encodedlen(t_cost, m_cost, parallelism,
                                                 salt_len, hash_len, Argon2_id));

    int result = argon2id_hash_encoded(t_cost, m_cost, parallelism,
                                       password.data(), password.size(),
                                       salt.data(), salt.size(),
                                       hash_len, encoded.data(), encoded.size());

    if (result != ARGON2_OK) {
        return "";
    }

    return std::string(encoded.data());
}

bool password_verify(const std::string& password, const std::string& hash) {
    int result = argon2id_verify(hash.c_str(), password.data(), password.size());
    return result == ARGON2_OK;
}

// ============================================================================
// Utility Functions
// ============================================================================

bool secure_compare(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void secure_wipe(std::span<uint8_t> memory) {
    OPENSSL_cleanse(memory.data(), memory.size());
}

std::string key_to_hex(std::span<const uint8_t> key) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(key.size() * 2);
    for (auto byte : key) {
        result.push_back(hex_chars[(byte >> 4) & 0x0F]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

std::expected<std::vector<uint8_t>, CryptoError> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::unexpected(CryptoError::INVALID_KEY_SIZE);
    }

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::unexpected(CryptoError::INVALID_KEY_SIZE);
        }
        bytes.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return bytes;
}

} // namespace edgelink::crypto

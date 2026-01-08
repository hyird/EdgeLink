#include "common/crypto/ed25519.hpp"
#include <sodium.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <vector>

namespace edgelink::crypto {

// Base64 helper using libsodium
static std::string sodium_base64_encode(const uint8_t* data, size_t len) {
    size_t b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::vector<char> buf(b64_len);
    sodium_bin2base64(buf.data(), b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    // Remove null terminator
    return std::string(buf.data());
}

static bool sodium_base64_decode(const std::string& b64, uint8_t* out, size_t out_len, size_t* decoded_len) {
    size_t bin_len = 0;
    int ret = sodium_base642bin(out, out_len, b64.c_str(), b64.size(),
                                nullptr, &bin_len, nullptr, sodium_base64_VARIANT_ORIGINAL);
    if (decoded_len) *decoded_len = bin_len;
    return ret == 0;
}

std::pair<Ed25519PublicKey, Ed25519PrivateKey> Ed25519::generate_keypair() {
    Ed25519PublicKey pub;
    Ed25519PrivateKey priv;
    
    crypto_sign_keypair(pub.data(), priv.data());
    
    return {pub, priv};
}

Ed25519::Signature Ed25519::sign(
    const Ed25519PrivateKey& private_key,
    std::span<const uint8_t> message) {
    
    Signature sig;
    
    crypto_sign_detached(
        sig.data(), nullptr,
        message.data(), message.size(),
        private_key.data()
    );
    
    return sig;
}

bool Ed25519::verify(
    const Ed25519PublicKey& public_key,
    std::span<const uint8_t> message,
    const Signature& signature) {
    
    return crypto_sign_verify_detached(
        signature.data(),
        message.data(), message.size(),
        public_key.data()
    ) == 0;
}

std::string Ed25519::to_base64(const Ed25519PublicKey& key) {
    return sodium_base64_encode(key.data(), key.size());
}

std::string Ed25519::to_base64(const Ed25519PrivateKey& key) {
    return sodium_base64_encode(key.data(), key.size());
}

std::string Ed25519::signature_to_base64(const Signature& sig) {
    return sodium_base64_encode(sig.data(), sig.size());
}

std::expected<Ed25519PublicKey, ErrorCode> Ed25519::public_key_from_base64(const std::string& b64) {
    Ed25519PublicKey key;
    size_t decoded_len = 0;

    if (!sodium_base64_decode(b64, key.data(), key.size(), &decoded_len) || decoded_len != key.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    return key;
}

std::expected<Ed25519PrivateKey, ErrorCode> Ed25519::private_key_from_base64(const std::string& b64) {
    Ed25519PrivateKey key;
    size_t decoded_len = 0;

    if (!sodium_base64_decode(b64, key.data(), key.size(), &decoded_len) || decoded_len != key.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    return key;
}

std::expected<Ed25519::Signature, ErrorCode> Ed25519::signature_from_base64(const std::string& b64) {
    Signature sig;
    size_t decoded_len = 0;

    if (!sodium_base64_decode(b64, sig.data(), sig.size(), &decoded_len) || decoded_len != sig.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    return sig;
}

Ed25519PublicKey Ed25519::public_key_from_private(const Ed25519PrivateKey& private_key) {
    Ed25519PublicKey pub;
    
    // Ed25519 secret key contains public key in last 32 bytes
    std::memcpy(pub.data(), private_key.data() + 32, 32);
    
    return pub;
}

std::string Ed25519::key_fingerprint(const Ed25519PublicKey& public_key) {
    uint8_t hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, public_key.data(), public_key.size());
    
    // Return first 8 bytes as hex
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    
    return oss.str();
}

} // namespace edgelink::crypto

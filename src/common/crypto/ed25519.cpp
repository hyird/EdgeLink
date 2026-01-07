#include "common/crypto/ed25519.hpp"
#include <sodium.h>
#include <boost/beast/core/detail/base64.hpp>
#include <sstream>
#include <iomanip>

namespace edgelink::crypto {

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
    std::string result;
    result.resize(boost::beast::detail::base64::encoded_size(key.size()));
    result.resize(boost::beast::detail::base64::encode(result.data(), key.data(), key.size()));
    return result;
}

std::string Ed25519::to_base64(const Ed25519PrivateKey& key) {
    std::string result;
    result.resize(boost::beast::detail::base64::encoded_size(key.size()));
    result.resize(boost::beast::detail::base64::encode(result.data(), key.data(), key.size()));
    return result;
}

std::string Ed25519::signature_to_base64(const Signature& sig) {
    std::string result;
    result.resize(boost::beast::detail::base64::encoded_size(sig.size()));
    result.resize(boost::beast::detail::base64::encode(result.data(), sig.data(), sig.size()));
    return result;
}

std::expected<Ed25519PublicKey, ErrorCode> Ed25519::public_key_from_base64(const std::string& b64) {
    Ed25519PublicKey key;
    
    auto decoded_size = boost::beast::detail::base64::decode(key.data(), b64.data(), b64.size());
    if (decoded_size.first != key.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    return key;
}

std::expected<Ed25519PrivateKey, ErrorCode> Ed25519::private_key_from_base64(const std::string& b64) {
    Ed25519PrivateKey key;
    
    auto decoded_size = boost::beast::detail::base64::decode(key.data(), b64.data(), b64.size());
    if (decoded_size.first != key.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    return key;
}

std::expected<Ed25519::Signature, ErrorCode> Ed25519::signature_from_base64(const std::string& b64) {
    Signature sig;
    
    auto decoded_size = boost::beast::detail::base64::decode(sig.data(), b64.data(), b64.size());
    if (decoded_size.first != sig.size()) {
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

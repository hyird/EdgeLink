#include "common/crypto/x25519.hpp"
#include "common/crypto/hkdf.hpp"
#include <sodium.h>
#include <boost/beast/core/detail/base64.hpp>

namespace edgelink::crypto {

std::pair<X25519PublicKey, X25519PrivateKey> X25519::generate_keypair() {
    X25519PublicKey pub;
    X25519PrivateKey priv;
    
    crypto_box_keypair(pub.data(), priv.data());
    
    return {pub, priv};
}

std::expected<SessionKey, ErrorCode> X25519::compute_shared_secret(
    const X25519PrivateKey& my_private,
    const X25519PublicKey& peer_public) {
    
    SessionKey shared;
    
    if (crypto_scalarmult(shared.data(), my_private.data(), peer_public.data()) != 0) {
        return std::unexpected(ErrorCode::INTERNAL_ERROR);
    }
    
    return shared;
}

SessionKey X25519::derive_session_key(
    const SessionKey& shared_secret,
    uint32_t node_a_id,
    uint32_t node_b_id) {
    
    // Ensure consistent ordering (smaller ID first)
    uint32_t first_id = std::min(node_a_id, node_b_id);
    uint32_t second_id = std::max(node_a_id, node_b_id);
    
    return HKDF::derive_session_key(
        std::span<const uint8_t>(shared_secret.data(), shared_secret.size()),
        first_id,
        second_id
    );
}

std::string X25519::public_key_to_base64(const X25519PublicKey& key) {
    std::string result;
    result.resize(boost::beast::detail::base64::encoded_size(key.size()));
    result.resize(boost::beast::detail::base64::encode(result.data(), key.data(), key.size()));
    return result;
}

std::string X25519::private_key_to_base64(const X25519PrivateKey& key) {
    std::string result;
    result.resize(boost::beast::detail::base64::encoded_size(key.size()));
    result.resize(boost::beast::detail::base64::encode(result.data(), key.data(), key.size()));
    return result;
}

std::expected<X25519PublicKey, ErrorCode> X25519::public_key_from_base64(const std::string& b64) {
    X25519PublicKey key;
    
    auto decoded_size = boost::beast::detail::base64::decode(key.data(), b64.data(), b64.size());
    if (decoded_size.first != key.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    return key;
}

std::expected<X25519PrivateKey, ErrorCode> X25519::private_key_from_base64(const std::string& b64) {
    X25519PrivateKey key;
    
    auto decoded_size = boost::beast::detail::base64::decode(key.data(), b64.data(), b64.size());
    if (decoded_size.first != key.size()) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    return key;
}

bool X25519::validate_public_key(const X25519PublicKey& key) {
    // Check if the key is not all zeros
    bool all_zero = true;
    for (auto b : key) {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    return !all_zero;
}

} // namespace edgelink::crypto

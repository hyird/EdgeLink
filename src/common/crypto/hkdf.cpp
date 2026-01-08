#include "common/crypto/hkdf.hpp"
#include <sodium.h>
#include <cstring>

namespace edgelink::crypto {

std::array<uint8_t, 32> HKDF::hmac_sha256(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data) {
    
    std::array<uint8_t, 32> result;
    
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key.data(), key.size());
    crypto_auth_hmacsha256_update(&state, data.data(), data.size());
    crypto_auth_hmacsha256_final(&state, result.data());
    
    return result;
}

std::array<uint8_t, 32> HKDF::extract(
    std::span<const uint8_t> salt,
    std::span<const uint8_t> input_key_material) {
    
    // If salt is empty, use a string of zeros
    if (salt.empty()) {
        std::array<uint8_t, 32> zero_salt{};
        return hmac_sha256(zero_salt, input_key_material);
    }
    
    return hmac_sha256(salt, input_key_material);
}

std::vector<uint8_t> HKDF::expand(
    std::span<const uint8_t> prk,
    std::span<const uint8_t> info,
    size_t output_length) {
    
    std::vector<uint8_t> output;
    output.reserve(output_length);
    
    std::array<uint8_t, 32> t{};  // Previous block
    uint8_t counter = 1;
    
    while (output.size() < output_length) {
        // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        std::vector<uint8_t> input;
        
        if (counter > 1) {
            input.insert(input.end(), t.begin(), t.end());
        }
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);
        
        t = hmac_sha256(prk, input);
        
        // Append to output
        size_t remaining = output_length - output.size();
        size_t to_copy = std::min(remaining, t.size());
        output.insert(output.end(), t.begin(), t.begin() + to_copy);
        
        ++counter;
        
        // RFC 5869: output length cannot exceed 255 * hash length
        if (counter == 0) break;  // Overflow protection
    }
    
    return output;
}

std::vector<uint8_t> HKDF::derive(
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_length) {
    
    auto prk = extract(salt, input_key_material);
    return expand(prk, info, output_length);
}

SessionKey HKDF::derive_session_key(
    std::span<const uint8_t> shared_secret,
    uint32_t node_a_id,
    uint32_t node_b_id) {
    
    // Ensure consistent ordering (smaller ID first)
    uint32_t first_id = std::min(node_a_id, node_b_id);
    uint32_t second_id = std::max(node_a_id, node_b_id);
    
    // Build info: "edgelink-session" || first_id || second_id
    std::vector<uint8_t> info;
    const char* label = "edgelink-session";
    info.insert(info.end(), label, label + strlen(label));
    
    // Append node IDs (big endian)
    info.push_back(static_cast<uint8_t>((first_id >> 24) & 0xFF));
    info.push_back(static_cast<uint8_t>((first_id >> 16) & 0xFF));
    info.push_back(static_cast<uint8_t>((first_id >> 8) & 0xFF));
    info.push_back(static_cast<uint8_t>(first_id & 0xFF));
    
    info.push_back(static_cast<uint8_t>((second_id >> 24) & 0xFF));
    info.push_back(static_cast<uint8_t>((second_id >> 16) & 0xFF));
    info.push_back(static_cast<uint8_t>((second_id >> 8) & 0xFF));
    info.push_back(static_cast<uint8_t>(second_id & 0xFF));
    
    // Derive 32-byte session key
    auto derived = derive(shared_secret, {}, info, CryptoConstants::SESSION_KEY_SIZE);
    
    SessionKey key;
    std::memcpy(key.data(), derived.data(), key.size());
    
    return key;
}

} // namespace edgelink::crypto

#include "common/crypto/chacha20.hpp"
#include <sodium.h>
#include <cstring>

namespace edgelink::crypto {

std::expected<std::vector<uint8_t>, ErrorCode> ChaCha20Poly1305::encrypt(
    const SessionKey& key,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data) {
    
    Nonce nonce = generate_nonce();
    
    auto result = encrypt_with_nonce(key, nonce, plaintext, associated_data);
    if (!result) {
        return std::unexpected(result.error());
    }
    
    // Prepend nonce to ciphertext
    std::vector<uint8_t> output(nonce.size() + result->size());
    std::memcpy(output.data(), nonce.data(), nonce.size());
    std::memcpy(output.data() + nonce.size(), result->data(), result->size());
    
    return output;
}

std::expected<std::vector<uint8_t>, ErrorCode> ChaCha20Poly1305::encrypt_with_nonce(
    const SessionKey& key,
    const Nonce& nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> associated_data) {
    
    std::vector<uint8_t> ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;
    
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            associated_data.data(), associated_data.size(),
            nullptr,  // nsec (not used)
            nonce.data(),
            key.data()) != 0) {
        return std::unexpected(ErrorCode::INTERNAL_ERROR);
    }
    
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::expected<std::vector<uint8_t>, ErrorCode> ChaCha20Poly1305::decrypt(
    const SessionKey& key,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data) {
    
    if (ciphertext.size() < CryptoConstants::CHACHA20_NONCE_SIZE + CryptoConstants::POLY1305_TAG_SIZE) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    Nonce nonce;
    std::memcpy(nonce.data(), ciphertext.data(), nonce.size());
    
    auto encrypted = ciphertext.subspan(nonce.size());
    return decrypt_with_nonce(key, nonce, encrypted, associated_data);
}

std::expected<std::vector<uint8_t>, ErrorCode> ChaCha20Poly1305::decrypt_with_nonce(
    const SessionKey& key,
    const Nonce& nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> associated_data) {
    
    if (ciphertext.size() < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    std::vector<uint8_t> plaintext(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long plaintext_len;
    
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // nsec (not used)
            ciphertext.data(), ciphertext.size(),
            associated_data.data(), associated_data.size(),
            nonce.data(),
            key.data()) != 0) {
        return std::unexpected(ErrorCode::DECRYPTION_FAILED);  // Authentication failed
    }
    
    plaintext.resize(plaintext_len);
    return plaintext;
}

Nonce ChaCha20Poly1305::generate_nonce() {
    Nonce nonce;
    randombytes_buf(nonce.data(), nonce.size());
    return nonce;
}

Nonce ChaCha20Poly1305::create_nonce(uint32_t random_prefix, uint64_t counter) {
    Nonce nonce{};
    
    // First 4 bytes: random prefix (big endian)
    nonce[0] = static_cast<uint8_t>((random_prefix >> 24) & 0xFF);
    nonce[1] = static_cast<uint8_t>((random_prefix >> 16) & 0xFF);
    nonce[2] = static_cast<uint8_t>((random_prefix >> 8) & 0xFF);
    nonce[3] = static_cast<uint8_t>(random_prefix & 0xFF);
    
    // Last 8 bytes: counter (big endian)
    nonce[4] = static_cast<uint8_t>((counter >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((counter >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((counter >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((counter >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((counter >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(counter & 0xFF);
    
    return nonce;
}

uint64_t ChaCha20Poly1305::extract_counter(const Nonce& nonce) {
    return (static_cast<uint64_t>(nonce[4]) << 56) |
           (static_cast<uint64_t>(nonce[5]) << 48) |
           (static_cast<uint64_t>(nonce[6]) << 40) |
           (static_cast<uint64_t>(nonce[7]) << 32) |
           (static_cast<uint64_t>(nonce[8]) << 24) |
           (static_cast<uint64_t>(nonce[9]) << 16) |
           (static_cast<uint64_t>(nonce[10]) << 8) |
           static_cast<uint64_t>(nonce[11]);
}

// ============================================================================
// ReplayProtection Implementation
// ============================================================================

ReplayProtection::ReplayProtection(size_t window_size)
    : window_size_(window_size)
    , window_(window_size, false) {
}

bool ReplayProtection::check(uint64_t counter) {
    if (counter > max_counter_) {
        return true;  // New counter, definitely valid
    }
    
    // Check if too old
    if (max_counter_ - counter >= window_size_) {
        return false;  // Outside window, reject
    }
    
    // Check if already seen
    return !window_[index_of(counter)];
}

void ReplayProtection::mark_seen(uint64_t counter) {
    if (counter > max_counter_) {
        // Shift window
        uint64_t shift = counter - max_counter_;
        if (shift >= window_size_) {
            // Clear entire window
            std::fill(window_.begin(), window_.end(), false);
        } else {
            // Clear old entries
            for (uint64_t i = max_counter_ + 1; i <= counter; ++i) {
                window_[index_of(i)] = false;
            }
        }
        max_counter_ = counter;
    }
    
    window_[index_of(counter)] = true;
}

bool ReplayProtection::check_and_mark(uint64_t counter) {
    if (!check(counter)) {
        return false;
    }
    mark_seen(counter);
    return true;
}

void ReplayProtection::reset() {
    max_counter_ = 0;
    std::fill(window_.begin(), window_.end(), false);
}

size_t ReplayProtection::index_of(uint64_t counter) const {
    return counter % window_size_;
}

} // namespace edgelink::crypto

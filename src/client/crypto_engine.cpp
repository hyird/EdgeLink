#include "client/crypto_engine.hpp"
#include "common/crypto/x25519.hpp"
#include "common/crypto/chacha20.hpp"
#include "common/crypto/hkdf.hpp"
#include "common/log.hpp"

#include <sodium.h>
#include <cstring>
#include <random>
#include <arpa/inet.h>

namespace edgelink::client {

// ============================================================================
// ReplayWindow Implementation
// ============================================================================

bool ReplayWindow::check_and_update(uint64_t counter) {
    std::lock_guard<std::mutex> lock(*mutex_);
    
    // Counter 0 is never valid (reserved)
    if (counter == 0) {
        return false;
    }
    
    // If counter is newer than anything we've seen
    if (counter > highest_counter_) {
        uint64_t diff = counter - highest_counter_;
        
        if (diff >= WINDOW_SIZE) {
            // New counter is way ahead, reset window
            window_.reset();
        } else {
            // Shift window
            window_ <<= diff;
        }
        
        highest_counter_ = counter;
        window_.set(0);  // Mark current counter as seen
        return true;
    }
    
    // Counter is within or before window
    uint64_t diff = highest_counter_ - counter;
    
    if (diff >= WINDOW_SIZE) {
        // Too old, reject
        return false;
    }
    
    // Check if already seen
    if (window_.test(diff)) {
        return false;  // Replay!
    }
    
    // Mark as seen
    window_.set(diff);
    return true;
}

void ReplayWindow::reset() {
    std::lock_guard<std::mutex> lock(*mutex_);
    highest_counter_ = 0;
    window_.reset();
}

// ============================================================================
// CryptoEngine Implementation
// ============================================================================

CryptoEngine::CryptoEngine(uint32_t local_node_id)
    : local_node_id_(local_node_id)
{
    // Initialize libsodium if not already done
    if (sodium_init() < 0) {
        LOG_ERROR("Failed to initialize libsodium");
    }
    
    // Generate random initial keys
    std::memset(node_priv_.data(), 0, 32);
    std::memset(node_pub_.data(), 0, 32);
}

CryptoEngine::~CryptoEngine() {
    // Securely wipe keys
    sodium_memzero(node_priv_.data(), node_priv_.size());
    
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    for (auto& [id, session] : sessions_) {
        sodium_memzero(session.key.data(), session.key.size());
    }
}

void CryptoEngine::set_local_keys(
    const std::array<uint8_t, 32>& node_priv,
    const std::array<uint8_t, 32>& node_pub
) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    node_priv_ = node_priv;
    node_pub_ = node_pub;
    keys_initialized_ = true;
    
    LOG_INFO("CryptoEngine: Local keys set for node {}", local_node_id_);
}

std::expected<void, ErrorCode> CryptoEngine::add_peer(
    uint32_t peer_node_id,
    const std::array<uint8_t, 32>& peer_node_pub
) {
    if (!keys_initialized_) {
        LOG_ERROR("CryptoEngine: Local keys not initialized");
        return std::unexpected(ErrorCode::INTERNAL_ERROR);
    }
    
    if (peer_node_id == local_node_id_) {
        LOG_ERROR("CryptoEngine: Cannot add self as peer");
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    
    // Compute shared secret via X25519 ECDH
    std::array<uint8_t, 32> shared_secret;
    if (crypto_scalarmult(shared_secret.data(), node_priv_.data(), peer_node_pub.data()) != 0) {
        LOG_ERROR("CryptoEngine: X25519 key exchange failed for peer {}", peer_node_id);
        return std::unexpected(ErrorCode::CRYPTO_ERROR);
    }
    
    // Derive session key using HKDF
    auto session_key = derive_session_key(shared_secret, local_node_id_, peer_node_id);
    
    // Securely wipe shared secret
    sodium_memzero(shared_secret.data(), shared_secret.size());
    
    // Generate random nonce prefix
    std::array<uint8_t, 4> nonce_prefix;
    randombytes_buf(nonce_prefix.data(), nonce_prefix.size());
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        // Check if we have an existing session (for key rotation)
        auto it = sessions_.find(peer_node_id);
        if (it != sessions_.end()) {
            // Save old key for 5 minutes
            std::lock_guard<std::mutex> old_lock(old_keys_mutex_);
            OldSessionKey old_key;
            old_key.key = it->second.key;
            old_key.recv_window = std::move(it->second.recv_window);
            old_key.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(5);
            old_keys_[peer_node_id].push_back(std::move(old_key));
            
            LOG_DEBUG("CryptoEngine: Saved old key for peer {}", peer_node_id);
        }
        
        // Create new session
        SessionKey session;
        session.peer_node_id = peer_node_id;
        session.key = session_key;
        session.nonce_prefix = nonce_prefix;
        session.send_counter = 0;
        session.recv_window.reset();
        session.created_at = std::chrono::steady_clock::now();
        session.last_used = session.created_at;
        session.marked_for_rotation = false;
        
        sessions_[peer_node_id] = std::move(session);
        peer_pubkeys_[peer_node_id] = peer_node_pub;
    }
    
    LOG_INFO("CryptoEngine: Added peer {} with new session key", peer_node_id);
    return {};
}

void CryptoEngine::remove_peer(uint32_t peer_node_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(peer_node_id);
    if (it != sessions_.end()) {
        // Securely wipe key
        sodium_memzero(it->second.key.data(), it->second.key.size());
        sessions_.erase(it);
    }
    
    peer_pubkeys_.erase(peer_node_id);
    
    {
        std::lock_guard<std::mutex> old_lock(old_keys_mutex_);
        auto old_it = old_keys_.find(peer_node_id);
        if (old_it != old_keys_.end()) {
            for (auto& old_key : old_it->second) {
                sodium_memzero(old_key.key.data(), old_key.key.size());
            }
            old_keys_.erase(old_it);
        }
    }
    
    LOG_INFO("CryptoEngine: Removed peer {}", peer_node_id);
}

bool CryptoEngine::has_peer(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    return sessions_.contains(peer_node_id);
}

std::expected<std::array<uint8_t, 32>, ErrorCode> CryptoEngine::get_peer_pubkey(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = peer_pubkeys_.find(peer_node_id);
    if (it == peer_pubkeys_.end()) {
        return std::unexpected(ErrorCode::PEER_NOT_FOUND);
    }
    return it->second;
}

std::expected<std::vector<uint8_t>, ErrorCode> CryptoEngine::encrypt(
    uint32_t peer_node_id,
    const std::vector<uint8_t>& plaintext
) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(peer_node_id);
    if (it == sessions_.end()) {
        LOG_ERROR("CryptoEngine: No session for peer {}", peer_node_id);
        return std::unexpected(ErrorCode::PEER_NOT_FOUND);
    }
    
    auto& session = it->second;
    
    // Increment counter
    session.send_counter++;
    if (session.send_counter == 0) {
        // Counter overflow - should never happen in practice
        LOG_ERROR("CryptoEngine: Counter overflow for peer {}", peer_node_id);
        return std::unexpected(ErrorCode::CRYPTO_ERROR);
    }
    
    // Generate nonce
    auto nonce = generate_nonce(session.nonce_prefix, session.send_counter);
    
    // Allocate output: nonce(12) + ciphertext + tag(16)
    std::vector<uint8_t> output(12 + plaintext.size() + 16);
    
    // Copy nonce
    std::memcpy(output.data(), nonce.data(), 12);
    
    // Encrypt using ChaCha20-Poly1305
    unsigned long long ciphertext_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            output.data() + 12,  // ciphertext output
            &ciphertext_len,
            plaintext.data(),
            plaintext.size(),
            nullptr, 0,  // no additional data
            nullptr,     // secret nonce (unused)
            nonce.data(),
            session.key.data()
        ) != 0)
    {
        LOG_ERROR("CryptoEngine: Encryption failed for peer {}", peer_node_id);
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.encryption_failures++;
        return std::unexpected(ErrorCode::CRYPTO_ERROR);
    }
    
    session.last_used = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.packets_encrypted++;
    }
    
    return output;
}

std::expected<std::vector<uint8_t>, ErrorCode> CryptoEngine::decrypt(
    uint32_t peer_node_id,
    const std::vector<uint8_t>& ciphertext
) {
    // Minimum size: nonce(12) + tag(16)
    if (ciphertext.size() < 28) {
        LOG_ERROR("CryptoEngine: Ciphertext too short from peer {}", peer_node_id);
        return std::unexpected(ErrorCode::INVALID_FRAME);
    }
    
    std::unique_lock<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(peer_node_id);
    if (it == sessions_.end()) {
        LOG_ERROR("CryptoEngine: No session for peer {}", peer_node_id);
        return std::unexpected(ErrorCode::PEER_NOT_FOUND);
    }
    
    auto& session = it->second;
    
    // Extract nonce and get counter from it
    std::array<uint8_t, 12> nonce;
    std::memcpy(nonce.data(), ciphertext.data(), 12);
    
    uint64_t counter;
    std::memcpy(&counter, nonce.data() + 4, 8);
    
    // Check for replay
    if (!session.recv_window.check_and_update(counter)) {
        LOG_WARN("CryptoEngine: Replay attack detected from peer {}, counter {}", 
                 peer_node_id, counter);
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.replay_attacks_blocked++;
        return std::unexpected(ErrorCode::REPLAY_DETECTED);
    }
    
    // Allocate output
    std::vector<uint8_t> plaintext(ciphertext.size() - 28);
    unsigned long long plaintext_len;
    
    // Decrypt
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext.data(),
            &plaintext_len,
            nullptr,  // secret nonce (unused)
            ciphertext.data() + 12,  // ciphertext
            ciphertext.size() - 12,
            nullptr, 0,  // no additional data
            nonce.data(),
            session.key.data()
        ) != 0)
    {
        lock.unlock();
        
        // Try old keys during rotation period
        auto result = try_decrypt_with_old_key(peer_node_id, ciphertext);
        if (result) {
            return result;
        }
        
        LOG_ERROR("CryptoEngine: Decryption failed from peer {}", peer_node_id);
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.decryption_failures++;
        return std::unexpected(ErrorCode::CRYPTO_ERROR);
    }
    
    plaintext.resize(plaintext_len);
    session.last_used = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.packets_decrypted++;
    }
    
    return plaintext;
}

std::expected<std::vector<uint8_t>, ErrorCode> CryptoEngine::encrypt_with_header(
    uint32_t dst_node_id,
    const std::vector<uint8_t>& plaintext
) {
    // First encrypt the data
    auto encrypted = encrypt(dst_node_id, plaintext);
    if (!encrypted) {
        return std::unexpected(encrypted.error());
    }
    
    // Get counter from nonce
    uint64_t counter;
    std::memcpy(&counter, encrypted->data() + 4, 8);
    
    // Create header: src_node_id(4) + dst_node_id(4) + counter(8)
    std::vector<uint8_t> result(16 + encrypted->size());
    
    uint32_t src_be = htonl(local_node_id_);
    uint32_t dst_be = htonl(dst_node_id);
    
    std::memcpy(result.data(), &src_be, 4);
    std::memcpy(result.data() + 4, &dst_be, 4);
    std::memcpy(result.data() + 8, &counter, 8);
    std::memcpy(result.data() + 16, encrypted->data(), encrypted->size());
    
    return result;
}

std::expected<CryptoEngine::DecryptResult, ErrorCode> CryptoEngine::decrypt_with_header(
    const std::vector<uint8_t>& data
) {
    // Minimum: header(16) + nonce(12) + tag(16)
    if (data.size() < 44) {
        LOG_ERROR("CryptoEngine: Data too short for header decryption");
        return std::unexpected(ErrorCode::INVALID_FRAME);
    }
    
    // Parse header
    uint32_t src_be, dst_be;
    std::memcpy(&src_be, data.data(), 4);
    std::memcpy(&dst_be, data.data() + 4, 4);
    
    uint32_t src_node_id = ntohl(src_be);
    uint32_t dst_node_id = ntohl(dst_be);
    
    // Verify destination is us
    if (dst_node_id != local_node_id_) {
        LOG_ERROR("CryptoEngine: Packet not for us (dst={}, local={})", 
                  dst_node_id, local_node_id_);
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    
    // Extract encrypted data
    std::vector<uint8_t> encrypted(data.begin() + 16, data.end());
    
    // Decrypt
    auto plaintext = decrypt(src_node_id, encrypted);
    if (!plaintext) {
        return std::unexpected(plaintext.error());
    }
    
    DecryptResult result;
    result.src_node_id = src_node_id;
    result.plaintext = std::move(*plaintext);
    return result;
}

void CryptoEngine::mark_key_rotation(uint32_t peer_node_id) {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    
    auto it = sessions_.find(peer_node_id);
    if (it != sessions_.end()) {
        it->second.marked_for_rotation = true;
        it->second.rotation_deadline = std::chrono::steady_clock::now() + std::chrono::minutes(5);
        LOG_INFO("CryptoEngine: Marked key rotation for peer {}", peer_node_id);
    }
}

std::expected<std::array<uint8_t, 32>, ErrorCode> CryptoEngine::rotate_local_keys() {
    std::array<uint8_t, 32> new_priv, new_pub;
    
    // Generate new X25519 keypair
    if (crypto_box_keypair(new_pub.data(), new_priv.data()) != 0) {
        LOG_ERROR("CryptoEngine: Failed to generate new keypair");
        return std::unexpected(ErrorCode::CRYPTO_ERROR);
    }
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        
        // Securely wipe old private key
        sodium_memzero(node_priv_.data(), node_priv_.size());
        
        node_priv_ = new_priv;
        node_pub_ = new_pub;
        
        // Re-derive all session keys
        for (auto& [peer_id, session] : sessions_) {
            auto pub_it = peer_pubkeys_.find(peer_id);
            if (pub_it == peer_pubkeys_.end()) {
                continue;
            }
            
            // Save old key
            {
                std::lock_guard<std::mutex> old_lock(old_keys_mutex_);
                OldSessionKey old_key;
                old_key.key = session.key;
                old_key.recv_window = std::move(session.recv_window);
                old_key.expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(5);
                old_keys_[peer_id].push_back(std::move(old_key));
            }
            
            // Compute new shared secret
            std::array<uint8_t, 32> shared_secret;
            if (crypto_scalarmult(shared_secret.data(), node_priv_.data(), pub_it->second.data()) == 0) {
                session.key = derive_session_key(shared_secret, local_node_id_, peer_id);
                session.send_counter = 0;
                session.recv_window.reset();
                sodium_memzero(shared_secret.data(), shared_secret.size());
            }
        }
    }
    
    LOG_INFO("CryptoEngine: Rotated local keys");
    return new_pub;
}

void CryptoEngine::cleanup_old_keys() {
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(old_keys_mutex_);
    
    for (auto it = old_keys_.begin(); it != old_keys_.end(); ) {
        auto& keys = it->second;
        
        // Remove expired keys
        while (!keys.empty() && keys.front().expires_at <= now) {
            sodium_memzero(keys.front().key.data(), keys.front().key.size());
            keys.pop_front();
        }
        
        if (keys.empty()) {
            it = old_keys_.erase(it);
        } else {
            ++it;
        }
    }
}

CryptoEngine::Stats CryptoEngine::get_stats() const {
    Stats result;
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        result = stats_;
    }
    
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        result.active_sessions = static_cast<uint32_t>(sessions_.size());
    }
    
    return result;
}

// ============================================================================
// Private Methods
// ============================================================================

std::array<uint8_t, 32> CryptoEngine::derive_session_key(
    const std::array<uint8_t, 32>& shared_secret,
    uint32_t node_a_id,
    uint32_t node_b_id
) {
    // Ensure consistent ordering for both parties
    uint32_t id1 = std::min(node_a_id, node_b_id);
    uint32_t id2 = std::max(node_a_id, node_b_id);
    
    // Create info: "edgelink-session" + id1 + id2
    std::vector<uint8_t> info;
    const char* label = "edgelink-session";
    info.insert(info.end(), label, label + 16);
    
    uint32_t id1_be = htonl(id1);
    uint32_t id2_be = htonl(id2);
    info.insert(info.end(), reinterpret_cast<uint8_t*>(&id1_be), reinterpret_cast<uint8_t*>(&id1_be) + 4);
    info.insert(info.end(), reinterpret_cast<uint8_t*>(&id2_be), reinterpret_cast<uint8_t*>(&id2_be) + 4);
    
    // HKDF with SHA256 using crypto::HKDF
    auto key_vec = crypto::HKDF::derive(
        std::span<const uint8_t>(shared_secret.data(), shared_secret.size()),
        std::span<const uint8_t>{},  // empty salt
        std::span<const uint8_t>(info.data(), info.size()),
        32
    );
    
    std::array<uint8_t, 32> key;
    std::memcpy(key.data(), key_vec.data(), 32);
    return key;
}

std::array<uint8_t, 12> CryptoEngine::generate_nonce(
    const std::array<uint8_t, 4>& prefix,
    uint64_t counter
) {
    std::array<uint8_t, 12> nonce;
    std::memcpy(nonce.data(), prefix.data(), 4);
    std::memcpy(nonce.data() + 4, &counter, 8);
    return nonce;
}

std::expected<std::vector<uint8_t>, ErrorCode> CryptoEngine::try_decrypt_with_old_key(
    uint32_t peer_node_id,
    const std::vector<uint8_t>& ciphertext
) {
    std::lock_guard<std::mutex> lock(old_keys_mutex_);
    
    auto it = old_keys_.find(peer_node_id);
    if (it == old_keys_.end() || it->second.empty()) {
        return std::unexpected(ErrorCode::CRYPTO_ERROR);
    }
    
    // Extract nonce
    std::array<uint8_t, 12> nonce;
    std::memcpy(nonce.data(), ciphertext.data(), 12);
    
    // Try each old key
    for (auto& old_key : it->second) {
        std::vector<uint8_t> plaintext(ciphertext.size() - 28);
        unsigned long long plaintext_len;
        
        if (crypto_aead_chacha20poly1305_ietf_decrypt(
                plaintext.data(),
                &plaintext_len,
                nullptr,
                ciphertext.data() + 12,
                ciphertext.size() - 12,
                nullptr, 0,
                nonce.data(),
                old_key.key.data()
            ) == 0)
        {
            plaintext.resize(plaintext_len);
            LOG_DEBUG("CryptoEngine: Decrypted with old key for peer {}", peer_node_id);
            
            {
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.packets_decrypted++;
            }
            
            return plaintext;
        }
    }
    
    return std::unexpected(ErrorCode::CRYPTO_ERROR);
}

} // namespace edgelink::client

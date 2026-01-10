#include "client/crypto_engine.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <filesystem>

namespace edgelink::client {

std::string crypto_engine_error_message(CryptoEngineError error) {
    switch (error) {
        case CryptoEngineError::KEY_GENERATION_FAILED: return "Key generation failed";
        case CryptoEngineError::SESSION_KEY_NOT_FOUND: return "Session key not found";
        case CryptoEngineError::ENCRYPTION_FAILED: return "Encryption failed";
        case CryptoEngineError::DECRYPTION_FAILED: return "Decryption failed";
        case CryptoEngineError::INVALID_PEER: return "Invalid peer";
        default: return "Unknown crypto engine error";
    }
}

CryptoEngine::CryptoEngine() = default;

std::expected<void, CryptoEngineError> CryptoEngine::init() {
    // Generate machine key (Ed25519)
    auto mk = crypto::generate_machine_key();
    if (!mk) {
        spdlog::error("Failed to generate machine key");
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }
    machine_key_ = *mk;

    // Generate node key (X25519)
    auto nk = crypto::generate_node_key();
    if (!nk) {
        spdlog::error("Failed to generate node key");
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }
    node_key_ = *nk;

    initialized_ = true;
    spdlog::info("Crypto engine initialized with new keys");
    spdlog::debug("Machine key: {}...", crypto::key_to_hex(machine_key_.public_key).substr(0, 16));
    spdlog::debug("Node key: {}...", crypto::key_to_hex(node_key_.public_key).substr(0, 16));

    return {};
}

std::expected<void, CryptoEngineError> CryptoEngine::load_keys(
    std::span<const uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_pub,
    std::span<const uint8_t, ED25519_PRIVATE_KEY_SIZE> machine_priv,
    std::span<const uint8_t, X25519_KEY_SIZE> node_pub,
    std::span<const uint8_t, X25519_KEY_SIZE> node_priv) {

    std::copy(machine_pub.begin(), machine_pub.end(), machine_key_.public_key.begin());
    std::copy(machine_priv.begin(), machine_priv.end(), machine_key_.private_key.begin());
    std::copy(node_pub.begin(), node_pub.end(), node_key_.public_key.begin());
    std::copy(node_priv.begin(), node_priv.end(), node_key_.private_key.begin());

    initialized_ = true;
    spdlog::info("Crypto engine initialized with loaded keys");

    return {};
}

std::expected<std::array<uint8_t, ED25519_SIGNATURE_SIZE>, CryptoEngineError>
CryptoEngine::sign(std::span<const uint8_t> data) {
    auto result = crypto::ed25519_sign(data, machine_key_.private_key);
    if (!result) {
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }
    return *result;
}

std::expected<void, CryptoEngineError> CryptoEngine::derive_session_key(
    NodeId peer_id, std::span<const uint8_t, X25519_KEY_SIZE> peer_node_key) {

    // Check if already derived
    {
        std::shared_lock lock(sessions_mutex_);
        auto it = peer_sessions_.find(peer_id);
        if (it != peer_sessions_.end() && it->second.valid) {
            return {}; // Already have valid session key
        }
    }

    // Perform X25519 key exchange
    auto shared_secret = crypto::x25519_exchange(node_key_.private_key, peer_node_key);
    if (!shared_secret) {
        spdlog::error("X25519 key exchange failed for peer {}", peer_id);
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    // Derive session key using HKDF
    auto session_key = crypto::derive_session_key(*shared_secret, node_id_, peer_id);
    if (!session_key) {
        spdlog::error("Session key derivation failed for peer {}", peer_id);
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    // Store session
    {
        std::unique_lock lock(sessions_mutex_);
        PeerSession session;
        session.session_key = *session_key;
        session.send_counter = 0;
        session.recv_counter = 0;
        session.valid = true;
        peer_sessions_[peer_id] = session;
    }

    spdlog::debug("Derived session key for peer {}", peer_id);
    return {};
}

bool CryptoEngine::has_session_key(NodeId peer_id) const {
    std::shared_lock lock(sessions_mutex_);
    auto it = peer_sessions_.find(peer_id);
    return it != peer_sessions_.end() && it->second.valid;
}

void CryptoEngine::remove_session_key(NodeId peer_id) {
    std::unique_lock lock(sessions_mutex_);
    peer_sessions_.erase(peer_id);
    spdlog::debug("Removed session key for peer {}", peer_id);
}

void CryptoEngine::clear_all_session_keys() {
    std::unique_lock lock(sessions_mutex_);
    peer_sessions_.clear();
    spdlog::debug("Cleared all session keys");
}

uint64_t CryptoEngine::next_send_counter(NodeId peer_id) {
    std::unique_lock lock(sessions_mutex_);
    auto it = peer_sessions_.find(peer_id);
    if (it == peer_sessions_.end()) {
        return 0;
    }
    return it->second.send_counter++;
}

std::expected<std::vector<uint8_t>, CryptoEngineError> CryptoEngine::encrypt(
    NodeId peer_id, std::span<const uint8_t> plaintext,
    std::array<uint8_t, CHACHA20_NONCE_SIZE>& nonce_out) {

    PeerSession session;
    uint64_t counter;

    // Get session key and counter
    {
        std::unique_lock lock(sessions_mutex_);
        auto it = peer_sessions_.find(peer_id);
        if (it == peer_sessions_.end() || !it->second.valid) {
            return std::unexpected(CryptoEngineError::SESSION_KEY_NOT_FOUND);
        }
        session = it->second;
        counter = it->second.send_counter++;
    }

    // Construct nonce from base XOR counter
    nonce_out = crypto::xor_nonce_with_counter(session.session_key.send_nonce_base, counter);

    // Build AAD (additional authenticated data): src_node || dst_node
    std::array<uint8_t, 8> aad;
    aad[0] = (node_id_ >> 24) & 0xFF;
    aad[1] = (node_id_ >> 16) & 0xFF;
    aad[2] = (node_id_ >> 8) & 0xFF;
    aad[3] = node_id_ & 0xFF;
    aad[4] = (peer_id >> 24) & 0xFF;
    aad[5] = (peer_id >> 16) & 0xFF;
    aad[6] = (peer_id >> 8) & 0xFF;
    aad[7] = peer_id & 0xFF;

    // Encrypt
    auto result = crypto::chacha20_poly1305_encrypt(
        session.session_key.key, nonce_out, plaintext, aad);

    if (!result) {
        return std::unexpected(CryptoEngineError::ENCRYPTION_FAILED);
    }

    return *result;
}

std::expected<std::vector<uint8_t>, CryptoEngineError> CryptoEngine::decrypt(
    NodeId peer_id, std::span<const uint8_t, CHACHA20_NONCE_SIZE> nonce,
    std::span<const uint8_t> ciphertext) {

    PeerSession session;

    // Get session key
    {
        std::shared_lock lock(sessions_mutex_);
        auto it = peer_sessions_.find(peer_id);
        if (it == peer_sessions_.end() || !it->second.valid) {
            return std::unexpected(CryptoEngineError::SESSION_KEY_NOT_FOUND);
        }
        session = it->second;
    }

    // Build AAD: src_node || dst_node (from peer's perspective, so reversed)
    std::array<uint8_t, 8> aad;
    aad[0] = (peer_id >> 24) & 0xFF;
    aad[1] = (peer_id >> 16) & 0xFF;
    aad[2] = (peer_id >> 8) & 0xFF;
    aad[3] = peer_id & 0xFF;
    aad[4] = (node_id_ >> 24) & 0xFF;
    aad[5] = (node_id_ >> 16) & 0xFF;
    aad[6] = (node_id_ >> 8) & 0xFF;
    aad[7] = node_id_ & 0xFF;

    // Convert span to fixed-size array for the crypto function
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce_arr;
    std::copy(nonce.begin(), nonce.end(), nonce_arr.begin());

    // Decrypt
    auto result = crypto::chacha20_poly1305_decrypt(
        session.session_key.key, nonce_arr, ciphertext, aad);

    if (!result) {
        return std::unexpected(CryptoEngineError::DECRYPTION_FAILED);
    }

    return *result;
}

// Base64 encoding table
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Helper function to encode bytes to base64
static std::string to_base64(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve((len + 2) / 3 * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result.push_back(base64_chars[(n >> 18) & 0x3F]);
        result.push_back(base64_chars[(n >> 12) & 0x3F]);
        result.push_back((i + 1 < len) ? base64_chars[(n >> 6) & 0x3F] : '=');
        result.push_back((i + 2 < len) ? base64_chars[n & 0x3F] : '=');
    }

    return result;
}

// Helper function to decode base64 to bytes
static bool from_base64(const std::string& b64, uint8_t* out, size_t out_len) {
    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    size_t out_idx = 0;
    uint32_t buf = 0;
    int buf_len = 0;

    for (char c : b64) {
        if (c == '=') break;
        int val = decode_table[static_cast<unsigned char>(c)];
        if (val < 0) continue;  // Skip invalid chars

        buf = (buf << 6) | static_cast<uint32_t>(val);
        buf_len += 6;

        if (buf_len >= 8) {
            buf_len -= 8;
            if (out_idx >= out_len) return false;
            out[out_idx++] = static_cast<uint8_t>((buf >> buf_len) & 0xFF);
        }
    }

    return out_idx == out_len;
}

std::expected<void, CryptoEngineError> CryptoEngine::save_keys_to_file(const std::string& path) {
    // Create parent directory if needed
    std::filesystem::path file_path(path);
    if (file_path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(file_path.parent_path(), ec);
        if (ec) {
            spdlog::error("Failed to create key directory: {}", ec.message());
            return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
        }
    }

    // Write keys to file in base64 format (one key per line)
    std::ofstream file(path);
    if (!file) {
        spdlog::error("Failed to open key file for writing: {}", path);
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    file << "# EdgeLink client keys - DO NOT SHARE\n";
    file << "machine_public=" << to_base64(machine_key_.public_key.data(), machine_key_.public_key.size()) << "\n";
    file << "machine_private=" << to_base64(machine_key_.private_key.data(), machine_key_.private_key.size()) << "\n";
    file << "node_public=" << to_base64(node_key_.public_key.data(), node_key_.public_key.size()) << "\n";
    file << "node_private=" << to_base64(node_key_.private_key.data(), node_key_.private_key.size()) << "\n";

    if (!file) {
        spdlog::error("Failed to write keys to file: {}", path);
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    spdlog::info("Keys saved to: {}", path);
    return {};
}

std::expected<void, CryptoEngineError> CryptoEngine::load_keys_from_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        // File doesn't exist - not an error, will generate new keys
        return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
    }

    // Try to load as text format (base64)
    std::unordered_map<std::string, std::string> keys;
    std::string line;
    while (std::getline(file, line)) {
        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        auto eq_pos = line.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = line.substr(0, eq_pos);
            std::string value = line.substr(eq_pos + 1);
            // Trim whitespace
            while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
                value.pop_back();
            }
            keys[key] = value;
        }
    }

    // Check if we have the required keys
    if (keys.count("machine_public") && keys.count("machine_private") &&
        keys.count("node_public") && keys.count("node_private")) {

        // Decode base64 keys
        if (!from_base64(keys["machine_public"], machine_key_.public_key.data(), machine_key_.public_key.size()) ||
            !from_base64(keys["machine_private"], machine_key_.private_key.data(), machine_key_.private_key.size()) ||
            !from_base64(keys["node_public"], node_key_.public_key.data(), node_key_.public_key.size()) ||
            !from_base64(keys["node_private"], node_key_.private_key.data(), node_key_.private_key.size())) {
            spdlog::warn("Invalid base64 in key file, will generate new keys");
            return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
        }

        initialized_ = true;
        spdlog::info("Keys loaded from: {}", path);
        spdlog::debug("Machine key: {}...", crypto::key_to_hex(machine_key_.public_key).substr(0, 16));
        spdlog::debug("Node key: {}...", crypto::key_to_hex(node_key_.public_key).substr(0, 16));
        return {};
    }

    // Fallback: try to load as legacy binary format
    file.clear();
    file.seekg(0, std::ios::beg);

    constexpr size_t expected_size = ED25519_PUBLIC_KEY_SIZE + ED25519_PRIVATE_KEY_SIZE +
                                      X25519_KEY_SIZE + X25519_KEY_SIZE;

    std::vector<uint8_t> buffer(expected_size);
    file.read(reinterpret_cast<char*>(buffer.data()), expected_size);

    if (file.gcount() == static_cast<std::streamsize>(expected_size)) {
        // Parse binary buffer
        size_t offset = 0;
        std::copy_n(buffer.begin() + offset, ED25519_PUBLIC_KEY_SIZE, machine_key_.public_key.begin());
        offset += ED25519_PUBLIC_KEY_SIZE;
        std::copy_n(buffer.begin() + offset, ED25519_PRIVATE_KEY_SIZE, machine_key_.private_key.begin());
        offset += ED25519_PRIVATE_KEY_SIZE;
        std::copy_n(buffer.begin() + offset, X25519_KEY_SIZE, node_key_.public_key.begin());
        offset += X25519_KEY_SIZE;
        std::copy_n(buffer.begin() + offset, X25519_KEY_SIZE, node_key_.private_key.begin());

        initialized_ = true;
        spdlog::info("Keys loaded from: {} (legacy binary format)", path);
        spdlog::debug("Machine key: {}...", crypto::key_to_hex(machine_key_.public_key).substr(0, 16));
        spdlog::debug("Node key: {}...", crypto::key_to_hex(node_key_.public_key).substr(0, 16));
        return {};
    }

    spdlog::warn("Invalid key file format, will generate new keys");
    return std::unexpected(CryptoEngineError::KEY_GENERATION_FAILED);
}

} // namespace edgelink::client

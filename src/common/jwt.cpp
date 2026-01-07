#include "common/jwt.hpp"
#include <openssl/sha.h>
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

namespace edgelink {

// Helper to create integer claim for nlohmann_json backend
inline json_claim make_int_claim(int64_t value) {
    return json_claim(value);
}

// Helper to create integer array claim for nlohmann_json backend
inline json_claim make_int_array_claim(const std::vector<int64_t>& values) {
    nlohmann::json arr = nlohmann::json::array();
    for (auto v : values) {
        arr.push_back(v);
    }
    return json_claim(arr);
}

// Helper to extract integer from claim
inline int64_t get_int_claim(const json_claim& c) {
    return c.as_integer();
}

JWTManager::JWTManager(std::string secret, std::string algorithm)
    : secret_(std::move(secret))
    , algorithm_(std::move(algorithm))
    , verifier_(jwt::verify<json_traits>()
        .allow_algorithm(jwt::algorithm::hs256{secret_})
        .with_issuer("edgelink")) {
}

std::string JWTManager::generate_jti() {
    uint8_t bytes[16];
    randombytes_buf(bytes, sizeof(bytes));
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        oss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return oss.str();
}

int64_t JWTManager::now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string JWTManager::create_auth_token(
    uint32_t node_id,
    const std::string& machine_key_hash,
    uint32_t network_id,
    const std::string& virtual_ip,
    std::chrono::hours expire_hours) {
    
    auto now_time = std::chrono::system_clock::now();
    auto exp_time = now_time + expire_hours;
    
    auto token = jwt::create<json_traits>()
        .set_issuer("edgelink")
        .set_type("JWT")
        .set_issued_at(now_time)
        .set_expires_at(exp_time)
        .set_id(generate_jti())
        .set_payload_claim("type", json_claim(std::string("auth")))
        .set_payload_claim("node_id", make_int_claim(node_id))
        .set_payload_claim("machine_key_hash", json_claim(machine_key_hash))
        .set_payload_claim("network_id", make_int_claim(network_id))
        .set_payload_claim("virtual_ip", json_claim(virtual_ip))
        .sign(jwt::algorithm::hs256{secret_});
    
    return token;
}

std::string JWTManager::create_relay_token(
    uint32_t node_id,
    uint32_t network_id,
    const std::vector<uint32_t>& allowed_relays,
    std::chrono::minutes expire_minutes) {
    
    auto now_time = std::chrono::system_clock::now();
    auto exp_time = now_time + expire_minutes;
    
    std::vector<int64_t> relays;
    for (auto id : allowed_relays) {
        relays.push_back(static_cast<int64_t>(id));
    }
    
    auto token = jwt::create<json_traits>()
        .set_issuer("edgelink")
        .set_type("JWT")
        .set_issued_at(now_time)
        .set_expires_at(exp_time)
        .set_id(generate_jti())
        .set_payload_claim("type", json_claim(std::string("relay")))
        .set_payload_claim("node_id", make_int_claim(node_id))
        .set_payload_claim("network_id", make_int_claim(network_id))
        .set_payload_claim("allowed_relays", make_int_array_claim(relays))
        .sign(jwt::algorithm::hs256{secret_});
    
    return token;
}

std::string JWTManager::create_server_token(
    uint32_t server_id,
    const std::string& server_name,
    uint8_t capabilities,
    const std::string& region,
    std::chrono::hours expire_hours) {
    
    auto now_time = std::chrono::system_clock::now();
    auto exp_time = now_time + expire_hours;
    
    auto token = jwt::create<json_traits>()
        .set_issuer("edgelink")
        .set_type("JWT")
        .set_issued_at(now_time)
        .set_expires_at(exp_time)
        .set_id(generate_jti())
        .set_payload_claim("type", json_claim(std::string("server")))
        .set_payload_claim("server_id", make_int_claim(server_id))
        .set_payload_claim("server_name", json_claim(server_name))
        .set_payload_claim("capabilities", make_int_claim(capabilities))
        .set_payload_claim("region", json_claim(region))
        .sign(jwt::algorithm::hs256{secret_});
    
    return token;
}

std::expected<AuthTokenClaims, ErrorCode> JWTManager::verify_auth_token(const std::string& token) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        verifier_.verify(decoded);
        
        auto type = decoded.get_payload_claim("type").as_string();
        if (type != "auth") {
            return std::unexpected(ErrorCode::INVALID_TOKEN);
        }
        
        std::string jti = decoded.get_id();
        if (is_blacklisted(jti)) {
            return std::unexpected(ErrorCode::TOKEN_REVOKED);
        }
        
        AuthTokenClaims claims;
        claims.type = TokenType::AUTH;
        claims.node_id = static_cast<uint32_t>(decoded.get_payload_claim("node_id").as_integer());
        claims.machine_key_hash = decoded.get_payload_claim("machine_key_hash").as_string();
        claims.network_id = static_cast<uint32_t>(decoded.get_payload_claim("network_id").as_integer());
        claims.virtual_ip = decoded.get_payload_claim("virtual_ip").as_string();
        claims.iat = decoded.get_issued_at().time_since_epoch().count() / 1000000000;
        claims.exp = decoded.get_expires_at().time_since_epoch().count() / 1000000000;
        claims.jti = jti;
        
        return claims;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_TOKEN);
    }
}

std::expected<RelayTokenClaims, ErrorCode> JWTManager::verify_relay_token(const std::string& token) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        verifier_.verify(decoded);
        
        auto type = decoded.get_payload_claim("type").as_string();
        if (type != "relay") {
            return std::unexpected(ErrorCode::INVALID_TOKEN);
        }
        
        std::string jti = decoded.get_id();
        if (is_blacklisted(jti)) {
            return std::unexpected(ErrorCode::TOKEN_REVOKED);
        }
        
        RelayTokenClaims claims;
        claims.type = TokenType::RELAY;
        claims.node_id = static_cast<uint32_t>(decoded.get_payload_claim("node_id").as_integer());
        claims.network_id = static_cast<uint32_t>(decoded.get_payload_claim("network_id").as_integer());
        
        auto relays_claim = decoded.get_payload_claim("allowed_relays");
        auto relays_json = relays_claim.to_json();
        if (relays_json.is_array()) {
            for (const auto& r : relays_json) {
                if (r.is_number_integer()) {
                    claims.allowed_relays.push_back(static_cast<uint32_t>(r.get<int64_t>()));
                }
            }
        }
        
        claims.iat = decoded.get_issued_at().time_since_epoch().count() / 1000000000;
        claims.exp = decoded.get_expires_at().time_since_epoch().count() / 1000000000;
        claims.jti = jti;
        
        return claims;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_TOKEN);
    }
}

std::expected<ServerTokenClaims, ErrorCode> JWTManager::verify_server_token(const std::string& token) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        verifier_.verify(decoded);
        
        auto type = decoded.get_payload_claim("type").as_string();
        if (type != "server") {
            return std::unexpected(ErrorCode::INVALID_TOKEN);
        }
        
        std::string jti = decoded.get_id();
        if (is_blacklisted(jti)) {
            return std::unexpected(ErrorCode::TOKEN_REVOKED);
        }
        
        ServerTokenClaims claims;
        claims.type = TokenType::SERVER;
        claims.server_id = static_cast<uint32_t>(decoded.get_payload_claim("server_id").as_integer());
        claims.server_name = decoded.get_payload_claim("server_name").as_string();
        claims.capabilities = static_cast<uint8_t>(decoded.get_payload_claim("capabilities").as_integer());
        claims.region = decoded.get_payload_claim("region").as_string();
        claims.iat = decoded.get_issued_at().time_since_epoch().count() / 1000000000;
        claims.exp = decoded.get_expires_at().time_since_epoch().count() / 1000000000;
        claims.jti = jti;
        
        return claims;
    } catch (const jwt::error::token_verification_exception&) {
        return std::unexpected(ErrorCode::INVALID_TOKEN);
    } catch (const std::exception&) {
        return std::unexpected(ErrorCode::INVALID_TOKEN);
    }
}

void JWTManager::blacklist_token(const std::string& jti, int64_t expires_at) {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    blacklist_[jti] = expires_at;
}

bool JWTManager::is_blacklisted(const std::string& jti) const {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    return blacklist_.find(jti) != blacklist_.end();
}

void JWTManager::cleanup_blacklist() {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    int64_t current_time = now();
    
    for (auto it = blacklist_.begin(); it != blacklist_.end();) {
        if (it->second < current_time) {
            it = blacklist_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<std::pair<std::string, int64_t>> JWTManager::get_blacklist() const {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    std::vector<std::pair<std::string, int64_t>> result;
    result.reserve(blacklist_.size());
    
    for (const auto& [jti, exp] : blacklist_) {
        result.emplace_back(jti, exp);
    }
    
    return result;
}

void JWTManager::sync_blacklist(const std::vector<std::pair<std::string, int64_t>>& entries, 
                                 bool full_sync) {
    std::lock_guard<std::mutex> lock(blacklist_mutex_);
    
    if (full_sync) {
        blacklist_.clear();
    }
    
    for (const auto& [jti, exp] : entries) {
        blacklist_[jti] = exp;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string sha256_hash(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);
    
    std::ostringstream oss;
    oss << "sha256:";
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    
    return oss.str();
}

bool should_refresh_token(int64_t expires_at, std::chrono::minutes threshold) {
    auto now = std::chrono::system_clock::now();
    auto exp = std::chrono::system_clock::time_point{std::chrono::seconds{expires_at}};
    
    return (exp - now) < threshold;
}

} // namespace edgelink

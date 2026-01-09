#pragma once

#include "protocol.hpp"
#include <nlohmann/json.hpp>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <string>
#include <optional>
#include <expected>
#include <chrono>
#include <unordered_set>
#include <unordered_map>
#include <mutex>

namespace edgelink {

// NOTE: Do NOT import wire::ErrorCode here to avoid conflicts with proto types
// Use wire::ErrorCode directly in function signatures

// JSON traits for jwt-cpp (using nlohmann_json)
using json_traits = jwt::traits::nlohmann_json;
using json_claim = jwt::basic_claim<json_traits>;

// ============================================================================
// JWT Token Claims
// ============================================================================

// auth_token claims
struct AuthTokenClaims {
    TokenType type{TokenType::AUTH};
    uint32_t node_id{0};
    std::string machine_key_hash;   // SHA256 of machine_key_pub
    uint32_t network_id{0};
    std::string virtual_ip;
    int64_t iat{0};                 // Issued at
    int64_t exp{0};                 // Expires at
    std::string jti;                // Token ID
};

// relay_token claims
struct RelayTokenClaims {
    TokenType type{TokenType::RELAY};
    uint32_t node_id{0};
    uint32_t network_id{0};
    std::vector<uint32_t> allowed_relays;
    int64_t iat{0};
    int64_t exp{0};
    std::string jti;
};

// server_token claims
struct ServerTokenClaims {
    TokenType type{TokenType::SERVER};
    uint32_t server_id{0};
    std::string server_name;
    uint8_t capabilities{0};        // ServerCapability flags
    std::string region;
    int64_t iat{0};
    int64_t exp{0};
    std::string jti;
};

// ============================================================================
// JWT Manager
// ============================================================================
class JWTManager {
public:
    explicit JWTManager(std::string secret, std::string algorithm = "HS256");
    
    // ========================================================================
    // Token Generation
    // ========================================================================
    
    // Generate auth_token
    std::string create_auth_token(
        uint32_t node_id,
        const std::string& machine_key_hash,
        uint32_t network_id,
        const std::string& virtual_ip,
        std::chrono::hours expire_hours = std::chrono::hours{24}
    );
    
    // Generate relay_token
    std::string create_relay_token(
        uint32_t node_id,
        uint32_t network_id,
        const std::vector<uint32_t>& allowed_relays,
        std::chrono::minutes expire_minutes = std::chrono::minutes{90}
    );
    
    // Generate server_token
    std::string create_server_token(
        uint32_t server_id,
        const std::string& server_name,
        uint8_t capabilities,
        const std::string& region,
        std::chrono::hours expire_hours = std::chrono::hours{8760}  // 1 year
    );
    
    // ========================================================================
    // Token Verification
    // ========================================================================
    
    // Verify and decode auth_token
    std::expected<AuthTokenClaims, wire::ErrorCode> verify_auth_token(const std::string& token);

    // Verify and decode relay_token
    std::expected<RelayTokenClaims, wire::ErrorCode> verify_relay_token(const std::string& token);

    // Verify and decode server_token
    std::expected<ServerTokenClaims, wire::ErrorCode> verify_server_token(const std::string& token);
    
    // ========================================================================
    // Token Blacklist
    // ========================================================================
    
    // Add token to blacklist
    void blacklist_token(const std::string& jti, int64_t expires_at);
    
    // Check if token is blacklisted
    bool is_blacklisted(const std::string& jti) const;
    
    // Clean expired blacklist entries
    void cleanup_blacklist();
    
    // Get all blacklist entries (for sync)
    std::vector<std::pair<std::string, int64_t>> get_blacklist() const;
    
    // Sync blacklist (for relay servers)
    void sync_blacklist(const std::vector<std::pair<std::string, int64_t>>& entries, 
                        bool full_sync = false);
    
    // Get the secret key (for external verification)
    const std::string& secret() const { return secret_; }

private:
    std::string secret_;
    std::string algorithm_;
    jwt::verifier<jwt::default_clock, json_traits> verifier_;
    
    // Blacklist: jti -> expires_at
    mutable std::mutex blacklist_mutex_;
    std::unordered_map<std::string, int64_t> blacklist_;
    
    // Generate unique token ID
    static std::string generate_jti();
    
    // Get current timestamp
    static int64_t now();
};

// ============================================================================
// Utility Functions
// ============================================================================

// Compute SHA256 hash of a string (for machine_key_hash)
std::string sha256_hash(const std::string& input);

// Check if a token is about to expire (for refresh)
bool should_refresh_token(int64_t expires_at, std::chrono::minutes threshold);

// Simple JWT verification that returns claims as string map
// Used by relay server for quick token validation
std::unordered_map<std::string, std::string> verify_jwt(
    const std::string& secret,
    const std::string& token);

// Generate a generic JWT with custom claims
// Used by ws_server for simple token generation
std::string generate_jwt(
    const std::string& secret,
    const std::unordered_map<std::string, std::string>& claims,
    int expire_minutes);

} // namespace edgelink

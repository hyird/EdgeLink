#pragma once

#include "common/types.hpp"
#include <chrono>
#include <expected>
#include <optional>
#include <string>

namespace edgelink::controller {

// JWT error types
enum class JwtError {
    CREATION_FAILED,
    INVALID_TOKEN,
    EXPIRED,
    INVALID_CLAIMS,
    SIGNATURE_INVALID,
};

std::string jwt_error_message(JwtError error);

// Auth token claims
struct AuthTokenClaims {
    NodeId node_id = 0;
    NetworkId network_id = 0;
    std::string issuer;
    uint64_t issued_at = 0;    // Unix timestamp (seconds)
    uint64_t expires_at = 0;   // Unix timestamp (seconds)
};

// Relay token claims
struct RelayTokenClaims {
    NodeId node_id = 0;
    NetworkId network_id = 0;
    std::string issuer;
    uint64_t issued_at = 0;
    uint64_t expires_at = 0;
};

// JWT utility class
class JwtUtil {
public:
    // Initialize with secret key (use random bytes in production)
    explicit JwtUtil(const std::string& secret);

    // Create auth token (valid for 24 hours by default)
    std::expected<std::string, JwtError> create_auth_token(
        NodeId node_id, NetworkId network_id,
        std::chrono::seconds validity = std::chrono::hours(24));

    // Create relay token (valid for 90 minutes by default)
    std::expected<std::string, JwtError> create_relay_token(
        NodeId node_id, NetworkId network_id,
        std::chrono::seconds validity = std::chrono::minutes(90));

    // Verify and decode auth token
    std::expected<AuthTokenClaims, JwtError> verify_auth_token(const std::string& token);

    // Verify and decode relay token
    std::expected<RelayTokenClaims, JwtError> verify_relay_token(const std::string& token);

    // Get expiration timestamp from a token (without full verification)
    std::optional<uint64_t> get_token_expiry(const std::string& token);

    // Check if token is close to expiry (within threshold)
    bool is_token_expiring_soon(const std::string& token,
                                std::chrono::seconds threshold = std::chrono::minutes(15));

private:
    std::string secret_;
    static constexpr const char* ISSUER = "edgelink-controller";
    static constexpr const char* AUTH_TOKEN_TYPE = "auth";
    static constexpr const char* RELAY_TOKEN_TYPE = "relay";
};

} // namespace edgelink::controller

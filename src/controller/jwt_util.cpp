#include "controller/jwt_util.hpp"
#include "common/logger.hpp"
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.jwt"); }
}

// Use nlohmann_json traits for jwt-cpp
using json_traits = jwt::traits::nlohmann_json;
using json_claim = jwt::basic_claim<json_traits>;

std::string jwt_error_message(JwtError error) {
    switch (error) {
        case JwtError::CREATION_FAILED: return "Failed to create JWT";
        case JwtError::INVALID_TOKEN: return "Invalid JWT token";
        case JwtError::EXPIRED: return "JWT token expired";
        case JwtError::INVALID_CLAIMS: return "Invalid JWT claims";
        case JwtError::SIGNATURE_INVALID: return "Invalid JWT signature";
        default: return "Unknown JWT error";
    }
}

JwtUtil::JwtUtil(const std::string& secret) : secret_(secret) {}

std::expected<std::string, JwtError> JwtUtil::create_auth_token(
    NodeId node_id, NetworkId network_id, std::chrono::seconds validity) {

    try {
        auto now = std::chrono::system_clock::now();
        auto exp = now + validity;

        auto token = jwt::create<json_traits>()
            .set_issuer(ISSUER)
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_payload_claim("typ", json_claim(std::string(AUTH_TOKEN_TYPE)))
            .set_payload_claim("nid", json_claim(static_cast<int64_t>(node_id)))
            .set_payload_claim("net", json_claim(static_cast<int64_t>(network_id)))
            .sign(jwt::algorithm::hs256{secret_});

        return token;
    } catch (const std::exception& e) {
        log().error("Failed to create auth token: {}", e.what());
        return std::unexpected(JwtError::CREATION_FAILED);
    }
}

std::expected<std::string, JwtError> JwtUtil::create_relay_token(
    NodeId node_id, NetworkId network_id, std::chrono::seconds validity) {

    try {
        auto now = std::chrono::system_clock::now();
        auto exp = now + validity;

        auto token = jwt::create<json_traits>()
            .set_issuer(ISSUER)
            .set_type("JWT")
            .set_issued_at(now)
            .set_expires_at(exp)
            .set_payload_claim("typ", json_claim(std::string(RELAY_TOKEN_TYPE)))
            .set_payload_claim("nid", json_claim(static_cast<int64_t>(node_id)))
            .set_payload_claim("net", json_claim(static_cast<int64_t>(network_id)))
            .sign(jwt::algorithm::hs256{secret_});

        return token;
    } catch (const std::exception& e) {
        log().error("Failed to create relay token: {}", e.what());
        return std::unexpected(JwtError::CREATION_FAILED);
    }
}

std::expected<AuthTokenClaims, JwtError> JwtUtil::verify_auth_token(const std::string& token) {
    try {
        auto verifier = jwt::verify<json_traits>()
            .allow_algorithm(jwt::algorithm::hs256{secret_})
            .with_issuer(ISSUER);

        auto decoded = jwt::decode<json_traits>(token);
        verifier.verify(decoded);

        // Check token type
        auto typ = decoded.get_payload_claim("typ").as_string();
        if (typ != AUTH_TOKEN_TYPE) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        AuthTokenClaims claims;
        claims.node_id = static_cast<NodeId>(decoded.get_payload_claim("nid").as_integer());
        claims.network_id = static_cast<NetworkId>(decoded.get_payload_claim("net").as_integer());
        claims.issuer = decoded.get_issuer();

        auto iat = decoded.get_issued_at();
        auto exp = decoded.get_expires_at();
        claims.issued_at = std::chrono::duration_cast<std::chrono::seconds>(
            iat.time_since_epoch()).count();
        claims.expires_at = std::chrono::duration_cast<std::chrono::seconds>(
            exp.time_since_epoch()).count();

        return claims;
    } catch (const jwt::error::token_verification_exception& e) {
        log().debug("Auth token verification failed: {}", e.what());
        if (std::string(e.what()).find("expired") != std::string::npos) {
            return std::unexpected(JwtError::EXPIRED);
        }
        return std::unexpected(JwtError::SIGNATURE_INVALID);
    } catch (const std::exception& e) {
        log().debug("Auth token decode failed: {}", e.what());
        return std::unexpected(JwtError::INVALID_TOKEN);
    }
}

std::expected<RelayTokenClaims, JwtError> JwtUtil::verify_relay_token(const std::string& token) {
    try {
        auto verifier = jwt::verify<json_traits>()
            .allow_algorithm(jwt::algorithm::hs256{secret_})
            .with_issuer(ISSUER);

        auto decoded = jwt::decode<json_traits>(token);
        verifier.verify(decoded);

        // Check token type
        auto typ = decoded.get_payload_claim("typ").as_string();
        if (typ != RELAY_TOKEN_TYPE) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        RelayTokenClaims claims;
        claims.node_id = static_cast<NodeId>(decoded.get_payload_claim("nid").as_integer());
        claims.network_id = static_cast<NetworkId>(decoded.get_payload_claim("net").as_integer());
        claims.issuer = decoded.get_issuer();

        auto iat = decoded.get_issued_at();
        auto exp = decoded.get_expires_at();
        claims.issued_at = std::chrono::duration_cast<std::chrono::seconds>(
            iat.time_since_epoch()).count();
        claims.expires_at = std::chrono::duration_cast<std::chrono::seconds>(
            exp.time_since_epoch()).count();

        return claims;
    } catch (const jwt::error::token_verification_exception& e) {
        log().debug("Relay token verification failed: {}", e.what());
        if (std::string(e.what()).find("expired") != std::string::npos) {
            return std::unexpected(JwtError::EXPIRED);
        }
        return std::unexpected(JwtError::SIGNATURE_INVALID);
    } catch (const std::exception& e) {
        log().debug("Relay token decode failed: {}", e.what());
        return std::unexpected(JwtError::INVALID_TOKEN);
    }
}

std::optional<uint64_t> JwtUtil::get_token_expiry(const std::string& token) {
    try {
        auto decoded = jwt::decode<json_traits>(token);
        auto exp = decoded.get_expires_at();
        return std::chrono::duration_cast<std::chrono::seconds>(
            exp.time_since_epoch()).count();
    } catch (...) {
        return std::nullopt;
    }
}

bool JwtUtil::is_token_expiring_soon(const std::string& token, std::chrono::seconds threshold) {
    auto expiry = get_token_expiry(token);
    if (!expiry) return true; // Invalid token considered as expiring

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    return (*expiry - now) <= threshold.count();
}

} // namespace edgelink::controller

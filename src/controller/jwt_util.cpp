#include "controller/jwt_util.hpp"
#include "common/logger.hpp"
#include <boost/json.hpp>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <array>
#include <sstream>
#include <iomanip>

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.jwt"); }

// Base64URL encoding (RFC 4648)
std::string base64url_encode(const std::vector<uint8_t>& data) {
    static constexpr char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) val |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) val |= static_cast<uint32_t>(data[i + 2]);

        result.push_back(base64_chars[(val >> 18) & 0x3F]);
        result.push_back(base64_chars[(val >> 12) & 0x3F]);
        if (i + 1 < data.size()) result.push_back(base64_chars[(val >> 6) & 0x3F]);
        if (i + 2 < data.size()) result.push_back(base64_chars[val & 0x3F]);
    }

    // Base64URL: no padding
    return result;
}

std::string base64url_encode(const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return base64url_encode(data);
}

// Base64URL decoding
std::optional<std::vector<uint8_t>> base64url_decode(const std::string& encoded) {
    static constexpr int8_t decode_table[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    std::vector<uint8_t> result;
    result.reserve((encoded.size() * 3) / 4);

    std::string padded = encoded;
    // Add padding if needed for decoding
    while (padded.size() % 4 != 0) {
        padded += 'A'; // Padding character (will be ignored)
    }

    for (size_t i = 0; i < padded.size(); i += 4) {
        int8_t b1 = decode_table[static_cast<uint8_t>(padded[i])];
        int8_t b2 = decode_table[static_cast<uint8_t>(padded[i + 1])];
        int8_t b3 = i + 2 < padded.size() ? decode_table[static_cast<uint8_t>(padded[i + 2])] : 0;
        int8_t b4 = i + 3 < padded.size() ? decode_table[static_cast<uint8_t>(padded[i + 3])] : 0;

        if (b1 < 0 || b2 < 0) return std::nullopt;

        uint32_t val = (static_cast<uint32_t>(b1) << 18) |
                       (static_cast<uint32_t>(b2) << 12) |
                       (b3 >= 0 ? static_cast<uint32_t>(b3) << 6 : 0) |
                       (b4 >= 0 ? static_cast<uint32_t>(b4) : 0);

        result.push_back((val >> 16) & 0xFF);
        if (b3 >= 0 && i + 2 < encoded.size()) result.push_back((val >> 8) & 0xFF);
        if (b4 >= 0 && i + 3 < encoded.size()) result.push_back(val & 0xFF);
    }

    // Remove padding bytes
    size_t actual_size = (encoded.size() * 3) / 4;
    if (encoded.size() % 4 == 2) actual_size -= 2;
    else if (encoded.size() % 4 == 3) actual_size -= 1;
    result.resize(actual_size);

    return result;
}

// HMAC-SHA256 signature
std::vector<uint8_t> hmac_sha256(const std::string& data, const std::string& key) {
    std::array<uint8_t, EVP_MAX_MD_SIZE> hash;
    unsigned int hash_len = 0;

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const uint8_t*>(data.data()), data.size(),
         hash.data(), &hash_len);

    return std::vector<uint8_t>(hash.begin(), hash.begin() + hash_len);
}

} // anonymous namespace

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
        auto iat = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        auto exp = iat + validity.count();

        // Header
        boost::json::object header;
        header["alg"] = "HS256";
        header["typ"] = "JWT";
        std::string header_json = boost::json::serialize(header);
        std::string header_b64 = base64url_encode(header_json);

        // Payload
        boost::json::object payload;
        payload["iss"] = ISSUER;
        payload["iat"] = iat;
        payload["exp"] = exp;
        payload["typ"] = AUTH_TOKEN_TYPE;
        payload["nid"] = static_cast<int64_t>(node_id);
        payload["net"] = static_cast<int64_t>(network_id);
        std::string payload_json = boost::json::serialize(payload);
        std::string payload_b64 = base64url_encode(payload_json);

        // Signature
        std::string signing_input = header_b64 + "." + payload_b64;
        auto signature = hmac_sha256(signing_input, secret_);
        std::string signature_b64 = base64url_encode(signature);

        return header_b64 + "." + payload_b64 + "." + signature_b64;

    } catch (const std::exception& e) {
        log().error("Failed to create auth token: {}", e.what());
        return std::unexpected(JwtError::CREATION_FAILED);
    }
}

std::expected<std::string, JwtError> JwtUtil::create_relay_token(
    NodeId node_id, NetworkId network_id, std::chrono::seconds validity) {

    try {
        auto now = std::chrono::system_clock::now();
        auto iat = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        auto exp = iat + validity.count();

        // Header
        boost::json::object header;
        header["alg"] = "HS256";
        header["typ"] = "JWT";
        std::string header_json = boost::json::serialize(header);
        std::string header_b64 = base64url_encode(header_json);

        // Payload
        boost::json::object payload;
        payload["iss"] = ISSUER;
        payload["iat"] = iat;
        payload["exp"] = exp;
        payload["typ"] = RELAY_TOKEN_TYPE;
        payload["nid"] = static_cast<int64_t>(node_id);
        payload["net"] = static_cast<int64_t>(network_id);
        std::string payload_json = boost::json::serialize(payload);
        std::string payload_b64 = base64url_encode(payload_json);

        // Signature
        std::string signing_input = header_b64 + "." + payload_b64;
        auto signature = hmac_sha256(signing_input, secret_);
        std::string signature_b64 = base64url_encode(signature);

        return header_b64 + "." + payload_b64 + "." + signature_b64;

    } catch (const std::exception& e) {
        log().error("Failed to create relay token: {}", e.what());
        return std::unexpected(JwtError::CREATION_FAILED);
    }
}

std::expected<AuthTokenClaims, JwtError> JwtUtil::verify_auth_token(const std::string& token) {
    try {
        // Split token into parts
        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);

        if (first_dot == std::string::npos || second_dot == std::string::npos) {
            return std::unexpected(JwtError::INVALID_TOKEN);
        }

        std::string header_b64 = token.substr(0, first_dot);
        std::string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
        std::string signature_b64 = token.substr(second_dot + 1);

        // Verify signature
        std::string signing_input = header_b64 + "." + payload_b64;
        auto expected_signature = hmac_sha256(signing_input, secret_);
        auto provided_signature = base64url_decode(signature_b64);

        if (!provided_signature || *provided_signature != expected_signature) {
            return std::unexpected(JwtError::SIGNATURE_INVALID);
        }

        // Decode payload
        auto payload_bytes = base64url_decode(payload_b64);
        if (!payload_bytes) {
            return std::unexpected(JwtError::INVALID_TOKEN);
        }

        std::string payload_json(payload_bytes->begin(), payload_bytes->end());
        auto payload = boost::json::parse(payload_json).as_object();

        // Check issuer
        if (!payload.contains("iss") || payload["iss"].as_string() != ISSUER) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        // Check token type
        if (!payload.contains("typ") || payload["typ"].as_string() != AUTH_TOKEN_TYPE) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        // Check expiration
        if (!payload.contains("exp")) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        auto exp = payload["exp"].as_int64();
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (now >= exp) {
            return std::unexpected(JwtError::EXPIRED);
        }

        // Extract claims
        AuthTokenClaims claims;
        claims.node_id = static_cast<NodeId>(payload["nid"].as_int64());
        claims.network_id = static_cast<NetworkId>(payload["net"].as_int64());
        claims.issuer = std::string(payload["iss"].as_string());
        claims.issued_at = static_cast<uint64_t>(payload["iat"].as_int64());
        claims.expires_at = static_cast<uint64_t>(exp);

        return claims;

    } catch (const std::exception& e) {
        log().debug("Auth token verification failed: {}", e.what());
        return std::unexpected(JwtError::INVALID_TOKEN);
    }
}

std::expected<RelayTokenClaims, JwtError> JwtUtil::verify_relay_token(const std::string& token) {
    try {
        // Split token into parts
        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);

        if (first_dot == std::string::npos || second_dot == std::string::npos) {
            return std::unexpected(JwtError::INVALID_TOKEN);
        }

        std::string header_b64 = token.substr(0, first_dot);
        std::string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
        std::string signature_b64 = token.substr(second_dot + 1);

        // Verify signature
        std::string signing_input = header_b64 + "." + payload_b64;
        auto expected_signature = hmac_sha256(signing_input, secret_);
        auto provided_signature = base64url_decode(signature_b64);

        if (!provided_signature || *provided_signature != expected_signature) {
            return std::unexpected(JwtError::SIGNATURE_INVALID);
        }

        // Decode payload
        auto payload_bytes = base64url_decode(payload_b64);
        if (!payload_bytes) {
            return std::unexpected(JwtError::INVALID_TOKEN);
        }

        std::string payload_json(payload_bytes->begin(), payload_bytes->end());
        auto payload = boost::json::parse(payload_json).as_object();

        // Check issuer
        if (!payload.contains("iss") || payload["iss"].as_string() != ISSUER) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        // Check token type
        if (!payload.contains("typ") || payload["typ"].as_string() != RELAY_TOKEN_TYPE) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        // Check expiration
        if (!payload.contains("exp")) {
            return std::unexpected(JwtError::INVALID_CLAIMS);
        }

        auto exp = payload["exp"].as_int64();
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (now >= exp) {
            return std::unexpected(JwtError::EXPIRED);
        }

        // Extract claims
        RelayTokenClaims claims;
        claims.node_id = static_cast<NodeId>(payload["nid"].as_int64());
        claims.network_id = static_cast<NetworkId>(payload["net"].as_int64());
        claims.issuer = std::string(payload["iss"].as_string());
        claims.issued_at = static_cast<uint64_t>(payload["iat"].as_int64());
        claims.expires_at = static_cast<uint64_t>(exp);

        return claims;

    } catch (const std::exception& e) {
        log().debug("Relay token verification failed: {}", e.what());
        return std::unexpected(JwtError::INVALID_TOKEN);
    }
}

std::optional<uint64_t> JwtUtil::get_token_expiry(const std::string& token) {
    try {
        // Split token
        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);

        if (first_dot == std::string::npos || second_dot == std::string::npos) {
            return std::nullopt;
        }

        std::string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);

        // Decode payload (skip signature verification for this quick check)
        auto payload_bytes = base64url_decode(payload_b64);
        if (!payload_bytes) {
            return std::nullopt;
        }

        std::string payload_json(payload_bytes->begin(), payload_bytes->end());
        auto payload = boost::json::parse(payload_json).as_object();

        if (!payload.contains("exp")) {
            return std::nullopt;
        }

        return static_cast<uint64_t>(payload["exp"].as_int64());

    } catch (...) {
        return std::nullopt;
    }
}

bool JwtUtil::is_token_expiring_soon(const std::string& token, std::chrono::seconds threshold) {
    auto expiry = get_token_expiry(token);
    if (!expiry) return true; // Invalid token considered as expiring

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    return (*expiry - now) <= static_cast<uint64_t>(threshold.count());
}

} // namespace edgelink::controller

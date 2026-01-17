#pragma once

// Auth Protobuf Helpers
//
// This file provides auth-related helper functions that require full protobuf
// type definitions. It must be included AFTER edgelink.pb.h.
//
// Note: This is separate from proto_convert.hpp because proto_convert.hpp
// uses forward declarations for protobuf types, which is insufficient for
// these helper functions that need to access protobuf message fields.

// Disable GCC warning for protobuf's concept usage
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-requires"
#endif

#include "edgelink.pb.h"

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#include "common/types.hpp"
#include <vector>
#include <cstdint>

namespace edgelink {

// ============================================================================
// AuthType Conversion
// ============================================================================

inline pb::AuthType to_proto_auth_type(AuthType type) {
    switch (type) {
        case AuthType::USER:
            return pb::AUTH_TYPE_USER;
        case AuthType::AUTHKEY:
            return pb::AUTH_TYPE_AUTHKEY;
        case AuthType::MACHINE:
            return pb::AUTH_TYPE_MACHINE;
        default:
            return pb::AUTH_TYPE_UNKNOWN;
    }
}

inline AuthType from_proto_auth_type(pb::AuthType type) {
    switch (type) {
        case pb::AUTH_TYPE_USER:
            return AuthType::USER;
        case pb::AUTH_TYPE_AUTHKEY:
            return AuthType::AUTHKEY;
        case pb::AUTH_TYPE_MACHINE:
            return AuthType::MACHINE;
        default:
            return AuthType::USER;
    }
}

// ============================================================================
// Auth Sign Data (for signature verification)
// ============================================================================

/// Get data to be signed for AuthRequest (protobuf version)
/// This creates a canonical byte representation of the auth request fields
/// that is used for ED25519 signature generation/verification.
inline std::vector<uint8_t> get_auth_sign_data(const pb::AuthRequest& req) {
    std::vector<uint8_t> data;

    // Auth type (1 byte)
    data.push_back(static_cast<uint8_t>(req.auth_type()));

    // Machine key (32 bytes)
    const auto& mk = req.machine_key();
    data.insert(data.end(), mk.begin(), mk.end());

    // Node key (32 bytes)
    const auto& nk = req.node_key();
    data.insert(data.end(), nk.begin(), nk.end());

    // Auth data (variable length, prefixed with size)
    const auto& ak = req.auth_data();
    uint32_t ak_size = static_cast<uint32_t>(ak.size());
    data.push_back(static_cast<uint8_t>(ak_size & 0xFF));
    data.push_back(static_cast<uint8_t>((ak_size >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((ak_size >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((ak_size >> 24) & 0xFF));
    data.insert(data.end(), ak.begin(), ak.end());

    // Timestamp (8 bytes, little-endian)
    uint64_t ts = req.timestamp();
    for (int i = 0; i < 8; ++i) {
        data.push_back(static_cast<uint8_t>((ts >> (i * 8)) & 0xFF));
    }

    // Hostname (variable length, prefixed with size)
    const auto& hostname = req.hostname();
    uint32_t hostname_size = static_cast<uint32_t>(hostname.size());
    data.push_back(static_cast<uint8_t>(hostname_size & 0xFF));
    data.push_back(static_cast<uint8_t>((hostname_size >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((hostname_size >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((hostname_size >> 24) & 0xFF));
    data.insert(data.end(), hostname.begin(), hostname.end());

    // OS (variable length, prefixed with size)
    const auto& os = req.os();
    uint32_t os_size = static_cast<uint32_t>(os.size());
    data.push_back(static_cast<uint8_t>(os_size & 0xFF));
    data.push_back(static_cast<uint8_t>((os_size >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>((os_size >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((os_size >> 24) & 0xFF));
    data.insert(data.end(), os.begin(), os.end());

    return data;
}

} // namespace edgelink

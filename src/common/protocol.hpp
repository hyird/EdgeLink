#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <variant>

namespace edgelink {

// ============================================================================
// Protocol Version
// ============================================================================
constexpr uint8_t PROTOCOL_VERSION = 0x01;

// ============================================================================
// Message Types (8.2 from design doc)
// ============================================================================
enum class MessageType : uint8_t {
    // Authentication
    AUTH_REQUEST     = 0x01,
    AUTH_RESPONSE    = 0x02,
    
    // Configuration
    CONFIG           = 0x03,
    CONFIG_UPDATE    = 0x04,
    
    // Control messages
    CONTROL          = 0x05,
    
    // Data
    DATA             = 0x10,
    
    // Heartbeat
    PING             = 0x20,
    PONG             = 0x21,
    LATENCY_REPORT   = 0x22,
    
    // P2P
    P2P_INIT         = 0x30,
    P2P_ENDPOINT     = 0x31,
    P2P_PING         = 0x32,
    P2P_PONG         = 0x33,
    P2P_KEEPALIVE    = 0x34,
    P2P_STATUS       = 0x35,
    
    // Server (Relay/STUN)
    SERVER_REGISTER      = 0x40,
    SERVER_REGISTER_RESP = 0x41,
    SERVER_NODE_LOC      = 0x42,
    SERVER_BLACKLIST     = 0x43,
    SERVER_HEARTBEAT     = 0x44,
    SERVER_LATENCY       = 0x45,
    SERVER_RELAY_LIST    = 0x46,  // Controller -> Relay: list of other relays for mesh
    SERVER_LATENCY_REPORT = 0x47, // Relay -> Controller: mesh latency report
    
    // Relay specific
    RELAY_AUTH           = 0x50,
    RELAY_AUTH_RESP      = 0x51,
    
    // Mesh (Relay-to-Relay)
    MESH_HELLO           = 0x60,
    MESH_HELLO_ACK       = 0x61,
    MESH_FORWARD         = 0x62,
    MESH_PING            = 0x63,
    MESH_PONG            = 0x64,
    
    // Error
    ERROR_MSG            = 0xFF
};

// Alias for client code compatibility
using FrameType = MessageType;

constexpr std::string_view message_type_to_string(MessageType type) {
    switch (type) {
        case MessageType::AUTH_REQUEST:        return "AUTH_REQUEST";
        case MessageType::AUTH_RESPONSE:       return "AUTH_RESPONSE";
        case MessageType::CONFIG:              return "CONFIG";
        case MessageType::CONFIG_UPDATE:       return "CONFIG_UPDATE";
        case MessageType::CONTROL:             return "CONTROL";
        case MessageType::DATA:                return "DATA";
        case MessageType::PING:                return "PING";
        case MessageType::PONG:                return "PONG";
        case MessageType::LATENCY_REPORT:      return "LATENCY_REPORT";
        case MessageType::P2P_INIT:            return "P2P_INIT";
        case MessageType::P2P_ENDPOINT:        return "P2P_ENDPOINT";
        case MessageType::P2P_PING:            return "P2P_PING";
        case MessageType::P2P_PONG:            return "P2P_PONG";
        case MessageType::P2P_KEEPALIVE:       return "P2P_KEEPALIVE";
        case MessageType::P2P_STATUS:          return "P2P_STATUS";
        case MessageType::SERVER_REGISTER:     return "SERVER_REGISTER";
        case MessageType::SERVER_REGISTER_RESP:return "SERVER_REGISTER_RESP";
        case MessageType::SERVER_NODE_LOC:     return "SERVER_NODE_LOC";
        case MessageType::SERVER_BLACKLIST:    return "SERVER_BLACKLIST";
        case MessageType::SERVER_HEARTBEAT:    return "SERVER_HEARTBEAT";
        case MessageType::SERVER_LATENCY:      return "SERVER_LATENCY";
        case MessageType::SERVER_RELAY_LIST:   return "SERVER_RELAY_LIST";
        case MessageType::SERVER_LATENCY_REPORT: return "SERVER_LATENCY_REPORT";
        case MessageType::RELAY_AUTH:          return "RELAY_AUTH";
        case MessageType::RELAY_AUTH_RESP:     return "RELAY_AUTH_RESP";
        case MessageType::MESH_HELLO:          return "MESH_HELLO";
        case MessageType::MESH_HELLO_ACK:      return "MESH_HELLO_ACK";
        case MessageType::MESH_FORWARD:        return "MESH_FORWARD";
        case MessageType::MESH_PING:           return "MESH_PING";
        case MessageType::MESH_PONG:           return "MESH_PONG";
        case MessageType::ERROR_MSG:           return "ERROR_MSG";
        default:                               return "UNKNOWN";
    }
}

// ============================================================================
// Frame Flags
// ============================================================================
namespace FrameFlags {
    constexpr uint8_t NONE       = 0x00;
    constexpr uint8_t NEED_ACK   = 0x01;  // Bit 0: requires acknowledgment
    constexpr uint8_t COMPRESSED = 0x02;  // Bit 1: payload is compressed
}

// ============================================================================
// Error Codes (8.4 from design doc)
// ============================================================================
enum class ErrorCode : uint16_t {
    // General errors (0xxx)
    SUCCESS               = 0,
    INVALID_ARGUMENT      = 1,
    SYSTEM_ERROR          = 2,
    NOT_CONNECTED         = 3,
    DISCONNECTED          = 4,
    TIMEOUT               = 5,
    
    // Authentication errors (1xxx)
    INVALID_TOKEN         = 1001,
    TOKEN_EXPIRED         = 1002,
    TOKEN_REVOKED         = 1003,
    INVALID_MACHINE_KEY   = 1004,
    SIGNATURE_FAILED      = 1005,
    NODE_UNAUTHORIZED     = 1006,
    AUTH_FAILED           = 1007,
    NOT_AUTHORIZED        = 1008,
    MAX_RETRIES_EXCEEDED  = 1009,
    
    // Protocol errors (2xxx)
    UNSUPPORTED_VERSION   = 2001,
    INVALID_MESSAGE       = 2002,
    MESSAGE_TOO_LARGE     = 2003,
    INVALID_FRAME         = 2004,
    
    // Routing errors (3xxx)
    NODE_NOT_FOUND        = 3001,
    NODE_OFFLINE          = 3002,
    NO_ROUTE              = 3003,
    PEER_NOT_FOUND        = 3004,
    NO_RELAY_AVAILABLE    = 3005,
    
    // Server errors (4xxx)
    INTERNAL_ERROR        = 4001,
    SERVICE_UNAVAILABLE   = 4002,
    OVERLOADED            = 4003,
    
    // Crypto errors (5xxx)
    CRYPTO_ERROR          = 5001,
    REPLAY_DETECTED       = 5002,
    KEY_EXCHANGE_FAILED   = 5003,
    INVALID_KEY           = 5004   // Invalid or weak cryptographic key
};

constexpr std::string_view error_code_to_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS:             return "Success";
        case ErrorCode::INVALID_ARGUMENT:    return "Invalid argument";
        case ErrorCode::SYSTEM_ERROR:        return "System error";
        case ErrorCode::NOT_CONNECTED:       return "Not connected";
        case ErrorCode::DISCONNECTED:        return "Disconnected";
        case ErrorCode::TIMEOUT:             return "Timeout";
        case ErrorCode::INVALID_TOKEN:       return "Invalid token";
        case ErrorCode::TOKEN_EXPIRED:       return "Token expired";
        case ErrorCode::TOKEN_REVOKED:       return "Token revoked";
        case ErrorCode::INVALID_MACHINE_KEY: return "Invalid machine key";
        case ErrorCode::SIGNATURE_FAILED:    return "Signature verification failed";
        case ErrorCode::NODE_UNAUTHORIZED:   return "Node not authorized";
        case ErrorCode::AUTH_FAILED:         return "Authentication failed";
        case ErrorCode::NOT_AUTHORIZED:      return "Not authorized";
        case ErrorCode::MAX_RETRIES_EXCEEDED:return "Max retries exceeded";
        case ErrorCode::UNSUPPORTED_VERSION: return "Unsupported protocol version";
        case ErrorCode::INVALID_MESSAGE:     return "Invalid message format";
        case ErrorCode::MESSAGE_TOO_LARGE:   return "Message too large";
        case ErrorCode::INVALID_FRAME:       return "Invalid frame";
        case ErrorCode::NODE_NOT_FOUND:      return "Target node not found";
        case ErrorCode::NODE_OFFLINE:        return "Target node offline";
        case ErrorCode::NO_ROUTE:            return "No route available";
        case ErrorCode::PEER_NOT_FOUND:      return "Peer not found";
        case ErrorCode::NO_RELAY_AVAILABLE:  return "No relay available";
        case ErrorCode::INTERNAL_ERROR:      return "Internal server error";
        case ErrorCode::SERVICE_UNAVAILABLE: return "Service unavailable";
        case ErrorCode::OVERLOADED:          return "Server overloaded";
        case ErrorCode::CRYPTO_ERROR:        return "Cryptographic error";
        case ErrorCode::REPLAY_DETECTED:     return "Replay attack detected";
        case ErrorCode::KEY_EXCHANGE_FAILED: return "Key exchange failed";
        case ErrorCode::INVALID_KEY:         return "Invalid or weak cryptographic key";
        default:                             return "Unknown error";
    }
}

// ============================================================================
// Network Constants
// ============================================================================
namespace NetworkConstants {
    constexpr size_t MAX_FRAME_SIZE = 65535;
    constexpr size_t HEADER_SIZE = 5;  // Version(1) + Type(1) + Flags(1) + Length(2)
    constexpr size_t MAX_PAYLOAD_SIZE = MAX_FRAME_SIZE - HEADER_SIZE;
    constexpr size_t MAX_PACKET_SIZE = 65536;  // TUN packet buffer size
    
    constexpr size_t DATA_HEADER_SIZE = 20;  // Src(4) + Dst(4) + Nonce(12)
    constexpr size_t AUTH_TAG_SIZE = 16;     // ChaCha20-Poly1305 tag
    
    constexpr uint16_t DEFAULT_TUN_MTU = 1400;
    constexpr uint16_t DEFAULT_STUN_PORT = 3478;
    constexpr uint16_t DEFAULT_WSS_PORT = 443;
    
    constexpr uint32_t DEFAULT_KEEPALIVE_INTERVAL_SEC = 25;
    constexpr uint32_t DEFAULT_LATENCY_REPORT_INTERVAL_SEC = 30;
    constexpr uint32_t DEFAULT_P2P_PUNCH_TIMEOUT_SEC = 5;
    constexpr uint32_t DEFAULT_P2P_PUNCH_RETRIES = 3;
    constexpr uint32_t DEFAULT_HEARTBEAT_INTERVAL = 30;  // seconds
    constexpr uint32_t DEFAULT_RECONNECT_INTERVAL = 5;   // seconds
    constexpr uint32_t MAX_RECONNECT_INTERVAL = 300;     // 5 minutes max
}

// ============================================================================
// Crypto Constants
// ============================================================================
namespace CryptoConstants {
    constexpr size_t X25519_KEY_SIZE = 32;
    constexpr size_t ED25519_PUB_SIZE = 32;
    constexpr size_t ED25519_SEC_SIZE = 64;
    constexpr size_t ED25519_SIG_SIZE = 64;
    constexpr size_t CHACHA20_KEY_SIZE = 32;
    constexpr size_t CHACHA20_NONCE_SIZE = 12;
    constexpr size_t POLY1305_TAG_SIZE = 16;
    constexpr size_t SESSION_KEY_SIZE = 32;
    
    // Nonce: 4 bytes random + 8 bytes counter
    constexpr size_t NONCE_RANDOM_SIZE = 4;
    constexpr size_t NONCE_COUNTER_SIZE = 8;
    
    // Replay protection sliding window
    constexpr size_t REPLAY_WINDOW_SIZE = 2048;
}

// ============================================================================
// Key Types
// ============================================================================
using X25519PublicKey = std::array<uint8_t, CryptoConstants::X25519_KEY_SIZE>;
using X25519PrivateKey = std::array<uint8_t, CryptoConstants::X25519_KEY_SIZE>;
using Ed25519PublicKey = std::array<uint8_t, CryptoConstants::ED25519_PUB_SIZE>;
using Ed25519PrivateKey = std::array<uint8_t, CryptoConstants::ED25519_SEC_SIZE>;
using SessionKey = std::array<uint8_t, CryptoConstants::SESSION_KEY_SIZE>;
using Nonce = std::array<uint8_t, CryptoConstants::CHACHA20_NONCE_SIZE>;
using AuthTag = std::array<uint8_t, CryptoConstants::POLY1305_TAG_SIZE>;

// ============================================================================
// Endpoint Types (for P2P)
// ============================================================================
enum class EndpointType : uint8_t {
    LAN   = 1,  // Local network address (highest priority)
    STUN  = 2,  // STUN detected address
    UPNP  = 2,  // UPnP/NAT-PMP mapped address (same priority as STUN)
    RELAY = 3   // Relay observed address (lowest priority)
};

struct Endpoint {
    EndpointType type;
    std::string ip;
    uint16_t port;
    uint8_t priority;  // Lower is better
    
    bool operator<(const Endpoint& other) const {
        return priority < other.priority;
    }
};

// ============================================================================
// NAT Types
// ============================================================================
enum class NATType : uint8_t {
    UNKNOWN             = 0,
    OPEN                = 1,  // No NAT
    FULL_CONE           = 2,  // Easy to punch
    RESTRICTED_CONE     = 3,  // Possible to punch
    PORT_RESTRICTED     = 4,  // Harder to punch
    SYMMETRIC           = 5   // Very hard to punch
};

constexpr std::string_view nat_type_to_string(NATType type) {
    switch (type) {
        case NATType::OPEN:             return "Open";
        case NATType::FULL_CONE:        return "Full Cone";
        case NATType::RESTRICTED_CONE:  return "Restricted Cone";
        case NATType::PORT_RESTRICTED:  return "Port Restricted";
        case NATType::SYMMETRIC:        return "Symmetric";
        default:                        return "Unknown";
    }
}

// ============================================================================
// Server Capabilities
// ============================================================================
namespace ServerCapability {
    constexpr uint8_t RELAY = 0x01;
    constexpr uint8_t STUN  = 0x02;
}

// ============================================================================
// Token Types
// ============================================================================
enum class TokenType : uint8_t {
    AUTH   = 1,  // auth_token for node authentication
    RELAY  = 2,  // relay_token for relay connection
    SERVER = 3   // server_token for relay/stun server
};

} // namespace edgelink

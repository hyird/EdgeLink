#pragma once

#include "protocol.hpp"
#include <boost/json.hpp>
#include <span>
#include <expected>

namespace edgelink {

// All frame/payload types are in the wire:: namespace to avoid conflicts with
// proto-generated types in the edgelink:: namespace
namespace wire {

// ============================================================================
// Frame Header (5 bytes)
// ============================================================================
// ┌──────────┬──────────┬──────────┬──────────────────────────────────────────┐
// │ Version  │  Type    │  Flags   │  Length                                  │
// │  (1B)    │  (1B)    │  (1B)    │  (2B, Big Endian)                        │
// └──────────┴──────────┴──────────┴──────────────────────────────────────────┘
struct FrameHeader {
    uint8_t version{PROTOCOL_VERSION};
    MessageType type{MessageType::ERROR_MSG};
    uint8_t flags{FrameFlags::NONE};
    uint16_t length{0};
    
    // Serialize to bytes
    void serialize(std::span<uint8_t, NetworkConstants::HEADER_SIZE> out) const;
    
    // Deserialize from bytes
    static std::expected<FrameHeader, ErrorCode> deserialize(
        std::span<const uint8_t, NetworkConstants::HEADER_SIZE> in);
    
    bool need_ack() const { return flags & FrameFlags::NEED_ACK; }
    bool is_compressed() const { return flags & FrameFlags::COMPRESSED; }
};

// ============================================================================
// Complete Frame
// ============================================================================
struct Frame {
    FrameHeader header;
    std::vector<uint8_t> payload;
    
    // Extended fields for relay routing (used by client/relay)
    uint32_t src_id{0};
    uint32_t dst_id{0};
    uint32_t relay_id{0};
    
    // Convenience accessor for type
    MessageType type{MessageType::ERROR_MSG};
    
    // Create a frame with the given type and payload
    static Frame create(MessageType type, std::vector<uint8_t> payload, 
                        uint8_t flags = FrameFlags::NONE);
    
    // Serialize complete frame
    std::vector<uint8_t> serialize() const;
    
    // Deserialize complete frame
    static std::expected<Frame, ErrorCode> deserialize(std::span<const uint8_t> data);
    
    // Parse frame from data (returns true on success)
    bool parse(std::span<const uint8_t> data) {
        auto result = deserialize(data);
        if (result) {
            *this = std::move(*result);
            return true;
        }
        return false;
    }
    
    // Helper to check if we have enough data for a complete frame
    static std::optional<size_t> get_frame_size(std::span<const uint8_t> data);
    
    // Convenience accessors
    uint8_t version() const { return header.version; }
    uint8_t flags() const { return header.flags; }
    
    // JSON payload helpers
    boost::json::value payload_json() const;
    void set_payload_json(const boost::json::value& json);
};

// ============================================================================
// DATA Payload Format
// ============================================================================
// ┌──────────┬──────────┬──────────┬──────────────────────────────┬───────┐
// │ Src Node │ Dst Node │  Nonce   │ Encrypted Payload            │ Tag   │
// │   (4B)   │   (4B)   │  (12B)   │ (Variable)                   │ (16B) │
// └──────────┴──────────┴──────────┴──────────────────────────────┴───────┘
struct DataPayload {
    uint32_t src_node_id{0};
    uint32_t dst_node_id{0};
    Nonce nonce{};
    std::vector<uint8_t> encrypted_data;  // Includes auth tag at the end
    
    std::vector<uint8_t> serialize() const;
    static std::expected<DataPayload, ErrorCode> deserialize(std::span<const uint8_t> data);
    
    // JSON serialization for relay forwarding
    boost::json::object to_json() const;
    bool from_json(const boost::json::value& v);
};

// ============================================================================
// AUTH_REQUEST Payload
// ============================================================================
struct AuthRequestPayload {
    std::string machine_key_pub;        // Base64 encoded Ed25519 public key
    std::string node_key_pub;           // Base64 encoded X25519 public key
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;
    std::string signature;              // Ed25519 signature of the request
    uint64_t timestamp;
    
    boost::json::object to_json() const;
    static std::expected<AuthRequestPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// AUTH_RESPONSE Payload
// ============================================================================
struct AuthResponsePayload {
    bool success{false};
    uint32_t node_id{0};
    std::string virtual_ip;
    std::string auth_token;             // JWT auth token
    std::string relay_token;            // JWT relay token
    std::string error_message;
    
    boost::json::object to_json() const;
    static std::expected<AuthResponsePayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// CONFIG Payload (complete network configuration)
// ============================================================================
struct RelayInfo {
    uint32_t server_id;
    std::string name;
    std::string url;                    // WSS URL
    std::string region;
    
    boost::json::object to_json() const;
    static std::expected<RelayInfo, ErrorCode> from_json(const boost::json::value& v);
};

struct STUNInfo {
    uint32_t server_id;
    std::string name;
    std::string ip;
    uint16_t port;
    std::string secondary_ip;           // For full NAT detection
    
    boost::json::object to_json() const;
    static std::expected<STUNInfo, ErrorCode> from_json(const boost::json::value& v);
};

struct PeerInfo {
    uint32_t node_id;
    std::string name;
    std::string virtual_ip;
    std::string node_key_pub;           // Base64 encoded X25519 public key
    bool online{false};
    std::vector<Endpoint> endpoints;

    boost::json::object to_json() const;
    static std::expected<PeerInfo, ErrorCode> from_json(const boost::json::value& v);
};

struct RouteInfo {
    std::string cidr;
    uint32_t gateway_node_id;
    uint16_t priority;
    uint16_t weight;
    bool enabled{true};
    
    boost::json::object to_json() const;
    static std::expected<RouteInfo, ErrorCode> from_json(const boost::json::value& v);
};

struct ConfigPayload {
    uint64_t version{0};                // Config version for incremental updates
    uint32_t network_id{0};
    std::string network_name;
    std::string subnet;
    
    std::vector<RelayInfo> relays;
    std::vector<STUNInfo> stun_servers;
    std::vector<PeerInfo> peers;
    std::vector<RouteInfo> routes;
    
    // Token refresh info
    std::string new_relay_token;
    int64_t relay_token_expires_at{0};
    
    boost::json::object to_json() const;
    static std::expected<ConfigPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// CONFIG_UPDATE Payload (incremental update)
// ============================================================================
enum class UpdateAction : uint8_t {
    ADD    = 1,
    UPDATE = 2,
    REMOVE = 3
};

struct ConfigUpdatePayload {
    uint64_t version{0};
    
    // Peer updates
    struct PeerUpdate {
        UpdateAction action;
        PeerInfo peer;
    };
    std::vector<PeerUpdate> peer_updates;
    
    // Route updates
    struct RouteUpdate {
        UpdateAction action;
        RouteInfo route;
    };
    std::vector<RouteUpdate> route_updates;
    
    // Server updates
    struct ServerUpdate {
        UpdateAction action;
        std::variant<RelayInfo, STUNInfo> server;
    };
    std::vector<ServerUpdate> server_updates;
    
    // Token refresh
    std::optional<std::string> new_relay_token;
    std::optional<int64_t> relay_token_expires_at;
    
    boost::json::object to_json() const;
    static std::expected<ConfigUpdatePayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// LATENCY_REPORT Payload
// ============================================================================
struct LatencyReportPayload {
    struct LatencyEntry {
        std::string dst_type;   // "relay" or "node"
        uint32_t dst_id;
        uint32_t rtt_ms;
    };
    std::vector<LatencyEntry> entries;
    
    boost::json::object to_json() const;
    static std::expected<LatencyReportPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// P2P_ENDPOINT Payload
// ============================================================================
struct P2PEndpointPayload {
    uint32_t peer_node_id;
    std::vector<Endpoint> endpoints;
    NATType nat_type{NATType::UNKNOWN};

    boost::json::object to_json() const;
    static std::expected<P2PEndpointPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// P2P_STATUS Payload
// ============================================================================
struct P2PStatusPayload {
    uint32_t peer_node_id;
    bool connected{false};
    std::string endpoint_ip;
    uint16_t endpoint_port{0};
    uint32_t rtt_ms{0};
    
    boost::json::object to_json() const;
    static std::expected<P2PStatusPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// SERVER_REGISTER Payload
// ============================================================================
struct ServerRegisterPayload {
    std::string server_token;
    std::string name;
    uint8_t capabilities{0};    // ServerCapability flags
    std::string region;
    std::string relay_url;      // Optional, if relay enabled
    std::string stun_ip;        // Optional, if stun enabled
    uint16_t stun_port{0};
    std::string stun_ip2;       // Optional secondary IP
    
    boost::json::object to_json() const;
    static std::expected<ServerRegisterPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// SERVER_NODE_LOC Payload (node location sync from controller to relay)
// ============================================================================
struct ServerNodeLocPayload {
    struct NodeLocation {
        uint32_t node_id;
        std::vector<uint32_t> connected_relay_ids;
    };
    std::vector<NodeLocation> nodes;
    
    boost::json::object to_json() const;
    static std::expected<ServerNodeLocPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// SERVER_BLACKLIST Payload (token blacklist sync)
// ============================================================================
struct ServerBlacklistPayload {
    struct BlacklistEntry {
        std::string jti;        // Token ID to blacklist
        int64_t expires_at;     // When this entry can be removed
    };
    
    bool full_sync{false};      // If true, replace entire blacklist
    std::vector<BlacklistEntry> entries;
    
    boost::json::object to_json() const;
    static std::expected<ServerBlacklistPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// RELAY_AUTH Payload (node auth to relay server)
// ============================================================================
struct RelayAuthPayload {
    std::string relay_token;    // JWT relay token from controller
    
    boost::json::object to_json() const;
    bool from_json(const boost::json::value& v);  // Returns true on success
};

// ============================================================================
// ERROR Payload
// ============================================================================
struct ErrorPayload {
    int code{static_cast<int>(ErrorCode::INTERNAL_ERROR)};
    std::string message;
    std::string details;

    boost::json::object to_json() const;
    bool from_json(const boost::json::value& v);  // Returns true on success
};

// ============================================================================
// Helper Functions
// ============================================================================

// Serialize JSON payload to Frame
Frame create_json_frame(MessageType type, const boost::json::object& json,
                        uint8_t flags = FrameFlags::NONE);

// Parse JSON from Frame payload
std::expected<boost::json::value, ErrorCode> parse_json_payload(const Frame& frame);

} // namespace wire

// Re-export commonly used types for backward compatibility
using wire::FrameHeader;
using wire::Frame;
using wire::DataPayload;

} // namespace edgelink

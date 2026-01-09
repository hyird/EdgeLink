#pragma once

#include "protocol.hpp"
#include "binary_codec.hpp"
#include <boost/json.hpp>
#include <span>
#include <expected>

namespace edgelink {

// ============================================================================
// Wire Protocol Types (wire:: namespace)
// ============================================================================
// These types are used for the binary wire protocol, which is used for:
// - WebSocket communication (Client <-> Controller, Client <-> Relay)
// - P2P direct communication between nodes (UDP)
// - Binary frame serialization for network transmission
//
// All communication uses the compact binary format for efficiency.
// See docs/architecture.md for detailed protocol specification.
// ============================================================================
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

    // Create a frame with optional compression
    // If compress=true and payload is compressible, the COMPRESSED flag will be set
    static Frame create_compressed(MessageType type, std::vector<uint8_t> payload,
                                   uint8_t flags = FrameFlags::NONE);

    // Serialize complete frame
    std::vector<uint8_t> serialize() const;

    // Deserialize complete frame (auto-decompresses if COMPRESSED flag is set)
    static std::expected<Frame, ErrorCode> deserialize(std::span<const uint8_t> data);

    // Deserialize without decompression (for forwarding)
    static std::expected<Frame, ErrorCode> deserialize_raw(std::span<const uint8_t> data);

    // Decompress payload if compressed, returns true on success or if not compressed
    bool decompress_if_needed();

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
    bool is_compressed() const { return header.is_compressed(); }

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
// AUTH_REQUEST Payload (architecture.md section 2.4.2)
// ============================================================================
// Binary format:
// ┌────────────┬────────────┬────────────┬────────────┐
// │ auth_type  │ machine_key│  node_key  │  hostname  │
// │   (1 B)    │  (32 B)    │  (32 B)    │ (len+str)  │
// ├────────────┼────────────┼────────────┼────────────┤
// │    os      │   arch     │  version   │ timestamp  │
// │ (len+str)  │ (len+str)  │ (len+str)  │   (8 B)    │
// ├────────────┼────────────┴────────────┴────────────┤
// │ signature  │  auth_data (optional, depends on type)│
// │  (64 B)    │         (variable)                   │
// └────────────┴──────────────────────────────────────┘
struct AuthRequestPayload {
    AuthType auth_type{AuthType::MACHINE};  // Authentication type
    std::array<uint8_t, 32> machine_key{};  // Ed25519 public key (raw bytes)
    std::array<uint8_t, 32> node_key{};     // X25519 public key (raw bytes)
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;
    uint64_t timestamp{0};
    std::array<uint8_t, 64> signature{};    // Ed25519 signature (raw bytes)

    // Auth-type specific data
    std::string username;                   // For AuthType::USER
    std::array<uint8_t, 32> password_hash{}; // For AuthType::USER (SHA256)
    std::string auth_key;                   // For AuthType::AUTHKEY

    // Legacy fields for JSON compatibility
    std::string machine_key_pub;            // Base64 encoded (for JSON)
    std::string node_key_pub;               // Base64 encoded (for JSON)
    std::string signature_b64;              // Base64 encoded (for JSON)

    // Binary serialization
    std::vector<uint8_t> serialize_binary() const;
    static std::expected<AuthRequestPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    // JSON serialization (for backward compatibility)
    boost::json::object to_json() const;
    static std::expected<AuthRequestPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// AUTH_RESPONSE Payload (architecture.md section 2.4.3)
// ============================================================================
// Binary format:
// ┌────────────┬────────────┬────────────┬────────────┐
// │  success   │  node_id   │ virtual_ip │ network_id │
// │   (1 B)    │   (4 B)    │   (4 B)    │   (4 B)    │
// ├────────────┼────────────┴────────────┴────────────┤
// │ auth_token │           relay_token                │
// │ (len+bytes)│          (len+bytes)                 │
// ├────────────┼──────────────────────────────────────┤
// │error_code  │           error_msg                  │
// │   (2 B)    │          (len+str)                   │
// └────────────┴──────────────────────────────────────┘
struct AuthResponsePayload {
    bool success{false};
    uint32_t node_id{0};
    uint32_t virtual_ip_int{0};         // IPv4 in network byte order
    uint32_t network_id{0};
    std::string auth_token;             // JWT auth token
    std::string relay_token;            // JWT relay token
    uint16_t error_code{0};
    std::string error_message;

    // Legacy field for JSON compatibility
    std::string virtual_ip;             // IPv4 as string (for JSON)

    // Binary serialization
    std::vector<uint8_t> serialize_binary() const;
    static std::expected<AuthResponsePayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    // JSON serialization (for backward compatibility)
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

// RouteInfo binary format (architecture.md section 6.3.1):
// ┌────────────┬────────────┬────────────┬────────────┬────────────┐
// │  ip_type   │   prefix   │ prefix_len │gateway_node│  priority  │
// │   (1 B)    │ (4/16 B)   │   (1 B)    │   (4 B)    │   (2 B)    │
// ├────────────┼────────────┼────────────┼────────────┼────────────┤
// │   weight   │   metric   │   flags    │            │            │
// │   (2 B)    │   (4 B)    │   (1 B)    │            │            │
// └────────────┴────────────┴────────────┴────────────┴────────────┘
struct RouteInfo {
    uint8_t ip_type{4};                 // 4=IPv4, 6=IPv6
    uint32_t prefix{0};                 // IPv4 prefix (network byte order)
    uint8_t prefix_len{0};              // 0-32 for IPv4, 0-128 for IPv6
    uint32_t gateway_node_id{0};
    uint16_t priority{100};
    uint16_t weight{100};
    uint32_t metric{0};
    uint8_t flags{RouteFlags::ENABLED};

    // Legacy field for JSON compatibility
    std::string cidr;
    bool enabled{true};

    // Binary serialization
    std::vector<uint8_t> serialize_binary() const;
    static std::expected<RouteInfo, ErrorCode> deserialize_binary(BinaryReader& reader);

    // JSON serialization
    boost::json::object to_json() const;
    static std::expected<RouteInfo, ErrorCode> from_json(const boost::json::value& v);

    // Helpers
    void from_cidr(std::string_view cidr_str);
    std::string to_cidr() const;
};

// ConfigPayload binary format (architecture.md section 2.4.4):
// ┌────────────┬────────────┬────────────┬────────────┐
// │  version   │ network_id │   subnet   │subnet_mask │
// │   (8 B)    │   (4 B)    │   (4 B)    │   (1 B)    │
// ├────────────┼────────────┴────────────┴────────────┤
// │relay_count │           relays[]                   │
// │   (2 B)    │    (RelayInfo 数组)                  │
// ├────────────┼──────────────────────────────────────┤
// │ stun_count │           stuns[]                    │
// │   (2 B)    │    (STUNInfo 数组)                   │
// ├────────────┼──────────────────────────────────────┤
// │ peer_count │           peers[]                    │
// │   (2 B)    │    (PeerInfo 数组)                   │
// ├────────────┼──────────────────────────────────────┤
// │route_count │           routes[]                   │
// │   (2 B)    │    (RouteInfo 数组)                  │
// ├────────────┼────────────┬────────────┬────────────┤
// │  relay_    │  expires   │   网络     │            │
// │  token     │    (8 B)   │   名称     │            │
// │(len+bytes) │            │ (len+str)  │            │
// └────────────┴────────────┴────────────┴────────────┘
struct ConfigPayload {
    uint64_t version{0};                // Config version for incremental updates
    uint32_t network_id{0};
    uint32_t subnet_ip{0};              // Subnet IP (e.g., 10.0.0.0)
    uint8_t subnet_mask{24};            // Subnet mask length
    std::string network_name;

    std::vector<RelayInfo> relays;
    std::vector<STUNInfo> stun_servers;
    std::vector<PeerInfo> peers;
    std::vector<RouteInfo> routes;

    // Token refresh info
    std::string new_relay_token;
    int64_t relay_token_expires_at{0};

    // Legacy field for JSON compatibility
    std::string subnet;                 // CIDR format string

    // Binary serialization
    std::vector<uint8_t> serialize_binary() const;
    static std::expected<ConfigPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    // JSON serialization
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
// Binary format:
// ┌────────────┬────────────┬────────────────────────────────────┐
// │ full_sync  │entry_count │           entries[]                │
// │   (1 B)    │   (2 B)    │   (jti_len + jti + expires_at)     │
// └────────────┴────────────┴────────────────────────────────────┘
struct ServerBlacklistPayload {
    struct BlacklistEntry {
        std::string jti;        // Token ID to blacklist
        int64_t expires_at;     // When this entry can be removed
    };

    bool full_sync{false};      // If true, replace entire blacklist
    std::vector<BlacklistEntry> entries;

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<ServerBlacklistPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

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
// ROUTE_ANNOUNCE Payload (Announce a new route)
// ============================================================================
struct RouteAnnouncePayload {
    uint32_t gateway_node_id{0};        // Node providing this route
    std::vector<RouteInfo> routes;      // Routes being announced

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<RouteAnnouncePayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    boost::json::object to_json() const;
    static std::expected<RouteAnnouncePayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// ROUTE_UPDATE Payload (Route changes from controller)
// ============================================================================
struct RouteUpdatePayload {
    uint64_t version{0};                // Routing table version
    enum class Action : uint8_t {
        ADD = 1,
        UPDATE = 2,
        REMOVE = 3
    };

    struct RouteChange {
        Action action;
        RouteInfo route;
    };

    std::vector<RouteChange> changes;

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<RouteUpdatePayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    boost::json::object to_json() const;
    static std::expected<RouteUpdatePayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// MESH_HELLO Payload (Relay-to-Relay handshake initiation)
// ============================================================================
// Binary format:
// ┌────────────┬────────────┬────────────┬────────────┐
// │ server_id  │   token    │   region   │capabilities│
// │   (4 B)    │ (len+str)  │ (len+str)  │   (1 B)    │
// └────────────┴────────────┴────────────┴────────────┘
struct MeshHelloPayload {
    uint32_t server_id{0};              // Sender's server ID
    std::string server_token;           // Server authentication token
    std::string region;                 // Server region
    uint8_t capabilities{0};            // ServerCapability flags

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<MeshHelloPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    boost::json::object to_json() const;
    static std::expected<MeshHelloPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// MESH_HELLO_ACK Payload (Relay-to-Relay handshake response)
// ============================================================================
struct MeshHelloAckPayload {
    bool success{false};
    uint32_t server_id{0};              // Responder's server ID
    std::string region;
    uint8_t capabilities{0};
    std::string error_message;          // If success is false

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<MeshHelloAckPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    boost::json::object to_json() const;
    static std::expected<MeshHelloAckPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// MESH_FORWARD Payload (Forward data through mesh network)
// ============================================================================
// Binary format:
// ┌────────────┬────────────┬────────────┬────────────┐
// │   src_id   │   dst_id   │   ttl      │   data     │
// │   (4 B)    │   (4 B)    │   (1 B)    │ (len+bytes)│
// └────────────┴────────────┴────────────┴────────────┘
struct MeshForwardPayload {
    uint32_t src_relay_id{0};           // Source relay server ID
    uint32_t dst_node_id{0};            // Destination node ID
    uint8_t ttl{3};                     // Time-to-live (hop count)
    std::vector<uint8_t> data;          // Original DATA frame

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<MeshForwardPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    boost::json::object to_json() const;
    static std::expected<MeshForwardPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// MESH_PING/PONG Payload (Relay-to-Relay latency measurement)
// ============================================================================
struct MeshPingPayload {
    uint64_t timestamp{0};              // Send timestamp (milliseconds)
    uint32_t sequence{0};               // Sequence number

    std::vector<uint8_t> serialize_binary() const;
    static std::expected<MeshPingPayload, ErrorCode> deserialize_binary(std::span<const uint8_t> data);

    boost::json::object to_json() const;
    static std::expected<MeshPingPayload, ErrorCode> from_json(const boost::json::value& v);
};

// ============================================================================
// Compression Constants
// ============================================================================
namespace CompressionConstants {
    // Minimum payload size to consider compression (smaller payloads are rarely compressible)
    constexpr size_t MIN_COMPRESS_SIZE = 64;

    // Maximum compressed size expansion factor (LZ4 worst case is ~1.0x + 16 bytes)
    constexpr size_t COMPRESS_BOUND_EXTRA = 32;

    // Compression level: 0 = default, 1-12 = fast levels
    constexpr int DEFAULT_COMPRESSION_LEVEL = 1;
}

// ============================================================================
// Compression Utilities
// ============================================================================

// Compress data using LZ4
// Returns compressed data, or empty vector on failure
std::vector<uint8_t> compress_payload(std::span<const uint8_t> data);

// Decompress LZ4 data
// original_size is a hint for the output buffer (0 = auto-detect)
std::expected<std::vector<uint8_t>, ErrorCode> decompress_payload(
    std::span<const uint8_t> compressed_data, size_t original_size_hint = 0);

// Check if compression would be beneficial for this payload
bool should_compress(std::span<const uint8_t> data);

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

#pragma once

#include "common/types.hpp"
#include "common/frame.hpp"
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace edgelink {

// Parse error type
enum class ParseError {
    INSUFFICIENT_DATA,
    INVALID_FORMAT,
    STRING_TOO_LONG,
    ARRAY_TOO_LARGE,
};

std::string parse_error_message(ParseError error);

// ============================================================================
// Authentication Messages
// ============================================================================

// AUTH_REQUEST (0x01)
struct AuthRequest {
    AuthType auth_type = AuthType::AUTHKEY;
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> machine_key{};
    std::array<uint8_t, X25519_KEY_SIZE> node_key{};
    std::string hostname;
    std::string os;
    std::string arch;
    std::string version;
    uint64_t timestamp = 0;
    std::array<uint8_t, ED25519_SIGNATURE_SIZE> signature{};
    std::vector<uint8_t> auth_data; // Content depends on auth_type

    std::vector<uint8_t> serialize() const;
    static std::expected<AuthRequest, ParseError> parse(std::span<const uint8_t> data);

    // Get data to be signed (everything except signature itself)
    std::vector<uint8_t> get_sign_data() const;
};

// AUTH_RESPONSE (0x02)
struct AuthResponse {
    bool success = false;
    NodeId node_id = 0;
    IPv4Address virtual_ip{};
    NetworkId network_id = 0;
    std::vector<uint8_t> auth_token;   // JWT
    std::vector<uint8_t> relay_token;  // JWT
    uint16_t error_code = 0;
    std::string error_msg;

    std::vector<uint8_t> serialize() const;
    static std::expected<AuthResponse, ParseError> parse(std::span<const uint8_t> data);
};

// RELAY_AUTH (0x60)
struct RelayAuth {
    std::vector<uint8_t> relay_token;
    NodeId node_id = 0;
    std::array<uint8_t, X25519_KEY_SIZE> node_key{};

    std::vector<uint8_t> serialize() const;
    static std::expected<RelayAuth, ParseError> parse(std::span<const uint8_t> data);
};

// RELAY_AUTH_RESP (0x61)
struct RelayAuthResp {
    bool success = false;
    uint16_t error_code = 0;
    std::string error_msg;

    std::vector<uint8_t> serialize() const;
    static std::expected<RelayAuthResp, ParseError> parse(std::span<const uint8_t> data);
};

// ============================================================================
// Configuration Messages
// ============================================================================

// CONFIG (0x10)
struct Config {
    uint64_t version = 0;
    NetworkId network_id = 0;
    IPv4Address subnet{};
    uint8_t subnet_mask = 0;
    std::string network_name;
    std::vector<RelayInfo> relays;
    std::vector<StunInfo> stuns;
    std::vector<PeerInfo> peers;
    std::vector<RouteInfo> routes;
    std::vector<uint8_t> relay_token;
    uint64_t relay_token_expires = 0;

    std::vector<uint8_t> serialize() const;
    static std::expected<Config, ParseError> parse(std::span<const uint8_t> data);
};

// CONFIG_UPDATE (0x11)
struct ConfigUpdate {
    uint64_t version = 0;
    ConfigUpdateFlags update_flags = ConfigUpdateFlags::NONE;
    std::vector<RelayInfo> add_relays;
    std::vector<ServerId> del_relay_ids;
    std::vector<PeerInfo> add_peers;
    std::vector<NodeId> del_peer_ids;
    std::vector<RouteInfo> add_routes;
    std::vector<RouteInfo> del_routes; // Using RouteInfo as RouteIdentifier

    // Optional: when TOKEN_REFRESH flag is set
    std::vector<uint8_t> relay_token;
    uint64_t relay_token_expires = 0;

    std::vector<uint8_t> serialize() const;
    static std::expected<ConfigUpdate, ParseError> parse(std::span<const uint8_t> data);
};

// CONFIG_ACK (0x12)
struct ConfigAck {
    uint64_t version = 0;
    ConfigAckStatus status = ConfigAckStatus::SUCCESS;

    struct ErrorItem {
        ConfigErrorItemType item_type;
        uint32_t item_id;
        uint16_t error_code;
    };
    std::vector<ErrorItem> error_items;

    std::vector<uint8_t> serialize() const;
    static std::expected<ConfigAck, ParseError> parse(std::span<const uint8_t> data);
};

// ============================================================================
// Data Messages
// ============================================================================

// DATA (0x20)
struct DataPayload {
    NodeId src_node = 0;
    NodeId dst_node = 0;
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce{};
    std::vector<uint8_t> encrypted_payload; // Includes auth_tag at the end

    std::vector<uint8_t> serialize() const;
    static std::expected<DataPayload, ParseError> parse(std::span<const uint8_t> data);
};

// DATA_ACK (0x21)
struct DataAck {
    NodeId src_node = 0;
    NodeId dst_node = 0;
    std::array<uint8_t, CHACHA20_NONCE_SIZE> ack_nonce{};
    DataAckFlags ack_flags = DataAckFlags::SUCCESS;

    std::vector<uint8_t> serialize() const;
    static std::expected<DataAck, ParseError> parse(std::span<const uint8_t> data);
};

// ============================================================================
// Heartbeat Messages
// ============================================================================

// PING/PONG (0x30/0x31)
struct Ping {
    uint64_t timestamp = 0;
    uint32_t seq_num = 0;

    std::vector<uint8_t> serialize() const;
    static std::expected<Ping, ParseError> parse(std::span<const uint8_t> data);
};

using Pong = Ping; // Same structure

// ============================================================================
// Error Messages
// ============================================================================

// ERROR (0xFF)
struct ErrorPayload {
    uint16_t error_code = 0;
    FrameType request_type = FrameType::FRAME_ERROR;
    uint32_t request_id = 0;
    std::string error_msg;

    std::vector<uint8_t> serialize() const;
    static std::expected<ErrorPayload, ParseError> parse(std::span<const uint8_t> data);
};

// GENERIC_ACK (0xFE)
struct GenericAck {
    FrameType request_type = FrameType::FRAME_ERROR;
    uint32_t request_id = 0;
    uint8_t status = 0;

    std::vector<uint8_t> serialize() const;
    static std::expected<GenericAck, ParseError> parse(std::span<const uint8_t> data);
};

// ============================================================================
// Serialization Helpers
// ============================================================================

namespace serialization {

// Serialize helper structures
void write_endpoint(BinaryWriter& writer, const Endpoint& ep);
std::expected<Endpoint, ParseError> read_endpoint(BinaryReader& reader);

void write_peer_info(BinaryWriter& writer, const PeerInfo& peer);
std::expected<PeerInfo, ParseError> read_peer_info(BinaryReader& reader);

void write_relay_info(BinaryWriter& writer, const RelayInfo& relay);
std::expected<RelayInfo, ParseError> read_relay_info(BinaryReader& reader);

void write_stun_info(BinaryWriter& writer, const StunInfo& stun);
std::expected<StunInfo, ParseError> read_stun_info(BinaryReader& reader);

void write_route_info(BinaryWriter& writer, const RouteInfo& route);
std::expected<RouteInfo, ParseError> read_route_info(BinaryReader& reader);

void write_subnet_info(BinaryWriter& writer, const SubnetInfo& subnet);
std::expected<SubnetInfo, ParseError> read_subnet_info(BinaryReader& reader);

} // namespace serialization

} // namespace edgelink

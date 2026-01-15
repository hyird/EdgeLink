#pragma once

#include "common/constants.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace edgelink {

// ============================================================================
// 保留旧名称的兼容别名（逐步迁移后删除）
// ============================================================================
inline constexpr uint8_t PROTOCOL_VERSION = protocol::VERSION;
inline constexpr uint32_t P2P_MAGIC = protocol::P2P_MAGIC;

// Core ID types
using NodeId = uint32_t;
using NetworkId = uint32_t;
using ServerId = uint32_t;
using MessageId = uint32_t;
using ConnectionId = uint32_t;  // 连接标识符（用于多路连接）

// 密钥大小别名（兼容旧代码）
inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = crypto::ED25519_PUBLIC_KEY_SIZE;
inline constexpr size_t ED25519_PRIVATE_KEY_SIZE = crypto::ED25519_PRIVATE_KEY_SIZE;
inline constexpr size_t ED25519_SIGNATURE_SIZE = crypto::ED25519_SIGNATURE_SIZE;
inline constexpr size_t X25519_KEY_SIZE = crypto::X25519_KEY_SIZE;
inline constexpr size_t SESSION_KEY_SIZE = crypto::SESSION_KEY_SIZE;
inline constexpr size_t CHACHA20_NONCE_SIZE = crypto::CHACHA20_NONCE_SIZE;
inline constexpr size_t POLY1305_TAG_SIZE = crypto::POLY1305_TAG_SIZE;

// Key structures
struct MachineKey {
    std::array<uint8_t, ED25519_PUBLIC_KEY_SIZE> public_key{};
    std::array<uint8_t, ED25519_PRIVATE_KEY_SIZE> private_key{};
};

struct NodeKey {
    std::array<uint8_t, X25519_KEY_SIZE> public_key{};
    std::array<uint8_t, X25519_KEY_SIZE> private_key{};
};

struct SessionKey {
    std::array<uint8_t, SESSION_KEY_SIZE> key{};
    std::array<uint8_t, CHACHA20_NONCE_SIZE> send_nonce_base{};
    std::array<uint8_t, CHACHA20_NONCE_SIZE> recv_nonce_base{};
};

// Frame types (0x01-0xFF)
enum class FrameType : uint8_t {
    // Authentication (0x01-0x0F)
    AUTH_REQUEST = 0x01,
    AUTH_RESPONSE = 0x02,
    AUTH_CHALLENGE = 0x03,
    AUTH_VERIFY = 0x04,

    // Configuration (0x10-0x1F)
    CONFIG = 0x10,
    CONFIG_UPDATE = 0x11,
    CONFIG_ACK = 0x12,

    // Data (0x20-0x2F)
    DATA = 0x20,
    DATA_ACK = 0x21,

    // Heartbeat (0x30-0x3F)
    PING = 0x30,
    PONG = 0x31,
    LATENCY_REPORT = 0x32,
    CONNECTION_METRICS = 0x33,  // Client 上报连接延迟指标
    PATH_SELECTION = 0x34,      // Controller 指示连接路径选择
    PEER_PATH_REPORT = 0x35,    // Client 上报到每个 Peer 经过每个 Relay 的延迟
    PEER_ROUTING_UPDATE = 0x36, // Controller 下发每个 Peer 的最优路径
    RELAY_LATENCY_REPORT = 0x37, // Client 上报到每个 Relay 的延迟

    // P2P (0x40-0x4F)
    P2P_INIT = 0x40,
    P2P_ENDPOINT = 0x41,
    P2P_PING = 0x42,
    P2P_PONG = 0x43,
    P2P_KEEPALIVE = 0x44,
    P2P_STATUS = 0x45,
    ENDPOINT_UPDATE = 0x46,  // 客户端上报自己的端点
    ENDPOINT_ACK = 0x47,     // 端点上报确认

    // Server (0x50-0x5F)
    SERVER_REGISTER = 0x50,
    SERVER_REGISTER_RESP = 0x51,
    SERVER_NODE_LOC = 0x52,
    SERVER_BLACKLIST = 0x53,
    SERVER_HEARTBEAT = 0x54,
    SERVER_RELAY_LIST = 0x55,
    SERVER_LATENCY_REPORT = 0x56,

    // Relay Auth (0x60-0x6F)
    RELAY_AUTH = 0x60,
    RELAY_AUTH_RESP = 0x61,

    // Mesh (0x70-0x7F)
    MESH_HELLO = 0x70,
    MESH_HELLO_ACK = 0x71,
    MESH_FORWARD = 0x72,
    MESH_PING = 0x73,
    MESH_PONG = 0x74,

    // Routing (0x80-0x8F)
    ROUTE_ANNOUNCE = 0x80,
    ROUTE_UPDATE = 0x81,
    ROUTE_WITHDRAW = 0x82,
    ROUTE_ACK = 0x83,

    // Security (0x90-0x9F)
    NODE_REVOKE = 0x90,
    NODE_REVOKE_ACK = 0x91,
    NODE_REVOKE_BATCH = 0x92,

    // Lifecycle (0xA0-0xAF)
    SHUTDOWN_NOTIFY = 0xA0,
    SHUTDOWN_ACK = 0xA1,

    // Generic (0xF0-0xFF)
    GENERIC_ACK = 0xFE,
    FRAME_ERROR = 0xFF,  // Note: Can't use ERROR due to Windows macro conflict
};

// Frame flags
enum class FrameFlags : uint8_t {
    NONE = 0x00,
    NEED_ACK = 0x01,
    COMPRESSED = 0x02,
    ENCRYPTED = 0x04,
    FRAGMENTED = 0x08,
};

inline FrameFlags operator|(FrameFlags a, FrameFlags b) {
    return static_cast<FrameFlags>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

inline FrameFlags operator&(FrameFlags a, FrameFlags b) {
    return static_cast<FrameFlags>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}

inline bool has_flag(FrameFlags flags, FrameFlags flag) {
    return (static_cast<uint8_t>(flags) & static_cast<uint8_t>(flag)) != 0;
}

// Authentication types
enum class AuthType : uint8_t {
    USER = 0x01,
    AUTHKEY = 0x02,
    MACHINE = 0x03,
};

// IP type
enum class IpType : uint8_t {
    IPv4 = 0x04,
    IPv6 = 0x06,
};

// Endpoint type
enum class EndpointType : uint8_t {
    LAN = 0x01,
    STUN = 0x02,
    UPNP = 0x03,
    RELAY = 0x04,
};

// Path type
enum class PathType : uint8_t {
    LAN = 0x01,
    STUN = 0x02,
    RELAY = 0x03,
};

// P2P connection status
enum class P2PStatus : uint8_t {
    DISCONNECTED = 0x00,
    P2P = 0x01,
    RELAY_ONLY = 0x02,
};

// Challenge types
enum class ChallengeType : uint8_t {
    TOTP = 0x01,
    SMS = 0x02,
    EMAIL = 0x03,
};

// CONFIG_UPDATE flags
enum class ConfigUpdateFlags : uint16_t {
    NONE = 0x0000,
    RELAY_CHANGED = 0x0001,
    PEER_CHANGED = 0x0002,
    ROUTE_CHANGED = 0x0004,
    TOKEN_REFRESH = 0x0008,
    FULL_SYNC = 0x0010,
};

inline ConfigUpdateFlags operator|(ConfigUpdateFlags a, ConfigUpdateFlags b) {
    return static_cast<ConfigUpdateFlags>(static_cast<uint16_t>(a) | static_cast<uint16_t>(b));
}

inline bool has_flag(ConfigUpdateFlags flags, ConfigUpdateFlags flag) {
    return (static_cast<uint16_t>(flags) & static_cast<uint16_t>(flag)) != 0;
}

// Route flags
enum class RouteFlags : uint8_t {
    NONE = 0x00,
    ENABLED = 0x01,
    PRIMARY = 0x02,
    EXIT_NODE = 0x04,
    AUTO = 0x08,
};

inline RouteFlags operator|(RouteFlags a, RouteFlags b) {
    return static_cast<RouteFlags>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

inline bool has_flag(RouteFlags flags, RouteFlags flag) {
    return (static_cast<uint8_t>(flags) & static_cast<uint8_t>(flag)) != 0;
}

// DATA_ACK flags
enum class DataAckFlags : uint8_t {
    SUCCESS = 0x01,
    DECRYPT_FAILED = 0x02,
    DUPLICATE = 0x04,
};

// CONFIG_ACK status
enum class ConfigAckStatus : uint8_t {
    SUCCESS = 0x00,
    PARTIAL_FAILURE = 0x01,
    TOTAL_FAILURE = 0x02,
};

// Config error item type
enum class ConfigErrorItemType : uint8_t {
    RELAY = 0x01,
    PEER = 0x02,
    ROUTE = 0x03,
};

// IPv4 address (network byte order)
struct IPv4Address {
    std::array<uint8_t, 4> bytes{};

    static IPv4Address from_string(const std::string& str);
    std::string to_string() const;
    uint32_t to_u32() const;
    static IPv4Address from_u32(uint32_t addr);
};

// Network endpoint
struct Endpoint {
    EndpointType type = EndpointType::LAN;
    IpType ip_type = IpType::IPv4;
    std::array<uint8_t, 16> address{}; // IPv4 uses first 4 bytes
    uint16_t port = 0;
    uint8_t priority = 0;
};

// Subnet info
struct SubnetInfo {
    IpType ip_type = IpType::IPv4;
    std::array<uint8_t, 16> prefix{}; // IPv4 uses first 4 bytes
    uint8_t prefix_len = 0;
};

// Route info
struct RouteInfo {
    IpType ip_type = IpType::IPv4;
    std::array<uint8_t, 16> prefix{};
    uint8_t prefix_len = 0;
    NodeId gateway_node = 0;
    uint16_t metric = 0;
    RouteFlags flags = RouteFlags::NONE;
};

// Peer info
struct PeerInfo {
    NodeId node_id = 0;
    IPv4Address virtual_ip{};
    std::array<uint8_t, X25519_KEY_SIZE> node_key{};
    bool online = false;
    bool exit_node = false;  // 该节点是否可作为出口节点
    std::string name;
    std::vector<Endpoint> endpoints;
    std::vector<SubnetInfo> allowed_subnets;
};

// Relay info
struct RelayInfo {
    ServerId server_id = 0;
    std::string hostname;
    std::vector<Endpoint> endpoints;
    uint16_t priority = 0;
    std::string region;
};

// STUN server info
struct StunInfo {
    std::string hostname;
    uint16_t port = 3478;
};

// Latency entry
struct LatencyEntry {
    ServerId server_id = 0;
    uint16_t latency_ms = 0;
    uint16_t jitter_ms = 0;
    uint8_t packet_loss = 0; // 0-100
};

// Get frame type name for logging
const char* frame_type_name(FrameType type);

// ============================================================================
// 统一 P2P 配置（唯一定义，供 Client 和 P2PManager 使用）
// ============================================================================
struct P2PConfig {
    bool enabled = true;                                                // 启用 P2P 直连
    uint16_t bind_port = 0;                                             // UDP 绑定端口（0 = 随机）
    std::chrono::seconds keepalive_interval{1};                         // Keepalive 间隔
    std::chrono::seconds keepalive_timeout{3};                          // Keepalive 超时
    std::chrono::seconds punch_timeout{10};                             // 打洞超时
    std::chrono::seconds endpoint_resolve_timeout{5};                   // 端点解析超时（等待 P2P_ENDPOINT）
    uint32_t punch_batch_count = defaults::PUNCH_BATCH_COUNT;           // 打洞批次数
    uint32_t punch_batch_size = defaults::PUNCH_BATCH_SIZE;             // 每批发送包数
    std::chrono::milliseconds punch_batch_interval{defaults::PUNCH_BATCH_INTERVAL};  // 批次间隔
    std::chrono::seconds retry_interval{60};                            // 失败后重试间隔
    std::chrono::milliseconds stun_timeout{5000};                       // STUN 查询超时
    std::chrono::seconds endpoint_refresh_interval{60};                 // 端点刷新间隔

    // 从旧格式的秒数构造
    static P2PConfig from_seconds(
        bool enabled, uint16_t bind_port,
        uint32_t keepalive_interval_sec, uint32_t keepalive_timeout_sec,
        uint32_t punch_timeout_sec, uint32_t punch_batch_count, uint32_t punch_batch_size,
        uint32_t punch_batch_interval_ms, uint32_t retry_interval_sec,
        uint32_t stun_timeout_ms, uint32_t endpoint_refresh_sec
    ) {
        P2PConfig cfg;
        cfg.enabled = enabled;
        cfg.bind_port = bind_port;
        cfg.keepalive_interval = std::chrono::seconds(keepalive_interval_sec);
        cfg.keepalive_timeout = std::chrono::seconds(keepalive_timeout_sec);
        cfg.punch_timeout = std::chrono::seconds(punch_timeout_sec);
        cfg.punch_batch_count = punch_batch_count;
        cfg.punch_batch_size = punch_batch_size;
        cfg.punch_batch_interval = std::chrono::milliseconds(punch_batch_interval_ms);
        cfg.retry_interval = std::chrono::seconds(retry_interval_sec);
        cfg.stun_timeout = std::chrono::milliseconds(stun_timeout_ms);
        cfg.endpoint_refresh_interval = std::chrono::seconds(endpoint_refresh_sec);
        return cfg;
    }
};

} // namespace edgelink

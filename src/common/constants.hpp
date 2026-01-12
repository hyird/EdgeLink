#pragma once

#include <chrono>
#include <cstdint>

namespace edgelink {

// ============================================================================
// 协议版本
// ============================================================================
namespace protocol {

// 协议版本号
inline constexpr uint8_t VERSION = 0x02;

// P2P UDP 魔数 "ELNK" (0x454C4E4B)
inline constexpr uint32_t P2P_MAGIC = 0x454C4E4B;

// ============================================================================
// 内部消息类型 (用于 P2P 数据包识别)
// ============================================================================
inline constexpr uint8_t INTERNAL_PING = 0xEE;
inline constexpr uint8_t INTERNAL_PONG = 0xEF;

// ============================================================================
// 消息大小限制
// ============================================================================
inline constexpr size_t MAX_FRAME_SIZE = 65536;
inline constexpr size_t MAX_PAYLOAD_SIZE = 65000;
inline constexpr size_t PING_MESSAGE_SIZE = 13;  // 1 + 8 + 4 bytes

// ============================================================================
// 序列化长度限制
// ============================================================================
inline constexpr size_t MAX_STRING_LENGTH = 255;
inline constexpr size_t MAX_ARRAY_LENGTH = 65535;
inline constexpr size_t MAX_PEERS_COUNT = 1000;
inline constexpr size_t MAX_ROUTES_COUNT = 1000;
inline constexpr size_t MAX_ENDPOINTS_COUNT = 32;

}  // namespace protocol

// ============================================================================
// 密钥大小
// ============================================================================
namespace crypto {

inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
inline constexpr size_t ED25519_PRIVATE_KEY_SIZE = 64;
inline constexpr size_t ED25519_SIGNATURE_SIZE = 64;
inline constexpr size_t X25519_KEY_SIZE = 32;
inline constexpr size_t SESSION_KEY_SIZE = 32;
inline constexpr size_t CHACHA20_NONCE_SIZE = 12;
inline constexpr size_t POLY1305_TAG_SIZE = 16;

}  // namespace crypto

// ============================================================================
// 默认超时设置
// ============================================================================
namespace defaults {

// Ping/Pong
inline constexpr auto PING_TIMEOUT = std::chrono::milliseconds(5000);
inline constexpr auto PING_INTERVAL = std::chrono::seconds(5);

// 连接超时
inline constexpr auto CONNECT_TIMEOUT = std::chrono::seconds(10);
inline constexpr auto AUTH_TIMEOUT = std::chrono::seconds(10);
inline constexpr auto CONFIG_ACK_TIMEOUT = std::chrono::seconds(5);

// 重连
inline constexpr auto RECONNECT_INTERVAL = std::chrono::seconds(5);
inline constexpr auto FAILOVER_TIMEOUT = std::chrono::milliseconds(5000);

// DNS 刷新
inline constexpr auto DNS_REFRESH_INTERVAL = std::chrono::seconds(60);

// Relay
inline constexpr auto RELAY_KEEPALIVE_INTERVAL = std::chrono::seconds(30);

// 心跳超时
inline constexpr auto HEARTBEAT_TIMEOUT = std::chrono::seconds(30);

// P2P 相关
inline constexpr auto P2P_PUNCH_TIMEOUT = std::chrono::seconds(10);
inline constexpr auto P2P_KEEPALIVE_INTERVAL = std::chrono::seconds(1);
inline constexpr auto P2P_KEEPALIVE_TIMEOUT = std::chrono::seconds(3);
inline constexpr auto P2P_RETRY_INTERVAL = std::chrono::seconds(60);
inline constexpr auto P2P_NEGOTIATION_TIMEOUT = std::chrono::seconds(10);
inline constexpr auto P2P_RESOLVE_TIMEOUT = std::chrono::seconds(5);
inline constexpr auto STUN_TIMEOUT = std::chrono::milliseconds(5000);
inline constexpr auto ENDPOINT_REFRESH_INTERVAL = std::chrono::seconds(60);
inline constexpr auto ENDPOINT_UPLOAD_TIMEOUT = std::chrono::seconds(5);

// P2P 打洞参数 (EasyTier 风格)
inline constexpr uint32_t PUNCH_BATCH_COUNT = 5;
inline constexpr uint32_t PUNCH_BATCH_SIZE = 2;
inline constexpr auto PUNCH_BATCH_INTERVAL = std::chrono::milliseconds(400);

// 路由公告
inline constexpr auto ROUTE_ANNOUNCE_INTERVAL = std::chrono::seconds(60);

// 延迟测量
inline constexpr auto LATENCY_MEASURE_INTERVAL = std::chrono::seconds(30);

}  // namespace defaults

// ============================================================================
// 网络默认值
// ============================================================================
namespace network {

// 默认端口
inline constexpr uint16_t DEFAULT_CONTROLLER_PORT_TLS = 443;
inline constexpr uint16_t DEFAULT_CONTROLLER_PORT_PLAIN = 80;
inline constexpr uint16_t DEFAULT_STUN_PORT = 3478;
inline constexpr uint16_t DEFAULT_RELAY_PORT = 8081;

// TUN 设备
inline constexpr uint32_t DEFAULT_TUN_MTU = 1420;

// Channel 容量
inline constexpr size_t STATE_CHANNEL_CAPACITY = 64;
inline constexpr size_t DATA_CHANNEL_CAPACITY = 128;
inline constexpr size_t EVENT_CHANNEL_CAPACITY = 64;

}  // namespace network

// ============================================================================
// 数据库/存储
// ============================================================================
namespace storage {

// 延迟记录清理
inline constexpr auto LATENCY_RECORD_MAX_AGE = std::chrono::hours(24);
inline constexpr size_t LATENCY_RECORDS_PER_NODE = 100;

// JWT 过期时间
inline constexpr auto AUTH_TOKEN_EXPIRY = std::chrono::hours(24);
inline constexpr auto RELAY_TOKEN_EXPIRY = std::chrono::hours(1);

}  // namespace storage

}  // namespace edgelink

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
    ConnectionId connection_id = 0;  // 连接标识符（用于多路连接场景）
    bool exit_node = false;          // 声明自己可作为出口节点
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
    ConnectionId connection_id = 0;  // 连接标识符（用于多路连接场景）

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

// LATENCY_REPORT (0x32) - 节点上报到 Controller 的延迟测量结果
struct LatencyReportEntry {
    NodeId peer_node_id = 0;     // 目标节点 ID
    uint16_t latency_ms = 0;     // 延迟毫秒数 (0 = 超时/不可达)
    uint8_t path_type = 0;       // 0 = relay, 1 = p2p
};

struct LatencyReport {
    uint64_t timestamp = 0;                      // 测量时间戳
    std::vector<LatencyReportEntry> entries;     // 延迟条目列表

    std::vector<uint8_t> serialize() const;
    static std::expected<LatencyReport, ParseError> parse(std::span<const uint8_t> data);
};

// CONNECTION_METRICS (0x33) - Client 上报连接延迟指标
struct ConnectionMetricsEntry {
    ConnectionId connection_id = 0;  // 连接标识符
    uint16_t rtt_ms = 0;             // 往返延迟（毫秒）
    uint8_t packet_loss = 0;         // 丢包率（百分比，0-100）
    uint8_t is_active = 1;           // 是否活跃（1=活跃，0=失效）
};

struct ConnectionMetrics {
    uint64_t timestamp = 0;                          // 测量时间戳
    uint8_t channel_type = 0;                        // 0 = control, 1 = relay
    std::vector<ConnectionMetricsEntry> connections; // 连接指标列表

    std::vector<uint8_t> serialize() const;
    static std::expected<ConnectionMetrics, ParseError> parse(std::span<const uint8_t> data);
};

// PATH_SELECTION (0x34) - Controller 指示连接路径选择
struct PathSelection {
    ConnectionId preferred_connection_id = 0;  // 优选连接 ID
    uint8_t channel_type = 0;                  // 0 = control, 1 = relay
    std::string reason;                        // 选择原因（用于调试）

    std::vector<uint8_t> serialize() const;
    static std::expected<PathSelection, ParseError> parse(std::span<const uint8_t> data);
};

// PEER_PATH_REPORT (0x35) - Client 上报到每个 Peer 经过每个 Relay 的延迟
struct PeerPathReportEntry {
    NodeId peer_node_id = 0;           // 目标节点 ID
    ServerId relay_id = 0;             // 经过的 Relay ID (0 = P2P 直连)
    ConnectionId connection_id = 0;    // 使用的连接 ID
    uint16_t latency_ms = 0;           // 往返延迟（毫秒）
    uint8_t packet_loss = 0;           // 丢包率（百分比，0-100）
};

struct PeerPathReport {
    uint64_t timestamp = 0;                          // 测量时间戳
    std::vector<PeerPathReportEntry> entries;        // 延迟条目列表

    std::vector<uint8_t> serialize() const;
    static std::expected<PeerPathReport, ParseError> parse(std::span<const uint8_t> data);
};

// PEER_ROUTING_UPDATE (0x36) - Controller 下发每个 Peer 的最优路径
struct PeerRoutingEntry {
    NodeId peer_node_id = 0;           // 目标节点 ID
    ServerId relay_id = 0;             // 推荐使用的 Relay ID (0 = P2P 直连)
    ConnectionId connection_id = 0;    // 推荐使用的连接 ID
    uint8_t priority = 0;              // 优先级 (0 = 最高)
};

struct PeerRoutingUpdate {
    uint64_t version = 0;                           // 版本号（增量更新）
    std::vector<PeerRoutingEntry> routes;           // 路由条目列表

    std::vector<uint8_t> serialize() const;
    static std::expected<PeerRoutingUpdate, ParseError> parse(std::span<const uint8_t> data);
};

// RELAY_LATENCY_REPORT (0x37) - Client 上报到每个 Relay 的延迟
struct RelayLatencyReportEntry {
    ServerId relay_id = 0;             // Relay 服务器 ID
    ConnectionId connection_id = 0;    // 连接 ID
    uint16_t latency_ms = 0;           // 往返延迟（毫秒）
    uint8_t packet_loss = 0;           // 丢包率（百分比，0-100）
};

struct RelayLatencyReport {
    uint64_t timestamp = 0;                              // 测量时间戳
    std::vector<RelayLatencyReportEntry> entries;        // 延迟条目列表

    std::vector<uint8_t> serialize() const;
    static std::expected<RelayLatencyReport, ParseError> parse(std::span<const uint8_t> data);
};

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
// Routing Messages
// ============================================================================

// ROUTE_ANNOUNCE (0x80) - 节点公告自己可路由的子网
struct RouteAnnounce {
    uint32_t request_id = 0;               // 请求 ID，用于 ACK 匹配
    std::vector<RouteInfo> routes;         // 公告的路由列表

    std::vector<uint8_t> serialize() const;
    static std::expected<RouteAnnounce, ParseError> parse(std::span<const uint8_t> data);
};

// ROUTE_UPDATE (0x81) - Controller 推送路由更新给节点
struct RouteUpdate {
    uint64_t version = 0;                  // 路由表版本号
    std::vector<RouteInfo> add_routes;     // 新增路由
    std::vector<RouteInfo> del_routes;     // 删除路由

    std::vector<uint8_t> serialize() const;
    static std::expected<RouteUpdate, ParseError> parse(std::span<const uint8_t> data);
};

// ROUTE_WITHDRAW (0x82) - 节点撤销路由公告
struct RouteWithdraw {
    uint32_t request_id = 0;               // 请求 ID
    std::vector<RouteInfo> routes;         // 撤销的路由列表

    std::vector<uint8_t> serialize() const;
    static std::expected<RouteWithdraw, ParseError> parse(std::span<const uint8_t> data);
};

// ROUTE_ACK (0x83) - 路由操作确认
struct RouteAck {
    uint32_t request_id = 0;
    bool success = false;
    uint16_t error_code = 0;
    std::string error_msg;

    std::vector<uint8_t> serialize() const;
    static std::expected<RouteAck, ParseError> parse(std::span<const uint8_t> data);
};

// ============================================================================
// P2P Messages
// ============================================================================

// P2P_INIT (0x40) - 请求 Controller 返回对端端点
struct P2PInit {
    NodeId target_node = 0;         // 目标节点 ID
    uint32_t init_seq = 0;          // 请求序列号

    std::vector<uint8_t> serialize() const;
    static std::expected<P2PInit, ParseError> parse(std::span<const uint8_t> data);
};

// P2P_ENDPOINT (0x41) - Controller 返回对端端点列表
struct P2PEndpointMsg {
    uint32_t init_seq = 0;          // 对应的请求序列号
    NodeId peer_node = 0;           // 对端节点 ID
    std::array<uint8_t, X25519_KEY_SIZE> peer_key{};  // 对端公钥
    std::vector<Endpoint> endpoints; // 对端端点列表

    std::vector<uint8_t> serialize() const;
    static std::expected<P2PEndpointMsg, ParseError> parse(std::span<const uint8_t> data);
};

// P2P_PING (0x42) / P2P_PONG (0x43) - UDP 打洞探测
struct P2PPing {
    uint32_t magic = P2P_MAGIC;     // "ELNK" (0x454C4E4B)
    NodeId src_node = 0;            // 源节点 ID
    NodeId dst_node = 0;            // 目标节点 ID
    uint64_t timestamp = 0;         // 发送时间戳（微秒）
    uint32_t seq_num = 0;           // 序列号
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce{};  // 随机数
    std::array<uint8_t, ED25519_SIGNATURE_SIZE> signature{};  // Ed25519 签名

    std::vector<uint8_t> serialize() const;
    static std::expected<P2PPing, ParseError> parse(std::span<const uint8_t> data);

    // 获取待签名数据
    std::vector<uint8_t> get_sign_data() const;
};

using P2PPong = P2PPing;  // 结构相同

// P2P_KEEPALIVE (0x44) - P2P 连接保活
struct P2PKeepalive {
    uint64_t timestamp = 0;         // 时间戳
    uint32_t seq_num = 0;           // 序列号
    uint8_t flags = 0;              // 0x01 = 请求响应, 0x02 = 响应
    std::array<uint8_t, POLY1305_TAG_SIZE> mac{};  // Poly1305 MAC

    std::vector<uint8_t> serialize() const;
    static std::expected<P2PKeepalive, ParseError> parse(std::span<const uint8_t> data);
};

// P2P_STATUS (0x45) - 上报 P2P 状态给 Controller
struct P2PStatusMsg {
    NodeId peer_node = 0;           // 对端节点 ID
    P2PStatus status = P2PStatus::DISCONNECTED;  // 连接状态
    uint16_t latency_ms = 0;        // 往返延迟（毫秒）
    PathType path_type = PathType::RELAY;  // 路径类型

    std::vector<uint8_t> serialize() const;
    static std::expected<P2PStatusMsg, ParseError> parse(std::span<const uint8_t> data);
};

// ENDPOINT_UPDATE (0x46) - 客户端上报自己的端点
struct EndpointUpdate {
    uint32_t request_id = 0;          // 请求 ID，用于确认匹配
    std::vector<Endpoint> endpoints;  // 本节点的端点列表

    std::vector<uint8_t> serialize() const;
    static std::expected<EndpointUpdate, ParseError> parse(std::span<const uint8_t> data);
};

// ENDPOINT_ACK (0x47) - 端点上报确认
struct EndpointAck {
    uint32_t request_id = 0;          // 对应的请求 ID
    bool success = true;              // 是否成功
    uint8_t endpoint_count = 0;       // 收到的端点数量

    std::vector<uint8_t> serialize() const;
    static std::expected<EndpointAck, ParseError> parse(std::span<const uint8_t> data);
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

#pragma once

#include <cstdint>

namespace edgelink {

// ============================================================================
// 共享状态定义 - Client/Controller/Relay 共用
// ============================================================================
// 这些状态定义用于在各组件之间保持一致的状态视图

// ============================================================================
// 客户端会话状态 - Controller 视角下的客户端状态
// ============================================================================
enum class ClientSessionState : uint8_t {
    DISCONNECTED = 0,   // 未连接
    AUTHENTICATING,     // 认证中（收到 AUTH_REQUEST，等待验证）
    AUTHENTICATED,      // 已认证（认证成功，等待 Relay 连接）
    CONFIGURING,        // 配置中（已发送 CONFIG，等待 ACK）
    ONLINE,             // 在线（Control + Relay 都已连接）
    DEGRADED,           // 降级（Control 连接但 Relay 断开）
};

const char* client_session_state_name(ClientSessionState state);

// ============================================================================
// 控制面状态 - Client 视角下与 Controller 的连接状态
// ============================================================================
enum class ControlPlaneState : uint8_t {
    DISCONNECTED = 0,   // 未连接
    CONNECTING,         // 连接中
    AUTHENTICATING,     // 认证中（等待 AUTH_RESPONSE）
    CONFIGURING,        // 配置中（等待 CONFIG）
    READY,              // 就绪（已认证、已配置）
    RECONNECTING,       // 重连中
};

const char* control_plane_state_name(ControlPlaneState state);

// ============================================================================
// 数据面状态 - Client 视角下数据传输通道状态
// ============================================================================
enum class DataPlaneState : uint8_t {
    OFFLINE = 0,        // 离线（无可用数据通道）
    RELAY_ONLY,         // 仅 Relay（Relay 已连接，P2P 未就绪）
    HYBRID,             // 混合（Relay + 部分 P2P）
    DEGRADED,           // 降级（Relay 断开，仅部分 P2P）
};

const char* data_plane_state_name(DataPlaneState state);

// ============================================================================
// 整体连接阶段 - Client 总体状态（组合控制面+数据面）
// ============================================================================
enum class ConnectionPhase : uint8_t {
    OFFLINE = 0,        // 未连接
    AUTHENTICATING,     // 认证中（控制面连接中）
    CONFIGURING,        // 配置中（等待 CONFIG）
    ESTABLISHING,       // 建立中（数据面连接中）
    ONLINE,             // 在线（控制面+数据面就绪）
    RECONNECTING,       // 重连中
};

const char* connection_phase_name(ConnectionPhase phase);

// ============================================================================
// 端点同步状态 - Client 视角下本节点端点的发现和上报状态
// ============================================================================
enum class ClientEndpointSyncState : uint8_t {
    NOT_READY = 0,      // 未就绪（UDP socket 未初始化）
    DISCOVERING,        // 发现中（STUN 查询中）
    READY,              // 就绪（端点已发现）
    UPLOADING,          // 上报中（等待 ACK）
    SYNCED,             // 已同步（Controller 已确认）
};

const char* client_endpoint_sync_state_name(ClientEndpointSyncState state);

// ============================================================================
// 路由同步状态 - Client 视角
// ============================================================================
enum class RouteSyncState : uint8_t {
    DISABLED = 0,       // 禁用（不接受路由）
    PENDING,            // 待同步
    SYNCING,            // 同步中
    SYNCED,             // 已同步
};

const char* route_sync_state_name(RouteSyncState state);

// ============================================================================
// 对端数据路径 - Client 视角下每个对端的数据传输路径
// ============================================================================
enum class PeerDataPath : uint8_t {
    UNKNOWN = 0,        // 未知（未尝试连接）
    RELAY,              // 通过 Relay 转发
    P2P,                // 通过 P2P 直连
    UNREACHABLE,        // 不可达（对端离线或所有路径失败）
};

const char* peer_data_path_name(PeerDataPath path);

// ============================================================================
// P2P 连接状态 - Client 视角的 P2P 打洞流程
// ============================================================================
enum class P2PConnectionState : uint8_t {
    NONE = 0,           // 未发起
    INITIATING,         // 发起中（发送 P2P_INIT）
    WAITING_ENDPOINT,   // 等待端点（等待 P2P_ENDPOINT）
    PUNCHING,           // 打洞中（发送 UDP 打洞包）
    CONNECTED,          // 已连接
    FAILED,             // 失败（等待重试）
};

const char* p2p_connection_state_name(P2PConnectionState state);

// ============================================================================
// Relay 连接状态 - Client 视角（支持多 Relay）
// ============================================================================
enum class RelayConnectionState : uint8_t {
    DISCONNECTED = 0,   // 未连接
    CONNECTING,         // 连接中
    AUTHENTICATING,     // 认证中
    CONNECTED,          // 已连接
    RECONNECTING,       // 重连中
};

const char* relay_connection_state_name(RelayConnectionState state);

// ============================================================================
// Relay 会话状态 - Controller 视角下的 Relay 连接状态
// ============================================================================
enum class RelaySessionState : uint8_t {
    DISCONNECTED = 0,   // 未连接
    AUTHENTICATING,     // 认证中（收到 RELAY_AUTH，等待验证）
    CONNECTED,          // 已连接
    RECONNECTING,       // 重连中
};

const char* relay_session_state_name(RelaySessionState state);

// ============================================================================
// P2P 协商状态 - Controller 视角下的 P2P 状态
// ============================================================================
enum class P2PNegotiationPhase : uint8_t {
    NONE = 0,           // 未发起
    INITIATED,          // 已发起（收到 P2P_INIT）
    ENDPOINTS_SENT,     // 已发送端点（已发送 P2P_ENDPOINT）
    ESTABLISHED,        // 已建立（收到 P2P_STATUS 确认）
    FAILED,             // 失败
};

const char* p2p_negotiation_phase_name(P2PNegotiationPhase phase);

// ============================================================================
// 端点同步状态 - Controller 视角
// ============================================================================
enum class EndpointState : uint8_t {
    UNKNOWN = 0,        // 未知
    PENDING,            // 待同步（收到 ENDPOINT_UPDATE）
    SYNCED,             // 已同步（已发送 ENDPOINT_ACK）
};

const char* endpoint_state_name(EndpointState state);

// ============================================================================
// 路由状态 - Controller 视角
// ============================================================================
enum class RouteState : uint8_t {
    NONE = 0,           // 无路由
    ANNOUNCED,          // 已公告
    WITHDRAWN,          // 已撤销
};

const char* route_state_name(RouteState state);

// ============================================================================
// 会话事件 - 驱动状态转换
// ============================================================================
enum class SessionEvent : uint8_t {
    // 连接事件
    CONTROL_CONNECT,        // Control 连接建立
    CONTROL_DISCONNECT,     // Control 连接断开
    RELAY_CONNECT,          // Relay 连接建立
    RELAY_DISCONNECT,       // Relay 连接断开

    // 认证事件
    AUTH_REQUEST,           // 收到认证请求
    AUTH_SUCCESS,           // 认证成功
    AUTH_FAILED,            // 认证失败

    // 配置事件
    CONFIG_SENT,            // 配置已发送
    CONFIG_ACK,             // 收到配置确认

    // 端点事件
    ENDPOINT_UPDATE,        // 收到端点更新
    ENDPOINT_ACK_SENT,      // 端点确认已发送

    // P2P 事件
    P2P_INIT_RECEIVED,      // 收到 P2P_INIT
    P2P_ENDPOINT_SENT,      // P2P_ENDPOINT 已发送
    P2P_STATUS_RECEIVED,    // 收到 P2P_STATUS

    // 路由事件
    ROUTE_ANNOUNCE,         // 收到路由公告
    ROUTE_WITHDRAW,         // 收到路由撤销

    // 心跳事件
    PING_RECEIVED,          // 收到 PING
    PONG_SENT,              // PONG 已发送
    HEARTBEAT_TIMEOUT,      // 心跳超时
};

const char* session_event_name(SessionEvent event);

} // namespace edgelink

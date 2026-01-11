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

#pragma once

#include "common/types.hpp"
#include "common/connection_types.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <optional>

namespace edgelink::controller {

// ============================================================================
// Controller 端客户端会话状态机
// ============================================================================
// 管理 Controller 视角下每个客户端的连接状态、端点信息、P2P 协商等

// ============================================================================
// 单个客户端的完整状态
// ============================================================================
struct ClientState {
    NodeId node_id = 0;
    NetworkId network_id = 0;

    // ========== 会话状态 ==========
    ClientSessionState session_state = ClientSessionState::DISCONNECTED;
    RelaySessionState relay_state = RelaySessionState::DISCONNECTED;

    // ========== 认证信息 ==========
    std::string auth_key_hash;              // 认证密钥哈希
    uint64_t auth_time = 0;                 // 认证时间
    std::array<uint8_t, 32> session_key{};  // 会话密钥

    // ========== 端点信息 ==========
    EndpointState endpoint_state = EndpointState::UNKNOWN;
    std::vector<Endpoint> endpoints;        // 客户端上报的端点列表
    uint64_t endpoint_update_time = 0;      // 端点更新时间

    // ========== 配置同步 ==========
    uint64_t config_version = 0;            // 已发送的配置版本
    bool config_acked = false;              // 配置是否已确认
    uint64_t config_send_time = 0;          // 配置发送时间

    // ========== 心跳信息 ==========
    uint64_t last_ping_time = 0;            // 上次收到 PING 时间
    uint64_t last_pong_time = 0;            // 上次发送 PONG 时间
    uint16_t latency_ms = 0;                // 延迟（客户端上报）

    // ========== 路由信息 ==========
    std::vector<RouteInfo> announced_routes;  // 客户端公告的路由
    uint64_t route_update_time = 0;         // 路由更新时间

    // ========== P2P 协商（与其他客户端）==========
    struct P2PNegotiation {
        NodeId peer_id = 0;
        P2PNegotiationPhase phase = P2PNegotiationPhase::NONE;
        uint32_t init_seq = 0;              // P2P_INIT 序列号
        uint64_t init_time = 0;             // 发起时间
        uint64_t endpoint_send_time = 0;    // 端点发送时间
    };
    std::unordered_map<NodeId, P2PNegotiation> p2p_negotiations;

    // ========== 辅助方法 ==========
    bool is_online() const {
        return session_state == ClientSessionState::ONLINE;
    }

    bool is_authenticated() const {
        return session_state != ClientSessionState::DISCONNECTED &&
               session_state != ClientSessionState::AUTHENTICATING;
    }

    bool has_relay() const {
        return relay_state == RelaySessionState::CONNECTED;
    }
};

// ============================================================================
// 状态变更回调
// ============================================================================
struct SessionStateCallbacks {
    // 客户端会话状态变更
    std::function<void(NodeId node_id, ClientSessionState old_state, ClientSessionState new_state)>
        on_session_state_change;

    // Relay 会话状态变更
    std::function<void(NodeId node_id, RelaySessionState old_state, RelaySessionState new_state)>
        on_relay_state_change;

    // 客户端上线
    std::function<void(NodeId node_id, NetworkId network_id)> on_client_online;

    // 客户端下线
    std::function<void(NodeId node_id, NetworkId network_id)> on_client_offline;

    // 端点更新
    std::function<void(NodeId node_id, const std::vector<Endpoint>& endpoints)>
        on_endpoint_update;

    // 路由更新
    std::function<void(NodeId node_id, const std::vector<RouteInfo>& added,
                       const std::vector<RouteInfo>& removed)>
        on_route_update;

    // P2P 协商状态变更
    std::function<void(NodeId initiator, NodeId responder, P2PNegotiationPhase phase)>
        on_p2p_negotiation_change;
};

// ============================================================================
// 客户端会话状态机
// ============================================================================
class ClientSessionStateMachine {
public:
    ClientSessionStateMachine();
    ~ClientSessionStateMachine() = default;

    // 禁止拷贝
    ClientSessionStateMachine(const ClientSessionStateMachine&) = delete;
    ClientSessionStateMachine& operator=(const ClientSessionStateMachine&) = delete;

    // ========================================================================
    // 配置
    // ========================================================================

    // 设置回调
    void set_callbacks(SessionStateCallbacks callbacks);

    // 设置超时参数
    void set_auth_timeout(uint32_t ms) { auth_timeout_ms_ = ms; }
    void set_config_ack_timeout(uint32_t ms) { config_ack_timeout_ms_ = ms; }
    void set_heartbeat_timeout(uint32_t ms) { heartbeat_timeout_ms_ = ms; }
    void set_p2p_timeout(uint32_t ms) { p2p_timeout_ms_ = ms; }

    // ========================================================================
    // 事件处理 - 驱动状态转换
    // ========================================================================

    // 处理会话事件
    void handle_event(NodeId node_id, SessionEvent event);

    // 处理认证请求
    void handle_auth_request(NodeId node_id, NetworkId network_id,
                             const std::string& auth_key_hash,
                             const std::array<uint8_t, 32>& session_key);

    // 处理认证结果
    void handle_auth_result(NodeId node_id, bool success);

    // 处理端点更新
    void handle_endpoint_update(NodeId node_id, const std::vector<Endpoint>& endpoints);

    // 处理路由公告
    void handle_route_announce(NodeId node_id, const std::vector<RouteInfo>& routes);

    // 处理路由撤销
    void handle_route_withdraw(NodeId node_id, const std::vector<RouteInfo>& routes);

    // 处理 P2P_INIT
    void handle_p2p_init(NodeId initiator, NodeId responder, uint32_t seq);

    // 处理 P2P_STATUS
    void handle_p2p_status(NodeId node_id, NodeId peer_id, bool success);

    // ========================================================================
    // 状态查询
    // ========================================================================

    // 获取客户端状态
    std::optional<ClientState> get_client_state(NodeId node_id) const;

    // 获取所有在线客户端
    std::vector<NodeId> get_online_clients() const;

    // 获取网络中的所有客户端
    std::vector<NodeId> get_network_clients(NetworkId network_id) const;

    // 获取客户端端点
    std::vector<Endpoint> get_client_endpoints(NodeId node_id) const;

    // 获取客户端路由
    std::vector<RouteInfo> get_client_routes(NodeId node_id) const;

    // 检查客户端是否在线
    bool is_client_online(NodeId node_id) const;

    // 检查客户端是否有 Relay 连接
    bool has_client_relay(NodeId node_id) const;

    // ========================================================================
    // 客户端管理
    // ========================================================================

    // 添加客户端（Control 连接时）
    void add_client(NodeId node_id);

    // 移除客户端（断开连接时）
    void remove_client(NodeId node_id);

    // 更新客户端延迟
    void update_client_latency(NodeId node_id, uint16_t latency_ms);

    // 记录心跳
    void record_ping(NodeId node_id);
    void record_pong(NodeId node_id);

    // ========================================================================
    // 超时检测
    // ========================================================================

    // 检查所有超时（由定时器调用）
    void check_timeouts();

    // 获取当前时间（微秒）
    static uint64_t now_us();

    // ========================================================================
    // 重置
    // ========================================================================

    // 重置所有状态
    void reset();

private:
    // 内部状态转换
    void set_session_state(NodeId node_id, ClientSessionState new_state);
    void set_relay_state(NodeId node_id, RelaySessionState new_state);

    // 更新组合状态
    void update_session_state(NodeId node_id);

    // 获取可修改的客户端状态
    ClientState* get_client_state_mut(NodeId node_id);

    // 客户端状态
    mutable std::shared_mutex clients_mutex_;
    std::unordered_map<NodeId, ClientState> client_states_;

    // 回调
    SessionStateCallbacks callbacks_;

    // 超时参数（毫秒）
    uint32_t auth_timeout_ms_ = 10000;          // 认证超时
    uint32_t config_ack_timeout_ms_ = 5000;     // 配置确认超时
    uint32_t heartbeat_timeout_ms_ = 30000;     // 心跳超时
    uint32_t p2p_timeout_ms_ = 10000;           // P2P 协商超时
};

} // namespace edgelink::controller

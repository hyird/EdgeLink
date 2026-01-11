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

namespace edgelink {

// ============================================================================
// 统一节点状态机
// ============================================================================
// 用于 Client、Controller、Relay 三方共享的状态管理
// 每个节点维护其他节点的状态视图，通过协议消息同步

// ============================================================================
// 节点角色
// ============================================================================
enum class NodeRole : uint8_t {
    CLIENT = 0,         // 客户端节点
    CONTROLLER,         // 控制器节点
    RELAY,              // 中继节点
};

const char* node_role_name(NodeRole role);

// ============================================================================
// 节点连接状态
// ============================================================================
enum class NodeConnectionState : uint8_t {
    OFFLINE = 0,        // 离线
    CONNECTING,         // 连接中
    AUTHENTICATING,     // 认证中
    ONLINE,             // 在线
    DEGRADED,           // 降级（部分连接可用）
    RECONNECTING,       // 重连中
};

const char* node_connection_state_name(NodeConnectionState state);

// ============================================================================
// 数据通道状态
// ============================================================================
enum class DataChannelState : uint8_t {
    NONE = 0,           // 无数据通道
    RELAY_ONLY,         // 仅通过 Relay
    P2P_ONLY,           // 仅通过 P2P
    HYBRID,             // 混合模式（Relay + P2P）
};

const char* data_channel_state_name(DataChannelState state);

// ============================================================================
// P2P 连接状态
// ============================================================================
enum class P2PConnectionState : uint8_t {
    NONE = 0,           // 未发起
    INITIATING,         // 发起中（发送 P2P_INIT）
    WAITING_ENDPOINT,   // 等待端点
    PUNCHING,           // 打洞中
    CONNECTED,          // 已连接
    FAILED,             // 失败
};

const char* p2p_connection_state_name(P2PConnectionState state);

// ============================================================================
// 节点详细状态
// ============================================================================
struct NodeState {
    NodeId node_id = 0;
    NetworkId network_id = 0;
    NodeRole role = NodeRole::CLIENT;

    // ========== 连接状态 ==========
    NodeConnectionState connection_state = NodeConnectionState::OFFLINE;
    DataChannelState data_channel = DataChannelState::NONE;

    // ========== 虚拟 IP ==========
    IPv4Address virtual_ip{};

    // ========== 端点信息 ==========
    std::vector<Endpoint> endpoints;
    uint64_t endpoint_update_time = 0;
    bool endpoint_synced = false;

    // ========== 路由信息 ==========
    std::vector<RouteInfo> announced_routes;
    uint64_t route_update_time = 0;

    // ========== 延迟信息 ==========
    uint16_t latency_ms = 0;
    uint64_t last_ping_time = 0;
    uint64_t last_seen_time = 0;

    // ========== P2P 连接状态（与其他节点）==========
    struct P2PLink {
        NodeId peer_id = 0;
        P2PConnectionState state = P2PConnectionState::NONE;
        uint32_t init_seq = 0;
        std::vector<Endpoint> peer_endpoints;
        Endpoint active_endpoint{};         // 当前活跃端点
        uint64_t connect_time = 0;
        uint64_t last_recv_time = 0;
        uint16_t rtt_ms = 0;
        uint32_t punch_failures = 0;
    };
    std::unordered_map<NodeId, P2PLink> p2p_links;

    // ========== 辅助方法 ==========
    bool is_online() const {
        return connection_state == NodeConnectionState::ONLINE ||
               connection_state == NodeConnectionState::DEGRADED;
    }

    bool has_p2p(NodeId peer_id) const {
        auto it = p2p_links.find(peer_id);
        return it != p2p_links.end() && it->second.state == P2PConnectionState::CONNECTED;
    }

    bool can_reach(NodeId peer_id) const {
        return data_channel != DataChannelState::NONE || has_p2p(peer_id);
    }
};

// ============================================================================
// 节点事件
// ============================================================================
enum class NodeEvent : uint8_t {
    // 连接事件
    CONNECT,                // 连接
    DISCONNECT,             // 断开
    AUTH_SUCCESS,           // 认证成功
    AUTH_FAILED,            // 认证失败

    // 数据通道事件
    RELAY_CONNECTED,        // Relay 已连接
    RELAY_DISCONNECTED,     // Relay 断开
    P2P_CONNECTED,          // P2P 已连接
    P2P_DISCONNECTED,       // P2P 断开

    // 同步事件
    ENDPOINT_UPDATE,        // 端点更新
    ENDPOINT_SYNCED,        // 端点已同步
    ROUTE_ANNOUNCE,         // 路由公告
    ROUTE_WITHDRAW,         // 路由撤销

    // P2P 协商事件
    P2P_INIT,               // P2P 初始化
    P2P_ENDPOINT_RECEIVED,  // 收到对端端点
    P2P_PUNCH_START,        // 开始打洞
    P2P_PUNCH_SUCCESS,      // 打洞成功
    P2P_PUNCH_FAILED,       // 打洞失败
    P2P_KEEPALIVE_TIMEOUT,  // P2P 保活超时

    // 心跳事件
    PING,                   // 收到 PING
    PONG,                   // 收到 PONG
    HEARTBEAT_TIMEOUT,      // 心跳超时
};

const char* node_event_name(NodeEvent event);

// ============================================================================
// 状态变更回调
// ============================================================================
struct NodeStateCallbacks {
    // 连接状态变更
    std::function<void(NodeId node_id, NodeConnectionState old_state, NodeConnectionState new_state)>
        on_connection_state_change;

    // 数据通道变更
    std::function<void(NodeId node_id, DataChannelState old_state, DataChannelState new_state)>
        on_data_channel_change;

    // 节点上线/下线
    std::function<void(NodeId node_id, bool online)> on_node_status_change;

    // 端点更新
    std::function<void(NodeId node_id, const std::vector<Endpoint>& endpoints)>
        on_endpoint_update;

    // 路由变更
    std::function<void(NodeId node_id, const std::vector<RouteInfo>& added,
                       const std::vector<RouteInfo>& removed)>
        on_route_change;

    // P2P 状态变更
    std::function<void(NodeId node_id, NodeId peer_id, P2PConnectionState old_state, P2PConnectionState new_state)>
        on_p2p_state_change;
};

// ============================================================================
// 统一节点状态机
// ============================================================================
class NodeStateMachine {
public:
    NodeStateMachine(NodeId self_id, NodeRole self_role);
    ~NodeStateMachine() = default;

    // 禁止拷贝
    NodeStateMachine(const NodeStateMachine&) = delete;
    NodeStateMachine& operator=(const NodeStateMachine&) = delete;

    // ========================================================================
    // 配置
    // ========================================================================

    // 设置回调
    void set_callbacks(NodeStateCallbacks callbacks);

    // 设置超时参数（毫秒）
    void set_p2p_punch_timeout(uint32_t ms) { p2p_punch_timeout_ms_ = ms; }
    void set_p2p_keepalive_timeout(uint32_t ms) { p2p_keepalive_timeout_ms_ = ms; }
    void set_heartbeat_timeout(uint32_t ms) { heartbeat_timeout_ms_ = ms; }
    void set_p2p_retry_interval(uint32_t ms) { p2p_retry_interval_ms_ = ms; }

    // ========================================================================
    // 自身信息
    // ========================================================================

    NodeId self_id() const { return self_id_; }
    NodeRole self_role() const { return self_role_; }

    // ========================================================================
    // 事件处理
    // ========================================================================

    // 处理节点事件
    void handle_event(NodeId node_id, NodeEvent event);

    // 处理 P2P 事件
    void handle_p2p_event(NodeId node_id, NodeId peer_id, NodeEvent event);

    // ========================================================================
    // 节点管理
    // ========================================================================

    // 添加节点
    void add_node(NodeId node_id, NetworkId network_id, NodeRole role = NodeRole::CLIENT);

    // 移除节点
    void remove_node(NodeId node_id);

    // 更新节点端点
    void update_node_endpoints(NodeId node_id, const std::vector<Endpoint>& endpoints);

    // 更新节点路由
    void update_node_routes(NodeId node_id, const std::vector<RouteInfo>& add_routes,
                            const std::vector<RouteInfo>& del_routes);

    // 更新节点 IP
    void update_node_ip(NodeId node_id, const IPv4Address& ip);

    // 更新节点延迟
    void update_node_latency(NodeId node_id, uint16_t latency_ms);

    // 记录节点活动
    void record_node_activity(NodeId node_id);

    // ========================================================================
    // P2P 管理
    // ========================================================================

    // 发起 P2P 连接
    void initiate_p2p(NodeId peer_id, uint32_t seq);

    // 收到对端端点
    void receive_peer_endpoints(NodeId peer_id, const std::vector<Endpoint>& endpoints);

    // 设置活跃 P2P 端点
    void set_active_p2p_endpoint(NodeId peer_id, const Endpoint& endpoint);

    // 更新 P2P RTT
    void update_p2p_rtt(NodeId peer_id, uint16_t rtt_ms);

    // ========================================================================
    // 状态查询
    // ========================================================================

    // 获取节点状态
    std::optional<NodeState> get_node_state(NodeId node_id) const;

    // 获取所有在线节点
    std::vector<NodeId> get_online_nodes() const;

    // 获取网络中的节点
    std::vector<NodeId> get_network_nodes(NetworkId network_id) const;

    // 获取节点端点
    std::vector<Endpoint> get_node_endpoints(NodeId node_id) const;

    // 获取节点路由
    std::vector<RouteInfo> get_node_routes(NodeId node_id) const;

    // 获取 P2P 已连接的节点
    std::vector<NodeId> get_p2p_connected_nodes() const;

    // 获取需要 P2P 重试的节点
    std::vector<NodeId> get_p2p_retry_nodes() const;

    // 检查节点是否在线
    bool is_node_online(NodeId node_id) const;

    // 检查是否有 P2P 连接
    bool has_p2p_connection(NodeId peer_id) const;

    // ========================================================================
    // 超时检测
    // ========================================================================

    // 检查所有超时
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
    void set_connection_state(NodeId node_id, NodeConnectionState new_state);
    void set_data_channel_state(NodeId node_id, DataChannelState new_state);
    void set_p2p_state(NodeId node_id, NodeId peer_id, P2PConnectionState new_state);

    // 更新组合状态
    void update_data_channel_state(NodeId node_id);

    // 获取可修改的节点状态
    NodeState* get_node_state_mut(NodeId node_id);

    // 自身信息
    NodeId self_id_;
    NodeRole self_role_;

    // 节点状态
    mutable std::shared_mutex nodes_mutex_;
    std::unordered_map<NodeId, NodeState> node_states_;

    // 回调
    NodeStateCallbacks callbacks_;

    // 超时参数（毫秒）
    uint32_t p2p_punch_timeout_ms_ = 10000;
    uint32_t p2p_keepalive_timeout_ms_ = 3000;
    uint32_t heartbeat_timeout_ms_ = 30000;
    uint32_t p2p_retry_interval_ms_ = 60000;
};

} // namespace edgelink

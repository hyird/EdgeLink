#pragma once

#include "common/types.hpp"
#include "common/connection_types.hpp"
#include <array>
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

    // ========== 通用连接状态 ==========
    NodeConnectionState connection_state = NodeConnectionState::OFFLINE;
    DataChannelState data_channel = DataChannelState::NONE;

    // ========== Controller 视角的会话状态 ==========
    ClientSessionState session_state = ClientSessionState::DISCONNECTED;
    RelaySessionState relay_state = RelaySessionState::DISCONNECTED;

    // ========== Client 视角的控制面/数据面状态 ==========
    ControlPlaneState control_plane = ControlPlaneState::DISCONNECTED;
    DataPlaneState data_plane = DataPlaneState::OFFLINE;
    ConnectionPhase connection_phase = ConnectionPhase::OFFLINE;
    ClientEndpointSyncState endpoint_sync = ClientEndpointSyncState::NOT_READY;
    RouteSyncState route_sync = RouteSyncState::DISABLED;

    // ========== 认证信息 ==========
    std::string auth_key_hash;
    uint64_t auth_time = 0;
    std::array<uint8_t, 32> session_key{};

    // ========== 配置同步 ==========
    uint64_t config_version = 0;
    bool config_acked = false;
    uint64_t config_send_time = 0;

    // ========== 虚拟 IP ==========
    IPv4Address virtual_ip{};

    // ========== 端点信息 ==========
    std::vector<Endpoint> endpoints;
    uint64_t endpoint_update_time = 0;
    uint64_t endpoint_upload_time = 0;   // Client 端：端点上报时间
    bool endpoint_synced = false;
    EndpointState endpoint_state = EndpointState::UNKNOWN;  // Controller 视角

    // ========== 路由信息 ==========
    std::vector<RouteInfo> announced_routes;
    uint64_t route_update_time = 0;

    // ========== 延迟信息 ==========
    uint16_t latency_ms = 0;
    uint64_t last_ping_time = 0;
    uint64_t last_seen_time = 0;

    // ========== Relay 连接信息（Client 端使用，支持多 Relay）==========
    struct RelayConnection {
        std::string relay_id;
        RelayConnectionState state = RelayConnectionState::DISCONNECTED;
        uint64_t last_connect_time = 0;
        uint64_t last_recv_time = 0;
        uint64_t last_send_time = 0;
        uint16_t latency_ms = 0;
        uint32_t reconnect_count = 0;
        bool is_primary = false;

        bool is_connected() const {
            return state == RelayConnectionState::CONNECTED;
        }
    };
    std::unordered_map<std::string, RelayConnection> relay_connections;
    std::string primary_relay_id;

    // ========== P2P 连接状态（与其他节点）==========
    struct P2PLink {
        NodeId peer_id = 0;
        P2PConnectionState state = P2PConnectionState::NONE;
        uint32_t init_seq = 0;
        std::vector<Endpoint> peer_endpoints;
        Endpoint active_endpoint{};             // 当前活跃端点
        uint64_t connect_time = 0;
        uint64_t last_recv_time = 0;
        uint64_t last_send_time = 0;            // Client 端：上次发送时间
        uint16_t rtt_ms = 0;
        uint32_t punch_failures = 0;

        // Client 端扩展字段
        PeerDataPath data_path = PeerDataPath::UNKNOWN;
        PeerLinkState link_state = PeerLinkState::UNKNOWN;
        uint64_t last_resolve_time = 0;         // 上次发送 P2P_INIT 时间
        uint64_t last_endpoint_time = 0;        // 上次收到 P2P_ENDPOINT 时间
        uint64_t last_punch_time = 0;           // 上次发送打洞包时间
        uint32_t punch_count = 0;               // 打洞次数
        uint64_t next_retry_time = 0;           // 下次重试时间
        std::array<uint8_t, 16> p2p_addr{};     // P2P 对端地址（IPv6 格式）
        uint16_t p2p_port = 0;                  // P2P 对端端口

        // 辅助方法
        bool can_send_p2p() const {
            return data_path == PeerDataPath::P2P;
        }

        bool is_online() const {
            return data_path != PeerDataPath::UNKNOWN &&
                   data_path != PeerDataPath::UNREACHABLE;
        }
    };
    std::unordered_map<NodeId, P2PLink> p2p_links;

    // ========== P2P 协商状态（Controller 视角，与其他客户端）==========
    struct P2PNegotiation {
        NodeId peer_id = 0;
        P2PNegotiationPhase phase = P2PNegotiationPhase::NONE;
        uint32_t init_seq = 0;
        uint64_t init_time = 0;
        uint64_t endpoint_send_time = 0;
    };
    std::unordered_map<NodeId, P2PNegotiation> p2p_negotiations;

    // ========== P2P_INIT 序列号（Client 端使用）==========
    uint32_t next_init_seq = 0;

    // ========== 辅助方法 ==========
    bool is_online() const {
        return connection_state == NodeConnectionState::ONLINE ||
               connection_state == NodeConnectionState::DEGRADED;
    }

    // Controller 视角：会话是否在线
    bool is_session_online() const {
        return session_state == ClientSessionState::ONLINE;
    }

    // Controller 视角：是否已认证
    bool is_authenticated() const {
        return session_state != ClientSessionState::DISCONNECTED &&
               session_state != ClientSessionState::AUTHENTICATING;
    }

    // Controller 视角：是否有 Relay 连接
    bool has_relay() const {
        return relay_state == RelaySessionState::CONNECTED;
    }

    // Client 视角：控制面是否就绪
    bool is_control_ready() const {
        return control_plane == ControlPlaneState::READY;
    }

    // Client 视角：是否有数据通道
    bool has_data_path() const {
        return data_plane != DataPlaneState::OFFLINE;
    }

    // Client 视角：端点是否已同步
    bool is_endpoint_synced() const {
        return endpoint_sync == ClientEndpointSyncState::SYNCED;
    }

    // Client 视角：是否有已连接的 Relay
    bool has_connected_relay() const {
        for (const auto& [id, relay] : relay_connections) {
            if (relay.is_connected()) return true;
        }
        return false;
    }

    // Client 视角：获取已连接的 Relay 数量
    size_t connected_relay_count() const {
        size_t count = 0;
        for (const auto& [id, relay] : relay_connections) {
            if (relay.is_connected()) ++count;
        }
        return count;
    }

    bool has_p2p(NodeId peer_id) const {
        auto it = p2p_links.find(peer_id);
        return it != p2p_links.end() && it->second.state == P2PConnectionState::CONNECTED;
    }

    bool can_reach(NodeId peer_id) const {
        return data_channel != DataChannelState::NONE || has_p2p(peer_id);
    }

    // Client 视角：获取对端的链路状态
    PeerLinkState get_peer_link_state(NodeId peer_id) const {
        auto it = p2p_links.find(peer_id);
        if (it == p2p_links.end()) return PeerLinkState::UNKNOWN;
        return it->second.link_state;
    }

    // Client 视角：获取对端的数据路径
    PeerDataPath get_peer_data_path(NodeId peer_id) const {
        auto it = p2p_links.find(peer_id);
        if (it == p2p_links.end()) return PeerDataPath::UNKNOWN;
        return it->second.data_path;
    }

    // Client 视角：判断对端是否可通过 P2P 发送
    bool is_peer_p2p_ready(NodeId peer_id) const {
        auto it = p2p_links.find(peer_id);
        if (it == p2p_links.end()) return false;
        return it->second.can_send_p2p();
    }
};

// ============================================================================
// 节点事件
// ============================================================================
enum class NodeEvent : uint8_t {
    // ========== 通用连接事件 ==========
    CONNECT,                // 连接
    DISCONNECT,             // 断开

    // ========== Client 控制面事件 ==========
    START_CONNECT,          // 开始连接（Client 端）
    CONTROL_CONNECTED,      // Control 连接建立（Client 端）
    CONTROL_DISCONNECTED,   // Control 连接断开（Client 端）

    // ========== 认证事件 ==========
    AUTH_REQUEST,           // 收到认证请求（Controller 端）
    AUTH_SUCCESS,           // 认证成功
    AUTH_FAILED,            // 认证失败

    // ========== 配置事件 ==========
    CONFIG_SENT,            // 配置已发送（Controller 端）
    CONFIG_RECEIVED,        // 收到配置（Client 端）
    CONFIG_ACK,             // 收到配置确认

    // ========== Relay 事件 ==========
    RELAY_AUTH,             // Relay 认证请求
    RELAY_AUTH_SUCCESS,     // Relay 认证成功
    RELAY_CONNECTING,       // Relay 连接中（Client 端）
    RELAY_CONNECTED,        // Relay 已连接
    RELAY_DISCONNECTED,     // Relay 断开
    RELAY_RECONNECTING,     // Relay 重连中

    // ========== P2P 数据通道事件 ==========
    P2P_CONNECTED,          // P2P 已连接
    P2P_DISCONNECTED,       // P2P 断开

    // ========== 端点同步事件 ==========
    SOCKET_READY,           // UDP Socket 就绪（Client 端）
    STUN_SUCCESS,           // STUN 查询成功（Client 端）
    STUN_FAILED,            // STUN 查询失败（Client 端）
    ENDPOINT_UPDATE,        // 端点更新
    ENDPOINT_UPLOADED,      // 端点已上报（Client 端）
    ENDPOINT_ACK,           // 端点确认
    ENDPOINT_SYNCED,        // 端点已同步

    // ========== 路由事件 ==========
    ROUTE_ANNOUNCE,         // 路由公告
    ROUTE_WITHDRAW,         // 路由撤销
    ROUTES_RECEIVED,        // 收到路由（Client 端）
    ROUTES_APPLIED,         // 路由已应用（Client 端）

    // ========== P2P 协商事件 ==========
    P2P_INIT,               // P2P 初始化请求
    P2P_INIT_SENT,          // P2P_INIT 已发送（Client 端）
    P2P_ENDPOINT_SENT,      // P2P 端点已发送（Controller 端）
    P2P_ENDPOINT_RECEIVED,  // 收到对端端点
    P2P_PUNCH_START,        // 开始打洞
    P2P_PUNCH_SUCCESS,      // 打洞成功
    P2P_PUNCH_FAILED,       // 打洞失败
    P2P_PUNCH_TIMEOUT,      // 打洞超时（Client 端）
    P2P_STATUS,             // P2P 状态报告
    P2P_KEEPALIVE_TIMEOUT,  // P2P 保活超时

    // ========== 对端事件（Client 端）==========
    PEER_ONLINE,            // 对端上线
    PEER_OFFLINE,           // 对端下线

    // ========== 心跳事件 ==========
    PING,                   // 收到 PING
    PONG,                   // 收到 PONG
    HEARTBEAT_TIMEOUT,      // 心跳超时
};

const char* node_event_name(NodeEvent event);

// ============================================================================
// 状态变更回调
// ============================================================================
struct NodeStateCallbacks {
    // ========== 通用回调 ==========

    // 连接状态变更
    std::function<void(NodeId node_id, NodeConnectionState old_state, NodeConnectionState new_state)>
        on_connection_state_change;

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

    // ========== Controller 端回调 ==========

    // 会话状态变更（Controller 端使用）
    std::function<void(NodeId node_id, ClientSessionState old_state, ClientSessionState new_state)>
        on_session_state_change;

    // Relay 会话状态变更（Controller 视角）
    std::function<void(NodeId node_id, RelaySessionState old_state, RelaySessionState new_state)>
        on_relay_state_change;

    // 数据通道变更
    std::function<void(NodeId node_id, DataChannelState old_state, DataChannelState new_state)>
        on_data_channel_change;

    // 客户端上线（Controller 端使用）
    std::function<void(NodeId node_id, NetworkId network_id)> on_client_online;

    // 客户端下线（Controller 端使用）
    std::function<void(NodeId node_id, NetworkId network_id)> on_client_offline;

    // P2P 协商状态变更（Controller 端使用）
    std::function<void(NodeId initiator, NodeId responder, P2PNegotiationPhase phase)>
        on_p2p_negotiation_change;

    // ========== Client 端回调 ==========

    // 全局连接阶段变更（Client 端使用）
    std::function<void(ConnectionPhase old_phase, ConnectionPhase new_phase)>
        on_connection_phase_change;

    // 控制面状态变更（Client 端使用）
    std::function<void(ControlPlaneState old_state, ControlPlaneState new_state)>
        on_control_plane_change;

    // 数据面状态变更（Client 端使用）
    std::function<void(DataPlaneState old_state, DataPlaneState new_state)>
        on_data_plane_change;

    // Relay 连接状态变更（Client 端使用，支持多 Relay）
    std::function<void(const std::string& relay_id, RelayConnectionState old_state, RelayConnectionState new_state)>
        on_relay_connection_change;

    // 端点同步状态变更（Client 端使用）
    std::function<void(ClientEndpointSyncState old_state, ClientEndpointSyncState new_state)>
        on_endpoint_sync_change;

    // 路由同步状态变更（Client 端使用）
    std::function<void(RouteSyncState old_state, RouteSyncState new_state)>
        on_route_sync_change;

    // 对端连接状态变更（Client 端使用，组合视图）
    std::function<void(NodeId peer_id, PeerLinkState old_state, PeerLinkState new_state)>
        on_peer_link_state_change;

    // 对端数据路径变更（Client 端使用）
    std::function<void(NodeId peer_id, PeerDataPath old_path, PeerDataPath new_path)>
        on_peer_data_path_change;
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
    // 会话管理（Controller 端使用）
    // ========================================================================

    // 处理认证请求
    void handle_auth_request(NodeId node_id, NetworkId network_id,
                             const std::string& auth_key_hash,
                             const std::array<uint8_t, 32>& session_key);

    // 处理认证结果
    void handle_auth_result(NodeId node_id, bool success);

    // 标记配置已发送
    void mark_config_sent(NodeId node_id, uint64_t config_version);

    // 标记配置已确认
    void mark_config_acked(NodeId node_id);

    // 设置会话状态
    void set_session_state(NodeId node_id, ClientSessionState state);

    // 设置 Relay 会话状态
    void set_relay_session_state(NodeId node_id, RelaySessionState state);

    // 记录心跳
    void record_ping(NodeId node_id);
    void record_pong(NodeId node_id);

    // ========================================================================
    // P2P 协商管理（Controller 端使用）
    // ========================================================================

    // 处理 P2P 初始化请求
    void handle_p2p_init_request(NodeId initiator, NodeId responder, uint32_t seq);

    // 标记 P2P 端点已发送
    void mark_p2p_endpoint_sent(NodeId node_id, NodeId peer_id);

    // 处理 P2P 状态报告
    void handle_p2p_status(NodeId node_id, NodeId peer_id, bool success);

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
    // Client 端控制面/数据面管理
    // ========================================================================

    // 设置控制面状态
    void set_control_plane_state(ControlPlaneState state);

    // 设置数据面状态
    void set_data_plane_state_client(DataPlaneState state);

    // 设置连接阶段
    void set_connection_phase(ConnectionPhase phase);

    // 设置端点同步状态
    void set_endpoint_sync_state(ClientEndpointSyncState state);

    // 设置路由同步状态
    void set_route_sync_state(RouteSyncState state);

    // 更新组合连接阶段（基于控制面和数据面）
    void update_connection_phase();

    // 更新数据面状态（基于 Relay 和 P2P）
    void update_data_plane_state_client();

    // ========================================================================
    // Client 端 Relay 管理（支持多 Relay）
    // ========================================================================

    // 添加 Relay
    void add_relay(const std::string& relay_id, bool is_primary = false);

    // 移除 Relay
    void remove_relay(const std::string& relay_id);

    // 设置主 Relay
    void set_primary_relay(const std::string& relay_id);

    // 设置 Relay 连接状态
    void set_relay_connection_state(const std::string& relay_id, RelayConnectionState state);

    // 更新 Relay 延迟
    void update_relay_latency(const std::string& relay_id, uint16_t latency_ms);

    // 记录 Relay 收发时间
    void record_relay_recv(const std::string& relay_id);
    void record_relay_send(const std::string& relay_id);

    // 获取 Relay 信息
    std::optional<NodeState::RelayConnection> get_relay_info(const std::string& relay_id) const;
    std::vector<NodeState::RelayConnection> get_all_relay_info() const;
    bool has_connected_relay() const;
    size_t connected_relay_count() const;
    std::optional<std::string> get_primary_relay() const;

    // ========================================================================
    // Client 端对端管理
    // ========================================================================

    // 添加对端
    void add_peer(NodeId peer_id);

    // 移除对端
    void remove_peer(NodeId peer_id);

    // 设置对端链路状态
    void set_peer_link_state(NodeId peer_id, PeerLinkState state);

    // 设置对端数据路径
    void set_peer_data_path(NodeId peer_id, PeerDataPath path);

    // 更新对端活跃连接（P2P 成功后调用）
    void update_peer_active_connection(NodeId peer_id,
                                        const std::array<uint8_t, 16>& addr,
                                        uint16_t port,
                                        bool is_p2p);

    // 更新对端延迟
    void update_peer_latency(NodeId peer_id, uint16_t latency_ms);

    // 记录对端收发时间
    void record_peer_recv(NodeId peer_id);
    void record_peer_send(NodeId peer_id);

    // 更新对端链路状态（基于 P2P 和 Relay 状态）
    void update_peer_link_state(NodeId peer_id);

    // 获取对端状态
    PeerLinkState get_peer_link_state(NodeId peer_id) const;
    std::optional<NodeState::P2PLink> get_peer_state(NodeId peer_id) const;
    std::vector<std::pair<NodeId, NodeState::P2PLink>> get_all_peer_states() const;

    // 判断对端是否可通过 P2P 发送
    bool is_peer_p2p_ready(NodeId peer_id) const;

    // 获取需要重试 P2P 的对端列表
    std::vector<NodeId> get_peers_for_retry() const;

    // 获取需要发送 keepalive 的对端列表
    std::vector<NodeId> get_peers_for_keepalive() const;

    // 获取下一个 P2P_INIT 序列号
    uint32_t next_init_seq();

    // ========================================================================
    // Client 端状态查询
    // ========================================================================

    // 获取控制面状态
    ControlPlaneState control_plane_state() const;
    bool is_control_ready() const;

    // 获取数据面状态
    DataPlaneState data_plane_state_client() const;
    bool has_data_path() const;

    // 获取连接阶段
    ConnectionPhase connection_phase() const;
    bool is_client_connected() const;

    // 获取端点同步状态
    ClientEndpointSyncState endpoint_sync_state() const;
    bool is_endpoint_synced() const;

    // 获取路由同步状态
    RouteSyncState route_sync_state() const;

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

    // 检查客户端是否在线（基于会话状态）
    bool is_client_online(NodeId node_id) const;

    // 检查客户端是否有 Relay 连接
    bool has_client_relay(NodeId node_id) const;

    // 获取所有在线客户端（基于会话状态）
    std::vector<NodeId> get_online_clients() const;

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
    // 内部状态转换（Controller 端用于管理其他节点）
    void set_connection_state(NodeId node_id, NodeConnectionState new_state);
    void set_data_channel_state(NodeId node_id, DataChannelState new_state);
    void set_p2p_state(NodeId node_id, NodeId peer_id, P2PConnectionState new_state);
    void set_session_state_internal(NodeId node_id, ClientSessionState new_state);
    void set_relay_state_internal(NodeId node_id, RelaySessionState new_state);
    void set_p2p_negotiation_phase(NodeId node_id, NodeId peer_id, P2PNegotiationPhase phase);

    // 内部状态转换（Client 端自身状态）
    void set_control_plane_state_internal(ControlPlaneState new_state);
    void set_data_plane_state_internal(DataPlaneState new_state);
    void set_connection_phase_internal(ConnectionPhase new_phase);
    void set_endpoint_sync_state_internal(ClientEndpointSyncState new_state);
    void set_route_sync_state_internal(RouteSyncState new_state);
    void set_relay_connection_state_internal(const std::string& relay_id, RelayConnectionState new_state);
    void set_peer_link_state_internal(NodeId peer_id, PeerLinkState new_state);
    void set_peer_data_path_internal(NodeId peer_id, PeerDataPath new_path);

    // 更新组合状态（Controller 端）
    void update_data_channel_state(NodeId node_id);
    void update_session_state(NodeId node_id);

    // 获取可修改的节点状态
    NodeState* get_node_state_mut(NodeId node_id);

    // 获取可修改的 P2P 链路状态（Client 端自身的对端）
    NodeState::P2PLink* get_peer_link_mut(NodeId peer_id);

    // 获取可修改的 Relay 连接状态（Client 端自身）
    NodeState::RelayConnection* get_relay_connection_mut(const std::string& relay_id);

    // 自身信息
    NodeId self_id_;
    NodeRole self_role_;

    // 节点状态（Controller 端：管理其他节点的状态）
    mutable std::shared_mutex nodes_mutex_;
    std::unordered_map<NodeId, NodeState> node_states_;

    // Client 端自身状态
    NodeState self_state_;  // 存储自身的状态（包括 Relay 连接、对端 P2P 链路等）

    // 回调
    NodeStateCallbacks callbacks_;

    // 超时参数（毫秒）
    uint32_t p2p_punch_timeout_ms_ = 10000;
    uint32_t p2p_keepalive_timeout_ms_ = 3000;
    uint32_t heartbeat_timeout_ms_ = 30000;
    uint32_t p2p_retry_interval_ms_ = 60000;
    uint32_t auth_timeout_ms_ = 10000;
    uint32_t config_ack_timeout_ms_ = 5000;
    uint32_t p2p_negotiation_timeout_ms_ = 10000;
    uint32_t resolve_timeout_ms_ = 5000;        // Client 端：RESOLVING 超时
    uint32_t endpoint_upload_timeout_ms_ = 5000; // Client 端：端点上报超时
};

} // namespace edgelink

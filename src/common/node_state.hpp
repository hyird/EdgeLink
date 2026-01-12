#pragma once

#include "common/types.hpp"
#include "common/connection_types.hpp"
#include "common/constants.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <array>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <optional>

namespace asio = boost::asio;

namespace edgelink {

// ============================================================================
// Channel 类型定义（替代同步回调）
// ============================================================================
namespace channels {

// Controller 端事件通道
using ClientOnlineChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, NetworkId)>;
using ClientOfflineChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, NetworkId)>;
using EndpointUpdateChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, std::vector<Endpoint>)>;
using RouteChangeChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, std::vector<RouteInfo>, std::vector<RouteInfo>)>;

// Client 端事件通道
using ConnectionPhaseChannel = asio::experimental::channel<
    void(boost::system::error_code, ConnectionPhase, ConnectionPhase)>;
using PeerStateChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, P2PConnectionState, PeerDataPath)>;
using DataReceivedChannel = asio::experimental::channel<
    void(boost::system::error_code, NodeId, std::vector<uint8_t>)>;

}  // namespace channels

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
// 节点事件（用于状态机事件驱动）
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
// Controller 视角：客户端节点视图
// ============================================================================
struct ControllerNodeView {
    NodeId node_id = 0;
    NetworkId network_id = 0;
    IPv4Address virtual_ip{};

    // 会话状态
    ClientSessionState session_state = ClientSessionState::DISCONNECTED;
    RelaySessionState relay_state = RelaySessionState::DISCONNECTED;

    // 配置同步
    uint64_t config_version = 0;
    bool config_acked = false;
    uint64_t config_send_time = 0;

    // 端点信息
    std::vector<Endpoint> endpoints;
    uint64_t endpoint_update_time = 0;
    EndpointState endpoint_state = EndpointState::UNKNOWN;

    // 路由信息
    std::vector<RouteInfo> announced_routes;
    uint64_t route_update_time = 0;

    // 心跳/活动
    uint64_t last_ping_time = 0;
    uint64_t last_seen_time = 0;
    uint16_t latency_ms = 0;

    // P2P 协商状态（与其他客户端）
    struct P2PNegotiation {
        NodeId peer_id = 0;
        P2PNegotiationPhase phase = P2PNegotiationPhase::NONE;
        uint32_t init_seq = 0;
        uint64_t init_time = 0;
        uint64_t endpoint_send_time = 0;
    };
    std::unordered_map<NodeId, P2PNegotiation> p2p_negotiations;

    // 辅助方法
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
// Client 视角：自身状态
// ============================================================================
struct ClientSelfState {
    NodeId node_id = 0;
    NetworkId network_id = 0;
    IPv4Address virtual_ip{};

    // 控制面/数据面状态
    ControlPlaneState control_plane = ControlPlaneState::DISCONNECTED;
    DataPlaneState data_plane = DataPlaneState::OFFLINE;
    ConnectionPhase connection_phase = ConnectionPhase::OFFLINE;

    // 端点同步
    ClientEndpointSyncState endpoint_sync = ClientEndpointSyncState::NOT_READY;
    std::vector<Endpoint> local_endpoints;
    uint64_t endpoint_upload_time = 0;

    // 路由同步
    RouteSyncState route_sync = RouteSyncState::DISABLED;

    // P2P_INIT 序列号（由 ClientStateMachine 管理，不需要 atomic）
    uint32_t next_init_seq = 0;

    // Relay 连接（支持多 Relay）
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

    // 对端连接状态
    struct PeerConnection {
        NodeId peer_id = 0;
        P2PConnectionState p2p_state = P2PConnectionState::NONE;
        PeerDataPath data_path = PeerDataPath::UNKNOWN;

        // P2P 打洞相关
        uint32_t init_seq = 0;
        std::vector<Endpoint> peer_endpoints;
        asio::ip::udp::endpoint active_endpoint;

        // 时间戳
        uint64_t last_resolve_time = 0;     // 上次发送 P2P_INIT 时间
        uint64_t last_endpoint_time = 0;    // 上次收到 P2P_ENDPOINT 时间
        uint64_t last_punch_time = 0;       // 上次发送打洞包时间
        uint64_t last_recv_time = 0;        // 上次收到数据时间
        uint64_t last_send_time = 0;        // 上次发送数据时间
        uint64_t next_retry_time = 0;       // 下次重试时间

        // 统计
        uint32_t punch_count = 0;
        uint32_t punch_failures = 0;
        uint16_t rtt_ms = 0;

        // 辅助方法
        bool can_send_p2p() const {
            return data_path == PeerDataPath::P2P;
        }

        bool is_online() const {
            return data_path != PeerDataPath::UNKNOWN &&
                   data_path != PeerDataPath::UNREACHABLE;
        }
    };
    std::unordered_map<NodeId, PeerConnection> peer_connections;

    // 辅助方法
    bool is_control_ready() const {
        return control_plane == ControlPlaneState::READY;
    }

    bool has_data_path() const {
        return data_plane != DataPlaneState::OFFLINE;
    }

    bool is_endpoint_synced() const {
        return endpoint_sync == ClientEndpointSyncState::SYNCED;
    }

    bool has_connected_relay() const {
        for (const auto& [id, relay] : relay_connections) {
            if (relay.is_connected()) return true;
        }
        return false;
    }

    size_t connected_relay_count() const {
        size_t count = 0;
        for (const auto& [id, relay] : relay_connections) {
            if (relay.is_connected()) ++count;
        }
        return count;
    }

    bool has_p2p(NodeId peer_id) const {
        auto it = peer_connections.find(peer_id);
        return it != peer_connections.end() &&
               it->second.p2p_state == P2PConnectionState::CONNECTED;
    }

    bool is_peer_p2p_ready(NodeId peer_id) const {
        auto it = peer_connections.find(peer_id);
        if (it == peer_connections.end()) return false;
        return it->second.can_send_p2p();
    }

    PeerDataPath get_peer_data_path(NodeId peer_id) const {
        auto it = peer_connections.find(peer_id);
        if (it == peer_connections.end()) return PeerDataPath::UNKNOWN;
        return it->second.data_path;
    }
};

// ============================================================================
// Controller 端状态机
// ============================================================================
class ControllerStateMachine {
public:
    explicit ControllerStateMachine(asio::io_context& ioc);
    ~ControllerStateMachine() = default;

    // 禁止拷贝
    ControllerStateMachine(const ControllerStateMachine&) = delete;
    ControllerStateMachine& operator=(const ControllerStateMachine&) = delete;

    // ========================================================================
    // Channel 设置
    // ========================================================================
    void set_client_online_channel(channels::ClientOnlineChannel* ch) { client_online_channel_ = ch; }
    void set_client_offline_channel(channels::ClientOfflineChannel* ch) { client_offline_channel_ = ch; }
    void set_endpoint_update_channel(channels::EndpointUpdateChannel* ch) { endpoint_update_channel_ = ch; }
    void set_route_change_channel(channels::RouteChangeChannel* ch) { route_change_channel_ = ch; }

    // ========================================================================
    // 超时参数设置
    // ========================================================================
    void set_auth_timeout(std::chrono::milliseconds ms) { auth_timeout_ = ms; }
    void set_config_ack_timeout(std::chrono::milliseconds ms) { config_ack_timeout_ = ms; }
    void set_heartbeat_timeout(std::chrono::milliseconds ms) { heartbeat_timeout_ = ms; }
    void set_p2p_negotiation_timeout(std::chrono::milliseconds ms) { p2p_negotiation_timeout_ = ms; }

    // ========================================================================
    // 节点管理
    // ========================================================================

    // 添加节点
    void add_node(NodeId node_id, NetworkId network_id);

    // 移除节点
    void remove_node(NodeId node_id);

    // 获取节点视图
    std::optional<ControllerNodeView> get_node_view(NodeId node_id) const;

    // 获取网络中的所有节点
    std::vector<NodeId> get_network_nodes(NetworkId network_id) const;

    // 获取所有在线节点
    std::vector<NodeId> get_online_nodes() const;

    // ========================================================================
    // 会话管理
    // ========================================================================

    // 处理认证请求
    void handle_auth_request(NodeId node_id, NetworkId network_id);

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

    // ========================================================================
    // 端点管理
    // ========================================================================

    // 更新节点端点
    void update_node_endpoints(NodeId node_id, const std::vector<Endpoint>& endpoints);

    // 获取节点端点
    std::vector<Endpoint> get_node_endpoints(NodeId node_id) const;

    // ========================================================================
    // 路由管理
    // ========================================================================

    // 更新节点路由
    void update_node_routes(NodeId node_id,
                            const std::vector<RouteInfo>& add_routes,
                            const std::vector<RouteInfo>& del_routes);

    // 获取节点路由
    std::vector<RouteInfo> get_node_routes(NodeId node_id) const;

    // ========================================================================
    // P2P 协商管理
    // ========================================================================

    // 处理 P2P 初始化请求
    void handle_p2p_init(NodeId initiator, NodeId responder, uint32_t seq);

    // 标记 P2P 端点已发送
    void mark_p2p_endpoint_sent(NodeId node_id, NodeId peer_id);

    // 处理 P2P 状态报告
    void handle_p2p_status(NodeId node_id, NodeId peer_id, bool success);

    // ========================================================================
    // 心跳管理
    // ========================================================================

    // 记录心跳
    void record_ping(NodeId node_id);
    void record_pong(NodeId node_id, uint16_t latency_ms);

    // 记录活动
    void record_activity(NodeId node_id);

    // ========================================================================
    // 超时检测
    // ========================================================================

    // 检查所有超时
    void check_timeouts();

    // ========================================================================
    // 状态查询
    // ========================================================================

    // 检查节点是否在线
    bool is_node_online(NodeId node_id) const;

    // 检查节点是否有 Relay 连接
    bool has_node_relay(NodeId node_id) const;

    // 获取当前时间（微秒）
    static uint64_t now_us();

private:
    // 发送事件到 channel
    void notify_client_online(NodeId node_id, NetworkId network_id);
    void notify_client_offline(NodeId node_id, NetworkId network_id);
    void notify_endpoint_update(NodeId node_id, const std::vector<Endpoint>& endpoints);
    void notify_route_change(NodeId node_id,
                             const std::vector<RouteInfo>& added,
                             const std::vector<RouteInfo>& removed);

    // 获取可修改的节点视图
    ControllerNodeView* get_node_view_mut(NodeId node_id);

    asio::io_context& ioc_;

    // 节点状态
    mutable std::shared_mutex nodes_mutex_;
    std::unordered_map<NodeId, ControllerNodeView> nodes_;

    // 事件通道
    channels::ClientOnlineChannel* client_online_channel_ = nullptr;
    channels::ClientOfflineChannel* client_offline_channel_ = nullptr;
    channels::EndpointUpdateChannel* endpoint_update_channel_ = nullptr;
    channels::RouteChangeChannel* route_change_channel_ = nullptr;

    // 超时参数
    std::chrono::milliseconds auth_timeout_{10000};
    std::chrono::milliseconds config_ack_timeout_{5000};
    std::chrono::milliseconds heartbeat_timeout_{30000};
    std::chrono::milliseconds p2p_negotiation_timeout_{10000};
};

// ============================================================================
// Client 端状态机
// ============================================================================
class ClientStateMachine {
public:
    explicit ClientStateMachine(asio::io_context& ioc);
    ~ClientStateMachine() = default;

    // 禁止拷贝
    ClientStateMachine(const ClientStateMachine&) = delete;
    ClientStateMachine& operator=(const ClientStateMachine&) = delete;

    // ========================================================================
    // Channel 设置
    // ========================================================================
    void set_phase_channel(channels::ConnectionPhaseChannel* ch) { phase_channel_ = ch; }
    void set_peer_state_channel(channels::PeerStateChannel* ch) { peer_state_channel_ = ch; }

    // ========================================================================
    // 超时参数设置
    // ========================================================================
    void set_punch_timeout(std::chrono::milliseconds ms) { punch_timeout_ = ms; }
    void set_keepalive_timeout(std::chrono::milliseconds ms) { keepalive_timeout_ = ms; }
    void set_retry_interval(std::chrono::milliseconds ms) { retry_interval_ = ms; }
    void set_resolve_timeout(std::chrono::milliseconds ms) { resolve_timeout_ = ms; }
    void set_endpoint_upload_timeout(std::chrono::milliseconds ms) { endpoint_upload_timeout_ = ms; }

    // ========================================================================
    // 自身信息管理
    // ========================================================================

    // 设置自身 NodeId（认证成功后调用）
    void set_node_id(NodeId node_id);
    NodeId node_id() const;

    // 设置网络 ID
    void set_network_id(NetworkId network_id);
    NetworkId network_id() const;

    // 设置虚拟 IP
    void set_virtual_ip(const IPv4Address& ip);
    IPv4Address virtual_ip() const;

    // ========================================================================
    // 控制面状态管理
    // ========================================================================

    // 设置控制面状态
    void set_control_plane_state(ControlPlaneState state);
    ControlPlaneState control_plane_state() const;
    bool is_control_ready() const;

    // ========================================================================
    // 数据面状态管理
    // ========================================================================

    // 设置数据面状态
    void set_data_plane_state(DataPlaneState state);
    DataPlaneState data_plane_state() const;
    bool has_data_path() const;

    // 根据 Relay 和 P2P 状态自动更新数据面
    void update_data_plane_state();

    // ========================================================================
    // 连接阶段管理
    // ========================================================================

    // 设置连接阶段
    void set_connection_phase(ConnectionPhase phase);
    ConnectionPhase connection_phase() const;
    bool is_connected() const;

    // 根据控制面和数据面状态自动更新连接阶段
    void update_connection_phase();

    // ========================================================================
    // 端点同步管理
    // ========================================================================

    // 设置端点同步状态
    void set_endpoint_sync_state(ClientEndpointSyncState state);
    ClientEndpointSyncState endpoint_sync_state() const;
    bool is_endpoint_synced() const;

    // 更新本地端点
    void update_local_endpoints(const std::vector<Endpoint>& endpoints);
    std::vector<Endpoint> local_endpoints() const;

    // ========================================================================
    // 路由同步管理
    // ========================================================================

    // 设置路由同步状态
    void set_route_sync_state(RouteSyncState state);
    RouteSyncState route_sync_state() const;

    // ========================================================================
    // Relay 连接管理（支持多 Relay）
    // ========================================================================

    // 添加 Relay
    void add_relay(const std::string& relay_id, bool is_primary = false);

    // 移除 Relay
    void remove_relay(const std::string& relay_id);

    // 设置主 Relay
    void set_primary_relay(const std::string& relay_id);

    // 设置 Relay 连接状态
    void set_relay_state(const std::string& relay_id, RelayConnectionState state);

    // 更新 Relay 延迟
    void update_relay_latency(const std::string& relay_id, uint16_t latency_ms);

    // 记录 Relay 收发时间
    void record_relay_recv(const std::string& relay_id);
    void record_relay_send(const std::string& relay_id);

    // 获取 Relay 信息
    std::optional<ClientSelfState::RelayConnection> get_relay_info(const std::string& relay_id) const;
    std::vector<ClientSelfState::RelayConnection> get_all_relay_info() const;
    bool has_connected_relay() const;
    size_t connected_relay_count() const;
    std::optional<std::string> get_primary_relay() const;

    // ========================================================================
    // 对端连接管理
    // ========================================================================

    // 添加对端
    void add_peer(NodeId peer_id);

    // 移除对端
    void remove_peer(NodeId peer_id);

    // 设置对端 P2P 状态
    void set_peer_p2p_state(NodeId peer_id, P2PConnectionState state);

    // 设置对端数据路径
    void set_peer_data_path(NodeId peer_id, PeerDataPath path);

    // 原子设置对端 P2P 状态和数据路径（避免两个状态不一致）
    // 返回 true 如果状态发生了变化，false 如果状态未变
    bool set_peer_connection_state(NodeId peer_id, P2PConnectionState p2p_state, PeerDataPath data_path);

    // 发起 P2P 连接
    void initiate_p2p(NodeId peer_id);

    // 收到对端端点
    void receive_peer_endpoints(NodeId peer_id, const std::vector<Endpoint>& endpoints);

    // 设置活跃 P2P 端点
    void set_peer_active_endpoint(NodeId peer_id, const asio::ip::udp::endpoint& endpoint);

    // 更新对端延迟
    void update_peer_latency(NodeId peer_id, uint16_t rtt_ms);

    // 记录对端收发时间
    void record_peer_recv(NodeId peer_id);
    void record_peer_send(NodeId peer_id);

    // 标记打洞失败
    void record_punch_failure(NodeId peer_id);

    // 设置下次重试时间
    void set_peer_next_retry(NodeId peer_id, uint64_t time);

    // 获取对端状态
    std::optional<ClientSelfState::PeerConnection> get_peer_state(NodeId peer_id) const;
    std::vector<std::pair<NodeId, ClientSelfState::PeerConnection>> get_all_peer_states() const;

    // 获取对端 P2P 连接状态
    P2PConnectionState get_peer_p2p_state(NodeId peer_id) const;

    // 获取对端 RTT（毫秒）
    uint16_t get_peer_rtt(NodeId peer_id) const;

    // 获取需要重试 P2P 的对端列表
    std::vector<NodeId> get_peers_for_retry() const;

    // 获取需要发送 keepalive 的对端列表
    std::vector<NodeId> get_peers_for_keepalive() const;

    // 判断对端是否可通过 P2P 发送
    bool is_peer_p2p_ready(NodeId peer_id) const;

    // 获取下一个 P2P_INIT 序列号
    uint32_t next_init_seq();

    // ========================================================================
    // 超时检测
    // ========================================================================

    // 检查所有超时
    void check_timeouts();

    // ========================================================================
    // 重置
    // ========================================================================

    // 重置所有状态
    void reset();

    // ========================================================================
    // 工具方法
    // ========================================================================

    // 获取当前时间（微秒）
    static uint64_t now_us();

private:
    // 发送事件到 channel
    void notify_phase_change(ConnectionPhase old_phase, ConnectionPhase new_phase);
    void notify_peer_state_change(NodeId peer_id, P2PConnectionState p2p_state, PeerDataPath data_path);

    // 获取可修改的对端连接
    ClientSelfState::PeerConnection* get_peer_mut(NodeId peer_id);

    // 获取可修改的 Relay 连接
    ClientSelfState::RelayConnection* get_relay_mut(const std::string& relay_id);

    // 根据控制面和数据面状态计算连接阶段
    ConnectionPhase calculate_connection_phase() const;

    asio::io_context& ioc_;

    // 自身状态（分离锁）
    mutable std::shared_mutex self_mutex_;      // 保护基本字段
    mutable std::shared_mutex relays_mutex_;    // 保护 relay_connections
    mutable std::shared_mutex peers_mutex_;     // 保护 peer_connections

    ClientSelfState state_;

    // 事件通道
    channels::ConnectionPhaseChannel* phase_channel_ = nullptr;
    channels::PeerStateChannel* peer_state_channel_ = nullptr;

    // 超时参数
    std::chrono::milliseconds punch_timeout_{10000};
    std::chrono::milliseconds keepalive_timeout_{3000};
    std::chrono::milliseconds retry_interval_{60000};
    std::chrono::milliseconds resolve_timeout_{5000};
    std::chrono::milliseconds endpoint_upload_timeout_{5000};
};

}  // namespace edgelink

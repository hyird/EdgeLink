#pragma once

#include "common/types.hpp"
#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>
#include <string>

namespace edgelink::client {

// ============================================================================
// 架构说明：控制面与数据面分离
// ============================================================================
//
// 控制面 (Control Plane):
//   - ControlChannel: 认证、配置、路由同步、P2P 协调
//   - 状态：ControlPlaneState
//
// 数据面 (Data Plane):
//   - RelayChannel: 中继转发
//   - P2P UDP: 直接传输
//   - 状态：DataPlaneState, PeerDataPath
//
// ============================================================================

// ============================================================================
// 控制面状态 - 与 Controller 的连接和同步状态
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
// 数据面状态 - 数据传输通道状态
// ============================================================================
enum class DataPlaneState : uint8_t {
    OFFLINE = 0,        // 离线（无可用数据通道）
    RELAY_ONLY,         // 仅 Relay（Relay 已连接，P2P 未就绪）
    HYBRID,             // 混合（Relay + 部分 P2P）
    DEGRADED,           // 降级（Relay 断开，仅部分 P2P）
};

const char* data_plane_state_name(DataPlaneState state);

// ============================================================================
// 整体连接阶段 - 客户端总体状态（组合控制面+数据面）
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
// 端点同步状态 - 本节点端点的发现和上报状态
// ============================================================================
enum class EndpointSyncState : uint8_t {
    NOT_READY = 0,      // 未就绪（UDP socket 未初始化）
    DISCOVERING,        // 发现中（STUN 查询中）
    READY,              // 就绪（端点已发现）
    UPLOADING,          // 上报中（等待 ACK）
    SYNCED,             // 已同步（Controller 已确认）
};

const char* endpoint_sync_state_name(EndpointSyncState state);

// ============================================================================
// 对端数据路径状态 - 每个对端的数据传输路径
// ============================================================================
enum class PeerDataPath : uint8_t {
    UNKNOWN = 0,        // 未知（未尝试连接）
    RELAY,              // 通过 Relay 转发
    P2P,                // 通过 P2P 直连
    UNREACHABLE,        // 不可达（对端离线或所有路径失败）
};

const char* peer_data_path_name(PeerDataPath path);

// ============================================================================
// 对端 P2P 协商状态 - 控制面管理的 P2P 建立过程
// ============================================================================
enum class PeerP2PNegotiationState : uint8_t {
    IDLE = 0,           // 空闲（未发起 P2P）
    RESOLVING,          // 解析中（已发送 P2P_INIT，等待 P2P_ENDPOINT）
    PUNCHING,           // 打洞中（已收到端点，发送打洞包）
    ESTABLISHED,        // 已建立（P2P 连接成功）
    FAILED,             // 失败（超时或打洞失败，等待重试）
};

const char* peer_p2p_negotiation_state_name(PeerP2PNegotiationState state);

// ============================================================================
// 对端连接状态（组合视图）
// ============================================================================
enum class PeerLinkState : uint8_t {
    UNKNOWN = 0,        // 未知（未尝试连接）
    RESOLVING,          // 解析中（等待对端端点）
    PUNCHING,           // 打洞中（NAT 穿透）
    P2P_ACTIVE,         // P2P 活跃
    RELAY_FALLBACK,     // Relay 回退（P2P 失败或超时）
    OFFLINE,            // 对端离线
};

const char* peer_link_state_name(PeerLinkState state);

// ============================================================================
// 路由同步状态 - 路由表同步状态
// ============================================================================
enum class RouteSyncState : uint8_t {
    DISABLED = 0,       // 禁用（不接受路由）
    PENDING,            // 待同步
    SYNCING,            // 同步中
    SYNCED,             // 已同步
};

const char* route_sync_state_name(RouteSyncState state);

// ============================================================================
// Relay 连接状态
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
// Relay 详细信息
// ============================================================================
struct RelayInfo {
    std::string relay_id;                       // Relay 标识（URL 或 ID）
    RelayConnectionState state = RelayConnectionState::DISCONNECTED;
    uint64_t last_connect_time = 0;             // 上次连接时间
    uint64_t last_recv_time = 0;                // 上次收到数据时间
    uint64_t last_send_time = 0;                // 上次发送数据时间
    uint16_t latency_ms = 0;                    // RTT 延迟
    uint32_t reconnect_count = 0;               // 重连次数
    bool is_primary = false;                    // 是否为主 Relay

    bool is_connected() const {
        return state == RelayConnectionState::CONNECTED;
    }
};

// ============================================================================
// 对端详细状态
// ============================================================================
struct PeerState {
    NodeId peer_id = 0;

    // ========== 组合状态（方便查询）==========
    PeerLinkState link_state = PeerLinkState::UNKNOWN;

    // ========== 控制面状态（P2P 协商）==========
    PeerP2PNegotiationState negotiation_state = PeerP2PNegotiationState::IDLE;
    uint32_t init_seq = 0;                      // P2P_INIT 序列号
    std::vector<Endpoint> peer_endpoints;       // 对端端点列表（从 Controller 获取）
    uint64_t last_resolve_time = 0;             // 上次发送 P2P_INIT 时间
    uint64_t last_endpoint_time = 0;            // 上次收到 P2P_ENDPOINT 时间
    uint32_t punch_failures = 0;                // 连续失败次数
    uint64_t next_retry_time = 0;               // 下次重试时间

    // ========== 数据面状态（数据传输）==========
    PeerDataPath data_path = PeerDataPath::UNKNOWN;
    uint64_t last_punch_time = 0;               // 上次发送打洞包时间
    uint32_t punch_count = 0;                   // 打洞次数
    uint64_t last_recv_time = 0;                // 上次收到数据时间
    uint64_t last_send_time = 0;                // 上次发送数据时间
    uint16_t latency_ms = 0;                    // RTT 延迟

    // 活跃 P2P 连接信息
    std::array<uint8_t, 16> p2p_addr{};         // P2P 对端地址
    uint16_t p2p_port = 0;                      // P2P 对端端口

    // ========== 辅助方法 ==========
    bool can_send_p2p() const {
        return data_path == PeerDataPath::P2P;
    }

    bool is_online() const {
        return data_path != PeerDataPath::UNKNOWN &&
               data_path != PeerDataPath::UNREACHABLE;
    }
};

// ============================================================================
// 状态变更事件
// ============================================================================
enum class StateEvent : uint8_t {
    // 控制面连接事件
    START_CONNECT,          // 开始连接
    AUTH_SUCCESS,           // 认证成功
    AUTH_FAILED,            // 认证失败
    CONFIG_RECEIVED,        // 收到配置
    CONTROL_DISCONNECTED,   // Control 断开

    // Relay 事件（数据面）
    RELAY_CONNECTING,       // Relay 连接中
    RELAY_CONNECTED,        // Relay 已连接
    RELAY_DISCONNECTED,     // Relay 断开
    RELAY_RECONNECTING,     // Relay 重连中

    // 端点事件
    SOCKET_READY,           // UDP Socket 就绪
    STUN_SUCCESS,           // STUN 查询成功
    STUN_FAILED,            // STUN 查询失败
    ENDPOINT_UPLOADED,      // 端点已上报
    ENDPOINT_ACK,           // 端点 ACK

    // P2P 事件
    P2P_INIT_SENT,          // P2P_INIT 已发送
    P2P_ENDPOINT_RECEIVED,  // 收到对端端点
    PUNCH_STARTED,          // 开始打洞
    PUNCH_SUCCESS,          // 打洞成功
    PUNCH_TIMEOUT,          // 打洞超时
    P2P_KEEPALIVE_TIMEOUT,  // P2P 保活超时

    // 路由事件
    ROUTES_RECEIVED,        // 收到路由
    ROUTES_APPLIED,         // 路由已应用

    // 对端事件
    PEER_ONLINE,            // 对端上线
    PEER_OFFLINE,           // 对端下线
};

const char* state_event_name(StateEvent event);

// ============================================================================
// 状态变更回调
// ============================================================================
struct StateCallbacks {
    // 全局连接阶段变更
    std::function<void(ConnectionPhase old_phase, ConnectionPhase new_phase)> on_phase_change;

    // 控制面状态变更
    std::function<void(ControlPlaneState old_state, ControlPlaneState new_state)> on_control_plane_change;

    // 数据面状态变更
    std::function<void(DataPlaneState old_state, DataPlaneState new_state)> on_data_plane_change;

    // Relay 状态变更
    std::function<void(const std::string& relay_id, RelayConnectionState old_state, RelayConnectionState new_state)> on_relay_state_change;

    // 端点同步状态变更
    std::function<void(EndpointSyncState old_state, EndpointSyncState new_state)> on_endpoint_state_change;

    // 对端连接状态变更（组合视图）
    std::function<void(NodeId peer_id, PeerLinkState old_state, PeerLinkState new_state)> on_peer_state_change;

    // 对端数据路径变更（数据面）
    std::function<void(NodeId peer_id, PeerDataPath old_path, PeerDataPath new_path)> on_peer_data_path_change;

    // 路由同步状态变更
    std::function<void(RouteSyncState old_state, RouteSyncState new_state)> on_route_state_change;
};

// ============================================================================
// 统一连接状态机
// ============================================================================
class ConnectionStateMachine {
public:
    ConnectionStateMachine();
    ~ConnectionStateMachine() = default;

    // 禁止拷贝
    ConnectionStateMachine(const ConnectionStateMachine&) = delete;
    ConnectionStateMachine& operator=(const ConnectionStateMachine&) = delete;

    // ========================================================================
    // 配置
    // ========================================================================

    // 设置回调
    void set_callbacks(StateCallbacks callbacks);

    // 设置超时参数
    void set_resolve_timeout(uint32_t ms) { resolve_timeout_ms_ = ms; }
    void set_punch_timeout(uint32_t ms) { punch_timeout_ms_ = ms; }
    void set_keepalive_timeout(uint32_t ms) { keepalive_timeout_ms_ = ms; }
    void set_retry_interval(uint32_t ms) { retry_interval_ms_ = ms; }

    // ========================================================================
    // 事件处理 - 驱动状态转换
    // ========================================================================

    // 处理状态事件
    void handle_event(StateEvent event);

    // 处理对端相关事件
    void handle_peer_event(NodeId peer_id, StateEvent event);

    // 处理 Relay 相关事件
    void handle_relay_event(const std::string& relay_id, StateEvent event);

    // ========================================================================
    // 状态查询
    // ========================================================================

    // 全局连接阶段
    ConnectionPhase phase() const { return phase_.load(); }
    bool is_online() const { return phase_ == ConnectionPhase::ONLINE; }

    // 控制面状态
    ControlPlaneState control_plane_state() const { return control_plane_.load(); }
    bool is_control_ready() const { return control_plane_ == ControlPlaneState::READY; }

    // 数据面状态
    DataPlaneState data_plane_state() const { return data_plane_.load(); }
    bool has_data_path() const { return data_plane_ != DataPlaneState::OFFLINE; }

    // 端点状态
    EndpointSyncState endpoint_state() const { return endpoint_state_.load(); }
    bool is_endpoint_synced() const { return endpoint_state_ == EndpointSyncState::SYNCED; }

    // 路由状态
    RouteSyncState route_state() const { return route_state_.load(); }

    // Relay 状态
    std::optional<RelayInfo> get_relay_info(const std::string& relay_id) const;
    std::vector<RelayInfo> get_all_relay_info() const;
    bool has_connected_relay() const;
    size_t connected_relay_count() const;
    std::optional<std::string> get_primary_relay() const;

    // 对端状态
    PeerLinkState get_peer_link_state(NodeId peer_id) const;
    std::optional<PeerState> get_peer_state(NodeId peer_id) const;
    std::vector<std::pair<NodeId, PeerState>> get_all_peer_states() const;

    // 判断对端是否可通过 P2P 发送
    bool is_peer_p2p_ready(NodeId peer_id) const;

    // 获取需要重试 P2P 的对端列表
    std::vector<NodeId> get_peers_for_retry() const;

    // 获取需要发送 keepalive 的对端列表
    std::vector<NodeId> get_peers_for_keepalive() const;

    // ========================================================================
    // Relay 管理
    // ========================================================================

    // 添加 Relay
    void add_relay(const std::string& relay_id, bool is_primary = false);

    // 移除 Relay
    void remove_relay(const std::string& relay_id);

    // 设置主 Relay
    void set_primary_relay(const std::string& relay_id);

    // 更新 Relay 延迟
    void update_relay_latency(const std::string& relay_id, uint16_t latency_ms);

    // 记录 Relay 收发时间
    void record_relay_recv(const std::string& relay_id);
    void record_relay_send(const std::string& relay_id);

    // ========================================================================
    // 对端管理
    // ========================================================================

    // 添加对端
    void add_peer(NodeId peer_id);

    // 移除对端
    void remove_peer(NodeId peer_id);

    // 更新对端端点
    void update_peer_endpoints(NodeId peer_id, const std::vector<Endpoint>& endpoints);

    // 更新对端活跃连接
    void update_peer_active_connection(NodeId peer_id,
                                        const std::array<uint8_t, 16>& addr,
                                        uint16_t port,
                                        bool is_p2p);

    // 更新对端延迟
    void update_peer_latency(NodeId peer_id, uint16_t latency_ms);

    // 记录对端收发时间
    void record_peer_recv(NodeId peer_id);
    void record_peer_send(NodeId peer_id);

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

    // 重置对端状态
    void reset_peer(NodeId peer_id);

private:
    // 内部状态转换
    void set_phase(ConnectionPhase new_phase);
    void set_control_plane_state(ControlPlaneState new_state);
    void set_data_plane_state(DataPlaneState new_state);
    void set_endpoint_state(EndpointSyncState new_state);
    void set_route_state(RouteSyncState new_state);
    void set_peer_link_state(NodeId peer_id, PeerLinkState new_state);
    void set_peer_data_path(NodeId peer_id, PeerDataPath new_path);

    // 更新组合状态（基于控制面和数据面状态）
    void update_combined_phase();
    void update_data_plane_state();
    void update_peer_link_state(NodeId peer_id);

    // 获取可修改的对端状态（内部使用）
    PeerState* get_peer_state_mut(NodeId peer_id);

    // 获取可修改的 Relay 状态（内部使用）
    RelayInfo* get_relay_info_mut(const std::string& relay_id);

    // 设置 Relay 状态
    void set_relay_state(const std::string& relay_id, RelayConnectionState new_state);

    // 检查是否有已连接的 Relay（内部使用）
    bool has_connected_relay_internal() const;

    // ========== 全局状态 ==========
    std::atomic<ConnectionPhase> phase_{ConnectionPhase::OFFLINE};

    // ========== 控制面状态 ==========
    std::atomic<ControlPlaneState> control_plane_{ControlPlaneState::DISCONNECTED};
    std::atomic<EndpointSyncState> endpoint_state_{EndpointSyncState::NOT_READY};
    std::atomic<RouteSyncState> route_state_{RouteSyncState::DISABLED};

    // ========== 数据面状态 ==========
    std::atomic<DataPlaneState> data_plane_{DataPlaneState::OFFLINE};
    std::atomic<uint32_t> p2p_peer_count_{0};   // P2P 已连接的对端数

    // Relay 状态（支持多 Relay）
    mutable std::shared_mutex relays_mutex_;
    std::unordered_map<std::string, RelayInfo> relay_states_;
    std::string primary_relay_id_;              // 主 Relay 标识

    // 对端状态
    mutable std::shared_mutex peers_mutex_;
    std::unordered_map<NodeId, PeerState> peer_states_;

    // 回调
    StateCallbacks callbacks_;

    // 超时参数（毫秒）
    uint32_t resolve_timeout_ms_ = 5000;        // RESOLVING 超时
    uint32_t punch_timeout_ms_ = 10000;         // PUNCHING 超时
    uint32_t keepalive_timeout_ms_ = 3000;      // P2P keepalive 超时
    uint32_t retry_interval_ms_ = 60000;        // 重试间隔

    // P2P_INIT 序列号
    std::atomic<uint32_t> init_seq_{0};
};

} // namespace edgelink::client

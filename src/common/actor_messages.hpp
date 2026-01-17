// Actor 消息类型定义
// 定义所有 Actor 之间传递的消息结构

#pragma once

#include "common/frame.hpp"
#include "common/message.hpp"
#include "common/types.hpp"
#include "common/node_state.hpp"
#include "common/connection_types.hpp"
#include <variant>
#include <vector>
#include <memory>
#include <cstdint>
#include <unordered_map>

namespace edgelink::messages {

// 导入 edgelink 命名空间的类型（简化使用）
using edgelink::NodeId;
using edgelink::NetworkId;
using edgelink::IPv4Address;
using edgelink::Endpoint;
using edgelink::RouteInfo;
using edgelink::NodeEvent;
using edgelink::P2PConnectionState;
using edgelink::ConnectionPhase;
using edgelink::AuthResponse;
using edgelink::Config;
using edgelink::ConfigUpdate;
using edgelink::RouteUpdate;
using edgelink::P2PEndpointMsg;
using edgelink::P2PInit;
using edgelink::FrameType;

// ============================================================================
// 控制面消息（Control Channel）
// ============================================================================

// 控制消息载荷
struct ControlMessage {
    std::variant<
        AuthResponse,
        Config,
        ConfigUpdate,
        RouteUpdate,
        P2PEndpointMsg,
        std::pair<uint16_t, std::string>  // Error: (code, message)
    > payload;

    FrameType type;  // 原始帧类型
};

// ============================================================================
// 数据面消息（Relay/P2P）
// ============================================================================

// 数据消息
struct DataMessage {
    NodeId src_node;
    NodeId dst_node;
    std::shared_ptr<std::vector<uint8_t>> data;  // 使用 shared_ptr 避免拷贝
    bool from_p2p;  // true = P2P, false = Relay
};

// ============================================================================
// P2P 协议消息
// ============================================================================

// P2P 协议消息
struct P2PProtocolMessage {
    NodeId peer_id;
    std::variant<
        P2PInit,
        P2PEndpointMsg,
        P2PStatusMsg,
        P2PPing,
        P2PKeepalive
    > payload;
};

// ============================================================================
// 端点管理消息
// ============================================================================

// 端点消息类型
enum class EndpointMessageType {
    STUN_QUERY_START,        // 开始 STUN 查询
    STUN_QUERY_SUCCESS,      // STUN 查询成功
    STUN_QUERY_FAILED,       // STUN 查询失败
    ENDPOINTS_READY,         // 端点就绪
    ENDPOINT_REFRESH_REQUEST,// 请求刷新端点
};

// 端点管理消息
struct EndpointMessage {
    EndpointMessageType type;
    std::vector<Endpoint> endpoints;
    std::string error_message;  // 用于 FAILED 类型
};

// ============================================================================
// 路由管理消息
// ============================================================================

// 路由消息类型
enum class RouteMessageType {
    ANNOUNCE,           // 公告路由
    WITHDRAW,           // 撤回路由
    UPDATE_RECEIVED,    // 收到路由更新
    APPLY_ROUTES,       // 应用路由表
};

// 路由管理消息
struct RouteMessage {
    RouteMessageType type;
    std::vector<RouteInfo> routes;
};

// ============================================================================
// 状态机事件消息
// ============================================================================

struct StateMachineEvent {
    NodeEvent event;
    NodeId related_node;
    std::variant<
        std::monostate,
        P2PConnectionState,
        ConnectionPhase,
        std::vector<Endpoint>
    > data;
};

// ============================================================================
// 生命周期控制消息
// ============================================================================

// 生命周期消息类型
enum class LifecycleType {
    START,      // 启动
    STOP,       // 停止
    RESTART,    // 重启
    RECONNECT,  // 重新连接
    SHUTDOWN,   // 关闭
};

// 生命周期控制消息
struct LifecycleMessage {
    LifecycleType type;
    std::string reason;
};

// ============================================================================
// TUN 设备消息
// ============================================================================

// TUN 消息类型
enum class TunMessageType {
    OPEN,          // 打开设备
    CLOSE,         // 关闭设备
    WRITE_PACKET,  // 写入数据包
};

// TUN 设备消息
struct TunMessage {
    TunMessageType type;

    // OPEN 参数
    std::string dev_name;
    IPv4Address ip;
    IPv4Address netmask;
    uint32_t mtu = 0;

    // WRITE_PACKET 参数
    std::shared_ptr<std::vector<uint8_t>> packet;  // 零拷贝
};

// TUN 事件类型
enum class TunEventType {
    OPENED,           // 设备已打开
    CLOSED,           // 设备已关闭
    PACKET_RECEIVED,  // 收到数据包
    TUN_ERROR,        // 错误（避免与 Windows ERROR 宏冲突）
};

// TUN 设备事件
struct TunEvent {
    TunEventType type;

    // OPENED 参数
    std::string dev_name;
    IPv4Address ip;

    // PACKET_RECEIVED 参数
    std::shared_ptr<std::vector<uint8_t>> packet;
    IPv4Address src_ip;
    IPv4Address dst_ip;

    // ERROR 参数
    std::string error_message;
};

// ============================================================================
// Control Channel Actor 消息
// ============================================================================

// Control Channel 命令类型
enum class CtrlCmdType {
    CONNECT,                // 连接
    RECONNECT,              // 重新连接
    CLOSE,                  // 关闭
    SEND_PING,              // 发送 Ping
    SEND_ENDPOINT_UPDATE,   // 发送端点更新
    SEND_P2P_INIT,          // 发送 P2P 初始化
    SEND_ROUTE_ANNOUNCE,    // 发送路由公告
};

// Control Channel 命令消息
struct ControlChannelCmd {
    CtrlCmdType type;

    // CONNECT 参数
    std::string url;
    std::string authkey;
    bool use_tls = true;

    // SEND_ENDPOINT_UPDATE 参数
    std::vector<Endpoint> endpoints;
    uint32_t request_id = 0;

    // SEND_P2P_INIT 参数
    P2PInit p2p_init;

    // SEND_ROUTE_ANNOUNCE 参数
    std::vector<RouteInfo> routes;
};

// Control Channel 事件类型
enum class CtrlEventType {
    CONNECTED,          // 已连接
    DISCONNECTED,       // 已断开
    AUTH_RESPONSE,      // 认证响应
    CONFIG_RECEIVED,    // 收到配置
    ROUTE_UPDATE,       // 路由更新
    P2P_ENDPOINT,       // P2P 端点
    CTRL_ERROR,         // 错误（避免与 Windows ERROR 宏冲突）
};

// Control Channel 事件
struct ControlChannelEvent {
    CtrlEventType type;

    // CONNECTED 参数
    NodeId node_id;
    IPv4Address virtual_ip;
    std::vector<uint8_t> relay_token;

    // DISCONNECTED / ERROR 参数
    std::string reason;
    uint16_t error_code = 0;

    // AUTH_RESPONSE 参数
    AuthResponse auth_response;

    // CONFIG_RECEIVED 参数
    Config config;
    ConfigUpdate config_update;  // 用于增量配置更新

    // ROUTE_UPDATE 参数
    RouteUpdate route_update;

    // P2P_ENDPOINT 参数
    P2PEndpointMsg p2p_endpoint;
};

// ============================================================================
// Relay Channel Actor 消息
// ============================================================================

// Relay Channel 命令类型
enum class RelayCmdType {
    CONNECT,     // 连接
    CLOSE,       // 关闭
    SEND_DATA,   // 发送数据
};

// Relay Channel 命令消息
struct RelayChannelCmd {
    RelayCmdType type;

    // CONNECT 参数
    std::string url;
    std::vector<uint8_t> relay_token;
    bool use_tls = true;

    // SEND_DATA 参数
    NodeId peer_id;
    std::shared_ptr<std::vector<uint8_t>> plaintext;  // 零拷贝
};

// Relay Channel 事件类型
enum class RelayEventType {
    CONNECTED,       // 已连接
    DISCONNECTED,    // 已断开
    DATA_RECEIVED,   // 收到数据
    RELAY_ERROR,     // 错误（避免与 Windows ERROR 宏冲突）
};

// Relay Channel 事件
struct RelayChannelEvent {
    RelayEventType type;

    // DATA_RECEIVED 参数
    NodeId src_node;
    std::shared_ptr<std::vector<uint8_t>> plaintext;  // 零拷贝

    // DISCONNECTED / ERROR 参数
    std::string reason;
};

// ============================================================================
// P2P Manager Actor 消息
// ============================================================================

// P2P Manager 命令类型
enum class P2PCmdType {
    START,               // 启动
    STOP,                // 停止
    CONNECT_PEER,        // 连接对端
    DISCONNECT_PEER,     // 断开对端
    HANDLE_P2P_ENDPOINT, // 处理 P2P 端点消息
    SEND_DATA,           // 发送数据
};

// P2P Manager 命令消息
struct P2PManagerCmd {
    P2PCmdType type;

    // CONNECT_PEER / DISCONNECT_PEER / SEND_DATA 参数
    NodeId peer_id;

    // HANDLE_P2P_ENDPOINT 参数
    P2PEndpointMsg p2p_endpoint;

    // SEND_DATA 参数
    std::shared_ptr<std::vector<uint8_t>> plaintext;  // 零拷贝
};

// P2P Manager 事件类型
enum class P2PEventType {
    ENDPOINTS_READY,    // 本地端点就绪
    P2P_INIT_NEEDED,    // 需要 P2P_INIT
    PEER_CONNECTED,     // 对端已连接
    PEER_DISCONNECTED,  // 对端已断开
    DATA_RECEIVED,      // 收到数据
    P2P_ERROR,          // 错误（避免与 Windows ERROR 宏冲突）
};

// P2P Manager 事件
struct P2PManagerEvent {
    P2PEventType type;

    // ENDPOINTS_READY 参数
    std::vector<Endpoint> endpoints;

    // P2P_INIT_NEEDED 参数
    P2PInit p2p_init;

    // PEER_CONNECTED / PEER_DISCONNECTED / DATA_RECEIVED 参数
    NodeId peer_id;

    // PEER_CONNECTED 参数
    asio::ip::udp::endpoint udp_endpoint;

    // DATA_RECEIVED 参数
    std::shared_ptr<std::vector<uint8_t>> plaintext;  // 零拷贝

    // ERROR 参数
    std::string error_message;
};

// ============================================================================
// DataPlane Actor 消息
// ============================================================================

// DataPlane 命令类型
enum class DataPlaneCmdType {
    START,           // 启动
    STOP,            // 停止
    SEND_TO,         // 发送数据到对端
    UPDATE_ROUTE,    // 更新路由配置
};

// 对端数据路径类型
enum class PeerDataPath {
    NONE,    // 未连接
    P2P,     // P2P 直连
    RELAY,   // Relay 转发
};

// DataPlane 命令消息
struct DataPlaneCmd {
    DataPlaneCmdType type;

    // SEND_TO 参数
    NodeId peer_id;
    std::shared_ptr<std::vector<uint8_t>> data;  // 零拷贝

    // UPDATE_ROUTE 参数
    std::unordered_map<NodeId, PeerDataPath> route_table;  // NodeId -> 数据路径
};

// DataPlane 事件类型
enum class DataPlaneEventType {
    STARTED,         // 已启动
    STOPPED,         // 已停止
    DATA_RECEIVED,   // 收到数据
    DATA_ERROR,      // 数据错误（避免与 Windows ERROR 宏冲突）
};

// DataPlane 事件
struct DataPlaneEvent {
    DataPlaneEventType type;

    // DATA_RECEIVED 参数
    NodeId src_node;
    std::shared_ptr<std::vector<uint8_t>> data;  // 零拷贝

    // ERROR 参数
    std::string error_message;
};

// ============================================================================
// Client Actor 内部协调消息
// ============================================================================

// 客户端内部命令类型
enum class ClientInternalCmdType {
    START,                  // 启动客户端
    STOP,                   // 停止客户端
    RECONNECT,              // 重新连接
    TUN_REBUILD,            // 重建 TUN 设备
    IPC_RESTART,            // 重启 IPC 服务器
    ROUTE_REANNOUNCE,       // 重新公告路由
    SSL_CONTEXT_REBUILD,    // 重建 SSL 上下文
};

// 客户端内部命令消息
struct ClientInternalCmd {
    ClientInternalCmdType type;
    std::string reason;  // 命令原因（用于日志）
};

// ============================================================================
// SessionManager 消息（Controller 端）
// ============================================================================

enum class SessionManagerCmdType {
    START,                      // 启动 SessionManager
    STOP,                       // 停止 SessionManager
    BROADCAST_CONFIG_UPDATE,    // 广播配置更新
    BROADCAST_ROUTE_UPDATE,     // 广播路由更新
    NOTIFY_PEER_STATUS,         // 通知对端状态
    CHECK_TIMEOUTS,             // 检查超时
};

// SessionManager 命令消息
struct SessionManagerCmd {
    SessionManagerCmdType type;

    // BROADCAST_CONFIG_UPDATE 参数
    NetworkId network_id = 0;
    NodeId except_node = 0;

    // BROADCAST_ROUTE_UPDATE 参数
    std::vector<RouteInfo> add_routes;
    std::vector<RouteInfo> del_routes;

    // NOTIFY_PEER_STATUS 参数
    NodeId target_node = 0;
    NodeId peer_node = 0;
    bool online = false;
};

enum class SessionManagerEventType {
    STARTED,                // SessionManager 已启动
    STOPPED,                // SessionManager 已停止
    CLIENT_ONLINE,          // 客户端上线
    CLIENT_OFFLINE,         // 客户端下线
    CONFIG_BROADCASTED,     // 配置已广播
    ROUTE_BROADCASTED,      // 路由已广播
    SESSION_ERROR,          // 错误
};

// SessionManager 事件
struct SessionManagerEvent {
    SessionManagerEventType type;

    // CLIENT_ONLINE / CLIENT_OFFLINE 参数
    NodeId node_id = 0;
    NetworkId network_id = 0;

    // CONFIG_BROADCASTED / ROUTE_BROADCASTED 参数
    size_t broadcast_count = 0;  // 广播的节点数量

    // ERROR 参数
    std::string error_message;
};

// ============================================================================
// 消息优先级定义
// ============================================================================

enum class MessagePriority : uint8_t {
    CRITICAL = 0,   // 生命周期、错误
    HIGH = 1,       // 控制面、认证
    NORMAL = 2,     // 数据面、P2P
    LOW = 3,        // 统计、日志
};

// 带优先级的消息包装
template<typename T>
struct PrioritizedMessage {
    T message;
    MessagePriority priority;
    uint64_t timestamp;  // 消息创建时间

    bool operator<(const PrioritizedMessage& other) const {
        if (priority != other.priority) {
            return priority < other.priority;  // 优先级高的在前
        }
        return timestamp < other.timestamp;  // 时间早的在前
    }
};

} // namespace edgelink::messages

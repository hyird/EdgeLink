#pragma once

#include "common/types.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace asio = boost::asio;

namespace edgelink::client {

// NAT 类型
enum class NatType : uint8_t {
    UNKNOWN = 0,        // 未检测
    OPEN = 1,           // 无 NAT / 公网
    FULL_CONE = 2,      // 完全锥形 NAT (最易穿透)
    RESTRICTED = 3,     // 受限锥形 NAT
    PORT_RESTRICTED = 4, // 端口受限锥形 NAT
    SYMMETRIC = 5,       // 对称 NAT (最难穿透)
};

// NAT 类型名称
const char* nat_type_name(NatType type);

// 端点发现配置
struct EndpointConfig {
    uint32_t stun_timeout_ms = 5000;      // STUN 查询超时
    uint32_t stun_retry_count = 3;        // STUN 重试次数
    uint32_t stun_retry_interval_ms = 500; // STUN 重试间隔
    bool enable_lan_discovery = true;     // 启用 LAN 端点发现
    bool enable_stun_discovery = true;    // 启用 STUN 端点发现
};

// STUN 查询结果
struct StunQueryResult {
    bool success = false;
    Endpoint mapped_endpoint;     // 映射后的公网端点
    std::string stun_server;      // 使用的 STUN 服务器
    uint16_t local_port = 0;      // 本地端口
    std::chrono::milliseconds rtt{0}; // 往返时间
};

/**
 * EndpointManager - 端点发现和 NAT 检测
 *
 * 职责:
 * - 发现本地 LAN 端点
 * - 通过 STUN 发现公网端点
 * - 检测 NAT 类型
 * - 维护端点列表
 */
class EndpointManager {
public:
    explicit EndpointManager(asio::io_context& ioc);
    ~EndpointManager();

    // ========================================================================
    // 配置
    // ========================================================================

    // 设置配置
    void set_config(const EndpointConfig& config);

    // 设置 STUN 服务器列表
    void set_stun_servers(const std::vector<StunInfo>& stuns);

    // 设置本地绑定端口 (0 = 随机)
    void set_local_port(uint16_t port);

    // ========================================================================
    // 端点发现
    // ========================================================================

    // 初始化 UDP socket (必须在其他操作前调用)
    asio::awaitable<bool> init_socket();

    // 关闭 socket
    void close_socket();

    // 获取本地端点 (LAN IP + 绑定端口)
    std::vector<Endpoint> get_local_endpoints() const;

    // 通过 STUN 查询公网端点 (异步)
    asio::awaitable<StunQueryResult> query_stun_endpoint();

    // 获取所有已发现的端点 (LAN + STUN)
    std::vector<Endpoint> get_all_endpoints() const;

    // ========================================================================
    // NAT 类型检测
    // ========================================================================

    // 检测 NAT 类型 (需要至少 2 个 STUN 服务器)
    asio::awaitable<NatType> detect_nat_type();

    // 获取当前 NAT 类型
    NatType nat_type() const { return nat_type_.load(); }

    // ========================================================================
    // Socket 访问
    // ========================================================================

    // 获取 UDP socket (供 P2PManager 使用)
    asio::ip::udp::socket& socket() { return socket_; }
    const asio::ip::udp::socket& socket() const { return socket_; }

    // 获取本地端口
    uint16_t local_port() const;

    // 检查 socket 是否打开
    bool is_socket_open() const { return socket_.is_open(); }

    // ========================================================================
    // 状态
    // ========================================================================

    // 获取上次 STUN 查询结果
    const StunQueryResult& last_stun_result() const { return last_stun_result_; }

    // 获取 STUN 端点 (如果有)
    std::optional<Endpoint> stun_endpoint() const;

    // ========================================================================
    // STUN 包处理（供 P2PManager::recv_loop 调用）
    // ========================================================================

    // 判断 UDP 包是否是 STUN 响应
    static bool is_stun_response(std::span<const uint8_t> data);

    // 处理收到的 STUN 响应包（由 P2PManager::recv_loop 调用）
    void handle_stun_response(std::span<const uint8_t> data);

private:
    // 发送 STUN Binding Request
    asio::awaitable<StunQueryResult> send_stun_request(
        const asio::ip::udp::endpoint& stun_server,
        const std::string& server_name);

    // 解析 STUN Binding Response
    std::optional<Endpoint> parse_stun_response(
        std::span<const uint8_t> data,
        const std::array<uint8_t, 12>& txn_id);

    // 获取本地 IP 地址列表
    std::vector<asio::ip::address> get_local_addresses() const;

    asio::io_context& ioc_;
    asio::ip::udp::socket socket_;
    EndpointConfig config_;

    // STUN 服务器列表
    std::vector<StunInfo> stun_servers_;

    // 请求的本地端口 (0 = 随机)
    uint16_t requested_port_ = 0;

    // 本地端点缓存
    mutable std::mutex local_mutex_;
    std::vector<Endpoint> local_endpoints_;

    // STUN 结果
    mutable std::mutex stun_mutex_;
    StunQueryResult last_stun_result_;
    std::optional<Endpoint> stun_endpoint_;

    // NAT 类型
    std::atomic<NatType> nat_type_{NatType::UNKNOWN};

    // STUN 响应 channel（用于与 recv_loop 协作）
    // 当 recv_loop 收到 STUN 响应时，通过 channel 发送给等待的协程
    using StunResponseChannel = asio::experimental::channel<
        void(boost::system::error_code, std::array<uint8_t, 12>, std::vector<uint8_t>)>;
    std::unique_ptr<StunResponseChannel> stun_response_channel_;

    // 当前等待的 STUN 请求 txn_id（用于过滤不匹配的响应）
    mutable std::mutex pending_stun_mutex_;
    std::set<std::array<uint8_t, 12>> pending_stun_txn_ids_;
};

} // namespace edgelink::client

#pragma once

#include "client/channel.hpp"
#include "common/types.hpp"
#include "common/crypto.hpp"
#include "client/peer_manager.hpp"
#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <chrono>
#include <boost/cobalt.hpp>

namespace cobalt = boost::cobalt;

namespace edgelink::client {

// RTT 统计信息
struct RelayConnectionStats {
    uint16_t avg_rtt_ms = 0;          // 平均 RTT
    uint16_t min_rtt_ms = UINT16_MAX; // 最小 RTT
    uint16_t max_rtt_ms = 0;          // 最大 RTT
    uint32_t ping_count = 0;          // 发送的 PING 数量
    uint32_t pong_count = 0;          // 收到的 PONG 数量
    uint8_t packet_loss_percent = 0;  // 丢包率
    uint64_t last_rtt_time = 0;       // 上次 RTT 测量时间
};

// 单条 Relay 连接的封装
struct RelayConnectionInfo {
    ConnectionId connection_id = 0;
    std::shared_ptr<RelayChannel> channel;
    tcp::endpoint endpoint;
    RelayConnectionStats stats;
    bool is_active = false;
    uint64_t connected_time = 0;
};

// ============================================================================
// RelayConnectionPool - 单个 Relay 的多 IP 连接池
// ============================================================================

class RelayConnectionPool : public std::enable_shared_from_this<RelayConnectionPool> {
public:
    RelayConnectionPool(asio::io_context& ioc, ssl::context& ssl_ctx,
                        CryptoEngine& crypto, PeerManager& peers,
                        const RelayInfo& relay_info, bool use_tls);

    // 并发连接所有 IP（从 relay_info 的 endpoints 或 DNS 解析）
    cobalt::task<bool> connect_all(const std::vector<uint8_t>& relay_token);

    // 关闭所有连接
    cobalt::task<void> close_all();

    // 获取活跃连接（RTT 最优）
    std::shared_ptr<RelayChannel> active_connection();

    // 获取指定连接
    std::shared_ptr<RelayChannel> get_connection(ConnectionId id);

    // 所有连接
    std::vector<std::shared_ptr<RelayChannel>> all_connections();

    // 连接数量
    size_t connection_count() const;

    // 测量所有连接的 RTT
    cobalt::task<void> measure_rtt_all();

    // 选择最优连接（根据 RTT）
    void select_best_connection();

    // 切换到指定连接
    bool switch_to(ConnectionId connection_id);

    // Relay 信息
    ServerId relay_id() const { return relay_info_.server_id; }
    const RelayInfo& info() const { return relay_info_; }

    // 获取指定连接的统计信息
    std::optional<RelayConnectionStats> get_stats(ConnectionId id) const;

    // 获取活跃连接 ID
    ConnectionId active_connection_id() const;

    // 设置事件通道（转发给所有连接）
    void set_event_channel(events::RelayEventChannel* ch);

private:
    // 连接单个 endpoint
    cobalt::task<bool> connect_single(
        const tcp::endpoint& endpoint,
        const std::vector<uint8_t>& relay_token);

    // DNS 解析获取 endpoints
    cobalt::task<std::vector<tcp::endpoint>> resolve_endpoints();

    // 生成连接 ID
    ConnectionId generate_connection_id();

    // 更新连接的 RTT 统计
    void update_rtt(ConnectionId id, uint16_t rtt_ms);

    asio::io_context& ioc_;
    ssl::context& ssl_ctx_;
    CryptoEngine& crypto_;
    PeerManager& peers_;
    RelayInfo relay_info_;
    bool use_tls_;

    // 连接管理（线程安全）
    mutable std::shared_mutex mutex_;
    std::unordered_map<ConnectionId, RelayConnectionInfo> connections_;
    ConnectionId active_connection_id_ = 0;

    // 事件通道
    events::RelayEventChannel* event_ch_ = nullptr;
};

} // namespace edgelink::client

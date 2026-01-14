#include "client/relay_pool.hpp"
#include "common/log.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace edgelink::client {

namespace {
spdlog::logger& log() {
    static auto logger = edgelink::create_logger("relay_pool");
    return *logger;
}
} // anonymous namespace

RelayConnectionPool::RelayConnectionPool(
    asio::io_context& ioc, ssl::context& ssl_ctx,
    CryptoEngine& crypto, PeerManager& peers,
    const RelayInfo& relay_info, bool use_tls)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , peers_(peers)
    , relay_info_(relay_info)
    , use_tls_(use_tls) {
}

asio::awaitable<bool> RelayConnectionPool::connect_all(
    const std::vector<uint8_t>& relay_token) {

    log().info("Connecting to relay {} ({}), resolving endpoints...",
               relay_info_.server_id, relay_info_.hostname);

    // 获取所有 endpoints（从 RelayInfo 或 DNS 解析）
    std::vector<tcp::endpoint> endpoints;

    if (!relay_info_.endpoints.empty()) {
        // 使用 RelayInfo 中预配置的 endpoints
        for (const auto& ep : relay_info_.endpoints) {
            try {
                auto addr = asio::ip::make_address(ep.address);
                endpoints.emplace_back(addr, ep.port);
            } catch (const std::exception& e) {
                log().warn("Invalid endpoint address {}: {}", ep.address, e.what());
            }
        }
    }

    // 如果没有预配置的 endpoints，进行 DNS 解析
    if (endpoints.empty()) {
        endpoints = co_await resolve_endpoints();
    }

    if (endpoints.empty()) {
        log().error("No endpoints available for relay {}", relay_info_.server_id);
        co_return false;
    }

    log().info("Relay {} has {} endpoint(s), connecting in parallel...",
               relay_info_.server_id, endpoints.size());

    // 并发连接所有 endpoints
    std::vector<asio::awaitable<bool>> tasks;
    for (const auto& ep : endpoints) {
        tasks.push_back(connect_single(ep, relay_token));
    }

    // 等待所有连接完成
    size_t success_count = 0;
    for (auto& task : tasks) {
        try {
            if (co_await std::move(task)) {
                success_count++;
            }
        } catch (const std::exception& e) {
            log().warn("Connection task failed: {}", e.what());
        }
    }

    log().info("Relay {} connection complete: {}/{} successful",
               relay_info_.server_id, success_count, endpoints.size());

    // 选择最优连接
    if (success_count > 0) {
        select_best_connection();
    }

    co_return success_count > 0;
}

asio::awaitable<bool> RelayConnectionPool::connect_single(
    const tcp::endpoint& endpoint,
    const std::vector<uint8_t>& relay_token) {

    // 构建 URL
    std::string url;
    if (use_tls_) {
        url = fmt::format("wss://{}:{}/api/v1/relay",
                         endpoint.address().to_string(), endpoint.port());
    } else {
        url = fmt::format("ws://{}:{}/api/v1/relay",
                         endpoint.address().to_string(), endpoint.port());
    }

    log().debug("Connecting to relay endpoint: {}", url);

    // 创建 RelayChannel
    auto channel = std::make_shared<RelayChannel>(
        ioc_, ssl_ctx_, crypto_, peers_, url, use_tls_);

    // 设置事件通道
    channel->set_channels(channels_);

    // 连接
    auto start_time = std::chrono::steady_clock::now();
    bool connected = co_await channel->connect(relay_token);

    if (!connected) {
        log().warn("Failed to connect to relay endpoint: {}", url);
        co_return false;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start_time).count();

    // 生成连接 ID
    ConnectionId conn_id = generate_connection_id();

    // 存储连接信息
    {
        std::unique_lock lock(mutex_);

        RelayConnectionInfo info;
        info.connection_id = conn_id;
        info.channel = channel;
        info.endpoint = endpoint;
        info.connected_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        info.stats.avg_rtt_ms = static_cast<uint16_t>(elapsed);  // 初始 RTT = 连接时间

        connections_[conn_id] = std::move(info);

        log().info("Connected to relay {} endpoint {} (conn_id=0x{:08x}, initial_rtt={}ms)",
                   relay_info_.server_id, endpoint.address().to_string(),
                   conn_id, elapsed);
    }

    co_return true;
}

asio::awaitable<void> RelayConnectionPool::close_all() {
    std::vector<std::shared_ptr<RelayChannel>> channels_to_close;

    {
        std::unique_lock lock(mutex_);
        for (auto& [id, info] : connections_) {
            if (info.channel) {
                channels_to_close.push_back(info.channel);
            }
        }
        connections_.clear();
        active_connection_id_ = 0;
    }

    for (auto& channel : channels_to_close) {
        try {
            co_await channel->close();
        } catch (...) {
            // 忽略关闭错误
        }
    }

    log().info("Closed all connections for relay {}", relay_info_.server_id);
}

std::shared_ptr<RelayChannel> RelayConnectionPool::active_connection() {
    std::shared_lock lock(mutex_);
    auto it = connections_.find(active_connection_id_);
    if (it != connections_.end() && it->second.channel &&
        it->second.channel->is_connected()) {
        return it->second.channel;
    }
    return nullptr;
}

std::shared_ptr<RelayChannel> RelayConnectionPool::get_connection(ConnectionId id) {
    std::shared_lock lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        return it->second.channel;
    }
    return nullptr;
}

std::vector<std::shared_ptr<RelayChannel>> RelayConnectionPool::all_connections() {
    std::vector<std::shared_ptr<RelayChannel>> result;
    std::shared_lock lock(mutex_);
    for (const auto& [id, info] : connections_) {
        if (info.channel) {
            result.push_back(info.channel);
        }
    }
    return result;
}

size_t RelayConnectionPool::connection_count() const {
    std::shared_lock lock(mutex_);
    return connections_.size();
}

asio::awaitable<void> RelayConnectionPool::measure_rtt_all() {
    // TODO: 实现 RTT 测量
    // 需要 RelayChannel 支持 PING/PONG
    co_return;
}

void RelayConnectionPool::select_best_connection() {
    std::unique_lock lock(mutex_);

    ConnectionId best_id = 0;
    uint16_t best_rtt = UINT16_MAX;

    for (const auto& [id, info] : connections_) {
        if (info.channel && info.channel->is_connected()) {
            if (info.stats.avg_rtt_ms < best_rtt) {
                best_rtt = info.stats.avg_rtt_ms;
                best_id = id;
            }
        }
    }

    if (best_id != 0 && best_id != active_connection_id_) {
        // 更新活跃状态
        if (auto old_it = connections_.find(active_connection_id_);
            old_it != connections_.end()) {
            old_it->second.is_active = false;
        }

        active_connection_id_ = best_id;
        connections_[best_id].is_active = true;

        log().info("Selected best connection for relay {}: conn_id=0x{:08x}, rtt={}ms",
                   relay_info_.server_id, best_id, best_rtt);
    }
}

bool RelayConnectionPool::switch_to(ConnectionId connection_id) {
    std::unique_lock lock(mutex_);

    auto it = connections_.find(connection_id);
    if (it == connections_.end() || !it->second.channel ||
        !it->second.channel->is_connected()) {
        log().warn("Cannot switch to connection 0x{:08x}: not available", connection_id);
        return false;
    }

    // 更新活跃状态
    if (auto old_it = connections_.find(active_connection_id_);
        old_it != connections_.end()) {
        old_it->second.is_active = false;
    }

    active_connection_id_ = connection_id;
    it->second.is_active = true;

    log().info("Switched to connection 0x{:08x} for relay {}",
               connection_id, relay_info_.server_id);

    return true;
}

std::optional<RelayConnectionStats> RelayConnectionPool::get_stats(ConnectionId id) const {
    std::shared_lock lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        return it->second.stats;
    }
    return std::nullopt;
}

ConnectionId RelayConnectionPool::active_connection_id() const {
    std::shared_lock lock(mutex_);
    return active_connection_id_;
}

void RelayConnectionPool::set_channels(RelayChannelEvents channels) {
    channels_ = channels;

    // 更新已有连接的通道
    std::shared_lock lock(mutex_);
    for (auto& [id, info] : connections_) {
        if (info.channel) {
            info.channel->set_channels(channels);
        }
    }
}

asio::awaitable<std::vector<tcp::endpoint>> RelayConnectionPool::resolve_endpoints() {
    std::vector<tcp::endpoint> result;

    try {
        tcp::resolver resolver(ioc_);

        // 从 hostname 解析
        std::string host = relay_info_.hostname;
        std::string port = "443";  // 默认 TLS 端口

        // 检查是否包含端口
        auto colon_pos = host.rfind(':');
        if (colon_pos != std::string::npos && colon_pos > 0) {
            // 排除 IPv6 地址的情况
            if (host[0] != '[' || colon_pos > host.find(']')) {
                port = host.substr(colon_pos + 1);
                host = host.substr(0, colon_pos);
            }
        }

        if (!use_tls_) {
            port = "80";  // 默认非 TLS 端口
        }

        log().debug("Resolving relay hostname: {}:{}", host, port);

        auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

        for (const auto& ep : endpoints) {
            result.push_back(ep.endpoint());
            log().debug("Resolved: {}", ep.endpoint().address().to_string());
        }

    } catch (const std::exception& e) {
        log().error("Failed to resolve relay hostname {}: {}",
                    relay_info_.hostname, e.what());
    }

    co_return result;
}

ConnectionId RelayConnectionPool::generate_connection_id() {
    // 使用时间戳 + 随机数生成唯一 ID
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<ConnectionId>(now & 0xFFFFFFFF);
}

void RelayConnectionPool::update_rtt(ConnectionId id, uint16_t rtt_ms) {
    std::unique_lock lock(mutex_);
    auto it = connections_.find(id);
    if (it != connections_.end()) {
        auto& stats = it->second.stats;
        stats.ping_count++;
        stats.pong_count++;

        // 更新最小/最大值
        if (rtt_ms < stats.min_rtt_ms) stats.min_rtt_ms = rtt_ms;
        if (rtt_ms > stats.max_rtt_ms) stats.max_rtt_ms = rtt_ms;

        // 简单的移动平均
        stats.avg_rtt_ms = (stats.avg_rtt_ms * 7 + rtt_ms) / 8;
        stats.last_rtt_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
}

} // namespace edgelink::client

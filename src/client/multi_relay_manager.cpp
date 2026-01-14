#include "client/multi_relay_manager.hpp"
#include "common/log.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace edgelink::client {

namespace {
spdlog::logger& log() {
    static auto logger = edgelink::create_logger("multi_relay");
    return *logger;
}
} // anonymous namespace

MultiRelayManager::MultiRelayManager(
    asio::io_context& ioc, ssl::context& ssl_ctx,
    CryptoEngine& crypto, PeerManager& peers,
    const MultiRelayConfig& config)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , crypto_(crypto)
    , peers_(peers)
    , config_(config) {
}

asio::awaitable<bool> MultiRelayManager::initialize(
    const std::vector<RelayInfo>& relays,
    const std::vector<uint8_t>& relay_token,
    bool use_tls) {

    if (relays.empty()) {
        log().warn("No relays configured");
        co_return false;
    }

    log().info("Initializing multi-relay manager with {} relay(s)", relays.size());

    size_t success_count = 0;

    // 为每个 Relay 创建连接池并连接
    for (const auto& relay : relays) {
        log().info("Setting up relay pool for {} (id={}, region={})",
                   relay.hostname, relay.server_id, relay.region);

        auto pool = std::make_shared<RelayConnectionPool>(
            ioc_, ssl_ctx_, crypto_, peers_, relay, use_tls);

        // 设置事件通道
        pool->set_channels(channels_);

        // 连接所有 IP
        bool connected = co_await pool->connect_all(relay_token);

        if (connected) {
            std::unique_lock lock(mutex_);
            relay_pools_[relay.server_id] = pool;
            success_count++;

            log().info("Relay pool {} initialized with {} connection(s)",
                       relay.server_id, pool->connection_count());
        } else {
            log().warn("Failed to initialize relay pool for {}", relay.server_id);
        }
    }

    if (success_count == 0) {
        log().error("Failed to connect to any relay");
        co_return false;
    }

    // 启动 RTT 测量循环
    running_ = true;
    rtt_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    asio::co_spawn(ioc_, rtt_measure_loop(), asio::detached);

    log().info("Multi-relay manager initialized: {}/{} relays connected",
               success_count, relays.size());

    co_return true;
}

asio::awaitable<void> MultiRelayManager::stop() {
    running_ = false;

    if (rtt_timer_) {
        rtt_timer_->cancel();
    }

    std::vector<std::shared_ptr<RelayConnectionPool>> pools;
    {
        std::unique_lock lock(mutex_);
        for (auto& [id, pool] : relay_pools_) {
            pools.push_back(pool);
        }
        relay_pools_.clear();
    }

    for (auto& pool : pools) {
        co_await pool->close_all();
    }

    routing_table_.clear();

    log().info("Multi-relay manager stopped");
}

std::shared_ptr<RelayChannel> MultiRelayManager::get_channel_for_peer(NodeId peer_id) {
    // 1. 查询路由表
    auto route = routing_table_.get_route(peer_id);

    if (route) {
        // 2. 使用路由表指定的 Relay 和连接
        std::shared_lock lock(mutex_);
        auto it = relay_pools_.find(route->relay_id);
        if (it != relay_pools_.end()) {
            auto channel = it->second->get_connection(route->connection_id);
            if (channel && channel->is_connected()) {
                return channel;
            }
            // fallback: 使用该 Relay 的活跃连接
            channel = it->second->active_connection();
            if (channel && channel->is_connected()) {
                return channel;
            }
        }
    }

    // 3. 没有路由或指定连接不可用，使用第一个可用的 Relay
    std::shared_lock lock(mutex_);
    for (const auto& [id, pool] : relay_pools_) {
        auto channel = pool->active_connection();
        if (channel && channel->is_connected()) {
            return channel;
        }
    }

    return nullptr;
}

std::shared_ptr<RelayConnectionPool> MultiRelayManager::get_relay_pool(ServerId relay_id) {
    std::shared_lock lock(mutex_);
    auto it = relay_pools_.find(relay_id);
    if (it != relay_pools_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<RelayConnectionPool>> MultiRelayManager::all_relay_pools() {
    std::vector<std::shared_ptr<RelayConnectionPool>> result;
    std::shared_lock lock(mutex_);
    result.reserve(relay_pools_.size());
    for (const auto& [id, pool] : relay_pools_) {
        result.push_back(pool);
    }
    return result;
}

void MultiRelayManager::handle_peer_routing_update(const PeerRoutingUpdate& update) {
    log().info("Received PEER_ROUTING_UPDATE v{} with {} routes",
               update.version, update.routes.size());

    routing_table_.update(update);

    // 记录每个路由更新
    for (const auto& entry : update.routes) {
        log().debug("Route: peer {} -> relay {}, conn 0x{:08x}",
                    entry.peer_node_id, entry.relay_id, entry.connection_id);
    }
}

std::vector<std::pair<ServerId, ConnectionId>> MultiRelayManager::get_all_connections() const {
    std::vector<std::pair<ServerId, ConnectionId>> result;
    std::shared_lock lock(mutex_);

    for (const auto& [relay_id, pool] : relay_pools_) {
        // 获取该 Relay 的活跃连接 ID
        auto conn_id = pool->active_connection_id();
        if (conn_id != 0) {
            result.emplace_back(relay_id, conn_id);
        }
    }

    return result;
}

std::shared_ptr<RelayChannel> MultiRelayManager::get_active_relay_channel(ServerId relay_id) {
    auto pool = get_relay_pool(relay_id);
    if (pool) {
        return pool->active_connection();
    }
    return nullptr;
}

bool MultiRelayManager::has_available_connection() const {
    std::shared_lock lock(mutex_);
    for (const auto& [id, pool] : relay_pools_) {
        if (pool->connection_count() > 0) {
            return true;
        }
    }
    return false;
}

size_t MultiRelayManager::total_connection_count() const {
    size_t count = 0;
    std::shared_lock lock(mutex_);
    for (const auto& [id, pool] : relay_pools_) {
        count += pool->connection_count();
    }
    return count;
}

void MultiRelayManager::set_channels(RelayChannelEvents channels) {
    channels_ = channels;

    std::shared_lock lock(mutex_);
    for (auto& [id, pool] : relay_pools_) {
        pool->set_channels(channels);
    }
}

asio::awaitable<void> MultiRelayManager::rtt_measure_loop() {
    while (running_) {
        try {
            rtt_timer_->expires_after(config_.rtt_measure_interval);
            co_await rtt_timer_->async_wait(asio::use_awaitable);

            if (!running_) break;

            // 测量所有 Relay 连接的 RTT
            std::vector<std::shared_ptr<RelayConnectionPool>> pools;
            {
                std::shared_lock lock(mutex_);
                for (const auto& [id, pool] : relay_pools_) {
                    pools.push_back(pool);
                }
            }

            for (auto& pool : pools) {
                co_await pool->measure_rtt_all();
                pool->select_best_connection();
            }

            log().trace("RTT measurement cycle completed for {} relay(s)", pools.size());

        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                break;
            }
            log().warn("RTT measure loop error: {}", e.what());
        }
    }

    log().debug("RTT measure loop stopped");
}

} // namespace edgelink::client

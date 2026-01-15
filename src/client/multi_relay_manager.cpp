#include "client/multi_relay_manager.hpp"
#include "common/logger.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace edgelink::client {

namespace {
auto& log() {
    static auto& logger = Logger::get("multi_relay");
    return logger;
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
    bool use_tls,
    const std::string& controller_hostname) {

    if (relays.empty()) {
        log().warn("No relays configured");
        co_return false;
    }

    log().info("Initializing multi-relay manager with {} relay(s)", relays.size());

    size_t success_count = 0;

    // 为每个 Relay 创建连接池并连接
    for (const auto& relay : relays) {
        // 如果 relay hostname 是 "builtin" 或为空，使用控制器的 hostname
        RelayInfo actual_relay = relay;
        if (actual_relay.hostname.empty() || actual_relay.hostname == "builtin") {
            log().info("Relay {} uses builtin relay, using controller hostname: {}",
                       relay.server_id, controller_hostname);
            actual_relay.hostname = controller_hostname;
        }

        log().info("Setting up relay pool for {} (id={}, region={})",
                   actual_relay.hostname, actual_relay.server_id, actual_relay.region);

        auto pool = std::make_shared<RelayConnectionPool>(
            ioc_, ssl_ctx_, crypto_, peers_, actual_relay, use_tls);

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
    rtt_loop_done_ch_ = std::make_unique<CompletionChannel>(ioc_, 1);
    asio::co_spawn(ioc_, rtt_measure_loop(), asio::detached);

    log().info("Multi-relay manager initialized: {}/{} relays connected",
               success_count, relays.size());

    co_return true;
}

asio::awaitable<void> MultiRelayManager::stop() {
    running_ = false;

    // 取消 RTT 定时器并等待循环退出
    if (rtt_timer_) {
        rtt_timer_->cancel();

        // 等待 RTT 循环实际退出（避免 use-after-free）
        // 添加超时保护避免卡住
        if (rtt_loop_done_ch_) {
            try {
                // 使用轮询方式避免 parallel_group 导致的 TLS allocator 崩溃
                asio::steady_timer timeout_timer(ioc_);
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                bool loop_stopped = false;

                while (!loop_stopped && std::chrono::steady_clock::now() < deadline) {
                    rtt_loop_done_ch_->try_receive([&](boost::system::error_code) {
                        loop_stopped = true;
                    });

                    if (loop_stopped) {
                        break;
                    }

                    timeout_timer.expires_after(std::chrono::milliseconds(50));
                    co_await timeout_timer.async_wait(asio::use_awaitable);
                }

                if (loop_stopped) {
                    log().debug("RTT measure loop confirmed stopped");
                } else {
                    log().warn("RTT measure loop stop timeout (2s), forcing shutdown");
                }
            } catch (...) {
                log().debug("Failed to wait for RTT loop completion");
            }
        }
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

    // Validate routes before applying
    size_t valid_count = 0;
    size_t invalid_count = 0;

    PeerRoutingUpdate validated_update;
    validated_update.version = update.version;

    for (const auto& entry : update.routes) {
        // Check if relay exists in our pools
        bool relay_exists = false;
        {
            std::shared_lock lock(mutex_);
            relay_exists = (relay_pools_.find(entry.relay_id) != relay_pools_.end());
        }

        if (relay_exists) {
            // Optionally verify connection_id exists for the relay
            auto pool = get_relay_pool(entry.relay_id);
            if (pool) {
                auto channel = pool->get_connection(entry.connection_id);
                if (channel && channel->is_connected()) {
                    validated_update.routes.push_back(entry);
                    valid_count++;
                    log().debug("Route accepted: peer {} -> relay {}, conn 0x{:08x}",
                                entry.peer_node_id, entry.relay_id, entry.connection_id);
                } else {
                    invalid_count++;
                    log().warn("Route rejected: peer {} -> relay {}, conn 0x{:08x} (connection not found or not connected)",
                               entry.peer_node_id, entry.relay_id, entry.connection_id);
                }
            } else {
                invalid_count++;
                log().warn("Route rejected: peer {} -> relay {} (pool not found)",
                           entry.peer_node_id, entry.relay_id);
            }
        } else {
            invalid_count++;
            log().warn("Route rejected: peer {} -> relay {} (relay not in our pools)",
                       entry.peer_node_id, entry.relay_id);
        }
    }

    // Only update routing table with validated routes
    if (!validated_update.routes.empty()) {
        routing_table_.update(validated_update);
        log().info("Applied {} valid route(s), rejected {} invalid route(s)",
                   valid_count, invalid_count);
    } else {
        log().warn("No valid routes in update, routing table unchanged");
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

    // 通知 stop() 循环已完成
    if (rtt_loop_done_ch_) {
        rtt_loop_done_ch_->try_send(boost::system::error_code{});
    }
}

} // namespace edgelink::client

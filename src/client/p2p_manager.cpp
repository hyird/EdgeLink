#include "client/p2p_manager.hpp"
#include "common/logger.hpp"
#include "common/constants.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <chrono>

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("client.p2p"); }

// P2P 数据帧头格式: [4 bytes magic][4 bytes src_node][4 bytes dst_node][1 byte type][payload]
constexpr size_t P2P_FRAME_HEADER_SIZE = 13;
constexpr uint8_t P2P_TYPE_PING = 0x01;
constexpr uint8_t P2P_TYPE_PONG = 0x02;
constexpr uint8_t P2P_TYPE_KEEPALIVE = 0x03;
constexpr uint8_t P2P_TYPE_DATA = 0x04;

} // anonymous namespace

P2PManager::P2PManager(asio::io_context& ioc, CryptoEngine& crypto,
                       PeerManager& peers, EndpointManager& endpoints,
                       ClientStateMachine& state_machine)
    : ioc_(ioc)
    , crypto_(crypto)
    , peers_(peers)
    , endpoints_(endpoints)
    , state_machine_(state_machine)
    , keepalive_timer_(ioc)
    , punch_timer_(ioc)
    , retry_timer_(ioc)
    , endpoint_refresh_timer_(ioc)
{
}

P2PManager::~P2PManager() {
    running_ = false;
}

void P2PManager::set_config(const P2PConfig& config) {
    config_ = config;
}

void P2PManager::set_channels(P2PChannels channels) {
    channels_ = std::move(channels);
}

asio::awaitable<bool> P2PManager::start() {
    if (!config_.enabled) {
        log().info("P2P 已禁用");
        co_return false;
    }

    if (running_) {
        co_return true;
    }

    // 防止多个协程同时进入启动流程
    bool expected = false;
    if (!starting_.compare_exchange_strong(expected, true)) {
        log().debug("P2P 管理器正在启动中，等待...");
        while (starting_ && !running_) {
            asio::steady_timer wait_timer(ioc_);
            wait_timer.expires_after(std::chrono::milliseconds(100));
            co_await wait_timer.async_wait(asio::use_awaitable);
        }
        co_return running_.load();
    }

    auto reset_starting = [this]() { starting_ = false; };

    // 初始化 UDP socket
    endpoints_.set_local_port(config_.bind_port);
    if (!co_await endpoints_.init_socket()) {
        log().error("初始化 UDP socket 失败");
        reset_starting();
        co_return false;
    }

    // 查询 STUN 端点
    auto stun_result = co_await endpoints_.query_stun_endpoint();
    if (stun_result.success) {
        auto& addr = stun_result.mapped_endpoint.address;
        log().info("STUN 端点: {}.{}.{}.{}:{}",
            addr[0], addr[1], addr[2], addr[3],
            stun_result.mapped_endpoint.port);
    }

    running_ = true;
    starting_ = false;

    // 启动后台任务
    asio::co_spawn(ioc_, recv_loop(), asio::detached);
    asio::co_spawn(ioc_, keepalive_loop(), asio::detached);
    asio::co_spawn(ioc_, punch_timeout_loop(), asio::detached);
    asio::co_spawn(ioc_, retry_loop(), asio::detached);
    asio::co_spawn(ioc_, endpoint_refresh_loop(), asio::detached);

    log().info("P2P 管理器已启动，端口 {}", endpoints_.local_port());

    // 通知端点已就绪
    auto eps = endpoints_.get_all_endpoints();
    if (!eps.empty()) {
        notify_endpoints_ready(eps);
    }

    co_return true;
}

asio::awaitable<void> P2PManager::stop() {
    if (!running_) {
        co_return;
    }

    running_ = false;
    starting_ = false;

    // 取消定时器
    keepalive_timer_.cancel();
    punch_timer_.cancel();
    retry_timer_.cancel();
    endpoint_refresh_timer_.cancel();

    // 关闭 socket
    endpoints_.close_socket();

    // 清除上下文
    {
        std::unique_lock lock(contexts_mutex_);
        peer_contexts_.clear();
    }

    log().info("P2P 管理器已停止");
}

asio::awaitable<void> P2PManager::connect_peer(NodeId peer_id) {
    // 检查状态机中的当前状态
    auto current_state = state_machine_.get_peer_p2p_state(peer_id);
    if (current_state == P2PConnectionState::CONNECTED ||
        current_state == P2PConnectionState::PUNCHING ||
        current_state == P2PConnectionState::INITIATING ||
        current_state == P2PConnectionState::WAITING_ENDPOINT) {
        co_return;
    }

    uint32_t init_seq;
    {
        std::unique_lock lock(contexts_mutex_);
        auto& ctx = peer_contexts_[peer_id];
        ctx.init_seq = ++init_seq_;
        // 状态由 state_machine_ 管理
        ctx.punch_count = 0;
        ctx.last_punch_time = now_us();
        init_seq = ctx.init_seq;
    }

    // 更新状态机为 WAITING_ENDPOINT（跳过 INITIATING 避免状态竞争）
    state_machine_.set_peer_p2p_state(peer_id, P2PConnectionState::WAITING_ENDPOINT);

    // 先上报端点
    auto eps = endpoints_.get_all_endpoints();
    if (!eps.empty()) {
        log().debug("上报 {} 个端点后再发送 P2P_INIT", eps.size());
        notify_endpoints_ready(eps);
    }

    // 发送 P2P_INIT 请求
    P2PInit init;
    init.target_node = peer_id;
    init.init_seq = init_seq;

    log().debug("发送 P2P_INIT 到 peer {}, seq={}", peer_id, init.init_seq);

    request_p2p_init(init);
}

void P2PManager::disconnect_peer(NodeId peer_id) {
    {
        std::unique_lock lock(contexts_mutex_);
        peer_contexts_.erase(peer_id);
    }

    // 更新状态机
    state_machine_.set_peer_p2p_state(peer_id, P2PConnectionState::NONE);
    state_machine_.set_peer_data_path(peer_id, PeerDataPath::UNKNOWN);
}

void P2PManager::handle_p2p_endpoint(const P2PEndpointMsg& msg) {
    if (!running_) {
        log().debug("P2P 管理器未运行，忽略 peer {} 的 P2P_ENDPOINT", msg.peer_node);
        return;
    }

    bool passive_punch = (msg.init_seq == 0);

    // 验证对端身份：必须是已知的合法节点
    if (!peers_.has_peer(msg.peer_node)) {
        log().warn("收到未注册 peer {} 的 P2P_ENDPOINT，拒绝", msg.peer_node);
        return;
    }

    // 验证公钥匹配
    auto expected_key = peers_.get_peer_node_key(msg.peer_node);
    if (!expected_key || *expected_key != msg.peer_key) {
        log().warn("Peer {} 的公钥不匹配，拒绝 P2P_ENDPOINT", msg.peer_node);
        return;
    }

    {
        std::unique_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(msg.peer_node);

        if (it == peer_contexts_.end()) {
            if (passive_punch && !msg.endpoints.empty()) {
                log().debug("被动 P2P 打洞请求来自 peer {}", msg.peer_node);
            } else {
                log().warn("收到未知 peer {} 的 P2P_ENDPOINT", msg.peer_node);
                return;
            }
        } else if (!passive_punch) {
            if (it->second.init_seq != msg.init_seq) {
                log().debug("P2P_ENDPOINT seq 不匹配: 期望 {}, 收到 {}",
                    it->second.init_seq, msg.init_seq);
                return;
            }
        }

        // 获取或创建上下文
        auto& ctx = peer_contexts_[msg.peer_node];

        // 检查状态
        auto current_state = state_machine_.get_peer_p2p_state(msg.peer_node);
        if (current_state == P2PConnectionState::CONNECTED) {
            log().debug("已连接到 peer {}，忽略 P2P_ENDPOINT", msg.peer_node);
            return;
        }

        // 保存对端信息
        ctx.peer_key = msg.peer_key;
        ctx.peer_endpoints = msg.endpoints;
        ctx.punch_count = 0;
        ctx.last_punch_time = now_us();
    }

    log().debug("收到 peer {} 的 P2P_ENDPOINT: {} 个端点{}",
        msg.peer_node, msg.endpoints.size(),
        passive_punch ? " (被动打洞)" : "");

    for (const auto& ep : msg.endpoints) {
        log().debug("  - {}.{}.{}.{}:{} (type={})",
            ep.address[0], ep.address[1], ep.address[2], ep.address[3],
            ep.port, static_cast<int>(ep.type));
    }

    // 更新状态机
    state_machine_.set_peer_p2p_state(msg.peer_node, P2PConnectionState::PUNCHING);

    // 启动分批打洞
    asio::co_spawn(ioc_, do_punch_batches(msg.peer_node), asio::detached);
}

asio::awaitable<bool> P2PManager::send_data(NodeId peer_id, std::span<const uint8_t> data) {
    // 检查是否已连接
    if (state_machine_.get_peer_p2p_state(peer_id) != P2PConnectionState::CONNECTED) {
        co_return false;
    }

    asio::ip::udp::endpoint endpoint;
    {
        std::shared_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(peer_id);
        if (it == peer_contexts_.end()) {
            co_return false;
        }
        endpoint = it->second.active_endpoint;
    }

    // 确保有 session key
    if (!peers_.ensure_session_key(peer_id)) {
        co_return false;
    }

    // 加密数据
    std::array<uint8_t, crypto::CHACHA20_NONCE_SIZE> nonce;
    auto encrypt_result = crypto_.encrypt(peer_id, data, nonce);
    if (!encrypt_result) {
        co_return false;
    }

    // 构建加密数据 = nonce + ciphertext
    std::vector<uint8_t> encrypted;
    encrypted.reserve(nonce.size() + encrypt_result->size());
    encrypted.insert(encrypted.end(), nonce.begin(), nonce.end());
    encrypted.insert(encrypted.end(), encrypt_result->begin(), encrypt_result->end());

    // 构建 P2P 数据帧
    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + encrypted.size());

    // Magic
    uint32_t magic = protocol::P2P_MAGIC;
    frame.push_back(static_cast<uint8_t>(magic >> 24));
    frame.push_back(static_cast<uint8_t>((magic >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(magic & 0xFF));

    // Src node
    NodeId src = crypto_.node_id();
    frame.push_back(static_cast<uint8_t>(src >> 24));
    frame.push_back(static_cast<uint8_t>((src >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((src >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(src & 0xFF));

    // Dst node
    frame.push_back(static_cast<uint8_t>(peer_id >> 24));
    frame.push_back(static_cast<uint8_t>((peer_id >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((peer_id >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(peer_id & 0xFF));

    // Type
    frame.push_back(P2P_TYPE_DATA);

    // Encrypted payload
    frame.insert(frame.end(), encrypted.begin(), encrypted.end());

    try {
        co_await endpoints_.socket().async_send_to(
            asio::buffer(frame), endpoint, asio::use_awaitable);

        // 更新发送时间
        {
            std::unique_lock lock(contexts_mutex_);
            auto it = peer_contexts_.find(peer_id);
            if (it != peer_contexts_.end()) {
                it->second.last_send_time = now_us();
            }
        }

        co_return true;
    } catch (const std::exception& e) {
        log().error("发送 P2P 数据到 peer {} 失败: {}", peer_id, e.what());
        co_return false;
    }
}

bool P2PManager::is_p2p_connected(NodeId peer_id) const {
    return state_machine_.get_peer_p2p_state(peer_id) == P2PConnectionState::CONNECTED;
}

std::vector<Endpoint> P2PManager::our_endpoints() const {
    return endpoints_.get_all_endpoints();
}

asio::awaitable<void> P2PManager::recv_loop() {
    std::array<uint8_t, 65536> buffer;
    asio::ip::udp::endpoint sender;

    log().debug("recv_loop 已启动");

    while (running_ && endpoints_.is_socket_open()) {
        try {
            auto bytes = co_await endpoints_.socket().async_receive_from(
                asio::buffer(buffer), sender, asio::use_awaitable);

            if (bytes > 0) {
                // 过滤虚拟 IP 段 (100.64.0.0/10)
                if (sender.address().is_v4()) {
                    auto addr = sender.address().to_v4().to_bytes();
                    if (addr[0] == 100 && addr[1] >= 64 && addr[1] <= 127) {
                        continue;
                    }
                }
                handle_udp_packet(sender, std::span(buffer.data(), bytes));
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                log().debug("recv_loop: 操作已取消");
                break;
            }
            log().error("UDP 接收错误: {}", e.what());
        } catch (const std::exception& e) {
            log().error("recv_loop 异常: {}", e.what());
        }
    }

    log().debug("recv_loop 已结束");
}

asio::awaitable<void> P2PManager::keepalive_loop() {
    while (running_) {
        keepalive_timer_.expires_after(config_.keepalive_interval);

        try {
            co_await keepalive_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        // 收集已连接的对端
        std::vector<NodeId> connected_peers;
        {
            std::shared_lock lock(contexts_mutex_);
            for (const auto& [id, ctx] : peer_contexts_) {
                if (state_machine_.get_peer_p2p_state(id) == P2PConnectionState::CONNECTED) {
                    connected_peers.push_back(id);
                }
            }
        }

        // 发送 keepalive
        for (auto peer_id : connected_peers) {
            co_await send_p2p_keepalive(peer_id);
        }

        // 检查超时
        uint64_t now = now_us();
        auto timeout_us = std::chrono::duration_cast<std::chrono::microseconds>(
            config_.keepalive_timeout).count();

        std::vector<NodeId> timed_out;
        {
            std::shared_lock lock(contexts_mutex_);
            for (const auto& [id, ctx] : peer_contexts_) {
                if (state_machine_.get_peer_p2p_state(id) == P2PConnectionState::CONNECTED) {
                    if (now - ctx.last_recv_time > static_cast<uint64_t>(timeout_us)) {
                        timed_out.push_back(id);
                    }
                }
            }
        }

        for (auto peer_id : timed_out) {
            std::unique_lock lock(contexts_mutex_);
            auto it = peer_contexts_.find(peer_id);
            if (it == peer_contexts_.end()) continue;

            uint64_t current_time = now_us();
            if (state_machine_.get_peer_p2p_state(peer_id) == P2PConnectionState::CONNECTED &&
                current_time - it->second.last_recv_time > static_cast<uint64_t>(timeout_us)) {
                lock.unlock();

                log().warn("P2P 连接到 peer {} 超时", peer_id);

                // 更新状态机
                state_machine_.set_peer_p2p_state(peer_id, P2PConnectionState::FAILED);
                state_machine_.set_peer_data_path(peer_id, PeerDataPath::RELAY);

                report_p2p_status(peer_id, false);
            }
        }
    }
}

asio::awaitable<void> P2PManager::punch_timeout_loop() {
    // 使用 500ms 检查间隔，平衡精度和 CPU 开销
    constexpr auto CHECK_INTERVAL = std::chrono::milliseconds(500);

    while (running_) {
        punch_timer_.expires_after(CHECK_INTERVAL);

        try {
            co_await punch_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        uint64_t now = now_us();
        auto punch_timeout_us = std::chrono::duration_cast<std::chrono::microseconds>(
            config_.punch_timeout).count();
        auto resolve_timeout_us = std::chrono::duration_cast<std::chrono::microseconds>(
            config_.endpoint_resolve_timeout).count();

        std::vector<NodeId> timed_out;
        {
            std::shared_lock lock(contexts_mutex_);
            for (const auto& [id, ctx] : peer_contexts_) {
                if (ctx.last_punch_time > 0) {
                    auto state = state_machine_.get_peer_p2p_state(id);
                    if (state == P2PConnectionState::PUNCHING) {
                        if (now - ctx.last_punch_time > static_cast<uint64_t>(punch_timeout_us)) {
                            timed_out.push_back(id);
                        }
                    } else if (state == P2PConnectionState::WAITING_ENDPOINT ||
                               state == P2PConnectionState::INITIATING) {
                        if (now - ctx.last_punch_time > resolve_timeout_us) {
                            timed_out.push_back(id);
                        }
                    }
                }
            }
        }

        for (auto peer_id : timed_out) {
            std::unique_lock lock(contexts_mutex_);
            auto it = peer_contexts_.find(peer_id);
            if (it == peer_contexts_.end()) continue;

            auto state = state_machine_.get_peer_p2p_state(peer_id);
            if (state != P2PConnectionState::PUNCHING &&
                state != P2PConnectionState::WAITING_ENDPOINT &&
                state != P2PConnectionState::INITIATING) {
                continue;
            }

            uint64_t current_time = now_us();
            uint64_t timeout_us = (state == P2PConnectionState::PUNCHING)
                ? static_cast<uint64_t>(punch_timeout_us)
                : resolve_timeout_us;

            if (current_time - it->second.last_punch_time <= timeout_us) {
                continue;
            }

            lock.unlock();

            log().warn("P2P {} 到 peer {} 超时",
                       state == P2PConnectionState::PUNCHING ? "打洞" : "解析",
                       peer_id);

            // 更新状态机
            state_machine_.set_peer_p2p_state(peer_id, P2PConnectionState::FAILED);
            state_machine_.set_peer_data_path(peer_id, PeerDataPath::RELAY);

            report_p2p_status(peer_id, false);
        }
    }
}

asio::awaitable<void> P2PManager::do_punch_batches(NodeId peer_id) {
    log().debug("开始分批打洞到 peer {} ({} 批, {} 包/批, {}ms 间隔)",
                peer_id, config_.punch_batch_count, config_.punch_batch_size,
                config_.punch_batch_interval.count());

    // 检查状态是否仍然是 PUNCHING
    if (state_machine_.get_peer_p2p_state(peer_id) != P2PConnectionState::PUNCHING) {
        co_return;
    }

    std::vector<Endpoint> endpoints;
    {
        std::unique_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(peer_id);
        if (it == peer_contexts_.end()) {
            co_return;
        }
        endpoints = it->second.peer_endpoints;
        it->second.last_punch_time = now_us();
    }

    if (endpoints.empty()) {
        log().warn("peer {} 没有可打洞的端点", peer_id);
        co_return;
    }

    // 转换为 UDP 端点
    std::vector<asio::ip::udp::endpoint> udp_endpoints;
    for (const auto& ep : endpoints) {
        auto udp_ep = to_udp_endpoint(ep);
        if (udp_ep) {
            udp_endpoints.push_back(*udp_ep);
        }
    }

    if (udp_endpoints.empty()) {
        log().warn("peer {} 没有有效的 UDP 端点", peer_id);
        co_return;
    }

    asio::steady_timer batch_timer(ioc_);

    for (uint32_t batch = 0; batch < config_.punch_batch_count && running_; ++batch) {
        // 检查状态
        if (state_machine_.get_peer_p2p_state(peer_id) != P2PConnectionState::PUNCHING) {
            log().debug("peer {} 打洞状态已改变，停止批次", peer_id);
            co_return;
        }

        // 发送一批打洞包
        for (uint32_t pkt = 0; pkt < config_.punch_batch_size; ++pkt) {
            for (const auto& ep : udp_endpoints) {
                co_await send_p2p_ping(peer_id, ep);
            }
        }

        // 更新打洞计数
        {
            std::unique_lock lock(contexts_mutex_);
            auto it = peer_contexts_.find(peer_id);
            if (it != peer_contexts_.end()) {
                it->second.punch_count += config_.punch_batch_size * udp_endpoints.size();
            }
        }

        log().debug("发送打洞批次 {}/{} 到 peer {} ({} 端点)",
                    batch + 1, config_.punch_batch_count, peer_id, udp_endpoints.size());

        // 批次间隔
        if (batch + 1 < config_.punch_batch_count) {
            batch_timer.expires_after(config_.punch_batch_interval);
            try {
                co_await batch_timer.async_wait(asio::use_awaitable);
            } catch (const boost::system::system_error&) {
                break;
            }
        }
    }

    log().debug("完成分批打洞到 peer {}", peer_id);
}

asio::awaitable<void> P2PManager::retry_loop() {
    // 指数退避参数
    constexpr uint32_t MAX_RETRY_COUNT = 10;        // 最大重试次数后使用最大间隔
    constexpr uint64_t CHECK_INTERVAL_SEC = 5;      // 检查间隔（秒）

    while (running_) {
        // 使用较短的检查间隔，让指数退避更精确
        retry_timer_.expires_after(std::chrono::seconds(CHECK_INTERVAL_SEC));

        try {
            co_await retry_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        uint64_t now = now_us();

        // 收集可以重试的对端
        std::vector<NodeId> retry_peers;
        {
            std::unique_lock lock(contexts_mutex_);
            for (auto& [id, ctx] : peer_contexts_) {
                if (state_machine_.get_peer_p2p_state(id) == P2PConnectionState::FAILED) {
                    // 检查是否到达重试时间
                    if (now >= ctx.next_retry_time) {
                        retry_peers.push_back(id);

                        // 计算下次重试时间（指数退避）
                        uint32_t backoff_multiplier = std::min(ctx.retry_count, MAX_RETRY_COUNT);
                        uint64_t backoff_sec = static_cast<uint64_t>(config_.retry_interval.count())
                                               << backoff_multiplier;  // 2^n * base_interval
                        // 限制最大退避时间为 1 小时
                        backoff_sec = std::min(backoff_sec, uint64_t{3600});
                        ctx.next_retry_time = now + backoff_sec * 1000000;
                        ctx.retry_count++;

                        log().debug("peer {} 重试计数 {}，下次重试间隔 {} 秒",
                            id, ctx.retry_count, backoff_sec);
                    }
                }
            }
        }

        for (auto peer_id : retry_peers) {
            log().debug("重试 P2P 连接到 peer {}", peer_id);
            asio::co_spawn(ioc_, connect_peer(peer_id), asio::detached);
        }
    }
}

asio::awaitable<void> P2PManager::endpoint_refresh_loop() {
    // 等待初始刷新间隔
    endpoint_refresh_timer_.expires_after(config_.endpoint_refresh_interval);

    try {
        co_await endpoint_refresh_timer_.async_wait(asio::use_awaitable);
    } catch (const boost::system::system_error&) {
        co_return;
    }

    while (running_) {
        co_await refresh_endpoints();

        endpoint_refresh_timer_.expires_after(config_.endpoint_refresh_interval);

        try {
            co_await endpoint_refresh_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }
    }
}

asio::awaitable<void> P2PManager::refresh_endpoints() {
    if (!running_) {
        co_return;
    }

    log().debug("刷新端点（定期广播）");

    auto stun_result = co_await endpoints_.query_stun_endpoint();
    if (stun_result.success) {
        auto& addr = stun_result.mapped_endpoint.address;
        log().debug("STUN 刷新: {}.{}.{}.{}:{}",
            addr[0], addr[1], addr[2], addr[3],
            stun_result.mapped_endpoint.port);
    }

    auto eps = endpoints_.get_all_endpoints();
    if (!eps.empty()) {
        log().debug("广播 {} 个端点给 Controller", eps.size());
        notify_endpoints_ready(eps);
    }
}

void P2PManager::handle_udp_packet(const asio::ip::udp::endpoint& from,
                                    std::span<const uint8_t> data) {
    if (data.size() < P2P_FRAME_HEADER_SIZE) {
        return;
    }

    // 验证 Magic
    uint32_t magic = (static_cast<uint32_t>(data[0]) << 24) |
                     (static_cast<uint32_t>(data[1]) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8) |
                     static_cast<uint32_t>(data[3]);

    if (magic != protocol::P2P_MAGIC) {
        return;
    }

    // 解析源和目标节点
    NodeId src_node = (static_cast<NodeId>(data[4]) << 24) |
                      (static_cast<NodeId>(data[5]) << 16) |
                      (static_cast<NodeId>(data[6]) << 8) |
                      static_cast<NodeId>(data[7]);

    NodeId dst_node = (static_cast<NodeId>(data[8]) << 24) |
                      (static_cast<NodeId>(data[9]) << 16) |
                      (static_cast<NodeId>(data[10]) << 8) |
                      static_cast<NodeId>(data[11]);

    // 验证目标是我们
    if (dst_node != crypto_.node_id()) {
        return;
    }

    uint8_t pkt_type = data[12];
    auto payload = data.subspan(P2P_FRAME_HEADER_SIZE);

    switch (pkt_type) {
        case P2P_TYPE_PING: {
            auto result = P2PPing::parse(payload);
            if (result) {
                handle_p2p_ping(from, *result);
            }
            break;
        }
        case P2P_TYPE_PONG: {
            auto result = P2PPing::parse(payload);
            if (result) {
                handle_p2p_pong(from, *result);
            }
            break;
        }
        case P2P_TYPE_KEEPALIVE: {
            auto result = P2PKeepalive::parse(payload);
            if (result) {
                handle_p2p_keepalive(from, src_node, *result);
            }
            break;
        }
        case P2P_TYPE_DATA: {
            handle_p2p_data(from, src_node, payload);
            break;
        }
        default:
            log().debug("未知 P2P 包类型: 0x{:02x}", pkt_type);
            break;
    }
}

void P2PManager::handle_p2p_ping(const asio::ip::udp::endpoint& from,
                                  const P2PPing& ping) {
    log().debug("收到 P2P_PING 来自 {} (node {})",
        from.address().to_string(), ping.src_node);

    // 验证是否有该节点信息
    auto peer = peers_.get_peer(ping.src_node);
    if (!peer) {
        log().warn("收到未知 peer {} 的 P2P_PING，忽略", ping.src_node);
        return;
    }

    // 发送 PONG
    send_p2p_pong(ping, from);

    // 更新上下文
    {
        std::unique_lock lock(contexts_mutex_);
        auto& ctx = peer_contexts_[ping.src_node];

        // 填充 peer_key
        if (ctx.peer_key == std::array<uint8_t, X25519_KEY_SIZE>{}) {
            ctx.peer_key = peer->info.node_key;
            log().debug("从 PeerManager 填充 peer {} 的 peer_key", ping.src_node);
        }

        ctx.active_endpoint = from;
        ctx.last_recv_time = now_us();
    }

    // 确保会话密钥已派生（在锁外执行避免死锁）
    peers_.ensure_session_key(ping.src_node);

    // 原子更新状态机，返回值表示是否是新建立的连接
    bool newly_connected = state_machine_.set_peer_connection_state(
        ping.src_node, P2PConnectionState::CONNECTED, PeerDataPath::P2P);

    if (newly_connected) {
        log().info("P2P 连接已建立与 peer {} 通过 {}",
            ping.src_node, from.address().to_string());

        // 重置重试计数器
        {
            std::unique_lock lock(contexts_mutex_);
            if (auto it = peer_contexts_.find(ping.src_node); it != peer_contexts_.end()) {
                it->second.retry_count = 0;
                it->second.next_retry_time = 0;
            }
        }

        report_p2p_status(ping.src_node, true);
    }
}

void P2PManager::handle_p2p_pong(const asio::ip::udp::endpoint& from,
                                  const P2PPing& pong) {
    log().debug("收到 P2P_PONG 来自 {} (node {})",
        from.address().to_string(), pong.src_node);

    // 计算 RTT
    uint64_t now = now_us();
    uint16_t latency_ms = 0;
    if (now > pong.timestamp) {
        latency_ms = static_cast<uint16_t>((now - pong.timestamp) / 1000);
    }

    // 更新上下文
    {
        std::unique_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(pong.src_node);
        if (it == peer_contexts_.end()) {
            return;
        }

        it->second.active_endpoint = from;
        it->second.last_recv_time = now;
    }

    // 原子更新状态机，返回值表示是否是新建立的连接
    bool newly_connected = state_machine_.set_peer_connection_state(
        pong.src_node, P2PConnectionState::CONNECTED, PeerDataPath::P2P);
    state_machine_.update_peer_latency(pong.src_node, latency_ms);

    if (newly_connected) {
        log().info("P2P 连接已建立与 peer {} 通过 {} (延迟: {}ms)",
            pong.src_node, from.address().to_string(), latency_ms);

        // 重置重试计数器
        {
            std::unique_lock lock(contexts_mutex_);
            if (auto it = peer_contexts_.find(pong.src_node); it != peer_contexts_.end()) {
                it->second.retry_count = 0;
                it->second.next_retry_time = 0;
            }
        }

        report_p2p_status(pong.src_node, true);
    }
}

void P2PManager::handle_p2p_keepalive(const asio::ip::udp::endpoint& from,
                                       NodeId peer_id,
                                       const P2PKeepalive& keepalive) {
    if (state_machine_.get_peer_p2p_state(peer_id) != P2PConnectionState::CONNECTED) {
        return;
    }

    std::unique_lock lock(contexts_mutex_);
    auto it = peer_contexts_.find(peer_id);
    if (it != peer_contexts_.end()) {
        it->second.last_recv_time = now_us();
    }
}

void P2PManager::handle_p2p_data(const asio::ip::udp::endpoint& from,
                                  NodeId peer_id,
                                  std::span<const uint8_t> encrypted_data) {
    // 确保有 session key
    if (!peers_.ensure_session_key(peer_id)) {
        log().warn("peer {} 没有 session key", peer_id);
        return;
    }

    // 验证数据长度
    if (encrypted_data.size() < crypto::CHACHA20_NONCE_SIZE) {
        log().warn("peer {} 的 P2P 数据太短", peer_id);
        return;
    }

    // 提取 nonce 和 ciphertext
    std::array<uint8_t, crypto::CHACHA20_NONCE_SIZE> nonce;
    std::copy(encrypted_data.begin(),
              encrypted_data.begin() + crypto::CHACHA20_NONCE_SIZE,
              nonce.begin());
    auto ciphertext = encrypted_data.subspan(crypto::CHACHA20_NONCE_SIZE);

    // 解密
    auto decrypt_result = crypto_.decrypt(peer_id, nonce, ciphertext);
    if (!decrypt_result) {
        log().warn("解密 peer {} 的 P2P 数据失败", peer_id);
        return;
    }

    // 更新接收时间
    {
        std::unique_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(peer_id);
        if (it != peer_contexts_.end()) {
            it->second.last_recv_time = now_us();
        }
    }

    // 通过 channel 发送数据
    if (channels_.data_channel) {
        channels_.data_channel->try_send(
            boost::system::error_code{}, peer_id,
            std::vector<uint8_t>(decrypt_result->begin(), decrypt_result->end()));
    }
}

asio::awaitable<void> P2PManager::send_p2p_ping(NodeId peer_id,
                                                 const asio::ip::udp::endpoint& to) {
    P2PPing ping;
    ping.magic = protocol::P2P_MAGIC;
    ping.src_node = crypto_.node_id();
    ping.dst_node = peer_id;
    ping.timestamp = now_us();

    {
        std::unique_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(peer_id);
        if (it != peer_contexts_.end()) {
            ping.seq_num = ++it->second.ping_seq;
        }
    }

    auto payload = ping.serialize();

    // 构建完整帧
    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + payload.size());

    uint32_t magic = protocol::P2P_MAGIC;
    frame.push_back(static_cast<uint8_t>(magic >> 24));
    frame.push_back(static_cast<uint8_t>((magic >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(magic & 0xFF));

    NodeId src = crypto_.node_id();
    frame.push_back(static_cast<uint8_t>(src >> 24));
    frame.push_back(static_cast<uint8_t>((src >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((src >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(src & 0xFF));

    frame.push_back(static_cast<uint8_t>(peer_id >> 24));
    frame.push_back(static_cast<uint8_t>((peer_id >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((peer_id >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(peer_id & 0xFF));

    frame.push_back(P2P_TYPE_PING);
    frame.insert(frame.end(), payload.begin(), payload.end());

    try {
        co_await endpoints_.socket().async_send_to(
            asio::buffer(frame), to, asio::use_awaitable);

        log().debug("发送 P2P_PING 到 {} (peer {})",
            to.address().to_string(), peer_id);
    } catch (const std::exception& e) {
        log().debug("发送 P2P_PING 失败: {}", e.what());
    }
}

void P2PManager::send_p2p_pong(const P2PPing& ping,
                               const asio::ip::udp::endpoint& to) {
    P2PPing pong;
    pong.magic = protocol::P2P_MAGIC;
    pong.src_node = crypto_.node_id();
    pong.dst_node = ping.src_node;
    pong.timestamp = ping.timestamp;
    pong.seq_num = ping.seq_num;

    auto payload = pong.serialize();

    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + payload.size());

    uint32_t magic = protocol::P2P_MAGIC;
    frame.push_back(static_cast<uint8_t>(magic >> 24));
    frame.push_back(static_cast<uint8_t>((magic >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(magic & 0xFF));

    NodeId src = crypto_.node_id();
    frame.push_back(static_cast<uint8_t>(src >> 24));
    frame.push_back(static_cast<uint8_t>((src >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((src >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(src & 0xFF));

    frame.push_back(static_cast<uint8_t>(ping.src_node >> 24));
    frame.push_back(static_cast<uint8_t>((ping.src_node >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((ping.src_node >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(ping.src_node & 0xFF));

    frame.push_back(P2P_TYPE_PONG);
    frame.insert(frame.end(), payload.begin(), payload.end());

    boost::system::error_code ec;
    endpoints_.socket().send_to(asio::buffer(frame), to, 0, ec);

    if (!ec) {
        log().debug("发送 P2P_PONG 到 {} (peer {})",
            to.address().to_string(), ping.src_node);
    }
}

asio::awaitable<void> P2PManager::send_p2p_keepalive(NodeId peer_id) {
    if (state_machine_.get_peer_p2p_state(peer_id) != P2PConnectionState::CONNECTED) {
        co_return;
    }

    asio::ip::udp::endpoint endpoint;
    {
        std::shared_lock lock(contexts_mutex_);
        auto it = peer_contexts_.find(peer_id);
        if (it == peer_contexts_.end()) {
            co_return;
        }
        endpoint = it->second.active_endpoint;
    }

    P2PKeepalive keepalive;
    keepalive.timestamp = now_us();
    keepalive.seq_num = 0;
    keepalive.flags = 0x01;

    auto payload = keepalive.serialize();

    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + payload.size());

    uint32_t magic = protocol::P2P_MAGIC;
    frame.push_back(static_cast<uint8_t>(magic >> 24));
    frame.push_back(static_cast<uint8_t>((magic >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((magic >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(magic & 0xFF));

    NodeId src = crypto_.node_id();
    frame.push_back(static_cast<uint8_t>(src >> 24));
    frame.push_back(static_cast<uint8_t>((src >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((src >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(src & 0xFF));

    frame.push_back(static_cast<uint8_t>(peer_id >> 24));
    frame.push_back(static_cast<uint8_t>((peer_id >> 16) & 0xFF));
    frame.push_back(static_cast<uint8_t>((peer_id >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(peer_id & 0xFF));

    frame.push_back(P2P_TYPE_KEEPALIVE);
    frame.insert(frame.end(), payload.begin(), payload.end());

    try {
        co_await endpoints_.socket().async_send_to(
            asio::buffer(frame), endpoint, asio::use_awaitable);
    } catch (const std::exception& e) {
        log().debug("发送 keepalive 失败: {}", e.what());
    }
}

void P2PManager::report_p2p_status(NodeId peer_id, bool success) {
    P2PStatusMsg status;
    status.peer_node = peer_id;

    if (success) {
        status.status = P2PStatus::P2P;
        status.path_type = PathType::STUN;
        status.latency_ms = state_machine_.get_peer_rtt(peer_id);
    } else {
        status.status = P2PStatus::RELAY_ONLY;
        status.path_type = PathType::RELAY;
        status.latency_ms = 0;
    }

    if (channels_.status_channel) {
        channels_.status_channel->try_send(boost::system::error_code{}, status);
    }
}

void P2PManager::notify_endpoints_ready(const std::vector<Endpoint>& endpoints) {
    if (channels_.endpoints_channel) {
        channels_.endpoints_channel->try_send(boost::system::error_code{}, endpoints);
    }
}

void P2PManager::request_p2p_init(const P2PInit& init) {
    if (channels_.init_channel) {
        channels_.init_channel->try_send(boost::system::error_code{}, init);
    }
}

std::optional<asio::ip::udp::endpoint> P2PManager::to_udp_endpoint(const Endpoint& ep) {
    if (ep.ip_type != IpType::IPv4) {
        return std::nullopt;
    }

    asio::ip::address_v4::bytes_type bytes;
    std::copy(ep.address.begin(), ep.address.begin() + 4, bytes.begin());
    asio::ip::address_v4 addr(bytes);

    return asio::ip::udp::endpoint(addr, ep.port);
}

uint64_t P2PManager::now_us() {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()).count();
}

} // namespace edgelink::client

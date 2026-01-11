#include "client/p2p_manager.hpp"
#include "common/logger.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <chrono>

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("client.p2p"); }

// P2P 数据帧头 (在 UDP 数据包中)
// 格式: [4 bytes magic][4 bytes src_node][4 bytes dst_node][1 byte type][payload]
constexpr size_t P2P_FRAME_HEADER_SIZE = 13;
constexpr uint8_t P2P_TYPE_PING = 0x01;
constexpr uint8_t P2P_TYPE_PONG = 0x02;
constexpr uint8_t P2P_TYPE_KEEPALIVE = 0x03;
constexpr uint8_t P2P_TYPE_DATA = 0x04;

} // anonymous namespace

const char* p2p_state_name(P2PState state) {
    switch (state) {
        case P2PState::IDLE: return "IDLE";
        case P2PState::RESOLVING: return "RESOLVING";
        case P2PState::PUNCHING: return "PUNCHING";
        case P2PState::CONNECTED: return "CONNECTED";
        case P2PState::RELAY_ONLY: return "RELAY_ONLY";
        default: return "UNKNOWN";
    }
}

P2PManager::P2PManager(asio::io_context& ioc, CryptoEngine& crypto,
                       PeerManager& peers, EndpointManager& endpoints)
    : ioc_(ioc)
    , crypto_(crypto)
    , peers_(peers)
    , endpoints_(endpoints)
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

void P2PManager::set_callbacks(P2PCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

asio::awaitable<bool> P2PManager::start() {
    if (!config_.enabled) {
        log().info("P2P is disabled");
        co_return false;
    }

    if (running_) {
        co_return true;
    }

    // 初始化 UDP socket
    endpoints_.set_local_port(config_.bind_port);
    if (!co_await endpoints_.init_socket()) {
        log().error("Failed to initialize UDP socket");
        co_return false;
    }

    // 查询 STUN 端点
    auto stun_result = co_await endpoints_.query_stun_endpoint();
    if (stun_result.success) {
        auto& addr = stun_result.mapped_endpoint.address;
        log().info("STUN endpoint: {}.{}.{}.{}:{}",
            addr[0], addr[1], addr[2], addr[3],
            stun_result.mapped_endpoint.port);
    }

    running_ = true;

    // 启动后台任务
    asio::co_spawn(ioc_, recv_loop(), asio::detached);
    asio::co_spawn(ioc_, keepalive_loop(), asio::detached);
    asio::co_spawn(ioc_, punch_loop(), asio::detached);
    asio::co_spawn(ioc_, retry_loop(), asio::detached);
    asio::co_spawn(ioc_, endpoint_refresh_loop(), asio::detached);

    log().info("P2P manager started on port {}", endpoints_.local_port());

    // 通知端点已就绪，需要上报给 Controller
    if (callbacks_.on_endpoints_ready) {
        auto eps = endpoints_.get_all_endpoints();
        log().debug("Reporting {} endpoints to controller", eps.size());
        callbacks_.on_endpoints_ready(eps);
    }

    co_return true;
}

asio::awaitable<void> P2PManager::stop() {
    if (!running_) {
        co_return;
    }

    running_ = false;

    // 取消定时器
    keepalive_timer_.cancel();
    punch_timer_.cancel();
    retry_timer_.cancel();
    endpoint_refresh_timer_.cancel();

    // 关闭 socket
    endpoints_.close_socket();

    // 清除状态
    {
        std::unique_lock lock(states_mutex_);
        peer_states_.clear();
    }

    log().info("P2P manager stopped");
}

// 异步版本：等待端点上报确认后再发送 P2P_INIT，确保消息顺序
asio::awaitable<void> P2PManager::connect_peer_async(NodeId peer_id) {
    uint32_t init_seq;

    {
        std::unique_lock lock(states_mutex_);

        auto it = peer_states_.find(peer_id);
        if (it != peer_states_.end()) {
            auto& state = it->second;
            if (state.state == P2PState::CONNECTED ||
                state.state == P2PState::PUNCHING ||
                state.state == P2PState::RESOLVING) {
                // 已经在连接中
                co_return;
            }
        }

        // 创建或更新状态
        auto& state = peer_states_[peer_id];
        state.state = P2PState::RESOLVING;
        state.init_seq = ++init_seq_;
        state.punch_count = 0;
        state.last_punch_time = now_us();  // 记录 RESOLVING 开始时间
        init_seq = state.init_seq;
    }

    // 【关键修复】发起 P2P_INIT 前，先上传我们的端点给 Controller 并等待确认
    // 这样确保 Controller 在处理 P2P_INIT 时已经有我们的端点
    if (callbacks_.on_endpoints_ready_async) {
        auto eps = endpoints_.get_all_endpoints();
        if (!eps.empty()) {
            log().debug("Uploading {} endpoints before P2P_INIT (waiting for ACK)", eps.size());
            bool ack_received = co_await callbacks_.on_endpoints_ready_async(eps);
            if (!ack_received) {
                log().warn("Endpoint upload not confirmed, proceeding with P2P_INIT anyway");
            }
        }
    } else if (callbacks_.on_endpoints_ready) {
        // 回退到同步版本
        auto eps = endpoints_.get_all_endpoints();
        if (!eps.empty()) {
            log().debug("Uploading {} endpoints before P2P_INIT", eps.size());
            callbacks_.on_endpoints_ready(eps);
        }
    }

    // 发送 P2P_INIT 请求
    P2PInit init;
    init.target_node = peer_id;
    init.init_seq = init_seq;

    log().debug("Sending P2P_INIT to peer {}, seq={}", peer_id, init.init_seq);

    if (callbacks_.on_send_p2p_init_async) {
        co_await callbacks_.on_send_p2p_init_async(init);
    } else if (callbacks_.on_send_p2p_init) {
        callbacks_.on_send_p2p_init(init);
    }
}

// 同步版本：立即返回，内部启动异步连接
void P2PManager::connect_peer(NodeId peer_id) {
    // 快速检查是否已在连接中
    {
        std::shared_lock lock(states_mutex_);
        auto it = peer_states_.find(peer_id);
        if (it != peer_states_.end()) {
            auto& state = it->second;
            if (state.state == P2PState::CONNECTED ||
                state.state == P2PState::PUNCHING ||
                state.state == P2PState::RESOLVING) {
                return;
            }
        }
    }

    // 启动异步连接
    asio::co_spawn(ioc_, connect_peer_async(peer_id), asio::detached);
}

void P2PManager::disconnect_peer(NodeId peer_id) {
    std::unique_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        auto old_state = it->second.state;
        peer_states_.erase(it);
        lock.unlock();

        if (old_state != P2PState::IDLE) {
            if (callbacks_.on_state_change) {
                callbacks_.on_state_change(peer_id, P2PState::IDLE);
            }
        }
    }
}

void P2PManager::handle_p2p_endpoint(const P2PEndpointMsg& msg) {
    // 【关键修复】检查 P2P Manager 是否已启动
    // 场景：节点刚上线，P2P Manager 还在启动中，此时收到被动打洞请求
    // 如果不检查，do_punch_batches 会尝试使用未初始化的 socket
    if (!running_) {
        log().debug("P2P manager not running, ignoring P2P_ENDPOINT for peer {}", msg.peer_node);
        return;
    }

    std::unique_lock lock(states_mutex_);

    auto it = peer_states_.find(msg.peer_node);

    // seq=0 表示被动打洞请求（对端向我们发起了 P2P_INIT）
    bool passive_punch = (msg.init_seq == 0);

    if (it == peer_states_.end()) {
        if (passive_punch && !msg.endpoints.empty()) {
            // 被动打洞：创建新的状态并开始打洞
            log().debug("Passive P2P punch request from peer {}", msg.peer_node);
        } else {
            log().warn("Received P2P_ENDPOINT for unknown peer {}", msg.peer_node);
            return;
        }
    } else if (!passive_punch) {
        // 主动打洞：验证序列号
        auto& state = it->second;
        if (state.init_seq != msg.init_seq) {
            log().debug("P2P_ENDPOINT seq mismatch: expected {}, got {}",
                state.init_seq, msg.init_seq);
            return;
        }
    }

    // 获取或创建状态
    auto& state = peer_states_[msg.peer_node];

    // 如果已经是 CONNECTED 或正在 PUNCHING，不要重复处理
    if (state.state == P2PState::CONNECTED) {
        log().debug("Already connected to peer {}, ignoring P2P_ENDPOINT", msg.peer_node);
        return;
    }

    // 保存对端信息
    state.peer_key = msg.peer_key;
    state.peer_endpoints = msg.endpoints;
    state.state = P2PState::PUNCHING;
    state.punch_count = 0;
    // 【关键修复】在设置 PUNCHING 状态时就设置时间戳
    // 这样即使 do_punch_batches 协程启动延迟，也能正确检测超时
    state.last_punch_time = now_us();

    log().debug("Received P2P_ENDPOINT for peer {}: {} endpoints{}",
        msg.peer_node, msg.endpoints.size(),
        passive_punch ? " (passive punch)" : "");

    for (const auto& ep : msg.endpoints) {
        log().debug("  - {}.{}.{}.{}:{} (type={})",
            ep.address[0], ep.address[1], ep.address[2], ep.address[3],
            ep.port, static_cast<int>(ep.type));
    }

    lock.unlock();

    if (callbacks_.on_state_change) {
        callbacks_.on_state_change(msg.peer_node, P2PState::PUNCHING);
    }

    // 立即启动分批打洞 (EasyTier 风格)
    asio::co_spawn(ioc_, do_punch_batches(msg.peer_node), asio::detached);
}

std::optional<PeerP2PState> P2PManager::get_peer_state(NodeId peer_id) const {
    std::shared_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::pair<NodeId, PeerP2PState>> P2PManager::get_all_peer_states() const {
    std::vector<std::pair<NodeId, PeerP2PState>> result;
    std::shared_lock lock(states_mutex_);
    result.reserve(peer_states_.size());
    for (const auto& [id, state] : peer_states_) {
        result.emplace_back(id, state);
    }
    return result;
}

asio::awaitable<bool> P2PManager::send_data(NodeId peer_id, std::span<const uint8_t> data) {
    std::shared_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it == peer_states_.end() || it->second.state != P2PState::CONNECTED) {
        co_return false;
    }

    auto& state = it->second;
    auto endpoint = state.active_endpoint;
    lock.unlock();

    // 确保有 session key
    if (!peers_.ensure_session_key(peer_id)) {
        co_return false;
    }

    // 加密数据 (prepend nonce to ciphertext)
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    auto encrypt_result = crypto_.encrypt(peer_id, data, nonce);
    if (!encrypt_result) {
        co_return false;
    }

    // 构建 encrypted = nonce + ciphertext
    std::vector<uint8_t> encrypted;
    encrypted.reserve(nonce.size() + encrypt_result->size());
    encrypted.insert(encrypted.end(), nonce.begin(), nonce.end());
    encrypted.insert(encrypted.end(), encrypt_result->begin(), encrypt_result->end());

    // 构建 P2P 数据帧
    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + encrypted.size());

    // Magic
    uint32_t magic = P2P_MAGIC;
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
        std::unique_lock lock2(states_mutex_);
        auto it2 = peer_states_.find(peer_id);
        if (it2 != peer_states_.end()) {
            it2->second.last_send_time = now_us();
        }

        co_return true;
    } catch (const std::exception& e) {
        log().error("Failed to send P2P data to peer {}: {}", peer_id, e.what());
        co_return false;
    }
}

bool P2PManager::is_p2p_connected(NodeId peer_id) const {
    std::shared_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    return it != peer_states_.end() && it->second.state == P2PState::CONNECTED;
}

std::vector<Endpoint> P2PManager::our_endpoints() const {
    return endpoints_.get_all_endpoints();
}

asio::awaitable<void> P2PManager::recv_loop() {
    std::array<uint8_t, 65536> buffer;
    asio::ip::udp::endpoint sender;

    log().debug("recv_loop started");

    while (running_ && endpoints_.is_socket_open()) {
        try {
            auto bytes = co_await endpoints_.socket().async_receive_from(
                asio::buffer(buffer), sender, asio::use_awaitable);

            if (bytes > 0) {
                // 过滤掉虚拟 IP 段 (100.64.0.0/10) 的包，避免 TUN 回环
                if (sender.address().is_v4()) {
                    auto addr = sender.address().to_v4().to_bytes();
                    if (addr[0] == 100 && addr[1] >= 64 && addr[1] <= 127) {
                        // 忽略来自虚拟 IP 的包
                        continue;
                    }
                }
                handle_udp_packet(sender, std::span(buffer.data(), bytes));
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                log().debug("recv_loop: operation aborted");
                break;
            }
            log().error("UDP recv error: {}", e.what());
        } catch (const std::exception& e) {
            log().error("recv_loop exception: {}", e.what());
        }
    }

    log().debug("recv_loop ended");
}

asio::awaitable<void> P2PManager::keepalive_loop() {
    while (running_) {
        keepalive_timer_.expires_after(
            std::chrono::seconds(config_.keepalive_interval_sec));

        try {
            co_await keepalive_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        // 发送 keepalive 给所有已连接的对端
        std::vector<NodeId> connected_peers;
        {
            std::shared_lock lock(states_mutex_);
            for (const auto& [id, state] : peer_states_) {
                if (state.state == P2PState::CONNECTED) {
                    connected_peers.push_back(id);
                }
            }
        }

        for (auto peer_id : connected_peers) {
            co_await send_p2p_keepalive(peer_id);
        }

        // 检查超时
        uint64_t now = now_us();
        uint64_t timeout_us = config_.keepalive_timeout_sec * 1000000ULL;

        std::vector<NodeId> timed_out;
        {
            std::shared_lock lock(states_mutex_);
            for (const auto& [id, state] : peer_states_) {
                if (state.state == P2PState::CONNECTED) {
                    if (now - state.last_recv_time > timeout_us) {
                        timed_out.push_back(id);
                    }
                }
            }
        }

        // 【关键修复】在设置状态前再次检查时间戳，避免误判
        // 因为在释放读锁和获取写锁之间，可能收到了新的数据包
        for (auto peer_id : timed_out) {
            std::unique_lock lock(states_mutex_);
            auto it = peer_states_.find(peer_id);
            if (it == peer_states_.end()) continue;

            // 再次检查：状态是否仍为 CONNECTED，且确实超时
            uint64_t current_time = now_us();
            if (it->second.state == P2PState::CONNECTED &&
                current_time - it->second.last_recv_time > timeout_us) {
                it->second.state = P2PState::RELAY_ONLY;
                lock.unlock();

                log().warn("P2P connection to peer {} timed out", peer_id);
                if (callbacks_.on_state_change) {
                    callbacks_.on_state_change(peer_id, P2PState::RELAY_ONLY);
                }
                report_p2p_status(peer_id);
            }
            // 如果条件不满足，说明期间收到了新数据，跳过
        }
    }
}

asio::awaitable<void> P2PManager::punch_loop() {
    // 此循环只负责超时检测，打洞包发送由 do_punch_batches 协程完成
    while (running_) {
        punch_timer_.expires_after(std::chrono::seconds(1));

        try {
            co_await punch_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        uint64_t now = now_us();

        // 检查打洞超时和 RESOLVING 超时
        std::vector<NodeId> timed_out;
        {
            std::shared_lock lock(states_mutex_);
            for (const auto& [id, state] : peer_states_) {
                if (state.last_punch_time > 0) {
                    if (state.state == P2PState::PUNCHING) {
                        // 打洞超时 (punch_timeout_sec)
                        if (now - state.last_punch_time > config_.punch_timeout_sec * 1000000ULL) {
                            timed_out.push_back(id);
                        }
                    } else if (state.state == P2PState::RESOLVING) {
                        // RESOLVING 超时 (5 秒)
                        if (now - state.last_punch_time > 5 * 1000000ULL) {
                            timed_out.push_back(id);
                        }
                    }
                }
            }
        }

        for (auto peer_id : timed_out) {
            // 【关键修复】使用独占锁并再次检查状态，避免竞态条件
            // 场景：punch_loop 检测到超时后，handle_p2p_pong 收到 PONG 设置了 CONNECTED
            // 此时不应该再把状态改回 RELAY_ONLY
            std::unique_lock lock(states_mutex_);
            auto it = peer_states_.find(peer_id);
            if (it == peer_states_.end()) {
                continue;
            }

            auto& state = it->second;
            // 只有当状态仍为 PUNCHING 或 RESOLVING 时才设置为 RELAY_ONLY
            if (state.state != P2PState::PUNCHING && state.state != P2PState::RESOLVING) {
                // 状态已变化（可能已连接成功），跳过
                continue;
            }

            // 再次验证超时（避免误判）
            uint64_t current_time = now_us();
            uint64_t timeout_us = (state.state == P2PState::RESOLVING)
                ? 5 * 1000000ULL
                : config_.punch_timeout_sec * 1000000ULL;

            if (current_time - state.last_punch_time <= timeout_us) {
                // 时间戳已更新，可能期间有活动，跳过
                continue;
            }

            auto old_state = state.state;
            state.state = P2PState::RELAY_ONLY;
            lock.unlock();

            log().warn("P2P {} to peer {} timed out",
                       old_state == P2PState::RESOLVING ? "resolving" : "hole punching",
                       peer_id);

            if (callbacks_.on_state_change) {
                callbacks_.on_state_change(peer_id, P2PState::RELAY_ONLY);
            }
            report_p2p_status(peer_id);
        }
    }
}

asio::awaitable<void> P2PManager::do_punch_batches(NodeId peer_id) {
    // EasyTier 风格的分批打洞：每批 2 个包，共 5 批，间隔 400ms
    // 双向同时打洞 - 两端同时收到 P2P_ENDPOINT 后同时开始打洞

    log().debug("Starting batch hole punching to peer {} ({} batches, {} packets/batch, {}ms interval)",
                peer_id, config_.punch_batch_count, config_.punch_batch_size,
                config_.punch_batch_interval_ms);

    // 获取对端端点列表
    std::vector<Endpoint> endpoints;
    {
        std::unique_lock lock(states_mutex_);
        auto it = peer_states_.find(peer_id);
        if (it == peer_states_.end() || it->second.state != P2PState::PUNCHING) {
            co_return;
        }
        endpoints = it->second.peer_endpoints;
        it->second.last_punch_time = now_us();
    }

    if (endpoints.empty()) {
        log().warn("No endpoints to punch for peer {}", peer_id);
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
        log().warn("No valid UDP endpoints for peer {}", peer_id);
        co_return;
    }

    // 分批发送打洞包
    asio::steady_timer batch_timer(ioc_);

    for (uint32_t batch = 0; batch < config_.punch_batch_count && running_; ++batch) {
        // 检查状态是否还是 PUNCHING
        {
            std::shared_lock lock(states_mutex_);
            auto it = peer_states_.find(peer_id);
            if (it == peer_states_.end() || it->second.state != P2PState::PUNCHING) {
                // 状态已改变（可能已连接或失败），停止打洞
                log().debug("Punch state changed for peer {}, stopping batches", peer_id);
                co_return;
            }
        }

        // 发送一批打洞包：每批向所有端点发送 batch_size 个包
        for (uint32_t pkt = 0; pkt < config_.punch_batch_size; ++pkt) {
            for (const auto& ep : udp_endpoints) {
                co_await send_p2p_ping(peer_id, ep);
            }
        }

        // 更新打洞计数
        {
            std::unique_lock lock(states_mutex_);
            auto it = peer_states_.find(peer_id);
            if (it != peer_states_.end()) {
                it->second.punch_count += config_.punch_batch_size * udp_endpoints.size();
            }
        }

        log().debug("Sent punch batch {}/{} to peer {} ({} endpoints)",
                    batch + 1, config_.punch_batch_count, peer_id, udp_endpoints.size());

        // 批次间隔等待 (最后一批不需要等待)
        if (batch + 1 < config_.punch_batch_count) {
            batch_timer.expires_after(
                std::chrono::milliseconds(config_.punch_batch_interval_ms));
            try {
                co_await batch_timer.async_wait(asio::use_awaitable);
            } catch (const boost::system::system_error&) {
                break;
            }
        }
    }

    log().debug("Finished batch hole punching to peer {}", peer_id);
}

asio::awaitable<void> P2PManager::retry_loop() {
    while (running_) {
        retry_timer_.expires_after(
            std::chrono::seconds(config_.retry_interval_sec));

        try {
            co_await retry_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        // 重试所有 RELAY_ONLY 状态的对端
        std::vector<NodeId> retry_peers;
        {
            std::shared_lock lock(states_mutex_);
            for (const auto& [id, state] : peer_states_) {
                if (state.state == P2PState::RELAY_ONLY) {
                    retry_peers.push_back(id);
                }
            }
        }

        for (auto peer_id : retry_peers) {
            log().debug("Retrying P2P connection to peer {}", peer_id);
            connect_peer(peer_id);
        }
    }
}

asio::awaitable<void> P2PManager::endpoint_refresh_loop() {
    // 等待初始刷新间隔，避免启动时立即刷新 (start() 已经上报过一次)
    endpoint_refresh_timer_.expires_after(
        std::chrono::seconds(config_.endpoint_refresh_sec));

    try {
        co_await endpoint_refresh_timer_.async_wait(asio::use_awaitable);
    } catch (const boost::system::system_error&) {
        co_return;
    }

    while (running_) {
        // 刷新端点
        co_await refresh_endpoints();

        // 等待下一次刷新
        endpoint_refresh_timer_.expires_after(
            std::chrono::seconds(config_.endpoint_refresh_sec));

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

    log().debug("Refreshing endpoints (periodic broadcast)");

    // 重新查询 STUN 端点
    auto stun_result = co_await endpoints_.query_stun_endpoint();
    if (stun_result.success) {
        auto& addr = stun_result.mapped_endpoint.address;
        log().debug("STUN refresh: {}.{}.{}.{}:{}",
            addr[0], addr[1], addr[2], addr[3],
            stun_result.mapped_endpoint.port);
    }

    // 上报端点给 Controller
    if (callbacks_.on_endpoints_ready) {
        auto eps = endpoints_.get_all_endpoints();
        if (!eps.empty()) {
            log().debug("Broadcasting {} endpoints to controller", eps.size());
            callbacks_.on_endpoints_ready(eps);
        }
    }

    // 更新刷新时间
    last_endpoint_refresh_time_ = now_us();
}

void P2PManager::handle_udp_packet(const asio::ip::udp::endpoint& from,
                                    std::span<const uint8_t> data) {
    // 验证最小长度
    if (data.size() < P2P_FRAME_HEADER_SIZE) {
        return;
    }

    // 验证 Magic
    uint32_t magic = (static_cast<uint32_t>(data[0]) << 24) |
                     (static_cast<uint32_t>(data[1]) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8) |
                     static_cast<uint32_t>(data[3]);

    if (magic != P2P_MAGIC) {
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
            log().debug("Unknown P2P packet type: 0x{:02x}", pkt_type);
            break;
    }
}

void P2PManager::handle_p2p_ping(const asio::ip::udp::endpoint& from,
                                  const P2PPing& ping) {
    log().debug("Received P2P_PING from {} (node {})",
        from.address().to_string(), ping.src_node);

    // 【关键修复】验证是否有该节点的信息
    // 避免收到未知节点的 PING 时创建不完整的状态条目
    auto peer = peers_.get_peer(ping.src_node);
    if (!peer) {
        log().warn("Received P2P_PING from unknown peer {}, ignoring", ping.src_node);
        return;
    }

    // TODO: 验证签名

    // 发送 PONG
    send_p2p_pong(ping, from);

    // 更新状态
    std::unique_lock lock(states_mutex_);
    auto& state = peer_states_[ping.src_node];

    // 【关键修复】如果是新创建的状态条目，从 PeerManager 获取 peer_key
    // 这确保即使是被动接收 PING 的情况，也能正确加密/解密数据
    if (state.peer_key == std::array<uint8_t, X25519_KEY_SIZE>{}) {
        state.peer_key = peer->info.node_key;
        log().debug("Filled peer_key for peer {} from PeerManager", ping.src_node);
    }

    if (state.state != P2PState::CONNECTED) {
        state.state = P2PState::CONNECTED;
        state.active_endpoint = from;
        state.last_recv_time = now_us();

        lock.unlock();

        // 确保会话密钥已派生
        peers_.ensure_session_key(ping.src_node);

        log().info("P2P connection established with peer {} via {}",
            ping.src_node, from.address().to_string());

        if (callbacks_.on_state_change) {
            callbacks_.on_state_change(ping.src_node, P2PState::CONNECTED);
        }
        report_p2p_status(ping.src_node);
    } else {
        state.last_recv_time = now_us();
    }
}

void P2PManager::handle_p2p_pong(const asio::ip::udp::endpoint& from,
                                  const P2PPing& pong) {
    log().debug("Received P2P_PONG from {} (node {})",
        from.address().to_string(), pong.src_node);

    // 计算 RTT
    uint64_t now = now_us();
    uint16_t latency_ms = 0;
    if (now > pong.timestamp) {
        latency_ms = static_cast<uint16_t>((now - pong.timestamp) / 1000);
    }

    // 更新状态
    std::unique_lock lock(states_mutex_);
    auto it = peer_states_.find(pong.src_node);
    if (it == peer_states_.end()) {
        return;
    }

    auto& state = it->second;
    bool was_connected = (state.state == P2PState::CONNECTED);

    state.state = P2PState::CONNECTED;
    state.active_endpoint = from;
    state.last_recv_time = now;
    state.latency_ms = latency_ms;

    lock.unlock();

    if (!was_connected) {
        log().info("P2P connection established with peer {} via {} (latency: {}ms)",
            pong.src_node, from.address().to_string(), latency_ms);

        if (callbacks_.on_state_change) {
            callbacks_.on_state_change(pong.src_node, P2PState::CONNECTED);
        }
        report_p2p_status(pong.src_node);
    }

    // 更新 peer manager 中的延迟信息
    peers_.set_latency(pong.src_node, latency_ms);
}

void P2PManager::handle_p2p_keepalive(const asio::ip::udp::endpoint& from,
                                       NodeId peer_id,
                                       const P2PKeepalive& keepalive) {
    std::unique_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it == peer_states_.end() || it->second.state != P2PState::CONNECTED) {
        return;
    }

    it->second.last_recv_time = now_us();

    // 如果请求响应
    if (keepalive.flags & 0x01) {
        // TODO: 发送响应
    }
}

void P2PManager::handle_p2p_data(const asio::ip::udp::endpoint& from,
                                  NodeId peer_id,
                                  std::span<const uint8_t> encrypted_data) {
    // 确保有 session key
    if (!peers_.ensure_session_key(peer_id)) {
        log().warn("No session key for peer {}", peer_id);
        return;
    }

    // 验证数据长度 (nonce + ciphertext)
    if (encrypted_data.size() < CHACHA20_NONCE_SIZE) {
        log().warn("P2P data too short from peer {}", peer_id);
        return;
    }

    // 提取 nonce 和 ciphertext
    std::array<uint8_t, CHACHA20_NONCE_SIZE> nonce;
    std::copy(encrypted_data.begin(), encrypted_data.begin() + CHACHA20_NONCE_SIZE, nonce.begin());
    auto ciphertext = encrypted_data.subspan(CHACHA20_NONCE_SIZE);

    // 解密数据
    auto decrypt_result = crypto_.decrypt(peer_id, nonce, ciphertext);
    if (!decrypt_result) {
        log().warn("Failed to decrypt P2P data from peer {}", peer_id);
        return;
    }

    // 更新接收时间
    {
        std::unique_lock lock(states_mutex_);
        auto it = peer_states_.find(peer_id);
        if (it != peer_states_.end()) {
            it->second.last_recv_time = now_us();
        }
    }

    // 回调
    if (callbacks_.on_data) {
        callbacks_.on_data(peer_id, *decrypt_result);
    }
}

asio::awaitable<void> P2PManager::send_p2p_ping(NodeId peer_id,
                                                 const asio::ip::udp::endpoint& to) {
    P2PPing ping;
    ping.magic = P2P_MAGIC;
    ping.src_node = crypto_.node_id();
    ping.dst_node = peer_id;
    ping.timestamp = now_us();

    {
        std::unique_lock lock(states_mutex_);
        auto it = peer_states_.find(peer_id);
        if (it != peer_states_.end()) {
            ping.seq_num = ++it->second.ping_seq;
        }
    }

    // TODO: 添加签名

    auto payload = ping.serialize();

    // 构建完整帧
    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + payload.size());

    // Header
    uint32_t magic = P2P_MAGIC;
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

        log().debug("Sent P2P_PING to {} (peer {})",
            to.address().to_string(), peer_id);
    } catch (const std::exception& e) {
        log().debug("Failed to send P2P_PING: {}", e.what());
    }
}

void P2PManager::send_p2p_pong(const P2PPing& ping,
                               const asio::ip::udp::endpoint& to) {
    P2PPing pong;
    pong.magic = P2P_MAGIC;
    pong.src_node = crypto_.node_id();
    pong.dst_node = ping.src_node;
    pong.timestamp = ping.timestamp;  // 回显时间戳
    pong.seq_num = ping.seq_num;

    // TODO: 添加签名

    auto payload = pong.serialize();

    // 构建完整帧
    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + payload.size());

    uint32_t magic = P2P_MAGIC;
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
        log().debug("Sent P2P_PONG to {} (peer {})",
            to.address().to_string(), ping.src_node);
    }
}

asio::awaitable<void> P2PManager::send_p2p_keepalive(NodeId peer_id) {
    std::shared_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it == peer_states_.end() || it->second.state != P2PState::CONNECTED) {
        co_return;
    }

    auto endpoint = it->second.active_endpoint;
    lock.unlock();

    P2PKeepalive keepalive;
    keepalive.timestamp = now_us();
    keepalive.seq_num = 0;
    keepalive.flags = 0x01;  // 请求响应

    // TODO: 计算 MAC

    auto payload = keepalive.serialize();

    // 构建完整帧
    std::vector<uint8_t> frame;
    frame.reserve(P2P_FRAME_HEADER_SIZE + payload.size());

    uint32_t magic = P2P_MAGIC;
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
        log().debug("Failed to send keepalive: {}", e.what());
    }
}

void P2PManager::set_peer_state(NodeId peer_id, P2PState state) {
    std::unique_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        auto old_state = it->second.state;
        it->second.state = state;
        lock.unlock();

        if (old_state != state && callbacks_.on_state_change) {
            callbacks_.on_state_change(peer_id, state);
        }
    }
}

void P2PManager::report_p2p_status(NodeId peer_id) {
    std::shared_lock lock(states_mutex_);
    auto it = peer_states_.find(peer_id);
    if (it == peer_states_.end()) {
        return;
    }

    P2PStatusMsg status;
    status.peer_node = peer_id;
    status.latency_ms = it->second.latency_ms;

    switch (it->second.state) {
        case P2PState::CONNECTED:
            status.status = P2PStatus::P2P;
            status.path_type = PathType::STUN;  // 假设 STUN
            break;
        case P2PState::RELAY_ONLY:
            status.status = P2PStatus::RELAY_ONLY;
            status.path_type = PathType::RELAY;
            break;
        default:
            status.status = P2PStatus::DISCONNECTED;
            status.path_type = PathType::RELAY;
            break;
    }

    lock.unlock();

    if (callbacks_.on_send_p2p_status) {
        callbacks_.on_send_p2p_status(status);
    }
}

std::optional<NodeId> P2PManager::find_peer_by_endpoint(
    const asio::ip::udp::endpoint& ep) const {
    std::shared_lock lock(states_mutex_);
    for (const auto& [id, state] : peer_states_) {
        if (state.active_endpoint == ep) {
            return id;
        }
    }
    return std::nullopt;
}

std::optional<asio::ip::udp::endpoint> P2PManager::to_udp_endpoint(const Endpoint& ep) {
    if (ep.ip_type != IpType::IPv4) {
        return std::nullopt;  // TODO: 支持 IPv6
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

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

    log().info("P2P manager started on port {}", endpoints_.local_port());
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

    // 关闭 socket
    endpoints_.close_socket();

    // 清除状态
    {
        std::unique_lock lock(states_mutex_);
        peer_states_.clear();
    }

    log().info("P2P manager stopped");
}

void P2PManager::connect_peer(NodeId peer_id) {
    std::unique_lock lock(states_mutex_);

    auto it = peer_states_.find(peer_id);
    if (it != peer_states_.end()) {
        auto& state = it->second;
        if (state.state == P2PState::CONNECTED ||
            state.state == P2PState::PUNCHING ||
            state.state == P2PState::RESOLVING) {
            // 已经在连接中
            return;
        }
    }

    // 创建或更新状态
    auto& state = peer_states_[peer_id];
    state.state = P2PState::RESOLVING;
    state.init_seq = ++init_seq_;
    state.punch_count = 0;
    state.last_punch_time = now_us();  // 记录 RESOLVING 开始时间

    lock.unlock();

    // 发送 P2P_INIT 请求
    P2PInit init;
    init.target_node = peer_id;
    init.init_seq = state.init_seq;

    log().debug("Sending P2P_INIT to peer {}, seq={}", peer_id, init.init_seq);

    if (callbacks_.on_send_p2p_init) {
        callbacks_.on_send_p2p_init(init);
    }
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
    std::unique_lock lock(states_mutex_);

    auto it = peer_states_.find(msg.peer_node);
    if (it == peer_states_.end()) {
        log().warn("Received P2P_ENDPOINT for unknown peer {}", msg.peer_node);
        return;
    }

    auto& state = it->second;

    // 验证序列号
    if (state.init_seq != msg.init_seq) {
        log().debug("P2P_ENDPOINT seq mismatch: expected {}, got {}",
            state.init_seq, msg.init_seq);
        return;
    }

    // 保存对端信息
    state.peer_key = msg.peer_key;
    state.peer_endpoints = msg.endpoints;
    state.state = P2PState::PUNCHING;
    state.punch_count = 0;
    state.last_punch_time = 0;

    log().debug("Received P2P_ENDPOINT for peer {}: {} endpoints",
        msg.peer_node, msg.endpoints.size());

    for (const auto& ep : msg.endpoints) {
        log().debug("  - {}.{}.{}.{}:{} (type={})",
            ep.address[0], ep.address[1], ep.address[2], ep.address[3],
            ep.port, static_cast<int>(ep.type));
    }

    lock.unlock();

    if (callbacks_.on_state_change) {
        callbacks_.on_state_change(msg.peer_node, P2PState::PUNCHING);
    }
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

    while (running_ && endpoints_.is_socket_open()) {
        try {
            auto bytes = co_await endpoints_.socket().async_receive_from(
                asio::buffer(buffer), sender, asio::use_awaitable);

            if (bytes > 0) {
                handle_udp_packet(sender, std::span(buffer.data(), bytes));
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() == asio::error::operation_aborted) {
                break;
            }
            log().error("UDP recv error: {}", e.what());
        }
    }
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

        for (auto peer_id : timed_out) {
            log().warn("P2P connection to peer {} timed out", peer_id);
            set_peer_state(peer_id, P2PState::RELAY_ONLY);
            report_p2p_status(peer_id);
        }
    }
}

asio::awaitable<void> P2PManager::punch_loop() {
    while (running_) {
        punch_timer_.expires_after(
            std::chrono::milliseconds(config_.punch_interval_ms));

        try {
            co_await punch_timer_.async_wait(asio::use_awaitable);
        } catch (const boost::system::system_error&) {
            break;
        }

        if (!running_) break;

        uint64_t now = now_us();

        // 对正在打洞的对端发送 PING
        std::vector<std::pair<NodeId, std::vector<Endpoint>>> punching_peers;
        {
            std::shared_lock lock(states_mutex_);
            for (auto& [id, state] : peer_states_) {
                if (state.state == P2PState::PUNCHING) {
                    // 检查是否超时
                    uint64_t punch_start = state.last_punch_time;
                    if (punch_start > 0 &&
                        now - punch_start > config_.punch_timeout_sec * 1000000ULL) {
                        // 打洞超时，标记为 RELAY_ONLY
                        continue; // 将在下面处理
                    }

                    if (state.punch_count < config_.punch_attempts * state.peer_endpoints.size()) {
                        punching_peers.emplace_back(id, state.peer_endpoints);
                    }
                }
            }
        }

        for (const auto& [peer_id, endpoints] : punching_peers) {
            // 轮询发送到每个端点
            std::unique_lock lock(states_mutex_);
            auto it = peer_states_.find(peer_id);
            if (it == peer_states_.end()) continue;

            auto& state = it->second;
            if (state.last_punch_time == 0) {
                state.last_punch_time = now;
            }

            if (endpoints.empty()) continue;

            // 选择下一个端点
            size_t ep_index = state.punch_count % endpoints.size();
            const auto& ep = endpoints[ep_index];
            state.punch_count++;

            lock.unlock();

            auto udp_ep = to_udp_endpoint(ep);
            if (udp_ep) {
                co_await send_p2p_ping(peer_id, *udp_ep);
            }
        }

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
            std::shared_lock lock(states_mutex_);
            auto it = peer_states_.find(peer_id);
            if (it != peer_states_.end()) {
                auto old_state = it->second.state;
                lock.unlock();
                log().warn("P2P {} to peer {} timed out",
                           old_state == P2PState::RESOLVING ? "resolving" : "hole punching",
                           peer_id);
            } else {
                lock.unlock();
            }
            set_peer_state(peer_id, P2PState::RELAY_ONLY);
            report_p2p_status(peer_id);
        }
    }
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

    // TODO: 验证签名

    // 发送 PONG
    send_p2p_pong(ping, from);

    // 更新状态
    std::unique_lock lock(states_mutex_);
    auto& state = peer_states_[ping.src_node];

    if (state.state != P2PState::CONNECTED) {
        state.state = P2PState::CONNECTED;
        state.active_endpoint = from;
        state.last_recv_time = now_us();

        lock.unlock();

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

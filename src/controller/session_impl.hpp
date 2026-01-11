#pragma once

#include "controller/session.hpp"
#include "controller/session_manager.hpp"
#include "common/crypto.hpp"
#include "common/logger.hpp"

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.session"); }
}

// ============================================================================
// SessionBase implementation
// ============================================================================

template<typename StreamType>
SessionBase<StreamType>::SessionBase(StreamType&& ws, SessionManager& manager)
    : ws_(std::move(ws))
    , manager_(manager)
    , write_channel_(ws_.get_executor(), 1024) {  // Buffer up to 1024 messages
}

template<typename StreamType>
asio::awaitable<void> SessionBase<StreamType>::send_frame(FrameType type,
                                                           std::span<const uint8_t> payload,
                                                           FrameFlags flags) {
    auto data = FrameCodec::encode(type, payload, flags);
    co_await send_raw(data);
}

template<typename StreamType>
asio::awaitable<void> SessionBase<StreamType>::send_raw(std::span<const uint8_t> data) {
    std::vector<uint8_t> copy(data.begin(), data.end());

    // Try non-blocking send first (fast path)
    if (!write_channel_.try_send(boost::system::error_code{}, std::move(copy))) {
        // Channel full, this shouldn't happen often with 1024 buffer
        log().warn("Write channel full for node {}", node_id_);
    }
    co_return;
}

template<typename StreamType>
asio::awaitable<void> SessionBase<StreamType>::close() {
    try {
        co_await ws_.async_close(websocket::close_code::normal, asio::use_awaitable);
    } catch (...) {
        // Ignore close errors
    }
}

template<typename StreamType>
asio::awaitable<void> SessionBase<StreamType>::read_loop() {
    try {
        while (true) {
            read_buffer_.clear();
            auto bytes = co_await ws_.async_read(read_buffer_, asio::use_awaitable);
            (void)bytes;

            auto data = read_buffer_.data();
            std::span<const uint8_t> buffer(
                static_cast<const uint8_t*>(data.data()), data.size());

            // Decode frame
            auto result = FrameCodec::decode(buffer);
            if (!result) {
                log().warn("Failed to decode frame: {}", frame_error_message(result.error()));
                continue;
            }

            co_await handle_frame(result->first);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != websocket::error::closed) {
            log().debug("Session read error: {}", e.what());
        }
    }
}

template<typename StreamType>
asio::awaitable<void> SessionBase<StreamType>::write_loop() {
    try {
        while (ws_.is_open()) {
            // Wait for data from channel (thread-safe, lock-free)
            auto [ec, data] = co_await write_channel_.async_receive(asio::as_tuple(asio::use_awaitable));
            if (ec) {
                if (ec == asio::experimental::channel_errc::channel_closed) {
                    break;  // Normal shutdown
                }
                log().debug("Write channel error: {}", ec.message());
                break;
            }

            log().debug("Session write_loop: sending {} bytes to node {}", data.size(), node_id_);
            co_await ws_.async_write(asio::buffer(data), asio::use_awaitable);
            log().debug("Session write_loop: sent {} bytes to node {}", data.size(), node_id_);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted &&
            e.code() != websocket::error::closed) {
            log().debug("Session write error: {}", e.what());
        }
    }

    // Close channel on exit
    write_channel_.close();
}

template<typename StreamType>
asio::awaitable<void> SessionBase<StreamType>::send_error(uint16_t code,
                                                           const std::string& message,
                                                           FrameType request_type,
                                                           uint32_t request_id) {
    ErrorPayload error;
    error.error_code = code;
    error.request_type = request_type;
    error.request_id = request_id;
    error.error_msg = message;

    co_await send_frame(FrameType::FRAME_ERROR, error.serialize());
}

// ============================================================================
// ControlSessionImpl implementation
// ============================================================================

template<typename StreamType>
ControlSessionImpl<StreamType>::ControlSessionImpl(StreamType&& ws, SessionManager& manager)
    : SessionBase<StreamType>(std::move(ws), manager) {}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::start(StreamType ws, SessionManager& manager) {
    auto session = std::make_shared<ControlSessionImpl<StreamType>>(std::move(ws), manager);
    co_await session->run();
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::run() {
    log().info("Control session started");

    try {
        // Run read and write loops concurrently
        co_await (this->read_loop() || this->write_loop());
    } catch (const std::exception& e) {
        log().debug("Control session ended: {}", e.what());
    }

    // Cleanup
    if (this->authenticated_ && this->node_id_ != 0) {
        this->manager_.unregister_control_session(this->node_id_);
        this->manager_.clear_node_endpoints(this->node_id_);
        this->manager_.database().update_node_online(this->node_id_, false);

        // Get node's routes before deleting them (for broadcasting withdrawal)
        auto node_routes = this->manager_.database().get_node_routes(this->node_id_);

        // Delete node's announced routes from database
        this->manager_.database().delete_node_routes(this->node_id_);

        // Notify other nodes about peer status change
        co_await this->manager_.broadcast_config_update(this->network_id_, this->node_id_);

        // Notify other nodes about route withdrawal
        if (node_routes && !node_routes->empty()) {
            co_await this->manager_.broadcast_route_update(
                this->network_id_, this->node_id_, {}, *node_routes);
            log().info("Node {} disconnected, withdrew {} routes",
                       this->node_id_, node_routes->size());
        } else {
            log().info("Node {} disconnected from control channel", this->node_id_);
        }
    }
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_frame(const Frame& frame) {
    log().debug("Control: received {} frame", frame_type_name(frame.header.type));

    switch (frame.header.type) {
        case FrameType::AUTH_REQUEST:
            co_await handle_auth_request(frame);
            break;

        case FrameType::CONFIG_ACK:
            co_await handle_config_ack(frame);
            break;

        case FrameType::PING:
            co_await handle_ping(frame);
            break;

        case FrameType::LATENCY_REPORT:
            co_await handle_latency_report(frame);
            break;

        case FrameType::ROUTE_ANNOUNCE:
            co_await handle_route_announce(frame);
            break;

        case FrameType::ROUTE_WITHDRAW:
            co_await handle_route_withdraw(frame);
            break;

        case FrameType::P2P_INIT:
            co_await handle_p2p_init(frame);
            break;

        case FrameType::ENDPOINT_UPDATE:
            co_await handle_endpoint_update(frame);
            break;

        default:
            if (!this->authenticated_) {
                co_await this->send_error(1001, "Not authenticated", frame.header.type);
            } else {
                log().warn("Control: unhandled frame type 0x{:02X}",
                             static_cast<uint8_t>(frame.header.type));
            }
            break;
    }
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_auth_request(const Frame& frame) {
    auto request = AuthRequest::parse(frame.payload);
    if (!request) {
        co_await this->send_error(1002, "Invalid AUTH_REQUEST format", FrameType::AUTH_REQUEST);
        co_return;
    }

    log().info("Auth request from {} (auth_type={})",
                 request->hostname, static_cast<int>(request->auth_type));

    // Verify signature
    auto sign_data = request->get_sign_data();
    if (!crypto::ed25519_verify(sign_data, request->signature, request->machine_key)) {
        co_await this->send_error(1003, "Invalid signature", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Handle authkey authentication
    NetworkId network_id = 0;
    if (request->auth_type == AuthType::AUTHKEY) {
        std::string authkey(request->auth_data.begin(), request->auth_data.end());
        auto key_record = this->manager_.database().get_authkey(authkey);

        if (!key_record) {
            co_await this->send_error(1004, "Invalid authkey", FrameType::AUTH_REQUEST);
            co_return;
        }

        // Check expiration
        if (key_record->expires_at > 0 && key_record->expires_at < Database::now_ms()) {
            co_await this->send_error(1005, "Authkey expired", FrameType::AUTH_REQUEST);
            co_return;
        }

        // Check usage limit
        if (key_record->max_uses > 0 && key_record->use_count >= key_record->max_uses) {
            co_await this->send_error(1006, "Authkey usage limit exceeded", FrameType::AUTH_REQUEST);
            co_return;
        }

        network_id = key_record->network_id;
        this->manager_.database().increment_authkey_use(authkey);

    } else if (request->auth_type == AuthType::MACHINE) {
        // Reconnection - find existing node
        auto existing = this->manager_.database().get_node_by_machine_key(request->machine_key);
        if (!existing) {
            co_await this->send_error(1007, "Unknown machine key", FrameType::AUTH_REQUEST);
            co_return;
        }
        network_id = existing->network_id;
    } else {
        co_await this->send_error(1008, "Unsupported auth type", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Find or create node
    auto node = this->manager_.database().find_or_create_node(
        network_id, request->machine_key, request->node_key,
        request->hostname, request->os, request->arch, request->version);

    if (!node) {
        co_await this->send_error(1009, "Failed to create node", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Update state
    this->authenticated_ = true;
    this->node_id_ = node->id;
    this->network_id_ = node->network_id;

    // Update node online status
    this->manager_.database().update_node_online(this->node_id_, true);

    // Register session
    this->manager_.register_control_session(this->node_id_,
        std::static_pointer_cast<ISession>(this->shared_from_this()));

    // Create tokens
    auto auth_token = this->manager_.jwt().create_auth_token(this->node_id_, this->network_id_);
    auto relay_token = this->manager_.jwt().create_relay_token(this->node_id_, this->network_id_);

    if (!auth_token || !relay_token) {
        co_await this->send_error(1010, "Failed to create tokens", FrameType::AUTH_REQUEST);
        co_return;
    }

    // Build AUTH_RESPONSE
    AuthResponse response;
    response.success = true;
    response.node_id = this->node_id_;
    response.virtual_ip = node->virtual_ip;
    response.network_id = this->network_id_;
    response.auth_token = std::vector<uint8_t>(auth_token->begin(), auth_token->end());
    response.relay_token = std::vector<uint8_t>(relay_token->begin(), relay_token->end());
    response.error_code = 0;
    response.error_msg = "";

    co_await this->send_frame(FrameType::AUTH_RESPONSE, response.serialize());

    log().info("Node {} authenticated: {} ({})",
                 this->node_id_, node->hostname, node->virtual_ip.to_string());

    // Send CONFIG
    co_await send_config();

    // Notify other nodes about new peer
    co_await this->manager_.broadcast_config_update(this->network_id_, this->node_id_);
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::send_config() {
    // Get all nodes in network
    auto nodes = this->manager_.database().get_nodes_by_network(this->network_id_);
    if (!nodes) {
        log().error("Failed to get nodes for network {}", this->network_id_);
        co_return;
    }

    // Get network info
    auto network = this->manager_.database().get_network(this->network_id_);
    if (!network) {
        log().error("Failed to get network {}", this->network_id_);
        co_return;
    }

    // Parse CIDR
    auto slash_pos = network->cidr.find('/');
    auto subnet_ip = IPv4Address::from_string(network->cidr.substr(0, slash_pos));
    uint8_t subnet_mask = static_cast<uint8_t>(std::stoi(network->cidr.substr(slash_pos + 1)));

    // Build CONFIG
    Config config;
    config.version = this->manager_.current_config_version();
    config.network_id = this->network_id_;
    config.subnet = subnet_ip;
    config.subnet_mask = subnet_mask;
    config.network_name = network->name;

    // Add peers (excluding self)
    for (const auto& node : *nodes) {
        if (node.id == this->node_id_) continue;

        PeerInfo peer;
        peer.node_id = node.id;
        peer.virtual_ip = node.virtual_ip;
        peer.node_key = node.node_key;
        peer.online = node.online;
        peer.name = node.hostname;
        config.peers.push_back(peer);
    }

    // Add relay info (built-in relay = this controller)
    const auto& relay_cfg = this->manager_.builtin_relay_config();
    if (relay_cfg.enabled) {
        RelayInfo relay;
        relay.server_id = 0; // Built-in relay
        relay.hostname = relay_cfg.name;
        relay.priority = relay_cfg.priority;
        relay.region = relay_cfg.region;
        config.relays.push_back(relay);
    }

    // Add built-in STUN server (if enabled)
    const auto& stun_cfg = this->manager_.builtin_stun_config();
    if (stun_cfg.enabled && !stun_cfg.public_ip.empty()) {
        StunInfo stun;
        stun.hostname = stun_cfg.public_ip;
        stun.port = stun_cfg.port;
        config.stuns.push_back(stun);
    }

    // Add announced routes from all nodes in the network
    auto routes = this->manager_.database().get_network_routes(this->network_id_);
    if (routes) {
        config.routes = std::move(*routes);
    }

    // Create new relay token
    auto relay_token = this->manager_.jwt().create_relay_token(this->node_id_, this->network_id_);
    if (relay_token) {
        config.relay_token = std::vector<uint8_t>(relay_token->begin(), relay_token->end());
        auto expiry = this->manager_.jwt().get_token_expiry(*relay_token);
        config.relay_token_expires = expiry.value_or(0) * 1000; // Convert to ms
    }

    config_version_ = config.version;
    co_await this->send_frame(FrameType::CONFIG, config.serialize());

    log().debug("Sent CONFIG to node {} with {} peers, {} routes",
                this->node_id_, config.peers.size(), config.routes.size());
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_config_ack(const Frame& frame) {
    auto ack = ConfigAck::parse(frame.payload);
    if (!ack) {
        co_return;
    }

    log().debug("Node {} acknowledged config version {}", this->node_id_, ack->version);
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_ping(const Frame& frame) {
    auto ping = Ping::parse(frame.payload);
    if (!ping) {
        co_return;
    }

    // Send PONG with same timestamp and seq_num
    Pong pong;
    pong.timestamp = ping->timestamp;
    pong.seq_num = ping->seq_num;

    co_await this->send_frame(FrameType::PONG, pong.serialize());

    // Update last seen
    if (this->authenticated_) {
        this->manager_.database().update_node_last_seen(this->node_id_, Database::now_ms());
    }
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_latency_report(const Frame& frame) {
    if (!this->authenticated_) {
        co_await this->send_error(1001, "Not authenticated", FrameType::LATENCY_REPORT);
        co_return;
    }

    auto report = LatencyReport::parse(frame.payload);
    if (!report) {
        log().warn("Invalid LATENCY_REPORT from node {}", this->node_id_);
        co_return;
    }

    log().debug("Received latency report from node {} with {} entries",
                this->node_id_, report->entries.size());

    // 记录延迟数据（可用于路由优化、P2P 决策等）
    for (const auto& entry : report->entries) {
        log().trace("  Node {} -> Node {}: {}ms (path={})",
                    this->node_id_, entry.peer_node_id,
                    entry.latency_ms, entry.path_type == 0 ? "relay" : "p2p");
    }

    // 构建存储条目
    if (!report->entries.empty()) {
        std::vector<std::tuple<NodeId, uint16_t, uint8_t>> entries;
        entries.reserve(report->entries.size());
        for (const auto& entry : report->entries) {
            entries.emplace_back(entry.peer_node_id, entry.latency_ms, entry.path_type);
        }

        // 存储到数据库
        auto result = this->manager_.database().save_latency_reports(
            this->node_id_, entries, report->timestamp);
        if (!result) {
            log().warn("Failed to save latency report from node {}", this->node_id_);
        }

        // 定期清理旧数据（每个节点最多保留 1000 条记录）
        static thread_local uint32_t cleanup_counter = 0;
        if (++cleanup_counter % 100 == 0) {  // 每 100 次上报执行一次清理
            auto cleaned = this->manager_.database().cleanup_excess_latency_reports(1000);
            if (cleaned && *cleaned > 0) {
                log().debug("Cleaned up {} old latency records", *cleaned);
            }
        }
    }
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_route_announce(const Frame& frame) {
    if (!this->authenticated_) {
        co_await this->send_error(1001, "Not authenticated", FrameType::ROUTE_ANNOUNCE);
        co_return;
    }

    auto announce = RouteAnnounce::parse(frame.payload);
    if (!announce) {
        co_await send_route_ack(0, false, 2001, "Invalid ROUTE_ANNOUNCE format");
        co_return;
    }

    log().info("Node {} announcing {} routes", this->node_id_, announce->routes.size());

    // 存储路由到数据库
    auto result = this->manager_.database().upsert_routes(
        this->node_id_, this->network_id_, announce->routes);

    if (!result) {
        co_await send_route_ack(announce->request_id, false, 2002, "Failed to store routes");
        co_return;
    }

    // 发送成功 ACK
    co_await send_route_ack(announce->request_id, true);

    // 通知其他节点路由更新
    co_await this->manager_.broadcast_route_update(this->network_id_, this->node_id_, announce->routes, {});
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_route_withdraw(const Frame& frame) {
    if (!this->authenticated_) {
        co_await this->send_error(1001, "Not authenticated", FrameType::ROUTE_WITHDRAW);
        co_return;
    }

    auto withdraw = RouteWithdraw::parse(frame.payload);
    if (!withdraw) {
        co_await send_route_ack(0, false, 2001, "Invalid ROUTE_WITHDRAW format");
        co_return;
    }

    log().info("Node {} withdrawing {} routes", this->node_id_, withdraw->routes.size());

    // 从数据库删除路由
    auto result = this->manager_.database().delete_routes(this->node_id_, withdraw->routes);

    if (!result) {
        co_await send_route_ack(withdraw->request_id, false, 2003, "Failed to delete routes");
        co_return;
    }

    // 发送成功 ACK
    co_await send_route_ack(withdraw->request_id, true);

    // 通知其他节点路由更新
    co_await this->manager_.broadcast_route_update(this->network_id_, this->node_id_, {}, withdraw->routes);
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_p2p_init(const Frame& frame) {
    if (!this->authenticated_) {
        co_await this->send_error(1001, "Not authenticated", FrameType::P2P_INIT);
        co_return;
    }

    auto init = P2PInit::parse(frame.payload);
    if (!init) {
        log().error("Invalid P2P_INIT format");
        co_return;
    }

    log().debug("P2P_INIT from node {} targeting node {}, seq={}",
                this->node_id_, init->target_node, init->init_seq);

    // 查找目标节点的 Control Session
    auto target_session = this->manager_.get_control_session(init->target_node);
    if (!target_session) {
        log().debug("Target node {} not connected, cannot provide endpoints", init->target_node);
        // 发送空的 P2P_ENDPOINT 表示对端不在线
        P2PEndpointMsg resp;
        resp.init_seq = init->init_seq;
        resp.peer_node = init->target_node;
        resp.peer_key = {};  // 空公钥
        resp.endpoints = {}; // 空端点列表
        co_await this->send_frame(FrameType::P2P_ENDPOINT, resp.serialize());
        co_return;
    }

    // 从数据库获取对端节点信息
    auto peer_node = this->manager_.database().get_node(init->target_node);
    if (!peer_node) {
        log().warn("Target node {} not found in database", init->target_node);
        co_return;
    }

    // 构造 P2P_ENDPOINT 响应
    P2PEndpointMsg resp;
    resp.init_seq = init->init_seq;
    resp.peer_node = init->target_node;

    // 复制公钥 (machine_key)
    if (peer_node->machine_key.size() >= X25519_KEY_SIZE) {
        std::copy_n(peer_node->machine_key.begin(), X25519_KEY_SIZE, resp.peer_key.begin());
    }

    // 获取对端上报的端点列表
    resp.endpoints = this->manager_.get_node_endpoints(init->target_node);

    log().debug("Sending P2P_ENDPOINT to node {} for peer {}: {} endpoints",
                this->node_id_, init->target_node, resp.endpoints.size());

    co_await this->send_frame(FrameType::P2P_ENDPOINT, resp.serialize());
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::handle_endpoint_update(const Frame& frame) {
    if (!this->authenticated_) {
        co_await this->send_error(1001, "Not authenticated", FrameType::ENDPOINT_UPDATE);
        co_return;
    }

    auto update = EndpointUpdate::parse(frame.payload);
    if (!update) {
        log().error("Invalid ENDPOINT_UPDATE format");
        co_return;
    }

    log().debug("Node {} reported {} endpoints", this->node_id_, update->endpoints.size());
    for (const auto& ep : update->endpoints) {
        log().debug("  - {}.{}.{}.{}:{} (type={})",
                    ep.address[0], ep.address[1], ep.address[2], ep.address[3],
                    ep.port, static_cast<int>(ep.type));
    }

    // 存储端点到 SessionManager
    this->manager_.update_node_endpoints(this->node_id_, update->endpoints);
}

template<typename StreamType>
asio::awaitable<void> ControlSessionImpl<StreamType>::send_route_ack(
    uint32_t request_id, bool success, uint16_t error_code, const std::string& error_msg) {

    RouteAck ack;
    ack.request_id = request_id;
    ack.success = success;
    ack.error_code = error_code;
    ack.error_msg = error_msg;

    co_await this->send_frame(FrameType::ROUTE_ACK, ack.serialize());
}

// ============================================================================
// RelaySessionImpl implementation
// ============================================================================

template<typename StreamType>
RelaySessionImpl<StreamType>::RelaySessionImpl(StreamType&& ws, SessionManager& manager)
    : SessionBase<StreamType>(std::move(ws), manager) {}

template<typename StreamType>
asio::awaitable<void> RelaySessionImpl<StreamType>::start(StreamType ws, SessionManager& manager) {
    auto session = std::make_shared<RelaySessionImpl<StreamType>>(std::move(ws), manager);
    co_await session->run();
}

template<typename StreamType>
asio::awaitable<void> RelaySessionImpl<StreamType>::run() {
    log().info("Relay session started");

    try {
        co_await (this->read_loop() || this->write_loop());
    } catch (const std::exception& e) {
        log().debug("Relay session ended: {}", e.what());
    }

    // Cleanup
    if (this->authenticated_ && this->node_id_ != 0) {
        this->manager_.unregister_relay_session(this->node_id_);
        log().info("Node {} disconnected from relay channel", this->node_id_);
    }
}

template<typename StreamType>
asio::awaitable<void> RelaySessionImpl<StreamType>::handle_frame(const Frame& frame) {
    log().debug("Relay: received {} frame", frame_type_name(frame.header.type));

    switch (frame.header.type) {
        case FrameType::RELAY_AUTH:
            co_await handle_relay_auth(frame);
            break;

        case FrameType::DATA:
            co_await handle_data(frame);
            break;

        case FrameType::PING:
            co_await handle_ping(frame);
            break;

        default:
            if (!this->authenticated_) {
                co_await this->send_error(1001, "Not authenticated", frame.header.type);
            } else {
                log().warn("Relay: unhandled frame type 0x{:02X}",
                             static_cast<uint8_t>(frame.header.type));
            }
            break;
    }
}

template<typename StreamType>
asio::awaitable<void> RelaySessionImpl<StreamType>::handle_relay_auth(const Frame& frame) {
    auto auth = RelayAuth::parse(frame.payload);
    if (!auth) {
        co_await this->send_error(1002, "Invalid RELAY_AUTH format", FrameType::RELAY_AUTH);
        co_return;
    }

    // Verify relay token
    std::string token(auth->relay_token.begin(), auth->relay_token.end());
    auto claims = this->manager_.jwt().verify_relay_token(token);

    if (!claims) {
        co_await this->send_error(1003, jwt_error_message(claims.error()), FrameType::RELAY_AUTH);
        co_return;
    }

    // Verify node_id matches
    if (claims->node_id != auth->node_id) {
        co_await this->send_error(1004, "Node ID mismatch", FrameType::RELAY_AUTH);
        co_return;
    }

    // Update state
    this->authenticated_ = true;
    this->node_id_ = auth->node_id;
    this->network_id_ = claims->network_id;

    // Register relay session
    this->manager_.register_relay_session(this->node_id_,
        std::static_pointer_cast<ISession>(this->shared_from_this()));

    // Send success response
    RelayAuthResp response;
    response.success = true;
    response.error_code = 0;
    response.error_msg = "";

    co_await this->send_frame(FrameType::RELAY_AUTH_RESP, response.serialize());

    log().info("Node {} authenticated to relay channel", this->node_id_);
}

template<typename StreamType>
asio::awaitable<void> RelaySessionImpl<StreamType>::handle_data(const Frame& frame) {
    if (!this->authenticated_) {
        co_await this->send_error(1001, "Not authenticated", FrameType::DATA);
        co_return;
    }

    // Parse DATA payload to get dst_node
    auto data = DataPayload::parse(frame.payload);
    if (!data) {
        log().warn("Relay: failed to parse DATA payload");
        co_return; // Silently drop malformed data
    }

    auto src_ip = this->manager_.get_node_ip_str(data->src_node);
    auto dst_ip = this->manager_.get_node_ip_str(data->dst_node);

    log().debug("Relay: DATA from {} to {} ({} bytes)", src_ip, dst_ip, frame.payload.size());

    // Verify src_node matches authenticated node
    if (data->src_node != this->node_id_) {
        log().warn("Node {} attempted to send DATA with src_node={}",
                     this->manager_.get_node_ip_str(this->node_id_), src_ip);
        co_return;
    }

    // Find target relay session
    auto target = this->manager_.get_relay_session(data->dst_node);
    if (!target) {
        // Target not connected to relay, drop silently
        log().warn("Relay: DATA from {} to {} dropped: target not on relay", src_ip, dst_ip);
        co_return;
    }

    // Forward the entire frame as-is (we don't decrypt)
    auto frame_data = FrameCodec::encode(FrameType::DATA, frame.payload);
    co_await target->send_raw(frame_data);

    log().debug("Relay: forwarded DATA from {} to {} ({} bytes)", src_ip, dst_ip, frame.payload.size());
}

template<typename StreamType>
asio::awaitable<void> RelaySessionImpl<StreamType>::handle_ping(const Frame& frame) {
    auto ping = Ping::parse(frame.payload);
    if (!ping) {
        co_return;
    }

    Pong pong;
    pong.timestamp = ping->timestamp;
    pong.seq_num = ping->seq_num;

    co_await this->send_frame(FrameType::PONG, pong.serialize());
}

} // namespace edgelink::controller

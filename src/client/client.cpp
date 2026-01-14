#include "client/client.hpp"
#include "common/logger.hpp"
#include <nlohmann/json.hpp>
#include <future>

namespace edgelink::client {

namespace {
    auto& log() { return Logger::get("client"); }
}

const char* client_state_name(ClientState state) {
    switch (state) {
        case ClientState::STOPPED: return "STOPPED";
        case ClientState::STARTING: return "STARTING";
        case ClientState::AUTHENTICATING: return "AUTHENTICATING";
        case ClientState::CONNECTING_RELAY: return "CONNECTING_RELAY";
        case ClientState::RUNNING: return "RUNNING";
        case ClientState::RECONNECTING: return "RECONNECTING";
        default: return "UNKNOWN";
    }
}

Client::Client(asio::io_context& ioc, const ClientConfig& config)
    : ioc_(ioc)
    , ssl_ctx_(ssl::context::tlsv12_client)
    , config_(config)
    , crypto_()
    , peers_(crypto_)
    , state_machine_(ioc)
    , keepalive_timer_(ioc)
    , reconnect_timer_(ioc)
    , dns_refresh_timer_(ioc)
    , latency_timer_(ioc)
    , route_announce_timer_(ioc) {

    // Initialize config applier
    config_applier_ = std::make_unique<ConfigApplier>(*this);

    // 设置统一状态机
    setup_state_machine();

    // Initialize P2P managers
    endpoint_mgr_ = std::make_unique<EndpointManager>(ioc);
    p2p_mgr_ = std::make_unique<P2PManager>(ioc, crypto_, peers_, *endpoint_mgr_, state_machine_);

    // 创建 P2P 状态变化通道（由状态机使用）
    peer_state_channel_ = std::make_unique<edgelink::channels::PeerStateChannel>(ioc, 64);
    state_machine_.set_peer_state_channel(peer_state_channel_.get());

    // 创建 P2P channels（用于 P2PManager 通信）
    endpoints_ready_channel_ = std::make_unique<P2PChannels::EndpointsReadyChannel>(ioc, 16);
    p2p_init_channel_ = std::make_unique<P2PChannels::P2PInitChannel>(ioc, 16);
    p2p_status_channel_ = std::make_unique<P2PChannels::P2PStatusChannel>(ioc, 16);
    p2p_data_channel_ = std::make_unique<P2PChannels::DataChannel>(ioc, 64);

    // 设置 P2PManager 的 channels
    P2PChannels p2p_channels;
    p2p_channels.endpoints_channel = endpoints_ready_channel_.get();
    p2p_channels.init_channel = p2p_init_channel_.get();
    p2p_channels.status_channel = p2p_status_channel_.get();
    p2p_channels.data_channel = p2p_data_channel_.get();
    p2p_mgr_->set_channels(p2p_channels);

    // 设置 P2P 配置（直接使用 config_.p2p，已经是统一的 P2PConfig 类型）
    p2p_mgr_->set_config(config_.p2p);

    // Setup SSL context
    ssl_ctx_.set_default_verify_paths();

    if (config_.ssl_verify) {
        // Enable certificate verification
        ssl_ctx_.set_verify_mode(ssl::verify_peer);

        // Load custom CA certificate if specified
        if (!config_.ssl_ca_file.empty()) {
            boost::system::error_code ec;
            ssl_ctx_.load_verify_file(config_.ssl_ca_file, ec);
            if (ec) {
                log().warn("Failed to load CA file '{}': {}", config_.ssl_ca_file, ec.message());
            } else {
                log().info("Loaded custom CA certificate: {}", config_.ssl_ca_file);
            }
        }

        // Set verification callback for self-signed certificate handling
        if (config_.ssl_allow_self_signed) {
            ssl_ctx_.set_verify_callback([](bool preverified, ssl::verify_context& ctx) {
                // Get verification error
                int err = X509_STORE_CTX_get_error(ctx.native_handle());

                // Allow self-signed certificates
                if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
                    err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
                    log().debug("Accepting self-signed certificate");
                    return true;
                }

                // For other errors, use default verification result
                return preverified;
            });
            log().info("SSL: allowing self-signed certificates");
        }
        // Note: hostname verification is done per-connection in channel.cpp
        log().info("SSL: certificate verification enabled");
    } else {
        // Disable certificate verification (insecure, for testing only)
        ssl_ctx_.set_verify_mode(ssl::verify_none);
        log().warn("SSL: certificate verification DISABLED (insecure)");
    }
}

Client::~Client() {
    if (state_ != ClientState::STOPPED) {
        // Warning: Client is being destroyed without proper shutdown
        // This may cause resource leaks or undefined behavior
        log().error("Client destroyed without calling stop() first! State: {}",
                    client_state_name(state_));
    }

    teardown_ipc();
    teardown_tun();
}

void Client::set_events(ClientEvents events) {
    events_ = events;
}

void Client::setup_channels() {
    // 创建 handler 完成跟踪 channel (容量大于 handler 数量以确保不阻塞)
    handlers_done_ch_ = std::make_unique<HandlerCompletionChannel>(ioc_, 32);
    active_handlers_ = 0;

    // 创建 Control Channel 事件 channels
    ctrl_auth_response_ch_ = std::make_unique<channels::AuthResponseChannel>(ioc_, 4);
    ctrl_config_ch_ = std::make_unique<channels::ConfigChannel>(ioc_, 4);
    ctrl_config_update_ch_ = std::make_unique<channels::ConfigUpdateChannel>(ioc_, 16);
    ctrl_route_update_ch_ = std::make_unique<channels::RouteUpdateChannel>(ioc_, 16);
    ctrl_peer_routing_update_ch_ = std::make_unique<channels::PeerRoutingUpdateChannel>(ioc_, 16);
    ctrl_p2p_endpoint_ch_ = std::make_unique<channels::P2PEndpointMsgChannel>(ioc_, 32);
    ctrl_error_ch_ = std::make_unique<channels::ControlErrorChannel>(ioc_, 8);
    ctrl_connected_ch_ = std::make_unique<channels::ControlConnectedChannel>(ioc_, 4);
    ctrl_disconnected_ch_ = std::make_unique<channels::ControlDisconnectedChannel>(ioc_, 4);

    // 设置 ControlChannel 的 channels
    ControlChannelEvents ctrl_events;
    ctrl_events.auth_response = ctrl_auth_response_ch_.get();
    ctrl_events.config = ctrl_config_ch_.get();
    ctrl_events.config_update = ctrl_config_update_ch_.get();
    ctrl_events.route_update = ctrl_route_update_ch_.get();
    ctrl_events.peer_routing_update = ctrl_peer_routing_update_ch_.get();
    ctrl_events.p2p_endpoint = ctrl_p2p_endpoint_ch_.get();
    ctrl_events.error = ctrl_error_ch_.get();
    ctrl_events.connected = ctrl_connected_ch_.get();
    ctrl_events.disconnected = ctrl_disconnected_ch_.get();
    control_->set_channels(ctrl_events);

    // 创建 Relay Channel 事件 channels
    relay_data_ch_ = std::make_unique<channels::RelayDataChannel>(ioc_, 64);
    relay_connected_ch_ = std::make_unique<channels::RelayConnectedChannel>(ioc_, 4);
    relay_disconnected_ch_ = std::make_unique<channels::RelayDisconnectedChannel>(ioc_, 4);

    // 设置 RelayChannel 的 channels
    RelayChannelEvents relay_events;
    relay_events.data = relay_data_ch_.get();
    relay_events.connected = relay_connected_ch_.get();
    relay_events.disconnected = relay_disconnected_ch_.get();
    relay_->set_channels(relay_events);

    // 启动 Control Channel 事件处理协程 (12 handlers total)
    active_handlers_ += 12;
    asio::co_spawn(ioc_, ctrl_auth_response_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_config_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_config_update_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_route_update_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_peer_routing_update_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_p2p_endpoint_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_error_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_connected_handler(), asio::detached);
    asio::co_spawn(ioc_, ctrl_disconnected_handler(), asio::detached);

    // 启动 Relay Channel 事件处理协程
    asio::co_spawn(ioc_, relay_data_handler(), asio::detached);
    asio::co_spawn(ioc_, relay_connected_handler(), asio::detached);
    asio::co_spawn(ioc_, relay_disconnected_handler(), asio::detached);
}

// ============================================================================
// Control Channel 事件处理协程
// ============================================================================

asio::awaitable<void> Client::ctrl_auth_response_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, resp] = co_await ctrl_auth_response_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_auth_response_handler channel error: {}", ec.message());
            }
            break;
        }

        log().info("Authenticated: node_id={}, ip={}", resp.node_id, resp.virtual_ip.to_string());
        state_machine_.set_node_id(crypto_.node_id());
        state_machine_.set_control_plane_state(ControlPlaneState::CONFIGURING);
    }

    // Notify handler completion
    log().debug("ctrl_auth_response_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_config_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, config] = co_await ctrl_config_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_config_handler channel error: {}", ec.message());
            }
            break;
        }

        peers_.update_from_config(config.peers);

        {
            std::lock_guard lock(routes_mutex_);
            routes_ = config.routes;
        }

        log().info("Config received: {} peers, {} routes, {} stuns",
                   config.peers.size(), config.routes.size(), config.stuns.size());

        state_machine_.set_control_plane_state(ControlPlaneState::READY);

        if (endpoint_mgr_ && !config.stuns.empty()) {
            endpoint_mgr_->set_stun_servers(config.stuns);
        }

        // Initialize multi-relay manager if not already initialized and relays are available
        if (!multi_relay_mgr_ && !config.relays.empty()) {
            MultiRelayConfig relay_config;
            relay_config.enabled = true;
            relay_config.max_connections_per_relay = 2;  // Conservative default
            relay_config.rtt_measure_interval = std::chrono::seconds(10);

            multi_relay_mgr_ = std::make_shared<MultiRelayManager>(
                ioc_, ssl_ctx_, crypto_, peers_, relay_config);

            log().info("MultiRelayManager initialized with {} relays", config.relays.size());

            // Start multi-relay manager
            auto self = shared_from_this();
            bool use_tls = [&]() {
                std::shared_lock lock(config_mutex_);
                return config_.tls;
            }();
            asio::co_spawn(ioc_, [self, relays = config.relays, relay_token = config.relay_token, use_tls]() -> asio::awaitable<void> {
                try {
                    co_await self->multi_relay_mgr_->initialize(relays, relay_token, use_tls);
                    log().info("MultiRelayManager initialized successfully");

                    // Initialize latency measurer after relay manager is started
                    if (!self->latency_measurer_) {
                        LatencyMeasureConfig latency_config;
                        latency_config.measure_interval = std::chrono::seconds(30);
                        latency_config.report_interval = std::chrono::seconds(60);

                        self->latency_measurer_ = std::make_shared<PeerLatencyMeasurer>(
                            self->ioc_, *self->multi_relay_mgr_, self->peers_, latency_config);

                        co_await self->latency_measurer_->start();
                        log().info("PeerLatencyMeasurer started successfully");
                    }
                } catch (const std::exception& e) {
                    log().error("Failed to start multi-relay system: {}", e.what());
                }
            }, asio::detached);
        }

        bool accept_routes = [&]() {
            std::shared_lock lock(config_mutex_);
            return config_.accept_routes;
        }();

        if (accept_routes && is_tun_enabled()) {
            if (!route_mgr_) {
                route_mgr_ = std::make_unique<RouteManager>(*this);
                route_mgr_->start();
            }
            if (route_mgr_) {
                route_mgr_->sync_routes(config.routes);
            }
        }

        if (p2p_mgr_ && !p2p_mgr_->is_running()) {
            auto self = shared_from_this();
            asio::co_spawn(ioc_, [self]() -> asio::awaitable<void> {
                try {
                    co_await self->p2p_mgr_->start();
                    log().info("P2P manager started (STUN configured)");

                    std::vector<Endpoint> endpoints;
                    {
                        std::lock_guard lock(self->endpoints_mutex_);
                        if (!self->last_reported_endpoints_.empty()) {
                            endpoints = self->last_reported_endpoints_;
                        }
                    }

                    if (!endpoints.empty() && self->control_ && self->control_->is_connected()) {
                        co_await self->control_->send_endpoint_update(endpoints);
                        log().info("Resent {} endpoints after P2P manager started", endpoints.size());
                    }
                } catch (const std::exception& e) {
                    log().error("P2P manager failed: {}", e.what());
                }
            }(), asio::detached);
        }
    }

    // Notify handler completion
    log().debug("ctrl_config_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_config_update_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, update] = co_await ctrl_config_update_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_config_update_handler channel error: {}", ec.message());
            }
            break;
        }

        if (has_flag(update.update_flags, ConfigUpdateFlags::PEER_CHANGED)) {
            std::vector<NodeId> added_peer_ids;

            for (const auto& peer : update.add_peers) {
                peers_.add_peer(peer);
                added_peer_ids.push_back(peer.node_id);
                state_machine_.add_peer(peer.node_id);
                state_machine_.set_peer_data_path(peer.node_id, PeerDataPath::RELAY);
            }
            for (auto peer_id : update.del_peer_ids) {
                state_machine_.remove_peer(peer_id);
                peers_.remove_peer(peer_id);
                if (p2p_mgr_) {
                    p2p_mgr_->disconnect_peer(peer_id);
                }
            }

            bool accept_routes_config = [&]() {
                std::shared_lock lock(config_mutex_);
                return config_.accept_routes;
            }();

            if (!added_peer_ids.empty() && route_mgr_ && accept_routes_config) {
                std::vector<RouteInfo> relevant_routes;
                {
                    std::lock_guard lock(routes_mutex_);
                    for (const auto& route : routes_) {
                        for (auto peer_id : added_peer_ids) {
                            if (route.gateway_node == peer_id) {
                                relevant_routes.push_back(route);
                                break;
                            }
                        }
                    }
                }
                if (!relevant_routes.empty()) {
                    route_mgr_->apply_route_update(relevant_routes, {});
                    log().debug("Applied {} routes for {} newly online peers",
                               relevant_routes.size(), added_peer_ids.size());
                }
            }
        }
    }

    // Notify handler completion
    log().debug("ctrl_config_update_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_route_update_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, update] = co_await ctrl_route_update_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_route_update_handler channel error: {}", ec.message());
            }
            break;
        }

        log().info("Route update v{}: +{} routes, -{} routes",
                   update.version, update.add_routes.size(), update.del_routes.size());

        {
            std::lock_guard lock(routes_mutex_);

            for (const auto& route : update.add_routes) {
                bool found = false;
                for (auto& r : routes_) {
                    if (r.ip_type == route.ip_type &&
                        r.prefix == route.prefix &&
                        r.prefix_len == route.prefix_len &&
                        r.gateway_node == route.gateway_node) {
                        r = route;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    routes_.push_back(route);
                }
                log().debug("  + route /{} via node {}", route.prefix_len, route.gateway_node);
            }

            for (const auto& route : update.del_routes) {
                routes_.erase(
                    std::remove_if(routes_.begin(), routes_.end(),
                        [&route](const RouteInfo& r) {
                            return r.ip_type == route.ip_type &&
                                   r.prefix == route.prefix &&
                                   r.prefix_len == route.prefix_len &&
                                   r.gateway_node == route.gateway_node;
                        }),
                    routes_.end());
                log().debug("  - route /{} via node {}", route.prefix_len, route.gateway_node);
            }
        }

        if (route_mgr_) {
            route_mgr_->apply_route_update(update.add_routes, update.del_routes);
        }
    }

    // Notify handler completion
    log().debug("ctrl_route_update_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_peer_routing_update_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, update] = co_await ctrl_peer_routing_update_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_peer_routing_update_handler channel error: {}", ec.message());
            }
            break;
        }

        log().info("Peer routing update v{} with {} routes",
                   update.version, update.routes.size());

        // 传递给 MultiRelayManager 处理
        if (multi_relay_mgr_) {
            multi_relay_mgr_->handle_peer_routing_update(update);
        }
    }

    // Notify handler completion
    log().debug("ctrl_peer_routing_update_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_p2p_endpoint_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, msg] = co_await ctrl_p2p_endpoint_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_p2p_endpoint_handler channel error: {}", ec.message());
            }
            break;
        }

        if (p2p_mgr_) {
            p2p_mgr_->handle_p2p_endpoint(msg);
        }
    }

    // Notify handler completion
    log().debug("ctrl_p2p_endpoint_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_error_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, code, msg] = co_await ctrl_error_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_error_handler channel error: {}", ec.message());
            }
            break;
        }

        log().error("Control error {}: {}", code, msg);
        if (events_.error) {
            bool sent = events_.error->try_send(boost::system::error_code{}, code, msg);
            if (!sent) {
                log().warn("Failed to send error event (channel full or closed)");
            }
        }
    }

    // Notify handler completion
    log().debug("ctrl_error_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_connected_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec] = co_await ctrl_connected_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_connected_handler channel error: {}", ec.message());
            }
            break;
        }

        log().info("Control channel connected (CONFIG received)");
        // 注意：这里不需要额外处理，因为 CONNECTED 状态表示 CONFIG 已收到
        // 实际的配置处理在 ctrl_config_handler 中完成
    }

    // Notify handler completion
    log().debug("ctrl_connected_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::ctrl_disconnected_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec] = co_await ctrl_disconnected_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("ctrl_disconnected_handler channel error: {}", ec.message());
            }
            break;
        }

        log().warn("Control channel disconnected");
        state_machine_.set_control_plane_state(ControlPlaneState::DISCONNECTED);

        bool auto_reconnect = [&]() {
            std::shared_lock lock(config_mutex_);
            return config_.auto_reconnect;
        }();

        if (auto_reconnect && state_ != ClientState::STOPPED &&
            state_ != ClientState::RECONNECTING) {
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }
    }

    // Notify handler completion
    log().debug("ctrl_disconnected_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

// ============================================================================
// Relay Channel 事件处理协程
// ============================================================================

asio::awaitable<void> Client::relay_data_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec, src, data] = co_await relay_data_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("relay_data_handler channel error: {}", ec.message());
            }
            break;
        }

        auto src_peer_ip = peers_.get_peer_ip_str(src);
        log().debug("Received {} bytes from {}", data.size(), src_peer_ip);

        // Check for internal ping/pong messages
        if (data.size() >= 13 && (data[0] == 0xEE || data[0] == 0xEF)) {
            handle_ping_data(src, data);
            continue;
        }

        // If TUN mode is enabled, write IP packets to TUN device
        if (is_tun_enabled() && ip_packet::version(data) == 4) {
            auto src_ip = ip_packet::src_ipv4(data);
            auto dst_ip = ip_packet::dst_ipv4(data);
            log().debug("Writing to TUN: {} -> {} ({} bytes)",
                          src_ip.to_string(), dst_ip.to_string(), data.size());

            auto result = tun_->write(data);
            if (!result) {
                log().warn("Failed to write to TUN: {}", tun_error_message(result.error()));
            } else {
                log().debug("TUN write successful: {} bytes", data.size());
            }
        }

        // Call user callback via channel
        if (events_.data_received) {
            bool sent = events_.data_received->try_send(boost::system::error_code{}, src, std::move(data));
            if (!sent) {
                log().warn("Failed to send data_received event for peer {} (channel full or closed)", src);
            }
        }
    }

    // Notify handler completion
    log().debug("relay_data_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::relay_connected_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec] = co_await relay_connected_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("relay_connected_handler channel error: {}", ec.message());
            }
            break;
        }

        log().info("Relay channel connected");

        std::string relay_id = relay_ ? relay_->url() : "default";
        state_machine_.add_relay(relay_id, true);
        state_machine_.set_relay_state(relay_id, RelayConnectionState::CONNECTED);

        state_ = ClientState::RUNNING;

        if (events_.connected) {
            bool sent = events_.connected->try_send(boost::system::error_code{});
            if (!sent) {
                log().warn("Failed to send connected event (channel full or closed)");
            }
        }

        // Start keepalive
        asio::co_spawn(ioc_, keepalive_loop(), asio::detached);

        // Start P2P channel handlers
        if (p2p_mgr_) {
            asio::co_spawn(ioc_, p2p_endpoints_handler(), asio::detached);
            asio::co_spawn(ioc_, p2p_init_handler(), asio::detached);
            asio::co_spawn(ioc_, p2p_status_handler(), asio::detached);
            asio::co_spawn(ioc_, p2p_data_handler(), asio::detached);
        }

        // Start peer state handler
        if (peer_state_channel_) {
            asio::co_spawn(ioc_, p2p_state_handler(), asio::detached);
        }

        // Start DNS refresh loop
        asio::co_spawn(ioc_, dns_refresh_loop(), asio::detached);

        // Start latency measurement loop (read config with lock)
        {
            std::shared_lock lock(config_mutex_);
            if (config_.latency_measure_interval.count() > 0) {
                asio::co_spawn(ioc_, latency_measure_loop(), asio::detached);
            }
        }

        // Announce configured routes (read config with lock)
        {
            std::shared_lock lock(config_mutex_);
            if (!config_.advertise_routes.empty() || config_.exit_node) {
                asio::co_spawn(ioc_, announce_configured_routes(), asio::detached);

                if (config_.route_announce_interval.count() > 0) {
                    asio::co_spawn(ioc_, route_announce_loop(), asio::detached);
                }
            }
        }
    }

    // Notify handler completion
    log().debug("relay_connected_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

asio::awaitable<void> Client::relay_disconnected_handler() {
    while (state_ != ClientState::STOPPED) {
        auto [ec] = co_await relay_disconnected_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("relay_disconnected_handler channel error: {}", ec.message());
            }
            break;
        }

        log().warn("Relay channel disconnected");

        std::string relay_id = relay_ ? relay_->url() : "default";
        state_machine_.set_relay_state(relay_id, RelayConnectionState::DISCONNECTED);

        bool auto_reconnect = [&]() {
            std::shared_lock lock(config_mutex_);
            return config_.auto_reconnect;
        }();

        if (auto_reconnect && state_ != ClientState::STOPPED &&
            state_ != ClientState::RECONNECTING) {
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }
    }

    // Notify handler completion
    log().debug("relay_disconnected_handler stopped");
    if (handlers_done_ch_) {
        handlers_done_ch_->try_send(boost::system::error_code{});
    }
    active_handlers_--;
}

bool Client::setup_tun() {
    // 基本检查：control channel 必须存在
    if (!control_) {
        log().error("Cannot setup TUN: control channel does not exist");
        return false;
    }

    // 检查是否已经有 virtual_ip（表示认证成功）
    auto vip = control_->virtual_ip();
    if (vip.to_u32() == 0) {
        log().error("Cannot setup TUN: virtual IP not available (authentication not complete?)");
        return false;
    }

    log().debug("Setting up TUN device with virtual IP: {}", vip.to_string());

    // Create TUN device
    tun_ = TunDevice::create(ioc_);
    if (!tun_) {
        log().error("Failed to create TUN device");
        return false;
    }

    // Open TUN device
    auto result = tun_->open(config_.tun_name);
    if (!result) {
        log().error("Failed to open TUN device '{}': {}", config_.tun_name, tun_error_message(result.error()));
        tun_.reset();
        return false;
    }

    // Calculate netmask from prefix length (e.g., /16 -> 255.255.0.0)
    uint8_t prefix_len = control_->subnet_mask();
    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    auto netmask = IPv4Address::from_u32(mask);

    log().debug("Configuring TUN device: IP={}, netmask={}, MTU={}",
                vip.to_string(), netmask.to_string(), config_.tun_mtu);

    result = tun_->configure(vip, netmask, config_.tun_mtu);
    if (!result) {
        log().error("Failed to configure TUN device: {}", tun_error_message(result.error()));
        tun_->close();
        tun_.reset();
        return false;
    }

    // Create TUN packet channel and start reading
    tun_packet_ch_ = std::make_unique<channels::TunPacketChannel>(ioc_, 64);
    tun_handler_done_ch_ = std::make_unique<TunHandlerCompletionChannel>(ioc_, 1);
    tun_->set_packet_channel(tun_packet_ch_.get());
    tun_->start_read();

    // Start packet handler coroutine
    asio::co_spawn(ioc_, tun_packet_handler(), asio::detached);

    log().info("TUN device enabled: {} with IP {} (/{} bits)",
               tun_->name(), vip.to_string(), prefix_len);
    return true;
}

void Client::teardown_tun() {
    // Close channel first to wake up any waiting coroutines
    if (tun_packet_ch_) {
        tun_packet_ch_->close();
        tun_packet_ch_.reset();
        tun_handler_done_ch_.reset();
    }

    // Then close TUN device
    if (tun_) {
        tun_->stop_read();
        tun_->close();
        tun_.reset();
        log().info("TUN device closed");
    }
}

asio::awaitable<void> Client::tun_packet_handler() {
    while (state_ != ClientState::STOPPED && tun_packet_ch_) {
        auto [ec, packet] = co_await tun_packet_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("TUN packet channel closed: {}", ec.message());
            }
            break;
        }
        // 处理接收到的 TUN 数据包
        on_tun_packet(std::span<const uint8_t>(packet));
    }

    log().debug("TUN packet handler stopped");

    // Notify teardown_tun() that handler has exited
    if (tun_handler_done_ch_) {
        tun_handler_done_ch_->try_send(boost::system::error_code{});
    }
}

void Client::on_tun_packet(std::span<const uint8_t> packet) {
    // Validate IPv4 packet
    if (packet.size() < 20 || ip_packet::version(packet) != 4) {
        return;
    }

    // Get destination IP
    auto dst_ip = ip_packet::dst_ipv4(packet);
    auto src_ip = ip_packet::src_ipv4(packet);
    uint32_t dst_u32 = dst_ip.to_u32();

    // Silently drop multicast (224.0.0.0/4) and broadcast (255.255.255.255)
    uint8_t first_octet = (dst_u32 >> 24) & 0xFF;
    if (first_octet >= 224 || dst_u32 == 0xFFFFFFFF) {
        return;
    }

    // Silently drop subnet broadcast (e.g., 100.64.255.255 for /16)
    if (control_) {
        uint8_t prefix_len = control_->subnet_mask();
        if (prefix_len > 0 && prefix_len < 32) {
            uint32_t host_mask = (1U << (32 - prefix_len)) - 1;  // e.g., 0x0000FFFF for /16
            // Check if all host bits are 1 (broadcast address)
            if ((dst_u32 & host_mask) == host_mask) {
                return;
            }
        }
    }

    log().debug("TUN packet: {} -> {} ({} bytes)",
                  src_ip.to_string(), dst_ip.to_string(), packet.size());

    // Find peer by destination IP
    auto peer = peers_.get_peer_by_ip(dst_ip);
    if (!peer) {
        log().warn("TUN packet to unknown IP {}, dropping (known peers: {})",
                     dst_ip.to_string(), peers_.peer_count());
        return;
    }

    log().debug("Forwarding to {} ({})", peer->info.virtual_ip.to_string(),
                  peer->info.online ? "online" : "offline");

    // Send via relay - 使用 shared_from_this 保证生命周期安全（多线程环境）
    asio::co_spawn(ioc_, [self = shared_from_this(), peer_id = peer->info.node_id,
                          data = std::vector<uint8_t>(packet.begin(), packet.end())]()
                          -> asio::awaitable<void> {
        co_await self->send_to_peer(peer_id, data);
    }, asio::detached);
}

asio::awaitable<bool> Client::start() {
    if (state_ != ClientState::STOPPED) {
        log().warn("Client already started");
        co_return false;
    }

    state_ = ClientState::STARTING;
    log().info("Starting client...");

    // State directory (should be set by main, fallback to current directory)
    std::string state_dir = config_.state_dir.empty() ? "." : config_.state_dir;
    log().info("State directory: {}", state_dir);

    // Key file is always stored in state_dir
    std::string key_file = state_dir + "/keys";

    // Try to load existing keys, or generate new ones
    auto load_result = crypto_.load_keys_from_file(key_file);
    if (!load_result) {
        // Generate new keys
        auto init_result = crypto_.init();
        if (!init_result) {
            log().error("Failed to initialize crypto engine");
            state_ = ClientState::STOPPED;
            co_return false;
        }
        // Save new keys for future sessions
        auto save_result = crypto_.save_keys_to_file(key_file);
        if (!save_result) {
            log().warn("Failed to save keys (will regenerate on next startup)");
        }
    }

    // 支持多 Controller URL 故障转移
    if (config_.controller_hosts.empty()) {
        config_.controller_hosts.push_back("edge.a-z.xin");
    }

    log().info("TLS: {}", config_.tls ? "enabled" : "disabled");
    log().info("Controller hosts: {}", config_.controller_hosts.size());

    // 尝试连接每个 Controller
    bool controller_connected = false;

    for (size_t i = 0; i < config_.controller_hosts.size() && !controller_connected; ++i) {
        const auto& host_port = config_.controller_hosts[i];

        // 解析 host:port 格式
        auto [host, port] = ClientConfig::parse_host_port(host_port, config_.tls);

        // 构建 URL
        std::string scheme = config_.tls ? "wss://" : "ws://";
        std::string base_url = scheme + host + ":" + std::to_string(port);
        std::string control_url = base_url + "/api/v1/control";
        std::string relay_url = base_url + "/api/v1/relay";

        log().info("Trying controller {}/{}: {}:{}", i + 1, config_.controller_hosts.size(), host, port);
        log().debug("Control URL: {}", control_url);
        log().debug("Relay URL: {}", relay_url);

        // Create channels
        control_ = std::make_shared<ControlChannel>(ioc_, ssl_ctx_, crypto_, control_url, config_.tls);
        relay_ = std::make_shared<RelayChannel>(ioc_, ssl_ctx_, crypto_, peers_, relay_url, config_.tls);

        // Setup event channels
        setup_channels();

        // Connect to control channel
        state_ = ClientState::AUTHENTICATING;
        state_machine_.set_control_plane_state(ControlPlaneState::CONNECTING);
        log().info("Connecting to controller...");

        bool connected = co_await control_->connect(config_.authkey);
        if (!connected) {
            log().warn("Failed to connect to controller {}:{}", host, port);
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // Wait for auth response (30s timeout for high-latency networks)
        asio::steady_timer timer(ioc_);
        timer.expires_after(std::chrono::seconds(30));

        bool auth_ok = false;
        while (!control_->is_connected()) {
            auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                    asio::post(ioc_, asio::use_awaitable));
            if (timer.expiry() <= std::chrono::steady_clock::now()) {
                log().warn("Authentication timeout (30s) for {}:{}", host, port);
                break;
            }
            co_await asio::post(ioc_, asio::use_awaitable);
        }

        if (!control_->is_connected()) {
            try {
                co_await control_->close();
            } catch (const std::exception& e) {
                log().debug("Failed to close control channel: {}", e.what());
            } catch (...) {
                log().debug("Failed to close control channel: unknown error");
            }
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // Connect to relay channel
        state_ = ClientState::CONNECTING_RELAY;
        log().info("Connecting to relay...");

        connected = co_await relay_->connect(control_->relay_token());
        if (!connected) {
            log().warn("Failed to connect to relay {}:{}", host, port);
            try {
                co_await control_->close();
            } catch (const std::exception& e) {
                log().debug("Failed to close control channel: {}", e.what());
            } catch (...) {
                log().debug("Failed to close control channel: unknown error");
            }
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // Wait for relay auth (30s timeout for high-latency networks)
        timer.expires_after(std::chrono::seconds(30));
        while (!relay_->is_connected()) {
            auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                    asio::post(ioc_, asio::use_awaitable));
            if (timer.expiry() <= std::chrono::steady_clock::now()) {
                log().warn("Relay authentication timeout (30s) for {}:{}", host, port);
                break;
            }
            co_await asio::post(ioc_, asio::use_awaitable);
        }

        if (!relay_->is_connected()) {
            try {
                co_await control_->close();
            } catch (const std::exception& e) {
                log().debug("Failed to close control channel: {}", e.what());
            } catch (...) {
                log().debug("Failed to close control channel: unknown error");
            }
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // 连接成功
        controller_connected = true;
        log().info("Connected to controller: {}:{}", host, port);

        // Setup TUN device if enabled
        // TUN requires control channel with valid virtual_ip (from authentication)
        if (config_.enable_tun) {
            // Verify dependencies are met (should always be true at this point)
            if (!control_ || control_->virtual_ip().to_u32() == 0) {
                log().error("Cannot setup TUN: control channel or virtual IP not available (initialization order violation)");
                state_ = ClientState::STOPPED;
                co_return false;  // Hard error - this indicates a programming bug
            }

            if (!setup_tun()) {
                log().warn("TUN mode requested but failed to setup TUN device (likely OS/permission issue)");
                // Soft failure - continue without TUN, as this is an operational error
            }
        }
    }

    // 所有 controller 都失败了
    if (!controller_connected) {
        log().error("Failed to connect to any controller");
        if (config_.auto_reconnect) {
            log().info("Will retry in {}s...", config_.reconnect_interval.count());
            state_ = ClientState::STOPPED;
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        } else {
            state_ = ClientState::STOPPED;
        }
        co_return false;
    }

    // Start IPC server for CLI control
    if (config_.enable_ipc) {
        setup_ipc();
    }

    log().info("Client started successfully");
    log().info("  Node ID: {}", crypto_.node_id());
    log().info("  Virtual IP: {}", control_->virtual_ip().to_string());
    log().info("  Peers: {}", peers_.peer_count());
    if (is_tun_enabled()) {
        log().info("  TUN device: {}", tun_->name());
    }
    if (is_ipc_enabled()) {
        log().info("  IPC socket: {}", ipc_->socket_path());
    }

    co_return true;
}

asio::awaitable<void> Client::stop() {
    log().info("Stopping client...");

    // CRITICAL: Set stopped state FIRST to signal all handlers to exit their while loops
    state_ = ClientState::STOPPED;
    log().debug("State set to STOPPED, handlers will exit their loops");

    log().debug("Cancelling timers...");
    keepalive_timer_.cancel();
    reconnect_timer_.cancel();
    dns_refresh_timer_.cancel();
    latency_timer_.cancel();
    route_announce_timer_.cancel();

    // Reset reconnect counter
    reconnect_attempts_ = 0;

    // Clear pending pings to prevent resource leaks
    {
        std::lock_guard lock(ping_mutex_);
        if (!pending_pings_.empty()) {
            log().debug("Clearing {} pending ping(s)", pending_pings_.size());
            pending_pings_.clear();
        }
    }

    // Stop config watcher (has background watch loop)
    if (config_watcher_) {
        log().debug("Stopping config watcher...");
        config_watcher_->stop();
        config_watcher_.reset();
        log().debug("Config watcher stopped");
    }

    // Stop latency measurer first (depends on multi_relay_mgr_)
    if (latency_measurer_) {
        log().debug("Stopping latency measurer...");
        co_await latency_measurer_->stop();
        latency_measurer_.reset();
        log().debug("Latency measurer stopped");
    }

    // Stop multi-relay manager (has background RTT measurement loop)
    if (multi_relay_mgr_) {
        log().debug("Stopping multi-relay manager...");
        co_await multi_relay_mgr_->stop();
        multi_relay_mgr_.reset();
        log().debug("Multi-relay manager stopped");
    }

    // Stop P2P manager
    if (p2p_mgr_) {
        log().debug("Stopping P2P manager...");
        co_await p2p_mgr_->stop();
        log().debug("P2P manager stopped");
    }

    // Stop route manager first (removes routes from system)
    if (route_mgr_) {
        log().debug("Stopping route manager...");
        route_mgr_->stop();
        route_mgr_.reset();
        log().debug("Route manager stopped");
    }

    // Teardown TUN
    log().debug("Tearing down TUN device...");
    // Wait for TUN packet handler to exit before tearing down
    if (tun_packet_ch_ && tun_handler_done_ch_) {
        tun_packet_ch_->close();
        try {
            co_await tun_handler_done_ch_->async_receive(asio::use_awaitable);
            log().debug("TUN packet handler confirmed stopped");
        } catch (...) {
            log().warn("Failed to wait for TUN packet handler to stop");
        }
    }

    teardown_tun();
    log().debug("TUN device torn down");

    // Close all event channels to wake up waiting handlers
    log().debug("Closing event channels to wake up handlers...");
    if (ctrl_auth_response_ch_) ctrl_auth_response_ch_->close();
    if (ctrl_config_ch_) ctrl_config_ch_->close();
    if (ctrl_config_update_ch_) ctrl_config_update_ch_->close();
    if (ctrl_route_update_ch_) ctrl_route_update_ch_->close();
    if (ctrl_peer_routing_update_ch_) ctrl_peer_routing_update_ch_->close();
    if (ctrl_p2p_endpoint_ch_) ctrl_p2p_endpoint_ch_->close();
    if (ctrl_error_ch_) ctrl_error_ch_->close();
    if (ctrl_connected_ch_) ctrl_connected_ch_->close();
    if (ctrl_disconnected_ch_) ctrl_disconnected_ch_->close();
    if (relay_data_ch_) relay_data_ch_->close();
    if (relay_connected_ch_) relay_connected_ch_->close();
    if (relay_disconnected_ch_) relay_disconnected_ch_->close();

    // Wait for all handlers to exit (with timeout to avoid hanging)
    int expected_handlers = active_handlers_.load();
    log().debug("Waiting for {} handler(s) to exit...", expected_handlers);

    // Wait up to 5 seconds for handlers to complete
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    int completed = 0;

    while (completed < expected_handlers && std::chrono::steady_clock::now() < deadline) {
        try {
            asio::steady_timer wait_timer(ioc_);
            wait_timer.expires_after(std::chrono::milliseconds(50));

            // Try to receive one completion notification (non-blocking)
            bool received = false;
            handlers_done_ch_->try_receive([&](boost::system::error_code) {
                received = true;
                completed++;
            });

            if (!received) {
                // No handler completed yet, wait briefly and retry
                co_await wait_timer.async_wait(asio::use_awaitable);
            }
        } catch (...) {
            break;
        }
    }

    int remaining = active_handlers_.load();
    if (remaining > 0) {
        log().warn("{} of {} handler(s) did not exit cleanly", remaining, expected_handlers);
    } else {
        log().debug("All {} handlers exited successfully", completed);
    }

    if (relay_) {
        log().debug("Closing relay channel...");
        co_await relay_->close();
        log().debug("Relay channel closed");
    }

    if (control_) {
        log().debug("Closing control channel...");
        co_await control_->close();
        log().debug("Control channel closed");
    }

    log().info("Client stopped successfully");

    if (events_.disconnected) {
        bool sent = events_.disconnected->try_send(boost::system::error_code{});
        if (!sent) {
            log().debug("Failed to send disconnected event (channel closed)");
        }
    }
}

asio::awaitable<bool> Client::send_to_peer(NodeId peer_id, std::span<const uint8_t> data) {
    // 优先尝试 P2P 发送
    if (p2p_mgr_ && p2p_mgr_->is_running()) {
        if (p2p_mgr_->is_p2p_connected(peer_id)) {
            bool sent = co_await p2p_mgr_->send_data(peer_id, data);
            if (sent) {
                co_return true;
            }
            // P2P 发送失败，回退到 Relay
            log().debug("P2P send failed, falling back to relay");
        } else {
            // P2P 未连接，尝试发起连接（异步，不阻塞当前发送）
            asio::co_spawn(ioc_, p2p_mgr_->connect_peer(peer_id), asio::detached);
        }
    }

    // 优先使用 MultiRelayManager（智能路由选择）
    if (multi_relay_mgr_ && multi_relay_mgr_->has_available_connection()) {
        auto channel = multi_relay_mgr_->get_channel_for_peer(peer_id);
        if (channel && channel->is_connected()) {
            co_return co_await channel->send_data(peer_id, data);
        }
    }

    // 回退到单 Relay 发送
    if (!relay_ || !relay_->is_connected()) {
        log().warn("Cannot send: no relay connected");
        co_return false;
    }

    co_return co_await relay_->send_data(peer_id, data);
}

asio::awaitable<bool> Client::send_to_ip(const IPv4Address& ip, std::span<const uint8_t> data) {
    auto peer = peers_.get_peer_by_ip(ip);
    if (!peer) {
        log().warn("Cannot send: no peer with IP {}", ip.to_string());
        co_return false;
    }

    co_return co_await send_to_peer(peer->info.node_id, data);
}

asio::awaitable<bool> Client::send_ip_packet(std::span<const uint8_t> packet) {
    // Validate IPv4 packet
    if (packet.size() < 20 || ip_packet::version(packet) != 4) {
        log().warn("Invalid IP packet");
        co_return false;
    }

    // Get destination IP from packet
    auto dst_ip = ip_packet::dst_ipv4(packet);

    // Send to peer with that IP
    co_return co_await send_to_ip(dst_ip, packet);
}

asio::awaitable<void> Client::p2p_state_handler() {
    log().debug("Peer state handler started");

    while (state_ != ClientState::STOPPED) {
        try {
            // 从 channel 接收状态变化
            auto [ec, peer_id, p2p_state, data_path] = co_await peer_state_channel_->async_receive(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    log().debug("Peer state channel error: {}", ec.message());
                }
                break;
            }

            log().info("Peer state changed: peer={}, p2p={}, path={}",
                       peers_.get_peer_ip_str(peer_id),
                       p2p_connection_state_name(p2p_state),
                       peer_data_path_name(data_path));

            // 状态变化已在 ClientStateMachine 中处理，这里只做日志和可能的额外处理

        } catch (const std::exception& e) {
            log().warn("Peer state handler exception: {}", e.what());
            break;
        }
    }

    log().debug("Peer state handler stopped");
    co_return;
}

// P2P channel handlers
asio::awaitable<void> Client::p2p_endpoints_handler() {
    log().debug("P2P endpoints handler started");

    while (state_ != ClientState::STOPPED && endpoints_ready_channel_) {
        try {
            auto [ec, endpoints] = co_await endpoints_ready_channel_->async_receive(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    log().debug("Endpoints channel error: {}", ec.message());
                }
                break;
            }

            // 保存端点（用于重连后重发）
            {
                std::lock_guard lock(endpoints_mutex_);
                last_reported_endpoints_ = endpoints;
            }

            // 上报端点给 Controller
            if (control_ && control_->is_connected()) {
                log().debug("Sending endpoint update: {} endpoints", endpoints.size());
                co_await control_->send_endpoint_update(endpoints);
            }

        } catch (const std::exception& e) {
            log().warn("P2P endpoints handler exception: {}", e.what());
            break;
        }
    }

    log().debug("P2P endpoints handler stopped");
}

asio::awaitable<void> Client::p2p_init_handler() {
    log().debug("P2P init handler started");

    while (state_ != ClientState::STOPPED && p2p_init_channel_) {
        try {
            auto [ec, init] = co_await p2p_init_channel_->async_receive(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    log().debug("P2P init channel error: {}", ec.message());
                }
                break;
            }

            // 通过 Control Channel 发送 P2P_INIT
            if (control_ && control_->is_connected()) {
                co_await control_->send_p2p_init(init);
            }

        } catch (const std::exception& e) {
            log().warn("P2P init handler exception: {}", e.what());
            break;
        }
    }

    log().debug("P2P init handler stopped");
}

asio::awaitable<void> Client::p2p_status_handler() {
    log().debug("P2P status handler started");

    while (state_ != ClientState::STOPPED && p2p_status_channel_) {
        try {
            auto [ec, status] = co_await p2p_status_channel_->async_receive(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    log().debug("P2P status channel error: {}", ec.message());
                }
                break;
            }

            // TODO: 通过 Control Channel 发送 P2P_STATUS
            log().debug("P2P status: peer={}, state={}, latency={}ms",
                        status.peer_node, static_cast<int>(status.status), status.latency_ms);

        } catch (const std::exception& e) {
            log().warn("P2P status handler exception: {}", e.what());
            break;
        }
    }

    log().debug("P2P status handler stopped");
}

asio::awaitable<void> Client::p2p_data_handler() {
    log().debug("P2P data handler started");

    while (state_ != ClientState::STOPPED && p2p_data_channel_) {
        try {
            auto [ec, peer_id, data] = co_await p2p_data_channel_->async_receive(
                asio::as_tuple(asio::use_awaitable));

            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    log().debug("P2P data channel error: {}", ec.message());
                }
                break;
            }

            log().debug("P2P data received: {} bytes from {}",
                        data.size(), peers_.get_peer_ip_str(peer_id));

            // Check for internal ping/pong messages (type byte 0xEE/0xEF)
            if (data.size() >= 13 && (data[0] == 0xEE || data[0] == 0xEF)) {
                handle_ping_data(peer_id, data);
                continue;
            }

            // If TUN mode is enabled, write IP packets to TUN device
            if (is_tun_enabled() && ip_packet::version(data) == 4) {
                auto result = tun_->write(data);
                if (!result) {
                    log().warn("Failed to write to TUN: {}", tun_error_message(result.error()));
                }
            }

            // Call user callback via channel
            if (events_.data_received) {
                bool sent = events_.data_received->try_send(boost::system::error_code{}, peer_id, std::move(data));
                if (!sent) {
                    log().warn("Failed to send P2P data_received event for peer {} (channel full or closed)", peer_id);
                }
            }

        } catch (const std::exception& e) {
            log().warn("P2P data handler exception: {}", e.what());
            break;
        }
    }

    log().debug("P2P data handler stopped");
}

asio::awaitable<void> Client::keepalive_loop() {
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.ping_interval;
    }();

    while (state_ == ClientState::RUNNING) {
        try {
            keepalive_timer_.expires_after(interval);
            // Update interval in case config changed
            {
                std::shared_lock lock(config_mutex_);
                interval = config_.ping_interval;
            }
            co_await keepalive_timer_.async_wait(asio::use_awaitable);

            if (control_ && control_->is_connected()) {
                co_await control_->send_ping();
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                log().debug("Keepalive error: {}", e.what());
            }
            break;
        }
    }
}

asio::awaitable<void> Client::reconnect() {
    if (state_ == ClientState::RECONNECTING) {
        co_return;
    }

    state_ = ClientState::RECONNECTING;

    // Check if we've exceeded maximum retry attempts
    if (reconnect_attempts_ >= max_reconnect_attempts_) {
        log().error("Maximum reconnect attempts ({}) exceeded, giving up",
                    max_reconnect_attempts_);
        state_ = ClientState::STOPPED;
        if (events_.disconnected) {
            bool sent = events_.disconnected->try_send(boost::system::error_code{});
            if (!sent) {
                log().debug("Failed to send disconnected event (channel closed)");
            }
        }
        co_return;
    }

    reconnect_attempts_++;

    // Calculate exponential backoff: interval * 2^(attempts-1)
    // But cap at max_reconnect_interval_ (read config with lock)
    auto backoff_multiplier = (1 << (reconnect_attempts_ - 1));  // 2^(attempts-1)
    auto base_interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.reconnect_interval;
    }();
    auto backoff_interval = base_interval * backoff_multiplier;
    if (backoff_interval > max_reconnect_interval_) {
        backoff_interval = max_reconnect_interval_;
    }

    log().info("Attempting to reconnect (attempt {}/{}, backoff: {}s)...",
               reconnect_attempts_, max_reconnect_attempts_,
               backoff_interval.count());

    // Clear DNS cache so it will be re-initialized after reconnect
    {
        std::lock_guard lock(dns_cache_mutex_);
        cached_controller_endpoints_set_.clear();
    }

    // Teardown TUN on reconnect
    teardown_tun();

    // 【关键修复】停止 P2P manager，确保后台任务终止
    // 避免重连时老协程与新状态不一致导致崩溃
    if (p2p_mgr_) {
        try {
            co_await p2p_mgr_->stop();
        } catch (const std::exception& e) {
            log().debug("Failed to stop P2P manager: {}", e.what());
        } catch (...) {
            log().debug("Failed to stop P2P manager: unknown error");
        }
    }

    // Close existing channels
    if (relay_) {
        try {
            co_await relay_->close();
        } catch (const std::exception& e) {
            log().debug("Failed to close relay channel: {}", e.what());
        } catch (...) {
            log().debug("Failed to close relay channel: unknown error");
        }
        relay_.reset();
    }
    if (control_) {
        try {
            co_await control_->close();
        } catch (const std::exception& e) {
            log().debug("Failed to close control channel: {}", e.what());
        } catch (...) {
            log().debug("Failed to close control channel: unknown error");
        }
        control_.reset();
    }

    try {
        reconnect_timer_.expires_after(backoff_interval);
        co_await reconnect_timer_.async_wait(asio::use_awaitable);

        // Try to reconnect
        state_ = ClientState::STOPPED;
        bool success = co_await start();

        if (success) {
            // Reconnect succeeded, reset retry counter
            reconnect_attempts_ = 0;
            log().info("Reconnect successful");
        } else {
            bool auto_reconnect = [&]() {
                std::shared_lock lock(config_mutex_);
                return config_.auto_reconnect;
            }();
            if (auto_reconnect) {
                // start() failed, schedule another attempt
                log().warn("Reconnect failed, will retry in {}s (attempt {}/{})",
                           backoff_interval.count(), reconnect_attempts_,
                           max_reconnect_attempts_);
                asio::co_spawn(ioc_, reconnect(), asio::detached);
            }
        }

    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().debug("Reconnect error: {}", e.what());
            // Schedule another reconnect attempt
            bool auto_reconnect = [&]() {
                std::shared_lock lock(config_mutex_);
                return config_.auto_reconnect;
            }();
            if (auto_reconnect) {
                asio::co_spawn(ioc_, reconnect(), asio::detached);
            }
        } else {
            // Operation was cancelled (likely due to stop())
            reconnect_attempts_ = 0;  // Reset counter on cancellation
        }
    }
}

asio::awaitable<void> Client::dns_refresh_loop() {
    // Skip if DNS refresh is disabled (read with lock)
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.dns_refresh_interval;
    }();

    if (interval.count() == 0) {
        co_return;
    }

    while (state_ == ClientState::RUNNING) {
        try {
            dns_refresh_timer_.expires_after(interval);
            co_await dns_refresh_timer_.async_wait(asio::use_awaitable);

            if (state_ != ClientState::RUNNING) {
                break;
            }

            // Read config values with lock
            std::string controller_host;
            bool use_tls;
            bool auto_reconnect;
            {
                std::shared_lock lock(config_mutex_);
                if (config_.controller_hosts.empty()) {
                    continue;
                }
                controller_host = config_.controller_hosts[0];
                use_tls = config_.tls;
                auto_reconnect = config_.auto_reconnect;
                interval = config_.dns_refresh_interval;  // Update interval in case config changed
            }

            // 解析第一个 controller host
            auto [host, port_num] = ClientConfig::parse_host_port(controller_host, use_tls);
            std::string port = std::to_string(port_num);

            // Resolve DNS
            asio::ip::tcp::resolver resolver(ioc_);
            auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

            // Build endpoints set for comparison (ignore order)
            std::set<std::string> new_endpoints_set;
            std::string new_endpoints_str;
            for (const auto& ep : endpoints) {
                std::string endpoint_str = ep.endpoint().address().to_string() + ":" +
                                          std::to_string(ep.endpoint().port());
                new_endpoints_set.insert(endpoint_str);

                if (!new_endpoints_str.empty()) {
                    new_endpoints_str += ",";
                }
                new_endpoints_str += endpoint_str;
            }

            // Check if DNS resolution changed (compare sets to ignore order)
            bool changed = false;
            {
                std::lock_guard lock(dns_cache_mutex_);
                if (!cached_controller_endpoints_set_.empty() &&
                    cached_controller_endpoints_set_ != new_endpoints_set) {
                    changed = true;

                    // Build readable strings for logging
                    std::string old_str, new_str;
                    for (const auto& ep : cached_controller_endpoints_set_) {
                        if (!old_str.empty()) old_str += ",";
                        old_str += ep;
                    }
                    for (const auto& ep : new_endpoints_set) {
                        if (!new_str.empty()) new_str += ",";
                        new_str += ep;
                    }
                    log().info("DNS resolution changed: {} -> {}", old_str, new_str);
                }

                // Update cache (first time or unchanged)
                if (cached_controller_endpoints_set_.empty()) {
                    cached_controller_endpoints_set_ = new_endpoints_set;
                    log().debug("DNS cache initialized: {}", new_endpoints_str);
                }
            }

            if (changed) {
                // Trigger reconnect to use new endpoints
                if (auto_reconnect) {
                    asio::co_spawn(ioc_, reconnect(), asio::detached);
                }
                co_return;
            }

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                log().debug("DNS refresh error: {}", e.what());
            }
            break;
        }
    }
}

asio::awaitable<void> Client::latency_measure_loop() {
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.latency_measure_interval;
    }();

    log().info("Latency measurement started (interval: {}s)", interval.count());

    while (state_ == ClientState::RUNNING) {
        try {
            latency_timer_.expires_after(interval);
            // Update interval in case config changed
            {
                std::shared_lock lock(config_mutex_);
                interval = config_.latency_measure_interval;
            }
            co_await latency_timer_.async_wait(asio::use_awaitable);

            if (state_ != ClientState::RUNNING || !relay_ || !relay_->is_connected()) {
                continue;
            }

            // Get all online peers
            auto online_peers = peers_.get_online_peers();
            if (online_peers.empty()) {
                continue;
            }

            log().debug("Measuring latency to {} online peers", online_peers.size());

            // 收集延迟数据
            LatencyReport report;
            report.timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());

            // Ping each online peer (with small delay between pings to avoid burst)
            for (const auto& peer : online_peers) {
                if (state_ != ClientState::RUNNING) {
                    break;
                }

                // Skip self
                if (peer.info.node_id == crypto_.node_id()) {
                    continue;
                }

                // Send ping with short timeout (2s)
                uint16_t latency = co_await ping_peer(peer.info.node_id, std::chrono::milliseconds(2000));

                // 添加到报告
                LatencyReportEntry entry;
                entry.peer_node_id = peer.info.node_id;
                entry.latency_ms = latency;
                entry.path_type = 0;  // 0 = relay (目前只有 relay 模式)
                report.entries.push_back(entry);

                if (latency > 0) {
                    log().debug("Latency to {}: {}ms", peer.info.virtual_ip.to_string(), latency);
                } else {
                    log().debug("Latency to {}: timeout", peer.info.virtual_ip.to_string());
                }

                // Small delay between pings (100ms)
                asio::steady_timer delay_timer(co_await asio::this_coro::executor);
                delay_timer.expires_after(std::chrono::milliseconds(100));
                co_await delay_timer.async_wait(asio::use_awaitable);
            }

            // 上报延迟数据到 Controller
            if (!report.entries.empty() && control_ && control_->is_connected()) {
                co_await control_->send_latency_report(report);
                log().debug("Reported latency for {} peers to controller", report.entries.size());
            }

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                log().debug("Latency measurement error: {}", e.what());
            }
            break;
        }
    }

    log().debug("Latency measurement loop stopped");
}

asio::awaitable<void> Client::route_announce_loop() {
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.route_announce_interval;
    }();

    // 等待第一个间隔（首次公告已经在 on_connected 中完成）
    route_announce_timer_.expires_after(interval);

    try {
        co_await route_announce_timer_.async_wait(asio::use_awaitable);
    } catch (const boost::system::system_error&) {
        co_return;
    }

    log().info("Route announcement loop started (interval: {}s)", interval.count());

    while (state_ == ClientState::RUNNING) {
        try {
            // 重新公告路由
            if (control_ && control_->is_connected()) {
                log().debug("Re-announcing routes (periodic broadcast)");
                co_await announce_configured_routes();
            }

            // 等待下一个间隔 (update interval in case config changed)
            {
                std::shared_lock lock(config_mutex_);
                interval = config_.route_announce_interval;
            }
            route_announce_timer_.expires_after(interval);
            co_await route_announce_timer_.async_wait(asio::use_awaitable);

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                log().debug("Route announce error: {}", e.what());
            }
            break;
        }
    }

    log().debug("Route announcement loop stopped");
}

// ============================================================================
// IPC Server Management
// ============================================================================

bool Client::setup_ipc() {
    if (!config_.enable_ipc) {
        return false;
    }

    if (ipc_ && ipc_->is_running()) {
        return true;
    }

    ipc_ = std::make_shared<IpcServer>(ioc_, *this);

    // Set shutdown callback if provided (adapter from channel to callback)
    if (events_.shutdown_requested) {
        ipc_->set_shutdown_callback([ch = events_.shutdown_requested]() {
            ch->try_send(boost::system::error_code{});
        });
    }

    IpcServerConfig ipc_config;
    ipc_config.socket_path = config_.ipc_socket_path;
    ipc_config.enabled = true;

    if (!ipc_->start(ipc_config)) {
        log().warn("Failed to start IPC server");
        ipc_.reset();
        return false;
    }

    return true;
}

void Client::teardown_ipc() {
    if (ipc_) {
        ipc_->stop();
        ipc_.reset();
    }
}

// ============================================================================
// Ping Implementation
// ============================================================================

// Internal ping message format:
// Byte 0: 0xEE = ping request, 0xEF = pong response
// Bytes 1-4: sequence number (big-endian)
// Bytes 5-12: timestamp in milliseconds (big-endian)

asio::awaitable<uint16_t> Client::ping_peer(NodeId peer_id, std::chrono::milliseconds timeout) {
    if (!relay_ || !relay_->is_connected()) {
        log().warn("Cannot ping: relay not connected");
        co_return 0;
    }

    auto peer = peers_.get_peer(peer_id);
    if (!peer) {
        log().warn("Cannot ping: peer {} not found", peer_id);
        co_return 0;
    }

    if (!peer->info.online) {
        log().warn("Cannot ping: peer {} is offline", peer_id);
        co_return 0;
    }

    // Generate ping message
    uint32_t seq = ++ping_seq_;
    uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());

    std::vector<uint8_t> ping_msg(13);
    ping_msg[0] = 0xEE;  // ping request
    ping_msg[1] = (seq >> 24) & 0xFF;
    ping_msg[2] = (seq >> 16) & 0xFF;
    ping_msg[3] = (seq >> 8) & 0xFF;
    ping_msg[4] = seq & 0xFF;
    ping_msg[5] = (now >> 56) & 0xFF;
    ping_msg[6] = (now >> 48) & 0xFF;
    ping_msg[7] = (now >> 40) & 0xFF;
    ping_msg[8] = (now >> 32) & 0xFF;
    ping_msg[9] = (now >> 24) & 0xFF;
    ping_msg[10] = (now >> 16) & 0xFF;
    ping_msg[11] = (now >> 8) & 0xFF;
    ping_msg[12] = now & 0xFF;

    // Setup pending ping with channel
    uint64_t key = (static_cast<uint64_t>(peer_id) << 32) | seq;
    auto response_ch = std::make_shared<PingResponseChannel>(ioc_, 1);

    {
        std::lock_guard lock(ping_mutex_);
        pending_pings_[key] = PendingPing{now, response_ch};
    }

    // Send ping
    bool sent = co_await relay_->send_data(peer_id, ping_msg);
    if (!sent) {
        std::lock_guard lock(ping_mutex_);
        pending_pings_.erase(key);
        co_return 0;
    }

    log().debug("Ping sent to {} (seq={})", peer->info.virtual_ip.to_string(), seq);

    // Wait for response with timeout using parallel operations
    asio::steady_timer timer(co_await asio::this_coro::executor);
    timer.expires_after(timeout);

    uint16_t latency = 0;
    bool got_response = false;

    // Use experimental::make_parallel_group to wait for either timer or channel
    auto result = co_await asio::experimental::make_parallel_group(
        timer.async_wait(asio::deferred),
        response_ch->async_receive(asio::deferred)
    ).async_wait(
        asio::experimental::wait_for_one(),
        asio::use_awaitable
    );

    // Check which operation completed first
    // make_parallel_group returns: [completion_order, timer_ec, channel_ec, channel_value]
    auto completion_order = std::get<0>(result);
    if (completion_order[0] == 1) {
        // Channel received first (pong response)
        boost::system::error_code ec = std::get<2>(result);
        if (!ec) {
            latency = std::get<3>(result);
            got_response = true;
        }
    } else {
        // Timer expired first (timeout)
        log().debug("Ping timeout to {} (seq={})", peer->info.virtual_ip.to_string(), seq);
    }

    // Cleanup pending ping entry
    {
        std::lock_guard lock(ping_mutex_);
        pending_pings_.erase(key);
    }

    co_return latency;
}

asio::awaitable<uint16_t> Client::ping_ip(const IPv4Address& ip, std::chrono::milliseconds timeout) {
    auto peer = peers_.get_peer_by_ip(ip);
    if (!peer) {
        log().warn("Cannot ping: no peer with IP {}", ip.to_string());
        co_return 0;
    }
    co_return co_await ping_peer(peer->info.node_id, timeout);
}

void Client::handle_ping_data(NodeId src, std::span<const uint8_t> data) {
    if (data.size() < 13) return;

    uint8_t type = data[0];
    uint32_t seq = (static_cast<uint32_t>(data[1]) << 24) |
                   (static_cast<uint32_t>(data[2]) << 16) |
                   (static_cast<uint32_t>(data[3]) << 8) |
                   static_cast<uint32_t>(data[4]);
    uint64_t timestamp = (static_cast<uint64_t>(data[5]) << 56) |
                         (static_cast<uint64_t>(data[6]) << 48) |
                         (static_cast<uint64_t>(data[7]) << 40) |
                         (static_cast<uint64_t>(data[8]) << 32) |
                         (static_cast<uint64_t>(data[9]) << 24) |
                         (static_cast<uint64_t>(data[10]) << 16) |
                         (static_cast<uint64_t>(data[11]) << 8) |
                         static_cast<uint64_t>(data[12]);

    if (type == 0xEE) {
        // Ping request - send pong response
        log().debug("Received ping from {}, seq={}", peers_.get_peer_ip_str(src), seq);
        send_pong(src, seq, timestamp);
    } else if (type == 0xEF) {
        // Pong response - calculate latency
        uint64_t now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        uint16_t latency = static_cast<uint16_t>(std::min<uint64_t>(now - timestamp, 65535));

        log().debug("Received pong from {}, seq={}, latency={}ms",
                    peers_.get_peer_ip_str(src), seq, latency);

        // Update peer latency
        state_machine_.update_peer_latency(src, latency);

        // Check if this PONG is for PeerLatencyMeasurer (seq has relay_id encoded in upper 8 bits)
        // PeerLatencyMeasurer uses seq >= 0x01000000, Client::ping_peer() uses smaller values
        if (latency_measurer_ && latency_measurer_->is_running() && (seq & 0xFF000000) != 0) {
            // Forward to PeerLatencyMeasurer
            latency_measurer_->record_pong(src, seq, timestamp);
        } else {
            // Handle for Client::ping_peer()
            uint64_t key = (static_cast<uint64_t>(src) << 32) | seq;
            std::lock_guard lock(ping_mutex_);
            auto it = pending_pings_.find(key);
            if (it != pending_pings_.end()) {
                if (it->second.response_ch) {
                    bool sent = it->second.response_ch->try_send(boost::system::error_code{}, latency);
                    if (!sent) {
                        log().warn("Failed to send ping response for peer {} seq {} (channel closed)", src, seq);
                    }
                }
                // 不在这里 erase，让 ping_peer 在收到响应后清理
            }
        }
    }
}

void Client::send_pong(NodeId peer_id, uint32_t seq_num, uint64_t timestamp) {
    std::vector<uint8_t> pong_msg(13);
    pong_msg[0] = 0xEF;  // pong response
    pong_msg[1] = (seq_num >> 24) & 0xFF;
    pong_msg[2] = (seq_num >> 16) & 0xFF;
    pong_msg[3] = (seq_num >> 8) & 0xFF;
    pong_msg[4] = seq_num & 0xFF;
    pong_msg[5] = (timestamp >> 56) & 0xFF;
    pong_msg[6] = (timestamp >> 48) & 0xFF;
    pong_msg[7] = (timestamp >> 40) & 0xFF;
    pong_msg[8] = (timestamp >> 32) & 0xFF;
    pong_msg[9] = (timestamp >> 24) & 0xFF;
    pong_msg[10] = (timestamp >> 16) & 0xFF;
    pong_msg[11] = (timestamp >> 8) & 0xFF;
    pong_msg[12] = timestamp & 0xFF;

    // 使用 shared_from_this 保证生命周期安全（多线程环境）
    asio::co_spawn(ioc_, [self = shared_from_this(), peer_id, pong_msg = std::move(pong_msg)]() -> asio::awaitable<void> {
        co_await self->relay_->send_data(peer_id, pong_msg);
    }, asio::detached);
}

// ============================================================================
// Subnet Routing
// ============================================================================

asio::awaitable<void> Client::announce_routes(const std::vector<RouteInfo>& routes) {
    if (!control_ || !control_->is_connected()) {
        log().warn("Cannot announce routes: not connected");
        co_return;
    }

    co_await control_->send_route_announce(routes);
}

asio::awaitable<void> Client::withdraw_routes(const std::vector<RouteInfo>& routes) {
    if (!control_ || !control_->is_connected()) {
        log().warn("Cannot withdraw routes: not connected");
        co_return;
    }

    co_await control_->send_route_withdraw(routes);
}

asio::awaitable<void> Client::announce_configured_routes() {
    std::vector<RouteInfo> routes;

    // Read config values with lock
    std::vector<std::string> advertise_routes;
    bool exit_node;
    {
        std::shared_lock lock(config_mutex_);
        advertise_routes = config_.advertise_routes;
        exit_node = config_.exit_node;
    }

    // 解析配置中的路由 (CIDR 格式)
    for (const auto& cidr : advertise_routes) {
        auto slash_pos = cidr.find('/');
        if (slash_pos == std::string::npos) {
            log().warn("Invalid route CIDR format: {}", cidr);
            continue;
        }

        RouteInfo route;
        route.ip_type = IpType::IPv4;
        route.gateway_node = node_id();
        route.metric = 100;
        route.flags = RouteFlags::ENABLED;

        // 解析 IP 地址
        auto ip_str = cidr.substr(0, slash_pos);
        auto ip = IPv4Address::from_string(ip_str);
        std::copy(ip.bytes.begin(), ip.bytes.end(), route.prefix.begin());

        // 解析前缀长度
        try {
            route.prefix_len = static_cast<uint8_t>(std::stoi(cidr.substr(slash_pos + 1)));
        } catch (...) {
            log().warn("Invalid prefix length in route: {}", cidr);
            continue;
        }

        routes.push_back(route);
        log().info("Will announce route: {}", cidr);
    }

    // 如果是出口节点，添加默认路由
    if (exit_node) {
        RouteInfo default_route;
        default_route.ip_type = IpType::IPv4;
        default_route.prefix = {};  // 0.0.0.0
        default_route.prefix_len = 0;  // /0
        default_route.gateway_node = node_id();
        default_route.metric = 100;
        default_route.flags = RouteFlags::ENABLED | RouteFlags::EXIT_NODE;
        routes.push_back(default_route);
        log().info("Will announce exit node route: 0.0.0.0/0");
    }

    if (!routes.empty()) {
        co_await announce_routes(routes);
    }
}

// ============================================================================
// Configuration Hot-Reload Operations
// ============================================================================

void Client::request_reconnect() {
    log().info("Reconnect requested via hot-reload");

    // 在 io_context 中异步执行重连操作
    asio::co_spawn(ioc_, [this, self = shared_from_this()]() -> asio::awaitable<void> {
        // 先停止当前连接
        if (control_) {
            co_await control_->close();
            control_.reset();
        }
        if (relay_) {
            co_await relay_->close();
            relay_.reset();
        }

        state_ = ClientState::RECONNECTING;

        // 重建 SSL 上下文
        request_ssl_context_rebuild();

        // 等待一小段时间后重连
        asio::steady_timer timer(ioc_);
        timer.expires_after(std::chrono::milliseconds(100));
        co_await timer.async_wait(asio::use_awaitable);

        // 重新启动
        co_await start();
    }, asio::detached);
}

void Client::request_tun_rebuild() {
    log().info("TUN device rebuild requested via hot-reload");

    // 在 io_context 中异步执行
    asio::post(ioc_, [this, self = shared_from_this()]() {
        // 先关闭现有的 TUN 设备
        teardown_tun();

        // 如果配置启用了 TUN，重新创建
        if (config_.enable_tun) {
            // Verify client is connected before rebuilding TUN
            if (!control_ || control_->virtual_ip().to_u32() == 0 || !is_running()) {
                log().error("Cannot rebuild TUN: client not properly connected");
                return;
            }

            if (setup_tun()) {
                log().info("TUN device rebuilt successfully");
            } else {
                log().error("Failed to rebuild TUN device");
            }
        } else {
            log().info("TUN device disabled");
        }
    });
}

void Client::request_ipc_restart() {
    log().info("IPC server restart requested via hot-reload");

    // 在 io_context 中异步执行
    asio::post(ioc_, [this, self = shared_from_this()]() {
        // 先停止现有的 IPC 服务器
        teardown_ipc();

        // 如果配置启用了 IPC，重新启动
        if (config_.enable_ipc) {
            if (setup_ipc()) {
                log().info("IPC server restarted successfully");
            } else {
                log().error("Failed to restart IPC server");
            }
        } else {
            log().info("IPC server disabled");
        }
    });
}

void Client::request_route_reannounce() {
    log().info("Route re-announcement requested via hot-reload");

    // 在 io_context 中异步执行
    asio::co_spawn(ioc_, [this, self = shared_from_this()]() -> asio::awaitable<void> {
        if (!control_ || !control_->is_connected()) {
            log().warn("Cannot reannounce routes: not connected");
            co_return;
        }

        // 重新公告配置中的路由
        co_await announce_configured_routes();
        log().info("Routes reannounced successfully");
    }, asio::detached);
}

void Client::request_ssl_context_rebuild() {
    log().info("Rebuilding SSL context with new configuration");

    try {
        // 重新配置 SSL 上下文
        ssl_ctx_.set_default_verify_paths();

        if (config_.ssl_verify) {
            ssl_ctx_.set_verify_mode(ssl::verify_peer);
        } else {
            ssl_ctx_.set_verify_mode(ssl::verify_none);
        }

        if (!config_.ssl_ca_file.empty()) {
            ssl_ctx_.load_verify_file(config_.ssl_ca_file);
        }

        log().info("SSL context rebuilt successfully");
    } catch (const std::exception& e) {
        log().error("Failed to rebuild SSL context: {}", e.what());
    }
}

std::string Client::get_config_value(const std::string& key) const {
    // 根据 key 返回对应的配置值 (read with lock for thread safety)
    std::shared_lock lock(config_mutex_);

    if (key == "controller.url") {
        return config_.current_controller_host();
    } else if (key == "controller.tls") {
        return config_.tls ? "true" : "false";
    } else if (key == "controller.authkey") {
        return "***";  // 不返回实际密钥
    } else if (key == "connection.auto_reconnect") {
        return config_.auto_reconnect ? "true" : "false";
    } else if (key == "connection.reconnect_interval") {
        return std::to_string(config_.reconnect_interval.count());
    } else if (key == "connection.ping_interval") {
        return std::to_string(config_.ping_interval.count());
    } else if (key == "connection.dns_refresh_interval") {
        return std::to_string(config_.dns_refresh_interval.count());
    } else if (key == "connection.latency_measure_interval") {
        return std::to_string(config_.latency_measure_interval.count());
    } else if (key == "ssl.verify") {
        return config_.ssl_verify ? "true" : "false";
    } else if (key == "ssl.ca_file") {
        return config_.ssl_ca_file;
    } else if (key == "ssl.allow_self_signed") {
        return config_.ssl_allow_self_signed ? "true" : "false";
    } else if (key == "storage.state_dir") {
        return config_.state_dir;
    } else if (key == "tun.enable") {
        return config_.enable_tun ? "true" : "false";
    } else if (key == "tun.name") {
        return config_.tun_name;
    } else if (key == "tun.mtu") {
        return std::to_string(config_.tun_mtu);
    } else if (key == "ipc.enable") {
        return config_.enable_ipc ? "true" : "false";
    } else if (key == "ipc.socket_path") {
        return config_.ipc_socket_path;
    } else if (key == "routing.accept_routes") {
        return config_.accept_routes ? "true" : "false";
    } else if (key == "routing.advertise_routes") {
        // 序列化为 JSON 数组
        nlohmann::json arr = config_.advertise_routes;
        return arr.dump();
    } else if (key == "routing.exit_node") {
        return config_.exit_node ? "true" : "false";
    } else if (key == "log.level") {
        return config_.log_level;
    } else if (key == "log.file") {
        return config_.log_file;
    }
    return "";
}

asio::awaitable<void> Client::config_change_handler() {
    while (state_ != ClientState::STOPPED && config_change_ch_) {
        auto [ec, new_config] = co_await config_change_ch_->async_receive(
            asio::as_tuple(asio::use_awaitable));
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                log().debug("Config change channel closed: {}", ec.message());
            }
            break;
        }

        log().info("Configuration file changed, applying changes...");

        if (config_applier_) {
            auto changes = config_applier_->apply(config_, new_config);

            for (const auto& change : changes) {
                if (change.applied) {
                    log().info("Config applied: {} = {}", change.key, change.new_value);
                } else if (!change.message.empty()) {
                    log().info("Config change: {} - {}", change.key, change.message);
                }
            }

            // 更新配置 (with synchronization)
            {
                std::unique_lock lock(config_mutex_);
                config_ = new_config;
            }
        }
    }
}

void Client::enable_config_watch() {
    if (config_path_.empty()) {
        log().warn("Cannot enable config watch: config path not set");
        return;
    }

    if (config_watcher_) {
        log().debug("Config watcher already enabled");
        return;
    }

    // 创建配置变更 channel
    config_change_ch_ = std::make_unique<channels::ConfigChangeChannel>(ioc_, 4);

    config_watcher_ = std::make_unique<ConfigWatcher>(ioc_, config_path_);
    config_watcher_->set_channel(config_change_ch_.get());
    config_watcher_->start();

    // 启动配置变更处理协程
    asio::co_spawn(ioc_, config_change_handler(), asio::detached);

    log().info("Config file watching enabled: {}", config_path_);
}

void Client::disable_config_watch() {
    if (config_watcher_) {
        config_watcher_->stop();
        config_watcher_.reset();
    }
    if (config_change_ch_) {
        config_change_ch_->close();
        config_change_ch_.reset();
    }
    log().info("Config file watching disabled");
}

void Client::clear_system_routes() {
    if (route_mgr_) {
        log().info("Clearing all system routes");
        route_mgr_->cleanup_all();
    }
}

void Client::setup_state_machine() {
    // 配置状态机超时参数（直接使用 chrono 类型，自动转换）
    state_machine_.set_punch_timeout(std::chrono::duration_cast<std::chrono::milliseconds>(config_.p2p.punch_timeout));
    state_machine_.set_keepalive_timeout(std::chrono::duration_cast<std::chrono::milliseconds>(config_.p2p.keepalive_timeout));
    state_machine_.set_retry_interval(std::chrono::duration_cast<std::chrono::milliseconds>(config_.p2p.retry_interval));

    // 注意：状态变化现在通过 channel 通知，在 p2p_state_handler() 中处理
    // ClientState 的同步在回调中手动处理
}

} // namespace edgelink::client

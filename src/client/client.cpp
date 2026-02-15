#include "client/client.hpp"
#include "common/cobalt_utils.hpp"
#include "common/logger.hpp"
#include <future>
#include <unordered_set>

namespace edgelink::client {

namespace cobalt = boost::cobalt;

namespace {
    auto& log() { return Logger::get("client"); }

    // Hash function for RouteInfo (used in route update optimization)
    struct RouteInfoHash {
        std::size_t operator()(const RouteInfo& route) const noexcept {
            std::size_t h = 0;

            // Hash ip_type
            h ^= std::hash<uint8_t>{}(static_cast<uint8_t>(route.ip_type));

            // Hash prefix bytes (only up to prefix_len/8 bytes are significant)
            size_t prefix_bytes = (route.prefix_len + 7) / 8;
            for (size_t i = 0; i < prefix_bytes && i < route.prefix.size(); ++i) {
                h ^= std::hash<uint8_t>{}(route.prefix[i]) << (i % 8);
            }

            // Hash prefix_len
            h ^= std::hash<uint8_t>{}(route.prefix_len) << 16;

            // Hash gateway_node
            h ^= std::hash<NodeId>{}(route.gateway_node) << 24;

            return h;
        }
    };

    // Equality comparator for RouteInfo (used with RouteInfoHash)
    struct RouteInfoEqual {
        bool operator()(const RouteInfo& a, const RouteInfo& b) const noexcept {
            return a.ip_type == b.ip_type &&
                   a.prefix == b.prefix &&
                   a.prefix_len == b.prefix_len &&
                   a.gateway_node == b.gateway_node;
        }
    };
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
    peer_state_channel_ = std::make_unique<edgelink::channels::PeerStateChannel>(64, ioc.get_executor());
    state_machine_.set_peer_state_channel(peer_state_channel_.get());

    // P2P event channel is created in setup_channels() and set there

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
    handlers_done_ch_ = std::make_unique<HandlerCompletionChannel>(32, ioc_.get_executor());
    active_handlers_ = 0;

    // 创建 3 个统一事件 channels
    ctrl_events_ = std::make_unique<events::CtrlEventChannel>(32, ioc_.get_executor());
    relay_events_ = std::make_unique<events::RelayEventChannel>(64, ioc_.get_executor());
    p2p_events_ = std::make_unique<events::P2PEventChannel>(64, ioc_.get_executor());

    // 设置 ControlChannel 和 RelayChannel 的事件 channel
    control_->set_event_channel(ctrl_events_.get());
    relay_->set_event_channel(relay_events_.get());

    // 设置 P2PManager 的事件 channel
    if (p2p_mgr_) {
        p2p_mgr_->set_event_channel(p2p_events_.get());
    }

    // 启动 3 个事件循环协程 (replace 12 individual handlers)
    active_handlers_ += 3;
    cobalt_utils::spawn_task(ioc_.get_executor(), ctrl_event_loop());
    cobalt_utils::spawn_task(ioc_.get_executor(), relay_event_loop());
    cobalt_utils::spawn_task(ioc_.get_executor(), p2p_event_loop());
}

// ============================================================================
// Unified event loop coroutines
// ============================================================================

cobalt::task<void> Client::ctrl_event_loop() {
    co_await cobalt_utils::consume_channel(*ctrl_events_,
        [this](events::ctrl::Event event) -> cobalt::task<void> {
            co_await std::visit(overloaded{
                [this](events::ctrl::Connected& e) -> cobalt::task<void> {
                    log().info("Authenticated: node_id={}, ip={}", e.node_id, e.virtual_ip.to_string());
                    state_machine_.set_node_id(crypto_.node_id());
                    state_machine_.set_control_plane_state(ControlPlaneState::CONFIGURING);
                    co_return;
                },

                [this](events::ctrl::ConfigReceived& e) -> cobalt::task<void> {
                    auto& config = e.config;

                    // Controller 重连后：
                    // 1. 重置 FAILED 状态的 peer，让它们可以重新尝试打洞
                    // 2. 保持 CONNECTED 状态的 P2P 连接继续工作
                    // 3. 端点信息会在下面重新上报给 Controller
                    state_machine_.reset_all_peer_p2p_states();
                    if (p2p_mgr_) {
                        p2p_mgr_->clear_all_contexts();
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
                        relay_config.max_connections_per_relay = 2;
                        relay_config.rtt_measure_interval = std::chrono::seconds(10);

                        multi_relay_mgr_ = std::make_shared<MultiRelayManager>(
                            ioc_, ssl_ctx_, crypto_, peers_, relay_config);

                        log().debug("MultiRelayManager created with {} relays", config.relays.size());

                        auto self = shared_from_this();
                        auto relay_mgr = multi_relay_mgr_;
                        bool use_tls = [&]() {
                            std::shared_lock lock(config_mutex_);
                            return config_.tls;
                        }();

                        std::string controller_hostname;
                        if (control_) {
                            std::string url = control_->url();
                            size_t start = url.find("://");
                            if (start != std::string::npos) {
                                start += 3;
                                size_t end = url.find('/', start);
                                if (end != std::string::npos) {
                                    controller_hostname = url.substr(start, end - start);
                                } else {
                                    controller_hostname = url.substr(start);
                                }
                            }
                        }

                        cobalt_utils::spawn_task(ioc_.get_executor(), [self, relay_mgr, relays = config.relays, relay_token = config.relay_token, use_tls, controller_hostname]() -> cobalt::task<void> {
                            try {
                                co_await relay_mgr->initialize(relays, relay_token, use_tls, controller_hostname);
                                log().debug("MultiRelayManager initialization complete");

                                if (self->multi_relay_mgr_ && !self->latency_measurer_) {
                                    LatencyMeasureConfig latency_config;
                                    latency_config.measure_interval = std::chrono::seconds(30);
                                    latency_config.report_interval = std::chrono::seconds(60);

                                    self->latency_measurer_ = std::make_shared<PeerLatencyMeasurer>(
                                        self->ioc_, *relay_mgr, self->peers_, latency_config);

                                    co_await self->latency_measurer_->start();
                                    log().info("PeerLatencyMeasurer started successfully");
                                }

                                if (self->multi_relay_mgr_ && !self->relay_latency_reporter_) {
                                    RelayLatencyReporterConfig reporter_config;
                                    reporter_config.report_interval = std::chrono::seconds(30);
                                    reporter_config.initial_delay = std::chrono::seconds(5);

                                    self->relay_latency_reporter_ = std::make_shared<RelayLatencyReporter>(
                                        self->ioc_, *relay_mgr, reporter_config);

                                    self->relay_latency_reporter_->set_report_callback(
                                        [weak_self = std::weak_ptr<Client>(self->shared_from_this())](const RelayLatencyReport& report) {
                                            if (auto client = weak_self.lock()) {
                                                if (client->control_ && client->control_->is_connected()) {
                                                    cobalt_utils::spawn_task(client->ioc_.get_executor(),
                                                        client->control_->send_relay_latency_report(report));
                                                }
                                            }
                                        });

                                    co_await self->relay_latency_reporter_->start();
                                    log().info("RelayLatencyReporter started successfully");
                                }
                            } catch (const std::exception& e) {
                                log().error("Failed to start multi-relay system: {}", e.what());
                            }
                        }());
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

                            std::string use_exit_node_config = [&]() {
                                std::shared_lock lock(config_mutex_);
                                return config_.use_exit_node;
                            }();

                            if (!use_exit_node_config.empty()) {
                                const PeerInfo* exit_peer = nullptr;
                                for (const auto& peer : config.peers) {
                                    if (!peer.exit_node) continue;
                                    if (!peer.online) continue;
                                    if (peer.name == use_exit_node_config ||
                                        std::to_string(peer.node_id) == use_exit_node_config) {
                                        exit_peer = &peer;
                                        break;
                                    }
                                }

                                if (exit_peer) {
                                    RouteInfo default_route;
                                    default_route.ip_type = IpType::IPv4;
                                    default_route.prefix_len = 0;
                                    default_route.gateway_node = exit_peer->node_id;
                                    default_route.metric = 100;

                                    route_mgr_->apply_route_update({default_route}, {});
                                    current_exit_node_id_ = exit_peer->node_id;
                                    log().info("Added default route via exit node {} ({})",
                                               exit_peer->name, exit_peer->virtual_ip.to_string());
                                } else {
                                    current_exit_node_id_ = 0;
                                    log().warn("Exit node '{}' not found or offline", use_exit_node_config);
                                }
                            }
                        }
                    }

                    // 启动 P2P manager（如果尚未运行）
                    if (p2p_mgr_ && !p2p_mgr_->is_running()) {
                        try {
                            co_await p2p_mgr_->start();
                            log().info("P2P manager started (STUN configured)");
                        } catch (const std::exception& e) {
                            log().error("P2P manager failed to start: {}", e.what());
                        }
                    }

                    // 重新发送端点
                    std::vector<Endpoint> endpoints;
                    {
                        std::lock_guard lock(endpoints_mutex_);
                        if (!last_reported_endpoints_.empty()) {
                            endpoints = last_reported_endpoints_;
                        }
                    }

                    if (!endpoints.empty() && control_ && control_->is_connected()) {
                        co_await control_->send_endpoint_update(endpoints);
                        log().info("Resent {} endpoints to controller", endpoints.size());
                    }
                },

                [this](events::ctrl::ConfigUpdateReceived& e) -> cobalt::task<void> {
                    auto& update = e.update;

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

                            if (route_mgr_ && current_exit_node_id_ == peer_id) {
                                RouteInfo default_route;
                                default_route.ip_type = IpType::IPv4;
                                default_route.prefix_len = 0;
                                default_route.gateway_node = peer_id;
                                default_route.metric = 100;

                                route_mgr_->apply_route_update({}, {default_route});
                                current_exit_node_id_ = 0;
                                log().warn("Exit node (peer_id={}) went offline, removed default route",
                                           peer_id);
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

                            std::string use_exit_node_config = [&]() {
                                std::shared_lock lock(config_mutex_);
                                return config_.use_exit_node;
                            }();

                            if (!use_exit_node_config.empty() && current_exit_node_id_ == 0) {
                                for (const auto& peer : update.add_peers) {
                                    if (!peer.exit_node || !peer.online) continue;
                                    if (peer.name == use_exit_node_config ||
                                        std::to_string(peer.node_id) == use_exit_node_config) {
                                        RouteInfo default_route;
                                        default_route.ip_type = IpType::IPv4;
                                        default_route.prefix_len = 0;
                                        default_route.gateway_node = peer.node_id;
                                        default_route.metric = 100;

                                        route_mgr_->apply_route_update({default_route}, {});
                                        current_exit_node_id_ = peer.node_id;
                                        log().info("Exit node '{}' came online, added default route",
                                                   peer.name);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    co_return;
                },

                [this](events::ctrl::RouteUpdateReceived& e) -> cobalt::task<void> {
                    auto& update = e.route_update;

                    log().info("Route update v{}: +{} routes, -{} routes",
                               update.version, update.add_routes.size(), update.del_routes.size());

                    std::vector<RouteInfo> updated_routes;
                    {
                        std::lock_guard lock(routes_mutex_);
                        updated_routes = routes_;
                    }

                    if (!update.del_routes.empty()) {
                        std::unordered_set<RouteInfo, RouteInfoHash, RouteInfoEqual> delete_set(
                            update.del_routes.begin(), update.del_routes.end());

                        updated_routes.erase(
                            std::remove_if(updated_routes.begin(), updated_routes.end(),
                                [&delete_set](const RouteInfo& r) {
                                    return delete_set.find(r) != delete_set.end();
                                }),
                            updated_routes.end());

                        for (const auto& route : update.del_routes) {
                            log().trace("  - route /{} via node {}", route.prefix_len, route.gateway_node);
                        }
                    }

                    for (const auto& route : update.add_routes) {
                        auto it = std::find_if(updated_routes.begin(), updated_routes.end(),
                            [&route](const RouteInfo& r) {
                                return r.ip_type == route.ip_type &&
                                       r.prefix == route.prefix &&
                                       r.prefix_len == route.prefix_len &&
                                       r.gateway_node == route.gateway_node;
                            });

                        if (it != updated_routes.end()) {
                            *it = route;
                        } else {
                            updated_routes.push_back(route);
                        }
                        log().trace("  + route /{} via node {}", route.prefix_len, route.gateway_node);
                    }

                    {
                        std::lock_guard lock(routes_mutex_);
                        routes_ = std::move(updated_routes);
                    }

                    if (route_mgr_) {
                        route_mgr_->apply_route_update(update.add_routes, update.del_routes);
                    }
                    co_return;
                },

                [this](events::ctrl::PeerRoutingUpdateReceived& e) -> cobalt::task<void> {
                    log().info("Peer routing update v{} with {} routes",
                               e.update.version, e.update.routes.size());
                    if (multi_relay_mgr_) {
                        multi_relay_mgr_->handle_peer_routing_update(e.update);
                    }
                    co_return;
                },

                [this](events::ctrl::P2PEndpointReceived& e) -> cobalt::task<void> {
                    if (p2p_mgr_) {
                        p2p_mgr_->handle_p2p_endpoint(e.endpoint);
                    }
                    co_return;
                },

                [this](events::ctrl::Error& e) -> cobalt::task<void> {
                    log().error("Control error {}: {}", e.code, e.message);
                    if (events_.error) {
                        co_await cobalt::as_tuple(events_.error->write(
                            ClientErrorEvent{e.code, std::move(e.message)}));
                    }
                    co_return;
                },

                [this](events::ctrl::Disconnected& e) -> cobalt::task<void> {
                    log().warn("Control channel disconnected: {}", e.reason);
                    state_machine_.set_control_plane_state(ControlPlaneState::DISCONNECTED);

                    bool auto_reconnect = [&]() {
                        std::shared_lock lock(config_mutex_);
                        return config_.auto_reconnect;
                    }();

                    if (auto_reconnect && state_ != ClientState::STOPPED &&
                        state_ != ClientState::RECONNECTING) {
                        cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
                    }
                    co_return;
                },
            }, event);
        });

    // Notify handler completion
    if (handlers_done_ch_) {
        co_await cobalt::as_tuple(handlers_done_ch_->write());
    }
    active_handlers_--;
}

// ============================================================================
// Relay event loop
// ============================================================================

cobalt::task<void> Client::relay_event_loop() {
    co_await cobalt_utils::consume_channel(*relay_events_,
        [this](events::relay::Event event) -> cobalt::task<void> {
            co_await std::visit(overloaded{
                [this](events::relay::Connected&) -> cobalt::task<void> {
                    log().info("Relay channel connected");

                    std::string relay_id = relay_ ? relay_->url() : "default";
                    state_machine_.add_relay(relay_id, true);
                    state_machine_.set_relay_state(relay_id, RelayConnectionState::CONNECTED);

                    state_ = ClientState::RUNNING;

                    if (events_.connected) {
                        co_await cobalt::as_tuple(events_.connected->write());
                    }

                    // Start keepalive
                    edgelink::cobalt_utils::spawn_task(ioc_.get_executor(), keepalive_loop());

                    // Start peer state handler
                    if (peer_state_channel_) {
                        cobalt_utils::spawn_task(ioc_.get_executor(), p2p_state_handler());
                    }

                    // Start DNS refresh loop
                    edgelink::cobalt_utils::spawn_task(ioc_.get_executor(), dns_refresh_loop());

                    // Start latency measurement loop
                    {
                        std::shared_lock lock(config_mutex_);
                        if (config_.latency_measure_interval.count() > 0) {
                            cobalt_utils::spawn_task(ioc_.get_executor(), latency_measure_loop());
                        }
                    }

                    // Announce configured routes
                    {
                        std::shared_lock lock(config_mutex_);
                        if (!config_.advertise_routes.empty() || config_.exit_node) {
                            cobalt_utils::spawn_task(ioc_.get_executor(), announce_configured_routes());

                            if (config_.route_announce_interval.count() > 0) {
                                cobalt_utils::spawn_task(ioc_.get_executor(), route_announce_loop());
                            }
                        }
                    }
                    co_return;
                },

                [this](events::relay::Disconnected& e) -> cobalt::task<void> {
                    log().warn("Relay channel disconnected: {}", e.reason);

                    std::string relay_id = relay_ ? relay_->url() : "default";
                    state_machine_.set_relay_state(relay_id, RelayConnectionState::DISCONNECTED);

                    bool auto_reconnect = [&]() {
                        std::shared_lock lock(config_mutex_);
                        return config_.auto_reconnect;
                    }();

                    if (auto_reconnect && state_ != ClientState::STOPPED &&
                        state_ != ClientState::RECONNECTING) {
                        cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
                    }
                    co_return;
                },

                [this](events::relay::DataReceived& e) -> cobalt::task<void> {
                    auto src_peer_ip = peers_.get_peer_ip_str(e.src_node);
                    log().trace("Received {} bytes from {}", e.plaintext.size(), src_peer_ip);

                    // Check for internal ping/pong messages
                    if (e.plaintext.size() >= 13 && (e.plaintext[0] == 0xEE || e.plaintext[0] == 0xEF)) {
                        handle_ping_data(e.src_node, e.plaintext);
                        co_return;
                    }

                    // If TUN mode is enabled, write IP packets to TUN device
                    if (is_tun_enabled() && ip_packet::version(e.plaintext) == 4) {
                        auto src_ip = ip_packet::src_ipv4(e.plaintext);
                        auto dst_ip = ip_packet::dst_ipv4(e.plaintext);
                        log().trace("Writing to TUN: {} -> {} ({} bytes)",
                                      src_ip.to_string(), dst_ip.to_string(), e.plaintext.size());

                        auto result = tun_->write(e.plaintext);
                        if (!result) {
                            log().warn("Failed to write to TUN: {}", tun_error_message(result.error()));
                        }
                    }

                    // Call user callback via channel
                    if (events_.data_received) {
                        co_await cobalt::as_tuple(events_.data_received->write(
                            ClientDataEvent{e.src_node, std::move(e.plaintext)}));
                    }
                    co_return;
                },

                [this](events::relay::Pong& e) -> cobalt::task<void> {
                    // Relay pong - RTT already calculated by RelayChannel
                    log().trace("Relay pong: RTT={}ms", e.rtt_ms);
                    co_return;
                },
            }, event);
        });

    // Notify handler completion
    if (handlers_done_ch_) {
        co_await cobalt::as_tuple(handlers_done_ch_->write());
    }
    active_handlers_--;
}

// ============================================================================
// P2P event loop
// ============================================================================

cobalt::task<void> Client::p2p_event_loop() {
    co_await cobalt_utils::consume_channel(*p2p_events_,
        [this](events::p2p::Event event) -> cobalt::task<void> {
            co_await std::visit(overloaded{
                [this](events::p2p::EndpointsReady& e) -> cobalt::task<void> {
                    // 保存端点（用于重连后重发）
                    {
                        std::lock_guard lock(endpoints_mutex_);
                        last_reported_endpoints_ = e.endpoints;
                    }

                    // 上报端点给 Controller
                    if (control_ && control_->is_connected()) {
                        log().debug("Sending endpoint update: {} endpoints", e.endpoints.size());
                        co_await control_->send_endpoint_update(e.endpoints);
                    }
                },

                [this](events::p2p::InitNeeded& e) -> cobalt::task<void> {
                    // 通过 Control Channel 发送 P2P_INIT
                    if (control_ && control_->is_connected()) {
                        co_await control_->send_p2p_init(e.init);
                    }
                },

                [this](events::p2p::StatusChanged& e) -> cobalt::task<void> {
                    // 通过 Control Channel 发送 P2P_STATUS
                    if (control_ && control_->is_connected()) {
                        co_await control_->send_p2p_status(e.status);
                    }
                },

                [this](events::p2p::DataReceived& e) -> cobalt::task<void> {
                    log().trace("P2P data received: {} bytes from {}",
                                e.plaintext.size(), peers_.get_peer_ip_str(e.peer_id));

                    // Check for internal ping/pong messages
                    if (e.plaintext.size() >= 13 && (e.plaintext[0] == 0xEE || e.plaintext[0] == 0xEF)) {
                        handle_ping_data(e.peer_id, e.plaintext);
                        co_return;
                    }

                    // If TUN mode is enabled, write IP packets to TUN device
                    if (is_tun_enabled() && ip_packet::version(e.plaintext) == 4) {
                        auto result = tun_->write(e.plaintext);
                        if (!result) {
                            log().warn("Failed to write to TUN: {}", tun_error_message(result.error()));
                        }
                    }

                    // Call user callback via channel
                    if (events_.data_received) {
                        co_await cobalt::as_tuple(events_.data_received->write(
                            ClientDataEvent{e.peer_id, std::move(e.plaintext)}));
                    }
                    co_return;
                },
            }, event);
        });

    // Notify handler completion
    if (handlers_done_ch_) {
        co_await cobalt::as_tuple(handlers_done_ch_->write());
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
    tun_packet_ch_ = std::make_unique<channels::TunPacketChannel>(64, ioc_.get_executor());
    tun_handler_done_ch_ = std::make_unique<TunHandlerCompletionChannel>(1, ioc_.get_executor());
    tun_->set_packet_channel(tun_packet_ch_.get());
    tun_->start_read();

    // Start packet handler coroutine
    edgelink::cobalt_utils::spawn_task(ioc_.get_executor(), tun_packet_handler());

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

cobalt::task<void> Client::tun_packet_handler() {
    log().debug("TUN packet handler started");

    while (state_ != ClientState::STOPPED && tun_packet_ch_) {
        auto packet = co_await tun_packet_ch_->read();
        if (!packet) {
            log().debug("TUN packet channel closed");
            break;
        }
        // 处理接收到的 TUN 数据包
        on_tun_packet(std::span<const uint8_t>(*packet));
    }

    // Notify teardown_tun() that handler has exited
    if (tun_handler_done_ch_) {
        co_await cobalt::as_tuple(tun_handler_done_ch_->write());
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

    log().trace("TUN packet: {} -> {} ({} bytes)",
                  src_ip.to_string(), dst_ip.to_string(), packet.size());

    // Find peer by destination IP
    auto peer = peers_.get_peer_by_ip(dst_ip);
    if (!peer) {
        log().warn("TUN packet to unknown IP {}, dropping (known peers: {})",
                     dst_ip.to_string(), peers_.peer_count());
        return;
    }

    log().trace("Forwarding to {} ({})", peer->info.virtual_ip.to_string(),
                  peer->info.online ? "online" : "offline");

    // Send via relay - 使用 shared_from_this 保证生命周期安全（多线程环境）
    cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this(), peer_id = peer->info.node_id,
                          data = std::vector<uint8_t>(packet.begin(), packet.end())]()
                          -> cobalt::task<void> {
        co_await self->send_to_peer(peer_id, data);
    }());
}

cobalt::task<bool> Client::start() {
    if (state_ != ClientState::STOPPED) {
        log().warn("Client already started");
        co_return false;
    }

    state_ = ClientState::STARTING;
    log().info("Starting client...");

    // Copy config values once under lock to avoid data races with hot-reload
    std::string state_dir;
    std::string authkey;
    std::string controller_url;
    bool tls;
    {
        std::shared_lock lock(config_mutex_);
        state_dir = config_.state_dir.empty() ? "." : config_.state_dir;
        authkey = config_.authkey;
        controller_url = config_.controller_url.empty() ? "edge.a-z.xin" : config_.controller_url;
        tls = config_.tls;
    }

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

    log().info("TLS: {}", tls ? "enabled" : "disabled");

    // 解析 controller URL (格式: host 或 host:port)
    auto [host, port] = ClientConfig::parse_host_port(controller_url, tls);

    // 构建完整 URL
    std::string scheme = tls ? "wss://" : "ws://";
    std::string base_url = scheme + host + ":" + std::to_string(port);
    std::string control_url = base_url + "/api/v1/control";
    std::string relay_url = base_url + "/api/v1/relay";

    log().debug("Control URL: {}", control_url);
    log().debug("Relay URL: {}", relay_url);

    // Create channels
    control_ = std::make_shared<ControlChannel>(ioc_, ssl_ctx_, crypto_, control_url, tls);
    relay_ = std::make_shared<RelayChannel>(ioc_, ssl_ctx_, crypto_, peers_, relay_url, tls);

    // Set exit node capability
    {
        std::shared_lock lock(config_mutex_);
        control_->set_exit_node(config_.exit_node);
    }

    // Setup event channels
    setup_channels();

    // Connect to control channel
    state_ = ClientState::AUTHENTICATING;
    state_machine_.set_control_plane_state(ControlPlaneState::CONNECTING);
    log().info("Connecting to controller...");

    bool connected = co_await control_->connect(authkey);
    if (!connected) {
        log().warn("Failed to connect to controller {}:{}", host, port);
        if (config_.auto_reconnect) {
            log().info("Will retry in {}s...", config_.reconnect_interval.count());
            state_ = ClientState::STOPPED;
            cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
        } else {
            state_ = ClientState::STOPPED;
        }
        co_return false;
    }

    // Wait for auth response (30s timeout for high-latency networks)
    // 使用轮询方式避免 parallel_group 导致的 TLS allocator 崩溃
    asio::steady_timer timer(ioc_);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);

    while (!control_->is_connected()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            log().warn("Authentication timeout (30s) for {}:{}", host, port);
            break;
        }
        timer.expires_after(std::chrono::milliseconds(100));
        co_await timer.async_wait(cobalt::use_op);
    }

    if (!control_->is_connected()) {
        log().error("Failed to authenticate with controller");
        try {
            co_await control_->close();
        } catch (...) {}
        control_.reset();
        relay_.reset();
        if (config_.auto_reconnect) {
            log().info("Will retry in {}s...", config_.reconnect_interval.count());
            state_ = ClientState::STOPPED;
            cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
        } else {
            state_ = ClientState::STOPPED;
        }
        co_return false;
    }

    // Connect to relay channel (asynchronously, don't block startup)
    // Note: relay_ is kept as a fallback channel. Multi-relay system provides primary connectivity.
    state_ = ClientState::CONNECTING_RELAY;
    log().debug("Connecting to legacy relay (async)...");

    // Start relay connection in background (non-blocking)
    auto self = shared_from_this();
    cobalt_utils::spawn_task(ioc_.get_executor(), [self, relay_token = control_->relay_token()]() -> cobalt::task<void> {
        try {
            bool connected = co_await self->relay_->connect(relay_token);
            if (connected) {
                // Wait for authentication with timeout
                // 使用轮询方式避免 parallel_group 导致的 TLS allocator 崩溃
                asio::steady_timer timer(self->ioc_);
                auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);

                while (!self->relay_->is_connected()) {
                    if (std::chrono::steady_clock::now() >= deadline) {
                        log().warn("Relay authentication timeout (30s)");
                        break;
                    }
                    timer.expires_after(std::chrono::milliseconds(100));
                    co_await timer.async_wait(cobalt::use_op);
                }

                if (self->relay_->is_connected()) {
                    log().info("Legacy relay channel connected successfully (fallback channel)");
                } else {
                    log().warn("Legacy relay authentication failed (using multi-relay only)");
                }
            } else {
                log().warn("Legacy relay connection failed (using multi-relay only)");
            }
        } catch (const std::exception& e) {
            log().warn("Legacy relay connection error: {} (using multi-relay only)", e.what());
        }
    }());

    // Don't wait for relay - multi-relay system will provide connectivity
    log().info("Connected to controller: {}:{}", host, port);

    // Setup TUN device if enabled
    if (config_.enable_tun) {
        // Verify dependencies are met
        if (!control_ || control_->virtual_ip().to_u32() == 0) {
            log().error("Cannot setup TUN: control channel or virtual IP not available (initialization order violation)");
            state_ = ClientState::STOPPED;
            co_return false;
        }

        if (!setup_tun()) {
            log().warn("TUN mode requested but failed to setup TUN device (likely OS/permission issue)");
            // Soft failure - continue without TUN
        }
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

cobalt::task<void> Client::stop() {
    log().info("Stopping client...");

    // CRITICAL: Set stopped state FIRST to signal all handlers to exit their while loops
    state_ = ClientState::STOPPED;
    log().debug("State set to STOPPED, handlers will exit their loops");

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
        config_watcher_->stop();
        config_watcher_.reset();
        log().debug("Config watcher stopped");
    }

    // Stop latency measurer first (depends on multi_relay_mgr_)
    if (latency_measurer_) {
        co_await latency_measurer_->stop();
        latency_measurer_.reset();
        log().debug("Latency measurer stopped");
    }

    // Stop relay latency reporter (depends on multi_relay_mgr_)
    if (relay_latency_reporter_) {
        co_await relay_latency_reporter_->stop();
        relay_latency_reporter_.reset();
        log().debug("Relay latency reporter stopped");
    }

    // Stop multi-relay manager (has background RTT measurement loop)
    if (multi_relay_mgr_) {
        co_await multi_relay_mgr_->stop();
        multi_relay_mgr_.reset();
        log().debug("Multi-relay manager stopped");
    }

    // Stop P2P manager (with timeout to avoid hanging)
    if (p2p_mgr_) {
        log().debug("Stopping P2P manager...");
        try {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool stop_completed = false;
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, &stop_completed]() -> cobalt::task<void> {
                co_await p2p_mgr_->stop();
                stop_completed = true;
            }());

            asio::steady_timer timeout_timer(ioc_);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);

            while (!stop_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            if (stop_completed) {
                log().debug("P2P manager stopped successfully");
            } else {
                log().warn("P2P manager stop timeout (3s), forcing shutdown");
            }
        } catch (const std::exception& e) {
            log().warn("Error stopping P2P manager: {}", e.what());
        } catch (...) {
            log().warn("Unknown error stopping P2P manager");
        }
    }

    // Stop route manager first (removes routes from system)
    if (route_mgr_) {
        route_mgr_->stop();
        route_mgr_.reset();
        log().debug("Route manager stopped");
    }

    // Teardown TUN (with timeout to avoid hanging)
    // Wait for TUN packet handler to exit before tearing down
    if (tun_packet_ch_ && tun_handler_done_ch_) {
        tun_packet_ch_->close();
        try {
            auto read_tun_done = [this]() -> cobalt::task<void> {
                auto [ec] = co_await cobalt::as_tuple(tun_handler_done_ch_->read());
                (void)ec;
            };
            asio::steady_timer tun_timeout_timer(co_await cobalt::this_coro::executor, std::chrono::seconds(2));
            co_await cobalt::race(read_tun_done(), tun_timeout_timer.async_wait(cobalt::use_op));
            log().debug("TUN packet handler confirmed stopped");
        } catch (const std::exception& e) {
            log().warn("Error waiting for TUN packet handler: {}", e.what());
        } catch (...) {
            log().warn("Unknown error waiting for TUN packet handler");
        }
    }

    teardown_tun();
    log().debug("TUN device torn down");

    // Close all event channels to wake up waiting handlers
    if (ctrl_events_) ctrl_events_->close();
    if (relay_events_) relay_events_->close();
    if (p2p_events_) p2p_events_->close();

    // Wait for all handlers to exit (with timeout to avoid hanging)
    int expected_handlers = active_handlers_.load();
    log().debug("Waiting for {} handler(s) to exit...", expected_handlers);

    try {
        auto read_all_handlers = [this, expected_handlers]() -> cobalt::task<void> {
            for (int i = 0; i < expected_handlers; ++i) {
                auto [ec] = co_await cobalt::as_tuple(handlers_done_ch_->read());
                if (ec) break;
            }
        };
        asio::steady_timer handlers_timeout_timer(co_await cobalt::this_coro::executor, std::chrono::seconds(5));
        co_await cobalt::race(read_all_handlers(), handlers_timeout_timer.async_wait(cobalt::use_op));
    } catch (...) {}

    int remaining = active_handlers_.load();
    if (remaining > 0) {
        log().warn("{} of {} handler(s) did not exit cleanly", remaining, expected_handlers);
    } else {
        log().debug("All {} handlers exited successfully", expected_handlers);
    }

    // Close relay channel (with timeout)
    if (relay_) {
        try {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool close_completed = false;
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, &close_completed]() -> cobalt::task<void> {
                co_await relay_->close();
                close_completed = true;
            }());

            asio::steady_timer timeout_timer(ioc_);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);

            while (!close_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            if (close_completed) {
                log().debug("Relay channel closed successfully");
            } else {
                log().warn("Relay channel close timeout (2s)");
            }
        } catch (const std::exception& e) {
            log().warn("Error closing relay channel: {}", e.what());
        } catch (...) {
            log().warn("Unknown error closing relay channel");
        }
    }

    // Close control channel (with timeout)
    if (control_) {
        try {
            // 使用手动超时检查避免 parallel_group 导致的 TLS allocator 崩溃
            bool close_completed = false;
            cobalt_utils::spawn_task(ioc_.get_executor(), [this, &close_completed]() -> cobalt::task<void> {
                co_await control_->close();
                close_completed = true;
            }());

            asio::steady_timer timeout_timer(ioc_);
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);

            while (!close_completed && std::chrono::steady_clock::now() < deadline) {
                timeout_timer.expires_after(std::chrono::milliseconds(50));
                co_await timeout_timer.async_wait(cobalt::use_op);
            }

            if (close_completed) {
                log().debug("Control channel closed successfully");
            } else {
                log().warn("Control channel close timeout (2s)");
            }
        } catch (const std::exception& e) {
            log().warn("Error closing control channel: {}", e.what());
        } catch (...) {
            log().warn("Unknown error closing control channel");
        }
    }

    // Reset state machine to clear peer_connections before destruction
    // This prevents potential crashes if any dangling references exist
    state_machine_.reset();

    log().info("Client stopped successfully");

    if (events_.disconnected) {
        auto [ec_disc] = co_await cobalt::as_tuple(events_.disconnected->write());
        if (ec_disc) {
            log().debug("Failed to send disconnected event (channel closed)");
        }
    }
}

cobalt::task<bool> Client::send_to_peer(NodeId peer_id, std::span<const uint8_t> data) {
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
            cobalt_utils::spawn_task(ioc_.get_executor(), p2p_mgr_->connect_peer(peer_id));
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

cobalt::task<bool> Client::send_to_ip(const IPv4Address& ip, std::span<const uint8_t> data) {
    auto peer = peers_.get_peer_by_ip(ip);
    if (!peer) {
        log().warn("Cannot send: no peer with IP {}", ip.to_string());
        co_return false;
    }

    co_return co_await send_to_peer(peer->info.node_id, data);
}

cobalt::task<bool> Client::send_ip_packet(std::span<const uint8_t> packet) {
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

cobalt::task<void> Client::p2p_state_handler() {
    log().debug("Peer state handler started");

    while (state_ != ClientState::STOPPED) {
        try {
            // 从 channel 接收状态变化
            auto [ec, event] = co_await cobalt::as_tuple(peer_state_channel_->read());

            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    log().debug("Peer state channel error: {}", ec.message());
                }
                break;
            }

            log().info("Peer state changed: peer={}, p2p={}, path={}",
                       peers_.get_peer_ip_str(event.node_id),
                       p2p_connection_state_name(event.p2p_state),
                       peer_data_path_name(event.data_path));

            // 状态变化已在 ClientStateMachine 中处理，这里只做日志和可能的额外处理

        } catch (const std::exception& e) {
            log().warn("Peer state handler exception: {}", e.what());
            break;
        }
    }

    log().debug("Peer state handler stopped");
    co_return;
}

cobalt::task<void> Client::keepalive_loop() {
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.ping_interval;
    }();

    log().debug("Keepalive loop started");

    while (state_ == ClientState::RUNNING) {
        try {
            keepalive_timer_.expires_after(interval);
            // Update interval in case config changed
            {
                std::shared_lock lock(config_mutex_);
                interval = config_.ping_interval;
            }
            auto [ec] = co_await keepalive_timer_.async_wait(
                asio::as_tuple(cobalt::use_op));

            if (ec == asio::error::operation_aborted) {
                break;  // Timer cancelled, exit gracefully
            }

            if (control_ && control_->is_connected()) {
                cobalt_utils::spawn_task(ioc_.get_executor(), control_->send_ping());
                log().trace("Keepalive sent");
            }
        } catch (const std::exception& e) {
            log().error("Keepalive loop error: {}", e.what());
            break;
        }
    }

}

cobalt::task<void> Client::reconnect() {
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
            auto [ec_disc] = co_await cobalt::as_tuple(events_.disconnected->write());
            if (ec_disc) {
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

    // 【重要】Controller 重连时保持数据通路不变：
    // - 不关闭 TUN（保持路由工作）
    // - 不停止 P2P manager（保持 P2P 连接）
    // - 不关闭 multi_relay_mgr_（保持 Relay 连接）
    // - 只重连 Control Channel

    // 只关闭 Control Channel
    if (control_) {
        try {
            co_await control_->close();
        } catch (const std::exception& e) {
            log().debug("Failed to close control channel: {}", e.what());
        } catch (...) {
            log().debug("Failed to close control channel: unknown error");
        }
        // 不 reset，保留 channel 对象以便重连
    }

    try {
        reconnect_timer_.expires_after(backoff_interval);
        co_await reconnect_timer_.async_wait(cobalt::use_op);

        // 只重连 Control Channel，保持数据通路不变
        bool success = false;
        if (control_) {
            success = co_await control_->reconnect();
        }

        if (success) {
            // Reconnect succeeded, reset retry counter
            reconnect_attempts_ = 0;
            state_ = ClientState::RUNNING;
            log().info("Control channel reconnect successful");
        } else {
            bool auto_reconnect = [&]() {
                std::shared_lock lock(config_mutex_);
                return config_.auto_reconnect;
            }();
            if (auto_reconnect) {
                // reconnect() failed, schedule another attempt
                log().warn("Control reconnect failed, will retry in {}s (attempt {}/{})",
                           backoff_interval.count(), reconnect_attempts_,
                           max_reconnect_attempts_);
                cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
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
                cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
            }
        } else {
            // Operation was cancelled (likely due to stop())
            reconnect_attempts_ = 0;  // Reset counter on cancellation
        }
    }
}

cobalt::task<void> Client::dns_refresh_loop() {
    // Skip if DNS refresh is disabled (read with lock)
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.dns_refresh_interval;
    }();

    if (interval.count() == 0) {
        co_return;
    }

    log().debug("DNS refresh loop started");

    while (state_ == ClientState::RUNNING) {
        try {
            dns_refresh_timer_.expires_after(interval);
            auto [ec] = co_await dns_refresh_timer_.async_wait(
                asio::as_tuple(cobalt::use_op));

            if (ec == asio::error::operation_aborted) {
                break;  // Timer cancelled, exit gracefully
            }

            if (state_ != ClientState::RUNNING) {
                break;
            }

            // Read config values with lock
            std::string controller_host;
            bool use_tls;
            bool auto_reconnect;
            {
                std::shared_lock lock(config_mutex_);
                if (config_.controller_url.empty()) {
                    continue;
                }
                controller_host = config_.controller_url;
                use_tls = config_.tls;
                auto_reconnect = config_.auto_reconnect;
                interval = config_.dns_refresh_interval;  // Update interval in case config changed
            }

            // 解析 controller host
            auto [host, port_num] = ClientConfig::parse_host_port(controller_host, use_tls);
            std::string port = std::to_string(port_num);

            // Resolve DNS
            asio::ip::tcp::resolver resolver(ioc_);
            auto [ec2, endpoints] = co_await resolver.async_resolve(
                host, port, asio::as_tuple(cobalt::use_op));

            if (ec2) {
                log().warn("DNS resolution failed: {}", ec2.message());
                continue;
            }

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
                    cobalt_utils::spawn_task(ioc_.get_executor(), reconnect());
                }
                co_return;
            }

        } catch (const std::exception& e) {
            log().error("DNS refresh loop error: {}", e.what());
            break;
        }
    }

}

cobalt::task<void> Client::latency_measure_loop() {
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
            co_await latency_timer_.async_wait(cobalt::use_op);

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
            uint32_t responded = 0, timed_out = 0;
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
                    responded++;
                } else {
                    timed_out++;
                }

                // Small delay between pings (100ms)
                asio::steady_timer delay_timer(co_await cobalt::this_coro::executor);
                delay_timer.expires_after(std::chrono::milliseconds(100));
                co_await delay_timer.async_wait(cobalt::use_op);
            }
            log().debug("Latency: {}/{} peers responded, {} timeouts",
                        responded, online_peers.size(), timed_out);

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

}

cobalt::task<void> Client::route_announce_loop() {
    auto interval = [&]() {
        std::shared_lock lock(config_mutex_);
        return config_.route_announce_interval;
    }();

    // 等待第一个间隔（首次公告已经在 on_connected 中完成）
    route_announce_timer_.expires_after(interval);

    try {
        co_await route_announce_timer_.async_wait(cobalt::use_op);
    } catch (const boost::system::system_error&) {
        co_return;
    }

    log().info("Route announcement loop started (interval: {}s)", interval.count());

    while (state_ == ClientState::RUNNING) {
        try {
            // 重新公告路由
            if (control_ && control_->is_connected()) {
                log().trace("Re-announcing routes (periodic broadcast)");
                co_await announce_configured_routes();
            }

            // 等待下一个间隔 (update interval in case config changed)
            {
                std::shared_lock lock(config_mutex_);
                interval = config_.route_announce_interval;
            }
            route_announce_timer_.expires_after(interval);
            co_await route_announce_timer_.async_wait(cobalt::use_op);

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                log().debug("Route announce error: {}", e.what());
            }
            break;
        }
    }

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
        ipc_->set_shutdown_callback([ch = events_.shutdown_requested, ex = ioc_.get_executor()]() {
            cobalt_utils::fire_write(*ch, ex);
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

cobalt::task<uint16_t> Client::ping_peer(NodeId peer_id, std::chrono::milliseconds timeout) {
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
    auto response_ch = std::make_shared<PingResponseChannel>(1, ioc_.get_executor());

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

    // Wait for response with timeout using cobalt::race
    asio::steady_timer timer(ioc_,
        std::chrono::duration_cast<std::chrono::steady_clock::duration>(timeout));

    uint16_t latency = 0;
    bool got_response = false;

    auto result = co_await cobalt::race(
        [&]() -> cobalt::task<uint16_t> {
            auto [ec, val] = co_await cobalt::as_tuple(response_ch->read());
            if (!ec) co_return val;
            co_return static_cast<uint16_t>(0);
        }(),
        timer.async_wait(cobalt::use_op)
    );

    if (result.index() == 0) {
        latency = boost::variant2::get<0>(result);
        got_response = (latency > 0);
    }

    if (!got_response) {
        log().debug("Ping timeout to {} (seq={})", peer->info.virtual_ip.to_string(), seq);
    }

    // Cleanup pending ping entry
    {
        std::lock_guard lock(ping_mutex_);
        pending_pings_.erase(key);
    }

    co_return latency;
}

cobalt::task<uint16_t> Client::ping_ip(const IPv4Address& ip, std::chrono::milliseconds timeout) {
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
                    cobalt_utils::fire_write(*it->second.response_ch, latency, ioc_.get_executor());
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
    cobalt_utils::spawn_task(ioc_.get_executor(), [self = shared_from_this(), peer_id, pong_msg = std::move(pong_msg)]() -> cobalt::task<void> {
        co_await self->relay_->send_data(peer_id, pong_msg);
    }());
}

// ============================================================================
// Subnet Routing
// ============================================================================

cobalt::task<void> Client::announce_routes(const std::vector<RouteInfo>& routes) {
    if (!control_ || !control_->is_connected()) {
        log().warn("Cannot announce routes: not connected");
        co_return;
    }

    co_await control_->send_route_announce(routes);
}

cobalt::task<void> Client::withdraw_routes(const std::vector<RouteInfo>& routes) {
    if (!control_ || !control_->is_connected()) {
        log().warn("Cannot withdraw routes: not connected");
        co_return;
    }

    co_await control_->send_route_withdraw(routes);
}

cobalt::task<void> Client::announce_configured_routes() {
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

    // 注意：exit_node 不再自动广播 0.0.0.0/0
    // exit_node 能力通过 AUTH 消息声明，客户端通过 use_exit_node 配置选择使用
    if (exit_node) {
        log().info("This node is declared as exit node (capability only, not broadcasting default route)");
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
    cobalt_utils::spawn_task(ioc_.get_executor(), [this, self = shared_from_this()]() -> cobalt::task<void> {
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
        co_await timer.async_wait(cobalt::use_op);

        // 重新启动
        co_await start();
    }());
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
    cobalt_utils::spawn_task(ioc_.get_executor(), [this, self = shared_from_this()]() -> cobalt::task<void> {
        if (!control_ || !control_->is_connected()) {
            log().warn("Cannot reannounce routes: not connected");
            co_return;
        }

        // 重新公告配置中的路由
        co_await announce_configured_routes();
        log().info("Routes reannounced successfully");
    }());
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
    // Optimization: Copy only the needed value under lock, then convert outside lock
    // This reduces lock duration from O(string ops) to O(1) copy

    // Special case: authkey doesn't need lock access
    if (key == "controller.authkey") {
        return "***";  // 不返回实际密钥
    }

    // Capture the needed value under lock (minimal critical section)
    std::shared_lock lock(config_mutex_);

    if (key == "controller.url") {
        std::string url = config_.current_controller_url();
        lock.unlock();
        return url;
    } else if (key == "controller.tls") {
        bool tls = config_.tls;
        lock.unlock();
        return tls ? "true" : "false";
    } else if (key == "connection.auto_reconnect") {
        bool val = config_.auto_reconnect;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "connection.reconnect_interval") {
        auto val = config_.reconnect_interval.count();
        lock.unlock();
        return std::to_string(val);
    } else if (key == "connection.ping_interval") {
        auto val = config_.ping_interval.count();
        lock.unlock();
        return std::to_string(val);
    } else if (key == "connection.dns_refresh_interval") {
        auto val = config_.dns_refresh_interval.count();
        lock.unlock();
        return std::to_string(val);
    } else if (key == "connection.latency_measure_interval") {
        auto val = config_.latency_measure_interval.count();
        lock.unlock();
        return std::to_string(val);
    } else if (key == "ssl.verify") {
        bool val = config_.ssl_verify;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "ssl.ca_file") {
        std::string val = config_.ssl_ca_file;
        lock.unlock();
        return val;
    } else if (key == "ssl.allow_self_signed") {
        bool val = config_.ssl_allow_self_signed;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "storage.state_dir") {
        std::string val = config_.state_dir;
        lock.unlock();
        return val;
    } else if (key == "tun.enable") {
        bool val = config_.enable_tun;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "tun.name") {
        std::string val = config_.tun_name;
        lock.unlock();
        return val;
    } else if (key == "tun.mtu") {
        uint32_t val = config_.tun_mtu;
        lock.unlock();
        return std::to_string(val);
    } else if (key == "ipc.enable") {
        bool val = config_.enable_ipc;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "ipc.socket_path") {
        std::string val = config_.ipc_socket_path;
        lock.unlock();
        return val;
    } else if (key == "routing.accept_routes") {
        bool val = config_.accept_routes;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "routing.advertise_routes") {
        // Copy vector under lock
        std::vector<std::string> routes = config_.advertise_routes;
        lock.unlock();
        // Serialize outside lock
        boost::json::array arr;
        for (const auto& route : routes) {
            arr.push_back(boost::json::value(route));
        }
        return boost::json::serialize(arr);
    } else if (key == "routing.exit_node") {
        bool val = config_.exit_node;
        lock.unlock();
        return val ? "true" : "false";
    } else if (key == "log.level") {
        std::string val = config_.log_level;
        lock.unlock();
        return val;
    } else if (key == "log.file") {
        std::string val = config_.log_file;
        lock.unlock();
        return val;
    }

    lock.unlock();
    return "";
}

cobalt::task<void> Client::config_change_handler() {
    while (state_ != ClientState::STOPPED && config_change_ch_) {
        auto new_config_opt = co_await config_change_ch_->read();
        if (!new_config_opt) {
            log().debug("Config change channel closed");
            break;
        }
        auto new_config = std::move(*new_config_opt);

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
    config_change_ch_ = std::make_unique<channels::ConfigChangeChannel>(4, ioc_.get_executor());

    config_watcher_ = std::make_unique<ConfigWatcher>(ioc_, config_path_);
    config_watcher_->set_channel(config_change_ch_.get());
    config_watcher_->start();

    // 启动配置变更处理协程
    cobalt_utils::spawn_task(ioc_.get_executor(), config_change_handler());

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

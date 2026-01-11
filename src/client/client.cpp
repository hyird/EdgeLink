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
    , keepalive_timer_(ioc)
    , reconnect_timer_(ioc)
    , dns_refresh_timer_(ioc)
    , latency_timer_(ioc) {

    // Initialize config applier
    config_applier_ = std::make_unique<ConfigApplier>(*this);

    // Initialize P2P managers
    endpoint_mgr_ = std::make_unique<EndpointManager>(ioc);
    p2p_mgr_ = std::make_unique<P2PManager>(ioc, crypto_, peers_, *endpoint_mgr_);

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
    teardown_ipc();
    teardown_tun();
}

void Client::set_callbacks(ClientCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void Client::setup_callbacks() {
    // Control channel callbacks
    ControlChannelCallbacks control_cbs;

    control_cbs.on_auth_response = [this](const AuthResponse& resp) {
        log().info("Authenticated: node_id={}, ip={}", resp.node_id, resp.virtual_ip.to_string());
    };

    control_cbs.on_config = [this](const Config& config) {
        peers_.update_from_config(config.peers);

        // 保存路由信息
        {
            std::lock_guard lock(routes_mutex_);
            routes_ = config.routes;
        }

        log().info("Config received: {} peers, {} routes, {} stuns",
                   config.peers.size(), config.routes.size(), config.stuns.size());

        // 配置 STUN 服务器
        if (endpoint_mgr_ && !config.stuns.empty()) {
            endpoint_mgr_->set_stun_servers(config.stuns);
        }

        // 初始化路由管理器并同步路由到系统
        if (config_.accept_routes && is_tun_enabled()) {
            if (!route_mgr_) {
                route_mgr_ = std::make_unique<RouteManager>(*this);
                route_mgr_->start();
            }
            if (route_mgr_) {
                route_mgr_->sync_routes(config.routes);
            }
        }

        // 自动对所有在线 peer 发起 P2P 连接
        if (p2p_mgr_ && p2p_mgr_->is_running()) {
            for (const auto& peer : config.peers) {
                if (peer.online && peer.node_id != crypto_.node_id()) {
                    p2p_mgr_->connect_peer(peer.node_id);
                }
            }
        }
    };

    control_cbs.on_config_update = [this](const ConfigUpdate& update) {
        if (has_flag(update.update_flags, ConfigUpdateFlags::PEER_CHANGED)) {
            for (const auto& peer : update.add_peers) {
                peers_.add_peer(peer);
                // 新 peer 上线，自动发起 P2P 连接
                if (p2p_mgr_ && p2p_mgr_->is_running() &&
                    peer.online && peer.node_id != crypto_.node_id()) {
                    p2p_mgr_->connect_peer(peer.node_id);
                }
            }
            for (auto peer_id : update.del_peer_ids) {
                peers_.remove_peer(peer_id);
                // peer 下线，断开 P2P 连接
                if (p2p_mgr_) {
                    p2p_mgr_->disconnect_peer(peer_id);
                }
            }
        }
    };

    control_cbs.on_route_update = [this](const RouteUpdate& update) {
        log().info("Route update v{}: +{} routes, -{} routes",
                   update.version, update.add_routes.size(), update.del_routes.size());

        // 更新本地路由缓存
        {
            std::lock_guard lock(routes_mutex_);

            // 添加新路由
            for (const auto& route : update.add_routes) {
                // 检查是否已存在，如果存在则更新
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

            // 删除路由
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

        // 应用路由更新到系统路由表
        if (route_mgr_) {
            route_mgr_->apply_route_update(update.add_routes, update.del_routes);
        }
    };

    control_cbs.on_error = [this](uint16_t code, const std::string& msg) {
        log().error("Control error {}: {}", code, msg);
        if (callbacks_.on_error) {
            callbacks_.on_error(code, msg);
        }
    };

    control_cbs.on_p2p_endpoint = [this](const P2PEndpointMsg& msg) {
        // 转发给 P2PManager 处理
        if (p2p_mgr_) {
            p2p_mgr_->handle_p2p_endpoint(msg);
        }
    };

    control_cbs.on_disconnected = [this]() {
        log().warn("Control channel disconnected");
        // Reconnect if we were running or in the middle of connecting
        if (config_.auto_reconnect && state_ != ClientState::STOPPED &&
            state_ != ClientState::RECONNECTING) {
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }
    };

    control_->set_callbacks(std::move(control_cbs));

    // Relay channel callbacks
    RelayChannelCallbacks relay_cbs;

    relay_cbs.on_data = [this](NodeId src, std::span<const uint8_t> data) {
        auto src_peer_ip = peers_.get_peer_ip_str(src);
        log().debug("Received {} bytes from {}", data.size(), src_peer_ip);

        // Check for internal ping/pong messages (type byte 0xEE/0xEF)
        if (data.size() >= 13 && (data[0] == 0xEE || data[0] == 0xEF)) {
            handle_ping_data(src, data);
            return;
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

        // Call user callback
        if (callbacks_.on_data_received) {
            callbacks_.on_data_received(src, data);
        }
    };

    relay_cbs.on_connected = [this]() {
        log().info("Relay channel connected");
        state_ = ClientState::RUNNING;

        // Setup TUN if enabled
        if (config_.enable_tun) {
            if (!setup_tun()) {
                log().warn("TUN mode requested but failed to setup TUN device");
            }
        }

        if (callbacks_.on_connected) {
            callbacks_.on_connected();
        }

        // Start keepalive
        asio::co_spawn(ioc_, keepalive_loop(), asio::detached);

        // Start DNS refresh loop
        asio::co_spawn(ioc_, dns_refresh_loop(), asio::detached);

        // Start latency measurement loop
        if (config_.latency_measure_interval.count() > 0) {
            asio::co_spawn(ioc_, latency_measure_loop(), asio::detached);
        }

        // Announce configured routes (advertise_routes and exit_node)
        if (!config_.advertise_routes.empty() || config_.exit_node) {
            asio::co_spawn(ioc_, announce_configured_routes(), asio::detached);
        }

        // Start P2P manager
        if (p2p_mgr_) {
            auto self = shared_from_this();
            asio::co_spawn(ioc_, [self]() -> asio::awaitable<void> {
                try {
                    co_await self->p2p_mgr_->start();
                    log().info("P2P manager started successfully");
                } catch (const std::exception& e) {
                    log().error("P2P manager failed: {}", e.what());
                }
            }(), asio::detached);

            // TODO: 端点上报暂时禁用，需要调查内存问题
            // Endpoint reporting is temporarily disabled
        }
    };

    relay_cbs.on_disconnected = [this]() {
        log().warn("Relay channel disconnected");
        // Reconnect if we were running or in the middle of connecting
        if (config_.auto_reconnect && state_ != ClientState::STOPPED &&
            state_ != ClientState::RECONNECTING) {
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }
    };

    relay_->set_callbacks(std::move(relay_cbs));

    // P2P manager callbacks
    if (p2p_mgr_) {
        P2PCallbacks p2p_cbs;

        p2p_cbs.on_state_change = [this](NodeId peer_id, P2PState state) {
            log().info("P2P state changed: peer={}, state={}",
                       peers_.get_peer_ip_str(peer_id), p2p_state_name(state));
        };

        p2p_cbs.on_data = [this](NodeId peer_id, std::span<const uint8_t> data) {
            log().debug("P2P data received: {} bytes from {}",
                        data.size(), peers_.get_peer_ip_str(peer_id));

            // Check for internal ping/pong messages (type byte 0xEE/0xEF)
            if (data.size() >= 13 && (data[0] == 0xEE || data[0] == 0xEF)) {
                handle_ping_data(peer_id, data);
                return;
            }

            // If TUN mode is enabled, write IP packets to TUN device
            if (is_tun_enabled() && ip_packet::version(data) == 4) {
                auto result = tun_->write(data);
                if (!result) {
                    log().warn("Failed to write to TUN: {}", tun_error_message(result.error()));
                }
            }

            // Call user callback
            if (callbacks_.on_data_received) {
                callbacks_.on_data_received(peer_id, data);
            }
        };

        p2p_cbs.on_send_p2p_init = [this](const P2PInit& init) {
            // 通过 Control Channel 发送 P2P_INIT
            if (control_ && control_->is_connected()) {
                asio::co_spawn(ioc_, control_->send_p2p_init(init), asio::detached);
            }
        };

        p2p_cbs.on_send_p2p_status = [this](const P2PStatusMsg& status) {
            // TODO: 通过 Control Channel 发送 P2P_STATUS
            log().debug("P2P status: peer={}, state={}, latency={}ms",
                        status.peer_node, static_cast<int>(status.status), status.latency_ms);
        };

        p2p_mgr_->set_callbacks(std::move(p2p_cbs));
    }
}

bool Client::setup_tun() {
    if (!control_ || !control_->is_connected()) {
        log().error("Cannot setup TUN: not connected");
        return false;
    }

    // Create TUN device
    tun_ = TunDevice::create(ioc_);
    if (!tun_) {
        log().error("Failed to create TUN device");
        return false;
    }

    // Open TUN device
    auto result = tun_->open(config_.tun_name);
    if (!result) {
        log().error("Failed to open TUN device: {}", tun_error_message(result.error()));
        tun_.reset();
        return false;
    }

    // Configure TUN device with our virtual IP
    auto vip = control_->virtual_ip();

    // Calculate netmask from prefix length (e.g., /16 -> 255.255.0.0)
    uint8_t prefix_len = control_->subnet_mask();
    uint32_t mask = prefix_len == 0 ? 0 : (~0U << (32 - prefix_len));
    auto netmask = IPv4Address::from_u32(mask);

    result = tun_->configure(vip, netmask, config_.tun_mtu);
    if (!result) {
        log().error("Failed to configure TUN device: {}", tun_error_message(result.error()));
        tun_->close();
        tun_.reset();
        return false;
    }

    // Start reading packets from TUN
    tun_->start_read([this](std::span<const uint8_t> packet) {
        on_tun_packet(packet);
    });

    log().info("TUN device enabled: {} with IP {}", tun_->name(), vip.to_string());
    return true;
}

void Client::teardown_tun() {
    if (tun_) {
        tun_->stop_read();
        tun_->close();
        tun_.reset();
        log().info("TUN device closed");
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

    // Send via relay
    asio::co_spawn(ioc_, [this, peer_id = peer->info.node_id,
                          data = std::vector<uint8_t>(packet.begin(), packet.end())]()
                          -> asio::awaitable<void> {
        co_await send_to_peer(peer_id, data);
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

        // Setup callbacks
        setup_callbacks();

        // Connect to control channel
        state_ = ClientState::AUTHENTICATING;
        log().info("Connecting to controller...");

        bool connected = co_await control_->connect(config_.authkey);
        if (!connected) {
            log().warn("Failed to connect to controller {}:{}", host, port);
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // Wait a bit for auth response
        asio::steady_timer timer(ioc_);
        timer.expires_after(std::chrono::seconds(5));

        bool auth_ok = false;
        while (!control_->is_connected()) {
            auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                    asio::post(ioc_, asio::use_awaitable));
            if (timer.expiry() <= std::chrono::steady_clock::now()) {
                log().warn("Authentication timeout for {}:{}", host, port);
                break;
            }
            co_await asio::post(ioc_, asio::use_awaitable);
        }

        if (!control_->is_connected()) {
            try { co_await control_->close(); } catch (...) {}
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
            try { co_await control_->close(); } catch (...) {}
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // Wait for relay auth
        timer.expires_after(std::chrono::seconds(5));
        while (!relay_->is_connected()) {
            auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                    asio::post(ioc_, asio::use_awaitable));
            if (timer.expiry() <= std::chrono::steady_clock::now()) {
                log().warn("Relay authentication timeout for {}:{}", host, port);
                break;
            }
            co_await asio::post(ioc_, asio::use_awaitable);
        }

        if (!relay_->is_connected()) {
            try { co_await control_->close(); } catch (...) {}
            control_.reset();
            relay_.reset();
            continue;  // 尝试下一个 controller
        }

        // 连接成功
        controller_connected = true;
        log().info("Connected to controller: {}:{}", host, port);
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

    keepalive_timer_.cancel();
    reconnect_timer_.cancel();
    dns_refresh_timer_.cancel();
    latency_timer_.cancel();

    // Stop P2P manager
    if (p2p_mgr_) {
        co_await p2p_mgr_->stop();
    }

    // Stop route manager first (removes routes from system)
    if (route_mgr_) {
        route_mgr_->stop();
        route_mgr_.reset();
    }

    // Teardown TUN
    teardown_tun();

    if (relay_) {
        co_await relay_->close();
    }

    if (control_) {
        co_await control_->close();
    }

    state_ = ClientState::STOPPED;
    log().info("Client stopped");

    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
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
            p2p_mgr_->connect_peer(peer_id);
        }
    }

    // 通过 Relay 发送
    if (!relay_ || !relay_->is_connected()) {
        log().warn("Cannot send: relay not connected");
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

asio::awaitable<void> Client::keepalive_loop() {
    while (state_ == ClientState::RUNNING) {
        try {
            keepalive_timer_.expires_after(config_.ping_interval);
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
    log().info("Attempting to reconnect...");

    // Clear DNS cache so it will be re-initialized after reconnect
    cached_controller_endpoints_.clear();

    // Teardown TUN on reconnect
    teardown_tun();

    // Close existing channels
    if (relay_) {
        try { co_await relay_->close(); } catch (...) {}
        relay_.reset();
    }
    if (control_) {
        try { co_await control_->close(); } catch (...) {}
        control_.reset();
    }

    try {
        reconnect_timer_.expires_after(config_.reconnect_interval);
        co_await reconnect_timer_.async_wait(asio::use_awaitable);

        // Try to reconnect
        state_ = ClientState::STOPPED;
        bool success = co_await start();

        if (!success && config_.auto_reconnect) {
            // start() failed, schedule another attempt
            log().warn("Reconnect failed, will retry in {}s",
                         config_.reconnect_interval.count());
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }

    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            log().debug("Reconnect error: {}", e.what());
            // Schedule another reconnect attempt
            if (config_.auto_reconnect) {
                asio::co_spawn(ioc_, reconnect(), asio::detached);
            }
        }
    }
}

asio::awaitable<void> Client::dns_refresh_loop() {
    // Skip if DNS refresh is disabled
    if (config_.dns_refresh_interval.count() == 0) {
        co_return;
    }

    while (state_ == ClientState::RUNNING) {
        try {
            dns_refresh_timer_.expires_after(config_.dns_refresh_interval);
            co_await dns_refresh_timer_.async_wait(asio::use_awaitable);

            if (state_ != ClientState::RUNNING) {
                break;
            }

            // 使用当前的 controller host
            if (config_.controller_hosts.empty()) {
                continue;
            }

            // 解析第一个 controller host
            auto [host, port_num] = ClientConfig::parse_host_port(config_.controller_hosts[0], config_.tls);
            std::string port = std::to_string(port_num);

            // Resolve DNS
            asio::ip::tcp::resolver resolver(ioc_);
            auto endpoints = co_await resolver.async_resolve(host, port, asio::use_awaitable);

            // Build endpoints string for comparison
            std::string new_endpoints;
            for (const auto& ep : endpoints) {
                if (!new_endpoints.empty()) {
                    new_endpoints += ",";
                }
                new_endpoints += ep.endpoint().address().to_string();
                new_endpoints += ":";
                new_endpoints += std::to_string(ep.endpoint().port());
            }

            // Check if DNS resolution changed
            if (!cached_controller_endpoints_.empty() &&
                cached_controller_endpoints_ != new_endpoints) {
                log().info("DNS resolution changed: {} -> {}", cached_controller_endpoints_, new_endpoints);
                // Trigger reconnect to use new endpoints
                if (config_.auto_reconnect) {
                    asio::co_spawn(ioc_, reconnect(), asio::detached);
                }
                co_return;
            }

            // Update cache (first time or unchanged)
            if (cached_controller_endpoints_.empty()) {
                cached_controller_endpoints_ = new_endpoints;
                log().debug("DNS cache initialized: {}", new_endpoints);
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
    log().info("Latency measurement started (interval: {}s)", config_.latency_measure_interval.count());

    while (state_ == ClientState::RUNNING) {
        try {
            latency_timer_.expires_after(config_.latency_measure_interval);
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

    // Set shutdown callback if provided
    if (callbacks_.on_shutdown_requested) {
        ipc_->set_shutdown_callback(callbacks_.on_shutdown_requested);
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

    // Setup pending ping with promise
    uint64_t key = (static_cast<uint64_t>(peer_id) << 32) | seq;
    auto promise = std::make_shared<std::promise<uint16_t>>();
    auto future = promise->get_future();

    {
        std::lock_guard lock(ping_mutex_);
        pending_pings_[key] = PendingPing{now, [promise](uint16_t latency) {
            promise->set_value(latency);
        }};
    }

    // Send ping
    bool sent = co_await relay_->send_data(peer_id, ping_msg);
    if (!sent) {
        std::lock_guard lock(ping_mutex_);
        pending_pings_.erase(key);
        co_return 0;
    }

    log().debug("Ping sent to {} (seq={})", peer->info.virtual_ip.to_string(), seq);

    // Wait for response with timeout
    asio::steady_timer timer(co_await asio::this_coro::executor);
    timer.expires_after(timeout);

    bool timed_out = false;
    try {
        co_await timer.async_wait(asio::use_awaitable);
        timed_out = true;
    } catch (const boost::system::system_error& e) {
        if (e.code() == asio::error::operation_aborted) {
            // Timer was cancelled, meaning we got a response
        } else {
            throw;
        }
    }

    // Check if we got a response
    uint16_t latency = 0;
    {
        std::lock_guard lock(ping_mutex_);
        auto it = pending_pings_.find(key);
        if (it != pending_pings_.end()) {
            if (timed_out) {
                log().debug("Ping timeout to {} (seq={})", peer->info.virtual_ip.to_string(), seq);
            }
            pending_pings_.erase(it);
        }
    }

    // Try to get the future value (non-blocking)
    if (future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
        latency = future.get();
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
        peers_.set_latency(src, latency);

        // Find and complete pending ping
        uint64_t key = (static_cast<uint64_t>(src) << 32) | seq;
        std::lock_guard lock(ping_mutex_);
        auto it = pending_pings_.find(key);
        if (it != pending_pings_.end()) {
            if (it->second.callback) {
                it->second.callback(latency);
            }
            pending_pings_.erase(it);
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

    asio::co_spawn(ioc_, [this, peer_id, pong_msg = std::move(pong_msg)]() -> asio::awaitable<void> {
        co_await relay_->send_data(peer_id, pong_msg);
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

    // 解析配置中的路由 (CIDR 格式)
    for (const auto& cidr : config_.advertise_routes) {
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
    if (config_.exit_node) {
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
    // 根据 key 返回对应的配置值
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

void Client::enable_config_watch() {
    if (config_path_.empty()) {
        log().warn("Cannot enable config watch: config path not set");
        return;
    }

    if (config_watcher_) {
        log().debug("Config watcher already enabled");
        return;
    }

    config_watcher_ = std::make_unique<ConfigWatcher>(ioc_, config_path_);

    // 设置配置变更回调
    config_watcher_->start([this](const ClientConfig& new_config) {
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

            // 更新配置
            config_ = new_config;
        }
    });

    log().info("Config file watching enabled: {}", config_path_);
}

void Client::disable_config_watch() {
    if (config_watcher_) {
        config_watcher_->stop();
        config_watcher_.reset();
        log().info("Config file watching disabled");
    }
}

void Client::clear_system_routes() {
    if (route_mgr_) {
        log().info("Clearing all system routes");
        route_mgr_->cleanup_all();
    }
}

} // namespace edgelink::client

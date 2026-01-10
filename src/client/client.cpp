#include "client/client.hpp"
#include "common/logger.hpp"
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
        log().info("Config received: {} peers", config.peers.size());
    };

    control_cbs.on_config_update = [this](const ConfigUpdate& update) {
        if (has_flag(update.update_flags, ConfigUpdateFlags::PEER_CHANGED)) {
            for (const auto& peer : update.add_peers) {
                peers_.add_peer(peer);
            }
            for (auto peer_id : update.del_peer_ids) {
                peers_.remove_peer(peer_id);
            }
        }
    };

    control_cbs.on_error = [this](uint16_t code, const std::string& msg) {
        log().error("Control error {}: {}", code, msg);
        if (callbacks_.on_error) {
            callbacks_.on_error(code, msg);
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

    // Build control and relay URLs from server address
    // The URL can be just host:port - we add the scheme based on tls config
    std::string base_url = config_.controller_url;

    // Remove trailing slash if present
    if (!base_url.empty() && base_url.back() == '/') {
        base_url.pop_back();
    }

    // Remove any existing scheme (we'll add based on tls config)
    if (base_url.substr(0, 6) == "wss://") {
        base_url = base_url.substr(6);
    } else if (base_url.substr(0, 5) == "ws://") {
        base_url = base_url.substr(5);
    } else if (base_url.substr(0, 8) == "https://") {
        base_url = base_url.substr(8);
    } else if (base_url.substr(0, 7) == "http://") {
        base_url = base_url.substr(7);
    }

    // Remove path if user accidentally included it
    auto path_pos = base_url.find("/api/");
    if (path_pos != std::string::npos) {
        base_url = base_url.substr(0, path_pos);
    }

    // Add the correct scheme based on TLS config
    std::string scheme = config_.tls ? "wss://" : "ws://";
    base_url = scheme + base_url;

    std::string control_url = base_url + "/api/v1/control";
    std::string relay_url = base_url + "/api/v1/relay";

    log().info("TLS: {}", config_.tls ? "enabled" : "disabled");
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
        log().error("Failed to connect to controller");
        if (config_.auto_reconnect) {
            log().info("Will retry in {}s...", config_.reconnect_interval.count());
            state_ = ClientState::STOPPED;
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        } else {
            state_ = ClientState::STOPPED;
        }
        co_return false;
    }

    // Wait a bit for auth response
    asio::steady_timer timer(ioc_);
    timer.expires_after(std::chrono::seconds(5));

    while (!control_->is_connected()) {
        auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                asio::post(ioc_, asio::use_awaitable));
        if (timer.expiry() <= std::chrono::steady_clock::now()) {
            log().error("Authentication timeout");
            if (config_.auto_reconnect) {
                log().info("Will retry in {}s...", config_.reconnect_interval.count());
                state_ = ClientState::STOPPED;
                asio::co_spawn(ioc_, reconnect(), asio::detached);
            } else {
                state_ = ClientState::STOPPED;
            }
            co_return false;
        }
        co_await asio::post(ioc_, asio::use_awaitable);
    }

    // Connect to relay channel
    state_ = ClientState::CONNECTING_RELAY;
    log().info("Connecting to relay...");

    connected = co_await relay_->connect(control_->relay_token());
    if (!connected) {
        log().error("Failed to connect to relay");
        co_await control_->close();
        if (config_.auto_reconnect) {
            log().info("Will retry in {}s...", config_.reconnect_interval.count());
            state_ = ClientState::STOPPED;
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        } else {
            state_ = ClientState::STOPPED;
        }
        co_return false;
    }

    // Wait for relay auth
    timer.expires_after(std::chrono::seconds(5));
    while (!relay_->is_connected()) {
        auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                asio::post(ioc_, asio::use_awaitable));
        if (timer.expiry() <= std::chrono::steady_clock::now()) {
            log().error("Relay authentication timeout");
            co_await control_->close();
            if (config_.auto_reconnect) {
                log().info("Will retry in {}s...", config_.reconnect_interval.count());
                state_ = ClientState::STOPPED;
                asio::co_spawn(ioc_, reconnect(), asio::detached);
            } else {
                state_ = ClientState::STOPPED;
            }
            co_return false;
        }
        co_await asio::post(ioc_, asio::use_awaitable);
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

    // Teardown TUN first
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

            // Parse URL to get host and port
            std::string base_url = config_.controller_url;
            if (!base_url.empty() && base_url.back() == '/') {
                base_url.pop_back();
            }
            // Remove scheme
            if (base_url.substr(0, 6) == "wss://") {
                base_url = base_url.substr(6);
            } else if (base_url.substr(0, 5) == "ws://") {
                base_url = base_url.substr(5);
            } else if (base_url.substr(0, 8) == "https://") {
                base_url = base_url.substr(8);
            } else if (base_url.substr(0, 7) == "http://") {
                base_url = base_url.substr(7);
            }
            // Remove path
            auto path_pos = base_url.find('/');
            if (path_pos != std::string::npos) {
                base_url = base_url.substr(0, path_pos);
            }

            // Extract host and port
            std::string host = base_url;
            std::string port = config_.tls ? "443" : "80";
            auto colon_pos = base_url.find(':');
            if (colon_pos != std::string::npos) {
                host = base_url.substr(0, colon_pos);
                port = base_url.substr(colon_pos + 1);
            }

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

} // namespace edgelink::client

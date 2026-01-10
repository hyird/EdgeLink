#include "client/client.hpp"
#include <spdlog/spdlog.h>

namespace edgelink::client {

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
    , reconnect_timer_(ioc) {

    // Setup SSL context
    ssl_ctx_.set_default_verify_paths();
    ssl_ctx_.set_verify_mode(ssl::verify_none); // TODO: proper verification
}

Client::~Client() {
    teardown_tun();
}

void Client::set_callbacks(ClientCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void Client::setup_callbacks() {
    // Control channel callbacks
    ControlChannelCallbacks control_cbs;

    control_cbs.on_auth_response = [this](const AuthResponse& resp) {
        spdlog::info("Authenticated: node_id={}, ip={}", resp.node_id, resp.virtual_ip.to_string());
    };

    control_cbs.on_config = [this](const Config& config) {
        peers_.update_from_config(config.peers);
        spdlog::info("Config received: {} peers", config.peers.size());
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
        spdlog::error("Control error {}: {}", code, msg);
        if (callbacks_.on_error) {
            callbacks_.on_error(code, msg);
        }
    };

    control_cbs.on_disconnected = [this]() {
        spdlog::warn("Control channel disconnected");
        if (state_ == ClientState::RUNNING && config_.auto_reconnect) {
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }
    };

    control_->set_callbacks(std::move(control_cbs));

    // Relay channel callbacks
    RelayChannelCallbacks relay_cbs;

    relay_cbs.on_data = [this](NodeId src, std::span<const uint8_t> data) {
        spdlog::trace("Received {} bytes from node {}", data.size(), src);

        // If TUN mode is enabled, write IP packets to TUN device
        if (is_tun_enabled() && ip_packet::version(data) == 4) {
            auto result = tun_->write(data);
            if (!result) {
                spdlog::debug("Failed to write to TUN: {}", tun_error_message(result.error()));
            }
        }

        // Call user callback
        if (callbacks_.on_data_received) {
            callbacks_.on_data_received(src, data);
        }
    };

    relay_cbs.on_connected = [this]() {
        spdlog::info("Relay channel connected");
        state_ = ClientState::RUNNING;

        // Setup TUN if enabled
        if (config_.enable_tun) {
            if (!setup_tun()) {
                spdlog::warn("TUN mode requested but failed to setup TUN device");
            }
        }

        if (callbacks_.on_connected) {
            callbacks_.on_connected();
        }

        // Start keepalive
        asio::co_spawn(ioc_, keepalive_loop(), asio::detached);
    };

    relay_cbs.on_disconnected = [this]() {
        spdlog::warn("Relay channel disconnected");
        if (state_ == ClientState::RUNNING && config_.auto_reconnect) {
            asio::co_spawn(ioc_, reconnect(), asio::detached);
        }
    };

    relay_->set_callbacks(std::move(relay_cbs));
}

bool Client::setup_tun() {
    if (!control_ || !control_->is_connected()) {
        spdlog::error("Cannot setup TUN: not connected");
        return false;
    }

    // Create TUN device
    tun_ = TunDevice::create(ioc_);
    if (!tun_) {
        spdlog::error("Failed to create TUN device");
        return false;
    }

    // Open TUN device
    auto result = tun_->open(config_.tun_name);
    if (!result) {
        spdlog::error("Failed to open TUN device: {}", tun_error_message(result.error()));
        tun_.reset();
        return false;
    }

    // Configure TUN device with our virtual IP
    auto vip = control_->virtual_ip();
    auto netmask = IPv4Address::from_string("255.0.0.0");  // /8 for 10.x.x.x

    result = tun_->configure(vip, netmask, config_.tun_mtu);
    if (!result) {
        spdlog::error("Failed to configure TUN device: {}", tun_error_message(result.error()));
        tun_->close();
        tun_.reset();
        return false;
    }

    // Start reading packets from TUN
    tun_->start_read([this](std::span<const uint8_t> packet) {
        on_tun_packet(packet);
    });

    spdlog::info("TUN device enabled: {} with IP {}", tun_->name(), vip.to_string());
    return true;
}

void Client::teardown_tun() {
    if (tun_) {
        tun_->stop_read();
        tun_->close();
        tun_.reset();
        spdlog::info("TUN device closed");
    }
}

void Client::on_tun_packet(std::span<const uint8_t> packet) {
    // Validate IPv4 packet
    if (packet.size() < 20 || ip_packet::version(packet) != 4) {
        return;
    }

    // Get destination IP
    auto dst_ip = ip_packet::dst_ipv4(packet);

    // Find peer by destination IP
    auto peer = peers_.get_peer_by_ip(dst_ip);
    if (!peer) {
        spdlog::trace("TUN packet to unknown IP {}, dropping", dst_ip.to_string());
        return;
    }

    // Send via relay
    asio::co_spawn(ioc_, [this, peer_id = peer->info.node_id,
                          data = std::vector<uint8_t>(packet.begin(), packet.end())]()
                          -> asio::awaitable<void> {
        co_await send_to_peer(peer_id, data);
    }, asio::detached);
}

asio::awaitable<bool> Client::start() {
    if (state_ != ClientState::STOPPED) {
        spdlog::warn("Client already started");
        co_return false;
    }

    state_ = ClientState::STARTING;
    spdlog::info("Starting client...");

    // Initialize crypto
    auto init_result = crypto_.init();
    if (!init_result) {
        spdlog::error("Failed to initialize crypto engine");
        state_ = ClientState::STOPPED;
        co_return false;
    }

    // Build control and relay URLs from server address
    std::string base_url = config_.controller_url;
    // Remove trailing slash if present
    if (!base_url.empty() && base_url.back() == '/') {
        base_url.pop_back();
    }
    // Remove path if user accidentally included it
    auto path_pos = base_url.find("/api/");
    if (path_pos != std::string::npos) {
        base_url = base_url.substr(0, path_pos);
    }

    // Handle TLS scheme based on config
    if (config_.tls) {
        // Ensure wss:// scheme
        if (base_url.substr(0, 5) == "ws://") {
            base_url = "wss://" + base_url.substr(5);
        } else if (base_url.substr(0, 6) != "wss://") {
            base_url = "wss://" + base_url;
        }
    } else {
        // Ensure ws:// scheme
        if (base_url.substr(0, 6) == "wss://") {
            base_url = "ws://" + base_url.substr(6);
        } else if (base_url.substr(0, 5) != "ws://") {
            base_url = "ws://" + base_url;
        }
    }

    std::string control_url = base_url + "/api/v1/control";
    std::string relay_url = base_url + "/api/v1/relay";

    spdlog::info("TLS: {}", config_.tls ? "enabled" : "disabled");
    spdlog::debug("Control URL: {}", control_url);
    spdlog::debug("Relay URL: {}", relay_url);

    // Create channels
    control_ = std::make_shared<ControlChannel>(ioc_, ssl_ctx_, crypto_, control_url, config_.tls);
    relay_ = std::make_shared<RelayChannel>(ioc_, ssl_ctx_, crypto_, peers_, relay_url, config_.tls);

    // Setup callbacks
    setup_callbacks();

    // Connect to control channel
    state_ = ClientState::AUTHENTICATING;
    spdlog::info("Connecting to controller...");

    bool connected = co_await control_->connect(config_.authkey);
    if (!connected) {
        spdlog::error("Failed to connect to controller");
        state_ = ClientState::STOPPED;
        co_return false;
    }

    // Wait a bit for auth response
    asio::steady_timer timer(ioc_);
    timer.expires_after(std::chrono::seconds(5));

    while (!control_->is_connected()) {
        auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                asio::post(ioc_, asio::use_awaitable));
        if (timer.expiry() <= std::chrono::steady_clock::now()) {
            spdlog::error("Authentication timeout");
            state_ = ClientState::STOPPED;
            co_return false;
        }
        co_await asio::post(ioc_, asio::use_awaitable);
    }

    // Connect to relay channel
    state_ = ClientState::CONNECTING_RELAY;
    spdlog::info("Connecting to relay...");

    connected = co_await relay_->connect(control_->relay_token());
    if (!connected) {
        spdlog::error("Failed to connect to relay");
        co_await control_->close();
        state_ = ClientState::STOPPED;
        co_return false;
    }

    // Wait for relay auth
    timer.expires_after(std::chrono::seconds(5));
    while (!relay_->is_connected()) {
        auto result = co_await (timer.async_wait(asio::use_awaitable) ||
                                asio::post(ioc_, asio::use_awaitable));
        if (timer.expiry() <= std::chrono::steady_clock::now()) {
            spdlog::error("Relay authentication timeout");
            co_await control_->close();
            state_ = ClientState::STOPPED;
            co_return false;
        }
        co_await asio::post(ioc_, asio::use_awaitable);
    }

    spdlog::info("Client started successfully");
    spdlog::info("  Node ID: {}", crypto_.node_id());
    spdlog::info("  Virtual IP: {}", control_->virtual_ip().to_string());
    spdlog::info("  Peers: {}", peers_.peer_count());
    if (is_tun_enabled()) {
        spdlog::info("  TUN device: {}", tun_->name());
    }

    co_return true;
}

asio::awaitable<void> Client::stop() {
    spdlog::info("Stopping client...");

    keepalive_timer_.cancel();
    reconnect_timer_.cancel();

    // Teardown TUN first
    teardown_tun();

    if (relay_) {
        co_await relay_->close();
    }

    if (control_) {
        co_await control_->close();
    }

    state_ = ClientState::STOPPED;
    spdlog::info("Client stopped");

    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected();
    }
}

asio::awaitable<bool> Client::send_to_peer(NodeId peer_id, std::span<const uint8_t> data) {
    if (!relay_ || !relay_->is_connected()) {
        spdlog::warn("Cannot send: relay not connected");
        co_return false;
    }

    co_return co_await relay_->send_data(peer_id, data);
}

asio::awaitable<bool> Client::send_to_ip(const IPv4Address& ip, std::span<const uint8_t> data) {
    auto peer = peers_.get_peer_by_ip(ip);
    if (!peer) {
        spdlog::warn("Cannot send: no peer with IP {}", ip.to_string());
        co_return false;
    }

    co_return co_await send_to_peer(peer->info.node_id, data);
}

asio::awaitable<bool> Client::send_ip_packet(std::span<const uint8_t> packet) {
    // Validate IPv4 packet
    if (packet.size() < 20 || ip_packet::version(packet) != 4) {
        spdlog::warn("Invalid IP packet");
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
                spdlog::debug("Keepalive error: {}", e.what());
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
    spdlog::info("Attempting to reconnect...");

    // Teardown TUN on reconnect
    teardown_tun();

    try {
        reconnect_timer_.expires_after(config_.reconnect_interval);
        co_await reconnect_timer_.async_wait(asio::use_awaitable);

        // Try to reconnect
        state_ = ClientState::STOPPED;
        co_await start();

    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::operation_aborted) {
            spdlog::debug("Reconnect error: {}", e.what());
            // Schedule another reconnect attempt
            if (config_.auto_reconnect) {
                asio::co_spawn(ioc_, reconnect(), asio::detached);
            }
        }
    }
}

} // namespace edgelink::client

#include "client/control_channel.hpp"
#include "common/log.hpp"
#include "common/config.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include <regex>

namespace edgelink::client {

// ============================================================================
// Base64 Decode Helper
// ============================================================================

static std::vector<uint8_t> decode_base64(const std::string& encoded) {
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::vector<uint8_t> result;
    int val = 0, bits = -8;

    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

ControlChannel::ControlChannel(
    const std::string& controller_url,
    const std::string& machine_key_pub_b64,
    const std::string& machine_key_priv_b64,
    const std::string& auth_key
)
    : machine_key_pub_b64_(machine_key_pub_b64)
    , machine_key_priv_b64_(machine_key_priv_b64)
    , auth_key_(auth_key)
{
    // Parse controller URL: grpc://host:port or grpcs://host:port
    // Also support legacy ws://host:port format
    std::regex url_regex(R"((grpcs?|wss?)://([^:/]+)(?::(\d+))?)", std::regex::icase);
    std::smatch match;

    bool use_tls = true;
    if (std::regex_match(controller_url, match, url_regex)) {
        std::string scheme = match[1].str();
        use_tls = (scheme == "grpcs" || scheme == "wss" || scheme == "GRPCS" || scheme == "WSS");
        controller_host_ = match[2].str();
        controller_port_ = match[3].matched ? match[3].str() : (use_tls ? "443" : "80");
    } else {
        LOG_ERROR("ControlChannel: Invalid controller URL: {}", controller_url);
        controller_host_ = controller_url;
        controller_port_ = "443";
    }

    // Create gRPC channel
    std::string target = controller_host_ + ":" + controller_port_;

    grpc::ChannelArguments args;
    // gRPC-level keepalive for connection health
    // Server allows pings every 20s (GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS)
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);  // 60s interval
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);  // 20s timeout
    args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 0);  // Only when stream active

    if (use_tls) {
        auto creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
        channel_ = grpc::CreateCustomChannel(target, creds, args);
    } else {
        channel_ = grpc::CreateCustomChannel(target, grpc::InsecureChannelCredentials(), args);
    }

    stub_ = edgelink::ControlService::NewStub(channel_);

    LOG_INFO("ControlChannel: Configured for {} (TLS: {})",
             target, use_tls ? "yes" : "no");
}

ControlChannel::~ControlChannel() {
    disconnect();
}

void ControlChannel::set_callbacks(ControlCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

// ============================================================================
// Connection Management
// ============================================================================

void ControlChannel::connect() {
    if (state_ != State::DISCONNECTED && state_ != State::RECONNECTING) {
        LOG_WARN("ControlChannel: Already connecting or connected");
        return;
    }

    state_ = State::CONNECTING;
    shutdown_ = false;
    reconnect_attempts_ = 0;
    last_pong_ = std::chrono::steady_clock::now();

    LOG_INFO("ControlChannel: Connecting to {}:{}",
             controller_host_, controller_port_);

    run_stream();
}

void ControlChannel::disconnect() {
    shutdown_ = true;

    // Cancel the stream
    if (context_) {
        context_->TryCancel();
    }

    // Wait for threads to finish
    if (read_thread_ && read_thread_->joinable()) {
        read_thread_->join();
    }
    if (write_thread_ && write_thread_->joinable()) {
        write_cv_.notify_all();
        write_thread_->join();
    }

    read_thread_.reset();
    write_thread_.reset();
    stream_.reset();
    context_.reset();

    // Clear write queue
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        std::queue<edgelink::ControlMessage> empty;
        write_queue_.swap(empty);
    }

    state_ = State::DISCONNECTED;
    LOG_INFO("ControlChannel: Disconnected");
}

void ControlChannel::reconnect() {
    if (state_ == State::RECONNECTING) {
        return;
    }

    // Cancel current stream
    if (context_) {
        context_->TryCancel();
    }

    state_ = State::RECONNECTING;
    schedule_reconnect();
}

// ============================================================================
// gRPC Stream Management
// ============================================================================

void ControlChannel::run_stream() {
    // Create new context for the stream (no deadline for long-running stream)
    context_ = std::make_unique<grpc::ClientContext>();

    // Create bidirectional stream
    stream_ = stub_->Control(context_.get());

    if (!stream_) {
        LOG_ERROR("ControlChannel: Failed to create stream");
        reconnect();
        return;
    }

    state_ = State::AUTHENTICATING;
    LOG_INFO("ControlChannel: Stream connected, authenticating");

    // Send authentication request
    do_authenticate();

    // Start read and write threads (heartbeat merged into write thread)
    read_thread_ = std::make_unique<std::thread>(&ControlChannel::read_loop, this);
    write_thread_ = std::make_unique<std::thread>(&ControlChannel::write_loop, this);
}

void ControlChannel::read_loop() {
    edgelink::ControlMessage msg;

    while (!shutdown_ && stream_->Read(&msg)) {
        process_message(msg);
    }

    if (!shutdown_) {
        LOG_ERROR("ControlChannel: Stream read ended unexpectedly");
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected(ErrorCode::DISCONNECTED);
        }
        state_ = State::RECONNECTING;
        schedule_reconnect();
    }
}

void ControlChannel::write_loop() {
    constexpr auto heartbeat_interval = std::chrono::seconds(NetworkConstants::DEFAULT_HEARTBEAT_INTERVAL);
    auto next_heartbeat = std::chrono::steady_clock::now() + heartbeat_interval;

    while (!shutdown_) {
        std::unique_lock<std::mutex> lock(write_mutex_);

        // Wait with timeout for heartbeat
        auto wait_result = write_cv_.wait_until(lock, next_heartbeat, [this] {
            return !write_queue_.empty() || shutdown_;
        });

        if (shutdown_) break;

        // Process queued messages
        while (!write_queue_.empty()) {
            auto msg = std::move(write_queue_.front());
            write_queue_.pop();
            lock.unlock();

            if (!stream_->Write(msg)) {
                LOG_ERROR("ControlChannel: Write failed");
                if (!shutdown_) {
                    reconnect();
                }
                return;
            }

            lock.lock();
        }
        lock.unlock();

        // Check if it's time for heartbeat
        auto now = std::chrono::steady_clock::now();
        if (now >= next_heartbeat && state_ == State::CONNECTED) {
            // Check for missed pongs
            auto since_pong = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_pong_).count();

            if (since_pong > NetworkConstants::DEFAULT_HEARTBEAT_INTERVAL * 3) {
                LOG_WARN("ControlChannel: No pong received for {}s, reconnecting", since_pong);
                reconnect();
                return;
            }

            // Send ping
            auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

            edgelink::ControlMessage msg;
            auto* ping = msg.mutable_ping();
            ping->set_timestamp(ts);
            send_message(msg);

            next_heartbeat = now + heartbeat_interval;
        }
    }
}

void ControlChannel::send_message(const edgelink::ControlMessage& msg) {
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_queue_.push(msg);
    }
    write_cv_.notify_one();
}

// ============================================================================
// Authentication
// ============================================================================

void ControlChannel::do_authenticate() {
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    edgelink::ControlMessage msg;
    auto* auth_req = msg.mutable_auth_request();

    auth_req->set_machine_key_pub(machine_key_pub_b64_);
    auth_req->set_node_key_pub("");  // Will be set by crypto engine
    auth_req->set_timestamp(ts);
    auth_req->set_signature("");  // TODO: Sign with machine key

    // System info
    #ifdef _WIN32
    auth_req->set_os("windows");
    #elif __linux__
    auth_req->set_os("linux");
    #elif __APPLE__
    auth_req->set_os("darwin");
    #else
    auth_req->set_os("unknown");
    #endif

    #ifdef __x86_64__
    auth_req->set_arch("amd64");
    #elif __aarch64__
    auth_req->set_arch("arm64");
    #elif _M_X64
    auth_req->set_arch("amd64");
    #elif _M_ARM64
    auth_req->set_arch("arm64");
    #else
    auth_req->set_arch("unknown");
    #endif

    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    auth_req->set_hostname(hostname);
    auth_req->set_version("0.1.0");

    // Set auth_key for auto-registration
    if (!auth_key_.empty()) {
        auth_req->set_auth_key(auth_key_);
    }

    send_message(msg);
    LOG_DEBUG("ControlChannel: Authentication request sent");
}

void ControlChannel::on_auth_response(const edgelink::AuthResponse& response) {
    if (!response.success()) {
        LOG_ERROR("ControlChannel: Authentication failed: {}",
                  response.error_message());
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected(ErrorCode::AUTH_FAILED);
        }
        // Don't call disconnect() here - it would deadlock since we're in read_loop
        // Instead, set shutdown flag and let the stream end naturally
        shutdown_ = true;
        if (context_) {
            context_->TryCancel();
        }
        state_ = State::DISCONNECTED;
        return;
    }

    node_id_ = response.node_id();
    virtual_ip_ = response.virtual_ip();
    auth_token_ = response.auth_token();
    relay_token_ = response.relay_token();

    LOG_INFO("ControlChannel: Authenticated as node {} ({})",
             node_id_, virtual_ip_);

    state_ = State::CONNECTED;
    reconnect_attempts_ = 0;
    last_pong_ = std::chrono::steady_clock::now();

    if (callbacks_.on_connected) {
        callbacks_.on_connected();
    }
}

// ============================================================================
// Message Handling
// ============================================================================

void ControlChannel::process_message(const edgelink::ControlMessage& msg) {
    switch (msg.message_case()) {
        case edgelink::ControlMessage::kAuthResponse:
            on_auth_response(msg.auth_response());
            break;

        case edgelink::ControlMessage::kConfig:
            handle_config(msg.config());
            break;

        case edgelink::ControlMessage::kConfigUpdate:
            handle_config_update(msg.config_update());
            break;

        case edgelink::ControlMessage::kP2PEndpoint:
            handle_p2p_endpoint(msg.p2p_endpoint());
            break;

        case edgelink::ControlMessage::kPong:
            handle_pong(msg.pong());
            break;

        case edgelink::ControlMessage::kError:
            handle_error(msg.error());
            break;

        default:
            LOG_WARN("ControlChannel: Unknown message type: {}",
                     static_cast<int>(msg.message_case()));
            break;
    }
}

void ControlChannel::handle_config(const edgelink::Config& config) {
    auto update = convert_config(config);
    update.auth_token = auth_token_;
    update.relay_token = relay_token_;
    update.timestamp = std::chrono::system_clock::now();

    // Store network config
    network_config_ = update.network;

    if (callbacks_.on_config_update) {
        callbacks_.on_config_update(update);
    }
}

void ControlChannel::handle_config_update(const edgelink::ConfigUpdate& update) {
    // Handle IP change from controller
    if (update.has_ip_change()) {
        const auto& ip_change = update.ip_change();
        std::string old_ip = virtual_ip_;
        std::string new_ip = ip_change.new_ip();

        LOG_INFO("ControlChannel: IP change notification - {} -> {} (reason: {})",
                 old_ip, new_ip, ip_change.reason());

        // Update local state
        virtual_ip_ = new_ip;

        // Notify client to update TUN device
        if (callbacks_.on_ip_change) {
            callbacks_.on_ip_change(old_ip, new_ip, ip_change.reason());
        }
    }

    // Handle incremental updates
    for (const auto& peer_update : update.peer_updates()) {
        if (peer_update.action() == edgelink::ACTION_ADD ||
            peer_update.action() == edgelink::ACTION_UPDATE) {
            auto peer = convert_peer(peer_update.peer());
            if (peer.online && callbacks_.on_peer_online) {
                callbacks_.on_peer_online(peer.node_id, peer);
            }
        } else if (peer_update.action() == edgelink::ACTION_REMOVE) {
            if (callbacks_.on_peer_offline) {
                callbacks_.on_peer_offline(peer_update.peer().node_id());
            }
        }
    }

    // Handle token refresh
    if (update.has_new_relay_token()) {
        relay_token_ = update.new_relay_token();
        if (callbacks_.on_token_refresh) {
            callbacks_.on_token_refresh(auth_token_, relay_token_);
        }
    }
}

void ControlChannel::handle_p2p_endpoint(const edgelink::P2PEndpoint& endpoint) {
    std::vector<std::string> endpoints;
    for (const auto& ep : endpoint.endpoints()) {
        endpoints.push_back(ep.ip() + ":" + std::to_string(ep.port()));
    }

    std::string nat_type;
    switch (endpoint.nat_type()) {
        case edgelink::NAT_OPEN: nat_type = "open"; break;
        case edgelink::NAT_FULL_CONE: nat_type = "full_cone"; break;
        case edgelink::NAT_RESTRICTED_CONE: nat_type = "restricted_cone"; break;
        case edgelink::NAT_PORT_RESTRICTED: nat_type = "port_restricted"; break;
        case edgelink::NAT_SYMMETRIC: nat_type = "symmetric"; break;
        default: nat_type = "unknown"; break;
    }

    if (callbacks_.on_p2p_endpoints) {
        callbacks_.on_p2p_endpoints(endpoint.peer_node_id(), endpoints, nat_type);
    }
}

void ControlChannel::handle_pong(const edgelink::Pong& pong) {
    last_pong_ = std::chrono::steady_clock::now();
    missed_pongs_ = 0;
}

void ControlChannel::handle_error(const edgelink::Error& error) {
    LOG_ERROR("ControlChannel: Server error: {} - {}",
              static_cast<int>(error.code()), error.message());
}

// ============================================================================
// Reconnection
// ============================================================================

void ControlChannel::schedule_reconnect() {
    if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
        LOG_ERROR("ControlChannel: Max reconnect attempts reached");
        state_ = State::DISCONNECTED;
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected(ErrorCode::MAX_RETRIES_EXCEEDED);
        }
        return;
    }

    // Exponential backoff
    auto delay = INITIAL_RECONNECT_DELAY * (1 << std::min(reconnect_attempts_, 6u));
    if (delay > MAX_RECONNECT_DELAY) {
        delay = MAX_RECONNECT_DELAY;
    }

    LOG_INFO("ControlChannel: Reconnecting in {} seconds (attempt {})",
             std::chrono::duration_cast<std::chrono::seconds>(delay).count(),
             reconnect_attempts_ + 1);

    std::this_thread::sleep_for(delay);
    reconnect_attempts_++;

    // Clean up old resources
    if (read_thread_ && read_thread_->joinable()) {
        read_thread_->join();
    }
    if (write_thread_ && write_thread_->joinable()) {
        write_cv_.notify_all();
        write_thread_->join();
    }

    read_thread_.reset();
    write_thread_.reset();
    stream_.reset();
    context_.reset();

    last_pong_ = std::chrono::steady_clock::now();
    state_ = State::CONNECTING;

    LOG_INFO("ControlChannel: Connecting to {}:{}",
             controller_host_, controller_port_);
    run_stream();
}

// ============================================================================
// Control Messages
// ============================================================================

void ControlChannel::report_latency(uint32_t peer_node_id, uint32_t relay_id,
                                    uint32_t latency_ms) {
    if (state_ != State::CONNECTED) {
        return;
    }

    edgelink::ControlMessage msg;
    auto* report = msg.mutable_latency_report();
    auto* entry = report->add_entries();
    entry->set_dst_type("relay");
    entry->set_dst_id(relay_id);
    entry->set_rtt_ms(latency_ms);

    send_message(msg);
}

void ControlChannel::report_latency_batch(
    const std::vector<LatencyMeasurement>& measurements) {
    if (state_ != State::CONNECTED || measurements.empty()) {
        return;
    }

    edgelink::ControlMessage msg;
    auto* report = msg.mutable_latency_report();

    for (const auto& m : measurements) {
        auto* entry = report->add_entries();
        entry->set_dst_type(m.peer_id > 0 ? "node" : "relay");
        entry->set_dst_id(m.peer_id > 0 ? m.peer_id : m.server_id);
        entry->set_rtt_ms(m.rtt_ms);
    }

    LOG_DEBUG("ControlChannel: Reporting {} latency measurements",
              measurements.size());
    send_message(msg);
}

void ControlChannel::report_relay_connection(uint32_t server_id, bool connected) {
    if (state_ != State::CONNECTED) {
        return;
    }

    // Use P2P status to report relay connection
    edgelink::ControlMessage msg;
    auto* status = msg.mutable_p2p_status();
    status->set_peer_node_id(0);  // 0 indicates relay
    status->set_connected(connected);

    send_message(msg);
}

void ControlChannel::report_endpoints(const std::vector<std::string>& endpoints) {
    if (state_ != State::CONNECTED) {
        return;
    }

    // Use P2P status to report our endpoints
    edgelink::ControlMessage msg;
    auto* status = msg.mutable_p2p_status();
    status->set_peer_node_id(node_id_);
    status->set_connected(true);

    if (!endpoints.empty()) {
        // Parse first endpoint for reporting
        auto pos = endpoints[0].find(':');
        if (pos != std::string::npos) {
            status->set_endpoint_ip(endpoints[0].substr(0, pos));
            status->set_endpoint_port(
                std::stoi(endpoints[0].substr(pos + 1)));
        }
    }

    send_message(msg);
}

void ControlChannel::request_peer_endpoints(uint32_t peer_node_id) {
    if (state_ != State::CONNECTED) {
        return;
    }

    LOG_DEBUG("ControlChannel: Requesting P2P endpoints for peer {}",
              peer_node_id);

    edgelink::ControlMessage msg;
    auto* init = msg.mutable_p2p_init();
    init->set_peer_node_id(peer_node_id);

    send_message(msg);
}

void ControlChannel::report_key_rotation(
    const std::array<uint8_t, 32>& new_pubkey,
    const std::string& signature_b64) {
    if (state_ != State::CONNECTED) {
        return;
    }

    // Key rotation is handled through auth request with new key
    LOG_WARN("ControlChannel: Key rotation not yet implemented in gRPC");
}

// ============================================================================
// Conversion Helpers
// ============================================================================

ConfigUpdate ControlChannel::convert_config(const edgelink::Config& proto_config) {
    ConfigUpdate config;

    config.network.network_id = proto_config.network_id();
    config.network.network_name = proto_config.network_name();
    config.network.cidr = proto_config.subnet();

    // Convert peers
    for (const auto& proto_peer : proto_config.peers()) {
        config.peers.push_back(convert_peer(proto_peer));
    }

    // Convert relays
    for (const auto& proto_relay : proto_config.relays()) {
        config.relays.push_back(convert_relay(proto_relay));
    }

    // Convert routes
    for (const auto& proto_route : proto_config.routes()) {
        SubnetRouteInfo route;
        route.cidr = proto_route.cidr();
        route.via_node_id = proto_route.gateway_node_id();
        route.priority = proto_route.priority();
        route.weight = proto_route.weight();
        route.gateway_online = proto_route.enabled();
        config.subnet_routes.push_back(route);
    }

    config.relay_token = proto_config.new_relay_token();

    return config;
}

PeerInfo ControlChannel::convert_peer(const edgelink::PeerInfo& proto_peer) {
    PeerInfo peer;

    peer.node_id = proto_peer.node_id();
    peer.hostname = proto_peer.name();
    peer.virtual_ip = proto_peer.virtual_ip();
    peer.online = proto_peer.online();

    // Decode node_key_pub from base64
    std::string key_b64 = proto_peer.node_key_pub();
    if (!key_b64.empty()) {
        auto key_bytes = decode_base64(key_b64);
        if (key_bytes.size() == 32) {
            std::copy(key_bytes.begin(), key_bytes.end(),
                      peer.node_key_pub.begin());
        }
    }

    // Convert endpoints
    for (const auto& ep : proto_peer.endpoints()) {
        peer.endpoints.push_back(ep.ip() + ":" + std::to_string(ep.port()));
    }

    return peer;
}

RelayServerInfo ControlChannel::convert_relay(
    const edgelink::RelayInfo& proto_relay) {
    RelayServerInfo relay;

    relay.id = proto_relay.server_id();
    relay.name = proto_relay.name();
    relay.region = proto_relay.region();
    relay.url = proto_relay.url();  // gRPC URL: grpc://host:port or grpcs://host:port

    return relay;
}

} // namespace edgelink::client

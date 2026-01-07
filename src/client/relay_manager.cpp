#include "client/relay_manager.hpp"
#include "common/log.hpp"

#include <nlohmann/json.hpp>

namespace edgelink::client {

using json = nlohmann::json;

// ============================================================================
// Constructor / Destructor
// ============================================================================

RelayManager::RelayManager(
    net::io_context& ioc,
    ssl::context& ssl_ctx,
    uint32_t local_node_id,
    const std::string& relay_token
)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , resolver_(ioc)
    , local_node_id_(local_node_id)
    , relay_token_(relay_token)
    , latency_timer_(ioc)
{
    LOG_INFO("RelayManager: Initialized for node {}", local_node_id);
}

RelayManager::~RelayManager() {
    disconnect_all();
}

void RelayManager::set_callbacks(RelayManagerCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void RelayManager::update_token(const std::string& new_token) {
    relay_token_ = new_token;
    LOG_DEBUG("RelayManager: Token updated");
}

// ============================================================================
// Configuration
// ============================================================================

void RelayManager::update_relays(const std::vector<RelayServerInfo>& relays) {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    
    // Track which relays to remove
    std::vector<uint32_t> to_remove;
    for (auto& [id, _] : relays_) {
        bool found = false;
        for (auto& info : relays) {
            if (info.server_id == id) {
                found = true;
                break;
            }
        }
        if (!found) {
            to_remove.push_back(id);
        }
    }
    
    // Remove old relays
    for (auto id : to_remove) {
        auto it = relays_.find(id);
        if (it != relays_.end()) {
            if (it->second->ws && it->second->ws->is_open()) {
                beast::error_code ec;
                it->second->ws->close(websocket::close_code::normal, ec);
            }
            relays_.erase(it);
        }
    }
    
    // Add/update relays
    for (auto& info : relays) {
        auto it = relays_.find(info.server_id);
        if (it == relays_.end()) {
            // New relay
            auto relay = std::make_shared<RelayConnection>();
            relay->server_id = info.server_id;
            relay->host = info.host;
            relay->port = info.port;
            relay->path = info.path;
            relay->region = info.region;
            relays_[info.server_id] = relay;
            
            LOG_INFO("RelayManager: Added relay {} ({}:{})", 
                     info.server_id, info.host, info.port);
        } else {
            // Update existing
            it->second->host = info.host;
            it->second->port = info.port;
            it->second->path = info.path;
            it->second->region = info.region;
        }
    }
}

void RelayManager::update_paths(const std::vector<PeerPath>& paths) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    
    for (auto& path : paths) {
        peer_paths_[path.peer_node_id] = path;
    }
    
    LOG_DEBUG("RelayManager: Updated {} peer paths", paths.size());
}

// ============================================================================
// Connection Management
// ============================================================================

void RelayManager::connect_all() {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    
    for (auto& [id, relay] : relays_) {
        if (relay->state == RelayConnection::State::DISCONNECTED) {
            do_connect_relay(relay);
        }
    }
}

void RelayManager::connect_relay(uint32_t relay_id) {
    std::shared_ptr<RelayConnection> relay;
    
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) {
            LOG_ERROR("RelayManager: Unknown relay ID {}", relay_id);
            return;
        }
        relay = it->second;
    }
    
    if (relay->state == RelayConnection::State::DISCONNECTED) {
        do_connect_relay(relay);
    }
}

void RelayManager::disconnect_relay(uint32_t relay_id) {
    std::shared_ptr<RelayConnection> relay;
    
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) {
            return;
        }
        relay = it->second;
    }
    
    if (relay->ws && relay->ws->is_open()) {
        beast::error_code ec;
        relay->ws->close(websocket::close_code::normal, ec);
    }
    
    relay->state = RelayConnection::State::DISCONNECTED;
    
    // Cancel heartbeat
    auto timer_it = heartbeat_timers_.find(relay_id);
    if (timer_it != heartbeat_timers_.end() && timer_it->second) {
        timer_it->second->cancel();
    }
}

void RelayManager::disconnect_all() {
    latency_timer_.cancel();
    
    std::lock_guard<std::mutex> lock(relays_mutex_);
    
    for (auto& [id, relay] : relays_) {
        if (relay->ws && relay->ws->is_open()) {
            beast::error_code ec;
            relay->ws->close(websocket::close_code::normal, ec);
        }
        relay->state = RelayConnection::State::DISCONNECTED;
    }
    
    for (auto& [id, timer] : heartbeat_timers_) {
        if (timer) {
            timer->cancel();
        }
    }
    heartbeat_timers_.clear();
}

// ============================================================================
// Connection Flow
// ============================================================================

void RelayManager::do_connect_relay(std::shared_ptr<RelayConnection> relay) {
    relay->state = RelayConnection::State::CONNECTING;
    
    LOG_INFO("RelayManager: Connecting to relay {} ({}:{})", 
             relay->server_id, relay->host, relay->port);
    
    resolver_.async_resolve(
        relay->host,
        std::to_string(relay->port),
        [self = shared_from_this(), relay](beast::error_code ec, tcp::resolver::results_type results) {
            self->on_relay_resolve(relay, ec, results);
        }
    );
}

void RelayManager::on_relay_resolve(std::shared_ptr<RelayConnection> relay, beast::error_code ec,
                                    tcp::resolver::results_type results) {
    if (ec) {
        LOG_ERROR("RelayManager: Resolve failed for relay {}: {}", relay->server_id, ec.message());
        schedule_relay_reconnect(relay);
        return;
    }
    
    auto ep = results.begin()->endpoint();
    
    relay->ws = std::make_unique<RelayConnection::WsStream>(ioc_, ssl_ctx_);
    
    // Set SNI hostname
    if (!SSL_set_tlsext_host_name(relay->ws->next_layer().native_handle(), relay->host.c_str())) {
        LOG_ERROR("RelayManager: Failed to set SNI for relay {}", relay->server_id);
    }
    
    beast::get_lowest_layer(*relay->ws).expires_after(std::chrono::seconds(30));
    
    beast::get_lowest_layer(*relay->ws).async_connect(
        ep,
        [self = shared_from_this(), relay](beast::error_code ec) {
            self->on_relay_connect(relay, ec);
        }
    );
}

void RelayManager::on_relay_connect(std::shared_ptr<RelayConnection> relay, beast::error_code ec) {
    if (ec) {
        LOG_ERROR("RelayManager: TCP connect failed for relay {}: {}", relay->server_id, ec.message());
        schedule_relay_reconnect(relay);
        return;
    }
    
    beast::get_lowest_layer(*relay->ws).expires_after(std::chrono::seconds(30));
    
    relay->ws->next_layer().async_handshake(
        ssl::stream_base::client,
        [self = shared_from_this(), relay](beast::error_code ec) {
            self->on_relay_ssl_handshake(relay, ec);
        }
    );
}

void RelayManager::on_relay_ssl_handshake(std::shared_ptr<RelayConnection> relay, beast::error_code ec) {
    if (ec) {
        LOG_ERROR("RelayManager: SSL handshake failed for relay {}: {}", relay->server_id, ec.message());
        schedule_relay_reconnect(relay);
        return;
    }
    
    beast::get_lowest_layer(*relay->ws).expires_never();
    
    relay->ws->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
    
    // Include relay_token in auth header
    relay->ws->set_option(websocket::stream_base::decorator(
        [this](websocket::request_type& req) {
            req.set(beast::http::field::authorization, "Bearer " + relay_token_);
            req.set(beast::http::field::user_agent, "edgelink-client/1.0");
        }
    ));
    
    relay->ws->async_handshake(
        relay->host,
        relay->path,
        [self = shared_from_this(), relay](beast::error_code ec) {
            self->on_relay_ws_handshake(relay, ec);
        }
    );
}

void RelayManager::on_relay_ws_handshake(std::shared_ptr<RelayConnection> relay, beast::error_code ec) {
    if (ec) {
        LOG_ERROR("RelayManager: WebSocket handshake failed for relay {}: {}", relay->server_id, ec.message());
        schedule_relay_reconnect(relay);
        return;
    }
    
    LOG_INFO("RelayManager: Connected to relay {}", relay->server_id);
    
    // Start reading
    do_relay_read(relay);
    
    // Send auth frame
    do_relay_auth(relay);
}

// ============================================================================
// Authentication
// ============================================================================

void RelayManager::do_relay_auth(std::shared_ptr<RelayConnection> relay) {
    json auth_data;
    auth_data["token"] = relay_token_;
    auth_data["node_id"] = local_node_id_;
    
    std::string payload = auth_data.dump();
    
    Frame frame;
    frame.type = FrameType::RELAY_AUTH;
    frame.src_id = local_node_id_;
    frame.dst_id = relay->server_id;
    frame.payload.assign(payload.begin(), payload.end());
    
    send_to_relay(relay, std::move(frame));
}

void RelayManager::on_relay_auth_response(std::shared_ptr<RelayConnection> relay, const Frame& frame) {
    try {
        std::string payload_str(frame.payload.begin(), frame.payload.end());
        json response = json::parse(payload_str);
        
        if (!response.value("success", false)) {
            LOG_ERROR("RelayManager: Auth failed for relay {}: {}", 
                      relay->server_id, response.value("error", "Unknown"));
            schedule_relay_reconnect(relay);
            return;
        }
        
        relay->state = RelayConnection::State::CONNECTED;
        relay->reconnect_attempts = 0;
        relay->last_pong = std::chrono::steady_clock::now();
        
        LOG_INFO("RelayManager: Authenticated to relay {}", relay->server_id);
        
        // Start heartbeat
        start_relay_heartbeat(relay);
        
        // Notify callback
        if (callbacks_.on_relay_state_changed) {
            callbacks_.on_relay_state_changed(relay->server_id, RelayConnection::State::CONNECTED);
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("RelayManager: Failed to parse auth response: {}", e.what());
        schedule_relay_reconnect(relay);
    }
}

// ============================================================================
// Reading
// ============================================================================

void RelayManager::do_relay_read(std::shared_ptr<RelayConnection> relay) {
    relay->ws->async_read(
        relay->read_buffer,
        [self = shared_from_this(), relay](beast::error_code ec, std::size_t bytes) {
            self->on_relay_read(relay, ec, bytes);
        }
    );
}

void RelayManager::on_relay_read(std::shared_ptr<RelayConnection> relay, beast::error_code ec,
                                  std::size_t bytes_transferred) {
    if (ec) {
        if (ec == websocket::error::closed) {
            LOG_INFO("RelayManager: Relay {} connection closed", relay->server_id);
        } else {
            LOG_ERROR("RelayManager: Read error from relay {}: {}", relay->server_id, ec.message());
        }
        
        relay->state = RelayConnection::State::DISCONNECTED;
        
        if (callbacks_.on_relay_state_changed) {
            callbacks_.on_relay_state_changed(relay->server_id, RelayConnection::State::DISCONNECTED);
        }
        
        schedule_relay_reconnect(relay);
        return;
    }
    
    relay->bytes_received += bytes_transferred;
    relay->packets_received++;
    
    // Parse frame
    auto data = beast::buffers_to_string(relay->read_buffer.data());
    relay->read_buffer.consume(bytes_transferred);
    
    std::vector<uint8_t> frame_data(data.begin(), data.end());
    auto frame_result = Frame::deserialize(frame_data);
    
    if (!frame_result) {
        LOG_ERROR("RelayManager: Failed to deserialize frame from relay {}", relay->server_id);
        do_relay_read(relay);
        return;
    }
    
    process_relay_frame(relay, *frame_result);
    
    // Continue reading
    if (relay->state != RelayConnection::State::DISCONNECTED) {
        do_relay_read(relay);
    }
}

void RelayManager::process_relay_frame(std::shared_ptr<RelayConnection> relay, const Frame& frame) {
    switch (frame.type) {
        case FrameType::RELAY_AUTH: {
            on_relay_auth_response(relay, frame);
            break;
        }
        
        case FrameType::DATA: {
            // Forward to callback
            if (callbacks_.on_data_received) {
                callbacks_.on_data_received(frame.src_id, frame.payload);
            }
            break;
        }
        
        case FrameType::PING: {
            // Respond with PONG
            Frame pong;
            pong.type = FrameType::PONG;
            pong.src_id = local_node_id_;
            pong.dst_id = relay->server_id;
            pong.payload = frame.payload;
            send_to_relay(relay, std::move(pong));
            break;
        }
        
        case FrameType::PONG: {
            relay->last_pong = std::chrono::steady_clock::now();
            relay->missed_pongs = 0;
            
            // Calculate latency
            auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                relay->last_pong - relay->last_ping
            ).count();
            relay->latency_ms = static_cast<uint32_t>(rtt);
            
            // Check if this is a latency probe response
            if (frame.payload.size() >= 8) {
                uint32_t probe_peer_id;
                std::memcpy(&probe_peer_id, frame.payload.data() + 4, 4);
                
                if (probe_peer_id != 0) {
                    uint64_t key = (static_cast<uint64_t>(relay->server_id) << 32) | probe_peer_id;
                    
                    std::lock_guard<std::mutex> lock(probes_mutex_);
                    auto it = pending_probes_.find(key);
                    if (it != pending_probes_.end()) {
                        auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - it->second
                        ).count();
                        pending_probes_.erase(it);
                        
                        {
                            std::lock_guard<std::mutex> lat_lock(latency_mutex_);
                            latency_data_[relay->server_id][probe_peer_id] = static_cast<uint32_t>(latency);
                        }
                        
                        if (callbacks_.on_latency_measured) {
                            callbacks_.on_latency_measured(relay->server_id, probe_peer_id, 
                                                          static_cast<uint32_t>(latency));
                        }
                    }
                }
            }
            break;
        }
        
        default:
            LOG_WARN("RelayManager: Unexpected frame type {} from relay {}", 
                     static_cast<int>(frame.type), relay->server_id);
            break;
    }
}

// ============================================================================
// Writing
// ============================================================================

void RelayManager::send_to_relay(std::shared_ptr<RelayConnection> relay, Frame frame) {
    auto data = frame.serialize();
    
    {
        std::lock_guard<std::mutex> lock(relay->write_mutex);
        relay->write_queue.push(std::move(data));
    }
    
    if (!relay->writing.exchange(true)) {
        do_relay_write(relay);
    }
}

void RelayManager::do_relay_write(std::shared_ptr<RelayConnection> relay) {
    std::vector<uint8_t> data;
    
    {
        std::lock_guard<std::mutex> lock(relay->write_mutex);
        if (relay->write_queue.empty()) {
            relay->writing = false;
            return;
        }
        data = std::move(relay->write_queue.front());
        relay->write_queue.pop();
    }
    
    relay->bytes_sent += data.size();
    relay->packets_sent++;
    
    relay->ws->binary(true);
    relay->ws->async_write(
        net::buffer(data),
        [self = shared_from_this(), relay](beast::error_code ec, std::size_t) {
            if (ec) {
                LOG_ERROR("RelayManager: Write error to relay {}: {}", relay->server_id, ec.message());
                return;
            }
            self->do_relay_write(relay);
        }
    );
}

// ============================================================================
// Heartbeat
// ============================================================================

void RelayManager::start_relay_heartbeat(std::shared_ptr<RelayConnection> relay) {
    auto& timer = heartbeat_timers_[relay->server_id];
    if (!timer) {
        timer = std::make_unique<net::steady_timer>(ioc_);
    }
    
    timer->expires_after(std::chrono::seconds(NetworkConstants::DEFAULT_HEARTBEAT_INTERVAL));
    timer->async_wait([self = shared_from_this(), relay, this](boost::system::error_code ec) {
        if (!ec) {
            self->on_relay_heartbeat(relay);
        }
    });
}

void RelayManager::on_relay_heartbeat(std::shared_ptr<RelayConnection> relay) {
    if (relay->state != RelayConnection::State::CONNECTED) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto since_pong = std::chrono::duration_cast<std::chrono::seconds>(now - relay->last_pong).count();
    
    if (since_pong > NetworkConstants::DEFAULT_HEARTBEAT_INTERVAL * 3) {
        LOG_WARN("RelayManager: No pong from relay {} for {}s, reconnecting", relay->server_id, since_pong);
        relay->state = RelayConnection::State::DISCONNECTED;
        schedule_relay_reconnect(relay);
        return;
    }
    
    // Send PING
    relay->last_ping = now;
    
    Frame ping;
    ping.type = FrameType::PING;
    ping.src_id = local_node_id_;
    ping.dst_id = relay->server_id;
    
    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    ping.payload.resize(8);
    std::memcpy(ping.payload.data(), &ts, 8);
    
    send_to_relay(relay, std::move(ping));
    
    // Reschedule
    start_relay_heartbeat(relay);
}

// ============================================================================
// Reconnection
// ============================================================================

void RelayManager::schedule_relay_reconnect(std::shared_ptr<RelayConnection> relay) {
    if (relay->reconnect_attempts >= 10) {
        LOG_ERROR("RelayManager: Max reconnect attempts for relay {}", relay->server_id);
        relay->state = RelayConnection::State::DISCONNECTED;
        return;
    }
    
    relay->state = RelayConnection::State::RECONNECTING;
    
    // Exponential backoff
    auto delay = std::chrono::seconds(1 << std::min(relay->reconnect_attempts, 6u));
    
    LOG_INFO("RelayManager: Reconnecting to relay {} in {}s", 
             relay->server_id, delay.count());
    
    auto& timer = heartbeat_timers_[relay->server_id];
    if (!timer) {
        timer = std::make_unique<net::steady_timer>(ioc_);
    }
    timer->expires_after(delay);
    timer->async_wait([self = shared_from_this(), relay](boost::system::error_code ec) {
        if (!ec) {
            self->on_relay_reconnect(relay);
        }
    });
}

void RelayManager::on_relay_reconnect(std::shared_ptr<RelayConnection> relay) {
    relay->reconnect_attempts++;
    
    if (relay->ws) {
        beast::error_code ec;
        if (relay->ws->is_open()) {
            relay->ws->close(websocket::close_code::going_away, ec);
        }
        relay->ws.reset();
    }
    
    do_connect_relay(relay);
}

// ============================================================================
// Data Transmission
// ============================================================================

std::expected<void, ErrorCode> RelayManager::send_to_peer(
    uint32_t dst_node_id,
    const std::vector<uint8_t>& encrypted_data
) {
    // Get best relay for this peer
    uint32_t relay_id = get_best_relay(dst_node_id);
    if (relay_id == 0) {
        LOG_ERROR("RelayManager: No relay available for peer {}", dst_node_id);
        return std::unexpected(ErrorCode::NO_RELAY_AVAILABLE);
    }
    
    return send_via_relay(relay_id, dst_node_id, encrypted_data);
}

std::expected<void, ErrorCode> RelayManager::send_via_relay(
    uint32_t relay_id,
    uint32_t dst_node_id,
    const std::vector<uint8_t>& encrypted_data
) {
    std::shared_ptr<RelayConnection> relay;
    
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) {
            return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        relay = it->second;
    }
    
    if (relay->state != RelayConnection::State::CONNECTED) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }
    
    Frame frame;
    frame.type = FrameType::DATA;
    frame.src_id = local_node_id_;
    frame.dst_id = dst_node_id;
    frame.relay_id = relay_id;
    frame.payload = encrypted_data;
    
    send_to_relay(relay, std::move(frame));
    return {};
}

// ============================================================================
// Latency Measurement
// ============================================================================

void RelayManager::measure_latency_to_peer(uint32_t peer_node_id) {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    
    for (auto& [id, relay] : relays_) {
        if (relay->state == RelayConnection::State::CONNECTED) {
            send_latency_probe(relay, peer_node_id);
        }
    }
}

void RelayManager::send_latency_probe(std::shared_ptr<RelayConnection> relay, uint32_t peer_node_id) {
    auto now = std::chrono::steady_clock::now();
    
    uint64_t key = (static_cast<uint64_t>(relay->server_id) << 32) | peer_node_id;
    {
        std::lock_guard<std::mutex> lock(probes_mutex_);
        pending_probes_[key] = now;
    }
    
    Frame ping;
    ping.type = FrameType::PING;
    ping.src_id = local_node_id_;
    ping.dst_id = peer_node_id;
    ping.relay_id = relay->server_id;
    
    // Payload: timestamp(8) + peer_id(4)
    ping.payload.resize(12);
    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::memcpy(ping.payload.data(), &ts, 8);
    std::memcpy(ping.payload.data() + 8, &peer_node_id, 4);
    
    send_to_relay(relay, std::move(ping));
}

void RelayManager::start_latency_measurements() {
    latency_measuring_ = true;
    on_latency_timer();
}

void RelayManager::stop_latency_measurements() {
    latency_measuring_ = false;
    latency_timer_.cancel();
}

void RelayManager::on_latency_timer() {
    if (!latency_measuring_) {
        return;
    }
    
    // Measure to all known peers
    std::vector<uint32_t> peers;
    {
        std::lock_guard<std::mutex> lock(paths_mutex_);
        for (auto& [peer_id, _] : peer_paths_) {
            peers.push_back(peer_id);
        }
    }
    
    for (auto peer_id : peers) {
        measure_latency_to_peer(peer_id);
    }
    
    // Reschedule
    latency_timer_.expires_after(std::chrono::seconds(30));
    latency_timer_.async_wait([self = shared_from_this()](boost::system::error_code ec) {
        if (!ec) {
            self->on_latency_timer();
        }
    });
}

// ============================================================================
// Status
// ============================================================================

uint32_t RelayManager::get_best_relay(uint32_t peer_node_id) const {
    // First check if we have a configured path
    {
        std::lock_guard<std::mutex> lock(paths_mutex_);
        auto it = peer_paths_.find(peer_node_id);
        if (it != peer_paths_.end() && it->second.primary_relay_id != 0) {
            // Verify relay is connected
            std::lock_guard<std::mutex> relay_lock(relays_mutex_);
            auto relay_it = relays_.find(it->second.primary_relay_id);
            if (relay_it != relays_.end() && 
                relay_it->second->state == RelayConnection::State::CONNECTED) {
                return it->second.primary_relay_id;
            }
            
            // Try backup
            if (it->second.backup_relay_id != 0) {
                relay_it = relays_.find(it->second.backup_relay_id);
                if (relay_it != relays_.end() &&
                    relay_it->second->state == RelayConnection::State::CONNECTED) {
                    return it->second.backup_relay_id;
                }
            }
        }
    }
    
    // Fall back to lowest latency connected relay
    uint32_t best_relay = 0;
    uint32_t best_latency = UINT32_MAX;
    
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        for (auto& [id, relay] : relays_) {
            if (relay->state == RelayConnection::State::CONNECTED) {
                if (relay->latency_ms < best_latency) {
                    best_latency = relay->latency_ms;
                    best_relay = id;
                }
            }
        }
    }
    
    return best_relay;
}

RelayConnection::State RelayManager::get_relay_state(uint32_t relay_id) const {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    auto it = relays_.find(relay_id);
    if (it == relays_.end()) {
        return RelayConnection::State::DISCONNECTED;
    }
    return it->second->state.load();
}

std::vector<uint32_t> RelayManager::get_connected_relays() const {
    std::vector<uint32_t> result;
    std::lock_guard<std::mutex> lock(relays_mutex_);
    
    for (auto& [id, relay] : relays_) {
        if (relay->state == RelayConnection::State::CONNECTED) {
            result.push_back(id);
        }
    }
    
    return result;
}

uint32_t RelayManager::get_latency(uint32_t peer_node_id, uint32_t relay_id) const {
    std::lock_guard<std::mutex> lock(latency_mutex_);
    
    auto relay_it = latency_data_.find(relay_id);
    if (relay_it == latency_data_.end()) {
        return UINT32_MAX;
    }
    
    auto peer_it = relay_it->second.find(peer_node_id);
    if (peer_it == relay_it->second.end()) {
        return UINT32_MAX;
    }
    
    return peer_it->second;
}

RelayManager::Stats RelayManager::get_stats() const {
    Stats result;
    
    std::lock_guard<std::mutex> lock(relays_mutex_);
    
    for (auto& [id, relay] : relays_) {
        if (relay->state == RelayConnection::State::CONNECTED) {
            result.connected_relays++;
        }
        result.total_bytes_sent += relay->bytes_sent;
        result.total_bytes_received += relay->bytes_received;
        result.total_packets_sent += relay->packets_sent;
        result.total_packets_received += relay->packets_received;
    }
    
    return result;
}

} // namespace edgelink::client

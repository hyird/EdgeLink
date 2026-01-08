#include "p2p_manager.hpp"
#include "common/log.hpp"

#include <cstring>
#include <algorithm>

namespace edgelink::client {

// P2P packet types (first byte)
constexpr uint8_t P2P_PACKET_PUNCH = 0x01;      // Hole punch packet
constexpr uint8_t P2P_PACKET_PING = 0x02;       // P2P ping (handshake)
constexpr uint8_t P2P_PACKET_PONG = 0x03;       // P2P pong (handshake response)
constexpr uint8_t P2P_PACKET_KEEPALIVE = 0x04;  // NAT keepalive
constexpr uint8_t P2P_PACKET_DATA = 0x10;       // Encrypted data

// ============================================================================
// Constructor / Destructor
// ============================================================================

P2PManager::P2PManager(net::io_context& ioc,
                       std::shared_ptr<EndpointManager> endpoint_manager,
                       std::shared_ptr<CryptoEngine> crypto_engine,
                       uint32_t local_node_id)
    : ioc_(ioc)
    , endpoint_manager_(std::move(endpoint_manager))
    , crypto_engine_(std::move(crypto_engine))
    , local_node_id_(local_node_id)
    , recv_buffer_(65536)
    , keepalive_timer_(ioc)
{
    LOG_INFO("P2PManager: Initialized for node {}", local_node_id);
}

P2PManager::~P2PManager() {
    stop();
}

// ============================================================================
// Lifecycle
// ============================================================================

void P2PManager::start() {
    if (running_.exchange(true)) {
        return;
    }
    
    LOG_INFO("P2PManager: Starting...");
    
    // Start receiving on the EndpointManager's UDP socket
    do_receive();
    
    // Start keepalive timer
    start_keepalive_timer();
}

void P2PManager::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    
    LOG_INFO("P2PManager: Stopping...");
    
    keepalive_timer_.cancel();
    
    // Cancel all punch timers
    for (auto& [id, timer] : punch_timers_) {
        timer->cancel();
    }
    punch_timers_.clear();
    
    // Close all connections
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [id, conn] : connections_) {
            conn->state = P2PState::DISCONNECTED;
        }
    }
}

// ============================================================================
// Connection Management
// ============================================================================

void P2PManager::initiate_connection(uint32_t peer_node_id) {
    LOG_INFO("P2PManager: Initiating P2P connection to peer {}", peer_node_id);
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    
    auto& conn = connections_[peer_node_id];
    if (!conn) {
        conn = std::make_shared<P2PConnection>();
        conn->peer_node_id = peer_node_id;
    }
    
    // Don't re-initiate if already trying or connected
    if (conn->state == P2PState::CONNECTED || 
        conn->state == P2PState::PUNCHING ||
        conn->state == P2PState::HANDSHAKING) {
        LOG_DEBUG("P2PManager: Connection to {} already in progress (state={})",
                  peer_node_id, p2p_state_to_string(conn->state));
        return;
    }
    
    conn->reset();
    set_connection_state(conn, P2PState::INITIATING);
    
    // Request punch init from controller
    if (callbacks_.on_punch_request) {
        callbacks_.on_punch_request(peer_node_id);
    }
}

void P2PManager::handle_peer_endpoints(uint32_t peer_node_id,
                                       const std::vector<Endpoint>& endpoints,
                                       NatType peer_nat_type) {
    LOG_INFO("P2PManager: Received {} endpoints for peer {}, NAT type: {}",
             endpoints.size(), peer_node_id, nat_type_to_string(peer_nat_type));
    
    // Check if P2P is feasible
    NatType our_nat = endpoint_manager_->get_nat_type();
    if (!is_p2p_feasible(our_nat, peer_nat_type)) {
        LOG_WARN("P2PManager: P2P not feasible (our NAT: {}, peer NAT: {})",
                 endpoint_manager_->get_nat_type_string(),
                 nat_type_to_string(peer_nat_type));
        
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(peer_node_id);
        if (it != connections_.end()) {
            set_connection_state(it->second, P2PState::FAILED);
        }
        return;
    }
    
    std::shared_ptr<P2PConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(peer_node_id);
        if (it == connections_.end()) {
            conn = std::make_shared<P2PConnection>();
            conn->peer_node_id = peer_node_id;
            connections_[peer_node_id] = conn;
        } else {
            conn = it->second;
        }
        
        conn->peer_endpoints = endpoints;
    }
    
    set_connection_state(conn, P2PState::EXCHANGING);
    
    // Start punching
    start_punching(conn);
}

void P2PManager::handle_p2p_init(uint32_t peer_node_id,
                                 const std::vector<Endpoint>& peer_endpoints,
                                 NatType peer_nat_type) {
    LOG_INFO("P2PManager: Peer {} wants to connect (P2P init)", peer_node_id);
    
    // Same as handle_peer_endpoints - start the punching process
    handle_peer_endpoints(peer_node_id, peer_endpoints, peer_nat_type);
}

void P2PManager::close_connection(uint32_t peer_node_id) {
    LOG_INFO("P2PManager: Closing P2P connection to peer {}", peer_node_id);
    
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(peer_node_id);
    if (it != connections_.end()) {
        set_connection_state(it->second, P2PState::DISCONNECTED);
        
        // Remove endpoint mapping
        std::lock_guard<std::mutex> ep_lock(endpoint_map_mutex_);
        std::string key = it->second->active_endpoint.address().to_string() + ":" +
                          std::to_string(it->second->active_endpoint.port());
        endpoint_to_peer_.erase(key);
    }
    
    // Cancel punch timer if any
    auto timer_it = punch_timers_.find(peer_node_id);
    if (timer_it != punch_timers_.end()) {
        timer_it->second->cancel();
        punch_timers_.erase(timer_it);
    }
}

// ============================================================================
// Data Transmission
// ============================================================================

bool P2PManager::send_to_peer(uint32_t peer_node_id, const std::vector<uint8_t>& data) {
    std::shared_ptr<P2PConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        auto it = connections_.find(peer_node_id);
        if (it == connections_.end() || it->second->state != P2PState::CONNECTED) {
            return false;
        }
        conn = it->second;
    }
    
    // Build P2P data packet
    std::vector<uint8_t> packet;
    packet.reserve(1 + 4 + data.size());
    
    packet.push_back(P2P_PACKET_DATA);
    
    // Source node ID (4 bytes)
    packet.push_back((local_node_id_ >> 24) & 0xFF);
    packet.push_back((local_node_id_ >> 16) & 0xFF);
    packet.push_back((local_node_id_ >> 8) & 0xFF);
    packet.push_back(local_node_id_ & 0xFF);
    
    // Data (already encrypted by caller)
    packet.insert(packet.end(), data.begin(), data.end());
    
    // Send via UDP
    auto& socket = endpoint_manager_->get_udp_socket();
    boost::system::error_code ec;
    socket.send_to(net::buffer(packet), conn->active_endpoint, 0, ec);
    
    if (ec) {
        LOG_WARN("P2PManager: Failed to send to peer {}: {}", peer_node_id, ec.message());
        return false;
    }
    
    conn->packets_sent++;
    conn->bytes_sent += packet.size();
    
    return true;
}

// ============================================================================
// Status
// ============================================================================

bool P2PManager::is_connected(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(peer_node_id);
    return it != connections_.end() && it->second->state == P2PState::CONNECTED;
}

P2PState P2PManager::get_state(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(peer_node_id);
    if (it == connections_.end()) {
        return P2PState::DISCONNECTED;
    }
    return it->second->state;
}

uint32_t P2PManager::get_rtt(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(peer_node_id);
    if (it == connections_.end() || it->second->state != P2PState::CONNECTED) {
        return 0;
    }
    return it->second->rtt_ms;
}

std::vector<uint32_t> P2PManager::get_connected_peers() const {
    std::vector<uint32_t> result;
    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (const auto& [id, conn] : connections_) {
        if (conn->state == P2PState::CONNECTED) {
            result.push_back(id);
        }
    }
    return result;
}

// ============================================================================
// UDP Receive
// ============================================================================

void P2PManager::do_receive() {
    if (!running_) return;
    
    auto& socket = endpoint_manager_->get_udp_socket();
    
    socket.async_receive_from(
        net::buffer(recv_buffer_),
        recv_endpoint_,
        [this, self = shared_from_this()](const boost::system::error_code& ec,
                                          std::size_t bytes_received) {
            handle_receive(ec, bytes_received, recv_endpoint_);
        }
    );
}

void P2PManager::handle_receive(const boost::system::error_code& ec,
                                std::size_t bytes_received,
                                const udp::endpoint& sender) {
    if (!running_) return;
    
    if (ec) {
        if (ec != net::error::operation_aborted) {
            LOG_WARN("P2PManager: Receive error: {}", ec.message());
        }
        do_receive();
        return;
    }
    
    if (bytes_received > 0) {
        process_p2p_packet(sender, recv_buffer_.data(), bytes_received);
    }
    
    do_receive();
}

void P2PManager::process_p2p_packet(const udp::endpoint& sender,
                                    const uint8_t* data, size_t len) {
    if (len < 1) return;
    
    uint8_t packet_type = data[0];
    
    // Find connection by sender endpoint
    auto conn = find_connection_by_endpoint(sender);
    
    switch (packet_type) {
        case P2P_PACKET_PUNCH: {
            // Received punch packet - we might have successfully punched
            LOG_DEBUG("P2PManager: Received punch packet from {}", 
                      sender.address().to_string());
            
            if (conn && (conn->state == P2PState::PUNCHING || 
                         conn->state == P2PState::EXCHANGING)) {
                // Remember this endpoint and start handshake
                conn->active_endpoint = sender;
                set_connection_state(conn, P2PState::HANDSHAKING);
                send_p2p_ping(conn);
            }
            break;
        }
        
        case P2P_PACKET_PING: {
            // Received P2P ping - respond with pong
            LOG_DEBUG("P2PManager: Received P2P ping from {}",
                      sender.address().to_string());
            
            if (len < 13) break;  // 1 + 4 + 8 = type + node_id + timestamp
            
            uint32_t sender_node_id = (data[1] << 24) | (data[2] << 16) | 
                                      (data[3] << 8) | data[4];
            
            // Find or create connection for this peer
            if (!conn) {
                std::lock_guard<std::mutex> lock(connections_mutex_);
                auto it = connections_.find(sender_node_id);
                if (it != connections_.end()) {
                    conn = it->second;
                    conn->active_endpoint = sender;
                }
            }
            
            if (conn) {
                // Send pong with their timestamp
                std::vector<uint8_t> pong;
                pong.reserve(13);
                pong.push_back(P2P_PACKET_PONG);
                pong.push_back((local_node_id_ >> 24) & 0xFF);
                pong.push_back((local_node_id_ >> 16) & 0xFF);
                pong.push_back((local_node_id_ >> 8) & 0xFF);
                pong.push_back(local_node_id_ & 0xFF);
                // Echo back their timestamp
                pong.insert(pong.end(), data + 5, data + 13);
                
                auto& socket = endpoint_manager_->get_udp_socket();
                socket.send_to(net::buffer(pong), sender);
                
                // If we were also in handshaking state, mark as connected
                if (conn->state == P2PState::HANDSHAKING ||
                    conn->state == P2PState::PUNCHING) {
                    set_connection_state(conn, P2PState::CONNECTED);
                    
                    // Update endpoint mapping
                    {
                        std::lock_guard<std::mutex> ep_lock(endpoint_map_mutex_);
                        std::string key = sender.address().to_string() + ":" +
                                          std::to_string(sender.port());
                        endpoint_to_peer_[key] = conn->peer_node_id;
                    }
                    
                    if (callbacks_.on_connected) {
                        callbacks_.on_connected(conn->peer_node_id, conn->rtt_ms);
                    }
                }
            }
            break;
        }
        
        case P2P_PACKET_PONG: {
            // Received P2P pong - handshake complete
            if (conn && len >= 13) {
                handle_p2p_pong(conn, data, len);
            }
            break;
        }
        
        case P2P_PACKET_KEEPALIVE: {
            // Received keepalive
            if (conn && conn->state == P2PState::CONNECTED) {
                handle_keepalive(conn, data, len);
            }
            break;
        }
        
        case P2P_PACKET_DATA: {
            // Received data packet
            if (conn && conn->state == P2PState::CONNECTED && len > 5) {
                conn->packets_received++;
                conn->bytes_received += len;
                conn->last_keepalive_received = std::chrono::steady_clock::now();
                conn->missed_keepalives = 0;
                
                // Extract data (skip header)
                std::vector<uint8_t> payload(data + 5, data + len);
                
                if (callbacks_.on_data_received) {
                    callbacks_.on_data_received(conn->peer_node_id, payload);
                }
            }
            break;
        }
        
        default:
            LOG_DEBUG("P2PManager: Unknown packet type 0x{:02x} from {}",
                      packet_type, sender.address().to_string());
            break;
    }
}

// ============================================================================
// UDP Hole Punching
// ============================================================================

void P2PManager::start_punching(std::shared_ptr<P2PConnection> conn) {
    LOG_INFO("P2PManager: Starting UDP hole punching for peer {}", conn->peer_node_id);
    
    set_connection_state(conn, P2PState::PUNCHING);
    conn->punch_start_time = std::chrono::steady_clock::now();
    conn->punch_attempt = 0;
    
    // Create punch timer
    auto timer = std::make_unique<net::steady_timer>(ioc_);
    punch_timers_[conn->peer_node_id] = std::move(timer);
    
    // Start punching
    on_punch_timer(conn);
}

void P2PManager::send_punch_packet(std::shared_ptr<P2PConnection> conn,
                                   const udp::endpoint& target) {
    // Build punch packet
    std::vector<uint8_t> punch;
    punch.reserve(9);
    
    punch.push_back(P2P_PACKET_PUNCH);
    
    // Source node ID
    punch.push_back((local_node_id_ >> 24) & 0xFF);
    punch.push_back((local_node_id_ >> 16) & 0xFF);
    punch.push_back((local_node_id_ >> 8) & 0xFF);
    punch.push_back(local_node_id_ & 0xFF);
    
    // Sequence number
    punch.push_back((conn->punch_attempt >> 24) & 0xFF);
    punch.push_back((conn->punch_attempt >> 16) & 0xFF);
    punch.push_back((conn->punch_attempt >> 8) & 0xFF);
    punch.push_back(conn->punch_attempt & 0xFF);
    
    auto& socket = endpoint_manager_->get_udp_socket();
    boost::system::error_code ec;
    socket.send_to(net::buffer(punch), target, 0, ec);
    
    if (ec) {
        LOG_DEBUG("P2PManager: Punch send error: {}", ec.message());
    } else {
        LOG_DEBUG("P2PManager: Sent punch #{} to {}:{}", 
                  conn->punch_attempt,
                  target.address().to_string(),
                  target.port());
    }
    
    conn->last_punch_sent = std::chrono::steady_clock::now();
}

void P2PManager::on_punch_timer(std::shared_ptr<P2PConnection> conn) {
    if (!running_) return;
    if (conn->state != P2PState::PUNCHING && conn->state != P2PState::EXCHANGING) {
        return;
    }
    
    // Check timeout
    auto elapsed = std::chrono::steady_clock::now() - conn->punch_start_time;
    if (elapsed > PUNCH_TIMEOUT) {
        conn->punch_retry++;
        if (conn->punch_retry >= MAX_PUNCH_RETRIES) {
            LOG_WARN("P2PManager: Punch failed for peer {} after {} retries",
                     conn->peer_node_id, conn->punch_retry);
            set_connection_state(conn, P2PState::FAILED);
            return;
        }
        
        LOG_INFO("P2PManager: Punch timeout for peer {}, retry {}/{}",
                 conn->peer_node_id, conn->punch_retry, MAX_PUNCH_RETRIES);
        
        // Reset and retry
        conn->punch_start_time = std::chrono::steady_clock::now();
        conn->punch_attempt = 0;
    }
    
    // Send punch to all peer endpoints
    for (const auto& ep : conn->peer_endpoints) {
        try {
            net::ip::address addr = net::ip::make_address(ep.address);
            udp::endpoint target(addr, ep.port);
            send_punch_packet(conn, target);
        } catch ([[maybe_unused]] const std::exception& e) {
            LOG_DEBUG("P2PManager: Invalid endpoint {}: {}", ep.to_string(), e.what());
        }
    }
    
    conn->punch_attempt++;
    
    // Check if max attempts reached for this round
    if (conn->punch_attempt >= MAX_PUNCH_ATTEMPTS) {
        LOG_DEBUG("P2PManager: Reached max punch attempts, waiting...");
        return;
    }
    
    // Schedule next punch
    auto it = punch_timers_.find(conn->peer_node_id);
    if (it != punch_timers_.end()) {
        it->second->expires_after(PUNCH_INTERVAL);
        it->second->async_wait([this, conn, self = shared_from_this()]
                               (const boost::system::error_code& ec) {
            if (!ec) {
                on_punch_timer(conn);
            }
        });
    }
}

// ============================================================================
// Handshake
// ============================================================================

void P2PManager::send_p2p_ping(std::shared_ptr<P2PConnection> conn) {
    LOG_DEBUG("P2PManager: Sending P2P ping to peer {}", conn->peer_node_id);
    
    std::vector<uint8_t> ping;
    ping.reserve(13);
    
    ping.push_back(P2P_PACKET_PING);
    
    // Source node ID
    ping.push_back((local_node_id_ >> 24) & 0xFF);
    ping.push_back((local_node_id_ >> 16) & 0xFF);
    ping.push_back((local_node_id_ >> 8) & 0xFF);
    ping.push_back(local_node_id_ & 0xFF);
    
    // Timestamp (8 bytes)
    auto now = std::chrono::steady_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    for (int i = 7; i >= 0; i--) {
        ping.push_back((ts >> (i * 8)) & 0xFF);
    }
    
    conn->last_ping_sent = now;
    
    auto& socket = endpoint_manager_->get_udp_socket();
    socket.send_to(net::buffer(ping), conn->active_endpoint);
}

void P2PManager::handle_p2p_pong(std::shared_ptr<P2PConnection> conn,
                                 const uint8_t* data, size_t len) {
    if (len < 13) return;
    
    LOG_DEBUG("P2PManager: Received P2P pong from peer {}", conn->peer_node_id);
    
    // Calculate RTT
    uint64_t sent_ts = 0;
    for (int i = 0; i < 8; i++) {
        sent_ts = (sent_ts << 8) | data[5 + i];
    }
    
    auto now = std::chrono::steady_clock::now();
    auto now_ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    conn->rtt_ms = static_cast<uint32_t>(now_ts - sent_ts);
    conn->last_pong_received = now;
    
    LOG_INFO("P2PManager: P2P connection to peer {} established, RTT: {} ms",
             conn->peer_node_id, conn->rtt_ms);
    
    // Cancel punch timer
    auto timer_it = punch_timers_.find(conn->peer_node_id);
    if (timer_it != punch_timers_.end()) {
        timer_it->second->cancel();
    }
    
    // Mark as connected
    if (conn->state != P2PState::CONNECTED) {
        set_connection_state(conn, P2PState::CONNECTED);
        
        // Update endpoint mapping
        {
            std::lock_guard<std::mutex> lock(endpoint_map_mutex_);
            std::string key = conn->active_endpoint.address().to_string() + ":" +
                              std::to_string(conn->active_endpoint.port());
            endpoint_to_peer_[key] = conn->peer_node_id;
        }
        
        if (callbacks_.on_connected) {
            callbacks_.on_connected(conn->peer_node_id, conn->rtt_ms);
        }
    }
}

// ============================================================================
// Keepalive
// ============================================================================

void P2PManager::start_keepalive_timer() {
    keepalive_timer_.expires_after(KEEPALIVE_CHECK_INTERVAL);
    keepalive_timer_.async_wait([this, self = shared_from_this()]
                                (const boost::system::error_code& ec) {
        if (!ec && running_) {
            on_keepalive_timer();
        }
    });
}

void P2PManager::on_keepalive_timer() {
    if (!running_) return;
    
    auto now = std::chrono::steady_clock::now();
    
    std::vector<std::shared_ptr<P2PConnection>> to_check;
    {
        std::lock_guard<std::mutex> lock(connections_mutex_);
        for (auto& [id, conn] : connections_) {
            if (conn->state == P2PState::CONNECTED) {
                to_check.push_back(conn);
            }
        }
    }
    
    for (auto& conn : to_check) {
        // Check if we need to send keepalive
        auto since_last_sent = now - conn->last_keepalive_sent;
        if (since_last_sent >= conn->keepalive_interval) {
            send_keepalive(conn);
        }
        
        // Check for missed keepalives
        auto since_last_recv = now - conn->last_keepalive_received;
        if (since_last_recv > conn->keepalive_interval * 2) {
            conn->missed_keepalives++;
            conn->successful_keepalives = 0;
            conn->keepalive_interval = std::chrono::seconds{25};  // Reset to min
            
            if (conn->missed_keepalives >= MAX_MISSED_KEEPALIVES) {
                LOG_WARN("P2PManager: Peer {} lost ({} missed keepalives)",
                         conn->peer_node_id, conn->missed_keepalives);
                handle_connection_lost(conn);
                continue;
            }
        }
    }
    
    // Reschedule
    start_keepalive_timer();
}

void P2PManager::send_keepalive(std::shared_ptr<P2PConnection> conn) {
    if (conn->state != P2PState::CONNECTED) return;
    
    std::vector<uint8_t> keepalive;
    keepalive.reserve(14);
    
    keepalive.push_back(P2P_PACKET_KEEPALIVE);
    
    // Source node ID
    keepalive.push_back((local_node_id_ >> 24) & 0xFF);
    keepalive.push_back((local_node_id_ >> 16) & 0xFF);
    keepalive.push_back((local_node_id_ >> 8) & 0xFF);
    keepalive.push_back(local_node_id_ & 0xFF);
    
    // Sequence number
    conn->keepalive_sequence++;
    keepalive.push_back((conn->keepalive_sequence >> 24) & 0xFF);
    keepalive.push_back((conn->keepalive_sequence >> 16) & 0xFF);
    keepalive.push_back((conn->keepalive_sequence >> 8) & 0xFF);
    keepalive.push_back(conn->keepalive_sequence & 0xFF);
    
    // Timestamp (4 bytes, low 32 bits of milliseconds)
    auto ts = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    keepalive.push_back((ts >> 24) & 0xFF);
    keepalive.push_back((ts >> 16) & 0xFF);
    keepalive.push_back((ts >> 8) & 0xFF);
    keepalive.push_back(ts & 0xFF);
    
    auto& socket = endpoint_manager_->get_udp_socket();
    boost::system::error_code ec;
    socket.send_to(net::buffer(keepalive), conn->active_endpoint, 0, ec);
    
    if (!ec) {
        conn->last_keepalive_sent = std::chrono::steady_clock::now();
    }
}

void P2PManager::handle_keepalive(std::shared_ptr<P2PConnection> conn,
                                  const uint8_t* data, size_t len) {
    if (len < 14) return;
    
    conn->last_keepalive_received = std::chrono::steady_clock::now();
    conn->missed_keepalives = 0;
    
    // Adaptive keepalive - if 10 successful keepalives, increase interval
    conn->successful_keepalives++;
    if (conn->successful_keepalives >= 10 && 
        conn->keepalive_interval < std::chrono::seconds{55}) {
        conn->keepalive_interval += std::chrono::seconds{5};
        conn->successful_keepalives = 0;
        LOG_DEBUG("P2PManager: Increased keepalive interval to {} seconds for peer {}",
                  conn->keepalive_interval.count(), conn->peer_node_id);
    }
    
    // Send keepalive response (echo back)
    send_keepalive(conn);
}

// ============================================================================
// Connection State
// ============================================================================

void P2PManager::set_connection_state(std::shared_ptr<P2PConnection> conn, 
                                      P2PState new_state) {
    P2PState old_state = conn->state;
    if (old_state == new_state) return;
    
    conn->state = new_state;
    
    LOG_INFO("P2PManager: Peer {} state: {} -> {}",
             conn->peer_node_id,
             p2p_state_to_string(old_state),
             p2p_state_to_string(new_state));
    
    if (callbacks_.on_state_changed) {
        callbacks_.on_state_changed(conn->peer_node_id, new_state);
    }
}

void P2PManager::handle_connection_timeout(std::shared_ptr<P2PConnection> conn) {
    LOG_WARN("P2PManager: Connection timeout for peer {}", conn->peer_node_id);
    set_connection_state(conn, P2PState::FAILED);
}

void P2PManager::handle_connection_lost(std::shared_ptr<P2PConnection> conn) {
    LOG_WARN("P2PManager: Connection lost to peer {}", conn->peer_node_id);
    
    // Remove endpoint mapping
    {
        std::lock_guard<std::mutex> lock(endpoint_map_mutex_);
        std::string key = conn->active_endpoint.address().to_string() + ":" +
                          std::to_string(conn->active_endpoint.port());
        endpoint_to_peer_.erase(key);
    }
    
    set_connection_state(conn, P2PState::DISCONNECTED);
    
    if (callbacks_.on_disconnected) {
        callbacks_.on_disconnected(conn->peer_node_id);
    }
}

// ============================================================================
// Helpers
// ============================================================================

std::shared_ptr<P2PConnection> P2PManager::find_connection_by_endpoint(
    const udp::endpoint& ep) {
    
    std::string key = ep.address().to_string() + ":" + std::to_string(ep.port());
    
    {
        std::lock_guard<std::mutex> lock(endpoint_map_mutex_);
        auto it = endpoint_to_peer_.find(key);
        if (it != endpoint_to_peer_.end()) {
            std::lock_guard<std::mutex> conn_lock(connections_mutex_);
            auto conn_it = connections_.find(it->second);
            if (conn_it != connections_.end()) {
                return conn_it->second;
            }
        }
    }
    
    // Fallback: check all connections for matching endpoint
    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (auto& [id, conn] : connections_) {
        for (const auto& peer_ep : conn->peer_endpoints) {
            if (peer_ep.address == ep.address().to_string() &&
                peer_ep.port == ep.port()) {
                return conn;
            }
        }
    }
    
    return nullptr;
}

bool P2PManager::is_p2p_feasible(NatType our_nat, NatType peer_nat) const {
    // Based on NAT compatibility matrix from design doc
    
    // If either side is OPEN or FULL_CONE, always possible
    if (our_nat == NatType::OPEN || our_nat == NatType::FULL_CONE ||
        peer_nat == NatType::OPEN || peer_nat == NatType::FULL_CONE) {
        return true;
    }
    
    // RESTRICTED_CONE can work with most types
    if (our_nat == NatType::RESTRICTED_CONE || peer_nat == NatType::RESTRICTED_CONE) {
        return true;
    }
    
    // PORT_RESTRICTED vs PORT_RESTRICTED or SYMMETRIC is harder but possible
    if (our_nat == NatType::PORT_RESTRICTED && peer_nat == NatType::PORT_RESTRICTED) {
        return true;
    }
    
    // SYMMETRIC vs SYMMETRIC is nearly impossible
    if (our_nat == NatType::SYMMETRIC && peer_nat == NatType::SYMMETRIC) {
        return false;
    }
    
    // SYMMETRIC vs PORT_RESTRICTED has low success rate
    if ((our_nat == NatType::SYMMETRIC && peer_nat == NatType::PORT_RESTRICTED) ||
        (our_nat == NatType::PORT_RESTRICTED && peer_nat == NatType::SYMMETRIC)) {
        // Allow but with warning - might fail
        LOG_WARN("P2PManager: Symmetric + Port Restricted NAT - P2P may fail");
        return true;
    }
    
    // Unknown NAT - try anyway
    if (our_nat == NatType::UNKNOWN || peer_nat == NatType::UNKNOWN) {
        return true;
    }
    
    return false;
}

} // namespace edgelink::client

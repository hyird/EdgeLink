#include "mesh_manager.hpp"
#include "mesh_client.hpp"
#include "mesh_session.hpp"
#include "relay_server.hpp"
#include "controller_client.hpp"
#include "common/log.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/strand.hpp>
#include <chrono>
#include <algorithm>

namespace edgelink {

// ============================================================================
// MeshPeerInfo Implementation
// ============================================================================

bool MeshPeerInfo::from_json(const boost::json::object& obj) {
    try {
        if (obj.contains("relay_id")) {
            relay_id = static_cast<uint32_t>(obj.at("relay_id").as_int64());
        }
        if (obj.contains("url")) {
            url = obj.at("url").as_string().c_str();
        }
        if (obj.contains("region")) {
            region = obj.at("region").as_string().c_str();
        }
        return !url.empty();
    } catch (...) {
        return false;
    }
}

boost::json::object MeshPeerInfo::to_json() const {
    return {
        {"relay_id", relay_id},
        {"url", url},
        {"region", region}
    };
}

// ============================================================================
// MeshManager Implementation
// ============================================================================

MeshManager::MeshManager(asio::io_context& ioc, RelayServer& server, const ServerConfig& config)
    : ioc_(ioc)
    , server_(server)
    , config_(config)
{
    LOG_INFO("MeshManager initialized");
}

MeshManager::~MeshManager() {
    stop();
}

void MeshManager::start() {
    if (running_) {
        return;
    }
    
    running_ = true;
    
    // Connect to peers from configuration (if manual mode)
    if (!config_.mesh.peers.empty()) {
        LOG_INFO("Connecting to {} configured mesh peers", config_.mesh.peers.size());
        
        for (const auto& peer_url : config_.mesh.peers) {
            MeshPeerInfo peer;
            peer.url = peer_url;
            peer.relay_id = 0;  // Will be assigned after handshake
            connect_to_peer(peer);
        }
    }
    
    // Start latency probing
    start_latency_probe();
    
    LOG_INFO("MeshManager started");
}

void MeshManager::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Stop probe timer
    if (probe_timer_) {
        probe_timer_->cancel();
    }
    
    // Close all outbound connections
    {
        std::unique_lock lock(outbound_mutex_);
        for (auto& [id, client] : outbound_peers_) {
            if (client) {
                client->close();
            }
        }
        outbound_peers_.clear();
    }
    
    // Close all inbound connections
    {
        std::unique_lock lock(inbound_mutex_);
        for (auto& [id, session] : inbound_peers_) {
            if (session) {
                session->close();
            }
        }
        inbound_peers_.clear();
    }
    
    LOG_INFO("MeshManager stopped");
}

void MeshManager::update_peers(const std::vector<MeshPeerInfo>& peers) {
    std::unique_lock lock(peers_mutex_);
    
    // Track which relays we should be connected to
    std::set<uint32_t> new_peer_ids;
    
    for (const auto& peer : peers) {
        if (peer.relay_id == server_.server_id()) {
            continue;  // Skip self
        }
        
        new_peer_ids.insert(peer.relay_id);
        
        // Check if we already know this peer
        auto it = known_peers_.find(peer.relay_id);
        if (it == known_peers_.end()) {
            // New peer - connect
            known_peers_[peer.relay_id] = peer;
            
            // Only initiate connection if our relay_id is smaller (to avoid duplicate connections)
            if (server_.server_id() < peer.relay_id) {
                connect_to_peer(peer);
                LOG_INFO("Adding mesh peer: {} ({}) - initiating connection", peer.relay_id, peer.url);
            } else {
                LOG_INFO("Adding mesh peer: {} ({}) - waiting for their connection", peer.relay_id, peer.url);
            }
        } else if (it->second.url != peer.url) {
            // URL changed - reconnect
            LOG_INFO("Mesh peer {} URL changed from {} to {}", peer.relay_id, it->second.url, peer.url);
            
            // Close existing connection if any
            {
                std::unique_lock out_lock(outbound_mutex_);
                auto out_it = outbound_peers_.find(peer.relay_id);
                if (out_it != outbound_peers_.end()) {
                    out_it->second->close();
                    outbound_peers_.erase(out_it);
                }
            }
            
            known_peers_[peer.relay_id] = peer;
            
            if (server_.server_id() < peer.relay_id) {
                connect_to_peer(peer);
            }
        }
    }
    
    // Remove peers that are no longer in the list
    for (auto it = known_peers_.begin(); it != known_peers_.end();) {
        if (new_peer_ids.find(it->first) == new_peer_ids.end()) {
            LOG_INFO("Removing mesh peer: {}", it->first);
            
            // Close outbound connection
            {
                std::unique_lock out_lock(outbound_mutex_);
                auto out_it = outbound_peers_.find(it->first);
                if (out_it != outbound_peers_.end()) {
                    out_it->second->close();
                    outbound_peers_.erase(out_it);
                }
            }
            
            // Close inbound connection
            {
                std::unique_lock in_lock(inbound_mutex_);
                auto in_it = inbound_peers_.find(it->first);
                if (in_it != inbound_peers_.end()) {
                    in_it->second->close();
                    inbound_peers_.erase(in_it);
                }
            }
            
            it = known_peers_.erase(it);
        } else {
            ++it;
        }
    }
}

bool MeshManager::forward_to_relay(uint32_t relay_id, const Frame& frame) {
    auto conn = get_connection(relay_id);
    
    if (!conn || !conn->is_connected()) {
        LOG_DEBUG("Cannot forward to relay {} - not connected", relay_id);
        return false;
    }
    
    // Wrap the frame in a MESH_FORWARD message
    boost::json::object mesh_msg;
    mesh_msg["type"] = "mesh_forward";
    mesh_msg["src_relay_id"] = server_.server_id();
    
    // Include the original frame data as base64 or nested JSON
    // For simplicity, we'll re-serialize the payload
    try {
        mesh_msg["payload"] = boost::json::parse(
            std::string(frame.payload.begin(), frame.payload.end()));
    } catch (...) {
        // Not JSON, encode as binary
        LOG_DEBUG("Frame payload is not JSON, sending raw");
    }
    mesh_msg["original_type"] = static_cast<int>(frame.header.type);
    
    Frame mesh_frame = create_json_frame(MessageType::MESH_FORWARD, mesh_msg, FrameFlags::NONE);
    conn->send(mesh_frame);
    
    stats_.frames_forwarded++;
    stats_.bytes_forwarded += frame.payload.size();
    
    return true;
}

void MeshManager::broadcast(const Frame& frame) {
    auto relays = get_connected_relays();
    
    for (uint32_t relay_id : relays) {
        auto conn = get_connection(relay_id);
        if (conn && conn->is_connected()) {
            conn->send(frame);
        }
    }
}

std::optional<uint32_t> MeshManager::get_latency(uint32_t relay_id) const {
    std::shared_lock lock(latency_mutex_);
    
    auto it = relay_latencies_.find(relay_id);
    if (it != relay_latencies_.end() && it->second.sample_count > 0) {
        // 返回平均 RTT，这是实际测量的端到端延迟（包含 CDN 延迟）
        return it->second.avg_rtt_ms;
    }
    return std::nullopt;
}

std::vector<uint32_t> MeshManager::get_connected_relays() const {
    std::vector<uint32_t> relays;
    
    {
        std::shared_lock lock(outbound_mutex_);
        for (const auto& [id, client] : outbound_peers_) {
            if (client && client->is_connected()) {
                relays.push_back(id);
            }
        }
    }
    
    {
        std::shared_lock lock(inbound_mutex_);
        for (const auto& [id, session] : inbound_peers_) {
            if (session && session->is_connected()) {
                if (std::find(relays.begin(), relays.end(), id) == relays.end()) {
                    relays.push_back(id);
                }
            }
        }
    }
    
    return relays;
}

void MeshManager::accept_connection(std::shared_ptr<MeshSession> session) {
    uint32_t relay_id = session->peer_relay_id();
    
    // Set up callbacks
    session->set_message_callback([this, relay_id](const Frame& frame) {
        on_mesh_frame(relay_id, frame);
    });
    
    session->set_close_callback([this, relay_id]() {
        on_peer_disconnected(relay_id);
    });
    
    // Register as inbound connection
    register_inbound_adapter(relay_id, session);
}

void MeshManager::register_inbound_adapter(uint32_t relay_id, std::shared_ptr<MeshConnection> adapter) {
    {
        std::unique_lock lock(inbound_mutex_);
        
        // Close existing inbound connection if any
        auto it = inbound_peers_.find(relay_id);
        if (it != inbound_peers_.end() && it->second) {
            LOG_INFO("Replacing existing inbound connection from relay {}", relay_id);
            it->second->close();
        }
        
        inbound_peers_[relay_id] = adapter;
    }
    
    stats_.mesh_connections++;
    LOG_INFO("Registered inbound mesh connection from relay {}", relay_id);
    
    if (connection_callback_) {
        connection_callback_(relay_id, true);
    }
}

void MeshManager::on_peer_disconnected(uint32_t relay_id) {
    bool was_connected = false;
    
    // Remove from outbound
    {
        std::unique_lock lock(outbound_mutex_);
        auto it = outbound_peers_.find(relay_id);
        if (it != outbound_peers_.end()) {
            outbound_peers_.erase(it);
            was_connected = true;
        }
    }
    
    // Remove from inbound
    {
        std::unique_lock lock(inbound_mutex_);
        auto it = inbound_peers_.find(relay_id);
        if (it != inbound_peers_.end()) {
            inbound_peers_.erase(it);
            was_connected = true;
        }
    }
    
    // Remove latency data
    {
        std::unique_lock lock(latency_mutex_);
        relay_latencies_.erase(relay_id);
    }
    
    if (was_connected) {
        LOG_INFO("Mesh peer {} disconnected", relay_id);
        
        if (connection_callback_) {
            connection_callback_(relay_id, false);
        }
    }
    
    // Schedule reconnect if this was a known peer and we should initiate
    {
        std::shared_lock lock(peers_mutex_);
        auto it = known_peers_.find(relay_id);
        if (it != known_peers_.end() && running_) {
            // Only reconnect if we're the initiator (lower relay_id)
            if (server_.server_id() < relay_id) {
                // Reconnect after delay
                auto timer = std::make_shared<asio::steady_timer>(ioc_);
                timer->expires_after(std::chrono::seconds(5));
                timer->async_wait([this, peer = it->second, timer](boost::system::error_code ec) {
                    if (!ec && running_) {
                        LOG_INFO("Attempting to reconnect to mesh peer {}", peer.relay_id);
                        connect_to_peer(peer);
                    }
                });
            }
        }
    }
}

void MeshManager::on_mesh_frame(uint32_t relay_id, const Frame& frame) {
    // Handle MESH_PONG for latency measurement
    if (frame.header.type == MessageType::MESH_PONG) {
        try {
            auto json = frame.payload_json();
            if (json.is_object()) {
                auto& obj = json.as_object();
                if (obj.contains("ping_id")) {
                    uint64_t ping_id = static_cast<uint64_t>(obj.at("ping_id").as_int64());
                    handle_pong(relay_id, ping_id);
                }
            }
        } catch (...) {
            LOG_DEBUG("Failed to parse MESH_PONG from relay {}", relay_id);
        }
        return;
    }
    
    // Handle MESH_PING - respond with PONG containing same ping_id
    if (frame.header.type == MessageType::MESH_PING) {
        try {
            auto json = frame.payload_json();
            boost::json::object pong_msg;
            
            // Echo back the ping_id for RTT calculation
            if (json.is_object()) {
                auto& obj = json.as_object();
                if (obj.contains("ping_id")) {
                    pong_msg["ping_id"] = obj.at("ping_id").as_int64();
                }
            }
            pong_msg["src_relay_id"] = server_.server_id();
            
            Frame pong = create_json_frame(MessageType::MESH_PONG, pong_msg, FrameFlags::NONE);
            
            auto conn = get_connection(relay_id);
            if (conn && conn->is_connected()) {
                conn->send(pong);
            }
        } catch (...) {
            LOG_DEBUG("Failed to process MESH_PING from relay {}", relay_id);
        }
        return;
    }
    
    // Handle MESH_FORWARD - extract and process the forwarded data
    if (frame.header.type == MessageType::MESH_FORWARD) {
        try {
            auto json = frame.payload_json();
            if (!json.is_object()) {
                LOG_DEBUG("MESH_FORWARD payload is not a JSON object");
                return;
            }
            auto& obj = json.as_object();
            
            // Extract the forwarded data payload
            if (obj.contains("payload")) {
                auto& payload = obj.at("payload");
                
                // Reconstruct the original frame
                MessageType orig_type = MessageType::DATA;
                if (obj.contains("original_type")) {
                    orig_type = static_cast<MessageType>(obj.at("original_type").as_int64());
                }
                
                // Create frame with original data
                std::string payload_str = boost::json::serialize(payload);
                Frame orig_frame = Frame::create(orig_type, 
                    std::vector<uint8_t>(payload_str.begin(), payload_str.end()), 
                    FrameFlags::NONE);
                
                // Forward to RelayServer for local delivery
                if (message_callback_) {
                    message_callback_(relay_id, orig_frame);
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to process MESH_FORWARD from relay {}: {}", relay_id, e.what());
        }
        return;
    }
    
    // Pass other frames to callback
    if (message_callback_) {
        message_callback_(relay_id, frame);
    }
}

std::shared_ptr<MeshConnection> MeshManager::get_connection(uint32_t relay_id) {
    // Check outbound first (we prefer our own connections)
    {
        std::shared_lock lock(outbound_mutex_);
        auto it = outbound_peers_.find(relay_id);
        if (it != outbound_peers_.end() && it->second && it->second->is_connected()) {
            return it->second;
        }
    }
    
    // Check inbound
    {
        std::shared_lock lock(inbound_mutex_);
        auto it = inbound_peers_.find(relay_id);
        if (it != inbound_peers_.end() && it->second && it->second->is_connected()) {
            return it->second;
        }
    }
    
    return nullptr;
}

void MeshManager::connect_to_peer(const MeshPeerInfo& peer) {
    LOG_INFO("Connecting to mesh peer: {} (relay_id={})", peer.url, peer.relay_id);
    
    auto client = std::make_shared<MeshClient>(ioc_, *this, server_.server_id(), peer);
    
    // Set up callbacks
    client->set_connect_callback([this, relay_id = peer.relay_id, client](bool success) {
        if (success) {
            on_peer_connected(client->peer_relay_id(), client);
        } else {
            LOG_WARN("Failed to connect to mesh peer {}", relay_id);
        }
    });
    
    client->set_message_callback([this, client](const Frame& frame) {
        on_mesh_frame(client->peer_relay_id(), frame);
    });
    
    client->set_close_callback([this, client]() {
        on_peer_disconnected(client->peer_relay_id());
    });
    
    // Start connection
    client->connect();
}

void MeshManager::on_peer_connected(uint32_t relay_id, std::shared_ptr<MeshClient> client) {
    {
        std::unique_lock lock(outbound_mutex_);
        
        // Close existing outbound connection if any
        auto it = outbound_peers_.find(relay_id);
        if (it != outbound_peers_.end() && it->second) {
            LOG_INFO("Replacing existing outbound connection to relay {}", relay_id);
            it->second->close();
        }
        
        outbound_peers_[relay_id] = client;
    }
    
    stats_.mesh_connections++;
    LOG_INFO("Connected to mesh peer {} (outbound)", relay_id);
    
    if (connection_callback_) {
        connection_callback_(relay_id, true);
    }
}

void MeshManager::start_latency_probe() {
    probe_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    on_latency_probe_timer();
}

void MeshManager::on_latency_probe_timer() {
    if (!running_) {
        return;
    }
    
    // Probe all connected relays
    auto relays = get_connected_relays();
    for (uint32_t relay_id : relays) {
        send_ping_to_peer(relay_id);
    }
    
    // Report latencies to controller periodically
    report_latencies();
    
    // Schedule next probe
    probe_timer_->expires_after(std::chrono::seconds(PROBE_INTERVAL_SEC));
    probe_timer_->async_wait([this](boost::system::error_code ec) {
        if (!ec) {
            on_latency_probe_timer();
        }
    });
}

void MeshManager::send_ping_to_peer(uint32_t relay_id) {
    auto conn = get_connection(relay_id);
    if (!conn || !conn->is_connected()) {
        return;
    }
    
    // 生成唯一的 ping_id 和记录发送时间
    uint64_t ping_id = next_ping_id_++;
    auto send_time = std::chrono::steady_clock::now().time_since_epoch().count();
    
    {
        std::lock_guard lock(pending_pings_mutex_);
        pending_pings_[ping_id] = {relay_id, send_time};
    }
    
    // 发送 MESH_PING，包含 ping_id 用于匹配响应
    boost::json::object ping_msg;
    ping_msg["ping_id"] = ping_id;
    ping_msg["src_relay_id"] = server_.server_id();
    
    Frame ping_frame = create_json_frame(MessageType::MESH_PING, ping_msg, FrameFlags::NONE);
    conn->send(ping_frame);
    
    LOG_DEBUG("Sent MESH_PING {} to relay {}", ping_id, relay_id);
}

void MeshManager::handle_pong(uint32_t relay_id, uint64_t ping_id) {
    auto recv_time = std::chrono::steady_clock::now().time_since_epoch().count();
    
    int64_t send_time = 0;
    uint32_t expected_relay_id = 0;
    
    {
        std::lock_guard lock(pending_pings_mutex_);
        auto it = pending_pings_.find(ping_id);
        if (it != pending_pings_.end()) {
            expected_relay_id = it->second.first;
            send_time = it->second.second;
            pending_pings_.erase(it);
        } else {
            LOG_DEBUG("Received PONG for unknown ping_id {} from relay {}", ping_id, relay_id);
            return;
        }
    }
    
    // 验证响应来自预期的 Relay
    if (expected_relay_id != relay_id) {
        LOG_WARN("PONG relay mismatch: expected {} got {}", expected_relay_id, relay_id);
        return;
    }
    
    // 计算真实的端到端 RTT（包含 CDN 延迟）
    uint32_t rtt_ms = static_cast<uint32_t>((recv_time - send_time) / 1000000);  // ns to ms
    
    {
        std::unique_lock lock(latency_mutex_);
        relay_latencies_[relay_id].update(rtt_ms);
        
        auto& stats = relay_latencies_[relay_id];
        LOG_INFO("Mesh RTT to relay {}: current={}ms avg={}ms min={}ms max={}ms (samples={})", 
                 relay_id, stats.current_rtt_ms, stats.avg_rtt_ms, 
                 stats.min_rtt_ms, stats.max_rtt_ms, stats.sample_count);
    }
}

void MeshManager::report_latencies() {
    // 清理过期的 pending pings（超过 30 秒未响应的）
    {
        std::lock_guard lock(pending_pings_mutex_);
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        for (auto it = pending_pings_.begin(); it != pending_pings_.end();) {
            int64_t age_ms = (now - it->second.second) / 1000000;
            if (age_ms > 30000) {  // 30 秒超时
                LOG_DEBUG("Ping {} to relay {} timed out", it->first, it->second.first);
                it = pending_pings_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // 上报延迟数据到 Controller
    auto latencies = get_all_latencies();
    
    if (!latencies.empty()) {
        LOG_DEBUG("=== Mesh Latency Report ({} peers) ===", latencies.size());
        
        boost::json::object report;
        report["src_relay_id"] = server_.server_id();
        
        boost::json::array latency_array;
        
        for (const auto& [relay_id, avg_rtt, min_rtt, max_rtt] : latencies) {
            LOG_DEBUG("  Relay {}: avg={}ms min={}ms max={}ms",
                     relay_id, avg_rtt, min_rtt, max_rtt);
            
            boost::json::object entry;
            entry["relay_id"] = relay_id;
            entry["avg_rtt_ms"] = avg_rtt;
            entry["min_rtt_ms"] = min_rtt;
            entry["max_rtt_ms"] = max_rtt;
            latency_array.push_back(entry);
        }
        
        report["latencies"] = latency_array;
        
        // Send to controller
        Frame frame = create_json_frame(MessageType::SERVER_LATENCY_REPORT, report, FrameFlags::NONE);
        
        auto* ctrl = server_.controller_client();
        if (ctrl && ctrl->is_connected()) {
            ctrl->send(frame);
            LOG_INFO("Sent mesh latency report to controller: {} peers", latencies.size());
        }
    }
}

std::vector<std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>> MeshManager::get_all_latencies() const {
    std::vector<std::tuple<uint32_t, uint32_t, uint32_t, uint32_t>> result;
    
    std::shared_lock lock(latency_mutex_);
    
    for (const auto& [relay_id, stats] : relay_latencies_) {
        if (stats.sample_count > 0) {
            result.emplace_back(relay_id, stats.avg_rtt_ms, stats.min_rtt_ms, stats.max_rtt_ms);
        }
    }
    
    return result;
}

} // namespace edgelink

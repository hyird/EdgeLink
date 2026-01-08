#include "grpc_relay_manager.hpp"
#include "common/log.hpp"

#include <chrono>

namespace edgelink::client {

// ============================================================================
// GrpcRelayManager Implementation
// ============================================================================

GrpcRelayManager::GrpcRelayManager(uint32_t local_node_id, const std::string& relay_token)
    : local_node_id_(local_node_id)
    , relay_token_(relay_token)
{}

GrpcRelayManager::~GrpcRelayManager() {
    disconnect_all();
}

void GrpcRelayManager::set_callbacks(GrpcRelayManagerCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void GrpcRelayManager::update_token(const std::string& new_token) {
    relay_token_ = new_token;
    LOG_INFO("GrpcRelayManager: Token updated");
}

void GrpcRelayManager::update_relays(const std::vector<RelayServerInfo>& relays) {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    relay_servers_ = relays;

    // Update or add relays
    for (const auto& info : relays) {
        auto it = relays_.find(info.id);
        if (it == relays_.end()) {
            // New relay
            auto relay = std::make_shared<GrpcRelayConnection>();
            relay->server_id = info.id;
            relay->url = info.url;
            relay->region = info.region;
            relays_[info.id] = relay;
        } else {
            // Update existing
            it->second->url = info.url;
            it->second->region = info.region;
        }
    }

    LOG_INFO("GrpcRelayManager: Updated {} relays", relays.size());
}

void GrpcRelayManager::update_paths(const std::vector<GrpcPeerPath>& paths) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    peer_paths_.clear();
    for (const auto& path : paths) {
        peer_paths_[path.peer_node_id] = path;
    }
}

void GrpcRelayManager::connect_all() {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (auto& [id, relay] : relays_) {
        if (relay->state == GrpcRelayConnection::State::DISCONNECTED) {
            do_connect_relay(relay);
        }
    }
}

void GrpcRelayManager::connect_relay(uint32_t relay_id) {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    auto it = relays_.find(relay_id);
    if (it != relays_.end() &&
        it->second->state == GrpcRelayConnection::State::DISCONNECTED) {
        do_connect_relay(it->second);
    }
}

void GrpcRelayManager::disconnect_relay(uint32_t relay_id) {
    std::shared_ptr<GrpcRelayConnection> relay;
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) return;
        relay = it->second;
    }

    relay->running = false;
    relay->state = GrpcRelayConnection::State::DISCONNECTED;

    // Cancel the stream
    if (relay->stream && relay->context) {
        relay->context->TryCancel();
    }

    // Wait for threads to finish
    if (relay->read_thread && relay->read_thread->joinable()) {
        relay->read_thread->join();
    }
    if (relay->write_thread && relay->write_thread->joinable()) {
        relay->write_thread->join();
    }

    relay->stream.reset();
    relay->stub.reset();
    relay->channel.reset();

    if (callbacks_.on_relay_state_changed) {
        callbacks_.on_relay_state_changed(relay_id, GrpcRelayConnection::State::DISCONNECTED);
    }

    LOG_INFO("GrpcRelayManager: Disconnected from relay {}", relay_id);
}

void GrpcRelayManager::disconnect_all() {
    shutdown_ = true;
    stop_latency_measurements();

    std::vector<uint32_t> relay_ids;
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        for (const auto& [id, _] : relays_) {
            relay_ids.push_back(id);
        }
    }

    for (uint32_t id : relay_ids) {
        disconnect_relay(id);
    }
}

void GrpcRelayManager::do_connect_relay(std::shared_ptr<GrpcRelayConnection> relay) {
    relay->state = GrpcRelayConnection::State::CONNECTING;

    if (callbacks_.on_relay_state_changed) {
        callbacks_.on_relay_state_changed(relay->server_id, relay->state);
    }

    // Parse URL and create channel
    std::string target = relay->url;
    std::shared_ptr<grpc::ChannelCredentials> creds;

    // Check if TLS
    if (target.find("grpcs://") == 0) {
        target = target.substr(8);  // Remove grpcs://
        creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
    } else if (target.find("grpc://") == 0) {
        target = target.substr(7);  // Remove grpc://
        creds = grpc::InsecureChannelCredentials();
    } else {
        // Default to TLS
        creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
    }

    relay->channel = grpc::CreateChannel(target, creds);

    // Wait for channel to be ready
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(10);
    if (!relay->channel->WaitForConnected(deadline)) {
        LOG_WARN("GrpcRelayManager: Failed to connect to relay {} at {}",
                 relay->server_id, target);
        relay->state = GrpcRelayConnection::State::DISCONNECTED;
        schedule_relay_reconnect(relay);
        return;
    }

    relay->stub = edgelink::RelayService::NewStub(relay->channel);

    // Create new context for the stream
    relay->context = std::make_unique<grpc::ClientContext>();
    relay->stream = relay->stub->Relay(relay->context.get());

    if (!relay->stream) {
        LOG_WARN("GrpcRelayManager: Failed to create stream for relay {}", relay->server_id);
        relay->state = GrpcRelayConnection::State::DISCONNECTED;
        schedule_relay_reconnect(relay);
        return;
    }

    relay->running = true;
    relay->state = GrpcRelayConnection::State::AUTHENTICATING;

    // Start read/write threads
    relay->read_thread = std::make_unique<std::thread>([this, relay]() {
        read_loop(relay);
    });

    relay->write_thread = std::make_unique<std::thread>([this, relay]() {
        write_loop(relay);
    });

    // Send auth
    do_relay_auth(relay);

    LOG_INFO("GrpcRelayManager: Connecting to relay {} at {}", relay->server_id, target);
}

void GrpcRelayManager::do_relay_auth(std::shared_ptr<GrpcRelayConnection> relay) {
    edgelink::RelayMessage msg;
    auto* auth = msg.mutable_relay_auth();
    auth->set_relay_token(relay_token_);

    send_message(relay, std::move(msg));
}

void GrpcRelayManager::read_loop(std::shared_ptr<GrpcRelayConnection> relay) {
    edgelink::RelayMessage msg;

    while (relay->running && relay->stream->Read(&msg)) {
        process_relay_message(relay, msg);
        msg.Clear();
    }

    // Stream ended
    if (relay->running) {
        LOG_INFO("GrpcRelayManager: Relay {} stream ended", relay->server_id);
        relay->running = false;
        relay->state = GrpcRelayConnection::State::DISCONNECTED;

        if (callbacks_.on_relay_state_changed) {
            callbacks_.on_relay_state_changed(relay->server_id,
                GrpcRelayConnection::State::DISCONNECTED);
        }

        if (!shutdown_) {
            schedule_relay_reconnect(relay);
        }
    }
}

void GrpcRelayManager::write_loop(std::shared_ptr<GrpcRelayConnection> relay) {
    while (relay->running) {
        edgelink::RelayMessage msg;
        bool has_msg = false;

        {
            std::lock_guard<std::mutex> lock(relay->write_mutex);
            if (!relay->write_queue.empty()) {
                msg = std::move(relay->write_queue.front());
                relay->write_queue.pop();
                has_msg = true;
            }
        }

        if (has_msg) {
            if (!relay->stream->Write(msg)) {
                LOG_WARN("GrpcRelayManager: Failed to write to relay {}", relay->server_id);
                relay->running = false;
                break;
            }
            relay->packets_sent++;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

void GrpcRelayManager::process_relay_message(std::shared_ptr<GrpcRelayConnection> relay,
                                              const edgelink::RelayMessage& msg) {
    switch (msg.message_case()) {
        case edgelink::RelayMessage::kRelayAuthResponse: {
            const auto& resp = msg.relay_auth_response();
            if (resp.success()) {
                relay->state = GrpcRelayConnection::State::CONNECTED;
                relay->reconnect_attempts = 0;
                LOG_INFO("GrpcRelayManager: Authenticated to relay {}", relay->server_id);

                if (callbacks_.on_relay_state_changed) {
                    callbacks_.on_relay_state_changed(relay->server_id,
                        GrpcRelayConnection::State::CONNECTED);
                }

                start_relay_heartbeat(relay);
            } else {
                LOG_WARN("GrpcRelayManager: Auth failed for relay {}: {}",
                         relay->server_id, resp.error_message());
                relay->running = false;
                relay->state = GrpcRelayConnection::State::DISCONNECTED;
            }
            break;
        }

        case edgelink::RelayMessage::kRelayData: {
            const auto& packet = msg.relay_data();
            relay->packets_received++;
            relay->bytes_received += packet.encrypted_data().size();

            if (callbacks_.on_data_received) {
                std::vector<uint8_t> data(packet.encrypted_data().begin(),
                                          packet.encrypted_data().end());
                callbacks_.on_data_received(packet.src_node_id(), data);
            }
            break;
        }

        case edgelink::RelayMessage::kPong: {
            relay->last_pong = std::chrono::steady_clock::now();
            relay->missed_pongs = 0;

            auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                relay->last_pong - relay->last_ping).count();
            relay->latency_ms = static_cast<uint32_t>(rtt);

            LOG_DEBUG("GrpcRelayManager: Relay {} latency: {}ms", relay->server_id, rtt);
            break;
        }

        case edgelink::RelayMessage::kError: {
            const auto& error = msg.error();
            LOG_WARN("GrpcRelayManager: Error from relay {}: {} - {}",
                     relay->server_id, static_cast<int>(error.code()), error.message());
            break;
        }

        default:
            LOG_WARN("GrpcRelayManager: Unknown message from relay {}: {}",
                     relay->server_id, static_cast<int>(msg.message_case()));
            break;
    }
}

void GrpcRelayManager::send_message(std::shared_ptr<GrpcRelayConnection> relay,
                                     edgelink::RelayMessage msg) {
    std::lock_guard<std::mutex> lock(relay->write_mutex);
    relay->write_queue.push(std::move(msg));
}

std::expected<void, ErrorCode> GrpcRelayManager::send_to_peer(
    uint32_t dst_node_id,
    const std::vector<uint8_t>& encrypted_data) {

    // Find best relay for this peer
    uint32_t relay_id = 0;
    {
        std::lock_guard<std::mutex> lock(paths_mutex_);
        auto it = peer_paths_.find(dst_node_id);
        if (it != peer_paths_.end()) {
            relay_id = it->second.primary_relay_id;
        }
    }

    // If no specific path, use first connected relay
    if (relay_id == 0) {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        for (const auto& [id, relay] : relays_) {
            if (relay->state == GrpcRelayConnection::State::CONNECTED) {
                relay_id = id;
                break;
            }
        }
    }

    if (relay_id == 0) {
        return std::unexpected(ErrorCode::NO_RELAY_AVAILABLE);
    }

    return send_via_relay(relay_id, dst_node_id, encrypted_data);
}

std::expected<void, ErrorCode> GrpcRelayManager::send_via_relay(
    uint32_t relay_id,
    uint32_t dst_node_id,
    const std::vector<uint8_t>& encrypted_data) {

    std::shared_ptr<GrpcRelayConnection> relay;
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) {
            return std::unexpected(ErrorCode::NODE_NOT_FOUND);
        }
        relay = it->second;
    }

    if (relay->state != GrpcRelayConnection::State::CONNECTED) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }

    edgelink::RelayMessage msg;
    auto* packet = msg.mutable_data();
    packet->set_src_node_id(local_node_id_);
    packet->set_dst_node_id(dst_node_id);
    packet->set_encrypted_data(encrypted_data.data(), encrypted_data.size());

    send_message(relay, std::move(msg));
    relay->bytes_sent += encrypted_data.size();

    return {};
}

void GrpcRelayManager::schedule_relay_reconnect(std::shared_ptr<GrpcRelayConnection> relay) {
    if (shutdown_) return;

    relay->reconnect_attempts++;
    relay->state = GrpcRelayConnection::State::RECONNECTING;

    // Exponential backoff: 1s, 2s, 4s, 8s, max 60s
    uint32_t delay_s = std::min(1u << relay->reconnect_attempts, 60u);

    LOG_INFO("GrpcRelayManager: Reconnecting to relay {} in {}s (attempt {})",
             relay->server_id, delay_s, relay->reconnect_attempts);

    std::thread([this, relay, delay_s]() {
        std::this_thread::sleep_for(std::chrono::seconds(delay_s));
        if (!shutdown_ && relay->state == GrpcRelayConnection::State::RECONNECTING) {
            do_connect_relay(relay);
        }
    }).detach();
}

void GrpcRelayManager::start_relay_heartbeat(std::shared_ptr<GrpcRelayConnection> relay) {
    auto heartbeat_thread = std::make_unique<std::thread>([this, relay]() {
        while (relay->running &&
               relay->state == GrpcRelayConnection::State::CONNECTED) {

            edgelink::RelayMessage msg;
            msg.mutable_ping()->set_timestamp(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());

            relay->last_ping = std::chrono::steady_clock::now();
            send_message(relay, std::move(msg));

            std::this_thread::sleep_for(std::chrono::seconds(30));

            // Check if pong was received
            auto since_pong = std::chrono::steady_clock::now() - relay->last_pong;
            if (since_pong > std::chrono::seconds(90)) {
                relay->missed_pongs++;
                if (relay->missed_pongs >= 3) {
                    LOG_WARN("GrpcRelayManager: Relay {} unresponsive, reconnecting",
                             relay->server_id);
                    relay->running = false;
                    break;
                }
            }
        }
    });

    std::lock_guard<std::mutex> lock(relays_mutex_);
    heartbeat_threads_[relay->server_id] = std::move(heartbeat_thread);
}

void GrpcRelayManager::measure_latency_to_peer(uint32_t peer_node_id) {
    // Send latency probe through all connected relays
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (auto& [id, relay] : relays_) {
        if (relay->state == GrpcRelayConnection::State::CONNECTED) {
            // TODO: Implement proper latency probing through relays
        }
    }
}

void GrpcRelayManager::start_latency_measurements() {
    latency_measuring_ = true;
    // TODO: Implement periodic latency measurements
}

void GrpcRelayManager::stop_latency_measurements() {
    latency_measuring_ = false;
}

uint32_t GrpcRelayManager::get_best_relay(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    auto it = peer_paths_.find(peer_node_id);
    if (it != peer_paths_.end()) {
        return it->second.primary_relay_id;
    }

    // Return first connected relay
    std::lock_guard<std::mutex> rlock(relays_mutex_);
    for (const auto& [id, relay] : relays_) {
        if (relay->state == GrpcRelayConnection::State::CONNECTED) {
            return id;
        }
    }
    return 0;
}

GrpcRelayConnection::State GrpcRelayManager::get_relay_state(uint32_t relay_id) const {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    auto it = relays_.find(relay_id);
    if (it != relays_.end()) {
        return it->second->state;
    }
    return GrpcRelayConnection::State::DISCONNECTED;
}

std::vector<uint32_t> GrpcRelayManager::get_connected_relays() const {
    std::vector<uint32_t> result;
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (const auto& [id, relay] : relays_) {
        if (relay->state == GrpcRelayConnection::State::CONNECTED) {
            result.push_back(id);
        }
    }
    return result;
}

uint32_t GrpcRelayManager::get_latency(uint32_t peer_node_id, uint32_t relay_id) const {
    std::lock_guard<std::mutex> lock(latency_mutex_);
    auto rit = latency_data_.find(relay_id);
    if (rit != latency_data_.end()) {
        auto pit = rit->second.find(peer_node_id);
        if (pit != rit->second.end()) {
            return pit->second;
        }
    }
    return 0;
}

GrpcRelayManager::Stats GrpcRelayManager::get_stats() const {
    Stats stats;
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (const auto& [id, relay] : relays_) {
        if (relay->state == GrpcRelayConnection::State::CONNECTED) {
            stats.connected_relays++;
        }
        stats.total_bytes_sent += relay->bytes_sent;
        stats.total_bytes_received += relay->bytes_received;
        stats.total_packets_sent += relay->packets_sent;
        stats.total_packets_received += relay->packets_received;
    }
    return stats;
}

} // namespace edgelink::client

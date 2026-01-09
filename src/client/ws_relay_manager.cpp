#include "ws_relay_manager.hpp"
#include "common/config.hpp"
#include "common/log.hpp"

namespace edgelink::client {

// ============================================================================
// WsRelayConnection Implementation (inherits from WsClient)
// ============================================================================

WsRelayConnection::WsRelayConnection(net::io_context& ioc, uint32_t server_id,
                                     const std::string& url, const std::string& region,
                                     const std::string& relay_token,
                                     std::function<void(uint32_t, const wire::Frame&)> on_frame)
    : WsClient(ioc, url + paths::WS_RELAY, "Relay-" + std::to_string(server_id))
    , server_id_(server_id)
    , region_(region)
    , relay_token_(relay_token)
    , on_frame_callback_(std::move(on_frame))
{}

void WsRelayConnection::do_authenticate() {
    // Create RELAY_AUTH frame (binary)
    wire::RelayAuthPayload auth_payload;
    auth_payload.relay_token = relay_token_;

    auto binary = auth_payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::RELAY_AUTH, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("WsRelayConnection: RELAY_AUTH sent ({} bytes)", frame.payload.size());

    // Start reading for auth response (base class handles the read loop)
}

void WsRelayConnection::process_frame(const wire::Frame& frame) {
    // Handle auth response specially (server sends RELAY_AUTH_RESP)
    if (state() == State::AUTHENTICATING && frame.header.type == wire::MessageType::RELAY_AUTH_RESP) {
        auto result = wire::AuthResponsePayload::deserialize_binary(frame.payload);
        if (!result) {
            LOG_WARN("WsRelayConnection: Invalid AUTH_RESPONSE: error={}",
                     static_cast<int>(result.error()));
            auth_failed("Invalid auth response");
            return;
        }

        if (!result->success) {
            auth_failed(result->error_message);
            return;
        }

        LOG_INFO("WsRelayConnection: Authenticated with relay {}", server_id_);
        auth_complete();
        return;
    }

    // Pass other frames to callback
    if (on_frame_callback_) {
        on_frame_callback_(server_id_, frame);
    }
}

// ============================================================================
// WsRelayManager Implementation
// ============================================================================

WsRelayManager::WsRelayManager(net::io_context& ioc, uint32_t local_node_id, const std::string& relay_token)
    : ioc_(ioc)
    , local_node_id_(local_node_id)
    , relay_token_(relay_token)
{}

WsRelayManager::~WsRelayManager() {
    disconnect_all();
}

void WsRelayManager::set_callbacks(WsRelayManagerCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

void WsRelayManager::update_token(const std::string& new_token) {
    relay_token_ = new_token;

    // Update all existing connections
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (auto& [id, relay] : relays_) {
        relay->update_token(new_token);
    }

    LOG_INFO("WsRelayManager: Token updated");
}

void WsRelayManager::update_relays(const std::vector<RelayServerInfo>& relays) {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    relay_servers_ = relays;

    // Update or add relays
    for (const auto& info : relays) {
        auto it = relays_.find(info.id);
        if (it == relays_.end()) {
            // Create new relay connection
            auto relay = std::make_shared<WsRelayConnection>(
                ioc_, info.id, info.url, info.region, relay_token_,
                [this](uint32_t id, const wire::Frame& frame) {
                    on_relay_frame(id, frame);
                });

            // Set state change callback
            relay->set_callbacks({
                .on_connected = [this, id = info.id]() {
                    if (callbacks_.on_relay_state_changed) {
                        callbacks_.on_relay_state_changed(id, RelayState::CONNECTED);
                    }
                },
                .on_disconnected = [this, id = info.id](const std::string&) {
                    if (callbacks_.on_relay_state_changed) {
                        callbacks_.on_relay_state_changed(id, RelayState::DISABLED);
                    }
                },
                .on_state_changed = [this, id = info.id](WsClientState state) {
                    if (callbacks_.on_relay_state_changed) {
                        callbacks_.on_relay_state_changed(id, state);
                    }
                }
            });

            relays_[info.id] = relay;
        }
        // Note: URL updates require reconnection which is not handled here
    }

    LOG_INFO("WsRelayManager: Updated {} relays", relays.size());
}

void WsRelayManager::update_paths(const std::vector<WsPeerPath>& paths) {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    peer_paths_.clear();
    for (const auto& path : paths) {
        peer_paths_[path.peer_node_id] = path;
    }
}

void WsRelayManager::connect_all() {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (auto& [id, relay] : relays_) {
        if (relay->state() == RelayState::INIT || relay->state() == RelayState::DISABLED) {
            relay->connect();
        }
    }
}

void WsRelayManager::connect_relay(uint32_t relay_id) {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    auto it = relays_.find(relay_id);
    if (it != relays_.end()) {
        it->second->connect();
    }
}

void WsRelayManager::disconnect_relay(uint32_t relay_id) {
    std::shared_ptr<WsRelayConnection> relay;
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) return;
        relay = it->second;
    }

    relay->disconnect();
    LOG_INFO("WsRelayManager: Disconnected from relay {}", relay_id);
}

void WsRelayManager::disconnect_all() {
    shutdown_ = true;
    stop_latency_measurements();

    std::vector<std::shared_ptr<WsRelayConnection>> relay_list;
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        for (auto& [id, relay] : relays_) {
            relay_list.push_back(relay);
        }
    }

    for (auto& relay : relay_list) {
        relay->disconnect();
    }
}

void WsRelayManager::on_relay_frame(uint32_t relay_id, const wire::Frame& frame) {
    switch (frame.header.type) {
        case wire::MessageType::DATA: {
            // Parse DATA frame
            auto data_result = wire::DataPayload::deserialize(frame.payload);
            if (!data_result) {
                LOG_WARN("WsRelayManager: Invalid DATA frame from relay {}", relay_id);
                return;
            }

            // Deliver to callback
            if (callbacks_.on_data_received) {
                auto encrypted_packet = data_result->serialize();
                callbacks_.on_data_received(data_result->src_node_id, encrypted_packet);
            }
            break;
        }

        case wire::MessageType::ERROR_MSG: {
            auto result = wire::ErrorPayload::deserialize_binary(frame.payload);
            if (result) {
                LOG_WARN("WsRelayManager: Error from relay {}: {} - {}",
                        relay_id, result->code, result->message);
            } else {
                LOG_WARN("WsRelayManager: Error from relay {} (failed to parse): error={}",
                        relay_id, static_cast<int>(result.error()));
            }
            break;
        }

        default:
            LOG_DEBUG("WsRelayManager: Unhandled message type {} from relay {}",
                     static_cast<int>(frame.header.type), relay_id);
            break;
    }
}

std::expected<void, ErrorCode> WsRelayManager::send_to_peer(
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
            if (relay->state() == RelayState::CONNECTED) {
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

std::expected<void, ErrorCode> WsRelayManager::send_via_relay(
    uint32_t relay_id,
    uint32_t dst_node_id,
    const std::vector<uint8_t>& encrypted_data) {

    std::shared_ptr<WsRelayConnection> relay;
    {
        std::lock_guard<std::mutex> lock(relays_mutex_);
        auto it = relays_.find(relay_id);
        if (it == relays_.end()) {
            return std::unexpected(ErrorCode::NODE_NOT_FOUND);
        }
        relay = it->second;
    }

    if (relay->state() != RelayState::CONNECTED) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }

    // Create DATA frame
    auto frame = wire::Frame::create(wire::MessageType::DATA, encrypted_data);
    relay->send_frame(frame);

    return {};
}

void WsRelayManager::measure_latency_to_peer(uint32_t peer_node_id) {
    // Send ping through all relays that have paths to this peer
    // Latency will be measured by ping/pong in WsClient base class
}

void WsRelayManager::start_latency_measurements() {
    latency_measuring_ = true;
}

void WsRelayManager::stop_latency_measurements() {
    latency_measuring_ = false;
}

uint32_t WsRelayManager::get_best_relay(uint32_t peer_node_id) const {
    std::lock_guard<std::mutex> lock(paths_mutex_);
    auto it = peer_paths_.find(peer_node_id);
    if (it != peer_paths_.end()) {
        return it->second.primary_relay_id;
    }

    // Return first connected relay
    std::lock_guard<std::mutex> rlock(relays_mutex_);
    for (const auto& [id, relay] : relays_) {
        if (relay->state() == RelayState::CONNECTED) {
            return id;
        }
    }
    return 0;
}

RelayState WsRelayManager::get_relay_state(uint32_t relay_id) const {
    std::lock_guard<std::mutex> lock(relays_mutex_);
    auto it = relays_.find(relay_id);
    if (it != relays_.end()) {
        return it->second->state();
    }
    return RelayState::DISABLED;
}

std::vector<uint32_t> WsRelayManager::get_connected_relays() const {
    std::vector<uint32_t> result;
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (const auto& [id, relay] : relays_) {
        if (relay->state() == RelayState::CONNECTED) {
            result.push_back(id);
        }
    }
    return result;
}

uint32_t WsRelayManager::get_latency(uint32_t peer_node_id, uint32_t relay_id) const {
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

WsRelayManager::Stats WsRelayManager::get_stats() const {
    Stats stats;
    std::lock_guard<std::mutex> lock(relays_mutex_);
    for (const auto& [id, relay] : relays_) {
        if (relay->state() == RelayState::CONNECTED) {
            stats.connected_relays++;
        }
        const auto& relay_stats = relay->stats();
        stats.total_bytes_sent += relay_stats.bytes_sent;
        stats.total_bytes_received += relay_stats.bytes_received;
        stats.total_packets_sent += relay_stats.frames_sent;
        stats.total_packets_received += relay_stats.frames_received;
    }
    return stats;
}

} // namespace edgelink::client

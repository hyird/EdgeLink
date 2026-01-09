#include "controller_client.hpp"
#include "ws_relay_server.hpp"
#include "common/config.hpp"
#include "common/log.hpp"

namespace edgelink {

// ============================================================================
// ControllerClient Implementation (using WsClient base class)
// ============================================================================

ControllerClient::ControllerClient(net::io_context& ioc, WsRelayServer& server, const ServerConfig& config)
    : WsClient(ioc, config.controller.url + paths::WS_SERVER, "ControllerClient")
    , server_(server)
    , config_(config)
{
    // Set up base class callbacks
    set_callbacks({
        .on_connected = [this]() {
            LOG_INFO("ControllerClient: Connected and registered");
            if (connect_callback_) {
                connect_callback_(true, "");
            }
        },
        .on_disconnected = [this](const std::string& reason) {
            registered_ = false;
            if (disconnect_callback_) {
                disconnect_callback_(reason);
            }
        }
    });

    LOG_INFO("ControllerClient initialized for {}", config_.controller.url);
}

void ControllerClient::do_authenticate() {
    LOG_INFO("ControllerClient: Registering with controller...");

    // Build SERVER_REGISTER payload
    boost::json::object payload;
    payload["server_token"] = config_.controller.token;
    payload["name"] = config_.name;
    payload["region"] = config_.relay.region;

    // Construct relay URL (without path - client will append path internally)
    std::string relay_url = config_.relay.external_url;
    if (relay_url.empty()) {
        std::string scheme = config_.relay.tls.enabled ? "wss" : "ws";
        relay_url = scheme + "://" + config_.relay.listen_address + ":" +
                    std::to_string(config_.relay.listen_port);
    }
    payload["relay_url"] = relay_url;

    // STUN info
    if (config_.stun.enabled) {
        payload["stun_port"] = config_.stun.external_port;
        if (!config_.stun.ip.empty()) {
            payload["stun_ip"] = config_.stun.ip;
        }
        if (!config_.stun.secondary_ip.empty()) {
            payload["stun_ip2"] = config_.stun.secondary_ip;
        }
    }

    // Capabilities
    uint8_t caps = 0;
    if (!config_.relay.external_url.empty() || config_.relay.listen_port > 0) {
        caps |= wire::ServerCapability::RELAY;
    }
    if (config_.stun.enabled) {
        caps |= wire::ServerCapability::STUN;
    }
    payload["capabilities"] = caps;

    auto frame = wire::create_json_frame(wire::MessageType::SERVER_REGISTER, payload);
    send_frame(frame);

    // Base class will start reading after this
}

void ControllerClient::process_frame(const wire::Frame& frame) {
    // Handle auth response during authentication phase
    if (state() == State::AUTHENTICATING &&
        frame.header.type == wire::MessageType::SERVER_REGISTER_RESP) {
        handle_register_response(frame);
        return;
    }

    // Handle other frames when connected
    switch (frame.header.type) {
        case wire::MessageType::SERVER_NODE_LOC:
            handle_node_loc(frame);
            break;

        case wire::MessageType::SERVER_RELAY_LIST:
            handle_relay_list(frame);
            break;

        case wire::MessageType::SERVER_BLACKLIST:
            handle_blacklist(frame);
            break;

        case wire::MessageType::ERROR_MSG:
            handle_error(frame);
            break;

        default:
            // Let base class handle PING/PONG
            WsClient::process_frame(frame);
            break;
    }
}

void ControllerClient::handle_register_response(const wire::Frame& frame) {
    auto json_result = wire::parse_json_payload(frame);
    if (!json_result) {
        LOG_ERROR("ControllerClient: Failed to parse register response");
        auth_failed("Invalid register response");
        return;
    }

    auto& json = json_result->as_object();

    if (json.contains("success") && json.at("success").as_bool()) {
        server_id_ = static_cast<uint32_t>(json.at("server_id").as_int64());
        server_.set_server_id(server_id_);
        registered_ = true;

        LOG_INFO("ControllerClient: Registered as server ID {}", server_id_);

        // Signal auth complete to base class
        auth_complete();
    } else {
        std::string error = json.contains("error_message")
            ? json.at("error_message").as_string().c_str()
            : "Unknown error";
        LOG_ERROR("ControllerClient: Registration failed: {}", error);

        if (connect_callback_) {
            connect_callback_(false, error);
        }
        auth_failed(error);
    }
}

void ControllerClient::handle_node_loc(const wire::Frame& frame) {
    auto json_result = wire::parse_json_payload(frame);
    if (!json_result) {
        LOG_WARN("ControllerClient: Failed to parse node location update");
        return;
    }

    auto& json = json_result->as_object();
    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> locations;

    if (json.contains("nodes")) {
        for (const auto& node : json.at("nodes").as_array()) {
            const auto& n = node.as_object();
            uint32_t node_id = static_cast<uint32_t>(n.at("node_id").as_int64());
            std::vector<uint32_t> relay_ids;

            if (n.contains("connected_relay_ids")) {
                for (const auto& rid : n.at("connected_relay_ids").as_array()) {
                    relay_ids.push_back(static_cast<uint32_t>(rid.as_int64()));
                }
            }

            locations.emplace_back(node_id, std::move(relay_ids));
        }
    }

    if (node_loc_callback_) {
        node_loc_callback_(locations);
    }

    LOG_DEBUG("ControllerClient: Updated node locations: {} entries", locations.size());
}

void ControllerClient::handle_relay_list(const wire::Frame& frame) {
    auto json_result = wire::parse_json_payload(frame);
    if (!json_result) {
        LOG_WARN("ControllerClient: Failed to parse relay list");
        return;
    }

    auto& json = json_result->as_object();
    std::vector<wire::RelayInfo> relays;

    if (json.contains("relays")) {
        for (const auto& relay : json.at("relays").as_array()) {
            auto result = wire::RelayInfo::from_json(relay);
            if (result) {
                relays.push_back(std::move(*result));
            }
        }
    }

    if (relay_list_callback_) {
        relay_list_callback_(relays);
    }

    LOG_INFO("ControllerClient: Received relay list: {} relays", relays.size());
}

void ControllerClient::handle_blacklist(const wire::Frame& frame) {
    // Try binary deserialization first
    auto result = wire::ServerBlacklistPayload::deserialize_binary(frame.payload);
    if (!result) {
        // Fall back to JSON
        auto json_result = wire::parse_json_payload(frame);
        if (json_result) {
            result = wire::ServerBlacklistPayload::from_json(*json_result);
        }
    }

    if (!result) {
        LOG_WARN("ControllerClient: Failed to parse blacklist update");
        return;
    }

    const auto& payload = *result;
    std::vector<std::pair<std::string, int64_t>> entries;
    for (const auto& e : payload.entries) {
        entries.emplace_back(e.jti, e.expires_at);
    }

    // Update relay server's blacklist directly
    for (const auto& [jti, expires_at] : entries) {
        server_.session_manager()->add_to_blacklist(jti, expires_at);
    }

    if (blacklist_callback_) {
        blacklist_callback_(payload.full_sync, entries);
    }

    LOG_DEBUG("ControllerClient: Updated token blacklist: {} entries (full_sync={})",
              entries.size(), payload.full_sync);
}

void ControllerClient::handle_error(const wire::Frame& frame) {
    auto json_result = wire::parse_json_payload(frame);
    if (json_result) {
        auto& json = json_result->as_object();
        int code = json.contains("code") ? static_cast<int>(json.at("code").as_int64()) : 0;
        std::string message = json.contains("message")
            ? json.at("message").as_string().c_str()
            : "Unknown error";
        LOG_ERROR("ControllerClient: Error from controller: {} - {}", code, message);
    }
}

void ControllerClient::send_heartbeat() {
    if (!registered_) {
        return;
    }

    boost::json::object payload;
    payload["server_id"] = server_id_;
    payload["timestamp"] = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    payload["connected_clients"] = static_cast<uint64_t>(
        server_.session_manager()->client_count());

    auto frame = wire::create_json_frame(wire::MessageType::SERVER_HEARTBEAT, payload);
    send_frame(frame);
}

void ControllerClient::send_latency_report(
    const std::vector<std::tuple<std::string, uint32_t, uint32_t>>& entries) {

    if (!registered_) {
        return;
    }

    boost::json::object payload;
    payload["server_id"] = server_id_;

    boost::json::array arr;
    for (const auto& [dst_type, dst_id, rtt_ms] : entries) {
        boost::json::object entry;
        entry["dst_type"] = dst_type;
        entry["dst_id"] = dst_id;
        entry["rtt_ms"] = rtt_ms;
        arr.push_back(entry);
    }
    payload["entries"] = arr;

    auto frame = wire::create_json_frame(wire::MessageType::LATENCY_REPORT, payload);
    send_frame(frame);
}

} // namespace edgelink

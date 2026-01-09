#include "client/control_channel_coro.hpp"
#include "common/config.hpp"
#include "common/log.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

namespace edgelink::client {

// ============================================================================
// Constructor / Destructor
// ============================================================================

ControlChannelCoro::ControlChannelCoro(
    net::io_context& ioc,
    const std::string& controller_url,
    const std::array<uint8_t, 32>& machine_key_pub,
    const std::array<uint8_t, 64>& machine_key_priv,
    const std::array<uint8_t, 32>& node_key_pub,
    const std::array<uint8_t, 32>& node_key_priv,
    const std::string& auth_key
)
    : WsClientCoro(ioc, controller_url + paths::WS_CONTROL, "ControlChannelCoro")
    , machine_key_pub_(machine_key_pub)
    , machine_key_priv_(machine_key_priv)
    , node_key_pub_(node_key_pub)
    , node_key_priv_(node_key_priv)
    , auth_key_(auth_key)
{
    // Determine auth type
    if (!auth_key_.empty()) {
        auth_type_ = wire::AuthType::AUTHKEY;
    } else {
        bool has_machine_key = false;
        for (auto b : machine_key_pub_) {
            if (b != 0) {
                has_machine_key = true;
                break;
            }
        }
        auth_type_ = has_machine_key ? wire::AuthType::MACHINE : wire::AuthType::USER;
    }

    LOG_INFO("ControlChannelCoro: Configured for {} (auth_type: {})",
             url(), static_cast<int>(auth_type_));
}

ControlChannelCoro::~ControlChannelCoro() = default;

void ControlChannelCoro::set_control_callbacks(ControlCallbacks callbacks) {
    control_callbacks_ = std::move(callbacks);
}

// ============================================================================
// WsClientCoro Interface
// ============================================================================

net::awaitable<void> ControlChannelCoro::on_connected() {
    LOG_DEBUG("ControlChannelCoro: Connection established");
    if (control_callbacks_.on_connected) {
        control_callbacks_.on_connected();
    }
    co_return;
}

net::awaitable<std::optional<wire::Frame>> ControlChannelCoro::create_auth_frame() {
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    boost::json::object auth_json;
    auth_json["auth_type"] = static_cast<int>(auth_type_);
    auth_json["timestamp"] = ts;

    // System info
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    auth_json["hostname"] = hostname;
    auth_json["version"] = "0.1.0";

#ifdef _WIN32
    auth_json["os"] = "windows";
#elif __linux__
    auth_json["os"] = "linux";
#elif __APPLE__
    auth_json["os"] = "darwin";
#else
    auth_json["os"] = "unknown";
#endif

#if defined(__x86_64__) || defined(_M_X64)
    auth_json["arch"] = "amd64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    auth_json["arch"] = "arm64";
#else
    auth_json["arch"] = "unknown";
#endif

    if (!auth_key_.empty()) {
        auth_json["auth_key"] = auth_key_;
    }

    LOG_DEBUG("ControlChannelCoro: Creating auth frame");
    co_return wire::create_json_frame(wire::MessageType::AUTH_REQUEST, auth_json);
}

net::awaitable<bool> ControlChannelCoro::handle_auth_response(const wire::Frame& frame) {
    auto json = frame.payload_json();
    if (json.is_null()) {
        LOG_ERROR("ControlChannelCoro: Invalid auth response payload");
        co_return false;
    }

    try {
        bool success = json.at("success").as_bool();

        if (!success) {
            std::string error_msg = "Unknown error";
            if (json.as_object().contains("error_message")) {
                error_msg = std::string(json.at("error_message").as_string());
            }
            LOG_ERROR("ControlChannelCoro: Authentication failed: {}", error_msg);
            co_return false;
        }

        node_id_ = static_cast<uint32_t>(json.at("node_id").as_int64());
        network_id_ = static_cast<uint32_t>(json.at("network_id").as_int64());

        if (json.as_object().contains("virtual_ip")) {
            virtual_ip_ = std::string(json.at("virtual_ip").as_string());
        }
        if (json.as_object().contains("auth_token")) {
            auth_token_ = std::string(json.at("auth_token").as_string());
        }
        if (json.as_object().contains("relay_token")) {
            relay_token_ = std::string(json.at("relay_token").as_string());
        }

        LOG_INFO("ControlChannelCoro: Authenticated as node {} ({})", node_id_, virtual_ip_);
        co_return true;

    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannelCoro: Failed to parse auth response: {}", e.what());
        co_return false;
    }
}

net::awaitable<void> ControlChannelCoro::process_frame(const wire::Frame& frame) {
    switch (frame.header.type) {
        case wire::MessageType::CONFIG:
            handle_config(frame);
            break;

        case wire::MessageType::CONFIG_UPDATE:
            handle_config_update(frame);
            break;

        case wire::MessageType::P2P_ENDPOINT:
            handle_p2p_endpoint(frame);
            break;

        case wire::MessageType::P2P_INIT:
            handle_p2p_init(frame);
            break;

        case wire::MessageType::ROUTE_UPDATE:
            handle_route_update(frame);
            break;

        case wire::MessageType::ERROR_MSG:
            handle_error(frame);
            break;

        default:
            LOG_DEBUG("ControlChannelCoro: Unhandled message type: {}",
                      static_cast<int>(frame.header.type));
            break;
    }
    co_return;
}

net::awaitable<void> ControlChannelCoro::on_disconnected(const std::string& reason) {
    LOG_DEBUG("ControlChannelCoro: Disconnected (reason: {})", reason);
    if (control_callbacks_.on_disconnected) {
        control_callbacks_.on_disconnected(ErrorCode::NOT_CONNECTED);
    }
    co_return;
}

// ============================================================================
// Frame Handlers
// ============================================================================

void ControlChannelCoro::handle_config(const wire::Frame& frame) {
    auto json = frame.payload_json();
    if (json.is_null()) {
        LOG_ERROR("ControlChannelCoro: Invalid config payload");
        return;
    }

    try {
        ConfigUpdate update;

        if (json.as_object().contains("version")) {
            update.version = static_cast<uint64_t>(json.at("version").as_int64());
        }

        if (json.as_object().contains("network_id")) {
            update.network.network_id = static_cast<uint32_t>(json.at("network_id").as_int64());
        }
        if (json.as_object().contains("network_name")) {
            update.network.network_name = std::string(json.at("network_name").as_string());
        }
        if (json.as_object().contains("subnet")) {
            update.network.cidr = std::string(json.at("subnet").as_string());
        }

        if (json.as_object().contains("peers") && json.at("peers").is_array()) {
            for (const auto& peer_json : json.at("peers").as_array()) {
                PeerInfo peer;
                peer.node_id = static_cast<uint32_t>(peer_json.at("node_id").as_int64());
                if (peer_json.as_object().contains("name")) {
                    peer.hostname = std::string(peer_json.at("name").as_string());
                }
                if (peer_json.as_object().contains("virtual_ip")) {
                    peer.virtual_ip = std::string(peer_json.at("virtual_ip").as_string());
                }
                if (peer_json.as_object().contains("online")) {
                    peer.online = peer_json.at("online").as_bool();
                }
                update.peers.push_back(std::move(peer));
            }
        }

        if (json.as_object().contains("relays") && json.at("relays").is_array()) {
            for (const auto& relay_json : json.at("relays").as_array()) {
                RelayServerInfo relay;
                relay.id = static_cast<uint32_t>(relay_json.at("server_id").as_int64());
                if (relay_json.as_object().contains("name")) {
                    relay.name = std::string(relay_json.at("name").as_string());
                }
                if (relay_json.as_object().contains("region")) {
                    relay.region = std::string(relay_json.at("region").as_string());
                }
                if (relay_json.as_object().contains("url")) {
                    relay.url = std::string(relay_json.at("url").as_string());
                }
                update.relays.push_back(std::move(relay));
            }
        }

        if (json.as_object().contains("routes") && json.at("routes").is_array()) {
            for (const auto& route_json : json.at("routes").as_array()) {
                SubnetRouteInfo route;
                if (route_json.as_object().contains("cidr")) {
                    route.cidr = std::string(route_json.at("cidr").as_string());
                }
                if (route_json.as_object().contains("gateway_node_id")) {
                    route.via_node_id = static_cast<uint32_t>(route_json.at("gateway_node_id").as_int64());
                }
                if (route_json.as_object().contains("priority")) {
                    route.priority = static_cast<uint16_t>(route_json.at("priority").as_int64());
                }
                update.subnet_routes.push_back(std::move(route));
            }
        }

        update.auth_token = auth_token_;
        if (json.as_object().contains("relay_token")) {
            relay_token_ = std::string(json.at("relay_token").as_string());
        }
        update.relay_token = relay_token_;
        update.timestamp = std::chrono::system_clock::now();

        network_config_ = update.network;
        config_version_ = update.version;

        if (control_callbacks_.on_config_update) {
            control_callbacks_.on_config_update(update);
        }

        send_config_ack(update.version);

    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannelCoro: Failed to parse config: {}", e.what());
    }
}

void ControlChannelCoro::handle_config_update(const wire::Frame& frame) {
    LOG_DEBUG("ControlChannelCoro: Received config update");
}

void ControlChannelCoro::handle_p2p_endpoint(const wire::Frame& frame) {
    auto json = frame.payload_json();
    if (json.is_null()) return;

    try {
        uint32_t peer_id = static_cast<uint32_t>(json.at("peer_node_id").as_int64());
        std::vector<std::string> endpoints;

        if (json.as_object().contains("endpoints") && json.at("endpoints").is_array()) {
            for (const auto& ep : json.at("endpoints").as_array()) {
                std::string ip = std::string(ep.at("ip").as_string());
                uint16_t port = static_cast<uint16_t>(ep.at("port").as_int64());
                endpoints.push_back(ip + ":" + std::to_string(port));
            }
        }

        wire::NATType nat_type = wire::NATType::UNKNOWN;
        if (json.as_object().contains("nat_type")) {
            nat_type = static_cast<wire::NATType>(json.at("nat_type").as_int64());
        }

        if (control_callbacks_.on_p2p_endpoints) {
            control_callbacks_.on_p2p_endpoints(peer_id, endpoints, nat_type);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannelCoro: Failed to parse P2P endpoint: {}", e.what());
    }
}

void ControlChannelCoro::handle_p2p_init(const wire::Frame& frame) {
    auto json = frame.payload_json();
    if (json.is_null()) return;

    try {
        uint32_t peer_id = static_cast<uint32_t>(json.at("peer_node_id").as_int64());
        std::vector<std::string> endpoints;

        if (json.as_object().contains("endpoints") && json.at("endpoints").is_array()) {
            for (const auto& ep : json.at("endpoints").as_array()) {
                std::string ip = std::string(ep.at("ip").as_string());
                uint16_t port = static_cast<uint16_t>(ep.at("port").as_int64());
                endpoints.push_back(ip + ":" + std::to_string(port));
            }
        }

        wire::NATType nat_type = wire::NATType::UNKNOWN;
        if (json.as_object().contains("nat_type")) {
            nat_type = static_cast<wire::NATType>(json.at("nat_type").as_int64());
        }

        if (control_callbacks_.on_p2p_init) {
            control_callbacks_.on_p2p_init(peer_id, endpoints, nat_type);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannelCoro: Failed to parse P2P init: {}", e.what());
    }
}

void ControlChannelCoro::handle_route_update(const wire::Frame& frame) {
    LOG_DEBUG("ControlChannelCoro: Received route update");

    auto result = wire::RouteUpdatePayload::deserialize_binary(frame.payload);
    if (!result) {
        auto json = frame.payload_json();
        if (!json.is_null()) {
            result = wire::RouteUpdatePayload::from_json(json);
        }
    }

    if (!result) {
        LOG_WARN("ControlChannelCoro: Invalid route update payload");
        return;
    }

    const auto& update = *result;
    LOG_DEBUG("ControlChannelCoro: Route update version={}, {} changes",
              update.version, update.changes.size());

    if (control_callbacks_.on_route_update) {
        control_callbacks_.on_route_update(update);
    }
}

void ControlChannelCoro::handle_error(const wire::Frame& frame) {
    auto json = frame.payload_json();
    if (json.is_null()) return;

    try {
        uint16_t code = static_cast<uint16_t>(json.at("code").as_int64());
        std::string message = "Unknown error";
        if (json.as_object().contains("message")) {
            message = std::string(json.at("message").as_string());
        }
        LOG_ERROR("ControlChannelCoro: Server error {}: {}", code, message);
    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannelCoro: Failed to parse error: {}", e.what());
    }
}

// ============================================================================
// Control Messages
// ============================================================================

void ControlChannelCoro::report_latency(uint32_t peer_node_id, uint32_t relay_id,
                                         uint32_t latency_ms) {
    if (!is_connected()) return;

    boost::json::object json;
    boost::json::array entries;
    boost::json::object entry;
    entry["dst_type"] = "relay";
    entry["dst_id"] = relay_id;
    entry["rtt_ms"] = latency_ms;
    entries.push_back(entry);
    json["entries"] = entries;

    auto frame = wire::create_json_frame(wire::MessageType::LATENCY_REPORT, json);
    send_frame(frame);
}

void ControlChannelCoro::report_latency_batch(
    const std::vector<LatencyMeasurement>& measurements) {
    if (!is_connected() || measurements.empty()) return;

    boost::json::object json;
    boost::json::array entries;

    for (const auto& m : measurements) {
        boost::json::object entry;
        entry["dst_type"] = m.dst_type;
        entry["dst_id"] = m.dst_id;
        entry["rtt_ms"] = m.rtt_ms;
        entries.push_back(entry);
    }
    json["entries"] = entries;

    auto frame = wire::create_json_frame(wire::MessageType::LATENCY_REPORT, json);
    send_frame(frame);
    LOG_DEBUG("ControlChannelCoro: Reporting {} latency measurements", measurements.size());
}

void ControlChannelCoro::report_endpoints(const std::vector<wire::Endpoint>& endpoints) {
    if (!is_connected()) return;

    boost::json::object json;
    boost::json::array eps;

    for (const auto& ep : endpoints) {
        boost::json::object ep_json;
        ep_json["type"] = static_cast<int>(ep.type);
        ep_json["ip"] = ep.ip;
        ep_json["port"] = ep.port;
        ep_json["priority"] = ep.priority;
        eps.push_back(ep_json);
    }
    json["endpoints"] = eps;

    auto frame = wire::create_json_frame(wire::MessageType::P2P_STATUS, json);
    send_frame(frame);
}

void ControlChannelCoro::request_peer_endpoints(uint32_t peer_node_id) {
    if (!is_connected()) return;

    LOG_DEBUG("ControlChannelCoro: Requesting P2P endpoints for peer {}", peer_node_id);

    boost::json::object json;
    json["peer_node_id"] = peer_node_id;

    auto frame = wire::create_json_frame(wire::MessageType::P2P_INIT, json);
    send_frame(frame);
}

void ControlChannelCoro::report_p2p_status(uint32_t peer_node_id, bool connected,
                                            const std::string& endpoint_ip,
                                            uint16_t endpoint_port, uint32_t rtt_ms) {
    if (!is_connected()) return;

    boost::json::object json;
    json["peer_node_id"] = peer_node_id;
    json["connected"] = connected;
    json["endpoint_ip"] = endpoint_ip;
    json["endpoint_port"] = endpoint_port;
    json["rtt_ms"] = rtt_ms;

    auto frame = wire::create_json_frame(wire::MessageType::P2P_STATUS, json);
    send_frame(frame);
}

void ControlChannelCoro::report_key_rotation(const std::array<uint8_t, 32>& new_pubkey,
                                              const std::array<uint8_t, 64>& signature) {
    if (!is_connected()) return;
    LOG_WARN("ControlChannelCoro: Key rotation not yet implemented");
}

void ControlChannelCoro::announce_route(const std::string& prefix, uint8_t prefix_len,
                                         uint16_t priority, uint16_t weight, uint8_t flags) {
    if (!is_connected()) return;

    boost::json::object json;
    json["prefix"] = prefix;
    json["prefix_len"] = prefix_len;
    json["priority"] = priority;
    json["weight"] = weight;
    json["flags"] = flags;

    auto frame = wire::create_json_frame(wire::MessageType::ROUTE_ANNOUNCE, json);
    send_frame(frame);
    LOG_INFO("ControlChannelCoro: Announcing route {}/{}", prefix, prefix_len);
}

void ControlChannelCoro::withdraw_route(const std::string& prefix, uint8_t prefix_len) {
    if (!is_connected()) return;

    boost::json::object json;
    json["prefix"] = prefix;
    json["prefix_len"] = prefix_len;

    auto frame = wire::create_json_frame(wire::MessageType::ROUTE_WITHDRAW, json);
    send_frame(frame);
    LOG_INFO("ControlChannelCoro: Withdrawing route {}/{}", prefix, prefix_len);
}

void ControlChannelCoro::send_config_ack(uint64_t version) {
    boost::json::object json;
    json["version"] = static_cast<int64_t>(version);

    auto frame = wire::create_json_frame(wire::MessageType::CONFIG_ACK, json);
    send_frame(frame);
}

} // namespace edgelink::client

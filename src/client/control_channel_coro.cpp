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
    // Build AuthRequestPayload using binary format
    wire::AuthRequestPayload payload;
    payload.auth_type = auth_type_;
    payload.machine_key = machine_key_pub_;
    payload.node_key = node_key_pub_;
    payload.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    // System info
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    payload.hostname = hostname;
    payload.version = "0.1.0";

#ifdef _WIN32
    payload.os = "windows";
#elif __linux__
    payload.os = "linux";
#elif __APPLE__
    payload.os = "darwin";
#else
    payload.os = "unknown";
#endif

#if defined(__x86_64__) || defined(_M_X64)
    payload.arch = "amd64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    payload.arch = "arm64";
#else
    payload.arch = "unknown";
#endif

    // Auth-type specific data
    if (!auth_key_.empty()) {
        payload.auth_key = auth_key_;
    }

    // TODO: Sign the payload with machine_key_priv_
    // For now, leave signature as zeros

    // Serialize to binary
    auto binary_payload = payload.serialize_binary();

    LOG_DEBUG("ControlChannelCoro: Creating AUTH_REQUEST (binary, {} bytes, auth_type={})",
              binary_payload.size(), static_cast<int>(auth_type_));

    co_return wire::Frame::create(wire::MessageType::AUTH_REQUEST, std::move(binary_payload));
}

net::awaitable<bool> ControlChannelCoro::handle_auth_response(const wire::Frame& frame) {
    LOG_DEBUG("ControlChannelCoro: Received AUTH_RESPONSE ({} bytes)", frame.payload.size());

    auto result = wire::AuthResponsePayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_ERROR("ControlChannelCoro: Failed to parse AUTH_RESPONSE: error={}",
                  static_cast<int>(result.error()));
        co_return false;
    }

    const auto& payload = *result;
    if (!payload.success) {
        LOG_ERROR("ControlChannelCoro: Authentication failed: code={}, msg={}",
                  payload.error_code, payload.error_message);
        co_return false;
    }

    node_id_ = payload.node_id;
    network_id_ = payload.network_id;
    auth_token_ = payload.auth_token;
    relay_token_ = payload.relay_token;

    // Convert virtual_ip_int to string
    if (payload.virtual_ip_int != 0) {
        struct in_addr addr;
        addr.s_addr = payload.virtual_ip_int;
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            virtual_ip_ = buf;
        }
    } else if (!payload.virtual_ip.empty()) {
        virtual_ip_ = payload.virtual_ip;
    }

    LOG_INFO("ControlChannelCoro: Authenticated as node {} ({})", node_id_, virtual_ip_);
    co_return true;
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
    LOG_DEBUG("ControlChannelCoro: Received CONFIG ({} bytes)", frame.payload.size());

    auto result = wire::ConfigPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_ERROR("ControlChannelCoro: Failed to parse CONFIG: error={}",
                  static_cast<int>(result.error()));
        return;
    }

    const auto& config = *result;

    ConfigUpdate update;
    update.auth_token = auth_token_;
    update.relay_token = relay_token_;
    update.timestamp = std::chrono::system_clock::now();
    update.version = config.version;
    update.network.network_id = config.network_id;
    update.network.network_name = config.network_name;
    update.network.cidr = config.subnet;

    // Convert peers
    for (const auto& p : config.peers) {
        PeerInfo peer;
        peer.node_id = p.node_id;
        peer.hostname = p.name;
        peer.virtual_ip = p.virtual_ip;
        peer.online = p.online;
        update.peers.push_back(std::move(peer));
    }

    // Convert relays
    for (const auto& r : config.relays) {
        RelayServerInfo relay;
        relay.id = r.server_id;
        relay.name = r.name;
        relay.region = r.region;
        relay.url = r.url;
        update.relays.push_back(std::move(relay));
    }

    // Convert routes
    for (const auto& r : config.routes) {
        SubnetRouteInfo route;
        route.cidr = r.to_cidr();
        route.via_node_id = r.gateway_node_id;
        route.priority = r.priority;
        update.subnet_routes.push_back(std::move(route));
    }

    // Update tokens if present
    if (!config.new_relay_token.empty()) {
        relay_token_ = config.new_relay_token;
        update.relay_token = relay_token_;
    }

    network_config_ = update.network;
    config_version_ = update.version;

    LOG_INFO("ControlChannelCoro: Config received (version={}, {} peers, {} relays, {} routes)",
             update.version, update.peers.size(), update.relays.size(), update.subnet_routes.size());

    if (control_callbacks_.on_config_update) {
        control_callbacks_.on_config_update(update);
    }

    send_config_ack(update.version);
}

void ControlChannelCoro::handle_config_update(const wire::Frame& frame) {
    LOG_DEBUG("ControlChannelCoro: Received config update");
}

void ControlChannelCoro::handle_p2p_endpoint(const wire::Frame& frame) {
    auto result = wire::P2PEndpointPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_ERROR("ControlChannelCoro: Failed to parse P2P_ENDPOINT: error={}",
                  static_cast<int>(result.error()));
        return;
    }

    const auto& payload = *result;
    std::vector<std::string> endpoints;
    for (const auto& ep : payload.endpoints) {
        endpoints.push_back(ep.ip + ":" + std::to_string(ep.port));
    }

    if (control_callbacks_.on_p2p_endpoints) {
        control_callbacks_.on_p2p_endpoints(payload.peer_node_id, endpoints, payload.nat_type);
    }
}

void ControlChannelCoro::handle_p2p_init(const wire::Frame& frame) {
    auto result = wire::P2PEndpointPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_ERROR("ControlChannelCoro: Failed to parse P2P_INIT: error={}",
                  static_cast<int>(result.error()));
        return;
    }

    const auto& payload = *result;
    std::vector<std::string> endpoints;
    for (const auto& ep : payload.endpoints) {
        endpoints.push_back(ep.ip + ":" + std::to_string(ep.port));
    }

    if (control_callbacks_.on_p2p_init) {
        control_callbacks_.on_p2p_init(payload.peer_node_id, endpoints, payload.nat_type);
    }
}

void ControlChannelCoro::handle_route_update(const wire::Frame& frame) {
    LOG_DEBUG("ControlChannelCoro: Received route update");

    auto result = wire::RouteUpdatePayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_WARN("ControlChannelCoro: Failed to parse ROUTE_UPDATE: error={}",
                 static_cast<int>(result.error()));
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
    auto result = wire::ErrorPayload::deserialize_binary(frame.payload);
    if (!result) {
        LOG_ERROR("ControlChannelCoro: Failed to parse ERROR_MSG");
        return;
    }

    LOG_ERROR("ControlChannelCoro: Server error {}: {}", result->code, result->message);
}

// ============================================================================
// Control Messages
// ============================================================================

void ControlChannelCoro::report_latency(uint32_t peer_node_id, uint32_t relay_id,
                                         uint32_t latency_ms) {
    if (!is_connected()) return;

    wire::LatencyReportPayload payload;
    payload.entries.push_back({
        .dst_type = 0,  // 0=relay
        .dst_id = relay_id,
        .rtt_ms = latency_ms
    });

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::LATENCY_REPORT, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("ControlChannelCoro: Reported latency to relay {} ({}ms)", relay_id, latency_ms);
}

void ControlChannelCoro::report_latency_batch(
    const std::vector<LatencyMeasurement>& measurements) {
    if (!is_connected() || measurements.empty()) return;

    wire::LatencyReportPayload payload;
    for (const auto& m : measurements) {
        payload.entries.push_back({
            .dst_type = static_cast<uint8_t>(m.dst_type == "node" ? 1 : 0),
            .dst_id = m.dst_id,
            .rtt_ms = m.rtt_ms
        });
    }

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::LATENCY_REPORT, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("ControlChannelCoro: Reported {} latency measurements", measurements.size());
}

void ControlChannelCoro::report_endpoints(const std::vector<wire::Endpoint>& endpoints) {
    if (!is_connected()) return;

    wire::P2PEndpointPayload payload;
    payload.peer_node_id = node_id_;  // Report our own endpoints
    payload.endpoints = endpoints;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::P2P_STATUS, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("ControlChannelCoro: Reported {} endpoints", endpoints.size());
}

void ControlChannelCoro::request_peer_endpoints(uint32_t peer_node_id) {
    if (!is_connected()) return;

    LOG_DEBUG("ControlChannelCoro: Requesting P2P endpoints for peer {}", peer_node_id);

    // P2P_INIT uses a simple binary format: peer_node_id(4)
    wire::BinaryWriter w;
    w.write_u32(peer_node_id);
    auto frame = wire::Frame::create(wire::MessageType::P2P_INIT, w.data());
    send_frame(frame);
}

void ControlChannelCoro::report_p2p_status(uint32_t peer_node_id, bool connected,
                                            const std::string& endpoint_ip,
                                            uint16_t endpoint_port, uint32_t rtt_ms) {
    if (!is_connected()) return;

    wire::P2PStatusPayload payload;
    payload.peer_node_id = peer_node_id;
    payload.connected = connected;
    // Convert IP string to uint32
    struct in_addr addr;
    if (inet_pton(AF_INET, endpoint_ip.c_str(), &addr) == 1) {
        payload.endpoint_ip = addr.s_addr;
    }
    payload.endpoint_port = endpoint_port;
    payload.rtt_ms = rtt_ms;

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::P2P_STATUS, std::move(binary));
    send_frame(frame);
    LOG_DEBUG("ControlChannelCoro: Reported P2P status for peer {} (connected={})",
              peer_node_id, connected);
}

void ControlChannelCoro::report_key_rotation(const std::array<uint8_t, 32>& new_pubkey,
                                              const std::array<uint8_t, 64>& signature) {
    if (!is_connected()) return;
    LOG_WARN("ControlChannelCoro: Key rotation not yet implemented");
}

void ControlChannelCoro::announce_route(const std::string& prefix, uint8_t prefix_len,
                                         uint16_t priority, uint16_t weight, uint8_t flags) {
    if (!is_connected()) return;

    wire::RouteAnnouncePayload payload;
    payload.gateway_node_id = node_id_;
    wire::RouteInfo route;
    route.from_cidr(prefix + "/" + std::to_string(prefix_len));
    route.priority = priority;
    route.weight = weight;
    route.flags = flags;
    payload.routes.push_back(route);

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::ROUTE_ANNOUNCE, std::move(binary));
    send_frame(frame);
    LOG_INFO("ControlChannelCoro: Announced route {}/{}", prefix, prefix_len);
}

void ControlChannelCoro::withdraw_route(const std::string& prefix, uint8_t prefix_len) {
    if (!is_connected()) return;

    // ROUTE_WITHDRAW uses RouteUpdatePayload with REMOVE action
    wire::RouteUpdatePayload payload;
    payload.version = config_version_;
    wire::RouteInfo route;
    route.from_cidr(prefix + "/" + std::to_string(prefix_len));
    payload.changes.push_back({
        .action = wire::RouteUpdatePayload::Action::REMOVE,
        .route = route
    });

    auto binary = payload.serialize_binary();
    auto frame = wire::Frame::create(wire::MessageType::ROUTE_WITHDRAW, std::move(binary));
    send_frame(frame);
    LOG_INFO("ControlChannelCoro: Withdrew route {}/{}", prefix, prefix_len);
}

void ControlChannelCoro::send_config_ack(uint64_t version) {
    // CONFIG_ACK: simple binary format with version(8)
    wire::BinaryWriter w;
    w.write_u64(version);
    auto frame = wire::Frame::create(wire::MessageType::CONFIG_ACK, w.data());
    send_frame(frame);
    LOG_DEBUG("ControlChannelCoro: Sent CONFIG_ACK for version {}", version);
}

} // namespace edgelink::client

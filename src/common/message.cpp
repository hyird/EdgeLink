#include "common/message.hpp"

namespace edgelink {

std::string parse_error_message(ParseError error) {
    switch (error) {
        case ParseError::INSUFFICIENT_DATA: return "Insufficient data";
        case ParseError::INVALID_FORMAT: return "Invalid format";
        case ParseError::STRING_TOO_LONG: return "String too long";
        case ParseError::ARRAY_TOO_LARGE: return "Array too large";
        default: return "Unknown parse error";
    }
}

// ============================================================================
// Serialization Helpers
// ============================================================================

namespace serialization {

void write_endpoint(BinaryWriter& writer, const Endpoint& ep) {
    writer.write_u8(static_cast<uint8_t>(ep.type));
    writer.write_u8(static_cast<uint8_t>(ep.ip_type));
    if (ep.ip_type == IpType::IPv4) {
        writer.write_bytes(std::span(ep.address.data(), 4));
    } else {
        writer.write_bytes(ep.address);
    }
    writer.write_u16_be(ep.port);
    writer.write_u8(ep.priority);
}

std::expected<Endpoint, ParseError> read_endpoint(BinaryReader& reader) {
    Endpoint ep;
    auto type = reader.read_u8();
    auto ip_type = reader.read_u8();
    if (!type || !ip_type) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    ep.type = static_cast<EndpointType>(*type);
    ep.ip_type = static_cast<IpType>(*ip_type);

    size_t addr_size = (ep.ip_type == IpType::IPv4) ? 4 : 16;
    auto addr = reader.read_bytes(addr_size);
    if (!addr) return std::unexpected(ParseError::INSUFFICIENT_DATA);
    std::copy(addr->begin(), addr->end(), ep.address.begin());

    auto port = reader.read_u16_be();
    auto priority = reader.read_u8();
    if (!port || !priority) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    ep.port = *port;
    ep.priority = *priority;
    return ep;
}

void write_subnet_info(BinaryWriter& writer, const SubnetInfo& subnet) {
    writer.write_u8(static_cast<uint8_t>(subnet.ip_type));
    if (subnet.ip_type == IpType::IPv4) {
        writer.write_bytes(std::span(subnet.prefix.data(), 4));
    } else {
        writer.write_bytes(subnet.prefix);
    }
    writer.write_u8(subnet.prefix_len);
}

std::expected<SubnetInfo, ParseError> read_subnet_info(BinaryReader& reader) {
    SubnetInfo subnet;
    auto ip_type = reader.read_u8();
    if (!ip_type) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    subnet.ip_type = static_cast<IpType>(*ip_type);
    size_t addr_size = (subnet.ip_type == IpType::IPv4) ? 4 : 16;

    auto prefix = reader.read_bytes(addr_size);
    auto prefix_len = reader.read_u8();
    if (!prefix || !prefix_len) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    std::copy(prefix->begin(), prefix->end(), subnet.prefix.begin());
    subnet.prefix_len = *prefix_len;
    return subnet;
}

void write_route_info(BinaryWriter& writer, const RouteInfo& route) {
    writer.write_u8(static_cast<uint8_t>(route.ip_type));
    if (route.ip_type == IpType::IPv4) {
        writer.write_bytes(std::span(route.prefix.data(), 4));
    } else {
        writer.write_bytes(route.prefix);
    }
    writer.write_u8(route.prefix_len);
    writer.write_u32_be(route.gateway_node);
    writer.write_u16_be(route.metric);
    writer.write_u8(static_cast<uint8_t>(route.flags));
}

std::expected<RouteInfo, ParseError> read_route_info(BinaryReader& reader) {
    RouteInfo route;
    auto ip_type = reader.read_u8();
    if (!ip_type) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    route.ip_type = static_cast<IpType>(*ip_type);
    size_t addr_size = (route.ip_type == IpType::IPv4) ? 4 : 16;

    auto prefix = reader.read_bytes(addr_size);
    auto prefix_len = reader.read_u8();
    auto gateway = reader.read_u32_be();
    auto metric = reader.read_u16_be();
    auto flags = reader.read_u8();

    if (!prefix || !prefix_len || !gateway || !metric || !flags) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    std::copy(prefix->begin(), prefix->end(), route.prefix.begin());
    route.prefix_len = *prefix_len;
    route.gateway_node = *gateway;
    route.metric = *metric;
    route.flags = static_cast<RouteFlags>(*flags);
    return route;
}

void write_peer_info(BinaryWriter& writer, const PeerInfo& peer) {
    writer.write_u32_be(peer.node_id);
    writer.write_bytes(peer.virtual_ip.bytes);
    writer.write_array(peer.node_key);
    writer.write_u8(peer.online ? 0x01 : 0x00);
    writer.write_string(peer.name);

    writer.write_u16_be(static_cast<uint16_t>(peer.endpoints.size()));
    for (const auto& ep : peer.endpoints) {
        write_endpoint(writer, ep);
    }

    writer.write_u16_be(static_cast<uint16_t>(peer.allowed_subnets.size()));
    for (const auto& subnet : peer.allowed_subnets) {
        write_subnet_info(writer, subnet);
    }
}

std::expected<PeerInfo, ParseError> read_peer_info(BinaryReader& reader) {
    PeerInfo peer;

    auto node_id = reader.read_u32_be();
    auto vip = reader.read_array<4>();
    auto node_key = reader.read_array<X25519_KEY_SIZE>();
    auto online = reader.read_u8();
    auto name = reader.read_string();

    if (!node_id || !vip || !node_key || !online || !name) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    peer.node_id = *node_id;
    std::copy(vip->begin(), vip->end(), peer.virtual_ip.bytes.begin());
    peer.node_key = *node_key;
    peer.online = (*online != 0);
    peer.name = *name;

    auto ep_count = reader.read_u16_be();
    if (!ep_count) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    peer.endpoints.reserve(*ep_count);
    for (uint16_t i = 0; i < *ep_count; ++i) {
        auto ep = read_endpoint(reader);
        if (!ep) return std::unexpected(ep.error());
        peer.endpoints.push_back(*ep);
    }

    auto subnet_count = reader.read_u16_be();
    if (!subnet_count) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    peer.allowed_subnets.reserve(*subnet_count);
    for (uint16_t i = 0; i < *subnet_count; ++i) {
        auto subnet = read_subnet_info(reader);
        if (!subnet) return std::unexpected(subnet.error());
        peer.allowed_subnets.push_back(*subnet);
    }

    return peer;
}

void write_relay_info(BinaryWriter& writer, const RelayInfo& relay) {
    writer.write_u32_be(relay.server_id);
    writer.write_string(relay.hostname);

    writer.write_u16_be(static_cast<uint16_t>(relay.endpoints.size()));
    for (const auto& ep : relay.endpoints) {
        write_endpoint(writer, ep);
    }

    writer.write_u16_be(relay.priority);
    writer.write_string(relay.region);
}

std::expected<RelayInfo, ParseError> read_relay_info(BinaryReader& reader) {
    RelayInfo relay;

    auto server_id = reader.read_u32_be();
    auto hostname = reader.read_string();

    if (!server_id || !hostname) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    relay.server_id = *server_id;
    relay.hostname = *hostname;

    auto ep_count = reader.read_u16_be();
    if (!ep_count) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    relay.endpoints.reserve(*ep_count);
    for (uint16_t i = 0; i < *ep_count; ++i) {
        auto ep = read_endpoint(reader);
        if (!ep) return std::unexpected(ep.error());
        relay.endpoints.push_back(*ep);
    }

    auto priority = reader.read_u16_be();
    auto region = reader.read_string();

    if (!priority || !region) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    relay.priority = *priority;
    relay.region = *region;
    return relay;
}

void write_stun_info(BinaryWriter& writer, const StunInfo& stun) {
    writer.write_string(stun.hostname);
    writer.write_u16_be(stun.port);
}

std::expected<StunInfo, ParseError> read_stun_info(BinaryReader& reader) {
    StunInfo stun;

    auto hostname = reader.read_string();
    auto port = reader.read_u16_be();

    if (!hostname || !port) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    stun.hostname = *hostname;
    stun.port = *port;
    return stun;
}

} // namespace serialization

// ============================================================================
// AuthRequest
// ============================================================================

std::vector<uint8_t> AuthRequest::get_sign_data() const {
    BinaryWriter writer;
    writer.write_u8(static_cast<uint8_t>(auth_type));
    writer.write_array(machine_key);
    writer.write_array(node_key);
    writer.write_string(hostname);
    writer.write_string(os);
    writer.write_string(arch);
    writer.write_string(version);
    writer.write_u64_be(timestamp);
    writer.write_u16_be(static_cast<uint16_t>(auth_data.size()));
    writer.write_bytes(auth_data);
    return writer.take();
}

std::vector<uint8_t> AuthRequest::serialize() const {
    BinaryWriter writer;
    writer.write_u8(static_cast<uint8_t>(auth_type));
    writer.write_array(machine_key);
    writer.write_array(node_key);
    writer.write_string(hostname);
    writer.write_string(os);
    writer.write_string(arch);
    writer.write_string(version);
    writer.write_u64_be(timestamp);
    writer.write_array(signature);
    writer.write_u16_be(static_cast<uint16_t>(auth_data.size()));
    writer.write_bytes(auth_data);
    return writer.take();
}

std::expected<AuthRequest, ParseError> AuthRequest::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    AuthRequest req;

    auto auth_type = reader.read_u8();
    auto machine_key = reader.read_array<ED25519_PUBLIC_KEY_SIZE>();
    auto node_key = reader.read_array<X25519_KEY_SIZE>();
    auto hostname = reader.read_string();
    auto os = reader.read_string();
    auto arch = reader.read_string();
    auto version = reader.read_string();
    auto timestamp = reader.read_u64_be();
    auto signature = reader.read_array<ED25519_SIGNATURE_SIZE>();
    auto auth_data_len = reader.read_u16_be();

    if (!auth_type || !machine_key || !node_key || !hostname || !os ||
        !arch || !version || !timestamp || !signature || !auth_data_len) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    auto auth_data = reader.read_bytes(*auth_data_len);
    if (!auth_data) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    req.auth_type = static_cast<AuthType>(*auth_type);
    req.machine_key = *machine_key;
    req.node_key = *node_key;
    req.hostname = *hostname;
    req.os = *os;
    req.arch = *arch;
    req.version = *version;
    req.timestamp = *timestamp;
    req.signature = *signature;
    req.auth_data = *auth_data;

    return req;
}

// ============================================================================
// AuthResponse
// ============================================================================

std::vector<uint8_t> AuthResponse::serialize() const {
    BinaryWriter writer;
    writer.write_u8(success ? 0x01 : 0x00);
    writer.write_u32_be(node_id);
    writer.write_bytes(virtual_ip.bytes);
    writer.write_u32_be(network_id);
    writer.write_u16_be(static_cast<uint16_t>(auth_token.size()));
    writer.write_bytes(auth_token);
    writer.write_u16_be(static_cast<uint16_t>(relay_token.size()));
    writer.write_bytes(relay_token);
    writer.write_u16_be(error_code);
    writer.write_string(error_msg);
    return writer.take();
}

std::expected<AuthResponse, ParseError> AuthResponse::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    AuthResponse resp;

    auto success = reader.read_u8();
    auto node_id = reader.read_u32_be();
    auto vip = reader.read_array<4>();
    auto network_id = reader.read_u32_be();
    auto auth_token_len = reader.read_u16_be();

    if (!success || !node_id || !vip || !network_id || !auth_token_len) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    auto auth_token = reader.read_bytes(*auth_token_len);
    auto relay_token_len = reader.read_u16_be();

    if (!auth_token || !relay_token_len) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    auto relay_token = reader.read_bytes(*relay_token_len);
    auto error_code = reader.read_u16_be();
    auto error_msg = reader.read_string();

    if (!relay_token || !error_code || !error_msg) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    resp.success = (*success != 0);
    resp.node_id = *node_id;
    std::copy(vip->begin(), vip->end(), resp.virtual_ip.bytes.begin());
    resp.network_id = *network_id;
    resp.auth_token = *auth_token;
    resp.relay_token = *relay_token;
    resp.error_code = *error_code;
    resp.error_msg = *error_msg;

    return resp;
}

// ============================================================================
// RelayAuth
// ============================================================================

std::vector<uint8_t> RelayAuth::serialize() const {
    BinaryWriter writer;
    writer.write_u16_be(static_cast<uint16_t>(relay_token.size()));
    writer.write_bytes(relay_token);
    writer.write_u32_be(node_id);
    writer.write_array(node_key);
    return writer.take();
}

std::expected<RelayAuth, ParseError> RelayAuth::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RelayAuth auth;

    auto token_len = reader.read_u16_be();
    if (!token_len) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    auto token = reader.read_bytes(*token_len);
    auto node_id = reader.read_u32_be();
    auto node_key = reader.read_array<X25519_KEY_SIZE>();

    if (!token || !node_id || !node_key) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    auth.relay_token = *token;
    auth.node_id = *node_id;
    auth.node_key = *node_key;

    return auth;
}

// ============================================================================
// RelayAuthResp
// ============================================================================

std::vector<uint8_t> RelayAuthResp::serialize() const {
    BinaryWriter writer;
    writer.write_u8(success ? 0x01 : 0x00);
    writer.write_u16_be(error_code);
    writer.write_string(error_msg);
    return writer.take();
}

std::expected<RelayAuthResp, ParseError> RelayAuthResp::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RelayAuthResp resp;

    auto success = reader.read_u8();
    auto error_code = reader.read_u16_be();
    auto error_msg = reader.read_string();

    if (!success || !error_code || !error_msg) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    resp.success = (*success != 0);
    resp.error_code = *error_code;
    resp.error_msg = *error_msg;

    return resp;
}

// ============================================================================
// Config
// ============================================================================

std::vector<uint8_t> Config::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(version);
    writer.write_u32_be(network_id);
    writer.write_bytes(subnet.bytes);
    writer.write_u8(subnet_mask);
    writer.write_string(network_name);

    writer.write_u16_be(static_cast<uint16_t>(relays.size()));
    writer.write_u16_be(static_cast<uint16_t>(stuns.size()));
    writer.write_u16_be(static_cast<uint16_t>(peers.size()));
    writer.write_u16_be(static_cast<uint16_t>(routes.size()));

    for (const auto& relay : relays) {
        serialization::write_relay_info(writer, relay);
    }
    for (const auto& stun : stuns) {
        serialization::write_stun_info(writer, stun);
    }
    for (const auto& peer : peers) {
        serialization::write_peer_info(writer, peer);
    }
    for (const auto& route : routes) {
        serialization::write_route_info(writer, route);
    }

    writer.write_u16_be(static_cast<uint16_t>(relay_token.size()));
    writer.write_bytes(relay_token);
    writer.write_u64_be(relay_token_expires);

    return writer.take();
}

std::expected<Config, ParseError> Config::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    Config cfg;

    auto version = reader.read_u64_be();
    auto network_id = reader.read_u32_be();
    auto subnet = reader.read_array<4>();
    auto subnet_mask = reader.read_u8();
    auto network_name = reader.read_string();

    auto relay_count = reader.read_u16_be();
    auto stun_count = reader.read_u16_be();
    auto peer_count = reader.read_u16_be();
    auto route_count = reader.read_u16_be();

    if (!version || !network_id || !subnet || !subnet_mask || !network_name ||
        !relay_count || !stun_count || !peer_count || !route_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    cfg.version = *version;
    cfg.network_id = *network_id;
    std::copy(subnet->begin(), subnet->end(), cfg.subnet.bytes.begin());
    cfg.subnet_mask = *subnet_mask;
    cfg.network_name = *network_name;

    cfg.relays.reserve(*relay_count);
    for (uint16_t i = 0; i < *relay_count; ++i) {
        auto relay = serialization::read_relay_info(reader);
        if (!relay) return std::unexpected(relay.error());
        cfg.relays.push_back(*relay);
    }

    cfg.stuns.reserve(*stun_count);
    for (uint16_t i = 0; i < *stun_count; ++i) {
        auto stun = serialization::read_stun_info(reader);
        if (!stun) return std::unexpected(stun.error());
        cfg.stuns.push_back(*stun);
    }

    cfg.peers.reserve(*peer_count);
    for (uint16_t i = 0; i < *peer_count; ++i) {
        auto peer = serialization::read_peer_info(reader);
        if (!peer) return std::unexpected(peer.error());
        cfg.peers.push_back(*peer);
    }

    cfg.routes.reserve(*route_count);
    for (uint16_t i = 0; i < *route_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        cfg.routes.push_back(*route);
    }

    auto token_len = reader.read_u16_be();
    if (!token_len) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    auto token = reader.read_bytes(*token_len);
    auto expires = reader.read_u64_be();

    if (!token || !expires) return std::unexpected(ParseError::INSUFFICIENT_DATA);

    cfg.relay_token = *token;
    cfg.relay_token_expires = *expires;

    return cfg;
}

// ============================================================================
// DataPayload
// ============================================================================

std::vector<uint8_t> DataPayload::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(src_node);
    writer.write_u32_be(dst_node);
    writer.write_array(nonce);
    writer.write_bytes(encrypted_payload);
    return writer.take();
}

std::expected<DataPayload, ParseError> DataPayload::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    DataPayload payload;

    auto src = reader.read_u32_be();
    auto dst = reader.read_u32_be();
    auto nonce = reader.read_array<CHACHA20_NONCE_SIZE>();

    if (!src || !dst || !nonce) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    payload.src_node = *src;
    payload.dst_node = *dst;
    payload.nonce = *nonce;

    auto remaining = reader.remaining_data();
    payload.encrypted_payload.assign(remaining.begin(), remaining.end());

    return payload;
}

// ============================================================================
// DataAck
// ============================================================================

std::vector<uint8_t> DataAck::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(src_node);
    writer.write_u32_be(dst_node);
    writer.write_array(ack_nonce);
    writer.write_u8(static_cast<uint8_t>(ack_flags));
    return writer.take();
}

std::expected<DataAck, ParseError> DataAck::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    DataAck ack;

    auto src = reader.read_u32_be();
    auto dst = reader.read_u32_be();
    auto nonce = reader.read_array<CHACHA20_NONCE_SIZE>();
    auto flags = reader.read_u8();

    if (!src || !dst || !nonce || !flags) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ack.src_node = *src;
    ack.dst_node = *dst;
    ack.ack_nonce = *nonce;
    ack.ack_flags = static_cast<DataAckFlags>(*flags);

    return ack;
}

// ============================================================================
// Ping
// ============================================================================

std::vector<uint8_t> Ping::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(timestamp);
    writer.write_u32_be(seq_num);
    return writer.take();
}

std::expected<Ping, ParseError> Ping::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    Ping ping;

    auto timestamp = reader.read_u64_be();
    auto seq_num = reader.read_u32_be();

    if (!timestamp || !seq_num) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ping.timestamp = *timestamp;
    ping.seq_num = *seq_num;

    return ping;
}

// ============================================================================
// LatencyReport
// ============================================================================

std::vector<uint8_t> LatencyReport::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(timestamp);
    writer.write_u16_be(static_cast<uint16_t>(entries.size()));

    for (const auto& entry : entries) {
        writer.write_u32_be(entry.peer_node_id);
        writer.write_u16_be(entry.latency_ms);
        writer.write_u8(entry.path_type);
    }

    return writer.take();
}

std::expected<LatencyReport, ParseError> LatencyReport::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    LatencyReport report;

    auto timestamp = reader.read_u64_be();
    auto count = reader.read_u16_be();

    if (!timestamp || !count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    report.timestamp = *timestamp;
    report.entries.reserve(*count);

    for (uint16_t i = 0; i < *count; ++i) {
        auto node_id = reader.read_u32_be();
        auto latency = reader.read_u16_be();
        auto path_type = reader.read_u8();

        if (!node_id || !latency || !path_type) {
            return std::unexpected(ParseError::INSUFFICIENT_DATA);
        }

        report.entries.push_back({*node_id, *latency, *path_type});
    }

    return report;
}

// ============================================================================
// ErrorPayload
// ============================================================================

std::vector<uint8_t> ErrorPayload::serialize() const {
    BinaryWriter writer;
    writer.write_u16_be(error_code);
    writer.write_u8(static_cast<uint8_t>(request_type));
    writer.write_u32_be(request_id);
    writer.write_string(error_msg);
    return writer.take();
}

std::expected<ErrorPayload, ParseError> ErrorPayload::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    ErrorPayload err;

    auto code = reader.read_u16_be();
    auto type = reader.read_u8();
    auto id = reader.read_u32_be();
    auto msg = reader.read_string();

    if (!code || !type || !id || !msg) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    err.error_code = *code;
    err.request_type = static_cast<FrameType>(*type);
    err.request_id = *id;
    err.error_msg = *msg;

    return err;
}

// ============================================================================
// GenericAck
// ============================================================================

std::vector<uint8_t> GenericAck::serialize() const {
    BinaryWriter writer;
    writer.write_u8(static_cast<uint8_t>(request_type));
    writer.write_u32_be(request_id);
    writer.write_u8(status);
    return writer.take();
}

std::expected<GenericAck, ParseError> GenericAck::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    GenericAck ack;

    auto type = reader.read_u8();
    auto id = reader.read_u32_be();
    auto status = reader.read_u8();

    if (!type || !id || !status) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ack.request_type = static_cast<FrameType>(*type);
    ack.request_id = *id;
    ack.status = *status;

    return ack;
}

// ============================================================================
// ConfigAck
// ============================================================================

std::vector<uint8_t> ConfigAck::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(version);
    writer.write_u8(static_cast<uint8_t>(status));
    writer.write_u16_be(static_cast<uint16_t>(error_items.size()));

    for (const auto& item : error_items) {
        writer.write_u8(static_cast<uint8_t>(item.item_type));
        writer.write_u32_be(item.item_id);
        writer.write_u16_be(item.error_code);
    }

    return writer.take();
}

std::expected<ConfigAck, ParseError> ConfigAck::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    ConfigAck ack;

    auto version = reader.read_u64_be();
    auto status = reader.read_u8();
    auto error_count = reader.read_u16_be();

    if (!version || !status || !error_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ack.version = *version;
    ack.status = static_cast<ConfigAckStatus>(*status);

    ack.error_items.reserve(*error_count);
    for (uint16_t i = 0; i < *error_count; ++i) {
        auto item_type = reader.read_u8();
        auto item_id = reader.read_u32_be();
        auto error_code = reader.read_u16_be();

        if (!item_type || !item_id || !error_code) {
            return std::unexpected(ParseError::INSUFFICIENT_DATA);
        }

        ack.error_items.push_back({
            static_cast<ConfigErrorItemType>(*item_type),
            *item_id,
            *error_code
        });
    }

    return ack;
}

// ============================================================================
// ConfigUpdate (simplified implementation)
// ============================================================================

std::vector<uint8_t> ConfigUpdate::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(version);
    writer.write_u16_be(static_cast<uint16_t>(update_flags));
    writer.write_u16_be(static_cast<uint16_t>(add_relays.size()));
    writer.write_u16_be(static_cast<uint16_t>(add_peers.size()));
    writer.write_u16_be(static_cast<uint16_t>(add_routes.size()));

    for (const auto& relay : add_relays) {
        serialization::write_relay_info(writer, relay);
    }

    writer.write_u16_be(static_cast<uint16_t>(del_relay_ids.size()));
    for (auto id : del_relay_ids) {
        writer.write_u32_be(id);
    }

    for (const auto& peer : add_peers) {
        serialization::write_peer_info(writer, peer);
    }

    writer.write_u16_be(static_cast<uint16_t>(del_peer_ids.size()));
    for (auto id : del_peer_ids) {
        writer.write_u32_be(id);
    }

    for (const auto& route : add_routes) {
        serialization::write_route_info(writer, route);
    }

    writer.write_u16_be(static_cast<uint16_t>(del_routes.size()));
    for (const auto& route : del_routes) {
        serialization::write_route_info(writer, route);
    }

    if (has_flag(update_flags, ConfigUpdateFlags::TOKEN_REFRESH)) {
        writer.write_u16_be(static_cast<uint16_t>(relay_token.size()));
        writer.write_bytes(relay_token);
        writer.write_u64_be(relay_token_expires);
    }

    return writer.take();
}

std::expected<ConfigUpdate, ParseError> ConfigUpdate::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    ConfigUpdate update;

    auto version = reader.read_u64_be();
    auto flags = reader.read_u16_be();
    auto relay_count = reader.read_u16_be();
    auto peer_count = reader.read_u16_be();
    auto route_count = reader.read_u16_be();

    if (!version || !flags || !relay_count || !peer_count || !route_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    update.version = *version;
    update.update_flags = static_cast<ConfigUpdateFlags>(*flags);

    // Add relays
    update.add_relays.reserve(*relay_count);
    for (uint16_t i = 0; i < *relay_count; ++i) {
        auto relay = serialization::read_relay_info(reader);
        if (!relay) return std::unexpected(relay.error());
        update.add_relays.push_back(*relay);
    }

    // Delete relay IDs
    auto del_relay_count = reader.read_u16_be();
    if (!del_relay_count) return std::unexpected(ParseError::INSUFFICIENT_DATA);
    update.del_relay_ids.reserve(*del_relay_count);
    for (uint16_t i = 0; i < *del_relay_count; ++i) {
        auto id = reader.read_u32_be();
        if (!id) return std::unexpected(ParseError::INSUFFICIENT_DATA);
        update.del_relay_ids.push_back(*id);
    }

    // Add peers
    update.add_peers.reserve(*peer_count);
    for (uint16_t i = 0; i < *peer_count; ++i) {
        auto peer = serialization::read_peer_info(reader);
        if (!peer) return std::unexpected(peer.error());
        update.add_peers.push_back(*peer);
    }

    // Delete peer IDs
    auto del_peer_count = reader.read_u16_be();
    if (!del_peer_count) return std::unexpected(ParseError::INSUFFICIENT_DATA);
    update.del_peer_ids.reserve(*del_peer_count);
    for (uint16_t i = 0; i < *del_peer_count; ++i) {
        auto id = reader.read_u32_be();
        if (!id) return std::unexpected(ParseError::INSUFFICIENT_DATA);
        update.del_peer_ids.push_back(*id);
    }

    // Add routes
    update.add_routes.reserve(*route_count);
    for (uint16_t i = 0; i < *route_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        update.add_routes.push_back(*route);
    }

    // Delete routes
    auto del_route_count = reader.read_u16_be();
    if (!del_route_count) return std::unexpected(ParseError::INSUFFICIENT_DATA);
    update.del_routes.reserve(*del_route_count);
    for (uint16_t i = 0; i < *del_route_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        update.del_routes.push_back(*route);
    }

    // Token refresh
    if (has_flag(update.update_flags, ConfigUpdateFlags::TOKEN_REFRESH)) {
        auto token_len = reader.read_u16_be();
        if (!token_len) return std::unexpected(ParseError::INSUFFICIENT_DATA);

        auto token = reader.read_bytes(*token_len);
        auto expires = reader.read_u64_be();

        if (!token || !expires) return std::unexpected(ParseError::INSUFFICIENT_DATA);

        update.relay_token = *token;
        update.relay_token_expires = *expires;
    }

    return update;
}

// ============================================================================
// RouteAnnounce
// ============================================================================

std::vector<uint8_t> RouteAnnounce::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(request_id);
    writer.write_u16_be(static_cast<uint16_t>(routes.size()));

    for (const auto& route : routes) {
        serialization::write_route_info(writer, route);
    }

    return writer.take();
}

std::expected<RouteAnnounce, ParseError> RouteAnnounce::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RouteAnnounce announce;

    auto req_id = reader.read_u32_be();
    auto route_count = reader.read_u16_be();

    if (!req_id || !route_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    announce.request_id = *req_id;
    announce.routes.reserve(*route_count);

    for (uint16_t i = 0; i < *route_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        announce.routes.push_back(*route);
    }

    return announce;
}

// ============================================================================
// RouteUpdate
// ============================================================================

std::vector<uint8_t> RouteUpdate::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(version);
    writer.write_u16_be(static_cast<uint16_t>(add_routes.size()));
    writer.write_u16_be(static_cast<uint16_t>(del_routes.size()));

    for (const auto& route : add_routes) {
        serialization::write_route_info(writer, route);
    }

    for (const auto& route : del_routes) {
        serialization::write_route_info(writer, route);
    }

    return writer.take();
}

std::expected<RouteUpdate, ParseError> RouteUpdate::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RouteUpdate update;

    auto ver = reader.read_u64_be();
    auto add_count = reader.read_u16_be();
    auto del_count = reader.read_u16_be();

    if (!ver || !add_count || !del_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    update.version = *ver;

    update.add_routes.reserve(*add_count);
    for (uint16_t i = 0; i < *add_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        update.add_routes.push_back(*route);
    }

    update.del_routes.reserve(*del_count);
    for (uint16_t i = 0; i < *del_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        update.del_routes.push_back(*route);
    }

    return update;
}

// ============================================================================
// RouteWithdraw
// ============================================================================

std::vector<uint8_t> RouteWithdraw::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(request_id);
    writer.write_u16_be(static_cast<uint16_t>(routes.size()));

    for (const auto& route : routes) {
        serialization::write_route_info(writer, route);
    }

    return writer.take();
}

std::expected<RouteWithdraw, ParseError> RouteWithdraw::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RouteWithdraw withdraw;

    auto req_id = reader.read_u32_be();
    auto route_count = reader.read_u16_be();

    if (!req_id || !route_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    withdraw.request_id = *req_id;
    withdraw.routes.reserve(*route_count);

    for (uint16_t i = 0; i < *route_count; ++i) {
        auto route = serialization::read_route_info(reader);
        if (!route) return std::unexpected(route.error());
        withdraw.routes.push_back(*route);
    }

    return withdraw;
}

// ============================================================================
// RouteAck
// ============================================================================

std::vector<uint8_t> RouteAck::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(request_id);
    writer.write_u8(success ? 1 : 0);
    writer.write_u16_be(error_code);
    writer.write_string(error_msg);
    return writer.take();
}

std::expected<RouteAck, ParseError> RouteAck::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RouteAck ack;

    auto req_id = reader.read_u32_be();
    auto succ = reader.read_u8();
    auto err_code = reader.read_u16_be();
    auto err_msg = reader.read_string();

    if (!req_id || !succ || !err_code || !err_msg) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ack.request_id = *req_id;
    ack.success = (*succ != 0);
    ack.error_code = *err_code;
    ack.error_msg = *err_msg;

    return ack;
}

// ============================================================================
// P2P Messages
// ============================================================================

// P2PInit
std::vector<uint8_t> P2PInit::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(target_node);
    writer.write_u32_be(init_seq);
    return writer.take();
}

std::expected<P2PInit, ParseError> P2PInit::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    P2PInit init;

    auto target = reader.read_u32_be();
    auto seq = reader.read_u32_be();

    if (!target || !seq) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    init.target_node = *target;
    init.init_seq = *seq;
    return init;
}

// P2PEndpointMsg
std::vector<uint8_t> P2PEndpointMsg::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(init_seq);
    writer.write_u32_be(peer_node);
    writer.write_bytes(peer_key);
    writer.write_u16_be(static_cast<uint16_t>(endpoints.size()));
    for (const auto& ep : endpoints) {
        serialization::write_endpoint(writer, ep);
    }
    return writer.take();
}

std::expected<P2PEndpointMsg, ParseError> P2PEndpointMsg::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    P2PEndpointMsg msg;

    auto seq = reader.read_u32_be();
    auto node = reader.read_u32_be();
    auto key = reader.read_bytes(X25519_KEY_SIZE);
    auto ep_count = reader.read_u16_be();

    if (!seq || !node || !key || !ep_count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    msg.init_seq = *seq;
    msg.peer_node = *node;
    std::copy(key->begin(), key->end(), msg.peer_key.begin());

    msg.endpoints.reserve(*ep_count);
    for (uint16_t i = 0; i < *ep_count; ++i) {
        auto ep = serialization::read_endpoint(reader);
        if (!ep) return std::unexpected(ep.error());
        msg.endpoints.push_back(*ep);
    }

    return msg;
}

// P2PPing / P2PPong
std::vector<uint8_t> P2PPing::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(magic);
    writer.write_u32_be(src_node);
    writer.write_u32_be(dst_node);
    writer.write_u64_be(timestamp);
    writer.write_u32_be(seq_num);
    writer.write_bytes(nonce);
    writer.write_bytes(signature);
    return writer.take();
}

std::expected<P2PPing, ParseError> P2PPing::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    P2PPing ping;

    auto m = reader.read_u32_be();
    auto src = reader.read_u32_be();
    auto dst = reader.read_u32_be();
    auto ts = reader.read_u64_be();
    auto seq = reader.read_u32_be();
    auto n = reader.read_bytes(CHACHA20_NONCE_SIZE);
    auto sig = reader.read_bytes(ED25519_SIGNATURE_SIZE);

    if (!m || !src || !dst || !ts || !seq || !n || !sig) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ping.magic = *m;
    ping.src_node = *src;
    ping.dst_node = *dst;
    ping.timestamp = *ts;
    ping.seq_num = *seq;
    std::copy(n->begin(), n->end(), ping.nonce.begin());
    std::copy(sig->begin(), sig->end(), ping.signature.begin());

    return ping;
}

std::vector<uint8_t> P2PPing::get_sign_data() const {
    BinaryWriter writer;
    writer.write_u32_be(magic);
    writer.write_u32_be(src_node);
    writer.write_u32_be(dst_node);
    writer.write_u64_be(timestamp);
    writer.write_u32_be(seq_num);
    writer.write_bytes(nonce);
    return writer.take();
}

// P2PKeepalive
std::vector<uint8_t> P2PKeepalive::serialize() const {
    BinaryWriter writer;
    writer.write_u64_be(timestamp);
    writer.write_u32_be(seq_num);
    writer.write_u8(flags);
    writer.write_bytes(mac);
    return writer.take();
}

std::expected<P2PKeepalive, ParseError> P2PKeepalive::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    P2PKeepalive ka;

    auto ts = reader.read_u64_be();
    auto seq = reader.read_u32_be();
    auto f = reader.read_u8();
    auto m = reader.read_bytes(POLY1305_TAG_SIZE);

    if (!ts || !seq || !f || !m) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    ka.timestamp = *ts;
    ka.seq_num = *seq;
    ka.flags = *f;
    std::copy(m->begin(), m->end(), ka.mac.begin());

    return ka;
}

// P2PStatusMsg
std::vector<uint8_t> P2PStatusMsg::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(peer_node);
    writer.write_u8(static_cast<uint8_t>(status));
    writer.write_u16_be(latency_ms);
    writer.write_u8(static_cast<uint8_t>(path_type));
    return writer.take();
}

std::expected<P2PStatusMsg, ParseError> P2PStatusMsg::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    P2PStatusMsg msg;

    auto node = reader.read_u32_be();
    auto st = reader.read_u8();
    auto lat = reader.read_u16_be();
    auto pt = reader.read_u8();

    if (!node || !st || !lat || !pt) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    msg.peer_node = *node;
    msg.status = static_cast<P2PStatus>(*st);
    msg.latency_ms = *lat;
    msg.path_type = static_cast<PathType>(*pt);

    return msg;
}

// ============================================================================
// EndpointUpdate
// ============================================================================

std::vector<uint8_t> EndpointUpdate::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(request_id);
    writer.write_u16_be(static_cast<uint16_t>(endpoints.size()));
    for (const auto& ep : endpoints) {
        serialization::write_endpoint(writer, ep);
    }
    return writer.take();
}

std::expected<EndpointUpdate, ParseError> EndpointUpdate::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    EndpointUpdate msg;

    auto req_id = reader.read_u32_be();
    if (!req_id) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }
    msg.request_id = *req_id;

    auto count = reader.read_u16_be();
    if (!count) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    msg.endpoints.reserve(*count);
    for (uint16_t i = 0; i < *count; ++i) {
        auto ep = serialization::read_endpoint(reader);
        if (!ep) {
            return std::unexpected(ep.error());
        }
        msg.endpoints.push_back(*ep);
    }

    return msg;
}

// ============================================================================
// EndpointAck
// ============================================================================

std::vector<uint8_t> EndpointAck::serialize() const {
    BinaryWriter writer;
    writer.write_u32_be(request_id);
    writer.write_u8(success ? 1 : 0);
    writer.write_u8(endpoint_count);
    return writer.take();
}

std::expected<EndpointAck, ParseError> EndpointAck::parse(std::span<const uint8_t> data) {
    BinaryReader reader(data);
    EndpointAck msg;

    auto req_id = reader.read_u32_be();
    if (!req_id) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }
    msg.request_id = *req_id;

    auto succ = reader.read_u8();
    if (!succ) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }
    msg.success = (*succ != 0);

    auto cnt = reader.read_u8();
    if (!cnt) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }
    msg.endpoint_count = *cnt;

    return msg;
}

} // namespace edgelink

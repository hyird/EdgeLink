#include "common/message.hpp"

namespace edgelink {

std::string parse_error_message(ParseError error) {
    switch (error) {
        case ParseError::INSUFFICIENT_DATA: return "Insufficient data";
        case ParseError::INVALID_FORMAT: return "Invalid format";
        case ParseError::STRING_TOO_LONG: return "String too long";
        case ParseError::ARRAY_TOO_LARGE: return "Array too large";
        case ParseError::PROTOBUF_ERROR: return "Protobuf parsing error";
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
    writer.write_u8(peer.exit_node ? 0x01 : 0x00);  // 出口节点标志
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
    auto exit_node = reader.read_u8();  // 出口节点标志
    auto name = reader.read_string();

    if (!node_id || !vip || !node_key || !online || !exit_node || !name) {
        return std::unexpected(ParseError::INSUFFICIENT_DATA);
    }

    peer.node_id = *node_id;
    std::copy(vip->begin(), vip->end(), peer.virtual_ip.bytes.begin());
    peer.node_key = *node_key;
    peer.online = (*online != 0);
    peer.exit_node = (*exit_node != 0);
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

// P2PPing::get_sign_data() - used for signature generation
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

} // namespace edgelink

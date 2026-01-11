#include "common/types.hpp"
#include <charconv>
#include <cstdio>

namespace edgelink {

IPv4Address IPv4Address::from_string(const std::string& str) {
    IPv4Address addr{};
    unsigned int a, b, c, d;
    if (std::sscanf(str.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        addr.bytes[0] = static_cast<uint8_t>(a);
        addr.bytes[1] = static_cast<uint8_t>(b);
        addr.bytes[2] = static_cast<uint8_t>(c);
        addr.bytes[3] = static_cast<uint8_t>(d);
    }
    return addr;
}

std::string IPv4Address::to_string() const {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  bytes[0], bytes[1], bytes[2], bytes[3]);
    return buf;
}

uint32_t IPv4Address::to_u32() const {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
}

IPv4Address IPv4Address::from_u32(uint32_t addr) {
    IPv4Address result{};
    result.bytes[0] = static_cast<uint8_t>((addr >> 24) & 0xFF);
    result.bytes[1] = static_cast<uint8_t>((addr >> 16) & 0xFF);
    result.bytes[2] = static_cast<uint8_t>((addr >> 8) & 0xFF);
    result.bytes[3] = static_cast<uint8_t>(addr & 0xFF);
    return result;
}

const char* frame_type_name(FrameType type) {
    switch (type) {
        case FrameType::AUTH_REQUEST: return "AUTH_REQUEST";
        case FrameType::AUTH_RESPONSE: return "AUTH_RESPONSE";
        case FrameType::AUTH_CHALLENGE: return "AUTH_CHALLENGE";
        case FrameType::AUTH_VERIFY: return "AUTH_VERIFY";
        case FrameType::CONFIG: return "CONFIG";
        case FrameType::CONFIG_UPDATE: return "CONFIG_UPDATE";
        case FrameType::CONFIG_ACK: return "CONFIG_ACK";
        case FrameType::DATA: return "DATA";
        case FrameType::DATA_ACK: return "DATA_ACK";
        case FrameType::PING: return "PING";
        case FrameType::PONG: return "PONG";
        case FrameType::LATENCY_REPORT: return "LATENCY_REPORT";
        case FrameType::P2P_INIT: return "P2P_INIT";
        case FrameType::P2P_ENDPOINT: return "P2P_ENDPOINT";
        case FrameType::P2P_PING: return "P2P_PING";
        case FrameType::P2P_PONG: return "P2P_PONG";
        case FrameType::P2P_KEEPALIVE: return "P2P_KEEPALIVE";
        case FrameType::P2P_STATUS: return "P2P_STATUS";
        case FrameType::ENDPOINT_UPDATE: return "ENDPOINT_UPDATE";
        case FrameType::ENDPOINT_ACK: return "ENDPOINT_ACK";
        case FrameType::SERVER_REGISTER: return "SERVER_REGISTER";
        case FrameType::SERVER_REGISTER_RESP: return "SERVER_REGISTER_RESP";
        case FrameType::SERVER_NODE_LOC: return "SERVER_NODE_LOC";
        case FrameType::SERVER_BLACKLIST: return "SERVER_BLACKLIST";
        case FrameType::SERVER_HEARTBEAT: return "SERVER_HEARTBEAT";
        case FrameType::SERVER_RELAY_LIST: return "SERVER_RELAY_LIST";
        case FrameType::SERVER_LATENCY_REPORT: return "SERVER_LATENCY_REPORT";
        case FrameType::RELAY_AUTH: return "RELAY_AUTH";
        case FrameType::RELAY_AUTH_RESP: return "RELAY_AUTH_RESP";
        case FrameType::MESH_HELLO: return "MESH_HELLO";
        case FrameType::MESH_HELLO_ACK: return "MESH_HELLO_ACK";
        case FrameType::MESH_FORWARD: return "MESH_FORWARD";
        case FrameType::MESH_PING: return "MESH_PING";
        case FrameType::MESH_PONG: return "MESH_PONG";
        case FrameType::ROUTE_ANNOUNCE: return "ROUTE_ANNOUNCE";
        case FrameType::ROUTE_UPDATE: return "ROUTE_UPDATE";
        case FrameType::ROUTE_WITHDRAW: return "ROUTE_WITHDRAW";
        case FrameType::ROUTE_ACK: return "ROUTE_ACK";
        case FrameType::NODE_REVOKE: return "NODE_REVOKE";
        case FrameType::NODE_REVOKE_ACK: return "NODE_REVOKE_ACK";
        case FrameType::NODE_REVOKE_BATCH: return "NODE_REVOKE_BATCH";
        case FrameType::SHUTDOWN_NOTIFY: return "SHUTDOWN_NOTIFY";
        case FrameType::SHUTDOWN_ACK: return "SHUTDOWN_ACK";
        case FrameType::GENERIC_ACK: return "GENERIC_ACK";
        case FrameType::FRAME_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

} // namespace edgelink

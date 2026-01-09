#include "common/frame.hpp"
#include <boost/endian/conversion.hpp>
#include <cstring>
#include <lz4.h>

namespace edgelink::wire {

// ============================================================================
// FrameHeader Implementation
// ============================================================================

void FrameHeader::serialize(std::span<uint8_t, NetworkConstants::HEADER_SIZE> out) const {
    out[0] = version;
    out[1] = static_cast<uint8_t>(type);
    out[2] = flags;
    // Big endian length
    out[3] = static_cast<uint8_t>((length >> 8) & 0xFF);
    out[4] = static_cast<uint8_t>(length & 0xFF);
}

std::expected<FrameHeader, ErrorCode> FrameHeader::deserialize(
    std::span<const uint8_t, NetworkConstants::HEADER_SIZE> in) {
    
    FrameHeader header;
    header.version = in[0];
    header.type = static_cast<MessageType>(in[1]);
    header.flags = in[2];
    header.length = (static_cast<uint16_t>(in[3]) << 8) | static_cast<uint16_t>(in[4]);
    
    if (header.version != PROTOCOL_VERSION) {
        return std::unexpected(ErrorCode::UNSUPPORTED_VERSION);
    }
    
    return header;
}

// ============================================================================
// Frame Implementation
// ============================================================================

Frame Frame::create(MessageType type, std::vector<uint8_t> payload, uint8_t flags) {
    Frame frame;
    frame.header.type = type;
    frame.header.flags = flags;
    frame.header.length = static_cast<uint16_t>(payload.size());
    frame.payload = std::move(payload);
    frame.type = type;
    return frame;
}

Frame Frame::create_compressed(MessageType type, std::vector<uint8_t> payload, uint8_t flags) {
    Frame frame;
    frame.header.type = type;
    frame.type = type;

    // Try to compress if payload is large enough
    if (should_compress(payload)) {
        auto compressed = compress_payload(payload);

        // Only use compression if it actually reduces size
        // (4 bytes header + compressed data must be smaller than original)
        if (!compressed.empty() && compressed.size() < payload.size()) {
            frame.header.flags = flags | FrameFlags::COMPRESSED;
            frame.header.length = static_cast<uint16_t>(compressed.size());
            frame.payload = std::move(compressed);
            return frame;
        }
    }

    // Fall back to uncompressed
    frame.header.flags = flags;
    frame.header.length = static_cast<uint16_t>(payload.size());
    frame.payload = std::move(payload);
    return frame;
}

std::vector<uint8_t> Frame::serialize() const {
    std::vector<uint8_t> data(NetworkConstants::HEADER_SIZE + payload.size());
    
    std::array<uint8_t, NetworkConstants::HEADER_SIZE> header_bytes;
    header.serialize(header_bytes);
    
    std::memcpy(data.data(), header_bytes.data(), NetworkConstants::HEADER_SIZE);
    std::memcpy(data.data() + NetworkConstants::HEADER_SIZE, payload.data(), payload.size());
    
    return data;
}

std::expected<Frame, ErrorCode> Frame::deserialize_raw(std::span<const uint8_t> data) {
    if (data.size() < NetworkConstants::HEADER_SIZE) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    std::array<uint8_t, NetworkConstants::HEADER_SIZE> header_bytes;
    std::memcpy(header_bytes.data(), data.data(), NetworkConstants::HEADER_SIZE);

    auto header_result = FrameHeader::deserialize(header_bytes);
    if (!header_result) {
        return std::unexpected(header_result.error());
    }

    Frame frame;
    frame.header = *header_result;
    frame.type = frame.header.type;

    if (data.size() < NetworkConstants::HEADER_SIZE + frame.header.length) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    frame.payload.resize(frame.header.length);
    std::memcpy(frame.payload.data(),
                data.data() + NetworkConstants::HEADER_SIZE,
                frame.header.length);

    return frame;
}

std::expected<Frame, ErrorCode> Frame::deserialize(std::span<const uint8_t> data) {
    // First, do raw deserialization
    auto result = deserialize_raw(data);
    if (!result) {
        return result;
    }

    Frame& frame = *result;

    // Auto-decompress if COMPRESSED flag is set
    if (frame.header.is_compressed()) {
        auto decompressed = decompress_payload(frame.payload);
        if (!decompressed) {
            return std::unexpected(decompressed.error());
        }

        // Update frame with decompressed payload
        frame.payload = std::move(*decompressed);
        frame.header.length = static_cast<uint16_t>(frame.payload.size());
        frame.header.flags &= ~FrameFlags::COMPRESSED;  // Clear compression flag
    }

    return frame;
}

bool Frame::decompress_if_needed() {
    if (!header.is_compressed()) {
        return true;  // Not compressed, nothing to do
    }

    auto decompressed = decompress_payload(payload);
    if (!decompressed) {
        return false;
    }

    payload = std::move(*decompressed);
    header.length = static_cast<uint16_t>(payload.size());
    header.flags &= ~FrameFlags::COMPRESSED;
    return true;
}

std::optional<size_t> Frame::get_frame_size(std::span<const uint8_t> data) {
    if (data.size() < NetworkConstants::HEADER_SIZE) {
        return std::nullopt;
    }
    
    uint16_t length = (static_cast<uint16_t>(data[3]) << 8) | static_cast<uint16_t>(data[4]);
    return NetworkConstants::HEADER_SIZE + length;
}

// ============================================================================
// DataPayload Implementation
// ============================================================================

std::vector<uint8_t> DataPayload::serialize() const {
    std::vector<uint8_t> data(8 + CryptoConstants::CHACHA20_NONCE_SIZE + encrypted_data.size());
    
    // Src node (big endian)
    data[0] = static_cast<uint8_t>((src_node_id >> 24) & 0xFF);
    data[1] = static_cast<uint8_t>((src_node_id >> 16) & 0xFF);
    data[2] = static_cast<uint8_t>((src_node_id >> 8) & 0xFF);
    data[3] = static_cast<uint8_t>(src_node_id & 0xFF);
    
    // Dst node (big endian)
    data[4] = static_cast<uint8_t>((dst_node_id >> 24) & 0xFF);
    data[5] = static_cast<uint8_t>((dst_node_id >> 16) & 0xFF);
    data[6] = static_cast<uint8_t>((dst_node_id >> 8) & 0xFF);
    data[7] = static_cast<uint8_t>(dst_node_id & 0xFF);
    
    // Nonce
    std::memcpy(data.data() + 8, nonce.data(), nonce.size());
    
    // Encrypted data
    std::memcpy(data.data() + 8 + nonce.size(), encrypted_data.data(), encrypted_data.size());
    
    return data;
}

std::expected<DataPayload, ErrorCode> DataPayload::deserialize(std::span<const uint8_t> data) {
    constexpr size_t min_size = 8 + CryptoConstants::CHACHA20_NONCE_SIZE + CryptoConstants::POLY1305_TAG_SIZE;
    
    if (data.size() < min_size) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    DataPayload payload;
    
    // Src node (big endian)
    payload.src_node_id = (static_cast<uint32_t>(data[0]) << 24) |
                          (static_cast<uint32_t>(data[1]) << 16) |
                          (static_cast<uint32_t>(data[2]) << 8) |
                          static_cast<uint32_t>(data[3]);
    
    // Dst node (big endian)
    payload.dst_node_id = (static_cast<uint32_t>(data[4]) << 24) |
                          (static_cast<uint32_t>(data[5]) << 16) |
                          (static_cast<uint32_t>(data[6]) << 8) |
                          static_cast<uint32_t>(data[7]);
    
    // Nonce
    std::memcpy(payload.nonce.data(), data.data() + 8, payload.nonce.size());
    
    // Encrypted data
    size_t encrypted_size = data.size() - 8 - payload.nonce.size();
    payload.encrypted_data.resize(encrypted_size);
    std::memcpy(payload.encrypted_data.data(), 
                data.data() + 8 + payload.nonce.size(), 
                encrypted_size);
    
    return payload;
}

// ============================================================================
// JSON Payload Implementations
// ============================================================================

boost::json::object AuthRequestPayload::to_json() const {
    return {
        {"machine_key_pub", machine_key_pub},
        {"node_key_pub", node_key_pub},
        {"hostname", hostname},
        {"os", os},
        {"arch", arch},
        {"version", version},
        {"signature", signature_b64},
        {"timestamp", timestamp}
    };
}

std::expected<AuthRequestPayload, ErrorCode> AuthRequestPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        AuthRequestPayload p;
        p.machine_key_pub = obj.at("machine_key_pub").as_string().c_str();
        p.node_key_pub = obj.at("node_key_pub").as_string().c_str();
        p.hostname = obj.at("hostname").as_string().c_str();
        p.os = obj.at("os").as_string().c_str();
        p.arch = obj.at("arch").as_string().c_str();
        p.version = obj.at("version").as_string().c_str();
        p.signature_b64 = obj.at("signature").as_string().c_str();
        p.timestamp = obj.at("timestamp").as_int64();
        return p;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object AuthResponsePayload::to_json() const {
    boost::json::object obj = {
        {"success", success}
    };
    
    if (success) {
        obj["node_id"] = node_id;
        obj["virtual_ip"] = virtual_ip;
        obj["auth_token"] = auth_token;
        obj["relay_token"] = relay_token;
    } else {
        obj["error"] = error_message;
    }
    
    return obj;
}

std::expected<AuthResponsePayload, ErrorCode> AuthResponsePayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        AuthResponsePayload p;
        p.success = obj.at("success").as_bool();
        
        if (p.success) {
            p.node_id = static_cast<uint32_t>(obj.at("node_id").as_int64());
            p.virtual_ip = obj.at("virtual_ip").as_string().c_str();
            p.auth_token = obj.at("auth_token").as_string().c_str();
            p.relay_token = obj.at("relay_token").as_string().c_str();
        } else {
            p.error_message = obj.at("error").as_string().c_str();
        }
        
        return p;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object RelayInfo::to_json() const {
    return {
        {"server_id", server_id},
        {"name", name},
        {"url", url},
        {"region", region}
    };
}

std::expected<RelayInfo, ErrorCode> RelayInfo::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        RelayInfo info;
        info.server_id = static_cast<uint32_t>(obj.at("server_id").as_int64());
        info.name = obj.at("name").as_string().c_str();
        info.url = obj.at("url").as_string().c_str();
        info.region = obj.at("region").as_string().c_str();
        return info;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object STUNInfo::to_json() const {
    return {
        {"server_id", server_id},
        {"name", name},
        {"ip", ip},
        {"port", port},
        {"secondary_ip", secondary_ip}
    };
}

std::expected<STUNInfo, ErrorCode> STUNInfo::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        STUNInfo info;
        info.server_id = static_cast<uint32_t>(obj.at("server_id").as_int64());
        info.name = obj.at("name").as_string().c_str();
        info.ip = obj.at("ip").as_string().c_str();
        info.port = static_cast<uint16_t>(obj.at("port").as_int64());
        if (obj.contains("secondary_ip")) {
            info.secondary_ip = obj.at("secondary_ip").as_string().c_str();
        }
        return info;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object PeerInfo::to_json() const {
    boost::json::array eps;
    for (const auto& ep : endpoints) {
        eps.push_back({
            {"type", static_cast<int>(ep.type)},
            {"ip", ep.ip},
            {"port", ep.port},
            {"priority", ep.priority}
        });
    }
    
    return {
        {"node_id", node_id},
        {"name", name},
        {"virtual_ip", virtual_ip},
        {"node_key_pub", node_key_pub},
        {"online", online},
        {"endpoints", eps}
    };
}

std::expected<PeerInfo, ErrorCode> PeerInfo::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        PeerInfo info;
        info.node_id = static_cast<uint32_t>(obj.at("node_id").as_int64());
        info.name = obj.at("name").as_string().c_str();
        info.virtual_ip = obj.at("virtual_ip").as_string().c_str();
        info.node_key_pub = obj.at("node_key_pub").as_string().c_str();
        info.online = obj.at("online").as_bool();
        
        if (obj.contains("endpoints")) {
            for (const auto& ep_val : obj.at("endpoints").as_array()) {
                const auto& ep_obj = ep_val.as_object();
                Endpoint ep;
                ep.type = static_cast<EndpointType>(ep_obj.at("type").as_int64());
                ep.ip = ep_obj.at("ip").as_string().c_str();
                ep.port = static_cast<uint16_t>(ep_obj.at("port").as_int64());
                ep.priority = static_cast<uint8_t>(ep_obj.at("priority").as_int64());
                info.endpoints.push_back(ep);
            }
        }
        
        return info;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object RouteInfo::to_json() const {
    return {
        {"cidr", cidr},
        {"gateway_node_id", gateway_node_id},
        {"priority", priority},
        {"weight", weight},
        {"enabled", enabled}
    };
}

std::expected<RouteInfo, ErrorCode> RouteInfo::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        RouteInfo info;
        info.cidr = obj.at("cidr").as_string().c_str();
        info.gateway_node_id = static_cast<uint32_t>(obj.at("gateway_node_id").as_int64());
        info.priority = static_cast<uint16_t>(obj.at("priority").as_int64());
        info.weight = static_cast<uint16_t>(obj.at("weight").as_int64());
        info.enabled = obj.at("enabled").as_bool();
        return info;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object ConfigPayload::to_json() const {
    boost::json::array relay_arr, stun_arr, peer_arr, route_arr;
    
    for (const auto& r : relays) relay_arr.push_back(r.to_json());
    for (const auto& s : stun_servers) stun_arr.push_back(s.to_json());
    for (const auto& p : peers) peer_arr.push_back(p.to_json());
    for (const auto& r : routes) route_arr.push_back(r.to_json());
    
    boost::json::object obj = {
        {"version", version},
        {"network_id", network_id},
        {"network_name", network_name},
        {"subnet", subnet},
        {"relays", relay_arr},
        {"stun_servers", stun_arr},
        {"peers", peer_arr},
        {"routes", route_arr}
    };
    
    if (!new_relay_token.empty()) {
        obj["new_relay_token"] = new_relay_token;
        obj["relay_token_expires_at"] = relay_token_expires_at;
    }
    
    return obj;
}

std::expected<ConfigPayload, ErrorCode> ConfigPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        ConfigPayload cfg;
        cfg.version = obj.at("version").as_int64();
        cfg.network_id = static_cast<uint32_t>(obj.at("network_id").as_int64());
        cfg.network_name = obj.at("network_name").as_string().c_str();
        cfg.subnet = obj.at("subnet").as_string().c_str();
        
        for (const auto& r : obj.at("relays").as_array()) {
            auto result = RelayInfo::from_json(r);
            if (!result) return std::unexpected(result.error());
            cfg.relays.push_back(*result);
        }
        
        for (const auto& s : obj.at("stun_servers").as_array()) {
            auto result = STUNInfo::from_json(s);
            if (!result) return std::unexpected(result.error());
            cfg.stun_servers.push_back(*result);
        }
        
        for (const auto& p : obj.at("peers").as_array()) {
            auto result = PeerInfo::from_json(p);
            if (!result) return std::unexpected(result.error());
            cfg.peers.push_back(*result);
        }
        
        for (const auto& r : obj.at("routes").as_array()) {
            auto result = RouteInfo::from_json(r);
            if (!result) return std::unexpected(result.error());
            cfg.routes.push_back(*result);
        }
        
        if (obj.contains("new_relay_token")) {
            cfg.new_relay_token = obj.at("new_relay_token").as_string().c_str();
            cfg.relay_token_expires_at = obj.at("relay_token_expires_at").as_int64();
        }
        
        return cfg;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object LatencyReportPayload::to_json() const {
    boost::json::array entries_arr;
    for (const auto& e : entries) {
        entries_arr.push_back({
            {"dst_type", e.dst_type},
            {"dst_id", e.dst_id},
            {"rtt_ms", e.rtt_ms}
        });
    }
    return {{"entries", entries_arr}};
}

std::expected<LatencyReportPayload, ErrorCode> LatencyReportPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        LatencyReportPayload p;
        for (const auto& e : obj.at("entries").as_array()) {
            const auto& entry = e.as_object();
            p.entries.push_back({
                .dst_type = entry.at("dst_type").as_string().c_str(),
                .dst_id = static_cast<uint32_t>(entry.at("dst_id").as_int64()),
                .rtt_ms = static_cast<uint32_t>(entry.at("rtt_ms").as_int64())
            });
        }
        return p;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

boost::json::object ErrorPayload::to_json() const {
    boost::json::object obj = {
        {"code", code},
        {"message", message}
    };
    if (!details.empty()) {
        obj["details"] = details;
    }
    return obj;
}

bool ErrorPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        code = static_cast<int>(obj.at("code").as_int64());
        message = obj.at("message").as_string().c_str();
        if (obj.contains("details")) {
            details = obj.at("details").as_string().c_str();
        }
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// RelayAuthPayload Implementation
// ============================================================================

boost::json::object RelayAuthPayload::to_json() const {
    return {
        {"relay_token", relay_token}
    };
}

bool RelayAuthPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        relay_token = obj.at("relay_token").as_string().c_str();
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// DataPayload JSON Implementation
// ============================================================================

boost::json::object DataPayload::to_json() const {
    // Base64 encode the binary data for JSON transport
    std::string nonce_b64, data_b64;
    // Simple hex encoding for now (could use base64)
    auto to_hex = [](const uint8_t* data, size_t len) -> std::string {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            result.push_back(hex[data[i] >> 4]);
            result.push_back(hex[data[i] & 0x0F]);
        }
        return result;
    };
    
    return {
        {"src_node_id", src_node_id},
        {"dst_node_id", dst_node_id},
        {"nonce", to_hex(nonce.data(), nonce.size())},
        {"data", to_hex(encrypted_data.data(), encrypted_data.size())}
    };
}

bool DataPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        src_node_id = static_cast<uint32_t>(obj.at("src_node_id").as_int64());
        dst_node_id = static_cast<uint32_t>(obj.at("dst_node_id").as_int64());
        
        // Hex decode
        auto from_hex = [](const std::string& hex) -> std::vector<uint8_t> {
            std::vector<uint8_t> result;
            result.reserve(hex.size() / 2);
            for (size_t i = 0; i < hex.size(); i += 2) {
                uint8_t byte = 0;
                if (hex[i] >= '0' && hex[i] <= '9') byte = (hex[i] - '0') << 4;
                else if (hex[i] >= 'a' && hex[i] <= 'f') byte = (hex[i] - 'a' + 10) << 4;
                else if (hex[i] >= 'A' && hex[i] <= 'F') byte = (hex[i] - 'A' + 10) << 4;
                if (hex[i+1] >= '0' && hex[i+1] <= '9') byte |= hex[i+1] - '0';
                else if (hex[i+1] >= 'a' && hex[i+1] <= 'f') byte |= hex[i+1] - 'a' + 10;
                else if (hex[i+1] >= 'A' && hex[i+1] <= 'F') byte |= hex[i+1] - 'A' + 10;
                result.push_back(byte);
            }
            return result;
        };
        
        std::string nonce_hex = obj.at("nonce").as_string().c_str();
        auto nonce_bytes = from_hex(nonce_hex);
        if (nonce_bytes.size() != nonce.size()) return false;
        std::memcpy(nonce.data(), nonce_bytes.data(), nonce.size());
        
        std::string data_hex = obj.at("data").as_string().c_str();
        encrypted_data = from_hex(data_hex);
        
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// Frame JSON Helper Methods
// ============================================================================

boost::json::value Frame::payload_json() const {
    try {
        std::string json_str(payload.begin(), payload.end());
        return boost::json::parse(json_str);
    } catch (...) {
        return boost::json::value{};
    }
}

void Frame::set_payload_json(const boost::json::value& json) {
    std::string json_str = boost::json::serialize(json);
    payload.assign(json_str.begin(), json_str.end());
    header.length = static_cast<uint16_t>(payload.size());
}

// ============================================================================
// Helper Functions
// ============================================================================

Frame create_json_frame(MessageType type, const boost::json::object& json, uint8_t flags) {
    std::string json_str = boost::json::serialize(json);
    std::vector<uint8_t> payload(json_str.begin(), json_str.end());
    return Frame::create(type, std::move(payload), flags);
}

std::expected<boost::json::value, ErrorCode> parse_json_payload(const Frame& frame) {
    try {
        std::string json_str(frame.payload.begin(), frame.payload.end());
        return boost::json::parse(json_str);
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ============================================================================
// Binary Serialization Implementations
// ============================================================================

// ----------------------------------------------------------------------------
// AuthRequestPayload Binary Serialization
// ----------------------------------------------------------------------------
std::vector<uint8_t> AuthRequestPayload::serialize_binary() const {
    BinaryWriter writer(256);  // Reserve reasonable size

    // auth_type (1 B)
    writer.write_u8(static_cast<uint8_t>(auth_type));

    // machine_key (32 B)
    writer.write_fixed_bytes(machine_key);

    // node_key (32 B)
    writer.write_fixed_bytes(node_key);

    // hostname (len+str)
    writer.write_string(hostname);

    // os (len+str)
    writer.write_string(os);

    // arch (len+str)
    writer.write_string(arch);

    // version (len+str)
    writer.write_string(version);

    // timestamp (8 B)
    writer.write_u64(timestamp);

    // signature (64 B)
    writer.write_fixed_bytes(signature);

    // auth_data (depends on auth_type)
    switch (auth_type) {
        case AuthType::USER:
            writer.write_string(username);
            writer.write_fixed_bytes(password_hash);
            break;
        case AuthType::AUTHKEY:
            writer.write_string(auth_key);
            break;
        case AuthType::MACHINE:
            // No additional data
            break;
    }

    return writer.take();
}

std::expected<AuthRequestPayload, ErrorCode> AuthRequestPayload::deserialize_binary(
    std::span<const uint8_t> data) {

    BinaryReader reader(data);
    AuthRequestPayload payload;

    // auth_type (1 B)
    auto auth_type_result = reader.read_u8();
    if (!auth_type_result) return std::unexpected(auth_type_result.error());
    payload.auth_type = static_cast<AuthType>(*auth_type_result);

    // machine_key (32 B)
    auto machine_key_result = reader.read_fixed_array<32>();
    if (!machine_key_result) return std::unexpected(machine_key_result.error());
    payload.machine_key = *machine_key_result;

    // node_key (32 B)
    auto node_key_result = reader.read_fixed_array<32>();
    if (!node_key_result) return std::unexpected(node_key_result.error());
    payload.node_key = *node_key_result;

    // hostname
    auto hostname_result = reader.read_string();
    if (!hostname_result) return std::unexpected(hostname_result.error());
    payload.hostname = *hostname_result;

    // os
    auto os_result = reader.read_string();
    if (!os_result) return std::unexpected(os_result.error());
    payload.os = *os_result;

    // arch
    auto arch_result = reader.read_string();
    if (!arch_result) return std::unexpected(arch_result.error());
    payload.arch = *arch_result;

    // version
    auto version_result = reader.read_string();
    if (!version_result) return std::unexpected(version_result.error());
    payload.version = *version_result;

    // timestamp (8 B)
    auto timestamp_result = reader.read_u64();
    if (!timestamp_result) return std::unexpected(timestamp_result.error());
    payload.timestamp = *timestamp_result;

    // signature (64 B)
    auto signature_result = reader.read_fixed_array<64>();
    if (!signature_result) return std::unexpected(signature_result.error());
    payload.signature = *signature_result;

    // auth_data (depends on auth_type)
    switch (payload.auth_type) {
        case AuthType::USER: {
            auto username_result = reader.read_string();
            if (!username_result) return std::unexpected(username_result.error());
            payload.username = *username_result;

            auto password_hash_result = reader.read_fixed_array<32>();
            if (!password_hash_result) return std::unexpected(password_hash_result.error());
            payload.password_hash = *password_hash_result;
            break;
        }
        case AuthType::AUTHKEY: {
            auto auth_key_result = reader.read_string();
            if (!auth_key_result) return std::unexpected(auth_key_result.error());
            payload.auth_key = *auth_key_result;
            break;
        }
        case AuthType::MACHINE:
            // No additional data
            break;
    }

    return payload;
}

// ----------------------------------------------------------------------------
// AuthResponsePayload Binary Serialization
// ----------------------------------------------------------------------------
std::vector<uint8_t> AuthResponsePayload::serialize_binary() const {
    BinaryWriter writer(256);

    // success (1 B)
    writer.write_bool(success);

    // node_id (4 B)
    writer.write_u32(node_id);

    // virtual_ip (4 B)
    writer.write_u32(virtual_ip_int);

    // network_id (4 B)
    writer.write_u32(network_id);

    // auth_token (len+bytes)
    writer.write_string(auth_token);

    // relay_token (len+bytes)
    writer.write_string(relay_token);

    // error_code (2 B)
    writer.write_u16(error_code);

    // error_msg (len+str)
    writer.write_string(error_message);

    return writer.take();
}

std::expected<AuthResponsePayload, ErrorCode> AuthResponsePayload::deserialize_binary(
    std::span<const uint8_t> data) {

    BinaryReader reader(data);
    AuthResponsePayload payload;

    // success
    auto success_result = reader.read_bool();
    if (!success_result) return std::unexpected(success_result.error());
    payload.success = *success_result;

    // node_id
    auto node_id_result = reader.read_u32();
    if (!node_id_result) return std::unexpected(node_id_result.error());
    payload.node_id = *node_id_result;

    // virtual_ip
    auto virtual_ip_result = reader.read_u32();
    if (!virtual_ip_result) return std::unexpected(virtual_ip_result.error());
    payload.virtual_ip_int = *virtual_ip_result;
    payload.virtual_ip = format_ipv4(*virtual_ip_result);

    // network_id
    auto network_id_result = reader.read_u32();
    if (!network_id_result) return std::unexpected(network_id_result.error());
    payload.network_id = *network_id_result;

    // auth_token
    auto auth_token_result = reader.read_string();
    if (!auth_token_result) return std::unexpected(auth_token_result.error());
    payload.auth_token = *auth_token_result;

    // relay_token
    auto relay_token_result = reader.read_string();
    if (!relay_token_result) return std::unexpected(relay_token_result.error());
    payload.relay_token = *relay_token_result;

    // error_code
    auto error_code_result = reader.read_u16();
    if (!error_code_result) return std::unexpected(error_code_result.error());
    payload.error_code = *error_code_result;

    // error_message
    auto error_msg_result = reader.read_string();
    if (!error_msg_result) return std::unexpected(error_msg_result.error());
    payload.error_message = *error_msg_result;

    return payload;
}

// ----------------------------------------------------------------------------
// RouteInfo Binary Serialization
// ----------------------------------------------------------------------------
std::vector<uint8_t> RouteInfo::serialize_binary() const {
    BinaryWriter writer(32);

    // ip_type (1 B)
    writer.write_u8(ip_type);

    // prefix (4 B for IPv4)
    writer.write_u32(prefix);

    // prefix_len (1 B)
    writer.write_u8(prefix_len);

    // gateway_node_id (4 B)
    writer.write_u32(gateway_node_id);

    // priority (2 B)
    writer.write_u16(priority);

    // weight (2 B)
    writer.write_u16(weight);

    // metric (4 B)
    writer.write_u32(metric);

    // flags (1 B)
    writer.write_u8(flags);

    return writer.take();
}

std::expected<RouteInfo, ErrorCode> RouteInfo::deserialize_binary(BinaryReader& reader) {
    RouteInfo info;

    // ip_type
    auto ip_type_result = reader.read_u8();
    if (!ip_type_result) return std::unexpected(ip_type_result.error());
    info.ip_type = *ip_type_result;

    // prefix (4 B for IPv4, 16 B for IPv6)
    if (info.ip_type == 4) {
        auto prefix_result = reader.read_u32();
        if (!prefix_result) return std::unexpected(prefix_result.error());
        info.prefix = *prefix_result;
    } else {
        // IPv6 support would go here
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    // prefix_len
    auto prefix_len_result = reader.read_u8();
    if (!prefix_len_result) return std::unexpected(prefix_len_result.error());
    info.prefix_len = *prefix_len_result;

    // gateway_node_id
    auto gateway_result = reader.read_u32();
    if (!gateway_result) return std::unexpected(gateway_result.error());
    info.gateway_node_id = *gateway_result;

    // priority
    auto priority_result = reader.read_u16();
    if (!priority_result) return std::unexpected(priority_result.error());
    info.priority = *priority_result;

    // weight
    auto weight_result = reader.read_u16();
    if (!weight_result) return std::unexpected(weight_result.error());
    info.weight = *weight_result;

    // metric
    auto metric_result = reader.read_u32();
    if (!metric_result) return std::unexpected(metric_result.error());
    info.metric = *metric_result;

    // flags
    auto flags_result = reader.read_u8();
    if (!flags_result) return std::unexpected(flags_result.error());
    info.flags = *flags_result;
    info.enabled = (info.flags & RouteFlags::ENABLED) != 0;

    // Generate CIDR string for compatibility
    info.cidr = info.to_cidr();

    return info;
}

void RouteInfo::from_cidr(std::string_view cidr_str) {
    auto result = parse_cidr_v4(cidr_str);
    if (result) {
        ip_type = 4;
        prefix = result->prefix;
        prefix_len = result->prefix_len;
        cidr = std::string(cidr_str);
    }
}

std::string RouteInfo::to_cidr() const {
    if (ip_type == 4) {
        return format_cidr_v4(prefix, prefix_len);
    }
    return cidr;
}

// ----------------------------------------------------------------------------
// ConfigPayload Binary Serialization
// ----------------------------------------------------------------------------
std::vector<uint8_t> ConfigPayload::serialize_binary() const {
    BinaryWriter writer(1024);

    // version (8 B)
    writer.write_u64(version);

    // network_id (4 B)
    writer.write_u32(network_id);

    // subnet (4 B)
    writer.write_u32(subnet_ip);

    // subnet_mask (1 B)
    writer.write_u8(subnet_mask);

    // network_name (len+str)
    writer.write_string(network_name);

    // relays array
    writer.write_array_header(static_cast<uint16_t>(relays.size()));
    for (const auto& relay : relays) {
        writer.write_u32(relay.server_id);
        writer.write_string(relay.name);
        writer.write_string(relay.url);
        writer.write_string(relay.region);
    }

    // stun_servers array
    writer.write_array_header(static_cast<uint16_t>(stun_servers.size()));
    for (const auto& stun : stun_servers) {
        writer.write_u32(stun.server_id);
        writer.write_string(stun.name);
        writer.write_string(stun.ip);
        writer.write_u16(stun.port);
        writer.write_string(stun.secondary_ip);
    }

    // peers array
    writer.write_array_header(static_cast<uint16_t>(peers.size()));
    for (const auto& peer : peers) {
        writer.write_u32(peer.node_id);
        writer.write_string(peer.name);
        writer.write_string(peer.virtual_ip);
        writer.write_string(peer.node_key_pub);
        writer.write_bool(peer.online);

        // endpoints
        writer.write_array_header(static_cast<uint16_t>(peer.endpoints.size()));
        for (const auto& ep : peer.endpoints) {
            writer.write_u8(static_cast<uint8_t>(ep.type));
            writer.write_string(ep.ip);
            writer.write_u16(ep.port);
            writer.write_u8(ep.priority);
        }
    }

    // routes array
    writer.write_array_header(static_cast<uint16_t>(routes.size()));
    for (const auto& route : routes) {
        auto route_bytes = route.serialize_binary();
        writer.write_fixed_bytes(route_bytes);
    }

    // relay_token (len+str)
    writer.write_string(new_relay_token);

    // relay_token_expires_at (8 B)
    writer.write_i64(relay_token_expires_at);

    return writer.take();
}

std::expected<ConfigPayload, ErrorCode> ConfigPayload::deserialize_binary(
    std::span<const uint8_t> data) {

    BinaryReader reader(data);
    ConfigPayload cfg;

    // version
    auto version_result = reader.read_u64();
    if (!version_result) return std::unexpected(version_result.error());
    cfg.version = *version_result;

    // network_id
    auto network_id_result = reader.read_u32();
    if (!network_id_result) return std::unexpected(network_id_result.error());
    cfg.network_id = *network_id_result;

    // subnet
    auto subnet_result = reader.read_u32();
    if (!subnet_result) return std::unexpected(subnet_result.error());
    cfg.subnet_ip = *subnet_result;

    // subnet_mask
    auto mask_result = reader.read_u8();
    if (!mask_result) return std::unexpected(mask_result.error());
    cfg.subnet_mask = *mask_result;
    cfg.subnet = format_cidr_v4(cfg.subnet_ip, cfg.subnet_mask);

    // network_name
    auto name_result = reader.read_string();
    if (!name_result) return std::unexpected(name_result.error());
    cfg.network_name = *name_result;

    // relays
    auto relay_count_result = reader.read_array_header();
    if (!relay_count_result) return std::unexpected(relay_count_result.error());
    for (uint16_t i = 0; i < *relay_count_result; ++i) {
        RelayInfo relay;
        auto id_r = reader.read_u32();
        if (!id_r) return std::unexpected(id_r.error());
        relay.server_id = *id_r;

        auto name_r = reader.read_string();
        if (!name_r) return std::unexpected(name_r.error());
        relay.name = *name_r;

        auto url_r = reader.read_string();
        if (!url_r) return std::unexpected(url_r.error());
        relay.url = *url_r;

        auto region_r = reader.read_string();
        if (!region_r) return std::unexpected(region_r.error());
        relay.region = *region_r;

        cfg.relays.push_back(relay);
    }

    // stun_servers
    auto stun_count_result = reader.read_array_header();
    if (!stun_count_result) return std::unexpected(stun_count_result.error());
    for (uint16_t i = 0; i < *stun_count_result; ++i) {
        STUNInfo stun;
        auto id_r = reader.read_u32();
        if (!id_r) return std::unexpected(id_r.error());
        stun.server_id = *id_r;

        auto name_r = reader.read_string();
        if (!name_r) return std::unexpected(name_r.error());
        stun.name = *name_r;

        auto ip_r = reader.read_string();
        if (!ip_r) return std::unexpected(ip_r.error());
        stun.ip = *ip_r;

        auto port_r = reader.read_u16();
        if (!port_r) return std::unexpected(port_r.error());
        stun.port = *port_r;

        auto sec_ip_r = reader.read_string();
        if (!sec_ip_r) return std::unexpected(sec_ip_r.error());
        stun.secondary_ip = *sec_ip_r;

        cfg.stun_servers.push_back(stun);
    }

    // peers
    auto peer_count_result = reader.read_array_header();
    if (!peer_count_result) return std::unexpected(peer_count_result.error());
    for (uint16_t i = 0; i < *peer_count_result; ++i) {
        PeerInfo peer;
        auto id_r = reader.read_u32();
        if (!id_r) return std::unexpected(id_r.error());
        peer.node_id = *id_r;

        auto name_r = reader.read_string();
        if (!name_r) return std::unexpected(name_r.error());
        peer.name = *name_r;

        auto vip_r = reader.read_string();
        if (!vip_r) return std::unexpected(vip_r.error());
        peer.virtual_ip = *vip_r;

        auto key_r = reader.read_string();
        if (!key_r) return std::unexpected(key_r.error());
        peer.node_key_pub = *key_r;

        auto online_r = reader.read_bool();
        if (!online_r) return std::unexpected(online_r.error());
        peer.online = *online_r;

        // endpoints
        auto ep_count_r = reader.read_array_header();
        if (!ep_count_r) return std::unexpected(ep_count_r.error());
        for (uint16_t j = 0; j < *ep_count_r; ++j) {
            Endpoint ep;
            auto type_r = reader.read_u8();
            if (!type_r) return std::unexpected(type_r.error());
            ep.type = static_cast<EndpointType>(*type_r);

            auto ip_r = reader.read_string();
            if (!ip_r) return std::unexpected(ip_r.error());
            ep.ip = *ip_r;

            auto port_r = reader.read_u16();
            if (!port_r) return std::unexpected(port_r.error());
            ep.port = *port_r;

            auto prio_r = reader.read_u8();
            if (!prio_r) return std::unexpected(prio_r.error());
            ep.priority = *prio_r;

            peer.endpoints.push_back(ep);
        }

        cfg.peers.push_back(peer);
    }

    // routes
    auto route_count_result = reader.read_array_header();
    if (!route_count_result) return std::unexpected(route_count_result.error());
    for (uint16_t i = 0; i < *route_count_result; ++i) {
        auto route_result = RouteInfo::deserialize_binary(reader);
        if (!route_result) return std::unexpected(route_result.error());
        cfg.routes.push_back(*route_result);
    }

    // relay_token
    auto token_result = reader.read_string();
    if (!token_result) return std::unexpected(token_result.error());
    cfg.new_relay_token = *token_result;

    // relay_token_expires_at
    auto expires_result = reader.read_i64();
    if (!expires_result) return std::unexpected(expires_result.error());
    cfg.relay_token_expires_at = *expires_result;

    return cfg;
}

// ----------------------------------------------------------------------------
// RouteAnnouncePayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> RouteAnnouncePayload::serialize_binary() const {
    BinaryWriter writer(128);
    writer.write_u32(gateway_node_id);
    writer.write_array_header(static_cast<uint16_t>(routes.size()));
    for (const auto& route : routes) {
        auto route_bytes = route.serialize_binary();
        writer.write_fixed_bytes(route_bytes);
    }
    return writer.take();
}

std::expected<RouteAnnouncePayload, ErrorCode> RouteAnnouncePayload::deserialize_binary(
    std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RouteAnnouncePayload payload;

    auto gw_r = reader.read_u32();
    if (!gw_r) return std::unexpected(gw_r.error());
    payload.gateway_node_id = *gw_r;

    auto count_r = reader.read_array_header();
    if (!count_r) return std::unexpected(count_r.error());

    for (uint16_t i = 0; i < *count_r; ++i) {
        auto route_r = RouteInfo::deserialize_binary(reader);
        if (!route_r) return std::unexpected(route_r.error());
        payload.routes.push_back(*route_r);
    }

    return payload;
}

boost::json::object RouteAnnouncePayload::to_json() const {
    boost::json::array routes_arr;
    for (const auto& r : routes) {
        routes_arr.push_back(r.to_json());
    }
    return {
        {"gateway_node_id", gateway_node_id},
        {"routes", routes_arr}
    };
}

std::expected<RouteAnnouncePayload, ErrorCode> RouteAnnouncePayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        RouteAnnouncePayload payload;
        payload.gateway_node_id = static_cast<uint32_t>(obj.at("gateway_node_id").as_int64());

        if (obj.contains("routes") && obj.at("routes").is_array()) {
            for (const auto& r : obj.at("routes").as_array()) {
                auto route_r = RouteInfo::from_json(r);
                if (route_r) {
                    payload.routes.push_back(*route_r);
                }
            }
        }
        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ----------------------------------------------------------------------------
// RouteUpdatePayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> RouteUpdatePayload::serialize_binary() const {
    BinaryWriter writer(256);
    writer.write_u64(version);
    writer.write_array_header(static_cast<uint16_t>(changes.size()));
    for (const auto& change : changes) {
        writer.write_u8(static_cast<uint8_t>(change.action));
        auto route_bytes = change.route.serialize_binary();
        writer.write_fixed_bytes(route_bytes);
    }
    return writer.take();
}

std::expected<RouteUpdatePayload, ErrorCode> RouteUpdatePayload::deserialize_binary(
    std::span<const uint8_t> data) {
    BinaryReader reader(data);
    RouteUpdatePayload payload;

    auto ver_r = reader.read_u64();
    if (!ver_r) return std::unexpected(ver_r.error());
    payload.version = *ver_r;

    auto count_r = reader.read_array_header();
    if (!count_r) return std::unexpected(count_r.error());

    for (uint16_t i = 0; i < *count_r; ++i) {
        RouteChange change;
        auto action_r = reader.read_u8();
        if (!action_r) return std::unexpected(action_r.error());
        change.action = static_cast<Action>(*action_r);

        auto route_r = RouteInfo::deserialize_binary(reader);
        if (!route_r) return std::unexpected(route_r.error());
        change.route = *route_r;

        payload.changes.push_back(change);
    }

    return payload;
}

boost::json::object RouteUpdatePayload::to_json() const {
    boost::json::array changes_arr;
    for (const auto& c : changes) {
        boost::json::object change_obj = {
            {"action", static_cast<int>(c.action)},
            {"route", c.route.to_json()}
        };
        changes_arr.push_back(change_obj);
    }
    return {
        {"version", static_cast<int64_t>(version)},
        {"changes", changes_arr}
    };
}

std::expected<RouteUpdatePayload, ErrorCode> RouteUpdatePayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        RouteUpdatePayload payload;
        payload.version = static_cast<uint64_t>(obj.at("version").as_int64());

        if (obj.contains("changes") && obj.at("changes").is_array()) {
            for (const auto& c : obj.at("changes").as_array()) {
                const auto& change_obj = c.as_object();
                RouteChange change;
                change.action = static_cast<Action>(change_obj.at("action").as_int64());

                auto route_r = RouteInfo::from_json(change_obj.at("route"));
                if (route_r) {
                    change.route = *route_r;
                    payload.changes.push_back(change);
                }
            }
        }
        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ----------------------------------------------------------------------------
// MeshHelloPayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> MeshHelloPayload::serialize_binary() const {
    BinaryWriter writer(128);
    writer.write_u32(server_id);
    writer.write_string(server_token);
    writer.write_string(region);
    writer.write_u8(capabilities);
    return writer.take();
}

std::expected<MeshHelloPayload, ErrorCode> MeshHelloPayload::deserialize_binary(
    std::span<const uint8_t> data) {
    BinaryReader reader(data);
    MeshHelloPayload payload;

    auto id_r = reader.read_u32();
    if (!id_r) return std::unexpected(id_r.error());
    payload.server_id = *id_r;

    auto token_r = reader.read_string();
    if (!token_r) return std::unexpected(token_r.error());
    payload.server_token = *token_r;

    auto region_r = reader.read_string();
    if (!region_r) return std::unexpected(region_r.error());
    payload.region = *region_r;

    auto cap_r = reader.read_u8();
    if (!cap_r) return std::unexpected(cap_r.error());
    payload.capabilities = *cap_r;

    return payload;
}

boost::json::object MeshHelloPayload::to_json() const {
    return {
        {"server_id", server_id},
        {"server_token", server_token},
        {"region", region},
        {"capabilities", capabilities}
    };
}

std::expected<MeshHelloPayload, ErrorCode> MeshHelloPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        MeshHelloPayload payload;
        payload.server_id = static_cast<uint32_t>(obj.at("server_id").as_int64());
        payload.server_token = obj.at("server_token").as_string().c_str();
        payload.region = obj.at("region").as_string().c_str();
        payload.capabilities = static_cast<uint8_t>(obj.at("capabilities").as_int64());
        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ----------------------------------------------------------------------------
// MeshHelloAckPayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> MeshHelloAckPayload::serialize_binary() const {
    BinaryWriter writer(64);
    writer.write_bool(success);
    writer.write_u32(server_id);
    writer.write_string(region);
    writer.write_u8(capabilities);
    writer.write_string(error_message);
    return writer.take();
}

std::expected<MeshHelloAckPayload, ErrorCode> MeshHelloAckPayload::deserialize_binary(
    std::span<const uint8_t> data) {
    BinaryReader reader(data);
    MeshHelloAckPayload payload;

    auto success_r = reader.read_bool();
    if (!success_r) return std::unexpected(success_r.error());
    payload.success = *success_r;

    auto id_r = reader.read_u32();
    if (!id_r) return std::unexpected(id_r.error());
    payload.server_id = *id_r;

    auto region_r = reader.read_string();
    if (!region_r) return std::unexpected(region_r.error());
    payload.region = *region_r;

    auto cap_r = reader.read_u8();
    if (!cap_r) return std::unexpected(cap_r.error());
    payload.capabilities = *cap_r;

    auto err_r = reader.read_string();
    if (!err_r) return std::unexpected(err_r.error());
    payload.error_message = *err_r;

    return payload;
}

boost::json::object MeshHelloAckPayload::to_json() const {
    boost::json::object obj = {
        {"success", success},
        {"server_id", server_id},
        {"region", region},
        {"capabilities", capabilities}
    };
    if (!success && !error_message.empty()) {
        obj["error_message"] = error_message;
    }
    return obj;
}

std::expected<MeshHelloAckPayload, ErrorCode> MeshHelloAckPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        MeshHelloAckPayload payload;
        payload.success = obj.at("success").as_bool();
        payload.server_id = static_cast<uint32_t>(obj.at("server_id").as_int64());
        payload.region = obj.at("region").as_string().c_str();
        payload.capabilities = static_cast<uint8_t>(obj.at("capabilities").as_int64());
        if (obj.contains("error_message")) {
            payload.error_message = obj.at("error_message").as_string().c_str();
        }
        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ----------------------------------------------------------------------------
// MeshForwardPayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> MeshForwardPayload::serialize_binary() const {
    BinaryWriter writer(data.size() + 16);
    writer.write_u32(src_relay_id);
    writer.write_u32(dst_node_id);
    writer.write_u8(ttl);
    writer.write_bytes(data);
    return writer.take();
}

std::expected<MeshForwardPayload, ErrorCode> MeshForwardPayload::deserialize_binary(
    std::span<const uint8_t> input_data) {
    BinaryReader reader(input_data);
    MeshForwardPayload payload;

    auto src_r = reader.read_u32();
    if (!src_r) return std::unexpected(src_r.error());
    payload.src_relay_id = *src_r;

    auto dst_r = reader.read_u32();
    if (!dst_r) return std::unexpected(dst_r.error());
    payload.dst_node_id = *dst_r;

    auto ttl_r = reader.read_u8();
    if (!ttl_r) return std::unexpected(ttl_r.error());
    payload.ttl = *ttl_r;

    auto data_r = reader.read_bytes();
    if (!data_r) return std::unexpected(data_r.error());
    payload.data = std::move(*data_r);

    return payload;
}

boost::json::object MeshForwardPayload::to_json() const {
    // Use hex encoding for data in JSON
    auto to_hex = [](const std::vector<uint8_t>& bytes) -> std::string {
        static const char hex[] = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            result.push_back(hex[b >> 4]);
            result.push_back(hex[b & 0x0F]);
        }
        return result;
    };

    return {
        {"src_relay_id", src_relay_id},
        {"dst_node_id", dst_node_id},
        {"ttl", ttl},
        {"data", to_hex(data)}
    };
}

std::expected<MeshForwardPayload, ErrorCode> MeshForwardPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        MeshForwardPayload payload;
        payload.src_relay_id = static_cast<uint32_t>(obj.at("src_relay_id").as_int64());
        payload.dst_node_id = static_cast<uint32_t>(obj.at("dst_node_id").as_int64());
        payload.ttl = static_cast<uint8_t>(obj.at("ttl").as_int64());

        // Hex decode data
        std::string hex = obj.at("data").as_string().c_str();
        payload.data.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            uint8_t byte = 0;
            if (hex[i] >= '0' && hex[i] <= '9') byte = (hex[i] - '0') << 4;
            else if (hex[i] >= 'a' && hex[i] <= 'f') byte = (hex[i] - 'a' + 10) << 4;
            else if (hex[i] >= 'A' && hex[i] <= 'F') byte = (hex[i] - 'A' + 10) << 4;
            if (hex[i+1] >= '0' && hex[i+1] <= '9') byte |= hex[i+1] - '0';
            else if (hex[i+1] >= 'a' && hex[i+1] <= 'f') byte |= hex[i+1] - 'a' + 10;
            else if (hex[i+1] >= 'A' && hex[i+1] <= 'F') byte |= hex[i+1] - 'A' + 10;
            payload.data.push_back(byte);
        }

        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ----------------------------------------------------------------------------
// MeshPingPayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> MeshPingPayload::serialize_binary() const {
    BinaryWriter writer(16);
    writer.write_u64(timestamp);
    writer.write_u32(sequence);
    return writer.take();
}

std::expected<MeshPingPayload, ErrorCode> MeshPingPayload::deserialize_binary(
    std::span<const uint8_t> data) {
    BinaryReader reader(data);
    MeshPingPayload payload;

    auto ts_r = reader.read_u64();
    if (!ts_r) return std::unexpected(ts_r.error());
    payload.timestamp = *ts_r;

    auto seq_r = reader.read_u32();
    if (!seq_r) return std::unexpected(seq_r.error());
    payload.sequence = *seq_r;

    return payload;
}

boost::json::object MeshPingPayload::to_json() const {
    return {
        {"timestamp", static_cast<int64_t>(timestamp)},
        {"sequence", sequence}
    };
}

std::expected<MeshPingPayload, ErrorCode> MeshPingPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        MeshPingPayload payload;
        payload.timestamp = static_cast<uint64_t>(obj.at("timestamp").as_int64());
        payload.sequence = static_cast<uint32_t>(obj.at("sequence").as_int64());
        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ----------------------------------------------------------------------------
// ServerBlacklistPayload Implementation
// ----------------------------------------------------------------------------
std::vector<uint8_t> ServerBlacklistPayload::serialize_binary() const {
    BinaryWriter writer(128);
    writer.write_bool(full_sync);
    writer.write_array_header(static_cast<uint16_t>(entries.size()));
    for (const auto& entry : entries) {
        writer.write_string(entry.jti);
        writer.write_i64(entry.expires_at);
    }
    return writer.take();
}

std::expected<ServerBlacklistPayload, ErrorCode> ServerBlacklistPayload::deserialize_binary(
    std::span<const uint8_t> data) {
    BinaryReader reader(data);
    ServerBlacklistPayload payload;

    auto full_sync_r = reader.read_bool();
    if (!full_sync_r) return std::unexpected(full_sync_r.error());
    payload.full_sync = *full_sync_r;

    auto count_r = reader.read_array_header();
    if (!count_r) return std::unexpected(count_r.error());

    for (uint16_t i = 0; i < *count_r; ++i) {
        BlacklistEntry entry;
        auto jti_r = reader.read_string();
        if (!jti_r) return std::unexpected(jti_r.error());
        entry.jti = *jti_r;

        auto expires_r = reader.read_i64();
        if (!expires_r) return std::unexpected(expires_r.error());
        entry.expires_at = *expires_r;

        payload.entries.push_back(entry);
    }

    return payload;
}

boost::json::object ServerBlacklistPayload::to_json() const {
    boost::json::array entries_arr;
    for (const auto& e : entries) {
        entries_arr.push_back({
            {"jti", e.jti},
            {"expires_at", e.expires_at}
        });
    }
    return {
        {"full_sync", full_sync},
        {"entries", entries_arr}
    };
}

std::expected<ServerBlacklistPayload, ErrorCode> ServerBlacklistPayload::from_json(const boost::json::value& v) {
    try {
        const auto& obj = v.as_object();
        ServerBlacklistPayload payload;
        payload.full_sync = obj.contains("full_sync") && obj.at("full_sync").as_bool();

        if (obj.contains("entries") && obj.at("entries").is_array()) {
            for (const auto& e : obj.at("entries").as_array()) {
                const auto& entry_obj = e.as_object();
                BlacklistEntry entry;
                entry.jti = entry_obj.at("jti").as_string().c_str();
                entry.expires_at = entry_obj.at("expires_at").as_int64();
                payload.entries.push_back(entry);
            }
        }
        return payload;
    } catch (...) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
}

// ============================================================================
// Compression Implementation
// ============================================================================

std::vector<uint8_t> compress_payload(std::span<const uint8_t> data) {
    if (data.empty()) {
        return {};
    }

    // Calculate max compressed size
    const int src_size = static_cast<int>(data.size());
    const int max_compressed = LZ4_compressBound(src_size);
    if (max_compressed <= 0) {
        return {};
    }

    // Allocate output buffer: 4 bytes for original size + compressed data
    std::vector<uint8_t> compressed(4 + static_cast<size_t>(max_compressed));

    // Store original size (big-endian) at the beginning
    compressed[0] = static_cast<uint8_t>((data.size() >> 24) & 0xFF);
    compressed[1] = static_cast<uint8_t>((data.size() >> 16) & 0xFF);
    compressed[2] = static_cast<uint8_t>((data.size() >> 8) & 0xFF);
    compressed[3] = static_cast<uint8_t>(data.size() & 0xFF);

    // Compress data
    const int compressed_size = LZ4_compress_default(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(compressed.data() + 4),
        src_size,
        max_compressed
    );

    if (compressed_size <= 0) {
        return {};
    }

    // Resize to actual size
    compressed.resize(4 + static_cast<size_t>(compressed_size));
    return compressed;
}

std::expected<std::vector<uint8_t>, ErrorCode> decompress_payload(
    std::span<const uint8_t> compressed_data, size_t original_size_hint) {

    if (compressed_data.size() < 4) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    // Read original size from header (big-endian)
    const size_t original_size =
        (static_cast<size_t>(compressed_data[0]) << 24) |
        (static_cast<size_t>(compressed_data[1]) << 16) |
        (static_cast<size_t>(compressed_data[2]) << 8) |
        static_cast<size_t>(compressed_data[3]);

    // Sanity check: don't allow decompression to arbitrarily large sizes
    constexpr size_t MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024;  // 10 MB
    if (original_size > MAX_DECOMPRESSED_SIZE) {
        return std::unexpected(ErrorCode::MESSAGE_TOO_LARGE);
    }

    // Use hint if provided and original_size is 0 (shouldn't happen normally)
    const size_t output_size = (original_size > 0) ? original_size : original_size_hint;
    if (output_size == 0) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    // Allocate output buffer
    std::vector<uint8_t> decompressed(output_size);

    // Decompress
    const int result = LZ4_decompress_safe(
        reinterpret_cast<const char*>(compressed_data.data() + 4),
        reinterpret_cast<char*>(decompressed.data()),
        static_cast<int>(compressed_data.size() - 4),
        static_cast<int>(output_size)
    );

    if (result < 0) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    // Verify decompressed size matches expected
    if (static_cast<size_t>(result) != original_size) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }

    return decompressed;
}

bool should_compress(std::span<const uint8_t> data) {
    // Don't compress small payloads
    if (data.size() < CompressionConstants::MIN_COMPRESS_SIZE) {
        return false;
    }

    // For larger payloads, always try compression
    // LZ4 is fast enough that the overhead is minimal even if incompressible
    return true;
}

} // namespace edgelink::wire

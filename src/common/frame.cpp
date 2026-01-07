#include "common/frame.hpp"
#include <boost/endian/conversion.hpp>
#include <cstring>

namespace edgelink {

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

std::expected<Frame, ErrorCode> Frame::deserialize(std::span<const uint8_t> data) {
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
    
    if (data.size() < NetworkConstants::HEADER_SIZE + frame.header.length) {
        return std::unexpected(ErrorCode::INVALID_MESSAGE);
    }
    
    frame.payload.resize(frame.header.length);
    std::memcpy(frame.payload.data(), 
                data.data() + NetworkConstants::HEADER_SIZE, 
                frame.header.length);
    
    return frame;
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
        {"signature", signature},
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
        p.signature = obj.at("signature").as_string().c_str();
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

} // namespace edgelink

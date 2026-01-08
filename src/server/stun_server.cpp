#include "stun_server.hpp"
#include "common/log.hpp"

#include <cstring>
#include <random>

namespace edgelink {

// ============================================================================
// STUNServer Implementation
// ============================================================================

STUNServer::STUNServer(asio::io_context& ioc, const ServerConfig& config)
    : ioc_(ioc)
    , config_(config)
    , socket_(ioc)
    , external_ip_(config.stun.external_ip)
    , external_ip2_(config.stun.external_ip2)
    , port_(config.stun.listen_port)
{
    LOG_INFO("STUNServer initializing on {}:{}", config_.stun.listen_address, port_);
}

STUNServer::~STUNServer() {
    stop();
}

void STUNServer::start() {
    if (running_) {
        LOG_WARN("STUNServer already running");
        return;
    }
    
    if (!config_.stun.enabled) {
        LOG_INFO("STUN server disabled in configuration");
        return;
    }
    
    // external_ip is required for STUN to work correctly
    if (external_ip_.empty()) {
        LOG_ERROR("STUNServer: external_ip is required but not configured");
        LOG_ERROR("STUNServer: Please set stun.external_ip to your server's public IP");
        return;
    }
    
    running_ = true;
    
    try {
        // Setup primary socket
        auto address = asio::ip::make_address(config_.stun.listen_address);
        udp::endpoint endpoint(address, port_);
        
        socket_.open(endpoint.protocol());
        socket_.set_option(asio::socket_base::reuse_address(true));
        socket_.bind(endpoint);
        
        LOG_INFO("STUNServer listening on {}:{} (external: {})", 
                 config_.stun.listen_address, port_, external_ip_);
        
        // Setup secondary socket if alternate IP is configured (for full NAT detection)
        if (!external_ip2_.empty()) {
            socket2_ = std::make_unique<udp::socket>(ioc_);
            // Note: In real deployment, this would bind to the alternate IP
            // For now, just using same socket with different response address
            LOG_INFO("STUN alternate address configured: {}", external_ip2_);
        }
        
        // Start receiving
        do_receive();
        
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to start STUNServer: {}", e.what());
        running_ = false;
        throw;
    }
}

void STUNServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    boost::system::error_code ec;
    socket_.close(ec);
    
    if (socket2_) {
        socket2_->close(ec);
        socket2_.reset();
    }
    
    LOG_INFO("STUNServer stopped");
}

void STUNServer::do_receive() {
    if (!running_) {
        return;
    }
    
    socket_.async_receive_from(
        asio::buffer(recv_buffer_),
        remote_endpoint_,
        [this](boost::system::error_code ec, std::size_t bytes_received) {
            on_receive(ec, bytes_received);
        });
}

void STUNServer::on_receive(boost::system::error_code ec, std::size_t bytes_received) {
    if (ec) {
        if (ec != asio::error::operation_aborted) {
            LOG_ERROR("STUN receive error: {}", ec.message());
            stats_.errors++;
        }
        
        if (running_) {
            do_receive();
        }
        return;
    }
    
    stats_.requests_received++;
    
    // Process the request
    process_request(remote_endpoint_, recv_buffer_, bytes_received);
    
    // Continue receiving
    do_receive();
}

void STUNServer::process_request(const udp::endpoint& remote, 
                                  const std::array<uint8_t, stun::MAX_MESSAGE_SIZE>& data,
                                  std::size_t size) {
    // Parse STUN header
    stun::Header header;
    if (!parse_header(data.data(), size, header)) {
        LOG_DEBUG("Invalid STUN header from {}:{}", 
                  remote.address().to_string(), remote.port());
        stats_.errors++;
        return;
    }
    
    // Verify magic cookie
    if (header.magic_cookie != stun::MAGIC_COOKIE) {
        LOG_DEBUG("Invalid magic cookie from {}:{}", 
                  remote.address().to_string(), remote.port());
        stats_.errors++;
        return;
    }
    
    // Handle message type
    switch (header.type) {
        case stun::BINDING_REQUEST: {
            LOG_DEBUG("STUN binding request from {}:{}", 
                      remote.address().to_string(), remote.port());
            
            // Check for CHANGE-REQUEST attribute
            bool change_ip = false, change_port = false;
            has_change_request(data.data(), size, change_ip, change_port);
            
            // Build and send response
            bool include_other_address = !external_ip2_.empty();
            auto response = build_binding_response(header, remote, include_other_address);
            send_response(remote, std::move(response));
            
            break;
        }
        
        default:
            LOG_DEBUG("Unknown STUN message type 0x{:04X} from {}:{}", 
                      header.type, remote.address().to_string(), remote.port());
            
            // Send error response
            auto response = build_error_response(header, 400, "Unknown message type");
            send_response(remote, std::move(response));
            stats_.errors++;
            break;
    }
}

bool STUNServer::parse_header(const uint8_t* data, std::size_t size, stun::Header& header) {
    if (size < stun::HEADER_SIZE) {
        return false;
    }
    
    // Message type (2 bytes, big endian)
    header.type = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    
    // Message length (2 bytes, big endian)
    header.length = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    
    // Magic cookie (4 bytes, big endian)
    header.magic_cookie = (static_cast<uint32_t>(data[4]) << 24) |
                          (static_cast<uint32_t>(data[5]) << 16) |
                          (static_cast<uint32_t>(data[6]) << 8) |
                          data[7];
    
    // Transaction ID (12 bytes)
    std::memcpy(header.transaction_id.data(), data + 8, stun::TRANSACTION_ID_SIZE);
    
    // Verify length makes sense
    if (stun::HEADER_SIZE + header.length > size) {
        return false;
    }
    
    return true;
}

bool STUNServer::has_change_request(const uint8_t* data, std::size_t size, 
                                     bool& change_ip, bool& change_port) {
    change_ip = false;
    change_port = false;
    
    // Skip header
    size_t offset = stun::HEADER_SIZE;
    
    while (offset + 4 <= size) {
        uint16_t attr_type = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        uint16_t attr_length = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
        
        if (attr_type == stun::ATTR_CHANGE_REQUEST && attr_length >= 4 && offset + 8 <= size) {
            uint32_t flags = (static_cast<uint32_t>(data[offset + 4]) << 24) |
                            (static_cast<uint32_t>(data[offset + 5]) << 16) |
                            (static_cast<uint32_t>(data[offset + 6]) << 8) |
                            data[offset + 7];
            
            change_ip = (flags & 0x04) != 0;
            change_port = (flags & 0x02) != 0;
            return true;
        }
        
        // Move to next attribute (4-byte aligned)
        offset += 4 + ((attr_length + 3) & ~3);
    }
    
    return false;
}

std::vector<uint8_t> STUNServer::build_binding_response(
    const stun::Header& request_header,
    const udp::endpoint& client_endpoint,
    bool include_other_address) {
    
    std::vector<uint8_t> buffer;
    buffer.reserve(128);
    
    // Reserve space for header (will fill in later)
    buffer.resize(stun::HEADER_SIZE);
    
    // Add XOR-MAPPED-ADDRESS (required)
    add_xor_mapped_address(buffer, client_endpoint, request_header);
    
    // Add MAPPED-ADDRESS (for compatibility)
    add_mapped_address(buffer, client_endpoint);
    
    // Add RESPONSE-ORIGIN (local address)
    add_response_origin(buffer, external_ip_, port_);
    
    // Add OTHER-ADDRESS if available
    if (include_other_address && !external_ip2_.empty()) {
        add_other_address(buffer, external_ip2_, port_);
    }
    
    // Add SOFTWARE attribute
    add_software(buffer);
    
    // Add FINGERPRINT attribute
    add_fingerprint(buffer);
    
    // Fill in header
    uint16_t attr_length = static_cast<uint16_t>(buffer.size() - stun::HEADER_SIZE);
    
    buffer[0] = (stun::BINDING_RESPONSE >> 8) & 0xFF;
    buffer[1] = stun::BINDING_RESPONSE & 0xFF;
    buffer[2] = (attr_length >> 8) & 0xFF;
    buffer[3] = attr_length & 0xFF;
    buffer[4] = (stun::MAGIC_COOKIE >> 24) & 0xFF;
    buffer[5] = (stun::MAGIC_COOKIE >> 16) & 0xFF;
    buffer[6] = (stun::MAGIC_COOKIE >> 8) & 0xFF;
    buffer[7] = stun::MAGIC_COOKIE & 0xFF;
    std::memcpy(buffer.data() + 8, request_header.transaction_id.data(), stun::TRANSACTION_ID_SIZE);
    
    return buffer;
}

std::vector<uint8_t> STUNServer::build_error_response(
    const stun::Header& request_header,
    uint16_t error_code,
    const std::string& reason) {
    
    std::vector<uint8_t> buffer;
    buffer.reserve(128);
    
    // Reserve space for header
    buffer.resize(stun::HEADER_SIZE);
    
    // Add ERROR-CODE attribute
    uint16_t class_code = error_code / 100;
    uint16_t number = error_code % 100;
    
    // Attribute header
    buffer.push_back((stun::ATTR_ERROR_CODE >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_ERROR_CODE & 0xFF);
    
    uint16_t value_length = static_cast<uint16_t>(4 + reason.size());
    buffer.push_back((value_length >> 8) & 0xFF);
    buffer.push_back(value_length & 0xFF);
    
    // Error code value
    buffer.push_back(0);
    buffer.push_back(0);
    buffer.push_back(static_cast<uint8_t>(class_code));
    buffer.push_back(static_cast<uint8_t>(number));
    
    // Reason phrase
    buffer.insert(buffer.end(), reason.begin(), reason.end());
    
    // Padding
    while (buffer.size() % 4 != 0) {
        buffer.push_back(0);
    }
    
    // Fill in header
    uint16_t attr_length = static_cast<uint16_t>(buffer.size() - stun::HEADER_SIZE);
    
    buffer[0] = (stun::BINDING_ERROR_RESPONSE >> 8) & 0xFF;
    buffer[1] = stun::BINDING_ERROR_RESPONSE & 0xFF;
    buffer[2] = (attr_length >> 8) & 0xFF;
    buffer[3] = attr_length & 0xFF;
    buffer[4] = (stun::MAGIC_COOKIE >> 24) & 0xFF;
    buffer[5] = (stun::MAGIC_COOKIE >> 16) & 0xFF;
    buffer[6] = (stun::MAGIC_COOKIE >> 8) & 0xFF;
    buffer[7] = stun::MAGIC_COOKIE & 0xFF;
    std::memcpy(buffer.data() + 8, request_header.transaction_id.data(), stun::TRANSACTION_ID_SIZE);
    
    return buffer;
}

void STUNServer::add_xor_mapped_address(std::vector<uint8_t>& buffer, 
                                         const udp::endpoint& endpoint,
                                         const stun::Header& header) {
    // Attribute header
    buffer.push_back((stun::ATTR_XOR_MAPPED_ADDRESS >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_XOR_MAPPED_ADDRESS & 0xFF);
    
    bool is_ipv6 = endpoint.address().is_v6();
    uint16_t value_length = is_ipv6 ? 20 : 8;
    
    buffer.push_back((value_length >> 8) & 0xFF);
    buffer.push_back(value_length & 0xFF);
    
    // Reserved byte
    buffer.push_back(0);
    
    // Address family
    buffer.push_back(is_ipv6 ? stun::IPV6 : stun::IPV4);
    
    // XOR'd port
    uint16_t port = endpoint.port();
    uint16_t xor_port = port ^ (stun::MAGIC_COOKIE >> 16);
    buffer.push_back((xor_port >> 8) & 0xFF);
    buffer.push_back(xor_port & 0xFF);
    
    // XOR'd address
    if (is_ipv6) {
        auto addr = endpoint.address().to_v6().to_bytes();
        // XOR with magic cookie + transaction ID
        uint8_t xor_key[16];
        xor_key[0] = (stun::MAGIC_COOKIE >> 24) & 0xFF;
        xor_key[1] = (stun::MAGIC_COOKIE >> 16) & 0xFF;
        xor_key[2] = (stun::MAGIC_COOKIE >> 8) & 0xFF;
        xor_key[3] = stun::MAGIC_COOKIE & 0xFF;
        std::memcpy(xor_key + 4, header.transaction_id.data(), 12);
        
        for (size_t i = 0; i < 16; i++) {
            buffer.push_back(addr[i] ^ xor_key[i]);
        }
    } else {
        auto addr = endpoint.address().to_v4().to_bytes();
        // XOR with magic cookie
        buffer.push_back(addr[0] ^ ((stun::MAGIC_COOKIE >> 24) & 0xFF));
        buffer.push_back(addr[1] ^ ((stun::MAGIC_COOKIE >> 16) & 0xFF));
        buffer.push_back(addr[2] ^ ((stun::MAGIC_COOKIE >> 8) & 0xFF));
        buffer.push_back(addr[3] ^ (stun::MAGIC_COOKIE & 0xFF));
    }
}

void STUNServer::add_mapped_address(std::vector<uint8_t>& buffer, 
                                     const udp::endpoint& endpoint) {
    // Attribute header
    buffer.push_back((stun::ATTR_MAPPED_ADDRESS >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_MAPPED_ADDRESS & 0xFF);
    
    bool is_ipv6 = endpoint.address().is_v6();
    uint16_t value_length = is_ipv6 ? 20 : 8;
    
    buffer.push_back((value_length >> 8) & 0xFF);
    buffer.push_back(value_length & 0xFF);
    
    // Reserved byte
    buffer.push_back(0);
    
    // Address family
    buffer.push_back(is_ipv6 ? stun::IPV6 : stun::IPV4);
    
    // Port
    uint16_t port = endpoint.port();
    buffer.push_back((port >> 8) & 0xFF);
    buffer.push_back(port & 0xFF);
    
    // Address
    if (is_ipv6) {
        auto addr = endpoint.address().to_v6().to_bytes();
        buffer.insert(buffer.end(), addr.begin(), addr.end());
    } else {
        auto addr = endpoint.address().to_v4().to_bytes();
        buffer.insert(buffer.end(), addr.begin(), addr.end());
    }
}

void STUNServer::add_other_address(std::vector<uint8_t>& buffer,
                                    const std::string& ip, uint16_t port) {
    // Attribute header
    buffer.push_back((stun::ATTR_OTHER_ADDRESS >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_OTHER_ADDRESS & 0xFF);
    
    auto addr = asio::ip::make_address(ip);
    bool is_ipv6 = addr.is_v6();
    uint16_t value_length = is_ipv6 ? 20 : 8;
    
    buffer.push_back((value_length >> 8) & 0xFF);
    buffer.push_back(value_length & 0xFF);
    
    // Reserved byte
    buffer.push_back(0);
    
    // Address family
    buffer.push_back(is_ipv6 ? stun::IPV6 : stun::IPV4);
    
    // Port
    buffer.push_back((port >> 8) & 0xFF);
    buffer.push_back(port & 0xFF);
    
    // Address
    if (is_ipv6) {
        auto bytes = addr.to_v6().to_bytes();
        buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    } else {
        auto bytes = addr.to_v4().to_bytes();
        buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    }
}

void STUNServer::add_response_origin(std::vector<uint8_t>& buffer,
                                      const std::string& ip, uint16_t port) {
    // Attribute header
    buffer.push_back((stun::ATTR_RESPONSE_ORIGIN >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_RESPONSE_ORIGIN & 0xFF);
    
    auto addr = asio::ip::make_address(ip);
    bool is_ipv6 = addr.is_v6();
    uint16_t value_length = is_ipv6 ? 20 : 8;
    
    buffer.push_back((value_length >> 8) & 0xFF);
    buffer.push_back(value_length & 0xFF);
    
    // Reserved byte
    buffer.push_back(0);
    
    // Address family
    buffer.push_back(is_ipv6 ? stun::IPV6 : stun::IPV4);
    
    // Port
    buffer.push_back((port >> 8) & 0xFF);
    buffer.push_back(port & 0xFF);
    
    // Address
    if (is_ipv6) {
        auto bytes = addr.to_v6().to_bytes();
        buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    } else {
        auto bytes = addr.to_v4().to_bytes();
        buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    }
}

void STUNServer::add_software(std::vector<uint8_t>& buffer) {
    std::string_view software(SOFTWARE_NAME);
    
    // Attribute header
    buffer.push_back((stun::ATTR_SOFTWARE >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_SOFTWARE & 0xFF);
    
    uint16_t length = static_cast<uint16_t>(software.size());
    buffer.push_back((length >> 8) & 0xFF);
    buffer.push_back(length & 0xFF);
    
    // Value
    buffer.insert(buffer.end(), software.begin(), software.end());
    
    // Padding
    while (buffer.size() % 4 != 0) {
        buffer.push_back(0);
    }
}

void STUNServer::add_fingerprint(std::vector<uint8_t>& buffer) {
    // CRC32 of message up to (but not including) FINGERPRINT
    // XOR'd with 0x5354554E
    
    // Simple CRC32 implementation (not production quality - should use proper library)
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < buffer.size(); i++) {
        crc ^= buffer[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^= 0xFFFFFFFF;
    crc ^= 0x5354554E;  // XOR with "STUN"
    
    // Attribute header
    buffer.push_back((stun::ATTR_FINGERPRINT >> 8) & 0xFF);
    buffer.push_back(stun::ATTR_FINGERPRINT & 0xFF);
    buffer.push_back(0);
    buffer.push_back(4);  // Length is always 4
    
    // Value (big endian)
    buffer.push_back((crc >> 24) & 0xFF);
    buffer.push_back((crc >> 16) & 0xFF);
    buffer.push_back((crc >> 8) & 0xFF);
    buffer.push_back(crc & 0xFF);
}

void STUNServer::send_response(const udp::endpoint& remote, std::vector<uint8_t> data) {
    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data));
    
    socket_.async_send_to(
        asio::buffer(*buffer),
        remote,
        [this, buffer](boost::system::error_code ec, std::size_t bytes_sent) {
            on_send(ec, bytes_sent);
        });
}

void STUNServer::on_send(boost::system::error_code ec, std::size_t /*bytes_sent*/) {
    if (ec) {
        LOG_ERROR("STUN send error: {}", ec.message());
        stats_.errors++;
    } else {
        stats_.responses_sent++;
    }
}

} // namespace edgelink

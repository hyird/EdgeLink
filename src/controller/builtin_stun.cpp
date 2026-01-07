#include "builtin_stun.hpp"
#include "common/log.hpp"

#include <boost/asio/buffer.hpp>
#include <cstring>
#include <arpa/inet.h>

namespace edgelink::controller {

BuiltinSTUN::BuiltinSTUN(net::io_context& ioc, const BuiltinSTUNConfig& config)
    : ioc_(ioc)
    , config_(config) {
    
    if (!config_.enabled) {
        return;
    }
    
    // Parse listen address
    std::string listen_addr = "0.0.0.0";
    port_ = 3478;
    
    auto pos = config_.listen.find(':');
    if (pos != std::string::npos) {
        listen_addr = config_.listen.substr(0, pos);
        port_ = static_cast<uint16_t>(std::stoi(config_.listen.substr(pos + 1)));
    }
    
    external_ip_ = config_.external_ip;
    external_ip2_ = config_.secondary_ip;
    
    if (external_ip_.empty()) {
        LOG_WARN("BuiltinSTUN: external_ip not configured, STUN may not work correctly");
    }
}

BuiltinSTUN::~BuiltinSTUN() {
    stop();
}

void BuiltinSTUN::start() {
    if (!config_.enabled) {
        LOG_INFO("BuiltinSTUN: Disabled in configuration");
        return;
    }
    
    if (running_) {
        return;
    }
    
    try {
        // Create primary socket
        socket_ = std::make_unique<udp::socket>(ioc_);
        
        udp::endpoint endpoint(net::ip::make_address("0.0.0.0"), port_);
        socket_->open(endpoint.protocol());
        socket_->set_option(net::socket_base::reuse_address(true));
        socket_->bind(endpoint);
        
        running_ = true;
        
        LOG_INFO("BuiltinSTUN: Started on port {} (external: {})", port_, external_ip_);
        
        if (!external_ip2_.empty()) {
            LOG_INFO("BuiltinSTUN: Secondary IP: {}", external_ip2_);
        }
        
        do_receive();
        
    } catch (const std::exception& e) {
        LOG_ERROR("BuiltinSTUN: Failed to start: {}", e.what());
        socket_.reset();
    }
}

void BuiltinSTUN::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    boost::system::error_code ec;
    if (socket_) {
        socket_->cancel(ec);
        socket_->close(ec);
        socket_.reset();
    }
    
    if (socket2_) {
        socket2_->cancel(ec);
        socket2_->close(ec);
        socket2_.reset();
    }
    
    LOG_INFO("BuiltinSTUN: Stopped");
}

void BuiltinSTUN::do_receive() {
    if (!running_ || !socket_) {
        return;
    }
    
    socket_->async_receive_from(
        net::buffer(recv_buffer_),
        remote_endpoint_,
        [this](boost::system::error_code ec, std::size_t bytes) {
            on_receive(ec, bytes);
        });
}

void BuiltinSTUN::on_receive(boost::system::error_code ec, std::size_t bytes_received) {
    if (ec) {
        if (ec != net::error::operation_aborted) {
            LOG_ERROR("BuiltinSTUN: Receive error: {}", ec.message());
            stats_.errors++;
        }
        return;
    }
    
    stats_.requests_received++;
    
    // Process the request
    process_request(remote_endpoint_, recv_buffer_, bytes_received);
    
    // Continue receiving
    do_receive();
}

void BuiltinSTUN::process_request(const udp::endpoint& remote,
                                   const std::array<uint8_t, stun::MAX_MESSAGE_SIZE>& data,
                                   std::size_t size) {
    stun::Header header;
    if (!parse_header(data.data(), size, header)) {
        LOG_WARN("BuiltinSTUN: Invalid STUN header from {}", remote.address().to_string());
        return;
    }
    
    if (header.type != stun::BINDING_REQUEST) {
        LOG_DEBUG("BuiltinSTUN: Non-binding request type: 0x{:04X}", header.type);
        return;
    }
    
    LOG_DEBUG("BuiltinSTUN: Binding request from {}:{}", 
              remote.address().to_string(), remote.port());
    
    // Build and send response
    bool include_other = !external_ip2_.empty();
    auto response = build_binding_response(header, remote, include_other);
    send_response(remote, std::move(response));
}

bool BuiltinSTUN::parse_header(const uint8_t* data, std::size_t size, stun::Header& header) {
    if (size < stun::HEADER_SIZE) {
        return false;
    }
    
    header.type = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    header.length = (static_cast<uint16_t>(data[2]) << 8) | data[3];
    header.magic_cookie = (static_cast<uint32_t>(data[4]) << 24) |
                          (static_cast<uint32_t>(data[5]) << 16) |
                          (static_cast<uint32_t>(data[6]) << 8) |
                          data[7];
    
    // Verify magic cookie
    if (header.magic_cookie != stun::MAGIC_COOKIE) {
        return false;
    }
    
    // Copy transaction ID
    std::memcpy(header.transaction_id.data(), data + 8, stun::TRANSACTION_ID_SIZE);
    
    return true;
}

std::vector<uint8_t> BuiltinSTUN::build_binding_response(
    const stun::Header& request_header,
    const udp::endpoint& client_endpoint,
    bool include_other_address) {
    
    std::vector<uint8_t> buffer;
    buffer.reserve(128);
    
    // Reserve space for header (will fill in later)
    buffer.resize(stun::HEADER_SIZE);
    
    // Add XOR-MAPPED-ADDRESS
    add_xor_mapped_address(buffer, client_endpoint, request_header);
    
    // Add MAPPED-ADDRESS (for compatibility)
    add_mapped_address(buffer, client_endpoint);
    
    // Add RESPONSE-ORIGIN
    if (!external_ip_.empty()) {
        add_response_origin(buffer, external_ip_, port_);
    }
    
    // Add OTHER-ADDRESS if we have secondary IP
    if (include_other_address && !external_ip2_.empty()) {
        add_other_address(buffer, external_ip2_, port_);
    }
    
    // Add SOFTWARE
    add_software(buffer);
    
    // Fill in header
    uint16_t msg_length = static_cast<uint16_t>(buffer.size() - stun::HEADER_SIZE);
    
    buffer[0] = (stun::BINDING_RESPONSE >> 8) & 0xFF;
    buffer[1] = stun::BINDING_RESPONSE & 0xFF;
    buffer[2] = (msg_length >> 8) & 0xFF;
    buffer[3] = msg_length & 0xFF;
    buffer[4] = (stun::MAGIC_COOKIE >> 24) & 0xFF;
    buffer[5] = (stun::MAGIC_COOKIE >> 16) & 0xFF;
    buffer[6] = (stun::MAGIC_COOKIE >> 8) & 0xFF;
    buffer[7] = stun::MAGIC_COOKIE & 0xFF;
    std::memcpy(buffer.data() + 8, request_header.transaction_id.data(), stun::TRANSACTION_ID_SIZE);
    
    return buffer;
}

std::vector<uint8_t> BuiltinSTUN::build_error_response(
    const stun::Header& request_header,
    uint16_t error_code,
    const std::string& reason) {
    
    std::vector<uint8_t> buffer;
    buffer.reserve(64 + reason.size());
    buffer.resize(stun::HEADER_SIZE);
    
    // ERROR-CODE attribute
    uint16_t attr_type = stun::ATTR_ERROR_CODE;
    uint16_t error_class = error_code / 100;
    uint16_t error_number = error_code % 100;
    uint16_t attr_length = static_cast<uint16_t>(4 + reason.size());
    uint16_t padded_length = (attr_length + 3) & ~3;
    
    buffer.push_back((attr_type >> 8) & 0xFF);
    buffer.push_back(attr_type & 0xFF);
    buffer.push_back((attr_length >> 8) & 0xFF);
    buffer.push_back(attr_length & 0xFF);
    buffer.push_back(0);  // Reserved
    buffer.push_back(0);  // Reserved
    buffer.push_back(static_cast<uint8_t>(error_class));
    buffer.push_back(static_cast<uint8_t>(error_number));
    buffer.insert(buffer.end(), reason.begin(), reason.end());
    
    // Pad to 4-byte boundary
    while (buffer.size() < stun::HEADER_SIZE + 4 + padded_length) {
        buffer.push_back(0);
    }
    
    // Fill in header
    uint16_t msg_length = static_cast<uint16_t>(buffer.size() - stun::HEADER_SIZE);
    
    buffer[0] = (stun::BINDING_ERROR_RESPONSE >> 8) & 0xFF;
    buffer[1] = stun::BINDING_ERROR_RESPONSE & 0xFF;
    buffer[2] = (msg_length >> 8) & 0xFF;
    buffer[3] = msg_length & 0xFF;
    buffer[4] = (stun::MAGIC_COOKIE >> 24) & 0xFF;
    buffer[5] = (stun::MAGIC_COOKIE >> 16) & 0xFF;
    buffer[6] = (stun::MAGIC_COOKIE >> 8) & 0xFF;
    buffer[7] = stun::MAGIC_COOKIE & 0xFF;
    std::memcpy(buffer.data() + 8, request_header.transaction_id.data(), stun::TRANSACTION_ID_SIZE);
    
    return buffer;
}

void BuiltinSTUN::add_xor_mapped_address(std::vector<uint8_t>& buffer,
                                          const udp::endpoint& endpoint,
                                          const stun::Header& header) {
    uint16_t attr_type = stun::ATTR_XOR_MAPPED_ADDRESS;
    uint16_t attr_length = 8;  // 1 + 1 + 2 + 4 for IPv4
    
    buffer.push_back((attr_type >> 8) & 0xFF);
    buffer.push_back(attr_type & 0xFF);
    buffer.push_back((attr_length >> 8) & 0xFF);
    buffer.push_back(attr_length & 0xFF);
    
    // Reserved
    buffer.push_back(0);
    
    // Family
    buffer.push_back(stun::IPV4);
    
    // XOR'd port
    uint16_t port = endpoint.port();
    uint16_t xport = port ^ static_cast<uint16_t>(stun::MAGIC_COOKIE >> 16);
    buffer.push_back((xport >> 8) & 0xFF);
    buffer.push_back(xport & 0xFF);
    
    // XOR'd address
    auto addr = endpoint.address().to_v4().to_bytes();
    buffer.push_back(addr[0] ^ ((stun::MAGIC_COOKIE >> 24) & 0xFF));
    buffer.push_back(addr[1] ^ ((stun::MAGIC_COOKIE >> 16) & 0xFF));
    buffer.push_back(addr[2] ^ ((stun::MAGIC_COOKIE >> 8) & 0xFF));
    buffer.push_back(addr[3] ^ (stun::MAGIC_COOKIE & 0xFF));
}

void BuiltinSTUN::add_mapped_address(std::vector<uint8_t>& buffer,
                                      const udp::endpoint& endpoint) {
    uint16_t attr_type = stun::ATTR_MAPPED_ADDRESS;
    uint16_t attr_length = 8;
    
    buffer.push_back((attr_type >> 8) & 0xFF);
    buffer.push_back(attr_type & 0xFF);
    buffer.push_back((attr_length >> 8) & 0xFF);
    buffer.push_back(attr_length & 0xFF);
    
    buffer.push_back(0);  // Reserved
    buffer.push_back(stun::IPV4);
    
    uint16_t port = endpoint.port();
    buffer.push_back((port >> 8) & 0xFF);
    buffer.push_back(port & 0xFF);
    
    auto addr = endpoint.address().to_v4().to_bytes();
    buffer.insert(buffer.end(), addr.begin(), addr.end());
}

void BuiltinSTUN::add_other_address(std::vector<uint8_t>& buffer,
                                     const std::string& ip, uint16_t port) {
    uint16_t attr_type = stun::ATTR_OTHER_ADDRESS;
    uint16_t attr_length = 8;
    
    buffer.push_back((attr_type >> 8) & 0xFF);
    buffer.push_back(attr_type & 0xFF);
    buffer.push_back((attr_length >> 8) & 0xFF);
    buffer.push_back(attr_length & 0xFF);
    
    buffer.push_back(0);  // Reserved
    buffer.push_back(stun::IPV4);
    
    buffer.push_back((port >> 8) & 0xFF);
    buffer.push_back(port & 0xFF);
    
    auto addr = net::ip::make_address_v4(ip).to_bytes();
    buffer.insert(buffer.end(), addr.begin(), addr.end());
}

void BuiltinSTUN::add_response_origin(std::vector<uint8_t>& buffer,
                                       const std::string& ip, uint16_t port) {
    uint16_t attr_type = stun::ATTR_RESPONSE_ORIGIN;
    uint16_t attr_length = 8;
    
    buffer.push_back((attr_type >> 8) & 0xFF);
    buffer.push_back(attr_type & 0xFF);
    buffer.push_back((attr_length >> 8) & 0xFF);
    buffer.push_back(attr_length & 0xFF);
    
    buffer.push_back(0);  // Reserved
    buffer.push_back(stun::IPV4);
    
    buffer.push_back((port >> 8) & 0xFF);
    buffer.push_back(port & 0xFF);
    
    auto addr = net::ip::make_address_v4(ip).to_bytes();
    buffer.insert(buffer.end(), addr.begin(), addr.end());
}

void BuiltinSTUN::add_software(std::vector<uint8_t>& buffer) {
    uint16_t attr_type = stun::ATTR_SOFTWARE;
    size_t name_len = std::strlen(SOFTWARE_NAME);
    uint16_t attr_length = static_cast<uint16_t>(name_len);
    uint16_t padded_length = (attr_length + 3) & ~3;
    
    buffer.push_back((attr_type >> 8) & 0xFF);
    buffer.push_back(attr_type & 0xFF);
    buffer.push_back((attr_length >> 8) & 0xFF);
    buffer.push_back(attr_length & 0xFF);
    
    buffer.insert(buffer.end(), SOFTWARE_NAME, SOFTWARE_NAME + name_len);
    
    // Pad to 4-byte boundary
    size_t current = buffer.size();
    size_t target = current + (padded_length - attr_length);
    while (buffer.size() < target) {
        buffer.push_back(0);
    }
}

void BuiltinSTUN::send_response(const udp::endpoint& remote, std::vector<uint8_t> data) {
    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data));
    
    socket_->async_send_to(
        net::buffer(*buffer),
        remote,
        [this, buffer](boost::system::error_code ec, std::size_t bytes) {
            on_send(ec, bytes);
        });
}

void BuiltinSTUN::on_send(boost::system::error_code ec, std::size_t /*bytes_sent*/) {
    if (ec) {
        LOG_ERROR("BuiltinSTUN: Send error: {}", ec.message());
        stats_.errors++;
    } else {
        stats_.responses_sent++;
    }
}

} // namespace edgelink::controller

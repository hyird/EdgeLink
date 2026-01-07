#pragma once

#include "common/protocol.hpp"
#include "common/config.hpp"

#include <boost/asio.hpp>
#include <memory>
#include <array>
#include <atomic>
#include <string>

namespace edgelink {

namespace asio = boost::asio;
using udp = asio::ip::udp;

// ============================================================================
// STUN Protocol Constants (RFC 5389)
// ============================================================================
namespace stun {

// STUN message types
constexpr uint16_t BINDING_REQUEST = 0x0001;
constexpr uint16_t BINDING_RESPONSE = 0x0101;
constexpr uint16_t BINDING_ERROR_RESPONSE = 0x0111;

// STUN attributes
constexpr uint16_t ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t ATTR_ERROR_CODE = 0x0009;
constexpr uint16_t ATTR_SOFTWARE = 0x8022;
constexpr uint16_t ATTR_FINGERPRINT = 0x8028;
constexpr uint16_t ATTR_OTHER_ADDRESS = 0x802C;
constexpr uint16_t ATTR_RESPONSE_ORIGIN = 0x802B;
constexpr uint16_t ATTR_CHANGE_REQUEST = 0x0003;

// Magic cookie (fixed value in STUN)
constexpr uint32_t MAGIC_COOKIE = 0x2112A442;

// Address families
constexpr uint8_t IPV4 = 0x01;
constexpr uint8_t IPV6 = 0x02;

// Header size
constexpr size_t HEADER_SIZE = 20;
constexpr size_t TRANSACTION_ID_SIZE = 12;

// Maximum message size
constexpr size_t MAX_MESSAGE_SIZE = 548;

// STUN header structure
struct Header {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    std::array<uint8_t, TRANSACTION_ID_SIZE> transaction_id;
};

// Attribute header
struct AttributeHeader {
    uint16_t type;
    uint16_t length;
};

} // namespace stun

// ============================================================================
// STUNServer - STUN server for NAT detection
// ============================================================================
class STUNServer {
public:
    STUNServer(asio::io_context& ioc, const ServerConfig& config);
    ~STUNServer();
    
    // Start/stop the server
    void start();
    void stop();
    
    // Check if running
    bool is_running() const { return running_; }
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> requests_received{0};
        std::atomic<uint64_t> responses_sent{0};
        std::atomic<uint64_t> errors{0};
    };
    const Stats& stats() const { return stats_; }

private:
    // Receive handling
    void do_receive();
    void on_receive(boost::system::error_code ec, std::size_t bytes_received);
    
    // Process STUN request
    void process_request(const udp::endpoint& remote, 
                         const std::array<uint8_t, stun::MAX_MESSAGE_SIZE>& data,
                         std::size_t size);
    
    // Build STUN response
    std::vector<uint8_t> build_binding_response(
        const stun::Header& request_header,
        const udp::endpoint& client_endpoint,
        bool include_other_address);
    
    std::vector<uint8_t> build_error_response(
        const stun::Header& request_header,
        uint16_t error_code,
        const std::string& reason);
    
    // Attribute builders
    void add_xor_mapped_address(std::vector<uint8_t>& buffer, 
                                 const udp::endpoint& endpoint,
                                 const stun::Header& header);
    void add_mapped_address(std::vector<uint8_t>& buffer, 
                            const udp::endpoint& endpoint);
    void add_other_address(std::vector<uint8_t>& buffer,
                           const std::string& ip, uint16_t port);
    void add_response_origin(std::vector<uint8_t>& buffer,
                             const std::string& ip, uint16_t port);
    void add_software(std::vector<uint8_t>& buffer);
    void add_fingerprint(std::vector<uint8_t>& buffer);
    
    // Parse helpers
    bool parse_header(const uint8_t* data, std::size_t size, stun::Header& header);
    bool has_change_request(const uint8_t* data, std::size_t size, 
                            bool& change_ip, bool& change_port);
    
    // Send response
    void send_response(const udp::endpoint& remote, std::vector<uint8_t> data);
    void on_send(boost::system::error_code ec, std::size_t bytes_sent);
    
    asio::io_context& ioc_;
    const ServerConfig& config_;
    
    // Primary socket
    udp::socket socket_;
    
    // Secondary socket (optional, for full NAT detection)
    std::unique_ptr<udp::socket> socket2_;
    
    // External IPs
    std::string external_ip_;
    std::string external_ip2_;
    uint16_t port_;
    
    // Receive buffer
    std::array<uint8_t, stun::MAX_MESSAGE_SIZE> recv_buffer_;
    udp::endpoint remote_endpoint_;
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Statistics
    Stats stats_;
    
    // Software name for STUN response
    static constexpr const char* SOFTWARE_NAME = "edgelink-stun/1.0";
};

} // namespace edgelink

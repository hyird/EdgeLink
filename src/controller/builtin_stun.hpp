#pragma once

#include "common/config.hpp"

#include <boost/asio.hpp>
#include <memory>
#include <array>
#include <atomic>
#include <string>

namespace edgelink::controller {

namespace net = boost::asio;
using udp = net::ip::udp;

// ============================================================================
// STUN Protocol Constants (RFC 5389)
// ============================================================================
namespace stun {

constexpr uint16_t BINDING_REQUEST = 0x0001;
constexpr uint16_t BINDING_RESPONSE = 0x0101;
constexpr uint16_t BINDING_ERROR_RESPONSE = 0x0111;

constexpr uint16_t ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t ATTR_ERROR_CODE = 0x0009;
constexpr uint16_t ATTR_SOFTWARE = 0x8022;
constexpr uint16_t ATTR_FINGERPRINT = 0x8028;
constexpr uint16_t ATTR_OTHER_ADDRESS = 0x802C;
constexpr uint16_t ATTR_RESPONSE_ORIGIN = 0x802B;

constexpr uint32_t MAGIC_COOKIE = 0x2112A442;
constexpr uint8_t IPV4 = 0x01;
constexpr uint8_t IPV6 = 0x02;

constexpr size_t HEADER_SIZE = 20;
constexpr size_t TRANSACTION_ID_SIZE = 12;
constexpr size_t MAX_MESSAGE_SIZE = 548;

struct Header {
    uint16_t type;
    uint16_t length;
    uint32_t magic_cookie;
    std::array<uint8_t, TRANSACTION_ID_SIZE> transaction_id;
};

} // namespace stun

// ============================================================================
// BuiltinSTUN - Built-in STUN server for Controller
// ============================================================================
class BuiltinSTUN {
public:
    BuiltinSTUN(net::io_context& ioc, const BuiltinSTUNConfig& config);
    ~BuiltinSTUN();
    
    // Start/stop the server
    void start();
    void stop();
    
    // Check if running
    bool is_running() const { return running_; }
    bool is_enabled() const { return config_.enabled; }
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> requests_received{0};
        std::atomic<uint64_t> responses_sent{0};
        std::atomic<uint64_t> errors{0};
    };
    const Stats& stats() const { return stats_; }

private:
    void do_receive();
    void on_receive(boost::system::error_code ec, std::size_t bytes_received);
    
    void process_request(const udp::endpoint& remote,
                         const std::array<uint8_t, stun::MAX_MESSAGE_SIZE>& data,
                         std::size_t size);
    
    std::vector<uint8_t> build_binding_response(
        const stun::Header& request_header,
        const udp::endpoint& client_endpoint,
        bool include_other_address);
    
    std::vector<uint8_t> build_error_response(
        const stun::Header& request_header,
        uint16_t error_code,
        const std::string& reason);
    
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
    
    bool parse_header(const uint8_t* data, std::size_t size, stun::Header& header);
    
    void send_response(const udp::endpoint& remote, std::vector<uint8_t> data);
    void on_send(boost::system::error_code ec, std::size_t bytes_sent);
    
    net::io_context& ioc_;
    BuiltinSTUNConfig config_;
    
    std::unique_ptr<udp::socket> socket_;
    std::unique_ptr<udp::socket> socket2_;  // Optional secondary socket
    
    std::string external_ip_;
    std::string external_ip2_;
    uint16_t port_;
    
    std::array<uint8_t, stun::MAX_MESSAGE_SIZE> recv_buffer_;
    udp::endpoint remote_endpoint_;
    
    std::atomic<bool> running_{false};
    Stats stats_;
    
    static constexpr const char* SOFTWARE_NAME = "edgelink-stun/1.0";
};

} // namespace edgelink::controller

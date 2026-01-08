#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <expected>
#include <memory>
#include <atomic>
#include <thread>
#include <boost/asio.hpp>

#include "common/protocol.hpp"

namespace edgelink::client {

// Import wire protocol error codes to avoid conflicts with proto types
using ErrorCode = wire::ErrorCode;

class TunDevice {
public:
    using PacketCallback = std::function<void(const std::vector<uint8_t>&)>;
    
    TunDevice(boost::asio::io_context& ioc, const std::string& name);
    ~TunDevice();
    
    // Non-copyable, non-movable
    TunDevice(const TunDevice&) = delete;
    TunDevice& operator=(const TunDevice&) = delete;
    
    // Create and configure the TUN device
    std::expected<void, ErrorCode> open();
    void close();
    
    // Configure IP address and routes
    std::expected<void, ErrorCode> set_address(const std::string& ip, uint8_t prefix_len);
    std::expected<void, ErrorCode> set_mtu(uint16_t mtu);
    std::expected<void, ErrorCode> bring_up();
    std::expected<void, ErrorCode> bring_down();
    
    // Add/remove routes through this interface
    std::expected<void, ErrorCode> add_route(const std::string& network, uint8_t prefix_len);
    std::expected<void, ErrorCode> del_route(const std::string& network, uint8_t prefix_len);
    
    // Packet handling
    void set_packet_callback(PacketCallback cb);
    void start_reading();
    void stop_reading();
    
    // Write packet to TUN (inject into network stack)
    std::expected<void, ErrorCode> write_packet(const std::vector<uint8_t>& packet);
    
    // Getters
    const std::string& name() const { return name_; }
    int fd() const { return fd_; }
    bool is_open() const { return fd_ >= 0; }
    
private:
#ifdef _WIN32
    // Windows: wintun-based implementation
    struct PlatformData;
    std::unique_ptr<PlatformData> platform_;
    std::thread read_thread_;
#else
    // POSIX: /dev/net/tun based implementation
    void do_read();
    int execute_ip_command(const std::vector<std::string>& args);
    std::unique_ptr<boost::asio::posix::stream_descriptor> stream_;
#endif
    
    boost::asio::io_context& ioc_;
    std::string name_;
    int fd_ = -1;
    uint16_t mtu_ = NetworkConstants::DEFAULT_TUN_MTU;
    
    std::vector<uint8_t> read_buffer_;
    PacketCallback packet_callback_;
    std::atomic<bool> reading_{false};
};

// Parse IPv4 address from packet (for routing decisions)
struct IPv4Header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
    
    static std::expected<IPv4Header, ErrorCode> parse(const std::vector<uint8_t>& packet);
    
    uint8_t version() const { return (version_ihl >> 4) & 0x0F; }
    uint8_t header_length() const { return (version_ihl & 0x0F) * 4; }
    
    std::string src_ip_string() const;
    std::string dst_ip_string() const;
};

} // namespace edgelink::client

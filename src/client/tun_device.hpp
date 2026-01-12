#pragma once

#include "common/types.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <expected>

namespace asio = boost::asio;

namespace edgelink::client {

// TUN device error codes
enum class TunError {
    OPEN_FAILED,
    CONFIGURE_FAILED,
    READ_FAILED,
    WRITE_FAILED,
    NOT_SUPPORTED,
};

std::string tun_error_message(TunError error);

// TUN 数据包通道（替代 PacketCallback）
namespace channels {
using TunPacketChannel = asio::experimental::channel<
    void(boost::system::error_code, std::vector<uint8_t>)>;
}  // namespace channels

// Abstract TUN device interface
class TunDevice {
public:
    virtual ~TunDevice() = default;

    // Open TUN device with specified name (or auto-generate)
    virtual std::expected<void, TunError> open(const std::string& name = "") = 0;

    // Configure IP address and bring up the interface
    virtual std::expected<void, TunError> configure(
        const IPv4Address& ip,
        const IPv4Address& netmask,
        uint32_t mtu = 1420) = 0;

    // Close the device
    virtual void close() = 0;

    // Check if device is open
    virtual bool is_open() const = 0;

    // Get device name
    virtual std::string name() const = 0;

    // Set packet channel for receiving packets
    virtual void set_packet_channel(channels::TunPacketChannel* channel) = 0;

    // Start reading packets (async, sends to channel)
    virtual void start_read() = 0;

    // Stop reading
    virtual void stop_read() = 0;

    // Write a packet to the TUN device
    virtual std::expected<void, TunError> write(std::span<const uint8_t> packet) = 0;

    // Async write
    virtual asio::awaitable<std::expected<void, TunError>> async_write(
        std::span<const uint8_t> packet) = 0;

    // Factory method - creates platform-specific TUN device
    static std::unique_ptr<TunDevice> create(asio::io_context& ioc);
};

// IP packet utilities
namespace ip_packet {

// Get IP version from packet (4 or 6)
inline uint8_t version(std::span<const uint8_t> packet) {
    if (packet.empty()) return 0;
    return (packet[0] >> 4) & 0x0F;
}

// Get destination IP from IPv4 packet
inline IPv4Address dst_ipv4(std::span<const uint8_t> packet) {
    if (packet.size() < 20) return {};
    return IPv4Address::from_u32(
        (static_cast<uint32_t>(packet[16]) << 24) |
        (static_cast<uint32_t>(packet[17]) << 16) |
        (static_cast<uint32_t>(packet[18]) << 8) |
        static_cast<uint32_t>(packet[19]));
}

// Get source IP from IPv4 packet
inline IPv4Address src_ipv4(std::span<const uint8_t> packet) {
    if (packet.size() < 20) return {};
    return IPv4Address::from_u32(
        (static_cast<uint32_t>(packet[12]) << 24) |
        (static_cast<uint32_t>(packet[13]) << 16) |
        (static_cast<uint32_t>(packet[14]) << 8) |
        static_cast<uint32_t>(packet[15]));
}

// Get total length from IPv4 packet
inline uint16_t total_length(std::span<const uint8_t> packet) {
    if (packet.size() < 4) return 0;
    return (static_cast<uint16_t>(packet[2]) << 8) | packet[3];
}

// Get protocol from IPv4 packet
inline uint8_t protocol(std::span<const uint8_t> packet) {
    if (packet.size() < 10) return 0;
    return packet[9];
}

// Protocol numbers
constexpr uint8_t PROTO_ICMP = 1;
constexpr uint8_t PROTO_TCP = 6;
constexpr uint8_t PROTO_UDP = 17;

} // namespace ip_packet

} // namespace edgelink::client

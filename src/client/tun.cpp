#include "client/tun_device.hpp"
#include "common/log.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <array>

namespace edgelink::client {

// ============================================================================
// TunDevice Implementation
// ============================================================================

TunDevice::TunDevice(boost::asio::io_context& ioc, const std::string& name)
    : ioc_(ioc)
    , name_(name)
{
    read_buffer_.resize(NetworkConstants::MAX_PACKET_SIZE);
}

TunDevice::~TunDevice() {
    close();
}

std::expected<void, ErrorCode> TunDevice::open() {
    if (fd_ >= 0) {
        return {};  // Already open
    }
    
    // Open TUN device
    fd_ = ::open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) {
        LOG_ERROR("TunDevice: Failed to open /dev/net/tun: {}", strerror(errno));
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    // Configure TUN interface
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info
    
    if (name_.size() < IFNAMSIZ) {
        std::strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);
    }
    
    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        LOG_ERROR("TunDevice: Failed to configure TUN device: {}", strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    // Get actual device name (might differ if we used a template)
    name_ = ifr.ifr_name;
    
    // Set non-blocking
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERROR("TunDevice: Failed to set non-blocking mode: {}", strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    // Create ASIO stream
    stream_ = std::make_unique<boost::asio::posix::stream_descriptor>(ioc_, fd_);
    
    LOG_INFO("TunDevice: Created interface {}", name_);
    return {};
}

void TunDevice::close() {
    stop_reading();
    
    if (stream_) {
        boost::system::error_code ec;
        stream_->close(ec);
        stream_.reset();
    }
    
    if (fd_ >= 0) {
        // Don't close fd_ as stream_ owns it after assignment
        fd_ = -1;
    }
    
    LOG_INFO("TunDevice: Closed interface {}", name_);
}

std::expected<void, ErrorCode> TunDevice::set_address(const std::string& ip, uint8_t prefix_len) {
    // Use ip command to set address
    std::vector<std::string> args = {
        "addr", "add", ip + "/" + std::to_string(prefix_len), "dev", name_
    };
    
    int ret = execute_ip_command(args);
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to set address {} on {}", ip, name_);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    LOG_INFO("TunDevice: Set address {}/{} on {}", ip, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::set_mtu(uint16_t mtu) {
    mtu_ = mtu;
    
    std::vector<std::string> args = {
        "link", "set", "dev", name_, "mtu", std::to_string(mtu)
    };
    
    int ret = execute_ip_command(args);
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to set MTU {} on {}", mtu, name_);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    LOG_INFO("TunDevice: Set MTU {} on {}", mtu, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_up() {
    std::vector<std::string> args = {
        "link", "set", "dev", name_, "up"
    };
    
    int ret = execute_ip_command(args);
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to bring up {}", name_);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    LOG_INFO("TunDevice: Interface {} is up", name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_down() {
    std::vector<std::string> args = {
        "link", "set", "dev", name_, "down"
    };
    
    int ret = execute_ip_command(args);
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to bring down {}", name_);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    LOG_INFO("TunDevice: Interface {} is down", name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::add_route(const std::string& network, uint8_t prefix_len) {
    std::vector<std::string> args = {
        "route", "add", network + "/" + std::to_string(prefix_len), "dev", name_
    };
    
    int ret = execute_ip_command(args);
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to add route {}/{} via {}", network, prefix_len, name_);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    LOG_INFO("TunDevice: Added route {}/{} via {}", network, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::del_route(const std::string& network, uint8_t prefix_len) {
    std::vector<std::string> args = {
        "route", "del", network + "/" + std::to_string(prefix_len), "dev", name_
    };
    
    int ret = execute_ip_command(args);
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to delete route {}/{}", network, prefix_len);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    LOG_INFO("TunDevice: Deleted route {}/{}", network, prefix_len);
    return {};
}

void TunDevice::set_packet_callback(PacketCallback cb) {
    packet_callback_ = std::move(cb);
}

void TunDevice::start_reading() {
    if (!stream_ || reading_) {
        return;
    }
    
    reading_ = true;
    do_read();
    
    LOG_DEBUG("TunDevice: Started reading from {}", name_);
}

void TunDevice::stop_reading() {
    reading_ = false;
    
    if (stream_) {
        boost::system::error_code ec;
        stream_->cancel(ec);
    }
}

void TunDevice::do_read() {
    if (!reading_ || !stream_) {
        return;
    }
    
    stream_->async_read_some(
        boost::asio::buffer(read_buffer_),
        [this](boost::system::error_code ec, std::size_t bytes_transferred) {
            if (ec) {
                if (ec != boost::asio::error::operation_aborted) {
                    LOG_ERROR("TunDevice: Read error: {}", ec.message());
                }
                return;
            }
            
            if (bytes_transferred > 0 && packet_callback_) {
                std::vector<uint8_t> packet(read_buffer_.begin(), 
                                           read_buffer_.begin() + bytes_transferred);
                packet_callback_(packet);
            }
            
            // Continue reading
            if (reading_) {
                do_read();
            }
        }
    );
}

std::expected<void, ErrorCode> TunDevice::write_packet(const std::vector<uint8_t>& packet) {
    if (!stream_) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }
    
    boost::system::error_code ec;
    boost::asio::write(*stream_, boost::asio::buffer(packet), ec);
    
    if (ec) {
        LOG_ERROR("TunDevice: Write error: {}", ec.message());
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    
    return {};
}

int TunDevice::execute_ip_command(const std::vector<std::string>& args) {
    // Build command
    std::string cmd = "ip";
    for (const auto& arg : args) {
        cmd += " " + arg;
    }
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    return std::system(cmd.c_str());
}

// ============================================================================
// IPv4Header Implementation
// ============================================================================

std::expected<IPv4Header, ErrorCode> IPv4Header::parse(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) {
        return std::unexpected(ErrorCode::INVALID_FRAME);
    }
    
    IPv4Header header;
    header.version_ihl = packet[0];
    
    // Check version
    if (header.version() != 4) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    
    // Check header length
    if (header.header_length() < 20 || header.header_length() > packet.size()) {
        return std::unexpected(ErrorCode::INVALID_FRAME);
    }
    
    header.tos = packet[1];
    header.total_length = (static_cast<uint16_t>(packet[2]) << 8) | packet[3];
    header.identification = (static_cast<uint16_t>(packet[4]) << 8) | packet[5];
    header.flags_fragment = (static_cast<uint16_t>(packet[6]) << 8) | packet[7];
    header.ttl = packet[8];
    header.protocol = packet[9];
    header.checksum = (static_cast<uint16_t>(packet[10]) << 8) | packet[11];
    
    std::memcpy(&header.src_addr, &packet[12], 4);
    std::memcpy(&header.dst_addr, &packet[16], 4);
    
    return header;
}

std::string IPv4Header::src_ip_string() const {
    struct in_addr addr;
    addr.s_addr = src_addr;
    return inet_ntoa(addr);
}

std::string IPv4Header::dst_ip_string() const {
    struct in_addr addr;
    addr.s_addr = dst_addr;
    return inet_ntoa(addr);
}

} // namespace edgelink::client

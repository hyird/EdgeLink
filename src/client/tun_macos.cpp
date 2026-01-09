#include "client/tun_device.hpp"
#include "common/log.hpp"

#ifdef __APPLE__

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include "common/platform_net.hpp"
#include <ifaddrs.h>
#include <cstring>
#include <array>

namespace edgelink::client {

// ============================================================================
// TunDevice Implementation (macOS utun)
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

    // Create utun socket
    fd_ = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd_ < 0) {
        LOG_ERROR("TunDevice: Failed to create socket: {}", strerror(errno));
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    // Get control ID for utun
    struct ctl_info ctlInfo{};
    strncpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name) - 1);
    
    if (ioctl(fd_, CTLIOCGINFO, &ctlInfo) < 0) {
        LOG_ERROR("TunDevice: Failed to get control info: {}", strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    // Try to find an available utun unit
    struct sockaddr_ctl sc{};
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ctlInfo.ctl_id;
    
    // Start from utun0 and try to find available one
    for (int unit = 0; unit < 256; unit++) {
        sc.sc_unit = unit + 1;  // utun units are 1-based
        
        if (connect(fd_, (struct sockaddr*)&sc, sizeof(sc)) == 0) {
            // Success! Get the actual interface name
            char ifname[IFNAMSIZ];
            socklen_t ifname_len = sizeof(ifname);
            if (getsockopt(fd_, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) == 0) {
                name_ = ifname;
            } else {
                name_ = "utun" + std::to_string(unit);
            }
            break;
        }
        
        if (unit == 255) {
            LOG_ERROR("TunDevice: No available utun units");
            ::close(fd_);
            fd_ = -1;
            return std::unexpected(ErrorCode::UNKNOWN);
        }
    }

    // Set non-blocking
    int flags = fcntl(fd_, F_GETFL, 0);
    if (flags < 0 || fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERROR("TunDevice: Failed to set non-blocking mode: {}", strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return std::unexpected(ErrorCode::UNKNOWN);
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
        fd_ = -1;
    }

    LOG_INFO("TunDevice: Closed interface {}", name_);
}

std::expected<void, ErrorCode> TunDevice::set_address(const std::string& ip, uint8_t prefix_len) {
    // Use ifconfig on macOS
    std::string cmd = "ifconfig " + name_ + " " + ip + "/" + std::to_string(prefix_len) + " " + ip;
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    int ret = std::system(cmd.c_str());
    
    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to set address {} on {}", ip, name_);
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    LOG_INFO("TunDevice: Set address {}/{} on {}", ip, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::set_mtu(uint16_t mtu) {
    mtu_ = mtu;

    std::string cmd = "ifconfig " + name_ + " mtu " + std::to_string(mtu);
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to set MTU {} on {}", mtu, name_);
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    LOG_INFO("TunDevice: Set MTU {} on {}", mtu, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_up() {
    std::string cmd = "ifconfig " + name_ + " up";
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to bring up {}", name_);
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    LOG_INFO("TunDevice: Interface {} is up", name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_down() {
    std::string cmd = "ifconfig " + name_ + " down";
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to bring down {}", name_);
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    LOG_INFO("TunDevice: Interface {} is down", name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::add_route(const std::string& network, uint8_t prefix_len) {
    std::string cmd = "route -n add -net " + network + "/" + std::to_string(prefix_len) + " -interface " + name_;
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to add route {}/{} via {}", network, prefix_len, name_);
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    LOG_INFO("TunDevice: Added route {}/{} via {}", network, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::del_route(const std::string& network, uint8_t prefix_len) {
    std::string cmd = "route -n delete -net " + network + "/" + std::to_string(prefix_len) + " -interface " + name_;
    
    LOG_DEBUG("TunDevice: Executing: {}", cmd);
    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        LOG_ERROR("TunDevice: Failed to delete route {}/{}", network, prefix_len);
        return std::unexpected(ErrorCode::UNKNOWN);
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

            // macOS utun prepends a 4-byte header (AF_INET/AF_INET6)
            if (bytes_transferred > 4 && packet_callback_) {
                // Skip the 4-byte protocol header
                std::vector<uint8_t> packet(read_buffer_.begin() + 4,
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

    // Prepend 4-byte header for utun
    std::vector<uint8_t> frame(4 + packet.size());
    
    // Determine protocol family from IP version
    if (!packet.empty()) {
        uint8_t version = (packet[0] >> 4) & 0x0F;
        if (version == 4) {
            frame[3] = AF_INET;
        } else if (version == 6) {
            frame[3] = AF_INET6;
        }
    }
    
    std::copy(packet.begin(), packet.end(), frame.begin() + 4);

    boost::system::error_code ec;
    boost::asio::write(*stream_, boost::asio::buffer(frame), ec);

    if (ec) {
        LOG_ERROR("TunDevice: Write error: {}", ec.message());
        return std::unexpected(ErrorCode::UNKNOWN);
    }

    return {};
}

int TunDevice::execute_ip_command(const std::vector<std::string>& args) {
    // Not used on macOS (we use ifconfig/route directly)
    return 0;
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

#endif // __APPLE__

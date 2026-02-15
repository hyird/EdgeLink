// TUN device implementation for Linux
// Uses /dev/net/tun interface

#include "client/tun_device.hpp"
#include "common/logger.hpp"
#include "common/cobalt_utils.hpp"

namespace cobalt = boost::cobalt;

#ifdef __linux__

namespace {
auto& log() { return edgelink::Logger::get("client.tun"); }
}

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <thread>

namespace edgelink::client {

std::string tun_error_message(TunError error) {
    switch (error) {
        case TunError::OPEN_FAILED: return "Failed to open TUN device";
        case TunError::CONFIGURE_FAILED: return "Failed to configure TUN device";
        case TunError::READ_FAILED: return "Failed to read from TUN device";
        case TunError::WRITE_FAILED: return "Failed to write to TUN device";
        case TunError::NOT_SUPPORTED: return "TUN not supported on this platform";
        default: return "Unknown TUN error";
    }
}

class LinuxTunDevice : public TunDevice {
public:
    explicit LinuxTunDevice(asio::io_context& ioc)
        : ioc_(ioc)
        , stream_(ioc) {}

    ~LinuxTunDevice() override {
        close();
    }

    std::expected<void, TunError> open(const std::string& name) override {
        // Open /dev/net/tun
        int fd = ::open("/dev/net/tun", O_RDWR);
        if (fd < 0) {
            log().error("Cannot open /dev/net/tun: {}", strerror(errno));
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Configure the TUN device
        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info

        if (!name.empty() && name.length() < IFNAMSIZ) {
            strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        }

        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            log().error("ioctl TUNSETIFF failed: {}", strerror(errno));
            ::close(fd);
            return std::unexpected(TunError::OPEN_FAILED);
        }

        name_ = ifr.ifr_name;
        fd_ = fd;

        // Set non-blocking
        int flags = fcntl(fd_, F_GETFL, 0);
        fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

        // Assign to ASIO stream
        stream_.assign(fd_);

        log().info("TUN device opened: {}", name_);
        return {};
    }

    std::expected<void, TunError> configure(
        const IPv4Address& ip,
        const IPv4Address& netmask,
        uint32_t mtu) override {

        if (fd_ < 0) {
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        struct ifreq ifr{};
        strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

        // Set IP address
        auto* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = htonl(ip.to_u32());

        if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
            log().error("Failed to set IP address: {}", strerror(errno));
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        // Set netmask
        addr->sin_addr.s_addr = htonl(netmask.to_u32());
        if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
            log().error("Failed to set netmask: {}", strerror(errno));
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        // Set MTU
        ifr.ifr_mtu = static_cast<int>(mtu);
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            log().error("Failed to set MTU: {}", strerror(errno));
            // Non-fatal, continue
        }

        // Bring interface up
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            log().error("Failed to bring interface up: {}", strerror(errno));
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        ::close(sock);

        ip_ = ip;
        netmask_ = netmask;
        mtu_ = mtu;

        log().info("TUN {} configured: {}/{} MTU={}", name_, ip.to_string(),
                     netmask.to_string(), mtu);
        return {};
    }

    void close() override {
        stop_read();

        if (stream_.is_open()) {
            boost::system::error_code ec;
            stream_.close(ec);
        }

        if (fd_ >= 0) {
            // Bring interface down
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock >= 0) {
                struct ifreq ifr{};
                strncpy(ifr.ifr_name, name_.c_str(), IFNAMSIZ - 1);
                if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
                    ioctl(sock, SIOCSIFFLAGS, &ifr);
                }
                ::close(sock);
            }

            fd_ = -1;
            log().info("TUN device {} closed", name_);
        }
    }

    bool is_open() const override {
        return fd_ >= 0 && stream_.is_open();
    }

    std::string name() const override {
        return name_;
    }

    void set_packet_channel(channels::TunPacketChannel* channel) override {
        packet_channel_ = channel;
    }

    void start_read() override {
        if (!is_open() || reading_) return;

        reading_ = true;
        do_read();
    }

    void stop_read() override {
        reading_ = false;
    }

    std::expected<void, TunError> write(std::span<const uint8_t> packet) override {
        if (!is_open()) {
            log().warn("TUN write failed: device not open");
            return std::unexpected(TunError::WRITE_FAILED);
        }

        boost::system::error_code ec;
        size_t bytes_written = asio::write(stream_, asio::buffer(packet.data(), packet.size()), ec);

        if (ec) {
            log().warn("TUN write error: {} (wrote {} of {} bytes)", ec.message(), bytes_written, packet.size());
            return std::unexpected(TunError::WRITE_FAILED);
        }

        if (bytes_written != packet.size()) {
            log().warn("TUN write incomplete: {} of {} bytes", bytes_written, packet.size());
            return std::unexpected(TunError::WRITE_FAILED);
        }

        log().trace("TUN write: {} bytes to fd {}", bytes_written, fd_);
        return {};
    }

    cobalt::task<std::expected<void, TunError>> async_write(
        std::span<const uint8_t> packet) override {

        if (!is_open()) {
            co_return std::unexpected(TunError::WRITE_FAILED);
        }

        try {
            co_await asio::async_write(stream_,
                asio::buffer(packet.data(), packet.size()),
                cobalt::use_op);
            co_return std::expected<void, TunError>{};
        } catch (const boost::system::system_error& e) {
            log().debug("TUN async write error: {}", e.what());
            co_return std::unexpected(TunError::WRITE_FAILED);
        }
    }

private:
    void do_read() {
        if (!reading_ || !is_open()) return;

        // 使用 shared_from_this 保证 LinuxTunDevice 在回调时仍存活
        auto self = shared_from_this();
        stream_.async_read_some(
            asio::buffer(read_buffer_),
            [self](const boost::system::error_code& ec, size_t bytes) {
                auto* linux_tun = static_cast<LinuxTunDevice*>(self.get());

                // 防御性检查：如果 reading_ 为 false，说明正在关闭，直接返回
                if (!linux_tun->reading_) return;

                if (ec) {
                    if (ec != asio::error::operation_aborted) {
                        log().debug("TUN read error: {}", ec.message());
                    }
                    return;
                }

                if (bytes > 0 && linux_tun->packet_channel_ && linux_tun->reading_) {
                    // 复制数据到 vector 并通过 channel 发送
                    std::vector<uint8_t> packet(linux_tun->read_buffer_.begin(),
                                                linux_tun->read_buffer_.begin() + bytes);
                    linux_tun->packet_channel_->try_send(boost::system::error_code{}, std::move(packet));
                }

                // Continue reading (双重检查避免析构时继续读取)
                if (linux_tun->reading_ && linux_tun->is_open()) {
                    linux_tun->do_read();
                }
            });
    }

    asio::io_context& ioc_;
    asio::posix::stream_descriptor stream_;
    int fd_ = -1;
    std::string name_;
    IPv4Address ip_;
    IPv4Address netmask_;
    uint32_t mtu_ = 1420;

    bool reading_ = false;
    channels::TunPacketChannel* packet_channel_ = nullptr;
    std::array<uint8_t, 65536> read_buffer_;
};

std::shared_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_shared<LinuxTunDevice>(ioc);
}

} // namespace edgelink::client

#else
// Not Linux - provide stub

namespace edgelink::client {

std::string tun_error_message(TunError error) {
    switch (error) {
        case TunError::OPEN_FAILED: return "Failed to open TUN device";
        case TunError::CONFIGURE_FAILED: return "Failed to configure TUN device";
        case TunError::READ_FAILED: return "Failed to read from TUN device";
        case TunError::WRITE_FAILED: return "Failed to write to TUN device";
        case TunError::NOT_SUPPORTED: return "TUN not supported on this platform";
        default: return "Unknown TUN error";
    }
}

class StubTunDevice : public TunDevice {
public:
    explicit StubTunDevice(asio::io_context&) {}

    std::expected<void, TunError> open(const std::string&) override {
        return std::unexpected(TunError::NOT_SUPPORTED);
    }

    std::expected<void, TunError> configure(const IPv4Address&, const IPv4Address&, uint32_t) override {
        return std::unexpected(TunError::NOT_SUPPORTED);
    }

    void close() override {}
    bool is_open() const override { return false; }
    std::string name() const override { return ""; }
    void set_packet_channel(channels::TunPacketChannel*) override {}
    void start_read() override {}
    void stop_read() override {}

    std::expected<void, TunError> write(std::span<const uint8_t>) override {
        return std::unexpected(TunError::NOT_SUPPORTED);
    }

    cobalt::task<std::expected<void, TunError>> async_write(std::span<const uint8_t>) override {
        co_return std::unexpected(TunError::NOT_SUPPORTED);
    }
};

std::shared_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_shared<StubTunDevice>(ioc);
}

} // namespace edgelink::client

#endif // __linux__

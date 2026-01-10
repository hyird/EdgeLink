// TUN device implementation for Linux
// Uses /dev/net/tun interface

#include "client/tun_device.hpp"
#include <spdlog/spdlog.h>

#ifdef __linux__

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
            spdlog::error("Cannot open /dev/net/tun: {}", strerror(errno));
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Configure the TUN device
        struct ifreq ifr{};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info

        if (!name.empty() && name.length() < IFNAMSIZ) {
            strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        }

        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            spdlog::error("ioctl TUNSETIFF failed: {}", strerror(errno));
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

        spdlog::info("TUN device opened: {}", name_);
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
            spdlog::error("Failed to set IP address: {}", strerror(errno));
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        // Set netmask
        addr->sin_addr.s_addr = htonl(netmask.to_u32());
        if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
            spdlog::error("Failed to set netmask: {}", strerror(errno));
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        // Set MTU
        ifr.ifr_mtu = static_cast<int>(mtu);
        if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
            spdlog::error("Failed to set MTU: {}", strerror(errno));
            // Non-fatal, continue
        }

        // Bring interface up
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            spdlog::error("Failed to bring interface up: {}", strerror(errno));
            ::close(sock);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        ::close(sock);

        ip_ = ip;
        netmask_ = netmask;
        mtu_ = mtu;

        spdlog::info("TUN {} configured: {}/{} MTU={}", name_, ip.to_string(),
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
            spdlog::info("TUN device {} closed", name_);
        }
    }

    bool is_open() const override {
        return fd_ >= 0 && stream_.is_open();
    }

    std::string name() const override {
        return name_;
    }

    void start_read(PacketCallback callback) override {
        if (!is_open() || reading_) return;

        reading_ = true;
        callback_ = std::move(callback);

        do_read();
    }

    void stop_read() override {
        reading_ = false;
        callback_ = nullptr;
    }

    std::expected<void, TunError> write(std::span<const uint8_t> packet) override {
        if (!is_open()) {
            spdlog::warn("TUN write failed: device not open");
            return std::unexpected(TunError::WRITE_FAILED);
        }

        boost::system::error_code ec;
        size_t bytes_written = asio::write(stream_, asio::buffer(packet.data(), packet.size()), ec);

        if (ec) {
            spdlog::warn("TUN write error: {} (wrote {} of {} bytes)", ec.message(), bytes_written, packet.size());
            return std::unexpected(TunError::WRITE_FAILED);
        }

        if (bytes_written != packet.size()) {
            spdlog::warn("TUN write incomplete: {} of {} bytes", bytes_written, packet.size());
            return std::unexpected(TunError::WRITE_FAILED);
        }

        spdlog::trace("TUN write: {} bytes to fd {}", bytes_written, fd_);
        return {};
    }

    asio::awaitable<std::expected<void, TunError>> async_write(
        std::span<const uint8_t> packet) override {

        if (!is_open()) {
            co_return std::unexpected(TunError::WRITE_FAILED);
        }

        try {
            co_await asio::async_write(stream_,
                asio::buffer(packet.data(), packet.size()),
                asio::use_awaitable);
            co_return std::expected<void, TunError>{};
        } catch (const boost::system::system_error& e) {
            spdlog::debug("TUN async write error: {}", e.what());
            co_return std::unexpected(TunError::WRITE_FAILED);
        }
    }

private:
    void do_read() {
        if (!reading_ || !is_open()) return;

        stream_.async_read_some(
            asio::buffer(read_buffer_),
            [this](const boost::system::error_code& ec, size_t bytes) {
                if (ec) {
                    if (ec != asio::error::operation_aborted) {
                        spdlog::debug("TUN read error: {}", ec.message());
                    }
                    return;
                }

                if (bytes > 0 && callback_) {
                    callback_(std::span<const uint8_t>(read_buffer_.data(), bytes));
                }

                // Continue reading
                if (reading_) {
                    do_read();
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
    PacketCallback callback_;
    std::array<uint8_t, 65536> read_buffer_;
};

std::unique_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_unique<LinuxTunDevice>(ioc);
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
    void start_read(PacketCallback) override {}
    void stop_read() override {}

    std::expected<void, TunError> write(std::span<const uint8_t>) override {
        return std::unexpected(TunError::NOT_SUPPORTED);
    }

    asio::awaitable<std::expected<void, TunError>> async_write(std::span<const uint8_t>) override {
        co_return std::unexpected(TunError::NOT_SUPPORTED);
    }
};

std::unique_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_unique<StubTunDevice>(ioc);
}

} // namespace edgelink::client

#endif // __linux__

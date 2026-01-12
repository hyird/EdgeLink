// TUN device implementation for macOS
// Uses utun interface (to be implemented)

#include "client/tun_device.hpp"
#include "common/logger.hpp"

#ifdef __APPLE__

namespace {
auto& log() { return edgelink::Logger::get("client.tun"); }
}

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <unistd.h>
#include <cstring>

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

// macOS utun implementation (stub for now)
class MacOSTunDevice : public TunDevice {
public:
    explicit MacOSTunDevice(asio::io_context& ioc)
        : ioc_(ioc)
        , stream_(ioc) {}

    ~MacOSTunDevice() override {
        close();
    }

    std::expected<void, TunError> open(const std::string& name) override {
        // Create utun socket
        int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
        if (fd < 0) {
            log().error("Failed to create utun socket: {}", strerror(errno));
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Get control id
        struct ctl_info ci{};
        strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name) - 1);

        if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
            log().error("Failed to get utun control info: {}", strerror(errno));
            ::close(fd);
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Connect to utun
        struct sockaddr_ctl sc{};
        sc.sc_id = ci.ctl_id;
        sc.sc_len = sizeof(sc);
        sc.sc_family = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;

        // Try to get a specific unit number or use 0 for auto
        unsigned int unit = 0;
        if (!name.empty() && name.substr(0, 4) == "utun") {
            try {
                unit = std::stoul(name.substr(4));
            } catch (...) {
                // Use auto
            }
        }
        sc.sc_unit = unit + 1; // utun unit numbers are 1-indexed

        if (connect(fd, reinterpret_cast<struct sockaddr*>(&sc), sizeof(sc)) < 0) {
            log().error("Failed to connect utun: {}", strerror(errno));
            ::close(fd);
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Get the actual interface name
        char ifname[IFNAMSIZ];
        socklen_t ifname_len = sizeof(ifname);
        if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
            log().error("Failed to get utun interface name: {}", strerror(errno));
            ::close(fd);
            return std::unexpected(TunError::OPEN_FAILED);
        }

        name_ = ifname;
        fd_ = fd;

        // Assign to ASIO stream
        stream_.assign(fd_);

        log().info("macOS utun device opened: {}", name_);
        return {};
    }

    std::expected<void, TunError> configure(
        const IPv4Address& ip,
        const IPv4Address& netmask,
        uint32_t mtu) override {

        if (fd_ < 0) {
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        // Configure using ifconfig command
        std::string cmd = "/sbin/ifconfig " + name_ + " " +
                          ip.to_string() + " " + ip.to_string() +
                          " netmask " + netmask.to_string() +
                          " mtu " + std::to_string(mtu) + " up";

        int result = system(cmd.c_str());
        if (result != 0) {
            log().error("Failed to configure utun: ifconfig returned {}", result);
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        ip_ = ip;
        netmask_ = netmask;
        mtu_ = mtu;

        log().info("macOS utun {} configured: {}/{} MTU={}", name_, ip.to_string(),
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
            fd_ = -1;
            log().info("macOS utun device {} closed", name_);
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
            return std::unexpected(TunError::WRITE_FAILED);
        }

        // macOS utun requires a 4-byte protocol header
        std::vector<uint8_t> buf(4 + packet.size());
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 2; // AF_INET

        std::memcpy(buf.data() + 4, packet.data(), packet.size());

        boost::system::error_code ec;
        asio::write(stream_, asio::buffer(buf), ec);

        if (ec) {
            log().debug("utun write error: {}", ec.message());
            return std::unexpected(TunError::WRITE_FAILED);
        }

        return {};
    }

    asio::awaitable<std::expected<void, TunError>> async_write(
        std::span<const uint8_t> packet) override {

        if (!is_open()) {
            co_return std::unexpected(TunError::WRITE_FAILED);
        }

        try {
            // macOS utun requires a 4-byte protocol header
            std::vector<uint8_t> buf(4 + packet.size());
            buf[0] = 0;
            buf[1] = 0;
            buf[2] = 0;
            buf[3] = 2; // AF_INET

            std::memcpy(buf.data() + 4, packet.data(), packet.size());

            co_await asio::async_write(stream_,
                asio::buffer(buf),
                asio::use_awaitable);
            co_return std::expected<void, TunError>{};
        } catch (const boost::system::system_error& e) {
            log().debug("utun async write error: {}", e.what());
            co_return std::unexpected(TunError::WRITE_FAILED);
        }
    }

private:
    void do_read() {
        if (!reading_ || !is_open()) return;

        // 使用 shared_from_this 保证 MacOSTunDevice 在回调时仍存活
        auto self = shared_from_this();
        stream_.async_read_some(
            asio::buffer(read_buffer_),
            [self](const boost::system::error_code& ec, size_t bytes) {
                auto* macos_tun = static_cast<MacOSTunDevice*>(self.get());

                // 防御性检查：如果 reading_ 为 false，说明正在关闭，直接返回
                if (!macos_tun->reading_) return;

                if (ec) {
                    if (ec != asio::error::operation_aborted) {
                        log().debug("utun read error: {}", ec.message());
                    }
                    return;
                }

                // Skip the 4-byte protocol header
                if (bytes > 4 && macos_tun->callback_ && macos_tun->reading_) {
                    macos_tun->callback_(std::span<const uint8_t>(macos_tun->read_buffer_.data() + 4, bytes - 4));
                }

                // Continue reading (双重检查避免析构时继续读取)
                if (macos_tun->reading_ && macos_tun->is_open()) {
                    macos_tun->do_read();
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

std::shared_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_shared<MacOSTunDevice>(ioc);
}

} // namespace edgelink::client

#else
// Not macOS - provide stub

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

std::shared_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_shared<StubTunDevice>(ioc);
}

} // namespace edgelink::client

#endif // __APPLE__

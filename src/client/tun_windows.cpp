// TUN device implementation for Windows
// Uses WinTun driver (https://www.wintun.net/)

#include "client/tun_device.hpp"
#include "common/logger.hpp"

#ifdef _WIN32

namespace {
auto& log() { return edgelink::Logger::get("client.tun"); }
}

#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <thread>
#include <atomic>

// WinTun types and function pointers
typedef void* WINTUN_ADAPTER_HANDLE;
typedef void* WINTUN_SESSION_HANDLE;
typedef GUID WINTUN_ADAPTER_LUID;

typedef WINTUN_ADAPTER_HANDLE (WINAPI *WINTUN_CREATE_ADAPTER_FUNC)(
    const WCHAR* Name, const WCHAR* TunnelType, const GUID* RequestedGUID);
typedef void (WINAPI *WINTUN_CLOSE_ADAPTER_FUNC)(WINTUN_ADAPTER_HANDLE Adapter);
typedef WINTUN_SESSION_HANDLE (WINAPI *WINTUN_START_SESSION_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
typedef void (WINAPI *WINTUN_END_SESSION_FUNC)(WINTUN_SESSION_HANDLE Session);
typedef BYTE* (WINAPI *WINTUN_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, DWORD* PacketSize);
typedef void (WINAPI *WINTUN_RELEASE_RECEIVE_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, const BYTE* Packet);
typedef BYTE* (WINAPI *WINTUN_ALLOCATE_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
typedef void (WINAPI *WINTUN_SEND_PACKET_FUNC)(
    WINTUN_SESSION_HANDLE Session, const BYTE* Packet);
typedef HANDLE (WINAPI *WINTUN_GET_READ_WAIT_EVENT_FUNC)(
    WINTUN_SESSION_HANDLE Session);
typedef void (WINAPI *WINTUN_GET_ADAPTER_LUID_FUNC)(
    WINTUN_ADAPTER_HANDLE Adapter, NET_LUID* Luid);

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

class WinTunDevice : public TunDevice {
public:
    explicit WinTunDevice(asio::io_context& ioc)
        : ioc_(ioc) {}

    ~WinTunDevice() override {
        close();
        if (wintun_dll_) {
            FreeLibrary(wintun_dll_);
        }
    }

    std::expected<void, TunError> open(const std::string& name) override {
        // Load WinTun DLL
        if (!load_wintun()) {
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Generate adapter name
        std::wstring wname;
        if (name.empty()) {
            wname = L"EdgeLink";
        } else {
            wname = std::wstring(name.begin(), name.end());
        }
        name_ = name.empty() ? "EdgeLink" : name;

        // Create adapter
        GUID guid = {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};
        adapter_ = wintun_create_adapter_(wname.c_str(), L"EdgeLink", &guid);

        if (!adapter_) {
            log().error("Failed to create WinTun adapter: {}", GetLastError());
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Get adapter LUID
        wintun_get_adapter_luid_(adapter_, &luid_);

        // Start session with 4MB ring buffer
        session_ = wintun_start_session_(adapter_, 0x400000);
        if (!session_) {
            log().error("Failed to start WinTun session: {}", GetLastError());
            wintun_close_adapter_(adapter_);
            adapter_ = nullptr;
            return std::unexpected(TunError::OPEN_FAILED);
        }

        // Get read event
        read_event_ = wintun_get_read_wait_event_(session_);

        log().info("WinTun adapter opened: {}", name_);
        return {};
    }

    std::expected<void, TunError> configure(
        const IPv4Address& ip,
        const IPv4Address& netmask,
        uint32_t mtu) override {

        if (!adapter_) {
            return std::unexpected(TunError::CONFIGURE_FAILED);
        }

        // Calculate prefix length from netmask
        uint32_t mask = netmask.to_u32();
        int prefix_len = 0;
        while (mask) {
            prefix_len += (mask & 1);
            mask >>= 1;
        }

        // Add IP address using netsh (simpler than using IP Helper API)
        std::string cmd = "netsh interface ip set address \"" + name_ +
                          "\" static " + ip.to_string() + " " + netmask.to_string();

        int result = system(cmd.c_str());
        if (result != 0) {
            log().warn("netsh command returned {}", result);
        }

        // Set MTU
        MIB_IPINTERFACE_ROW iface{};
        iface.Family = AF_INET;
        iface.InterfaceLuid = luid_;

        if (GetIpInterfaceEntry(&iface) == NO_ERROR) {
            iface.NlMtu = mtu;
            SetIpInterfaceEntry(&iface);
        }

        ip_ = ip;
        netmask_ = netmask;
        mtu_ = mtu;

        log().info("WinTun {} configured: {}/{} MTU={}", name_, ip.to_string(),
                     netmask.to_string(), mtu);
        return {};
    }

    void close() override {
        stop_read();

        if (session_) {
            wintun_end_session_(session_);
            session_ = nullptr;
        }

        if (adapter_) {
            wintun_close_adapter_(adapter_);
            adapter_ = nullptr;
        }

        read_event_ = nullptr;
        log().info("WinTun adapter closed");
    }

    bool is_open() const override {
        return session_ != nullptr;
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

        // Start read thread
        read_thread_ = std::thread([this]() {
            read_loop();
        });
    }

    void stop_read() override {
        reading_ = false;

        if (read_thread_.joinable()) {
            // Signal the event to wake up the thread
            if (read_event_) {
                SetEvent(read_event_);
            }
            read_thread_.join();
        }
    }

    std::expected<void, TunError> write(std::span<const uint8_t> packet) override {
        if (!is_open()) {
            return std::unexpected(TunError::WRITE_FAILED);
        }

        BYTE* buf = wintun_allocate_send_packet_(session_, static_cast<DWORD>(packet.size()));
        if (!buf) {
            return std::unexpected(TunError::WRITE_FAILED);
        }

        memcpy(buf, packet.data(), packet.size());
        wintun_send_packet_(session_, buf);

        return {};
    }

    asio::awaitable<std::expected<void, TunError>> async_write(
        std::span<const uint8_t> packet) override {

        // WinTun write is synchronous, wrap in post
        co_await asio::post(ioc_, asio::use_awaitable);
        co_return write(packet);
    }

private:
    bool load_wintun() {
        // Try to load wintun.dll from current directory first
        wintun_dll_ = LoadLibraryA("wintun.dll");
        if (!wintun_dll_) {
            // Try system directory
            wintun_dll_ = LoadLibraryA("C:\\Windows\\System32\\wintun.dll");
        }

        if (!wintun_dll_) {
            log().error("Failed to load wintun.dll. Please download from https://www.wintun.net/");
            return false;
        }

        // Load function pointers
        wintun_create_adapter_ = (WINTUN_CREATE_ADAPTER_FUNC)
            GetProcAddress(wintun_dll_, "WintunCreateAdapter");
        wintun_close_adapter_ = (WINTUN_CLOSE_ADAPTER_FUNC)
            GetProcAddress(wintun_dll_, "WintunCloseAdapter");
        wintun_start_session_ = (WINTUN_START_SESSION_FUNC)
            GetProcAddress(wintun_dll_, "WintunStartSession");
        wintun_end_session_ = (WINTUN_END_SESSION_FUNC)
            GetProcAddress(wintun_dll_, "WintunEndSession");
        wintun_receive_packet_ = (WINTUN_RECEIVE_PACKET_FUNC)
            GetProcAddress(wintun_dll_, "WintunReceivePacket");
        wintun_release_receive_packet_ = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)
            GetProcAddress(wintun_dll_, "WintunReleaseReceivePacket");
        wintun_allocate_send_packet_ = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)
            GetProcAddress(wintun_dll_, "WintunAllocateSendPacket");
        wintun_send_packet_ = (WINTUN_SEND_PACKET_FUNC)
            GetProcAddress(wintun_dll_, "WintunSendPacket");
        wintun_get_read_wait_event_ = (WINTUN_GET_READ_WAIT_EVENT_FUNC)
            GetProcAddress(wintun_dll_, "WintunGetReadWaitEvent");
        wintun_get_adapter_luid_ = (WINTUN_GET_ADAPTER_LUID_FUNC)
            GetProcAddress(wintun_dll_, "WintunGetAdapterLUID");

        if (!wintun_create_adapter_ || !wintun_close_adapter_ ||
            !wintun_start_session_ || !wintun_end_session_ ||
            !wintun_receive_packet_ || !wintun_release_receive_packet_ ||
            !wintun_allocate_send_packet_ || !wintun_send_packet_ ||
            !wintun_get_read_wait_event_ || !wintun_get_adapter_luid_) {
            log().error("Failed to load WinTun functions");
            FreeLibrary(wintun_dll_);
            wintun_dll_ = nullptr;
            return false;
        }

        log().debug("WinTun library loaded successfully");
        return true;
    }

    void read_loop() {
        while (reading_ && session_) {
            DWORD result = WaitForSingleObject(read_event_, 1000);

            if (!reading_) break;

            if (result == WAIT_OBJECT_0) {
                // Packets available
                while (reading_) {
                    DWORD packet_size = 0;
                    BYTE* packet = wintun_receive_packet_(session_, &packet_size);

                    if (!packet) break;

                    if (packet_channel_ && packet_size > 0) {
                        // Post to IO context and send via channel
                        std::vector<uint8_t> data(packet, packet + packet_size);
                        asio::post(ioc_, [this, data = std::move(data)]() {
                            if (packet_channel_) {
                                packet_channel_->try_send(boost::system::error_code{}, std::move(const_cast<std::vector<uint8_t>&>(data)));
                            }
                        });
                    }

                    wintun_release_receive_packet_(session_, packet);
                }
            }
        }
    }

    asio::io_context& ioc_;
    HMODULE wintun_dll_ = nullptr;
    WINTUN_ADAPTER_HANDLE adapter_ = nullptr;
    WINTUN_SESSION_HANDLE session_ = nullptr;
    HANDLE read_event_ = nullptr;
    NET_LUID luid_{};
    std::string name_;
    IPv4Address ip_;
    IPv4Address netmask_;
    uint32_t mtu_ = 1420;

    std::atomic<bool> reading_{false};
    std::thread read_thread_;
    channels::TunPacketChannel* packet_channel_ = nullptr;

    // WinTun function pointers
    WINTUN_CREATE_ADAPTER_FUNC wintun_create_adapter_ = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC wintun_close_adapter_ = nullptr;
    WINTUN_START_SESSION_FUNC wintun_start_session_ = nullptr;
    WINTUN_END_SESSION_FUNC wintun_end_session_ = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC wintun_receive_packet_ = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC wintun_release_receive_packet_ = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC wintun_allocate_send_packet_ = nullptr;
    WINTUN_SEND_PACKET_FUNC wintun_send_packet_ = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC wintun_get_read_wait_event_ = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC wintun_get_adapter_luid_ = nullptr;
};

std::unique_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return std::make_unique<WinTunDevice>(ioc);
}

} // namespace edgelink::client

#else
// Not Windows - this file shouldn't be compiled

namespace edgelink::client {

std::unique_ptr<TunDevice> TunDevice::create(asio::io_context& ioc) {
    return nullptr;
}

} // namespace edgelink::client

#endif // _WIN32

#include "client/tun_device.hpp"
#include "common/log.hpp"

#ifdef _WIN32

#include "wintun/wintun_static.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string>
#include <algorithm>
#include <codecvt>
#include <locale>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// No longer need function pointer typedefs - using static library directly

namespace edgelink::client {

// Wintun static library wrapper
class WintunInterface {
public:
    static WintunInterface& instance() {
        static WintunInterface inst;
        return inst;
    }

    bool is_loaded() const { return initialized_; }

private:
    bool initialized_ = false;

    WintunInterface() {
        // Initialize static wintun library
        if (WintunInitialize()) {
            initialized_ = true;
            LOG_INFO("WintunInterface: Initialized (static)");
        } else {
            LOG_ERROR("WintunInterface: Failed to initialize - error {}", GetLastError());
        }
    }

    ~WintunInterface() {
        if (initialized_) {
            WintunShutdown();
        }
    }
};

// Platform-specific implementation data
struct TunDevice::PlatformData {
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    HANDLE read_event = nullptr;
    NET_LUID adapter_luid{};
    NET_IFINDEX if_index = 0;
    std::wstring adapter_name;
};

// String conversion helper
static std::wstring utf8_to_wide(const std::string& str) {
    if (str.empty()) return {};
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], size_needed);
    return result;
}

// Generate a deterministic GUID from name
static GUID name_to_guid(const std::string& name) {
    GUID guid{};
    // Simple hash-based GUID generation
    uint32_t hash = 0;
    for (char c : name) {
        hash = hash * 31 + c;
    }
    guid.Data1 = hash;
    guid.Data2 = static_cast<uint16_t>(hash >> 16);
    guid.Data3 = static_cast<uint16_t>(hash >> 8);
    guid.Data4[0] = 'E';
    guid.Data4[1] = 'L';
    guid.Data4[2] = 'I';
    guid.Data4[3] = 'N';
    guid.Data4[4] = 'K';
    guid.Data4[5] = '0';
    guid.Data4[6] = '0';
    guid.Data4[7] = '1';
    return guid;
}

TunDevice::TunDevice(boost::asio::io_context& ioc, const std::string& name)
    : ioc_(ioc)
    , name_(name)
    , platform_(std::make_unique<PlatformData>())
{
    read_buffer_.resize(NetworkConstants::MAX_PACKET_SIZE);
    platform_->adapter_name = utf8_to_wide(name);
}

TunDevice::~TunDevice() {
    close();
}

std::expected<void, ErrorCode> TunDevice::open() {
    auto& wintun = WintunInterface::instance();
    if (!wintun.is_loaded()) {
        LOG_ERROR("TunDevice: Wintun not available");
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    if (platform_->adapter) {
        return {};  // Already open
    }

    // Create adapter
    GUID guid = name_to_guid(name_);
    platform_->adapter = WintunCreateAdapter(
        platform_->adapter_name.c_str(),
        L"EdgeLink",
        &guid
    );

    if (!platform_->adapter) {
        LOG_ERROR("TunDevice: Failed to create adapter");
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    // Get adapter LUID
    WintunGetAdapterLUID(platform_->adapter, &platform_->adapter_luid);

    // Get interface index
    if (ConvertInterfaceLuidToIndex(&platform_->adapter_luid, &platform_->if_index) != NO_ERROR) {
        LOG_ERROR("TunDevice: Failed to get interface index");
        WintunCloseAdapter(platform_->adapter);
        platform_->adapter = nullptr;
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    // Start session (8MB ring buffer)
    platform_->session = WintunStartSession(platform_->adapter, 0x800000);
    if (!platform_->session) {
        LOG_ERROR("TunDevice: Failed to start session");
        WintunCloseAdapter(platform_->adapter);
        platform_->adapter = nullptr;
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    platform_->read_event = WintunGetReadWaitEvent(platform_->session);
    fd_ = 1;  // Marker for "open"

    LOG_INFO("TunDevice: Created interface {} (index {})", name_, platform_->if_index);
    return {};
}

void TunDevice::close() {
    stop_reading();

    // With static library, always safe to call if handles are valid
    if (platform_->session) {
        WintunEndSession(platform_->session);
        platform_->session = nullptr;
    }

    if (platform_->adapter) {
        WintunCloseAdapter(platform_->adapter);
        platform_->adapter = nullptr;
    }

    platform_->read_event = nullptr;
    fd_ = -1;

    LOG_INFO("TunDevice: Closed interface {}", name_);
}

std::expected<void, ErrorCode> TunDevice::set_address(const std::string& ip, uint8_t prefix_len) {
    if (!platform_->adapter) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }

    // Parse IP address
    IN_ADDR addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        LOG_ERROR("TunDevice: Invalid IP address: {}", ip);
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    // Create unicast address row
    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = platform_->adapter_luid;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr = addr;
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;

    DWORD result = CreateUnicastIpAddressEntry(&row);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERROR("TunDevice: Failed to set IP address: error {}", result);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    LOG_INFO("TunDevice: Set address {}/{} on {}", ip, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::set_mtu(uint16_t mtu) {
    mtu_ = mtu;

    if (!platform_->adapter) {
        return {};  // Will apply when opened
    }

    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.InterfaceLuid = platform_->adapter_luid;
    row.Family = AF_INET;

    if (GetIpInterfaceEntry(&row) == NO_ERROR) {
        row.NlMtu = mtu;
        if (SetIpInterfaceEntry(&row) == NO_ERROR) {
            LOG_INFO("TunDevice: Set MTU {} on {}", mtu, name_);
            return {};
        }
    }

    LOG_WARN("TunDevice: Could not set MTU (will use default)");
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_up() {
    // Interface is automatically up when session starts
    LOG_INFO("TunDevice: Interface {} is up", name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_down() {
    // Nothing to do on Windows
    LOG_INFO("TunDevice: Interface {} is down", name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::add_route(const std::string& network, uint8_t prefix_len) {
    if (!platform_->adapter) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }

    IN_ADDR dest_addr;
    if (inet_pton(AF_INET, network.c_str(), &dest_addr) != 1) {
        LOG_ERROR("TunDevice: Invalid network address: {}", network);
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    MIB_IPFORWARD_ROW2 route{};
    InitializeIpForwardEntry(&route);
    route.InterfaceLuid = platform_->adapter_luid;
    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.DestinationPrefix.Prefix.Ipv4.sin_addr = dest_addr;
    route.DestinationPrefix.PrefixLength = prefix_len;
    route.NextHop.si_family = AF_INET;
    route.NextHop.Ipv4.sin_addr.s_addr = 0;  // On-link
    route.Metric = 0;
    route.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD result = CreateIpForwardEntry2(&route);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
        LOG_ERROR("TunDevice: Failed to add route: error {}", result);
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    LOG_INFO("TunDevice: Added route {}/{} via {}", network, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::del_route(const std::string& network, uint8_t prefix_len) {
    if (!platform_->adapter) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }

    IN_ADDR dest_addr;
    if (inet_pton(AF_INET, network.c_str(), &dest_addr) != 1) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    MIB_IPFORWARD_ROW2 route{};
    InitializeIpForwardEntry(&route);
    route.InterfaceLuid = platform_->adapter_luid;
    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.DestinationPrefix.Prefix.Ipv4.sin_addr = dest_addr;
    route.DestinationPrefix.PrefixLength = prefix_len;
    route.NextHop.si_family = AF_INET;

    DeleteIpForwardEntry2(&route);

    LOG_INFO("TunDevice: Deleted route {}/{}", network, prefix_len);
    return {};
}

void TunDevice::set_packet_callback(PacketCallback cb) {
    packet_callback_ = std::move(cb);
}

void TunDevice::start_reading() {
    if (!platform_->session || reading_) {
        return;
    }

    reading_ = true;

    // Start async read loop using a thread + post pattern
    read_thread_ = std::thread([this]() {
        auto& wintun = WintunInterface::instance();
        
        while (reading_) {
            DWORD result = WaitForSingleObject(platform_->read_event, 100);
            
            if (!reading_) break;
            
            if (result == WAIT_OBJECT_0) {
                DWORD packet_size;
                while (BYTE* packet = WintunReceivePacket(platform_->session, &packet_size)) {
                    if (packet_size > 0 && packet_callback_) {
                        std::vector<uint8_t> data(packet, packet + packet_size);
                        
                        // Post callback to io_context
                        boost::asio::post(ioc_, [this, pkt = std::move(data)]() {
                            if (packet_callback_) {
                                packet_callback_(pkt);
                            }
                        });
                    }
                    WintunReleaseReceivePacket(platform_->session, packet);
                }
            }
        }
    });

    LOG_DEBUG("TunDevice: Started reading from {}", name_);
}

void TunDevice::stop_reading() {
    reading_ = false;
    
    if (read_thread_.joinable()) {
        read_thread_.join();
    }
}

std::expected<void, ErrorCode> TunDevice::write_packet(const std::vector<uint8_t>& packet) {
    if (!platform_->session) {
        return std::unexpected(ErrorCode::NOT_CONNECTED);
    }

    auto& wintun = WintunInterface::instance();
    
    BYTE* send_packet = WintunAllocateSendPacket(
        platform_->session, 
        static_cast<DWORD>(packet.size())
    );

    if (!send_packet) {
        LOG_ERROR("TunDevice: Failed to allocate send packet");
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    memcpy(send_packet, packet.data(), packet.size());
    WintunSendPacket(platform_->session, send_packet);

    return {};
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

    if (header.version() != 4) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

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

    memcpy(&header.src_addr, &packet[12], 4);
    memcpy(&header.dst_addr, &packet[16], 4);

    return header;
}

std::string IPv4Header::src_ip_string() const {
    char buf[INET_ADDRSTRLEN];
    IN_ADDR addr;
    addr.s_addr = src_addr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

std::string IPv4Header::dst_ip_string() const {
    char buf[INET_ADDRSTRLEN];
    IN_ADDR addr;
    addr.s_addr = dst_addr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

} // namespace edgelink::client

#endif // _WIN32

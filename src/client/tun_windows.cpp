#include "client/tun_device.hpp"
#include "common/log.hpp"

#ifdef _WIN32

#include "wintun/wintun.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// Resource ID for embedded wintun.dll (if embedded)
#define IDR_WINTUN_DLL 301

namespace edgelink::client {

// Wintun DLL loader - handles dynamic loading and optional resource extraction
class WintunInterface {
public:
    static WintunInterface& instance() {
        static WintunInterface inst;
        return inst;
    }

    bool is_loaded() const { return module_ != nullptr; }

    // Function pointers
    WINTUN_CREATE_ADAPTER_FUNC CreateAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC OpenAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC CloseAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC GetAdapterLUID = nullptr;
    WINTUN_START_SESSION_FUNC StartSession = nullptr;
    WINTUN_END_SESSION_FUNC EndSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC GetReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC ReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC ReleaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC AllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC SendPacket = nullptr;
    WINTUN_SET_LOGGER_FUNC SetLogger = nullptr;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC GetRunningDriverVersion = nullptr;

private:
    HMODULE module_ = nullptr;
    std::wstring extracted_dll_path_;

    WintunInterface() {
        // Try loading wintun.dll from standard locations
        module_ = LoadLibraryExW(L"wintun.dll", nullptr, 
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        
        if (!module_) {
            module_ = LoadLibraryW(L"wintun.dll");
        }

#ifdef EDGELINK_WINTUN_EMBEDDED
        if (!module_) {
            if (ExtractEmbeddedDll()) {
                module_ = LoadLibraryW(extracted_dll_path_.c_str());
            }
        }
#endif

        if (!module_) {
            LOG_ERROR("WintunInterface: Failed to load wintun.dll - error {}", GetLastError());
            LOG_ERROR("WintunInterface: Please install wintun.dll from https://www.wintun.net/");
            return;
        }

        bool success = true;
        
        #define LOAD_FUNC(name) \
            name = (WINTUN_##name##_FUNC)GetProcAddress(module_, "Wintun" #name); \
            if (!name) { LOG_ERROR("WintunInterface: Failed to load Wintun" #name); success = false; }

        LOAD_FUNC(CreateAdapter);
        LOAD_FUNC(OpenAdapter);
        LOAD_FUNC(CloseAdapter);
        LOAD_FUNC(GetAdapterLUID);
        LOAD_FUNC(StartSession);
        LOAD_FUNC(EndSession);
        LOAD_FUNC(GetReadWaitEvent);
        LOAD_FUNC(ReceivePacket);
        LOAD_FUNC(ReleaseReceivePacket);
        LOAD_FUNC(AllocateSendPacket);
        LOAD_FUNC(SendPacket);
        LOAD_FUNC(SetLogger);
        LOAD_FUNC(GetRunningDriverVersion);

        #undef LOAD_FUNC

        if (!success) {
            FreeLibrary(module_);
            module_ = nullptr;
            return;
        }

        LOG_INFO("WintunInterface: Loaded wintun.dll successfully");
        
        DWORD version = GetRunningDriverVersion();
        if (version) {
            LOG_INFO("WintunInterface: Driver version {}.{}", 
                     (version >> 16) & 0xFFFF, version & 0xFFFF);
        }
    }

    ~WintunInterface() {
        if (module_) {
            FreeLibrary(module_);
        }
        if (!extracted_dll_path_.empty()) {
            DeleteFileW(extracted_dll_path_.c_str());
        }
    }

#ifdef EDGELINK_WINTUN_EMBEDDED
    bool ExtractEmbeddedDll() {
        HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_WINTUN_DLL), RT_RCDATA);
        if (!hRes) return false;

        HGLOBAL hData = LoadResource(nullptr, hRes);
        if (!hData) return false;

        DWORD size = SizeofResource(nullptr, hRes);
        void* data = LockResource(hData);
        if (!data || size == 0) return false;

        WCHAR temp_path[MAX_PATH];
        if (GetTempPathW(MAX_PATH, temp_path) == 0) return false;

        WCHAR dll_path[MAX_PATH];
        swprintf_s(dll_path, L"%swintun_%lu.dll", temp_path, GetCurrentProcessId());

        HANDLE hFile = CreateFileW(dll_path, GENERIC_WRITE, 0, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD written;
        BOOL ok = WriteFile(hFile, data, size, &written, nullptr);
        CloseHandle(hFile);

        if (!ok || written != size) {
            DeleteFileW(dll_path);
            return false;
        }

        extracted_dll_path_ = dll_path;
        LOG_INFO("WintunInterface: Extracted embedded wintun.dll");
        return true;
    }
#endif
};

struct TunDevice::PlatformData {
    WINTUN_ADAPTER_HANDLE adapter = nullptr;
    WINTUN_SESSION_HANDLE session = nullptr;
    HANDLE read_event = nullptr;
    NET_LUID adapter_luid{};
    NET_IFINDEX if_index = 0;
    std::wstring adapter_name;
};

static std::wstring utf8_to_wide(const std::string& str) {
    if (str.empty()) return {};
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], size_needed);
    return result;
}

static GUID name_to_guid(const std::string& name) {
    GUID guid{};
    uint32_t hash = 0;
    for (char c : name) {
        hash = hash * 31 + c;
    }
    guid.Data1 = hash;
    guid.Data2 = static_cast<uint16_t>(hash >> 16);
    guid.Data3 = static_cast<uint16_t>(hash >> 8);
    guid.Data4[0] = 'E'; guid.Data4[1] = 'L'; guid.Data4[2] = 'I'; guid.Data4[3] = 'N';
    guid.Data4[4] = 'K'; guid.Data4[5] = '0'; guid.Data4[6] = '0'; guid.Data4[7] = '1';
    return guid;
}

TunDevice::TunDevice(boost::asio::io_context& ioc, const std::string& name)
    : ioc_(ioc), name_(name), platform_(std::make_unique<PlatformData>())
{
    read_buffer_.resize(NetworkConstants::MAX_PACKET_SIZE);
    platform_->adapter_name = utf8_to_wide(name);
}

TunDevice::~TunDevice() { close(); }

std::expected<void, ErrorCode> TunDevice::open() {
    auto& wt = WintunInterface::instance();
    if (!wt.is_loaded()) {
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    if (platform_->adapter) return {};

    GUID guid = name_to_guid(name_);
    platform_->adapter = wt.CreateAdapter(platform_->adapter_name.c_str(), L"EdgeLink", &guid);
    if (!platform_->adapter) {
        LOG_ERROR("TunDevice: Failed to create adapter - error {}", GetLastError());
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    wt.GetAdapterLUID(platform_->adapter, &platform_->adapter_luid);
    if (ConvertInterfaceLuidToIndex(&platform_->adapter_luid, &platform_->if_index) != NO_ERROR) {
        wt.CloseAdapter(platform_->adapter);
        platform_->adapter = nullptr;
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    platform_->session = wt.StartSession(platform_->adapter, 0x800000);
    if (!platform_->session) {
        wt.CloseAdapter(platform_->adapter);
        platform_->adapter = nullptr;
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }

    platform_->read_event = wt.GetReadWaitEvent(platform_->session);
    fd_ = 1;
    LOG_INFO("TunDevice: Created interface {} (index {})", name_, platform_->if_index);
    return {};
}

void TunDevice::close() {
    stop_reading();
    auto& wt = WintunInterface::instance();
    if (!wt.is_loaded()) return;

    if (platform_->session) { wt.EndSession(platform_->session); platform_->session = nullptr; }
    if (platform_->adapter) { wt.CloseAdapter(platform_->adapter); platform_->adapter = nullptr; }
    platform_->read_event = nullptr;
    fd_ = -1;
    LOG_INFO("TunDevice: Closed interface {}", name_);
}

std::expected<void, ErrorCode> TunDevice::set_address(const std::string& ip, uint8_t prefix_len) {
    if (!platform_->adapter) return std::unexpected(ErrorCode::NOT_CONNECTED);

    IN_ADDR addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = platform_->adapter_luid;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr = addr;
    row.OnLinkPrefixLength = prefix_len;
    row.DadState = IpDadStatePreferred;

    DWORD result = CreateUnicastIpAddressEntry(&row);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    LOG_INFO("TunDevice: Set address {}/{} on {}", ip, prefix_len, name_);
    return {};
}

std::expected<void, ErrorCode> TunDevice::set_mtu(uint16_t mtu) {
    mtu_ = mtu;
    if (!platform_->adapter) return {};

    MIB_IPINTERFACE_ROW row{};
    InitializeIpInterfaceEntry(&row);
    row.InterfaceLuid = platform_->adapter_luid;
    row.Family = AF_INET;
    if (GetIpInterfaceEntry(&row) == NO_ERROR) {
        row.NlMtu = mtu;
        SetIpInterfaceEntry(&row);
    }
    return {};
}

std::expected<void, ErrorCode> TunDevice::bring_up() { return {}; }
std::expected<void, ErrorCode> TunDevice::bring_down() { return {}; }

std::expected<void, ErrorCode> TunDevice::add_route(const std::string& network, uint8_t prefix_len) {
    if (!platform_->adapter) return std::unexpected(ErrorCode::NOT_CONNECTED);

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
    route.Metric = 0;
    route.Protocol = MIB_IPPROTO_NETMGMT;

    DWORD result = CreateIpForwardEntry2(&route);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
        return std::unexpected(ErrorCode::SYSTEM_ERROR);
    }
    return {};
}

std::expected<void, ErrorCode> TunDevice::del_route(const std::string& network, uint8_t prefix_len) {
    if (!platform_->adapter) return std::unexpected(ErrorCode::NOT_CONNECTED);

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
    return {};
}

void TunDevice::set_packet_callback(PacketCallback cb) { packet_callback_ = std::move(cb); }

void TunDevice::start_reading() {
    if (!platform_->session || reading_) return;
    reading_ = true;

    read_thread_ = std::thread([this]() {
        auto& wt = WintunInterface::instance();
        while (reading_) {
            DWORD result = WaitForSingleObject(platform_->read_event, 100);
            if (!reading_) break;
            if (result == WAIT_OBJECT_0) {
                DWORD packet_size;
                while (BYTE* packet = wt.ReceivePacket(platform_->session, &packet_size)) {
                    if (packet_size > 0 && packet_callback_) {
                        std::vector<uint8_t> data(packet, packet + packet_size);
                        boost::asio::post(ioc_, [this, pkt = std::move(data)]() {
                            if (packet_callback_) packet_callback_(pkt);
                        });
                    }
                    wt.ReleaseReceivePacket(platform_->session, packet);
                }
            }
        }
    });
}

void TunDevice::stop_reading() {
    reading_ = false;
    if (read_thread_.joinable()) read_thread_.join();
}

std::expected<void, ErrorCode> TunDevice::write_packet(const std::vector<uint8_t>& packet) {
    if (!platform_->session) return std::unexpected(ErrorCode::NOT_CONNECTED);

    auto& wt = WintunInterface::instance();
    BYTE* send_packet = wt.AllocateSendPacket(platform_->session, static_cast<DWORD>(packet.size()));
    if (!send_packet) return std::unexpected(ErrorCode::SYSTEM_ERROR);

    memcpy(send_packet, packet.data(), packet.size());
    wt.SendPacket(platform_->session, send_packet);
    return {};
}

std::expected<IPv4Header, ErrorCode> IPv4Header::parse(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) return std::unexpected(ErrorCode::INVALID_FRAME);

    IPv4Header header;
    header.version_ihl = packet[0];
    if (header.version() != 4) return std::unexpected(ErrorCode::INVALID_ARGUMENT);
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
    IN_ADDR addr; addr.s_addr = src_addr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

std::string IPv4Header::dst_ip_string() const {
    char buf[INET_ADDRSTRLEN];
    IN_ADDR addr; addr.s_addr = dst_addr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
}

} // namespace edgelink::client

#endif // _WIN32

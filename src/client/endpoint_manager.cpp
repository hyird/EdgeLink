#include "endpoint_manager.hpp"
#include <spdlog/spdlog.h>
#include "common/platform_net.hpp"
#include <random>
#include <cstring>

#ifdef _WIN32
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <ifaddrs.h>
    #include <netinet/in.h>
    #include <net/if.h>
#endif

namespace edgelink::client {

// STUN constants (RFC 5389)
constexpr uint16_t STUN_MAGIC_COOKIE_HIGH = 0x2112;
constexpr uint16_t STUN_MAGIC_COOKIE_LOW = 0xA442;
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN message types
constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;
constexpr uint16_t STUN_BINDING_ERROR = 0x0111;

// STUN attributes
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;
constexpr uint16_t STUN_ATTR_SOFTWARE = 0x8022;
constexpr uint16_t STUN_ATTR_FINGERPRINT = 0x8028;

EndpointManager::EndpointManager(boost::asio::io_context& ioc,
                                 const EndpointManagerConfig& config)
    : ioc_(ioc)
    , config_(config)
    , udp_socket_(ioc)
    , stun_recv_buffer_(1024)
    , stun_timer_(ioc)
    , refresh_timer_(ioc)
{
    // 生成随机transaction ID
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    for (auto& b : stun_transaction_id_) {
        b = static_cast<uint8_t>(dist(gen));
    }
}

EndpointManager::~EndpointManager() {
    stop();
}

void EndpointManager::start() {
    if (running_.exchange(true)) {
        return;
    }
    
    spdlog::info("EndpointManager starting...");
    
    try {
        // 打开UDP socket
        udp_socket_.open(boost::asio::ip::udp::v4());
        
        // 绑定到指定端口或让系统分配
        boost::asio::ip::udp::endpoint local_ep(
            boost::asio::ip::address_v4::any(), 
            config_.local_udp_port
        );
        udp_socket_.bind(local_ep);
        
        local_port_ = udp_socket_.local_endpoint().port();
        spdlog::info("EndpointManager: UDP socket bound to port {}", local_port_);
        
    } catch (const std::exception& e) {
        spdlog::error("EndpointManager: Failed to open UDP socket: {}", e.what());
        running_ = false;
        return;
    }
    
    // 收集本地地址
    collect_local_addresses();
    
    // 开始STUN发现
    if (!config_.stun_servers.empty()) {
        start_stun_discovery();
    }
    
    // 通知初始端点
    notify_endpoints_changed();
}

void EndpointManager::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    
    spdlog::info("EndpointManager stopping...");
    
    boost::system::error_code ec;
    stun_timer_.cancel();
    refresh_timer_.cancel();
    
    if (udp_socket_.is_open()) {
        udp_socket_.close(ec);
    }
}

std::vector<Endpoint> EndpointManager::get_endpoints() const {
    std::lock_guard<std::mutex> lock(endpoints_mutex_);
    return endpoints_;
}

std::string EndpointManager::get_nat_type_string() const {
    switch (nat_type_.load()) {
        case NatType::UNKNOWN: return "unknown";
        case NatType::OPEN: return "open";
        case NatType::FULL_CONE: return "full_cone";
        case NatType::RESTRICTED_CONE: return "restricted_cone";
        case NatType::PORT_RESTRICTED: return "port_restricted";
        case NatType::SYMMETRIC: return "symmetric";
        default: return "unknown";
    }
}

std::optional<Endpoint> EndpointManager::get_public_endpoint() const {
    std::lock_guard<std::mutex> lock(endpoints_mutex_);
    for (const auto& ep : endpoints_) {
        if (ep.type == EndpointType::WAN) {
            return ep;
        }
    }
    return std::nullopt;
}

void EndpointManager::refresh() {
    if (!running_) return;
    
    spdlog::debug("EndpointManager: Refreshing endpoints...");
    
    // 重新收集本地地址
    collect_local_addresses();
    
    // 重新进行STUN发现
    if (!config_.stun_servers.empty()) {
        start_stun_discovery();
    }
}

void EndpointManager::collect_local_addresses() {
    std::vector<Endpoint> local_endpoints;
    
#ifdef _WIN32
    // Windows implementation using GetAdaptersAddresses
    ULONG bufferSize = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | 
                  GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    
    // Allocate buffer
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (pAddresses == nullptr) {
        spdlog::error("EndpointManager: Failed to allocate memory for adapter addresses");
        return;
    }
    
    DWORD dwRetVal = GetAdaptersAddresses(AF_INET, flags, nullptr, pAddresses, &bufferSize);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
        if (pAddresses == nullptr) {
            spdlog::error("EndpointManager: Failed to allocate memory for adapter addresses");
            return;
        }
        dwRetVal = GetAdaptersAddresses(AF_INET, flags, nullptr, pAddresses, &bufferSize);
    }
    
    if (dwRetVal != NO_ERROR) {
        spdlog::error("EndpointManager: GetAdaptersAddresses failed with error: {}", dwRetVal);
        free(pAddresses);
        return;
    }
    
    for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; 
         pCurrAddresses != nullptr; 
         pCurrAddresses = pCurrAddresses->Next) {
        
        // Skip loopback and non-operational adapters
        if (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (pCurrAddresses->OperStatus != IfOperStatusUp) continue;
        
        for (PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
             pUnicast != nullptr;
             pUnicast = pUnicast->Next) {
            
            if (pUnicast->Address.lpSockaddr->sa_family != AF_INET) continue;
            
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(pUnicast->Address.lpSockaddr);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
            
            std::string ip = ip_str;
            
            // Skip link-local addresses
            if (ip.substr(0, 7) == "169.254") continue;
            
            spdlog::debug("EndpointManager: Found local address {} on {}", ip, pCurrAddresses->AdapterName);
            
            Endpoint ep;
            ep.address = ip;
            ep.port = local_port_;
            ep.type = EndpointType::LAN;
            ep.priority = 10;
            ep.discovered_at = std::chrono::steady_clock::now();
            
            local_endpoints.push_back(ep);
        }
    }
    
    free(pAddresses);
#else
    // POSIX implementation using getifaddrs
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) {
        spdlog::error("EndpointManager: getifaddrs failed: {}", strerror(errno));
        return;
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        // 只处理IPv4
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        
        // 跳过loopback和down的接口
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;
        if (!(ifa->ifa_flags & IFF_RUNNING)) continue;
        
        struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip_str, sizeof(ip_str));
        
        std::string ip = ip_str;
        
        // 跳过link-local地址
        if (ip.substr(0, 7) == "169.254") continue;
        
        spdlog::debug("EndpointManager: Found local address {} on {}", ip, ifa->ifa_name);
        
        Endpoint ep;
        ep.address = ip;
        ep.port = local_port_;
        ep.type = EndpointType::LAN;
        ep.priority = 10;  // LAN地址优先级
        ep.discovered_at = std::chrono::steady_clock::now();
        
        local_endpoints.push_back(ep);
    }
    
    freeifaddrs(ifaddr);
#endif
    
    // 更新端点列表
    {
        std::lock_guard<std::mutex> lock(endpoints_mutex_);
        // 移除旧的LAN端点
        endpoints_.erase(
            std::remove_if(endpoints_.begin(), endpoints_.end(),
                [](const Endpoint& ep) { return ep.type == EndpointType::LAN; }),
            endpoints_.end()
        );
        // 添加新的
        endpoints_.insert(endpoints_.end(), local_endpoints.begin(), local_endpoints.end());
    }
    
    spdlog::info("EndpointManager: Collected {} local addresses", local_endpoints.size());
}

void EndpointManager::start_stun_discovery() {
    if (!running_) return;
    if (config_.stun_servers.empty()) return;
    
    stun_attempt_ = 0;
    send_stun_request(config_.stun_servers[0]);
}

void EndpointManager::send_stun_request(const StunServer& server) {
    if (!running_) return;
    
    spdlog::debug("EndpointManager: Sending STUN request to {}:{}", 
                  server.host, server.port);
    
    // 解析STUN服务器地址
    boost::asio::ip::udp::resolver resolver(ioc_);
    
    try {
        auto results = resolver.resolve(server.host, std::to_string(server.port));
        if (results.empty()) {
            spdlog::warn("EndpointManager: Failed to resolve STUN server {}", server.host);
            schedule_stun_refresh();
            return;
        }
        
        stun_server_endpoint_ = *results.begin();
        
    } catch (const std::exception& e) {
        spdlog::warn("EndpointManager: STUN server resolution failed: {}", e.what());
        schedule_stun_refresh();
        return;
    }
    
    // 构建STUN binding request
    auto request = build_stun_binding_request();
    
    // 发送请求
    udp_socket_.async_send_to(
        boost::asio::buffer(request),
        stun_server_endpoint_,
        [this](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                spdlog::warn("EndpointManager: STUN send failed: {}", ec.message());
            }
        }
    );
    
    // 设置接收
    udp_socket_.async_receive_from(
        boost::asio::buffer(stun_recv_buffer_),
        stun_server_endpoint_,
        [this](const boost::system::error_code& ec, std::size_t bytes) {
            handle_stun_response(ec, bytes, stun_server_endpoint_);
        }
    );
    
    // 设置超时
    stun_timer_.expires_after(config_.stun_timeout);
    stun_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted) return;
        if (!running_) return;
        
        spdlog::warn("EndpointManager: STUN request timeout");
        
        // 尝试下一个STUN服务器
        stun_attempt_++;
        if (stun_attempt_ < static_cast<int>(config_.stun_servers.size())) {
            send_stun_request(config_.stun_servers[stun_attempt_]);
        } else {
            spdlog::warn("EndpointManager: All STUN servers failed");
            schedule_stun_refresh();
        }
    });
}

void EndpointManager::handle_stun_response(const boost::system::error_code& ec,
                                           std::size_t bytes_received,
                                           const boost::asio::ip::udp::endpoint& sender) {
    if (ec == boost::asio::error::operation_aborted) return;
    if (!running_) return;
    
    stun_timer_.cancel();
    
    if (ec) {
        spdlog::warn("EndpointManager: STUN receive failed: {}", ec.message());
        schedule_stun_refresh();
        return;
    }
    
    spdlog::debug("EndpointManager: Received STUN response ({} bytes) from {}",
                  bytes_received, sender.address().to_string());
    
    auto result = parse_stun_response(stun_recv_buffer_.data(), bytes_received);
    
    if (result.success) {
        spdlog::info("EndpointManager: STUN discovered public endpoint {}:{}",
                     result.mapped_address, result.mapped_port);
        
        // 添加公网端点
        Endpoint ep;
        ep.address = result.mapped_address;
        ep.port = result.mapped_port;
        ep.type = EndpointType::WAN;
        ep.priority = 5;  // 公网地址优先级更高
        ep.discovered_at = std::chrono::steady_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(endpoints_mutex_);
            // 移除旧的WAN端点
            endpoints_.erase(
                std::remove_if(endpoints_.begin(), endpoints_.end(),
                    [](const Endpoint& e) { return e.type == EndpointType::WAN; }),
                endpoints_.end()
            );
            endpoints_.push_back(ep);
        }
        
        // 简单判断NAT类型
        // 如果本地端口和映射端口相同，可能是cone NAT
        // 完整的NAT类型检测需要多次STUN请求到不同地址
        if (ep.port == local_port_) {
            nat_type_ = NatType::FULL_CONE;
        } else {
            nat_type_ = NatType::PORT_RESTRICTED;
        }
        
        spdlog::info("EndpointManager: Detected NAT type: {}", get_nat_type_string());
        
        notify_endpoints_changed();
        
        if (nat_type_callback_) {
            nat_type_callback_(nat_type_.load());
        }
    } else {
        spdlog::warn("EndpointManager: Failed to parse STUN response");
    }
    
    schedule_stun_refresh();
}

void EndpointManager::schedule_stun_refresh() {
    if (!running_) return;
    
    refresh_timer_.expires_after(config_.stun_interval);
    refresh_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted) return;
        if (!running_) return;
        refresh();
    });
}

std::vector<uint8_t> EndpointManager::build_stun_binding_request() {
    std::vector<uint8_t> packet;
    packet.reserve(20);
    
    // Message Type: Binding Request (0x0001)
    packet.push_back(0x00);
    packet.push_back(0x01);
    
    // Message Length: 0 (no attributes)
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    // Magic Cookie
    packet.push_back(0x21);
    packet.push_back(0x12);
    packet.push_back(0xA4);
    packet.push_back(0x42);
    
    // Transaction ID (12 bytes)
    for (auto b : stun_transaction_id_) {
        packet.push_back(b);
    }
    
    return packet;
}

EndpointManager::StunResult EndpointManager::parse_stun_response(const uint8_t* data, size_t len) {
    StunResult result;
    
    if (len < 20) {
        spdlog::warn("EndpointManager: STUN response too short");
        return result;
    }
    
    // Check message type (Binding Response = 0x0101)
    uint16_t msg_type = (data[0] << 8) | data[1];
    if (msg_type != STUN_BINDING_RESPONSE) {
        spdlog::warn("EndpointManager: Not a STUN Binding Response: 0x{:04x}", msg_type);
        return result;
    }
    
    // Check magic cookie
    uint32_t cookie = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    if (cookie != STUN_MAGIC_COOKIE) {
        spdlog::warn("EndpointManager: Invalid STUN magic cookie");
        return result;
    }
    
    // Check transaction ID
    if (memcmp(data + 8, stun_transaction_id_.data(), 12) != 0) {
        spdlog::warn("EndpointManager: STUN transaction ID mismatch");
        return result;
    }
    
    // Message length
    uint16_t msg_len = (data[2] << 8) | data[3];
    if (20 + msg_len > len) {
        spdlog::warn("EndpointManager: STUN message length mismatch");
        return result;
    }
    
    // Parse attributes
    size_t pos = 20;
    while (pos + 4 <= 20 + msg_len) {
        uint16_t attr_type = (data[pos] << 8) | data[pos + 1];
        uint16_t attr_len = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        
        if (pos + attr_len > 20 + msg_len) break;
        
        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8) {
            // XOR-MAPPED-ADDRESS
            uint8_t family = data[pos + 1];
            if (family == 0x01) {  // IPv4
                uint16_t xport = (data[pos + 2] << 8) | data[pos + 3];
                result.mapped_port = xport ^ STUN_MAGIC_COOKIE_HIGH;
                
                uint32_t xaddr = (data[pos + 4] << 24) | (data[pos + 5] << 16) | 
                                 (data[pos + 6] << 8) | data[pos + 7];
                uint32_t addr = xaddr ^ STUN_MAGIC_COOKIE;
                
                struct in_addr in;
                in.s_addr = htonl(addr);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
                result.mapped_address = ip_str;
                result.success = true;
            }
        } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && attr_len >= 8 && !result.success) {
            // MAPPED-ADDRESS (fallback for old STUN servers)
            uint8_t family = data[pos + 1];
            if (family == 0x01) {  // IPv4
                result.mapped_port = (data[pos + 2] << 8) | data[pos + 3];
                
                struct in_addr in;
                memcpy(&in.s_addr, data + pos + 4, 4);
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));
                result.mapped_address = ip_str;
                result.success = true;
            }
        }
        
        // Align to 4 bytes
        pos += attr_len;
        if (attr_len % 4 != 0) {
            pos += 4 - (attr_len % 4);
        }
    }
    
    return result;
}

void EndpointManager::notify_endpoints_changed() {
    if (endpoint_callback_) {
        endpoint_callback_(get_endpoints());
    }
}

} // namespace edgelink::client

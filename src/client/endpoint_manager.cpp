#include "client/endpoint_manager.hpp"
#include "common/logger.hpp"
#include <boost/asio/use_awaitable.hpp>
#include <random>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#endif

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("client.endpoint"); }

// STUN 常量 (RFC 5389)
constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;
constexpr size_t STUN_HEADER_SIZE = 20;
constexpr size_t STUN_TXN_ID_SIZE = 12;

// STUN 消息类型
constexpr uint16_t STUN_BINDING_REQUEST = 0x0001;
constexpr uint16_t STUN_BINDING_RESPONSE = 0x0101;

// STUN 属性类型
constexpr uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

// 生成随机 Transaction ID
std::array<uint8_t, STUN_TXN_ID_SIZE> generate_txn_id() {
    std::array<uint8_t, STUN_TXN_ID_SIZE> txn_id;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& b : txn_id) {
        b = static_cast<uint8_t>(dis(gen));
    }
    return txn_id;
}

// 构建 STUN Binding Request
std::vector<uint8_t> build_stun_request(const std::array<uint8_t, STUN_TXN_ID_SIZE>& txn_id) {
    std::vector<uint8_t> request;
    request.reserve(STUN_HEADER_SIZE);

    // Message Type: Binding Request (0x0001)
    request.push_back(0x00);
    request.push_back(0x01);

    // Message Length: 0 (no attributes)
    request.push_back(0x00);
    request.push_back(0x00);

    // Magic Cookie
    request.push_back(static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 24));
    request.push_back(static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 16) & 0xFF));
    request.push_back(static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 8) & 0xFF));
    request.push_back(static_cast<uint8_t>(STUN_MAGIC_COOKIE & 0xFF));

    // Transaction ID
    request.insert(request.end(), txn_id.begin(), txn_id.end());

    return request;
}

// 读取 16 位大端整数
uint16_t read_u16_be(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

// 读取 32 位大端整数
uint32_t read_u32_be(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

} // anonymous namespace

const char* nat_type_name(NatType type) {
    switch (type) {
        case NatType::UNKNOWN: return "Unknown";
        case NatType::OPEN: return "Open";
        case NatType::FULL_CONE: return "Full Cone";
        case NatType::RESTRICTED: return "Restricted Cone";
        case NatType::PORT_RESTRICTED: return "Port Restricted Cone";
        case NatType::SYMMETRIC: return "Symmetric";
        default: return "Invalid";
    }
}

EndpointManager::EndpointManager(asio::io_context& ioc)
    : ioc_(ioc)
    , socket_(ioc)
{
}

EndpointManager::~EndpointManager() {
    close_socket();
}

void EndpointManager::set_config(const EndpointConfig& config) {
    config_ = config;
}

void EndpointManager::set_stun_servers(const std::vector<StunInfo>& stuns) {
    stun_servers_ = stuns;
    log().debug("STUN servers configured: {}", stuns.size());
    for (const auto& stun : stuns) {
        log().debug("  - {}:{}", stun.hostname, stun.port);
    }
}

void EndpointManager::set_local_port(uint16_t port) {
    requested_port_ = port;
}

asio::awaitable<bool> EndpointManager::init_socket() {
    if (socket_.is_open()) {
        co_return true;
    }

    try {
        // 创建 UDP socket
        socket_.open(asio::ip::udp::v4());

        // 绑定端口
        asio::ip::udp::endpoint local_ep(asio::ip::udp::v4(), requested_port_);
        socket_.bind(local_ep);

        // 获取实际绑定的端口
        auto bound_ep = socket_.local_endpoint();
        log().info("UDP socket bound to port {}", bound_ep.port());

        // 发现本地端点
        auto local_addrs = get_local_addresses();
        uint16_t port = bound_ep.port();

        std::lock_guard lock(local_mutex_);
        local_endpoints_.clear();
        for (const auto& addr : local_addrs) {
            if (addr.is_v4()) {
                Endpoint ep;
                ep.type = EndpointType::LAN;
                ep.ip_type = IpType::IPv4;
                auto bytes = addr.to_v4().to_bytes();
                std::copy(bytes.begin(), bytes.end(), ep.address.begin());
                ep.port = port;
                ep.priority = 100; // LAN 端点优先级较高
                local_endpoints_.push_back(ep);
                log().debug("Local endpoint: {}:{}", addr.to_string(), port);
            }
        }

        co_return true;
    } catch (const std::exception& e) {
        log().error("Failed to initialize UDP socket: {}", e.what());
        co_return false;
    }
}

void EndpointManager::close_socket() {
    if (socket_.is_open()) {
        boost::system::error_code ec;
        socket_.close(ec);
    }
}

std::vector<Endpoint> EndpointManager::get_local_endpoints() const {
    std::lock_guard lock(local_mutex_);
    return local_endpoints_;
}

asio::awaitable<StunQueryResult> EndpointManager::query_stun_endpoint() {
    StunQueryResult result;

    if (stun_servers_.empty()) {
        log().warn("No STUN servers configured");
        co_return result;
    }

    if (!socket_.is_open()) {
        log().error("Socket not initialized");
        co_return result;
    }

    // 尝试每个 STUN 服务器
    for (const auto& stun : stun_servers_) {
        try {
            // 解析 STUN 服务器地址
            asio::ip::udp::resolver resolver(ioc_);
            auto endpoints = co_await resolver.async_resolve(
                stun.hostname, std::to_string(stun.port), asio::use_awaitable);

            for (const auto& ep : endpoints) {
                if (ep.endpoint().address().is_v4()) {
                    result = co_await send_stun_request(ep.endpoint(), stun.hostname);
                    if (result.success) {
                        // 缓存结果
                        std::lock_guard lock(stun_mutex_);
                        last_stun_result_ = result;
                        stun_endpoint_ = result.mapped_endpoint;

                        log().info("STUN query successful: {}:{} (via {})",
                            result.mapped_endpoint.address[0], result.mapped_endpoint.address[1],
                            result.mapped_endpoint.address[2], result.mapped_endpoint.address[3],
                            result.mapped_endpoint.port, result.stun_server);

                        co_return result;
                    }
                    break; // 只尝试一个 IP
                }
            }
        } catch (const std::exception& e) {
            log().debug("STUN query to {} failed: {}", stun.hostname, e.what());
        }
    }

    log().warn("All STUN queries failed");
    co_return result;
}

std::vector<Endpoint> EndpointManager::get_all_endpoints() const {
    std::vector<Endpoint> endpoints;

    // 添加本地端点
    {
        std::lock_guard lock(local_mutex_);
        endpoints.insert(endpoints.end(), local_endpoints_.begin(), local_endpoints_.end());
    }

    // 添加 STUN 端点
    {
        std::lock_guard lock(stun_mutex_);
        if (stun_endpoint_) {
            endpoints.push_back(*stun_endpoint_);
        }
    }

    return endpoints;
}

asio::awaitable<NatType> EndpointManager::detect_nat_type() {
    // NAT 类型检测需要至少 2 个 STUN 服务器
    if (stun_servers_.size() < 2) {
        log().warn("NAT type detection requires at least 2 STUN servers");
        nat_type_ = NatType::UNKNOWN;
        co_return NatType::UNKNOWN;
    }

    // 查询第一个 STUN 服务器
    auto result1 = co_await query_stun_endpoint();
    if (!result1.success) {
        log().warn("NAT type detection failed: first STUN query failed");
        nat_type_ = NatType::UNKNOWN;
        co_return NatType::UNKNOWN;
    }

    // 保存第一次的映射结果
    auto first_mapped = result1.mapped_endpoint;

    // 查询第二个 STUN 服务器
    // 临时移除第一个服务器
    auto first_stun = stun_servers_.front();
    stun_servers_.erase(stun_servers_.begin());

    auto result2 = co_await query_stun_endpoint();

    // 恢复第一个服务器
    stun_servers_.insert(stun_servers_.begin(), first_stun);

    if (!result2.success) {
        log().warn("NAT type detection incomplete: second STUN query failed");
        // 假设是某种锥形 NAT
        nat_type_ = NatType::RESTRICTED;
        co_return NatType::RESTRICTED;
    }

    auto second_mapped = result2.mapped_endpoint;

    // 比较两次映射结果
    bool same_ip = std::equal(
        first_mapped.address.begin(), first_mapped.address.begin() + 4,
        second_mapped.address.begin());
    bool same_port = (first_mapped.port == second_mapped.port);

    if (same_ip && same_port) {
        // 两次映射相同 - 锥形 NAT (或 Open)
        // 无法区分具体类型，假设 Port Restricted
        nat_type_ = NatType::PORT_RESTRICTED;
        log().info("NAT type detected: Port Restricted Cone (same mapping)");
    } else if (same_ip && !same_port) {
        // IP 相同但端口不同 - Symmetric NAT (难穿透)
        nat_type_ = NatType::SYMMETRIC;
        log().info("NAT type detected: Symmetric (different ports)");
    } else {
        // IP 也不同 - Symmetric NAT (多出口)
        nat_type_ = NatType::SYMMETRIC;
        log().info("NAT type detected: Symmetric (different IPs)");
    }

    co_return nat_type_.load();
}

uint16_t EndpointManager::local_port() const {
    if (!socket_.is_open()) {
        return 0;
    }
    return socket_.local_endpoint().port();
}

std::optional<Endpoint> EndpointManager::stun_endpoint() const {
    std::lock_guard lock(stun_mutex_);
    return stun_endpoint_;
}

asio::awaitable<StunQueryResult> EndpointManager::send_stun_request(
    const asio::ip::udp::endpoint& stun_server,
    const std::string& server_name) {

    StunQueryResult result;
    result.stun_server = server_name;

    auto txn_id = generate_txn_id();
    auto request = build_stun_request(txn_id);

    // 记录发送时间
    auto start_time = std::chrono::steady_clock::now();

    // 发送请求 (最多重试几次)
    for (uint32_t i = 0; i < config_.stun_retry_count; ++i) {
        try {
            // 发送 Binding Request
            co_await socket_.async_send_to(
                asio::buffer(request), stun_server, asio::use_awaitable);

            // 接收响应 (with timeout)
            std::array<uint8_t, 1500> recv_buf;
            asio::ip::udp::endpoint sender;

            // 使用超时 - 使用 shared_ptr 确保 cancel_flag 的生命周期
            auto cancel_flag = std::make_shared<std::atomic<bool>>(false);
            asio::steady_timer timer(ioc_);
            timer.expires_after(std::chrono::milliseconds(config_.stun_timeout_ms));

            // 设置超时处理 - 捕获 shared_ptr 和 socket 指针
            auto* socket_ptr = &socket_;
            timer.async_wait([cancel_flag, socket_ptr](const boost::system::error_code& ec) {
                if (!ec && !cancel_flag->load()) {
                    boost::system::error_code cancel_ec;
                    socket_ptr->cancel(cancel_ec);
                }
            });

            size_t bytes_received = 0;
            bool timed_out = false;

            try {
                bytes_received = co_await socket_.async_receive_from(
                    asio::buffer(recv_buf), sender, asio::use_awaitable);
                cancel_flag->store(true);
                timer.cancel();
            } catch (const boost::system::system_error& e) {
                cancel_flag->store(true);
                timer.cancel();
                if (e.code() == asio::error::operation_aborted) {
                    // 超时
                    log().debug("STUN request timeout (attempt {})", i + 1);
                    timed_out = true;
                } else {
                    throw;
                }
            }

            if (timed_out) {
                continue;
            }

            // 计算 RTT
            auto end_time = std::chrono::steady_clock::now();
            result.rtt = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

            // 解析响应
            auto mapped = parse_stun_response(
                std::span(recv_buf.data(), bytes_received), txn_id);

            if (mapped) {
                result.success = true;
                result.mapped_endpoint = *mapped;
                result.local_port = socket_.local_endpoint().port();

                // 格式化 IP 用于日志
                auto& addr = result.mapped_endpoint.address;
                log().debug("STUN response from {}: {}.{}.{}.{}:{}",
                    server_name,
                    addr[0], addr[1], addr[2], addr[3],
                    result.mapped_endpoint.port);

                co_return result;
            }

        } catch (const std::exception& e) {
            log().debug("STUN request failed: {}", e.what());
        }

        // 重试间隔
        if (i + 1 < config_.stun_retry_count) {
            asio::steady_timer delay(ioc_);
            delay.expires_after(std::chrono::milliseconds(config_.stun_retry_interval_ms));
            co_await delay.async_wait(asio::use_awaitable);
        }
    }

    co_return result;
}

std::optional<Endpoint> EndpointManager::parse_stun_response(
    std::span<const uint8_t> data,
    const std::array<uint8_t, 12>& expected_txn_id) {

    // 验证最小长度
    if (data.size() < STUN_HEADER_SIZE) {
        return std::nullopt;
    }

    // 验证消息类型
    uint16_t msg_type = read_u16_be(data.data());
    if (msg_type != STUN_BINDING_RESPONSE) {
        return std::nullopt;
    }

    // 验证 Magic Cookie
    uint32_t magic = read_u32_be(data.data() + 4);
    if (magic != STUN_MAGIC_COOKIE) {
        return std::nullopt;
    }

    // 验证 Transaction ID
    if (!std::equal(expected_txn_id.begin(), expected_txn_id.end(), data.data() + 8)) {
        return std::nullopt;
    }

    // 解析属性
    uint16_t msg_len = read_u16_be(data.data() + 2);
    size_t offset = STUN_HEADER_SIZE;
    size_t end = STUN_HEADER_SIZE + msg_len;

    Endpoint result;
    bool found = false;

    while (offset + 4 <= end && offset + 4 <= data.size()) {
        uint16_t attr_type = read_u16_be(data.data() + offset);
        uint16_t attr_len = read_u16_be(data.data() + offset + 2);
        offset += 4;

        if (offset + attr_len > data.size()) {
            break;
        }

        if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS) {
            // XOR-MAPPED-ADDRESS (优先使用)
            if (attr_len >= 8) {
                uint8_t family = data[offset + 1];
                if (family == 0x01) { // IPv4
                    // XOR Port
                    uint16_t xor_port = read_u16_be(data.data() + offset + 2);
                    result.port = xor_port ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);

                    // XOR Address
                    uint32_t xor_addr = read_u32_be(data.data() + offset + 4);
                    uint32_t addr = xor_addr ^ STUN_MAGIC_COOKIE;

                    result.address[0] = static_cast<uint8_t>(addr >> 24);
                    result.address[1] = static_cast<uint8_t>((addr >> 16) & 0xFF);
                    result.address[2] = static_cast<uint8_t>((addr >> 8) & 0xFF);
                    result.address[3] = static_cast<uint8_t>(addr & 0xFF);

                    result.type = EndpointType::STUN;
                    result.ip_type = IpType::IPv4;
                    result.priority = 50; // STUN 端点优先级中等
                    found = true;
                }
            }
        } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && !found) {
            // MAPPED-ADDRESS (备用)
            if (attr_len >= 8) {
                uint8_t family = data[offset + 1];
                if (family == 0x01) { // IPv4
                    result.port = read_u16_be(data.data() + offset + 2);

                    result.address[0] = data[offset + 4];
                    result.address[1] = data[offset + 5];
                    result.address[2] = data[offset + 6];
                    result.address[3] = data[offset + 7];

                    result.type = EndpointType::STUN;
                    result.ip_type = IpType::IPv4;
                    result.priority = 50;
                    found = true;
                }
            }
        }

        // 属性对齐到 4 字节
        offset += attr_len;
        if (attr_len % 4 != 0) {
            offset += 4 - (attr_len % 4);
        }
    }

    if (found) {
        return result;
    }
    return std::nullopt;
}

std::vector<asio::ip::address> EndpointManager::get_local_addresses() const {
    std::vector<asio::ip::address> addresses;

#ifdef _WIN32
    // Windows 实现 - 使用 GetAdaptersAddresses
    ULONG buf_size = 15000;
    std::vector<uint8_t> buffer(buf_size);
    PIP_ADAPTER_ADDRESSES adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    DWORD result = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &buf_size);

    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(buf_size);
        adapters = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        result = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &buf_size);
    }

    if (result == NO_ERROR) {
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            // 跳过回环和隧道接口
            if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
                adapter->IfType == IF_TYPE_TUNNEL) {
                continue;
            }

            // 检查是否已连接
            if (adapter->OperStatus != IfOperStatusUp) {
                continue;
            }

            for (auto* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                auto* sockaddr = unicast->Address.lpSockaddr;
                if (sockaddr->sa_family == AF_INET) {
                    auto* addr_in = reinterpret_cast<sockaddr_in*>(sockaddr);
                    auto ip = asio::ip::make_address_v4(ntohl(addr_in->sin_addr.s_addr));

                    // 跳过回环地址
                    if (ip.is_loopback()) {
                        continue;
                    }

                    addresses.push_back(ip);
                }
            }
        }
    }
#else
    // Linux/macOS 实现 - 使用 getifaddrs
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        for (auto* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (!ifa->ifa_addr) continue;

            // 只处理 IPv4
            if (ifa->ifa_addr->sa_family != AF_INET) continue;

            // 跳过回环接口
            if (ifa->ifa_flags & IFF_LOOPBACK) continue;

            // 检查是否 UP
            if (!(ifa->ifa_flags & IFF_UP)) continue;

            auto* addr_in = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            auto ip = asio::ip::make_address_v4(ntohl(addr_in->sin_addr.s_addr));

            addresses.push_back(ip);
        }
        freeifaddrs(ifaddr);
    }
#endif

    return addresses;
}

} // namespace edgelink::client

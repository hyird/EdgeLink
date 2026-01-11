#include "controller/stun_server.hpp"
#include "common/logger.hpp"
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace edgelink::controller {

namespace {
auto& log() { return Logger::get("controller.stun"); }

// 写入 16 位大端整数
void write_u16_be(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 8));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// 写入 32 位大端整数
void write_u32_be(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>(val >> 24));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

// 读取 16 位大端整数
uint16_t read_u16_be(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | data[1];
}

} // anonymous namespace

StunServer::StunServer(asio::io_context& ioc, const std::string& bind_address, uint16_t port)
    : ioc_(ioc)
    , bind_address_(bind_address)
    , port_(port)
{
}

StunServer::~StunServer() {
    stop();
}

void StunServer::set_public_ip(const std::string& ip) {
    public_ip_ = ip;
}

asio::awaitable<void> StunServer::start() {
    if (running_) {
        co_return;
    }

    try {
        // 解析绑定地址
        asio::ip::udp::endpoint endpoint;
        if (bind_address_.empty() || bind_address_ == "0.0.0.0") {
            endpoint = asio::ip::udp::endpoint(asio::ip::udp::v4(), port_);
        } else {
            auto addr = asio::ip::make_address(bind_address_);
            endpoint = asio::ip::udp::endpoint(addr, port_);
        }

        // 创建 UDP socket
        socket_ = std::make_unique<asio::ip::udp::socket>(ioc_, endpoint);
        running_ = true;

        log().info("STUN server started on {}:{}", bind_address_, port_);
        if (!public_ip_.empty()) {
            log().info("  Public IP: {}", public_ip_);
        }

        // 启动接收循环
        co_await recv_loop();

    } catch (const std::exception& e) {
        log().error("Failed to start STUN server: {}", e.what());
        running_ = false;
    }
}

void StunServer::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    if (socket_) {
        boost::system::error_code ec;
        socket_->close(ec);
        socket_.reset();
    }
    log().info("STUN server stopped");
}

asio::awaitable<void> StunServer::recv_loop() {
    while (running_ && socket_) {
        try {
            auto bytes_received = co_await socket_->async_receive_from(
                asio::buffer(recv_buffer_),
                sender_endpoint_,
                asio::use_awaitable);

            if (bytes_received > 0) {
                handle_request(
                    sender_endpoint_,
                    std::span(recv_buffer_.data(), bytes_received));
            }
        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted) {
                log().error("STUN recv error: {}", e.what());
            }
            break;
        }
    }
}

void StunServer::handle_request(const asio::ip::udp::endpoint& from,
                                 std::span<const uint8_t> data) {
    // 验证消息格式
    if (!validate_stun_message(data)) {
        return;
    }

    // 读取消息类型
    uint16_t msg_type = read_u16_be(data.data());
    if (msg_type != static_cast<uint16_t>(StunMsgType::BINDING_REQUEST)) {
        log().debug("Ignoring non-binding request: 0x{:04x}", msg_type);
        return;
    }

    // 提取 Transaction ID (12 bytes, offset 8)
    std::span<const uint8_t> txn_id(data.data() + 8, STUN_TXN_ID_SIZE);

    // 构建响应
    auto response = build_binding_response(from, txn_id);

    // 发送响应
    boost::system::error_code ec;
    socket_->send_to(asio::buffer(response), from, 0, ec);
    if (ec) {
        log().error("Failed to send STUN response: {}", ec.message());
    } else {
        log().debug("STUN Binding Response sent to {}:{}",
                   from.address().to_string(), from.port());
    }
}

bool StunServer::validate_stun_message(std::span<const uint8_t> data) {
    // 最小长度检查
    if (data.size() < STUN_HEADER_SIZE) {
        return false;
    }

    // 检查前两位必须为 0 (RFC 5389)
    if ((data[0] & 0xC0) != 0) {
        return false;
    }

    // 检查 Magic Cookie (offset 4-7)
    uint32_t magic = (static_cast<uint32_t>(data[4]) << 24) |
                     (static_cast<uint32_t>(data[5]) << 16) |
                     (static_cast<uint32_t>(data[6]) << 8) |
                     static_cast<uint32_t>(data[7]);
    if (magic != STUN_MAGIC_COOKIE) {
        return false;
    }

    // 检查消息长度
    uint16_t msg_len = read_u16_be(data.data() + 2);
    if (data.size() < STUN_HEADER_SIZE + msg_len) {
        return false;
    }

    // 消息长度必须是 4 的倍数
    if (msg_len % 4 != 0) {
        return false;
    }

    return true;
}

std::vector<uint8_t> StunServer::build_binding_response(
    const asio::ip::udp::endpoint& client_addr,
    std::span<const uint8_t> txn_id) {

    std::vector<uint8_t> response;
    response.reserve(64);

    // 构建属性
    auto xor_mapped = build_xor_mapped_address(client_addr, txn_id);

    // SOFTWARE 属性
    std::string software = "EdgeLink STUN";
    std::vector<uint8_t> software_attr;
    write_u16_be(software_attr, static_cast<uint16_t>(StunAttrType::SOFTWARE));
    write_u16_be(software_attr, static_cast<uint16_t>(software.size()));
    software_attr.insert(software_attr.end(), software.begin(), software.end());
    // 填充到 4 字节对齐
    while (software_attr.size() % 4 != 0) {
        software_attr.push_back(0);
    }

    // 计算总属性长度
    uint16_t attrs_len = static_cast<uint16_t>(xor_mapped.size() + software_attr.size());

    // 写入头部
    // Message Type: Binding Response (0x0101)
    write_u16_be(response, static_cast<uint16_t>(StunMsgType::BINDING_RESPONSE));
    // Message Length
    write_u16_be(response, attrs_len);
    // Magic Cookie
    write_u32_be(response, STUN_MAGIC_COOKIE);
    // Transaction ID (12 bytes)
    response.insert(response.end(), txn_id.begin(), txn_id.end());

    // 写入属性
    response.insert(response.end(), xor_mapped.begin(), xor_mapped.end());
    response.insert(response.end(), software_attr.begin(), software_attr.end());

    return response;
}

std::vector<uint8_t> StunServer::build_xor_mapped_address(
    const asio::ip::udp::endpoint& addr,
    std::span<const uint8_t> txn_id) {

    std::vector<uint8_t> attr;

    // XOR-MAPPED-ADDRESS 属性类型
    write_u16_be(attr, static_cast<uint16_t>(StunAttrType::XOR_MAPPED_ADDRESS));

    if (addr.address().is_v4()) {
        // IPv4: 8 bytes value
        write_u16_be(attr, 8);  // 属性长度

        // Reserved (1 byte) + Family (1 byte)
        attr.push_back(0x00);  // Reserved
        attr.push_back(0x01);  // IPv4 family

        // XOR Port (port XOR 上 16 位 magic cookie)
        uint16_t xor_port = addr.port() ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
        write_u16_be(attr, xor_port);

        // XOR Address (address XOR magic cookie)
        auto ip_bytes = addr.address().to_v4().to_bytes();
        uint32_t ip_u32 = (static_cast<uint32_t>(ip_bytes[0]) << 24) |
                          (static_cast<uint32_t>(ip_bytes[1]) << 16) |
                          (static_cast<uint32_t>(ip_bytes[2]) << 8) |
                          static_cast<uint32_t>(ip_bytes[3]);
        uint32_t xor_ip = ip_u32 ^ STUN_MAGIC_COOKIE;
        write_u32_be(attr, xor_ip);

    } else {
        // IPv6: 20 bytes value
        write_u16_be(attr, 20);  // 属性长度

        // Reserved (1 byte) + Family (1 byte)
        attr.push_back(0x00);  // Reserved
        attr.push_back(0x02);  // IPv6 family

        // XOR Port
        uint16_t xor_port = addr.port() ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);
        write_u16_be(attr, xor_port);

        // XOR Address (address XOR magic cookie + txn_id)
        auto ip_bytes = addr.address().to_v6().to_bytes();

        // XOR with magic cookie (first 4 bytes)
        attr.push_back(ip_bytes[0] ^ static_cast<uint8_t>(STUN_MAGIC_COOKIE >> 24));
        attr.push_back(ip_bytes[1] ^ static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 16) & 0xFF));
        attr.push_back(ip_bytes[2] ^ static_cast<uint8_t>((STUN_MAGIC_COOKIE >> 8) & 0xFF));
        attr.push_back(ip_bytes[3] ^ static_cast<uint8_t>(STUN_MAGIC_COOKIE & 0xFF));

        // XOR with transaction ID (remaining 12 bytes)
        for (size_t i = 4; i < 16; ++i) {
            attr.push_back(ip_bytes[i] ^ txn_id[i - 4]);
        }
    }

    return attr;
}

} // namespace edgelink::controller

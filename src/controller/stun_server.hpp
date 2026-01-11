#pragma once

#include <boost/asio.hpp>
#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace asio = boost::asio;

namespace edgelink::controller {

// STUN 消息类型 (RFC 5389)
enum class StunMsgType : uint16_t {
    BINDING_REQUEST = 0x0001,
    BINDING_RESPONSE = 0x0101,
    BINDING_ERROR = 0x0111,
};

// STUN 属性类型
enum class StunAttrType : uint16_t {
    MAPPED_ADDRESS = 0x0001,
    XOR_MAPPED_ADDRESS = 0x0020,
    SOFTWARE = 0x8022,
    FINGERPRINT = 0x8028,
};

// STUN 魔数 (RFC 5389)
inline constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN 头部大小
inline constexpr size_t STUN_HEADER_SIZE = 20;
inline constexpr size_t STUN_TXN_ID_SIZE = 12;

/**
 * RFC 5389 兼容的 STUN 服务器
 *
 * 仅实现 Binding Request/Response，用于 NAT 类型检测和端点发现
 */
class StunServer {
public:
    StunServer(asio::io_context& ioc, const std::string& bind_address, uint16_t port);
    ~StunServer();

    // 设置公网 IP（用于 XOR-MAPPED-ADDRESS）
    void set_public_ip(const std::string& ip);

    // 启动服务
    asio::awaitable<void> start();

    // 停止服务
    void stop();

    // 是否正在运行
    bool is_running() const { return running_; }

    // 获取监听端口
    uint16_t port() const { return port_; }

    // 获取公网 IP
    const std::string& public_ip() const { return public_ip_; }

private:
    // UDP 接收循环
    asio::awaitable<void> recv_loop();

    // 处理 STUN 请求
    void handle_request(const asio::ip::udp::endpoint& from,
                        std::span<const uint8_t> data);

    // 构建 Binding Response
    std::vector<uint8_t> build_binding_response(
        const asio::ip::udp::endpoint& client_addr,
        std::span<const uint8_t> txn_id);

    // 构建 XOR-MAPPED-ADDRESS 属性
    std::vector<uint8_t> build_xor_mapped_address(
        const asio::ip::udp::endpoint& addr,
        std::span<const uint8_t> txn_id);

    // 验证 STUN 消息格式
    bool validate_stun_message(std::span<const uint8_t> data);

    asio::io_context& ioc_;
    std::string bind_address_;
    uint16_t port_;
    std::string public_ip_;

    std::unique_ptr<asio::ip::udp::socket> socket_;
    std::atomic<bool> running_{false};

    // 接收缓冲区
    std::array<uint8_t, 1500> recv_buffer_;
    asio::ip::udp::endpoint sender_endpoint_;
};

} // namespace edgelink::controller

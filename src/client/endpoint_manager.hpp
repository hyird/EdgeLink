#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <chrono>
#include <boost/asio.hpp>

namespace edgelink::client {

// 端点类型
enum class EndpointType {
    LAN,        // 局域网地址
    WAN,        // 公网地址 (通过STUN发现)
    RELAY       // Relay地址
};

// 端点信息
struct Endpoint {
    std::string address;        // IP地址
    uint16_t port;              // 端口
    EndpointType type;          // 端点类型
    int priority;               // 优先级 (数字越小优先级越高)
    std::chrono::steady_clock::time_point discovered_at;
    
    std::string to_string() const {
        return address + ":" + std::to_string(port);
    }
};

// NAT类型
enum class NatType {
    UNKNOWN,
    OPEN,               // 无NAT或全锥形
    FULL_CONE,          // 全锥形NAT
    RESTRICTED_CONE,    // 受限锥形NAT
    PORT_RESTRICTED,    // 端口受限锥形NAT
    SYMMETRIC           // 对称NAT (P2P困难)
};

inline const char* nat_type_to_string(NatType type) {
    switch (type) {
        case NatType::UNKNOWN: return "unknown";
        case NatType::OPEN: return "open";
        case NatType::FULL_CONE: return "full_cone";
        case NatType::RESTRICTED_CONE: return "restricted_cone";
        case NatType::PORT_RESTRICTED: return "port_restricted";
        case NatType::SYMMETRIC: return "symmetric";
        default: return "unknown";
    }
}

// STUN服务器配置
struct StunServer {
    std::string host;
    uint16_t port = 3478;
};

// EndpointManager配置
struct EndpointManagerConfig {
    std::vector<StunServer> stun_servers = {
        {"stun.l.google.com", 19302},
        {"stun1.l.google.com", 19302},
        {"stun.cloudflare.com", 3478}
    };
    
    uint16_t local_udp_port = 0;        // 0 = 系统分配
    std::chrono::seconds stun_interval{300};  // STUN刷新间隔
    std::chrono::seconds stun_timeout{5};     // STUN超时
    bool enable_upnp = false;           // UPnP端口映射 (暂不实现)
};

/**
 * EndpointManager - 端点发现和管理
 * 
 * 功能:
 * 1. 收集本地LAN地址
 * 2. 通过STUN发现公网地址和NAT类型
 * 3. 管理UDP socket用于P2P通信
 * 4. 定期刷新端点信息
 */
class EndpointManager : public std::enable_shared_from_this<EndpointManager> {
public:
    using EndpointCallback = std::function<void(const std::vector<Endpoint>&)>;
    using NatTypeCallback = std::function<void(NatType)>;
    
    explicit EndpointManager(boost::asio::io_context& ioc, 
                            const EndpointManagerConfig& config = {});
    ~EndpointManager();
    
    // 启动/停止
    void start();
    void stop();
    
    // 获取当前端点
    std::vector<Endpoint> get_endpoints() const;
    
    // 获取NAT类型
    NatType get_nat_type() const { return nat_type_.load(); }
    std::string get_nat_type_string() const;
    
    // 获取公网地址 (如果已发现)
    std::optional<Endpoint> get_public_endpoint() const;
    
    // 获取UDP socket用于P2P (仅在需要P2P时使用)
    boost::asio::ip::udp::socket& get_udp_socket() { return udp_socket_; }
    
    // 强制刷新端点
    void refresh();
    
    // 回调设置
    void set_endpoint_callback(EndpointCallback cb) { endpoint_callback_ = std::move(cb); }
    void set_nat_type_callback(NatTypeCallback cb) { nat_type_callback_ = std::move(cb); }
    
private:
    // 收集本地LAN地址
    void collect_local_addresses();
    
    // STUN相关
    void start_stun_discovery();
    void send_stun_request(const StunServer& server);
    void handle_stun_response(const boost::system::error_code& ec, 
                              std::size_t bytes_received,
                              const boost::asio::ip::udp::endpoint& sender);
    void schedule_stun_refresh();
    
    // STUN报文解析
    struct StunResult {
        bool success = false;
        std::string mapped_address;
        uint16_t mapped_port = 0;
        bool changed_address = false;
    };
    StunResult parse_stun_response(const uint8_t* data, size_t len);
    std::vector<uint8_t> build_stun_binding_request();
    
    // 通知端点更新
    void notify_endpoints_changed();
    
    boost::asio::io_context& ioc_;
    EndpointManagerConfig config_;
    
    // UDP socket
    boost::asio::ip::udp::socket udp_socket_;
    uint16_t local_port_ = 0;
    
    // 端点列表
    mutable std::mutex endpoints_mutex_;
    std::vector<Endpoint> endpoints_;
    
    // NAT类型
    std::atomic<NatType> nat_type_{NatType::UNKNOWN};
    
    // STUN状态
    std::array<uint8_t, 12> stun_transaction_id_;
    boost::asio::ip::udp::endpoint stun_server_endpoint_;
    std::vector<uint8_t> stun_recv_buffer_;
    boost::asio::steady_timer stun_timer_;
    int stun_attempt_ = 0;
    
    // 刷新定时器
    boost::asio::steady_timer refresh_timer_;
    
    // 运行状态
    std::atomic<bool> running_{false};
    
    // 回调
    EndpointCallback endpoint_callback_;
    NatTypeCallback nat_type_callback_;
};

} // namespace edgelink::client

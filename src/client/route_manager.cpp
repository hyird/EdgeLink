#include "client/route_manager.hpp"
#include "client/client.hpp"
#include "common/logger.hpp"

#include <sstream>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")
#else
#include <cstring>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#endif

namespace edgelink::client {

namespace {
    Logger& log() {
        static Logger& logger = Logger::get("client.route");
        return logger;
    }
}

RouteManager::RouteManager(Client& client)
    : client_(client) {
}

RouteManager::~RouteManager() {
    stop();
}

bool RouteManager::start() {
    if (running_) return true;

    // 检查 TUN 设备是否启用
    if (!client_.is_tun_enabled()) {
        log().debug("TUN not enabled, route manager disabled");
        return false;
    }

    auto* tun = client_.tun_device();
    if (!tun) {
        log().warn("TUN device not available");
        return false;
    }

    tun_name_ = tun->name();
    if (tun_name_.empty()) {
        log().warn("TUN device name is empty");
        return false;
    }

    if (!get_tun_interface_index()) {
        log().error("Failed to get TUN interface index for {}", tun_name_);
        return false;
    }

    running_ = true;
    log().info("Route manager started, TUN interface: {} (index {})", tun_name_, tun_ifindex_);
    return true;
}

void RouteManager::stop() {
    if (!running_) return;

    cleanup_all();
    running_ = false;
    log().info("Route manager stopped");
}

void RouteManager::apply_route_update(const std::vector<RouteInfo>& add_routes,
                                      const std::vector<RouteInfo>& del_routes) {
    if (!running_) return;

    // 删除路由
    for (const auto& route : del_routes) {
        del_system_route(route);
    }

    // 添加路由
    for (const auto& route : add_routes) {
        add_system_route(route);
    }
}

void RouteManager::sync_routes(const std::vector<RouteInfo>& routes) {
    if (!running_) return;

    std::lock_guard lock(mutex_);

    // 构建新路由集合
    std::set<std::string> new_routes;
    for (const auto& route : routes) {
        new_routes.insert(route_key(route));
    }

    // 删除不再需要的路由
    for (auto it = managed_routes_.begin(); it != managed_routes_.end(); ) {
        if (new_routes.find(*it) == new_routes.end()) {
            // 解析并删除
            // route_key 格式: "prefix/len->gateway_node"
            // 这里简化处理，直接从 routes 参数找
            it = managed_routes_.erase(it);
        } else {
            ++it;
        }
    }

    // 添加新路由
    for (const auto& route : routes) {
        std::string key = route_key(route);
        if (managed_routes_.find(key) == managed_routes_.end()) {
            if (add_system_route(route)) {
                managed_routes_.insert(key);
            }
        }
    }
}

void RouteManager::cleanup_all() {
    std::lock_guard lock(mutex_);

    log().debug("Cleaning up {} managed routes", managed_routes_.size());

    // 由于我们只存储了 key，清理时需要遍历当前路由列表
    // 这里简化实现：依赖 stop() 时 TUN 设备关闭会自动删除路由
    // 更完整的实现需要保存完整的 RouteInfo

    managed_routes_.clear();
}

size_t RouteManager::route_count() const {
    std::lock_guard lock(mutex_);
    return managed_routes_.size();
}

std::string RouteManager::route_key(const RouteInfo& route) {
    std::ostringstream oss;
    // 将 prefix 转换为可读格式 (IPv4 存储在前 4 字节)
    oss << static_cast<int>(route.prefix[0]) << "."
        << static_cast<int>(route.prefix[1]) << "."
        << static_cast<int>(route.prefix[2]) << "."
        << static_cast<int>(route.prefix[3])
        << "/" << static_cast<int>(route.prefix_len)
        << "->" << route.gateway_node;
    return oss.str();
}

// 从 RouteInfo 的 prefix 数组提取 IPv4 地址 (网络字节序)
static uint32_t get_ipv4_prefix_network_order(const RouteInfo& route) {
    // prefix 数组存储的是大端序 (网络字节序)
    return (static_cast<uint32_t>(route.prefix[0]) << 24) |
           (static_cast<uint32_t>(route.prefix[1]) << 16) |
           (static_cast<uint32_t>(route.prefix[2]) << 8) |
           static_cast<uint32_t>(route.prefix[3]);
}

// 获取 gateway 节点的虚拟 IP (返回 0 表示无效)
static uint32_t get_gateway_ip_u32(Client& client, NodeId gateway_node) {
    auto peer = client.peers().get_peer(gateway_node);
    if (peer) {
        return peer->info.virtual_ip.to_u32();
    }
    return 0;
}

// 获取 gateway 节点虚拟 IP 的字符串表示
static std::string get_gateway_ip_str(Client& client, NodeId gateway_node) {
    auto peer = client.peers().get_peer(gateway_node);
    if (peer) {
        return peer->info.virtual_ip.to_string();
    }
    return "";
}

#ifdef _WIN32
// ============================================================================
// Windows 实现 - 使用 IP Helper API
// ============================================================================

bool RouteManager::get_tun_interface_index() {
    // 通过接口名获取 LUID
    std::wstring wide_name(tun_name_.begin(), tun_name_.end());

    NET_LUID luid;
    DWORD result = ConvertInterfaceAliasToLuid(wide_name.c_str(), &luid);
    if (result != NO_ERROR) {
        // 尝试使用接口名作为 GUID
        result = ConvertInterfaceNameToLuidW(wide_name.c_str(), &luid);
        if (result != NO_ERROR) {
            log().error("ConvertInterfaceAliasToLuid failed: {}", result);
            return false;
        }
    }

    tun_luid_ = luid.Value;

    // 获取接口索引
    NET_IFINDEX ifindex;
    result = ConvertInterfaceLuidToIndex(&luid, &ifindex);
    if (result != NO_ERROR) {
        log().error("ConvertInterfaceLuidToIndex failed: {}", result);
        return false;
    }

    tun_ifindex_ = ifindex;
    return true;
}

bool RouteManager::add_system_route(const RouteInfo& route) {
    // 只处理 IPv4 路由
    if (route.ip_type != IpType::IPv4) {
        return false;
    }

    // 不添加自己公告的路由
    if (route.gateway_node == client_.node_id()) {
        return false;
    }

    // 查找 gateway 节点的虚拟 IP
    uint32_t gateway_ip = get_gateway_ip_u32(client_, route.gateway_node);
    if (gateway_ip == 0) {
        log().warn("Gateway node {} not found, skipping route", route.gateway_node);
        return false;
    }

    MIB_IPFORWARD_ROW2 row = {};
    InitializeIpForwardEntry(&row);

    // 设置目标网络 (prefix 已经是网络字节序)
    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(get_ipv4_prefix_network_order(route));
    row.DestinationPrefix.PrefixLength = route.prefix_len;

    // 设置下一跳 (gateway 节点的虚拟 IP)
    row.NextHop.si_family = AF_INET;
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(gateway_ip);

    // 设置接口
    NET_LUID luid;
    luid.Value = tun_luid_;
    row.InterfaceLuid = luid;
    row.InterfaceIndex = tun_ifindex_;

    // 路由属性
    row.ValidLifetime = 0xFFFFFFFF;  // 永久
    row.PreferredLifetime = 0xFFFFFFFF;
    row.Metric = route.metric;
    row.Protocol = static_cast<NL_ROUTE_PROTOCOL>(MIB_IPPROTO_NETMGMT);
    row.Loopback = FALSE;
    row.AutoconfigureAddress = FALSE;
    row.Immortal = FALSE;
    row.Age = 0;
    row.Origin = NlroManual;

    DWORD result = CreateIpForwardEntry2(&row);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
        log().error("CreateIpForwardEntry2 failed: {} for route {}", result, route_key(route));
        return false;
    }

    log().info("Added route: {} via {}", route_key(route), get_gateway_ip_str(client_, route.gateway_node));
    return true;
}

bool RouteManager::del_system_route(const RouteInfo& route) {
    if (route.ip_type != IpType::IPv4) {
        return false;
    }

    uint32_t gateway_ip = get_gateway_ip_u32(client_, route.gateway_node);
    if (gateway_ip == 0) {
        return false;
    }

    MIB_IPFORWARD_ROW2 row = {};
    InitializeIpForwardEntry(&row);

    row.DestinationPrefix.Prefix.si_family = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(get_ipv4_prefix_network_order(route));
    row.DestinationPrefix.PrefixLength = route.prefix_len;

    row.NextHop.si_family = AF_INET;
    row.NextHop.Ipv4.sin_addr.s_addr = htonl(gateway_ip);

    NET_LUID luid;
    luid.Value = tun_luid_;
    row.InterfaceLuid = luid;
    row.InterfaceIndex = tun_ifindex_;

    DWORD result = DeleteIpForwardEntry2(&row);
    if (result != NO_ERROR && result != ERROR_NOT_FOUND) {
        log().warn("DeleteIpForwardEntry2 failed: {} for route {}", result, route_key(route));
        return false;
    }

    log().info("Deleted route: {}", route_key(route));
    return true;
}

#else
// ============================================================================
// Linux 实现 - 使用 Netlink
// ============================================================================

bool RouteManager::get_tun_interface_index() {
    tun_ifindex_ = if_nametoindex(tun_name_.c_str());
    if (tun_ifindex_ == 0) {
        log().error("if_nametoindex failed for {}: {}", tun_name_, strerror(errno));
        return false;
    }
    return true;
}

namespace {
    // Netlink 请求结构
    struct RouteRequest {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
        char buf[256];
    };

    // 添加 Netlink 属性
    int add_attr(struct nlmsghdr* n, int maxlen, int type, const void* data, int len) {
        int attr_len = RTA_LENGTH(len);
        if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(attr_len) > static_cast<unsigned>(maxlen)) {
            return -1;
        }

        struct rtattr* rta = reinterpret_cast<struct rtattr*>(
            reinterpret_cast<char*>(n) + NLMSG_ALIGN(n->nlmsg_len));
        rta->rta_type = type;
        rta->rta_len = attr_len;
        memcpy(RTA_DATA(rta), data, len);
        n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(attr_len);
        return 0;
    }

    // 发送 Netlink 消息并等待响应
    bool send_netlink_route(struct nlmsghdr* nlh) {
        int sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
        if (sock < 0) {
            log().error("Failed to create netlink socket: {}", strerror(errno));
            return false;
        }

        struct sockaddr_nl addr = {};
        addr.nl_family = AF_NETLINK;

        if (bind(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            log().error("Failed to bind netlink socket: {}", strerror(errno));
            close(sock);
            return false;
        }

        struct sockaddr_nl dest = {};
        dest.nl_family = AF_NETLINK;

        struct iovec iov = { nlh, nlh->nlmsg_len };
        struct msghdr msg = {};
        msg.msg_name = &dest;
        msg.msg_namelen = sizeof(dest);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        if (sendmsg(sock, &msg, 0) < 0) {
            log().error("Failed to send netlink message: {}", strerror(errno));
            close(sock);
            return false;
        }

        // 等待 ACK
        char buf[4096];
        struct iovec recv_iov = { buf, sizeof(buf) };
        msg.msg_iov = &recv_iov;

        ssize_t len = recvmsg(sock, &msg, 0);
        close(sock);

        if (len < 0) {
            log().error("Failed to receive netlink response: {}", strerror(errno));
            return false;
        }

        struct nlmsghdr* resp = reinterpret_cast<struct nlmsghdr*>(buf);
        if (resp->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* err = static_cast<struct nlmsgerr*>(NLMSG_DATA(resp));
            if (err->error != 0 && err->error != -EEXIST && err->error != -ESRCH) {
                log().error("Netlink error: {}", strerror(-err->error));
                return false;
            }
        }

        return true;
    }
}

bool RouteManager::add_system_route(const RouteInfo& route) {
    // 只处理 IPv4 路由
    if (route.ip_type != IpType::IPv4) {
        return false;
    }

    // 不添加自己公告的路由
    if (route.gateway_node == client_.node_id()) {
        return false;
    }

    // 查找 gateway 节点的虚拟 IP
    uint32_t gateway_ip = get_gateway_ip_u32(client_, route.gateway_node);
    if (gateway_ip == 0) {
        log().warn("Gateway node {} not found, skipping route", route.gateway_node);
        return false;
    }

    RouteRequest req = {};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_NEWROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_dst_len = route.prefix_len;
    req.rtm.rtm_src_len = 0;
    req.rtm.rtm_tos = 0;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_protocol = RTPROT_STATIC;
    req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rtm.rtm_type = RTN_UNICAST;

    // 目标网络
    uint32_t dst = htonl(get_ipv4_prefix_network_order(route));
    add_attr(&req.nlh, sizeof(req), RTA_DST, &dst, 4);

    // 下一跳
    uint32_t gw = htonl(gateway_ip);
    add_attr(&req.nlh, sizeof(req), RTA_GATEWAY, &gw, 4);

    // 出接口
    add_attr(&req.nlh, sizeof(req), RTA_OIF, &tun_ifindex_, 4);

    // Metric
    uint32_t metric = route.metric;
    add_attr(&req.nlh, sizeof(req), RTA_PRIORITY, &metric, 4);

    if (!send_netlink_route(&req.nlh)) {
        log().error("Failed to add route: {}", route_key(route));
        return false;
    }

    log().info("Added route: {} via {}", route_key(route), get_gateway_ip_str(client_, route.gateway_node));
    return true;
}

bool RouteManager::del_system_route(const RouteInfo& route) {
    if (route.ip_type != IpType::IPv4) {
        return false;
    }

    uint32_t gateway_ip = get_gateway_ip_u32(client_, route.gateway_node);
    if (gateway_ip == 0) {
        return false;
    }

    RouteRequest req = {};

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_DELROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq = 1;

    req.rtm.rtm_family = AF_INET;
    req.rtm.rtm_dst_len = route.prefix_len;
    req.rtm.rtm_table = RT_TABLE_MAIN;
    req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;

    uint32_t dst = htonl(get_ipv4_prefix_network_order(route));
    add_attr(&req.nlh, sizeof(req), RTA_DST, &dst, 4);

    uint32_t gw = htonl(gateway_ip);
    add_attr(&req.nlh, sizeof(req), RTA_GATEWAY, &gw, 4);

    add_attr(&req.nlh, sizeof(req), RTA_OIF, &tun_ifindex_, 4);

    if (!send_netlink_route(&req.nlh)) {
        log().warn("Failed to delete route: {}", route_key(route));
        return false;
    }

    log().info("Deleted route: {}", route_key(route));
    return true;
}

#endif

} // namespace edgelink::client

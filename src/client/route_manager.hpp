#pragma once

#include "common/types.hpp"
#include <boost/asio.hpp>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace asio = boost::asio;

namespace edgelink::client {

// Forward declarations
class Client;

// 系统路由表管理器 - 将虚拟网络路由添加到操作系统路由表
class RouteManager {
public:
    explicit RouteManager(Client& client);
    ~RouteManager();

    // 启动路由管理器 (获取 TUN 设备接口索引等)
    bool start();

    // 停止并清理所有添加的路由
    void stop();

    // 应用路由更新 (添加新路由，删除旧路由)
    void apply_route_update(const std::vector<RouteInfo>& add_routes,
                           const std::vector<RouteInfo>& del_routes);

    // 同步所有路由 (清理旧的，添加当前的)
    void sync_routes(const std::vector<RouteInfo>& routes);

    // 清理所有由本管理器添加的路由
    void cleanup_all();

    // 获取当前管理的路由数量
    size_t route_count() const;

private:
    // 添加单条路由到系统
    bool add_system_route(const RouteInfo& route);

    // 删除单条路由
    bool del_system_route(const RouteInfo& route);

    // 获取 TUN 接口索引
    bool get_tun_interface_index();

    // 生成路由标识 (用于跟踪)
    static std::string route_key(const RouteInfo& route);

    Client& client_;
    bool running_ = false;

    // 已添加到系统的路由 (用于清理时能获取完整 RouteInfo)
    std::map<std::string, RouteInfo> managed_routes_;
    mutable std::mutex mutex_;

    // TUN 接口信息
    std::string tun_name_;
    uint32_t tun_ifindex_ = 0;

#ifdef _WIN32
    // Windows: 使用 IP Helper API
    uint64_t tun_luid_ = 0;
#endif
};

} // namespace edgelink::client

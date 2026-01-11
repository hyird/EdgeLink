#pragma once

#include <string>
#include <functional>
#include <memory>
#include <chrono>
#include <filesystem>
#include <boost/asio.hpp>

namespace edgelink::client {

struct ClientConfig;

// 配置文件变更回调
using ConfigChangeCallback = std::function<void(const ClientConfig&)>;

// 配置文件监控器
class ConfigWatcher : public std::enable_shared_from_this<ConfigWatcher> {
public:
    ConfigWatcher(boost::asio::io_context& ioc, const std::string& config_path);
    ~ConfigWatcher();

    // 启动监控
    void start(ConfigChangeCallback callback);

    // 停止监控
    void stop();

    // 手动触发重载
    bool reload();

    // 设置轮询间隔
    void set_interval(std::chrono::seconds interval) { interval_ = interval; }

    // 获取配置文件路径
    const std::string& config_path() const { return config_path_; }

private:
    // 监控循环
    boost::asio::awaitable<void> watch_loop();

    // 检查文件是否变更
    bool check_file_changed();

    // 计算文件哈希
    std::string compute_file_hash();

    boost::asio::io_context& ioc_;
    std::string config_path_;
    ConfigChangeCallback callback_;
    std::chrono::seconds interval_{5};
    bool running_ = false;

    // 上次文件状态
    std::filesystem::file_time_type last_write_time_;
    std::string last_hash_;
};

}  // namespace edgelink::client

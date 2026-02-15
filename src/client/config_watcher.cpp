#include "client/config_watcher.hpp"
#include "client/client.hpp"
#include "common/config.hpp"
#include "common/logger.hpp"
#include "common/cobalt_utils.hpp"
#include <fstream>
#include <sstream>
#include <openssl/sha.h>

namespace cobalt = boost::cobalt;

namespace edgelink::client {

ConfigWatcher::ConfigWatcher(boost::asio::io_context& ioc, const std::string& config_path)
    : ioc_(ioc), config_path_(config_path) {}

ConfigWatcher::~ConfigWatcher() {
    stop();
}

void ConfigWatcher::set_channel(channels::ConfigChangeChannel* channel) {
    channel_ = channel;
}

void ConfigWatcher::start() {
    if (running_) {
        return;
    }

    running_ = true;

    // 初始化文件状态
    try {
        if (std::filesystem::exists(config_path_)) {
            last_write_time_ = std::filesystem::last_write_time(config_path_);
            last_hash_ = compute_file_hash();
        }
    } catch (const std::exception& e) {
        LOG_WARN("client.config", "初始化配置文件监控失败: {}", e.what());
    }

    // 启动监控协程
    cobalt_utils::spawn_task(ioc_.get_executor(), watch_loop());

    LOG_INFO("client.config", "配置文件监控已启动: {}", config_path_);
}

void ConfigWatcher::stop() {
    running_ = false;
}

bool ConfigWatcher::reload() {
    if (!channel_) {
        LOG_WARN("client.config", "配置重载失败: 未设置通道");
        return false;
    }

    auto result = edgelink::ClientConfig::load(config_path_);
    if (!result.has_value()) {
        LOG_ERROR("client.config", "配置重载失败: {}", edgelink::config_error_message(result.error()));
        return false;
    }

    // 更新文件状态
    try {
        last_write_time_ = std::filesystem::last_write_time(config_path_);
        last_hash_ = compute_file_hash();
    } catch (const std::exception& e) {
        LOG_DEBUG("client.config", "Failed to update file status: {}", e.what());
    } catch (...) {
        LOG_DEBUG("client.config", "Failed to update file status: unknown error");
    }

    // 转换为 client::ClientConfig
    ClientConfig cfg;
    cfg.controller_url = result->controller_url;
    cfg.authkey = result->authkey;
    cfg.tls = result->tls;
    cfg.auto_reconnect = result->auto_reconnect;
    cfg.reconnect_interval = result->reconnect_interval;
    cfg.ping_interval = result->ping_interval;
    cfg.dns_refresh_interval = result->dns_refresh_interval;
    cfg.latency_measure_interval = result->latency_measure_interval;
    cfg.ssl_verify = result->ssl_verify;
    cfg.ssl_ca_file = result->ssl_ca_file;
    cfg.ssl_allow_self_signed = result->ssl_allow_self_signed;
    cfg.state_dir = result->state_dir;
    cfg.enable_tun = result->enable_tun;
    cfg.tun_name = result->tun_name;
    cfg.tun_mtu = result->tun_mtu;
    cfg.advertise_routes = result->advertise_routes;
    cfg.exit_node = result->exit_node;
    cfg.accept_routes = result->accept_routes;
    cfg.log_level = result->log_level;
    cfg.log_file = result->log_file;

    // 通过 channel 发送配置变更
    channel_->try_send(std::move(cfg));

    LOG_INFO("client.config", "配置已重新加载");
    return true;
}

cobalt::task<void> ConfigWatcher::watch_loop() {
    boost::asio::steady_timer timer(ioc_);

    while (running_) {
        timer.expires_after(interval_);

        try {
            co_await timer.async_wait(cobalt::use_op);
        } catch (const boost::system::system_error& e) {
            if (e.code() == boost::asio::error::operation_aborted) {
                break;
            }
            throw;
        }

        if (!running_) {
            break;
        }

        // 检查文件变更
        if (check_file_changed()) {
            LOG_DEBUG("client.config", "检测到配置文件变更，正在重新加载...");
            reload();
        }
    }

    LOG_DEBUG("client.config", "配置文件监控已停止");
}

bool ConfigWatcher::check_file_changed() {
    try {
        if (!std::filesystem::exists(config_path_)) {
            return false;
        }

        // 首先检查修改时间
        auto current_time = std::filesystem::last_write_time(config_path_);
        if (current_time == last_write_time_) {
            return false;
        }

        // 修改时间变了，检查内容哈希
        std::string current_hash = compute_file_hash();
        if (current_hash == last_hash_) {
            // 仅时间戳变化，内容未变
            last_write_time_ = current_time;
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        LOG_WARN("client.config", "检查配置文件变更失败: {}", e.what());
        return false;
    }
}

std::string ConfigWatcher::compute_file_hash() {
    std::ifstream file(config_path_, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // 计算 SHA-256 哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(content.data()), content.size(), hash);

    // 转换为十六进制字符串
    std::string result;
    result.reserve(SHA256_DIGEST_LENGTH * 2);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result += hex[hash[i] >> 4];
        result += hex[hash[i] & 0x0f];
    }

    return result;
}

}  // namespace edgelink::client

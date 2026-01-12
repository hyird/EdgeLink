// Actor 系统和线程池管理
// 提供多线程 io_context 和 Actor 路由功能

#pragma once

#include "common/actor.hpp"
#include "common/logger.hpp"
#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <string>

namespace asio = boost::asio;

namespace edgelink::actor {

// ============================================================================
// Actor 地址（用于路由）
// ============================================================================

struct ActorAddress {
    std::string name;
    std::string path;  // 例如: "/client/control", "/server/session/node_123"

    bool operator==(const ActorAddress& other) const {
        return name == other.name && path == other.path;
    }

    std::string to_string() const {
        return path + " (" + name + ")";
    }
};

// Hash for ActorAddress
struct ActorAddressHash {
    size_t operator()(const ActorAddress& addr) const {
        return std::hash<std::string>{}(addr.path);
    }
};

// ============================================================================
// Actor 路由表（全局消息路由）
// ============================================================================

class ActorRouter {
public:
    explicit ActorRouter(asio::io_context& ioc) : ioc_(ioc) {}

    // 禁止拷贝和移动
    ActorRouter(const ActorRouter&) = delete;
    ActorRouter& operator=(const ActorRouter&) = delete;
    ActorRouter(ActorRouter&&) = delete;
    ActorRouter& operator=(ActorRouter&&) = delete;

    // 注册 Actor
    void register_actor(const ActorAddress& addr, std::shared_ptr<void> actor) {
        std::unique_lock lock(mutex_);
        actors_[addr] = actor;
        log().debug("ActorRouter: registered actor at {}", addr.to_string());
    }

    // 注销 Actor
    void unregister_actor(const ActorAddress& addr) {
        std::unique_lock lock(mutex_);
        actors_.erase(addr);
        log().debug("ActorRouter: unregistered actor at {}", addr.to_string());
    }

    // 查找 Actor
    template<typename ActorType>
    std::shared_ptr<ActorType> find_actor(const ActorAddress& addr) {
        std::shared_lock lock(mutex_);
        auto it = actors_.find(addr);
        if (it == actors_.end()) {
            return nullptr;
        }
        return std::static_pointer_cast<ActorType>(it->second);
    }

    // 检查 Actor 是否存在
    bool has_actor(const ActorAddress& addr) const {
        std::shared_lock lock(mutex_);
        return actors_.find(addr) != actors_.end();
    }

    // 获取所有 Actor 地址
    std::vector<ActorAddress> get_all_addresses() const {
        std::shared_lock lock(mutex_);
        std::vector<ActorAddress> addrs;
        addrs.reserve(actors_.size());
        for (const auto& [addr, _] : actors_) {
            addrs.push_back(addr);
        }
        return addrs;
    }

private:
    asio::io_context& ioc_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<ActorAddress, std::shared_ptr<void>, ActorAddressHash> actors_;

    edgelink::Logger& log() {
        static auto logger = edgelink::Logger::get("ActorRouter");
        return logger;
    }
};

// ============================================================================
// Actor 系统（管理线程池和路由）
// ============================================================================

class ActorSystem {
public:
    // 配置
    struct Config {
        size_t worker_threads = std::thread::hardware_concurrency();  // 通用工作线程数
        size_t high_priority_threads = 1;   // 高优先级线程数（用于 DataPlane）
        bool enable_cpu_affinity = false;   // 是否启用 CPU 亲和性
        std::string name = "ActorSystem";   // 系统名称（用于日志）
    };

    explicit ActorSystem(const Config& config = Config{})
        : config_(config)
        , ioc_(config.worker_threads)
        , work_guard_(asio::make_work_guard(ioc_))
        , router_(ioc_)
        , running_(false) {
        log().info("ActorSystem created: {} worker threads, {} high-priority threads",
                   config_.worker_threads, config_.high_priority_threads);
    }

    ~ActorSystem() {
        if (running_.load()) {
            stop();
        }
    }

    // 禁止拷贝和移动
    ActorSystem(const ActorSystem&) = delete;
    ActorSystem& operator=(const ActorSystem&) = delete;
    ActorSystem(ActorSystem&&) = delete;
    ActorSystem& operator=(ActorSystem&&) = delete;

    // 启动 Actor 系统
    void start() {
        if (running_.exchange(true)) {
            log().warn("ActorSystem already running");
            return;
        }

        log().info("Starting ActorSystem...");

        // 启动通用工作线程池
        for (size_t i = 0; i < config_.worker_threads; ++i) {
            workers_.emplace_back([this, i]() {
                set_thread_name("actor-worker-" + std::to_string(i));

                // CPU 亲和性设置（可选）
                if (config_.enable_cpu_affinity) {
                    set_cpu_affinity(i);
                }

                log().debug("Worker thread {} started", i);

                try {
                    // 运行事件循环
                    ioc_.run();
                } catch (const std::exception& e) {
                    log().error("Worker thread {} exception: {}", i, e.what());
                }

                log().debug("Worker thread {} stopped", i);
            });
        }

        // 启动高优先级线程（专用于 DataPlane 等关键路径）
        for (size_t i = 0; i < config_.high_priority_threads; ++i) {
            high_priority_workers_.emplace_back([this, i]() {
                set_thread_name("actor-hp-" + std::to_string(i));
                set_thread_priority_high();

                log().debug("High-priority thread {} started", i);

                try {
                    // 独立的 io_context 用于高优先级任务
                    asio::io_context high_priority_ioc(1);
                    asio::io_context::work work(high_priority_ioc);
                    high_priority_ioc.run();
                } catch (const std::exception& e) {
                    log().error("High-priority thread {} exception: {}", i, e.what());
                }

                log().debug("High-priority thread {} stopped", i);
            });
        }

        log().info("ActorSystem started");
    }

    // 停止 Actor 系统
    void stop() {
        if (!running_.exchange(false)) {
            log().warn("ActorSystem not running");
            return;
        }

        log().info("Stopping ActorSystem...");

        // 停止接受新任务
        work_guard_.reset();
        ioc_.stop();

        // 等待所有工作线程结束
        for (auto& t : workers_) {
            if (t.joinable()) {
                t.join();
            }
        }

        // 等待所有高优先级线程结束
        for (auto& t : high_priority_workers_) {
            if (t.joinable()) {
                t.join();
            }
        }

        workers_.clear();
        high_priority_workers_.clear();

        log().info("ActorSystem stopped");
    }

    // 获取 io_context
    asio::io_context& io_context() { return ioc_; }

    // 获取路由器
    ActorRouter& router() { return router_; }

    // 检查是否正在运行
    bool is_running() const { return running_.load(); }

    // 获取配置
    const Config& config() const { return config_; }

private:
    // 设置线程名称（用于调试）
    void set_thread_name(const std::string& name) {
#ifdef _WIN32
        // Windows: SetThreadDescription (Windows 10+ only)
        // 简化实现，跳过
#else
        // Linux/macOS: pthread_setname_np
        pthread_setname_np(pthread_self(), name.c_str());
#endif
    }

    // 设置 CPU 亲和性
    void set_cpu_affinity(size_t cpu_id) {
#ifdef __linux__
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_id % std::thread::hardware_concurrency(), &cpuset);
        pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#else
        // Windows/macOS: 暂不支持
        (void)cpu_id;
#endif
    }

    // 设置线程优先级为高
    void set_thread_priority_high() {
#ifdef _WIN32
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#else
        // Linux/macOS: 需要 root 权限，暂时跳过
#endif
    }

    edgelink::Logger& log() {
        static auto logger = edgelink::Logger::get("ActorSystem");
        return logger;
    }

    Config config_;
    asio::io_context ioc_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    ActorRouter router_;

    std::atomic<bool> running_;
    std::vector<std::thread> workers_;
    std::vector<std::thread> high_priority_workers_;
};

} // namespace edgelink::actor

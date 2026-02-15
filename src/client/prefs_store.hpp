#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include <optional>
#include <mutex>

namespace edgelink {
namespace client {

// Forward declaration
struct ClientConfig;

// 默认配置值
constexpr const char* DEFAULT_CONTROLLER_URL = "edge.a-z.xin";
constexpr bool DEFAULT_TLS = true;

/// 动态配置存储（prefs.json）
/// 用于存储由 `edgelink set` 命令设置的运行时配置
/// 与静态配置文件 config.json 分离
class PrefsStore {
public:
    explicit PrefsStore(const std::filesystem::path& state_dir);
    ~PrefsStore() = default;

    // Non-copyable, movable
    PrefsStore(const PrefsStore&) = delete;
    PrefsStore& operator=(const PrefsStore&) = delete;
    PrefsStore(PrefsStore&&) = default;
    PrefsStore& operator=(PrefsStore&&) = default;

    /// 加载配置文件
    bool load();

    /// 保存配置文件
    bool save();

    /// 获取配置文件路径
    const std::filesystem::path& path() const { return prefs_path_; }

    /// 检查文件是否存在
    bool exists() const;

    /// 获取最后的错误信息
    const std::string& last_error() const { return last_error_; }

    // ========== 连接配置 ==========

    /// 获取 Controller URL
    std::optional<std::string> controller_url() const;

    /// 设置 Controller URL
    void set_controller_url(const std::string& url);

    /// 获取 AuthKey
    std::optional<std::string> authkey() const;

    /// 设置 AuthKey
    void set_authkey(const std::string& key);

    /// 是否启用 TLS
    std::optional<bool> tls() const;

    /// 设置是否启用 TLS
    void set_tls(bool value);

    // ========== Routing 配置 ==========

    /// 获取出口节点（peer name 或 ID）
    std::optional<std::string> exit_node() const;

    /// 设置出口节点
    void set_exit_node(const std::string& node);

    /// 清除出口节点
    void clear_exit_node();

    /// 是否声明为出口节点
    bool advertise_exit_node() const;

    /// 设置是否声明为出口节点
    void set_advertise_exit_node(bool value);

    /// 获取广播的路由列表
    std::vector<std::string> advertise_routes() const;

    /// 设置广播的路由列表
    void set_advertise_routes(const std::vector<std::string>& routes);

    /// 添加一条广播路由
    void add_advertise_route(const std::string& route);

    /// 移除一条广播路由
    void remove_advertise_route(const std::string& route);

    /// 是否接受其他节点的路由
    bool accept_routes() const;

    /// 设置是否接受其他节点的路由
    void set_accept_routes(bool value);

    // ========== 配置合并 ==========

    /// 将 prefs 配置合并到 ClientConfig
    /// prefs 中的配置项会覆盖 ClientConfig 中的对应项
    void apply_to(client::ClientConfig& config) const;

    /// 从 ClientConfig 中提取 prefs 相关的配置
    void extract_from(const client::ClientConfig& config);

private:
    std::filesystem::path prefs_path_;
    std::string last_error_;
    mutable std::mutex mutex_;

    // 配置值存储 - 连接
    std::optional<std::string> controller_url_;
    std::optional<std::string> authkey_;
    std::optional<bool> tls_;

    // 配置值存储 - 路由
    std::optional<std::string> exit_node_;
    bool advertise_exit_node_ = false;
    std::vector<std::string> advertise_routes_;
    bool accept_routes_ = true;

    /// 确保目录存在
    bool ensure_directory();

    /// 生成 JSON 内容
    std::string generate_json() const;
};

/// 获取平台特定的状态目录
/// - Windows: %LOCALAPPDATA%\EdgeLink\
/// - Linux: /var/lib/edgelink/
/// - macOS: ~/Library/Application Support/EdgeLink/
std::filesystem::path get_state_dir();

/// 获取默认的 prefs.json 路径
std::filesystem::path get_default_prefs_path();

} // namespace client
} // namespace edgelink

// Bring types into common namespace for compatibility
namespace edgelink {
    using client::PrefsStore;
    using client::get_state_dir;
    using client::get_default_prefs_path;
}

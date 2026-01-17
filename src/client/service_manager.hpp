#pragma once

#include <filesystem>
#include <string>

namespace edgelink::client {

/// 服务管理状态
enum class ServiceStatus {
    NOT_INSTALLED,  // 未安装
    STOPPED,        // 已安装但未运行
    RUNNING,        // 运行中
    UNKNOWN         // 状态未知
};

/// 跨平台服务管理器
/// 支持 Windows Service、Linux systemd、macOS launchd
class ServiceManager {
public:
    /// 检查服务是否已安装
    static bool is_installed();

    /// 检查服务是否正在运行
    static bool is_running();

    /// 获取服务状态
    static ServiceStatus status();

    /// 安装服务
    /// @param exe_path 可执行文件路径
    /// @return 成功返回 true
    static bool install(const std::filesystem::path& exe_path);

    /// 卸载服务
    static bool uninstall();

    /// 启动服务
    static bool start();

    /// 停止服务
    static bool stop();

    /// 获取服务名称
    static std::string service_name();

    /// 获取服务显示名称
    static std::string display_name();

    /// 获取最后的错误信息
    static const std::string& last_error();

private:
    static std::string last_error_;

#ifdef _WIN32
    // Windows Service Control Manager API
    static bool install_windows(const std::filesystem::path& exe_path);
    static bool uninstall_windows();
    static bool start_windows();
    static bool stop_windows();
    static bool is_installed_windows();
    static bool is_running_windows();
    static ServiceStatus status_windows();
#elif defined(__linux__)
    // Linux systemd
    static bool install_systemd(const std::filesystem::path& exe_path);
    static bool uninstall_systemd();
    static bool start_systemd();
    static bool stop_systemd();
    static bool is_installed_systemd();
    static bool is_running_systemd();
    static ServiceStatus status_systemd();

    // 生成 systemd unit 文件内容
    static std::string generate_unit_file(const std::filesystem::path& exe_path);

    // systemd unit 文件路径
    static std::filesystem::path unit_file_path();
#elif defined(__APPLE__)
    // macOS launchd
    static bool install_launchd(const std::filesystem::path& exe_path);
    static bool uninstall_launchd();
    static bool start_launchd();
    static bool stop_launchd();
    static bool is_installed_launchd();
    static bool is_running_launchd();
    static ServiceStatus status_launchd();

    // 生成 plist 文件内容
    static std::string generate_plist(const std::filesystem::path& exe_path);

    // plist 文件路径
    static std::filesystem::path plist_path();
#endif
};

/// 将服务状态转换为字符串
inline const char* service_status_name(ServiceStatus status) {
    switch (status) {
        case ServiceStatus::NOT_INSTALLED: return "not_installed";
        case ServiceStatus::STOPPED: return "stopped";
        case ServiceStatus::RUNNING: return "running";
        default: return "unknown";
    }
}

} // namespace edgelink::client

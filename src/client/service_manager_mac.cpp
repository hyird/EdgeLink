#if defined(__APPLE__)

#include "service_manager.hpp"
#include "common/logger.hpp"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <array>
#include <unistd.h>
#include <pwd.h>

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("service"); }

constexpr const char* SERVICE_LABEL = "com.edgelink.client";
constexpr const char* DISPLAY_NAME = "EdgeLink Client";

// 执行命令并获取输出
std::pair<int, std::string> exec_command(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) {
        return {-1, "Failed to execute command"};
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    int status = pclose(pipe);
    return {WEXITSTATUS(status), result};
}

// 检查是否是 root 用户
bool is_root() {
    return geteuid() == 0;
}

// 获取用户 home 目录
std::filesystem::path get_home_dir() {
    const char* home = std::getenv("HOME");
    if (home) {
        return std::filesystem::path(home);
    }
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        return std::filesystem::path(pw->pw_dir);
    }
    return std::filesystem::path("/");
}

}

std::string ServiceManager::last_error_;

std::string ServiceManager::service_name() {
    return SERVICE_LABEL;
}

std::string ServiceManager::display_name() {
    return DISPLAY_NAME;
}

const std::string& ServiceManager::last_error() {
    return last_error_;
}

bool ServiceManager::is_installed() {
    return is_installed_launchd();
}

bool ServiceManager::is_running() {
    return is_running_launchd();
}

ServiceStatus ServiceManager::status() {
    return status_launchd();
}

bool ServiceManager::install(const std::filesystem::path& exe_path) {
    return install_launchd(exe_path);
}

bool ServiceManager::uninstall() {
    return uninstall_launchd();
}

bool ServiceManager::start() {
    return start_launchd();
}

bool ServiceManager::stop() {
    return stop_launchd();
}

// ============================================================================
// macOS launchd Implementation
// ============================================================================

std::filesystem::path ServiceManager::plist_path() {
    if (is_root()) {
        // 系统级 daemon
        return std::filesystem::path("/Library/LaunchDaemons") / (std::string(SERVICE_LABEL) + ".plist");
    } else {
        // 用户级 agent
        return get_home_dir() / "Library/LaunchAgents" / (std::string(SERVICE_LABEL) + ".plist");
    }
}

std::string ServiceManager::generate_plist(const std::filesystem::path& exe_path) {
    std::ostringstream oss;

    oss << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        << "<plist version=\"1.0\">\n"
        << "<dict>\n"
        << "    <key>Label</key>\n"
        << "    <string>" << SERVICE_LABEL << "</string>\n"
        << "\n"
        << "    <key>ProgramArguments</key>\n"
        << "    <array>\n"
        << "        <string>" << exe_path.string() << "</string>\n"
        << "        <string>daemon</string>\n"
        << "    </array>\n"
        << "\n"
        << "    <key>RunAtLoad</key>\n"
        << "    <true/>\n"
        << "\n"
        << "    <key>KeepAlive</key>\n"
        << "    <true/>\n"
        << "\n"
        << "    <key>ThrottleInterval</key>\n"
        << "    <integer>5</integer>\n"
        << "\n"
        << "    <key>StandardOutPath</key>\n"
        << "    <string>/var/log/edgelink-client.log</string>\n"
        << "\n"
        << "    <key>StandardErrorPath</key>\n"
        << "    <string>/var/log/edgelink-client.log</string>\n"
        << "</dict>\n"
        << "</plist>\n";

    return oss.str();
}

bool ServiceManager::is_installed_launchd() {
    auto plist = plist_path();
    return std::filesystem::exists(plist);
}

bool ServiceManager::is_running_launchd() {
    std::string cmd = "launchctl list " + std::string(SERVICE_LABEL);
    auto [status, output] = exec_command(cmd);
    return status == 0;
}

ServiceStatus ServiceManager::status_launchd() {
    if (!is_installed_launchd()) {
        return ServiceStatus::NOT_INSTALLED;
    }

    std::string cmd = "launchctl list " + std::string(SERVICE_LABEL);
    auto [status, output] = exec_command(cmd);

    if (status == 0) {
        // 服务已加载，检查是否实际运行
        // launchctl list 输出格式: PID\tStatus\tLabel
        // 如果 PID 是 "-"，表示未运行
        if (output.find("-\t") == 0 || output.find("Could not find service") != std::string::npos) {
            return ServiceStatus::STOPPED;
        }
        return ServiceStatus::RUNNING;
    }

    return ServiceStatus::STOPPED;
}

bool ServiceManager::install_launchd(const std::filesystem::path& exe_path) {
    auto plist = plist_path();

    // 确保目录存在
    auto plist_dir = plist.parent_path();
    std::error_code ec;
    if (!std::filesystem::exists(plist_dir)) {
        std::filesystem::create_directories(plist_dir, ec);
        if (ec) {
            last_error_ = "Failed to create directory: " + plist_dir.string() + " - " + ec.message();
            return false;
        }
    }

    // 生成并写入 plist 文件
    std::string plist_content = generate_plist(exe_path);

    std::ofstream ofs(plist);
    if (!ofs) {
        last_error_ = "Failed to write plist file: " + plist.string();
        return false;
    }
    ofs << plist_content;
    ofs.close();

    log().info("Created launchd plist: {}", plist.string());

    // 加载服务
    std::string cmd = "launchctl load " + plist.string();
    auto [status, output] = exec_command(cmd);
    if (status != 0) {
        log().warn("Failed to load service (may already be loaded): {}", output);
        // 不算失败，继续
    }

    log().info("Service installed successfully");
    return true;
}

bool ServiceManager::uninstall_launchd() {
    auto plist = plist_path();

    // 先停止和卸载服务
    std::string cmd = "launchctl unload " + plist.string();
    exec_command(cmd);  // 忽略错误

    // 删除 plist 文件
    if (std::filesystem::exists(plist)) {
        std::error_code ec;
        std::filesystem::remove(plist, ec);
        if (ec) {
            last_error_ = "Failed to remove plist file: " + ec.message();
            return false;
        }
    }

    log().info("Service uninstalled successfully");
    return true;
}

bool ServiceManager::start_launchd() {
    if (!is_installed_launchd()) {
        last_error_ = "Service is not installed";
        return false;
    }

    auto plist = plist_path();

    // 尝试加载（如果未加载）并启动
    std::string cmd = "launchctl load " + plist.string();
    exec_command(cmd);  // 忽略错误，可能已加载

    cmd = "launchctl start " + std::string(SERVICE_LABEL);
    auto [status, output] = exec_command(cmd);
    if (status != 0) {
        // 可能服务名不存在，尝试重新加载
        cmd = "launchctl load -w " + plist.string();
        auto [status2, output2] = exec_command(cmd);
        if (status2 != 0) {
            last_error_ = "Failed to start service: " + output2;
            return false;
        }
    }

    // 验证服务是否真的启动了
    for (int i = 0; i < 10; ++i) {
        if (is_running_launchd()) {
            log().info("Service started successfully");
            return true;
        }
        usleep(500000);  // 0.5 秒
    }

    last_error_ = "Service failed to start";
    return false;
}

bool ServiceManager::stop_launchd() {
    if (!is_installed_launchd()) {
        last_error_ = "Service is not installed";
        return true;  // 不存在也算成功
    }

    std::string cmd = "launchctl stop " + std::string(SERVICE_LABEL);
    auto [status, output] = exec_command(cmd);
    if (status != 0) {
        // 可能服务已经停止了
        if (!is_running_launchd()) {
            return true;
        }
        last_error_ = "Failed to stop service: " + output;
        return false;
    }

    log().info("Service stopped successfully");
    return true;
}

} // namespace edgelink::client

#endif // __APPLE__

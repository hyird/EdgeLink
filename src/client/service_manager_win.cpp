#ifdef _WIN32

#include "service_manager.hpp"
#include "common/logger.hpp"

#include <windows.h>

namespace edgelink::client {

namespace {
auto& log() { return Logger::get("service"); }

constexpr const wchar_t* SERVICE_NAME = L"EdgeLinkClient";
constexpr const wchar_t* DISPLAY_NAME = L"EdgeLink Client";
constexpr const wchar_t* DESCRIPTION = L"EdgeLink Mesh VPN Client Service";
}

std::string ServiceManager::last_error_;

std::string ServiceManager::service_name() {
    return "EdgeLinkClient";
}

std::string ServiceManager::display_name() {
    return "EdgeLink Client";
}

const std::string& ServiceManager::last_error() {
    return last_error_;
}

bool ServiceManager::is_installed() {
    return is_installed_windows();
}

bool ServiceManager::is_running() {
    return is_running_windows();
}

ServiceStatus ServiceManager::status() {
    return status_windows();
}

bool ServiceManager::install(const std::filesystem::path& exe_path) {
    return install_windows(exe_path);
}

bool ServiceManager::uninstall() {
    return uninstall_windows();
}

bool ServiceManager::start() {
    return start_windows();
}

bool ServiceManager::stop() {
    return stop_windows();
}

// ============================================================================
// Windows Implementation
// ============================================================================

bool ServiceManager::is_installed_windows() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    bool installed = (service != nullptr);

    if (service) CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return installed;
}

bool ServiceManager::is_running_windows() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    bool running = false;

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp),
                             sizeof(ssp), &bytes_needed)) {
        running = (ssp.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return running;
}

ServiceStatus ServiceManager::status_windows() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        last_error_ = "Cannot connect to Service Control Manager";
        return ServiceStatus::UNKNOWN;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return ServiceStatus::NOT_INSTALLED;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    ServiceStatus result = ServiceStatus::UNKNOWN;

    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp),
                             sizeof(ssp), &bytes_needed)) {
        switch (ssp.dwCurrentState) {
            case SERVICE_STOPPED:
            case SERVICE_STOP_PENDING:
                result = ServiceStatus::STOPPED;
                break;
            case SERVICE_RUNNING:
            case SERVICE_START_PENDING:
            case SERVICE_CONTINUE_PENDING:
            case SERVICE_PAUSE_PENDING:
            case SERVICE_PAUSED:
                result = ServiceStatus::RUNNING;
                break;
            default:
                result = ServiceStatus::UNKNOWN;
                break;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return result;
}

bool ServiceManager::install_windows(const std::filesystem::path& exe_path) {
    // 需要管理员权限
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            last_error_ = "Access denied. Administrator privileges required to install service.";
        } else {
            last_error_ = "Cannot connect to Service Control Manager. Error: " + std::to_string(err);
        }
        return false;
    }

    // 构建服务命令行: "path\to\edgelink-client.exe" daemon
    std::wstring binary_path = exe_path.wstring() + L" daemon";

    // 创建服务
    SC_HANDLE service = CreateServiceW(
        scm,
        SERVICE_NAME,
        DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,  // 自动启动
        SERVICE_ERROR_NORMAL,
        binary_path.c_str(),
        nullptr,  // 不属于任何组
        nullptr,  // 不需要标签
        nullptr,  // 无依赖
        nullptr,  // LocalSystem 账户
        nullptr   // 无密码
    );

    if (!service) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);

        if (err == ERROR_SERVICE_EXISTS) {
            last_error_ = "Service already exists";
        } else if (err == ERROR_ACCESS_DENIED) {
            last_error_ = "Access denied. Administrator privileges required.";
        } else {
            last_error_ = "Failed to create service. Error: " + std::to_string(err);
        }
        return false;
    }

    // 设置服务描述
    SERVICE_DESCRIPTIONW desc;
    desc.lpDescription = const_cast<LPWSTR>(DESCRIPTION);
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);

    // 配置延迟自动启动
    SERVICE_DELAYED_AUTO_START_INFO delayed;
    delayed.fDelayedAutostart = TRUE;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);

    // 配置失败后重启
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 5000;  // 5 秒后重启
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 10000;  // 10 秒后重启
    actions[2].Type = SC_ACTION_RESTART;
    actions[2].Delay = 30000;  // 30 秒后重启

    SERVICE_FAILURE_ACTIONSW failure_actions;
    failure_actions.dwResetPeriod = 86400;  // 1 天后重置失败计数
    failure_actions.lpRebootMsg = nullptr;
    failure_actions.lpCommand = nullptr;
    failure_actions.cActions = 3;
    failure_actions.lpsaActions = actions;
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure_actions);

    log().info("Service installed successfully");

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return true;
}

bool ServiceManager::uninstall_windows() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        last_error_ = "Cannot connect to Service Control Manager";
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);

        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            last_error_ = "Service is not installed";
            return true;  // 不存在也算成功
        } else if (err == ERROR_ACCESS_DENIED) {
            last_error_ = "Access denied. Administrator privileges required.";
        } else {
            last_error_ = "Cannot open service. Error: " + std::to_string(err);
        }
        return false;
    }

    // 先停止服务（如果正在运行）
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp),
                             sizeof(ssp), &bytes_needed)) {
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS ss;
            ControlService(service, SERVICE_CONTROL_STOP, &ss);

            // 等待停止
            for (int i = 0; i < 30 && ssp.dwCurrentState != SERVICE_STOPPED; ++i) {
                Sleep(1000);
                QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                     reinterpret_cast<LPBYTE>(&ssp),
                                     sizeof(ssp), &bytes_needed);
            }
        }
    }

    // 删除服务
    bool success = DeleteService(service) != 0;
    if (!success) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            // 已标记删除，重启后生效
            success = true;
            log().warn("Service marked for deletion. Reboot required.");
        } else {
            last_error_ = "Failed to delete service. Error: " + std::to_string(err);
        }
    } else {
        log().info("Service uninstalled successfully");
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return success;
}

bool ServiceManager::start_windows() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        last_error_ = "Cannot connect to Service Control Manager";
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);

        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            last_error_ = "Service is not installed";
        } else if (err == ERROR_ACCESS_DENIED) {
            last_error_ = "Access denied. Administrator privileges required.";
        } else {
            last_error_ = "Cannot open service. Error: " + std::to_string(err);
        }
        return false;
    }

    // 检查是否已经在运行
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp),
                             sizeof(ssp), &bytes_needed)) {
        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            log().info("Service is already running");
            return true;
        }
    }

    // 启动服务
    if (!StartServiceW(service, 0, nullptr)) {
        DWORD err = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            log().info("Service is already running");
            return true;
        }

        last_error_ = "Failed to start service. Error: " + std::to_string(err);
        return false;
    }

    // 等待服务启动
    for (int i = 0; i < 30; ++i) {
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<LPBYTE>(&ssp),
                                 sizeof(ssp), &bytes_needed)) {
            if (ssp.dwCurrentState == SERVICE_RUNNING) {
                log().info("Service started successfully");
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return true;
            }
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                last_error_ = "Service failed to start";
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return false;
            }
        }
        Sleep(1000);
    }

    last_error_ = "Timeout waiting for service to start";
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return false;
}

bool ServiceManager::stop_windows() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        last_error_ = "Cannot connect to Service Control Manager";
        return false;
    }

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) {
        DWORD err = GetLastError();
        CloseServiceHandle(scm);

        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            last_error_ = "Service is not installed";
        } else if (err == ERROR_ACCESS_DENIED) {
            last_error_ = "Access denied. Administrator privileges required.";
        } else {
            last_error_ = "Cannot open service. Error: " + std::to_string(err);
        }
        return false;
    }

    // 检查是否已经停止
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp),
                             sizeof(ssp), &bytes_needed)) {
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            log().info("Service is already stopped");
            return true;
        }
    }

    // 停止服务
    SERVICE_STATUS ss;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &ss)) {
        DWORD err = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            log().info("Service is already stopped");
            return true;
        }

        last_error_ = "Failed to stop service. Error: " + std::to_string(err);
        return false;
    }

    // 等待服务停止
    for (int i = 0; i < 30; ++i) {
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<LPBYTE>(&ssp),
                                 sizeof(ssp), &bytes_needed)) {
            if (ssp.dwCurrentState == SERVICE_STOPPED) {
                log().info("Service stopped successfully");
                CloseServiceHandle(service);
                CloseServiceHandle(scm);
                return true;
            }
        }
        Sleep(1000);
    }

    last_error_ = "Timeout waiting for service to stop";
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return false;
}

} // namespace edgelink::client

#endif // _WIN32

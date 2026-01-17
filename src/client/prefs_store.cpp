#include "prefs_store.hpp"
#include "client/client.hpp"
#include "common/logger.hpp"

#include <toml++/toml.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <pwd.h>
#endif

namespace edgelink::client {

namespace {
auto& log = Logger::get("prefs");
}

PrefsStore::PrefsStore(const std::filesystem::path& state_dir)
    : prefs_path_(state_dir / "prefs.toml") {
}

bool PrefsStore::exists() const {
    return std::filesystem::exists(prefs_path_);
}

bool PrefsStore::ensure_directory() {
    try {
        auto dir = prefs_path_.parent_path();
        if (!dir.empty() && !std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
            log.debug("Created state directory: {}", dir.string());
        }
        return true;
    } catch (const std::exception& e) {
        last_error_ = std::string("Failed to create directory: ") + e.what();
        log.error("{}", last_error_);
        return false;
    }
}

bool PrefsStore::load() {
    std::lock_guard lock(mutex_);

    if (!exists()) {
        // 文件不存在，使用默认值
        log.debug("Prefs file not found, using defaults: {}", prefs_path_.string());
        return true;
    }

    try {
        auto table = toml::parse_file(prefs_path_.string());

        // [routing] section
        if (auto routing = table["routing"].as_table()) {
            // exit_node
            if (auto val = (*routing)["exit_node"].value<std::string>()) {
                if (!val->empty()) {
                    exit_node_ = *val;
                } else {
                    exit_node_.reset();
                }
            }

            // advertise_exit_node
            if (auto val = (*routing)["advertise_exit_node"].value<bool>()) {
                advertise_exit_node_ = *val;
            }

            // advertise_routes
            if (auto arr = (*routing)["advertise_routes"].as_array()) {
                advertise_routes_.clear();
                for (const auto& elem : *arr) {
                    if (auto str = elem.value<std::string>()) {
                        advertise_routes_.push_back(*str);
                    }
                }
            }

            // accept_routes
            if (auto val = (*routing)["accept_routes"].value<bool>()) {
                accept_routes_ = *val;
            }
        }

        log.info("Loaded prefs from: {}", prefs_path_.string());
        return true;
    } catch (const toml::parse_error& e) {
        last_error_ = std::string("TOML parse error: ") + e.what();
        log.error("{}", last_error_);
        return false;
    } catch (const std::exception& e) {
        last_error_ = std::string("Failed to load prefs: ") + e.what();
        log.error("{}", last_error_);
        return false;
    }
}

std::string PrefsStore::generate_toml() const {
    std::ostringstream oss;

    oss << "# EdgeLink 动态配置（由 edgelink set 命令管理）\n";
    oss << "# 手动编辑可能会被覆盖\n";
    oss << "\n";
    oss << "[routing]\n";

    // exit_node
    if (exit_node_) {
        oss << "exit_node = \"" << *exit_node_ << "\"\n";
    } else {
        oss << "# exit_node = \"\"\n";
    }

    // advertise_exit_node
    oss << "advertise_exit_node = " << (advertise_exit_node_ ? "true" : "false") << "\n";

    // advertise_routes
    oss << "advertise_routes = [";
    if (!advertise_routes_.empty()) {
        for (size_t i = 0; i < advertise_routes_.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "\"" << advertise_routes_[i] << "\"";
        }
    }
    oss << "]\n";

    // accept_routes
    oss << "accept_routes = " << (accept_routes_ ? "true" : "false") << "\n";

    oss << "\n";
    oss << "[network]\n";
    oss << "# 保留用于未来扩展\n";

    return oss.str();
}

bool PrefsStore::save() {
    std::lock_guard lock(mutex_);

    if (!ensure_directory()) {
        return false;
    }

    try {
        // 先写入临时文件，再原子重命名
        auto temp_path = prefs_path_;
        temp_path += ".tmp";

        {
            std::ofstream ofs(temp_path);
            if (!ofs) {
                last_error_ = "Failed to open temp file for writing";
                log.error("{}: {}", last_error_, temp_path.string());
                return false;
            }
            ofs << generate_toml();
        }

        // 原子重命名
        std::filesystem::rename(temp_path, prefs_path_);

        log.info("Saved prefs to: {}", prefs_path_.string());
        return true;
    } catch (const std::exception& e) {
        last_error_ = std::string("Failed to save prefs: ") + e.what();
        log.error("{}", last_error_);
        return false;
    }
}

// ========== Routing 配置访问器 ==========

std::optional<std::string> PrefsStore::exit_node() const {
    std::lock_guard lock(mutex_);
    return exit_node_;
}

void PrefsStore::set_exit_node(const std::string& node) {
    std::lock_guard lock(mutex_);
    if (node.empty()) {
        exit_node_.reset();
    } else {
        exit_node_ = node;
    }
}

void PrefsStore::clear_exit_node() {
    std::lock_guard lock(mutex_);
    exit_node_.reset();
}

bool PrefsStore::advertise_exit_node() const {
    std::lock_guard lock(mutex_);
    return advertise_exit_node_;
}

void PrefsStore::set_advertise_exit_node(bool value) {
    std::lock_guard lock(mutex_);
    advertise_exit_node_ = value;
}

std::vector<std::string> PrefsStore::advertise_routes() const {
    std::lock_guard lock(mutex_);
    return advertise_routes_;
}

void PrefsStore::set_advertise_routes(const std::vector<std::string>& routes) {
    std::lock_guard lock(mutex_);
    advertise_routes_ = routes;
}

void PrefsStore::add_advertise_route(const std::string& route) {
    std::lock_guard lock(mutex_);
    // 避免重复
    auto it = std::find(advertise_routes_.begin(), advertise_routes_.end(), route);
    if (it == advertise_routes_.end()) {
        advertise_routes_.push_back(route);
    }
}

void PrefsStore::remove_advertise_route(const std::string& route) {
    std::lock_guard lock(mutex_);
    advertise_routes_.erase(
        std::remove(advertise_routes_.begin(), advertise_routes_.end(), route),
        advertise_routes_.end()
    );
}

bool PrefsStore::accept_routes() const {
    std::lock_guard lock(mutex_);
    return accept_routes_;
}

void PrefsStore::set_accept_routes(bool value) {
    std::lock_guard lock(mutex_);
    accept_routes_ = value;
}

// ========== 配置合并 ==========

void PrefsStore::apply_to(client::ClientConfig& config) const {
    std::lock_guard lock(mutex_);

    // exit_node -> use_exit_node
    if (exit_node_) {
        config.use_exit_node = *exit_node_;
    }

    // advertise_exit_node -> exit_node
    config.exit_node = advertise_exit_node_;

    // advertise_routes
    if (!advertise_routes_.empty()) {
        config.advertise_routes = advertise_routes_;
    }

    // accept_routes
    config.accept_routes = accept_routes_;
}

void PrefsStore::extract_from(const client::ClientConfig& config) {
    std::lock_guard lock(mutex_);

    // use_exit_node -> exit_node
    if (!config.use_exit_node.empty()) {
        exit_node_ = config.use_exit_node;
    }

    // exit_node -> advertise_exit_node
    advertise_exit_node_ = config.exit_node;

    // advertise_routes
    advertise_routes_ = config.advertise_routes;

    // accept_routes
    accept_routes_ = config.accept_routes;
}

// ========== 平台特定函数 ==========

std::filesystem::path get_state_dir() {
#ifdef _WIN32
    // Windows: %LOCALAPPDATA%\EdgeLink\
    // Use environment variable directly to avoid issues with WIN32_LEAN_AND_MEAN
    if (auto appdata = std::getenv("LOCALAPPDATA")) {
        return std::filesystem::path(appdata) / "EdgeLink";
    }
    // Fallback to ProgramData
    return std::filesystem::path("C:\\ProgramData\\EdgeLink");

#elif defined(__APPLE__)
    // macOS: ~/Library/Application Support/EdgeLink/
    if (auto home = std::getenv("HOME")) {
        return std::filesystem::path(home) / "Library" / "Application Support" / "EdgeLink";
    }
    // Fallback via getpwuid
    if (auto pw = getpwuid(getuid())) {
        return std::filesystem::path(pw->pw_dir) / "Library" / "Application Support" / "EdgeLink";
    }
    return std::filesystem::path("/var/lib/edgelink");

#else
    // Linux: /var/lib/edgelink/ (system service) or ~/.local/share/edgelink/ (user)
    // 优先使用系统目录（需要 root），否则用用户目录
    if (geteuid() == 0) {
        return std::filesystem::path("/var/lib/edgelink");
    }

    // 用户目录
    if (auto xdg = std::getenv("XDG_DATA_HOME")) {
        return std::filesystem::path(xdg) / "edgelink";
    }
    if (auto home = std::getenv("HOME")) {
        return std::filesystem::path(home) / ".local" / "share" / "edgelink";
    }
    if (auto pw = getpwuid(getuid())) {
        return std::filesystem::path(pw->pw_dir) / ".local" / "share" / "edgelink";
    }
    return std::filesystem::path("/var/lib/edgelink");
#endif
}

std::filesystem::path get_default_prefs_path() {
    return get_state_dir() / "prefs.toml";
}

} // namespace edgelink::client

#include "prefs_store.hpp"
#include "client/client.hpp"
#include "common/logger.hpp"

#include <boost/json.hpp>
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

namespace json = boost::json;

namespace edgelink::client {

namespace {
auto& log = Logger::get("prefs");
}

PrefsStore::PrefsStore(const std::filesystem::path& state_dir)
    : prefs_path_(state_dir / "prefs.json") {
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
        // 向后兼容：如果 prefs.json 不存在但 prefs.toml 存在，提示迁移
        auto toml_path = prefs_path_.parent_path() / "prefs.toml";
        if (std::filesystem::exists(toml_path)) {
            log.warn("Found legacy prefs.toml but not prefs.json. "
                      "Please re-run 'edgelink-client up' or 'edgelink-client set' to migrate.");
        }
        log.debug("Prefs file not found, using defaults: {}", prefs_path_.string());
        return true;
    }

    try {
        std::ifstream ifs(prefs_path_);
        if (!ifs) {
            last_error_ = "Failed to open prefs file";
            log.error("{}: {}", last_error_, prefs_path_.string());
            return false;
        }

        std::stringstream buffer;
        buffer << ifs.rdbuf();
        auto jv = json::parse(buffer.str());
        auto& root = jv.as_object();

        // connection section
        if (auto it = root.find("connection"); it != root.end() && it->value().is_object()) {
            auto& conn = it->value().as_object();
            if (auto ci = conn.find("controller_url"); ci != conn.end() && ci->value().is_string()) {
                auto val = std::string(ci->value().as_string());
                if (!val.empty()) controller_url_ = val;
            }
            if (auto ci = conn.find("authkey"); ci != conn.end() && ci->value().is_string()) {
                auto val = std::string(ci->value().as_string());
                if (!val.empty()) authkey_ = val;
            }
            if (auto ci = conn.find("tls"); ci != conn.end() && ci->value().is_bool()) {
                tls_ = ci->value().as_bool();
            }
        }

        // routing section
        if (auto it = root.find("routing"); it != root.end() && it->value().is_object()) {
            auto& routing = it->value().as_object();

            // exit_node
            if (auto ci = routing.find("exit_node"); ci != routing.end() && ci->value().is_string()) {
                auto val = std::string(ci->value().as_string());
                if (!val.empty()) exit_node_ = val;
                else exit_node_.reset();
            }

            // advertise_exit_node
            if (auto ci = routing.find("advertise_exit_node"); ci != routing.end() && ci->value().is_bool()) {
                advertise_exit_node_ = ci->value().as_bool();
            }

            // advertise_routes
            if (auto ci = routing.find("advertise_routes"); ci != routing.end() && ci->value().is_array()) {
                advertise_routes_.clear();
                for (const auto& elem : ci->value().as_array()) {
                    if (elem.is_string())
                        advertise_routes_.emplace_back(elem.as_string());
                }
            }

            // accept_routes
            if (auto ci = routing.find("accept_routes"); ci != routing.end() && ci->value().is_bool()) {
                accept_routes_ = ci->value().as_bool();
            }
        }

        log.info("Loaded prefs from: {}", prefs_path_.string());
        return true;
    } catch (const boost::system::system_error& e) {
        last_error_ = std::string("JSON parse error: ") + e.what();
        log.error("{}", last_error_);
        return false;
    } catch (const std::exception& e) {
        last_error_ = std::string("Failed to load prefs: ") + e.what();
        log.error("{}", last_error_);
        return false;
    }
}

std::string PrefsStore::generate_json() const {
    json::object root;

    // connection section
    json::object conn;
    if (controller_url_)
        conn["controller_url"] = *controller_url_;
    if (authkey_)
        conn["authkey"] = *authkey_;
    if (tls_)
        conn["tls"] = *tls_;
    if (!conn.empty())
        root["connection"] = std::move(conn);

    // routing section
    json::object routing;
    if (exit_node_)
        routing["exit_node"] = *exit_node_;
    routing["advertise_exit_node"] = advertise_exit_node_;
    if (!advertise_routes_.empty()) {
        json::array arr;
        for (const auto& r : advertise_routes_)
            arr.emplace_back(r);
        routing["advertise_routes"] = std::move(arr);
    }
    routing["accept_routes"] = accept_routes_;
    root["routing"] = std::move(routing);

    return json::serialize(root);
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
            ofs << generate_json();
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

// ========== 连接配置访问器 ==========

std::optional<std::string> PrefsStore::controller_url() const {
    std::lock_guard lock(mutex_);
    return controller_url_;
}

void PrefsStore::set_controller_url(const std::string& url) {
    std::lock_guard lock(mutex_);
    if (url.empty()) {
        controller_url_.reset();
    } else {
        controller_url_ = url;
    }
}

std::optional<std::string> PrefsStore::authkey() const {
    std::lock_guard lock(mutex_);
    return authkey_;
}

void PrefsStore::set_authkey(const std::string& key) {
    std::lock_guard lock(mutex_);
    if (key.empty()) {
        authkey_.reset();
    } else {
        authkey_ = key;
    }
}

std::optional<bool> PrefsStore::tls() const {
    std::lock_guard lock(mutex_);
    return tls_;
}

void PrefsStore::set_tls(bool value) {
    std::lock_guard lock(mutex_);
    tls_ = value;
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

    // 连接配置（使用默认值）
    config.controller_url = controller_url_.value_or(DEFAULT_CONTROLLER_URL);
    if (authkey_) {
        config.authkey = *authkey_;
    }
    config.tls = tls_.value_or(DEFAULT_TLS);

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
    return get_state_dir() / "prefs.json";
}

} // namespace edgelink::client

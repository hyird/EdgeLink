#include "client/ipc_server.hpp"
#include "client/client.hpp"
#include "common/logger.hpp"

#include <boost/json.hpp>
#include <filesystem>
#include <sstream>

namespace json = boost::json;

namespace edgelink::client {

namespace {
    auto& log() { return Logger::get("client.ipc"); }
}

// ============================================================================
// IpcServer
// ============================================================================

IpcServer::IpcServer(asio::io_context& ioc, Client& client)
    : ioc_(ioc), client_(client) {}

IpcServer::~IpcServer() {
    stop();
}

std::string IpcServer::get_default_socket_path() {
#ifdef _WIN32
    // Windows: use a path in the user's temp directory
    return R"(\\.\pipe\edgelink-client)";
#elif defined(__APPLE__)
    // macOS: use /tmp or user-specific path
    const char* tmpdir = std::getenv("TMPDIR");
    if (tmpdir) {
        return std::string(tmpdir) + "edgelink-client.sock";
    }
    return "/tmp/edgelink-client.sock";
#else
    // Linux: use XDG_RUNTIME_DIR or /tmp
    const char* runtime_dir = std::getenv("XDG_RUNTIME_DIR");
    if (runtime_dir) {
        return std::string(runtime_dir) + "/edgelink-client.sock";
    }
    return "/tmp/edgelink-client.sock";
#endif
}

bool IpcServer::start(const IpcServerConfig& config) {
    if (running_) {
        return true;
    }

    config_ = config;
    if (config_.socket_path.empty()) {
        config_.socket_path = get_default_socket_path();
    }

#ifdef _WIN32
    // Windows named pipes handled differently
    // For now, use local stream protocol which Boost.Asio maps appropriately
    try {
        // Remove existing socket file if present
        std::error_code ec;
        std::filesystem::remove(config_.socket_path, ec);

        acceptor_ = std::make_unique<asio::local::stream_protocol::acceptor>(ioc_);
        acceptor_->open();
        acceptor_->bind(asio::local::stream_protocol::endpoint(config_.socket_path));
        acceptor_->listen();

        running_ = true;
        log().info("IPC server started on: {}", config_.socket_path);

        // Start accept loop
        asio::co_spawn(ioc_, accept_loop(), asio::detached);

        return true;
    } catch (const std::exception& e) {
        log().error("Failed to start IPC server: {}", e.what());
        return false;
    }
#else
    // Unix domain socket
    try {
        // Remove existing socket file if present
        std::error_code ec;
        std::filesystem::remove(config_.socket_path, ec);

        acceptor_ = std::make_unique<asio::local::stream_protocol::acceptor>(ioc_);
        acceptor_->open();
        acceptor_->bind(asio::local::stream_protocol::endpoint(config_.socket_path));
        acceptor_->listen();

        // Set socket permissions (user only)
        std::filesystem::permissions(config_.socket_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, ec);

        running_ = true;
        log().info("IPC server started on: {}", config_.socket_path);

        // Start accept loop
        asio::co_spawn(ioc_, accept_loop(), asio::detached);

        return true;
    } catch (const std::exception& e) {
        log().error("Failed to start IPC server: {}", e.what());
        return false;
    }
#endif
}

void IpcServer::stop() {
    if (!running_) return;

    running_ = false;

    if (acceptor_) {
        boost::system::error_code ec;
        acceptor_->close(ec);
        acceptor_.reset();
    }

    // Remove socket file
    std::error_code ec;
    std::filesystem::remove(config_.socket_path, ec);

    log().info("IPC server stopped");
}

asio::awaitable<void> IpcServer::accept_loop() {
    while (running_ && acceptor_) {
        try {
            auto socket = co_await acceptor_->async_accept(asio::use_awaitable);
            log().debug("IPC client connected");

            // Handle client in a new coroutine
            asio::co_spawn(ioc_, handle_client(std::move(socket)), asio::detached);

        } catch (const boost::system::system_error& e) {
            if (e.code() != asio::error::operation_aborted && running_) {
                log().error("IPC accept error: {}", e.what());
            }
        }
    }
}

asio::awaitable<void> IpcServer::handle_client(asio::local::stream_protocol::socket socket) {
    try {
        // Simple line-based protocol
        asio::streambuf buffer;

        while (running_) {
            // Read a line (request)
            size_t n = co_await asio::async_read_until(socket, buffer, '\n', asio::use_awaitable);

            std::istream is(&buffer);
            std::string request;
            std::getline(is, request);

            // Remove trailing CR if present (Windows compatibility)
            if (!request.empty() && request.back() == '\r') {
                request.pop_back();
            }

            log().debug("IPC request: {}", request);

            // Process request
            std::string response = process_request(request);

            // Send response (with newline)
            response += '\n';
            co_await asio::async_write(socket, asio::buffer(response), asio::use_awaitable);
        }
    } catch (const boost::system::system_error& e) {
        if (e.code() != asio::error::eof &&
            e.code() != asio::error::connection_reset &&
            e.code() != asio::error::broken_pipe) {
            log().debug("IPC client error: {}", e.what());
        }
    }

    log().debug("IPC client disconnected");
}

std::string IpcServer::process_request(const std::string& request) {
    try {
        // Parse JSON request
        auto jv = json::parse(request);
        auto& obj = jv.as_object();

        std::string cmd = json::value_to<std::string>(obj.at("cmd"));

        if (cmd == "status") {
            return handle_status();
        } else if (cmd == "peers") {
            bool online_only = false;
            if (obj.contains("online_only")) {
                online_only = obj.at("online_only").as_bool();
            }
            return handle_peers(online_only);
        } else if (cmd == "ping") {
            std::string target = json::value_to<std::string>(obj.at("target"));
            return handle_ping(target);
        } else if (cmd == "log_level") {
            std::string module = obj.contains("module") ?
                json::value_to<std::string>(obj.at("module")) : "";
            std::string level = obj.contains("level") ?
                json::value_to<std::string>(obj.at("level")) : "";
            return handle_log_level(module, level);
        } else if (cmd == "shutdown") {
            return handle_shutdown();
        } else {
            return encode_error(IpcStatus::INVALID_REQUEST, "Unknown command: " + cmd);
        }

    } catch (const std::exception& e) {
        return encode_error(IpcStatus::INVALID_REQUEST, std::string("Parse error: ") + e.what());
    }
}

std::string IpcServer::handle_status() {
    IpcStatusResponse data;

    data.state = client_state_name(client_.state());
    data.node_id = std::to_string(client_.node_id());
    data.virtual_ip = client_.virtual_ip().to_string();
    data.network_id = client_.network_id();
    data.peer_count = client_.peers().peer_count();
    data.online_peer_count = client_.peers().online_peer_count();
    data.tun_enabled = client_.is_tun_enabled();

    return encode_status_response(IpcStatus::OK, data);
}

std::string IpcServer::handle_peers(bool online_only) {
    std::vector<IpcPeerInfo> peers;

    auto peer_list = online_only ?
        client_.peers().get_online_peers() :
        client_.peers().get_all_peers();

    for (const auto& p : peer_list) {
        IpcPeerInfo info;
        info.node_id = std::to_string(p.info.node_id);
        info.virtual_ip = p.info.virtual_ip.to_string();
        info.name = p.info.name;
        info.online = p.info.online;
        info.latency_ms = p.latency_ms;

        switch (p.connection_status) {
            case P2PStatus::P2P:
                info.connection_status = "p2p";
                break;
            case P2PStatus::RELAY_ONLY:
                info.connection_status = "relay";
                break;
            default:
                info.connection_status = "disconnected";
                break;
        }

        peers.push_back(std::move(info));
    }

    return encode_peers_response(IpcStatus::OK, peers);
}

std::string IpcServer::handle_ping(const std::string& target) {
    // TODO: Implement ping functionality
    return encode_error(IpcStatus::ERROR, "Ping not implemented yet");
}

std::string IpcServer::handle_log_level(const std::string& module, const std::string& level) {
    if (level.empty()) {
        // Get current level
        auto& lm = LogManager::instance();
        if (module.empty()) {
            auto global_level = lm.get_global_level();
            json::object obj;
            obj["status"] = "ok";
            obj["global_level"] = std::string(log_level_to_string(global_level));

            auto module_levels = lm.get_all_module_levels();
            json::object modules;
            for (const auto& [m, l] : module_levels) {
                modules[m] = std::string(log_level_to_string(l));
            }
            obj["modules"] = modules;

            return json::serialize(obj);
        } else {
            auto mod_level = lm.get_module_level(module);
            json::object obj;
            obj["status"] = "ok";
            obj["module"] = module;
            obj["level"] = mod_level ?
                std::string(log_level_to_string(*mod_level)) : "default";
            return json::serialize(obj);
        }
    } else {
        // Set level
        auto new_level = log_level_from_string(level);
        auto& lm = LogManager::instance();

        if (module.empty()) {
            lm.set_global_level(new_level);
            log().info("Global log level set to: {}", level);
        } else {
            lm.set_module_level(module, new_level);
            log().info("Log level for '{}' set to: {}", module, level);
        }

        return encode_ok("Log level updated");
    }
}

std::string IpcServer::handle_shutdown() {
    log().info("Shutdown requested via IPC");

    if (shutdown_callback_) {
        // Post the callback to execute after response is sent
        asio::post(ioc_, [callback = shutdown_callback_]() {
            callback();
        });
    }

    return encode_ok("Shutdown initiated");
}

std::string IpcServer::encode_status_response(IpcStatus status, const IpcStatusResponse& data) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";
    obj["data"] = {
        {"state", data.state},
        {"node_id", data.node_id},
        {"virtual_ip", data.virtual_ip},
        {"network_id", data.network_id},
        {"peer_count", data.peer_count},
        {"online_peer_count", data.online_peer_count},
        {"tun_enabled", data.tun_enabled}
    };
    return json::serialize(obj);
}

std::string IpcServer::encode_peers_response(IpcStatus status, const std::vector<IpcPeerInfo>& peers) {
    json::object obj;
    obj["status"] = status == IpcStatus::OK ? "ok" : "error";

    json::array arr;
    for (const auto& p : peers) {
        arr.push_back({
            {"node_id", p.node_id},
            {"virtual_ip", p.virtual_ip},
            {"name", p.name},
            {"online", p.online},
            {"connection_status", p.connection_status},
            {"latency_ms", p.latency_ms}
        });
    }
    obj["peers"] = arr;

    return json::serialize(obj);
}

std::string IpcServer::encode_error(IpcStatus status, const std::string& message) {
    json::object obj;
    obj["status"] = "error";
    obj["code"] = static_cast<int>(status);
    obj["message"] = message;
    return json::serialize(obj);
}

std::string IpcServer::encode_ok(const std::string& message) {
    json::object obj;
    obj["status"] = "ok";
    if (!message.empty()) {
        obj["message"] = message;
    }
    return json::serialize(obj);
}

// ============================================================================
// IpcClient
// ============================================================================

IpcClient::IpcClient(const std::string& socket_path)
    : socket_path_(socket_path.empty() ? IpcServer::get_default_socket_path() : socket_path) {}

IpcClient::~IpcClient() {
    if (socket_) {
        boost::system::error_code ec;
        socket_->close(ec);
    }
}

bool IpcClient::connect() {
    try {
        socket_ = std::make_unique<asio::local::stream_protocol::socket>(ioc_);
        socket_->connect(asio::local::stream_protocol::endpoint(socket_path_));
        connected_ = true;
        return true;
    } catch (const std::exception&) {
        connected_ = false;
        return false;
    }
}

std::string IpcClient::send_request(const std::string& request) {
    if (!connected_ || !socket_) {
        return R"({"status":"error","message":"Not connected"})";
    }

    try {
        // Send request with newline
        std::string req = request + "\n";
        asio::write(*socket_, asio::buffer(req));

        // Read response
        asio::streambuf buffer;
        asio::read_until(*socket_, buffer, '\n');

        std::istream is(&buffer);
        std::string response;
        std::getline(is, response);

        // Remove trailing CR if present
        if (!response.empty() && response.back() == '\r') {
            response.pop_back();
        }

        return response;
    } catch (const std::exception& e) {
        return std::string(R"({"status":"error","message":")") + e.what() + "\"}";
    }
}

std::string IpcClient::get_status() {
    return send_request(R"({"cmd":"status"})");
}

std::string IpcClient::get_peers(bool online_only) {
    if (online_only) {
        return send_request(R"({"cmd":"peers","online_only":true})");
    }
    return send_request(R"({"cmd":"peers"})");
}

std::string IpcClient::ping_peer(const std::string& target) {
    return send_request(R"({"cmd":"ping","target":")" + target + "\"}");
}

std::string IpcClient::set_log_level(const std::string& module, const std::string& level) {
    json::object obj;
    obj["cmd"] = "log_level";
    if (!module.empty()) obj["module"] = module;
    if (!level.empty()) obj["level"] = level;
    return send_request(json::serialize(obj));
}

std::string IpcClient::request_shutdown() {
    return send_request(R"({"cmd":"shutdown"})");
}

} // namespace edgelink::client

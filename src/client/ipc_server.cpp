#include "ipc_server.hpp"
#include "client.hpp"
#include "common/log.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <chrono>
#include <filesystem>

namespace edgelink::client {

using json = nlohmann::json;

// ============================================================================
// Socket Path
// ============================================================================

std::string IPCServer::get_socket_path() {
#ifdef _WIN32
    // Windows: use named pipe path (Boost.Asio local sockets use file paths on Windows too)
    const char* temp = std::getenv("TEMP");
    if (!temp) temp = std::getenv("TMP");
    if (!temp) temp = "C:\\Windows\\Temp";
    return std::string(temp) + "\\edgelink-client.sock";
#else
    // POSIX: use Unix domain socket in /run or /var/run
    const char* runtime_dir = std::getenv("XDG_RUNTIME_DIR");
    if (runtime_dir) {
        return std::string(runtime_dir) + "/edgelink-client.sock";
    }
    // Fallback to /var/run (requires root)
    if (geteuid() == 0) {
        return "/var/run/edgelink-client.sock";
    }
    // User-level fallback
    const char* home = std::getenv("HOME");
    if (home) {
        std::string socket_dir = std::string(home) + "/.edgelink";
        std::filesystem::create_directories(socket_dir);
        return socket_dir + "/client.sock";
    }
    return "/tmp/edgelink-client.sock";
#endif
}

// ============================================================================
// IPCSession
// ============================================================================

IPCSession::IPCSession(local_stream::socket socket, Client* client)
    : socket_(std::move(socket))
    , client_(client)
{}

void IPCSession::start() {
    do_read();
}

void IPCSession::do_read() {
    auto self = shared_from_this();
    socket_.async_read_some(
        net::buffer(buffer_),
        [this, self](boost::system::error_code ec, std::size_t length) {
            if (ec) {
                if (ec != net::error::eof && ec != net::error::connection_reset) {
                    LOG_WARN("IPCSession: Read error: {}", ec.message());
                }
                return;
            }

            try {
                std::string request_str(buffer_.data(), length);
                auto request = json::parse(request_str);
                std::string response = handle_request(request);
                do_write(response);
            } catch (const json::parse_error& e) {
                LOG_ERROR("IPCSession: JSON parse error: {}", e.what());
                json error_response;
                error_response["error"] = "parse_error";
                error_response["message"] = "Invalid JSON request";
                do_write(error_response.dump());
            }
        });
}

void IPCSession::do_write(const std::string& response) {
    auto self = shared_from_this();
    net::async_write(
        socket_,
        net::buffer(response),
        [this, self](boost::system::error_code ec, std::size_t /*length*/) {
            if (ec) {
                LOG_WARN("IPCSession: Write error: {}", ec.message());
            }
            // Close connection after response
        });
}

std::string IPCSession::handle_request(const json& request) {
    std::string command = request.value("command", "");

    if (command == "status") {
        return handle_status();
    } else if (command == "disconnect") {
        return handle_disconnect();
    } else if (command == "reconnect") {
        return handle_reconnect();
    } else if (command == "ping") {
        uint32_t peer_id = request.value("peer_node_id", 0);
        return handle_ping(peer_id);
    } else {
        json error_response;
        error_response["error"] = "unknown_command";
        error_response["message"] = "Unknown command: " + command;
        return error_response.dump();
    }
}

std::string IPCSession::handle_status() {
    json response;

    if (!client_) {
        response["error"] = "internal_error";
        response["message"] = "Client not available";
        return response.dump();
    }

    response["connected"] = client_->is_running();
    response["state"] = client_->get_state_string();
    response["controller_url"] = client_->get_controller_url();

    auto control = client_->get_control_channel();
    if (control) {
        response["node_id"] = control->node_id();
        response["virtual_ip"] = control->virtual_ip();
    } else {
        response["node_id"] = 0;
        response["virtual_ip"] = "";
    }

    auto tun = client_->get_tun_device();
    if (tun) {
        response["tun_interface"] = tun->name();
    } else {
        response["tun_interface"] = "";
    }

    auto stats = client_->get_stats();
    response["packets_sent"] = stats.packets_sent;
    response["packets_received"] = stats.packets_received;
    response["bytes_sent"] = stats.bytes_sent;
    response["bytes_received"] = stats.bytes_received;

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.start_time).count();
    response["uptime_seconds"] = uptime;

    return response.dump();
}

std::string IPCSession::handle_disconnect() {
    json response;

    if (!client_) {
        response["success"] = false;
        response["message"] = "Client not available";
        return response.dump();
    }

    LOG_INFO("IPCService: Disconnect requested via IPC");
    client_->stop();

    response["success"] = true;
    response["message"] = "Disconnected";
    return response.dump();
}

std::string IPCSession::handle_reconnect() {
    json response;

    if (!client_) {
        response["success"] = false;
        response["message"] = "Client not available";
        return response.dump();
    }

    LOG_INFO("IPCService: Reconnect requested via IPC");

    auto control = client_->get_control_channel();
    if (control) {
        control->connect();
        response["success"] = true;
        response["message"] = "Reconnecting...";
    } else {
        response["success"] = false;
        response["message"] = "Control channel not available";
    }

    return response.dump();
}

std::string IPCSession::handle_ping(uint32_t peer_node_id) {
    json response;

    if (!client_) {
        response["success"] = false;
        response["error"] = "Client not available";
        return response.dump();
    }

    if (peer_node_id == 0) {
        // Ping controller - check if connected
        auto control = client_->get_control_channel();
        if (control && control->is_connected()) {
            response["success"] = true;
            response["latency_ms"] = 0;
        } else {
            response["success"] = false;
            response["error"] = "Not connected to controller";
        }
    } else {
        // Ping peer - for now just report if client is running
        response["success"] = false;
        response["error"] = "Peer ping not implemented yet";
    }

    return response.dump();
}

// ============================================================================
// IPCServer
// ============================================================================

IPCServer::IPCServer(net::io_context& ioc, Client* client)
    : ioc_(ioc)
    , client_(client)
{}

IPCServer::~IPCServer() {
    stop();
}

bool IPCServer::start() {
    if (running_) return true;

    std::string socket_path = get_socket_path();

    // Remove existing socket file
    std::remove(socket_path.c_str());

    try {
        local_stream::endpoint endpoint(socket_path);
        acceptor_ = std::make_unique<local_stream::acceptor>(ioc_, endpoint);

#ifndef _WIN32
        // Set socket permissions to allow user access
        chmod(socket_path.c_str(), 0660);
#endif

        running_ = true;
        do_accept();

        LOG_INFO("IPCServer: Listening on {}", socket_path);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("IPCServer: Failed to start on {}: {}", socket_path, e.what());
        return false;
    }
}

void IPCServer::stop() {
    if (!running_) return;

    running_ = false;

    if (acceptor_ && acceptor_->is_open()) {
        boost::system::error_code ec;
        acceptor_->close(ec);
    }

    acceptor_.reset();

    // Clean up socket file
    std::string socket_path = get_socket_path();
    std::remove(socket_path.c_str());

    LOG_INFO("IPCServer: Stopped");
}

void IPCServer::do_accept() {
    if (!running_ || !acceptor_) return;

    acceptor_->async_accept(
        [this](boost::system::error_code ec, local_stream::socket socket) {
            if (!ec) {
                std::make_shared<IPCSession>(std::move(socket), client_)->start();
            } else if (ec != net::error::operation_aborted) {
                LOG_WARN("IPCServer: Accept error: {}", ec.message());
            }

            if (running_) {
                do_accept();
            }
        });
}

// ============================================================================
// IPCClient (for CLI)
// ============================================================================

IPCClient::IPCClient() {}

IPCClient::~IPCClient() {
    if (socket_ && socket_->is_open()) {
        boost::system::error_code ec;
        socket_->close(ec);
    }
}

bool IPCClient::connect() {
    std::string socket_path = IPCServer::get_socket_path();

    try {
        socket_ = std::make_unique<local_stream::socket>(ioc_);
        local_stream::endpoint endpoint(socket_path);

        boost::system::error_code ec;
        socket_->connect(endpoint, ec);

        if (ec) {
            socket_.reset();
            return false;
        }

        connected_ = true;
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("IPCClient: Connection failed: {}", e.what());
        socket_.reset();
        return false;
    }
}

std::string IPCClient::send_request(const json& request) {
    if (!connected_ || !socket_) {
        return "";
    }

    try {
        std::string request_str = request.dump();

        // Send request
        boost::system::error_code ec;
        net::write(*socket_, net::buffer(request_str), ec);
        if (ec) {
            return "";
        }

        // Read response
        std::array<char, 8192> buffer;
        size_t length = socket_->read_some(net::buffer(buffer), ec);
        if (ec) {
            return "";
        }

        return std::string(buffer.data(), length);
    } catch (const std::exception& e) {
        LOG_ERROR("IPCClient: Request failed: {}", e.what());
        return "";
    }
}

std::optional<IPCStatusResponse> IPCClient::status() {
    json request;
    request["command"] = "status";

    std::string response_str = send_request(request);
    if (response_str.empty()) {
        return std::nullopt;
    }

    try {
        auto response_json = json::parse(response_str);

        if (response_json.contains("error")) {
            return std::nullopt;
        }

        IPCStatusResponse response;
        response.connected = response_json.value("connected", false);
        response.state = response_json.value("state", "");
        response.controller_url = response_json.value("controller_url", "");
        response.node_id = response_json.value("node_id", 0);
        response.virtual_ip = response_json.value("virtual_ip", "");
        response.tun_interface = response_json.value("tun_interface", "");
        response.packets_sent = response_json.value("packets_sent", 0);
        response.packets_received = response_json.value("packets_received", 0);
        response.bytes_sent = response_json.value("bytes_sent", 0);
        response.bytes_received = response_json.value("bytes_received", 0);
        response.uptime_seconds = response_json.value("uptime_seconds", 0);

        return response;
    } catch (const json::parse_error& e) {
        LOG_ERROR("IPCClient: Failed to parse status response: {}", e.what());
        return std::nullopt;
    }
}

std::optional<IPCDisconnectResponse> IPCClient::disconnect() {
    json request;
    request["command"] = "disconnect";

    std::string response_str = send_request(request);
    if (response_str.empty()) {
        return std::nullopt;
    }

    try {
        auto response_json = json::parse(response_str);

        IPCDisconnectResponse response;
        response.success = response_json.value("success", false);
        response.message = response_json.value("message", "");

        return response;
    } catch (const json::parse_error& e) {
        LOG_ERROR("IPCClient: Failed to parse disconnect response: {}", e.what());
        return std::nullopt;
    }
}

std::optional<IPCReconnectResponse> IPCClient::reconnect() {
    json request;
    request["command"] = "reconnect";

    std::string response_str = send_request(request);
    if (response_str.empty()) {
        return std::nullopt;
    }

    try {
        auto response_json = json::parse(response_str);

        IPCReconnectResponse response;
        response.success = response_json.value("success", false);
        response.message = response_json.value("message", "");

        return response;
    } catch (const json::parse_error& e) {
        LOG_ERROR("IPCClient: Failed to parse reconnect response: {}", e.what());
        return std::nullopt;
    }
}

std::optional<IPCPingResponse> IPCClient::ping(uint32_t peer_node_id) {
    json request;
    request["command"] = "ping";
    request["peer_node_id"] = peer_node_id;

    std::string response_str = send_request(request);
    if (response_str.empty()) {
        return std::nullopt;
    }

    try {
        auto response_json = json::parse(response_str);

        IPCPingResponse response;
        response.success = response_json.value("success", false);
        response.latency_ms = response_json.value("latency_ms", 0);
        response.error = response_json.value("error", "");

        return response;
    } catch (const json::parse_error& e) {
        LOG_ERROR("IPCClient: Failed to parse ping response: {}", e.what());
        return std::nullopt;
    }
}

} // namespace edgelink::client

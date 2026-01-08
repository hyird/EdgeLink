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

// ============================================================================
// Socket Path
// ============================================================================

std::string IPCServer::get_socket_path() {
#ifdef _WIN32
    // Windows: use named pipe
    return "unix:///./pipe/edgelink-client";
#else
    // POSIX: use Unix domain socket in /run or /var/run
    const char* runtime_dir = std::getenv("XDG_RUNTIME_DIR");
    if (runtime_dir) {
        return std::string("unix://") + runtime_dir + "/edgelink-client.sock";
    }
    // Fallback to /var/run (requires root)
    if (geteuid() == 0) {
        return "unix:///var/run/edgelink-client.sock";
    }
    // User-level fallback
    const char* home = std::getenv("HOME");
    if (home) {
        std::string socket_dir = std::string(home) + "/.edgelink";
        std::filesystem::create_directories(socket_dir);
        return "unix://" + socket_dir + "/client.sock";
    }
    return "unix:///tmp/edgelink-client.sock";
#endif
}

// ============================================================================
// IPCServiceImpl
// ============================================================================

IPCServiceImpl::IPCServiceImpl(Client* client)
    : client_(client)
{}

grpc::Status IPCServiceImpl::Status(
    grpc::ServerContext* context,
    const edgelink::IPCStatusRequest* request,
    edgelink::IPCStatusResponse* response) {

    if (!client_) {
        return grpc::Status(grpc::StatusCode::INTERNAL, "Client not available");
    }

    // Basic info
    response->set_connected(client_->is_running());
    response->set_state(client_->get_state_string());
    response->set_controller_url(client_->get_controller_url());

    auto control = client_->get_control_channel();
    if (control) {
        response->set_node_id(control->node_id());
        response->set_virtual_ip(control->virtual_ip());
    }

    auto tun = client_->get_tun_device();
    if (tun) {
        response->set_tun_interface(tun->name());
    }

    // Stats
    auto stats = client_->get_stats();
    response->set_packets_sent(stats.packets_sent);
    response->set_packets_received(stats.packets_received);
    response->set_bytes_sent(stats.bytes_sent);
    response->set_bytes_received(stats.bytes_received);

    auto now = std::chrono::steady_clock::now();
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        now - stats.start_time).count();
    response->set_uptime_seconds(uptime);

    // Note: Detailed peer/relay info would require additional accessor methods
    // For now, we return basic status only

    return grpc::Status::OK;
}

grpc::Status IPCServiceImpl::Disconnect(
    grpc::ServerContext* context,
    const edgelink::IPCDisconnectRequest* request,
    edgelink::IPCDisconnectResponse* response) {

    if (!client_) {
        response->set_success(false);
        response->set_message("Client not available");
        return grpc::Status::OK;
    }

    LOG_INFO("IPCService: Disconnect requested via IPC");
    client_->stop();

    response->set_success(true);
    response->set_message("Disconnected");
    return grpc::Status::OK;
}

grpc::Status IPCServiceImpl::Reconnect(
    grpc::ServerContext* context,
    const edgelink::IPCReconnectRequest* request,
    edgelink::IPCReconnectResponse* response) {

    if (!client_) {
        response->set_success(false);
        response->set_message("Client not available");
        return grpc::Status::OK;
    }

    LOG_INFO("IPCService: Reconnect requested via IPC");

    auto control = client_->get_control_channel();
    if (control) {
        control->reconnect();
        response->set_success(true);
        response->set_message("Reconnecting...");
    } else {
        response->set_success(false);
        response->set_message("Control channel not available");
    }

    return grpc::Status::OK;
}

grpc::Status IPCServiceImpl::Ping(
    grpc::ServerContext* context,
    const edgelink::IPCPingRequest* request,
    edgelink::IPCPingResponse* response) {

    if (!client_) {
        response->set_success(false);
        response->set_error("Client not available");
        return grpc::Status::OK;
    }

    uint32_t peer_id = request->peer_node_id();

    if (peer_id == 0) {
        // Ping controller - check if connected
        auto control = client_->get_control_channel();
        if (control && control->is_connected()) {
            response->set_success(true);
            response->set_latency_ms(0);  // Control channel handles its own ping/pong
        } else {
            response->set_success(false);
            response->set_error("Not connected to controller");
        }
    } else {
        // Ping peer - for now just report if client is running
        // TODO: Implement actual peer ping via P2P or Relay
        response->set_success(false);
        response->set_error("Peer ping not implemented yet");
    }

    return grpc::Status::OK;
}

// ============================================================================
// IPCServer
// ============================================================================

IPCServer::IPCServer(Client* client)
    : client_(client)
{}

IPCServer::~IPCServer() {
    stop();
}

bool IPCServer::start() {
    if (running_) return true;

    std::string socket_path = get_socket_path();

#ifndef _WIN32
    // Remove existing socket file
    std::string file_path = socket_path.substr(7);  // Remove "unix://"
    std::remove(file_path.c_str());
#endif

    service_ = std::make_unique<IPCServiceImpl>(client_);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(socket_path, grpc::InsecureServerCredentials());
    builder.RegisterService(service_.get());

    server_ = builder.BuildAndStart();

    if (!server_) {
        LOG_ERROR("IPCServer: Failed to start on {}", socket_path);
        return false;
    }

#ifndef _WIN32
    // Set socket permissions to allow user access
    std::string file_path2 = socket_path.substr(7);
    chmod(file_path2.c_str(), 0660);
#endif

    running_ = true;
    LOG_INFO("IPCServer: Listening on {}", socket_path);
    return true;
}

void IPCServer::stop() {
    if (!running_) return;

    if (server_) {
        server_->Shutdown();
        server_.reset();
    }

    service_.reset();
    running_ = false;

#ifndef _WIN32
    // Clean up socket file
    std::string socket_path = get_socket_path();
    std::string file_path = socket_path.substr(7);
    std::remove(file_path.c_str());
#endif

    LOG_INFO("IPCServer: Stopped");
}

// ============================================================================
// IPCClient (for CLI)
// ============================================================================

IPCClient::IPCClient() {}

IPCClient::~IPCClient() {}

bool IPCClient::connect() {
    std::string socket_path = IPCServer::get_socket_path();

    channel_ = grpc::CreateChannel(socket_path, grpc::InsecureChannelCredentials());

    // Try to connect with timeout
    auto deadline = std::chrono::system_clock::now() + std::chrono::seconds(2);
    if (!channel_->WaitForConnected(deadline)) {
        return false;
    }

    stub_ = edgelink::IPCService::NewStub(channel_);
    connected_ = true;
    return true;
}

std::optional<edgelink::IPCStatusResponse> IPCClient::status() {
    if (!connected_ || !stub_) return std::nullopt;

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));

    edgelink::IPCStatusRequest request;
    edgelink::IPCStatusResponse response;

    auto status = stub_->Status(&context, request, &response);
    if (!status.ok()) {
        return std::nullopt;
    }

    return response;
}

std::optional<edgelink::IPCDisconnectResponse> IPCClient::disconnect() {
    if (!connected_ || !stub_) return std::nullopt;

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));

    edgelink::IPCDisconnectRequest request;
    edgelink::IPCDisconnectResponse response;

    auto status = stub_->Disconnect(&context, request, &response);
    if (!status.ok()) {
        return std::nullopt;
    }

    return response;
}

std::optional<edgelink::IPCReconnectResponse> IPCClient::reconnect() {
    if (!connected_ || !stub_) return std::nullopt;

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));

    edgelink::IPCReconnectRequest request;
    edgelink::IPCReconnectResponse response;

    auto status = stub_->Reconnect(&context, request, &response);
    if (!status.ok()) {
        return std::nullopt;
    }

    return response;
}

std::optional<edgelink::IPCPingResponse> IPCClient::ping(uint32_t peer_node_id) {
    if (!connected_ || !stub_) return std::nullopt;

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(10));

    edgelink::IPCPingRequest request;
    request.set_peer_node_id(peer_node_id);

    edgelink::IPCPingResponse response;

    auto status = stub_->Ping(&context, request, &response);
    if (!status.ok()) {
        return std::nullopt;
    }

    return response;
}

} // namespace edgelink::client

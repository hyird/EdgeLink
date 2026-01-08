#pragma once

#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>

#include <grpcpp/grpcpp.h>
#include "edgelink.grpc.pb.h"

namespace edgelink::client {

// Forward declarations
class Client;

// ============================================================================
// IPC Service Implementation
// ============================================================================

class IPCServiceImpl final : public edgelink::IPCService::Service {
public:
    explicit IPCServiceImpl(Client* client);

    grpc::Status Status(
        grpc::ServerContext* context,
        const edgelink::IPCStatusRequest* request,
        edgelink::IPCStatusResponse* response) override;

    grpc::Status Disconnect(
        grpc::ServerContext* context,
        const edgelink::IPCDisconnectRequest* request,
        edgelink::IPCDisconnectResponse* response) override;

    grpc::Status Reconnect(
        grpc::ServerContext* context,
        const edgelink::IPCReconnectRequest* request,
        edgelink::IPCReconnectResponse* response) override;

    grpc::Status Ping(
        grpc::ServerContext* context,
        const edgelink::IPCPingRequest* request,
        edgelink::IPCPingResponse* response) override;

private:
    Client* client_;
};

// ============================================================================
// IPC Server (Unix socket for POSIX, named pipe for Windows)
// ============================================================================

class IPCServer {
public:
    explicit IPCServer(Client* client);
    ~IPCServer();

    // Non-copyable
    IPCServer(const IPCServer&) = delete;
    IPCServer& operator=(const IPCServer&) = delete;

    // Start/stop server
    bool start();
    void stop();

    // Get socket path
    static std::string get_socket_path();

private:
    Client* client_;
    std::unique_ptr<IPCServiceImpl> service_;
    std::unique_ptr<grpc::Server> server_;
    std::atomic<bool> running_{false};
};

// ============================================================================
// IPC Client (for CLI to connect to running daemon)
// ============================================================================

class IPCClient {
public:
    IPCClient();
    ~IPCClient();

    // Connect to running daemon
    bool connect();
    bool is_connected() const { return connected_; }

    // Commands
    std::optional<edgelink::IPCStatusResponse> status();
    std::optional<edgelink::IPCDisconnectResponse> disconnect();
    std::optional<edgelink::IPCReconnectResponse> reconnect();
    std::optional<edgelink::IPCPingResponse> ping(uint32_t peer_node_id = 0);

private:
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<edgelink::IPCService::Stub> stub_;
    bool connected_ = false;
};

} // namespace edgelink::client

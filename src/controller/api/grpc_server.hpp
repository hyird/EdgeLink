#pragma once

#include "common/config.hpp"
#include "controller/db/database.hpp"

#include <grpcpp/grpcpp.h>
#include "edgelink.grpc.pb.h"

#include <memory>
#include <string>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace edgelink::controller {

// Forward declarations
class AuthService;
class NodeService;
class ConfigService;
class PathService;

// ============================================================================
// Control Stream Handler
// ============================================================================

class ControlStreamHandler {
public:
    ControlStreamHandler(
        grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream,
        std::shared_ptr<Database> db,
        const std::string& jwt_secret,
        class GrpcSessionManager* session_manager);

    void run();

private:
    void handle_auth_request(const edgelink::AuthRequest& req);
    void handle_latency_report(const edgelink::LatencyReport& report);
    void handle_p2p_init(const edgelink::P2PInit& init);
    void handle_p2p_status(const edgelink::P2PStatus& status);
    void handle_ping(const edgelink::Ping& ping);

    void send_auth_response(bool success, uint32_t node_id,
                            const std::string& virtual_ip,
                            const std::string& auth_token,
                            const std::string& relay_token,
                            const std::string& error_msg = "");
    void send_config();
    void send_config_update();
    void send_pong(uint64_t timestamp);
    void send_error(edgelink::ErrorCode code, const std::string& message);

    grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream_;
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;
    class GrpcSessionManager* session_manager_;

    bool authenticated_{false};
    uint32_t node_id_{0};
    uint32_t network_id_{0};
    std::string machine_key_;
};

// ============================================================================
// Server Stream Handler
// ============================================================================

class ServerStreamHandler {
public:
    ServerStreamHandler(
        grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream,
        std::shared_ptr<Database> db,
        const std::string& server_token,
        class GrpcSessionManager* session_manager);

    void run();

private:
    void handle_server_register(const edgelink::ServerRegister& req);
    void handle_server_heartbeat(const edgelink::ServerHeartbeat& hb);
    void handle_server_latency_report(const edgelink::ServerLatencyReport& report);
    void handle_ping(const edgelink::Ping& ping);

    void send_register_response(bool success, uint32_t server_id,
                                const std::string& error_msg = "");
    void send_node_locations();
    void send_relay_list();
    void send_pong(uint64_t timestamp);
    void send_error(edgelink::ErrorCode code, const std::string& message);

    grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream_;
    std::shared_ptr<Database> db_;
    std::string server_token_;
    class GrpcSessionManager* session_manager_;

    bool authenticated_{false};
    uint32_t server_id_{0};
    std::string server_name_;
};

// ============================================================================
// gRPC Session Manager
// ============================================================================

class GrpcSessionManager {
public:
    // Control sessions (nodes)
    void add_control_session(uint32_t node_id, uint32_t network_id,
        grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream);
    void remove_control_session(uint32_t node_id);

    // Server sessions (relays/stun)
    void add_server_session(uint32_t server_id,
        grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream);
    void remove_server_session(uint32_t server_id);

    // Send to specific node
    void send_to_node(uint32_t node_id, const edgelink::ControlMessage& msg);

    // Send to specific server
    void send_to_server(uint32_t server_id, const edgelink::ServerMessage& msg);

    // Broadcast to all nodes in a network
    void broadcast_to_network(uint32_t network_id, const edgelink::ControlMessage& msg,
                              uint32_t exclude_node_id = 0);

    // Broadcast to all servers
    void broadcast_to_servers(const edgelink::ServerMessage& msg);

    // Push config update to a node
    void push_config_update(uint32_t node_id);

    // Get counts
    size_t node_count() const;
    size_t server_count() const;

private:
    mutable std::mutex control_mutex_;
    mutable std::mutex server_mutex_;

    struct ControlSession {
        grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream;
        uint32_t network_id;
    };

    struct ServerSession {
        grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream;
    };

    std::unordered_map<uint32_t, ControlSession> control_sessions_;
    std::unordered_map<uint32_t, ServerSession> server_sessions_;
};

// ============================================================================
// Control Service Implementation
// ============================================================================

class ControlServiceImpl final : public edgelink::ControlService::Service {
public:
    ControlServiceImpl(std::shared_ptr<Database> db,
                       const std::string& jwt_secret,
                       GrpcSessionManager* session_manager);

    grpc::Status Control(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<edgelink::ControlMessage, edgelink::ControlMessage>* stream
    ) override;

private:
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;
    GrpcSessionManager* session_manager_;
};

// ============================================================================
// Server Service Implementation
// ============================================================================

class ServerServiceImpl final : public edgelink::ServerService::Service {
public:
    ServerServiceImpl(std::shared_ptr<Database> db,
                      const std::string& server_token,
                      GrpcSessionManager* session_manager);

    grpc::Status ServerChannel(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>* stream
    ) override;

private:
    std::shared_ptr<Database> db_;
    std::string server_token_;
    GrpcSessionManager* session_manager_;
};

// ============================================================================
// Admin Service Implementation (Management API)
// ============================================================================

class AdminServiceImpl final : public edgelink::AdminService::Service {
public:
    AdminServiceImpl(std::shared_ptr<Database> db,
                     GrpcSessionManager* session_manager);

    // Health & Version
    grpc::Status Health(grpc::ServerContext* context,
                        const edgelink::HealthRequest* request,
                        edgelink::HealthResponse* response) override;

    // Network Management
    grpc::Status ListNetworks(grpc::ServerContext* context,
                              const edgelink::ListNetworksRequest* request,
                              edgelink::ListNetworksResponse* response) override;
    grpc::Status CreateNetwork(grpc::ServerContext* context,
                               const edgelink::CreateNetworkRequest* request,
                               edgelink::CreateNetworkResponse* response) override;
    grpc::Status DeleteNetwork(grpc::ServerContext* context,
                               const edgelink::DeleteNetworkRequest* request,
                               edgelink::DeleteNetworkResponse* response) override;

    // Node Management
    grpc::Status ListNodes(grpc::ServerContext* context,
                           const edgelink::ListNodesRequest* request,
                           edgelink::ListNodesResponse* response) override;
    grpc::Status GetNode(grpc::ServerContext* context,
                         const edgelink::GetNodeRequest* request,
                         edgelink::GetNodeResponse* response) override;
    grpc::Status AuthorizeNode(grpc::ServerContext* context,
                               const edgelink::AuthorizeNodeRequest* request,
                               edgelink::AuthorizeNodeResponse* response) override;
    grpc::Status DeauthorizeNode(grpc::ServerContext* context,
                                 const edgelink::DeauthorizeNodeRequest* request,
                                 edgelink::DeauthorizeNodeResponse* response) override;
    grpc::Status DeleteNode(grpc::ServerContext* context,
                            const edgelink::DeleteNodeRequest* request,
                            edgelink::DeleteNodeResponse* response) override;
    grpc::Status UpdateNodeIP(grpc::ServerContext* context,
                              const edgelink::UpdateNodeIPRequest* request,
                              edgelink::UpdateNodeIPResponse* response) override;

    // Server Management
    grpc::Status ListServers(grpc::ServerContext* context,
                             const edgelink::ListServersRequest* request,
                             edgelink::ListServersResponse* response) override;
    grpc::Status RegisterServer(grpc::ServerContext* context,
                                const edgelink::RegisterServerRequest* request,
                                edgelink::RegisterServerResponse* response) override;
    grpc::Status DeleteServer(grpc::ServerContext* context,
                              const edgelink::DeleteServerRequest* request,
                              edgelink::DeleteServerResponse* response) override;

    // Statistics
    grpc::Status GetStats(grpc::ServerContext* context,
                          const edgelink::StatsRequest* request,
                          edgelink::StatsResponse* response) override;

private:
    std::shared_ptr<Database> db_;
    GrpcSessionManager* session_manager_;
};

// Forward declaration
class BuiltinRelay;

// ============================================================================
// gRPC Server
// ============================================================================

class GrpcServer {
public:
    GrpcServer(const ControllerConfig& config,
               std::shared_ptr<Database> db);

    ~GrpcServer();

    void start();
    void stop();

    GrpcSessionManager* get_session_manager() { return &session_manager_; }

    // Set built-in relay (optional, for integrated relay functionality)
    void set_builtin_relay(BuiltinRelay* relay) { builtin_relay_ = relay; }

private:
    void setup_ssl_credentials();

    ControllerConfig config_;
    std::shared_ptr<Database> db_;

    std::unique_ptr<grpc::Server> server_;
    std::unique_ptr<ControlServiceImpl> control_service_;
    std::unique_ptr<ServerServiceImpl> server_service_;
    std::unique_ptr<AdminServiceImpl> admin_service_;
    GrpcSessionManager session_manager_;

    std::shared_ptr<grpc::ServerCredentials> credentials_;
    std::atomic<bool> running_{false};

    BuiltinRelay* builtin_relay_{nullptr};
};

} // namespace edgelink::controller

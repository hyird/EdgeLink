#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/config.hpp"
#include "common/jwt.hpp"

#include <grpcpp/grpcpp.h>
#include "edgelink.grpc.pb.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <functional>
#include <atomic>
#include <thread>

namespace edgelink {

// Forward declarations
class ControllerClient;
class MeshManager;

// ============================================================================
// Relay Stream Handler - Handles one client connection
// ============================================================================

class RelayStreamHandler {
public:
    using DataCallback = std::function<void(uint32_t src_node, uint32_t dst_node,
                                            const std::vector<uint8_t>& data)>;
    using CloseCallback = std::function<void(uint32_t node_id)>;

    RelayStreamHandler(
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream,
        class GrpcRelaySessionManager* session_manager,
        const std::string& jwt_secret);

    void run();

    uint32_t node_id() const { return node_id_; }
    bool is_authenticated() const { return authenticated_; }

    void set_data_callback(DataCallback cb) { data_callback_ = std::move(cb); }
    void set_close_callback(CloseCallback cb) { close_callback_ = std::move(cb); }

    // Send data to this client
    bool send_data(const edgelink::DataPacket& packet);

private:
    void handle_relay_auth(const edgelink::RelayAuth& auth);
    void handle_data(const edgelink::DataPacket& packet);
    void handle_ping(const edgelink::Ping& ping);

    void send_auth_response(bool success, uint32_t node_id, const std::string& error = "");
    void send_pong(uint64_t timestamp);
    void send_error(edgelink::ErrorCode code, const std::string& message);

    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream_;
    class GrpcRelaySessionManager* session_manager_;
    std::string jwt_secret_;

    bool authenticated_{false};
    uint32_t node_id_{0};
    std::string virtual_ip_;

    DataCallback data_callback_;
    CloseCallback close_callback_;
};

// ============================================================================
// Mesh Stream Handler - Handles relay-to-relay connections
// ============================================================================

class MeshStreamHandler {
public:
    MeshStreamHandler(
        grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream,
        class GrpcRelaySessionManager* session_manager,
        const std::string& server_token,
        uint32_t local_server_id);

    void run();

    uint32_t peer_server_id() const { return peer_server_id_; }
    bool is_authenticated() const { return authenticated_; }

    // Forward data through mesh
    bool forward_data(const edgelink::MeshForward& forward);

private:
    void handle_mesh_hello(const edgelink::MeshHello& hello);
    void handle_mesh_forward(const edgelink::MeshForward& forward);
    void handle_mesh_ping(const edgelink::MeshPing& ping);

    void send_hello_ack(bool success, const std::string& error = "");
    void send_pong(uint64_t timestamp);

    grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream_;
    class GrpcRelaySessionManager* session_manager_;
    std::string server_token_;
    uint32_t local_server_id_;

    bool authenticated_{false};
    uint32_t peer_server_id_{0};
};

// ============================================================================
// gRPC Relay Session Manager
// ============================================================================

class GrpcRelaySessionManager {
public:
    GrpcRelaySessionManager(const std::string& jwt_secret);

    // Client session management
    void add_client_session(uint32_t node_id,
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream);
    void remove_client_session(uint32_t node_id);

    // Mesh session management
    void add_mesh_session(uint32_t server_id,
        grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream);
    void remove_mesh_session(uint32_t server_id);

    // Send data to a node
    bool send_to_node(uint32_t node_id, const edgelink::DataPacket& packet);

    // Forward data through mesh
    bool forward_through_mesh(uint32_t target_server_id, const edgelink::MeshForward& forward);

    // Token validation
    bool validate_relay_token(const std::string& token, uint32_t& node_id,
                              std::string& virtual_ip);

    // Node location tracking
    void update_node_locations(const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& locations);
    std::vector<uint32_t> get_node_relay_locations(uint32_t node_id) const;

    // Token blacklist
    void add_to_blacklist(const std::string& jti, int64_t expires_at);

    // Get session counts
    size_t client_count() const;
    size_t mesh_count() const;

    const std::string& jwt_secret() const { return jwt_secret_; }

private:
    std::string jwt_secret_;

    // Client sessions
    mutable std::shared_mutex client_mutex_;
    std::unordered_map<uint32_t,
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>*> client_sessions_;

    // Mesh sessions (to other relays)
    mutable std::shared_mutex mesh_mutex_;
    std::unordered_map<uint32_t,
        grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>*> mesh_sessions_;

    // Token blacklist
    mutable std::shared_mutex blacklist_mutex_;
    std::unordered_map<std::string, int64_t> token_blacklist_;

    // Node locations
    mutable std::shared_mutex locations_mutex_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> node_locations_;
};

// ============================================================================
// Relay Service Implementation
// ============================================================================

class RelayServiceImpl final : public edgelink::RelayService::Service {
public:
    RelayServiceImpl(GrpcRelaySessionManager* session_manager,
                     const std::string& jwt_secret);

    grpc::Status Relay(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream
    ) override;

private:
    GrpcRelaySessionManager* session_manager_;
    std::string jwt_secret_;
};

// ============================================================================
// Mesh Service Implementation
// ============================================================================

class MeshServiceImpl final : public edgelink::MeshService::Service {
public:
    MeshServiceImpl(GrpcRelaySessionManager* session_manager,
                    const std::string& server_token,
                    uint32_t server_id);

    grpc::Status Mesh(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<edgelink::MeshMessage, edgelink::MeshMessage>* stream
    ) override;

private:
    GrpcRelaySessionManager* session_manager_;
    std::string server_token_;
    uint32_t server_id_;
};

// ============================================================================
// gRPC Relay Server
// ============================================================================

class GrpcRelayServer {
public:
    GrpcRelayServer(const ServerConfig& config);
    ~GrpcRelayServer();

    void start();
    void stop();

    // Server ID management
    uint32_t server_id() const { return server_id_; }
    void set_server_id(uint32_t id) { server_id_ = id; }

    // Controller client
    void set_controller_client(std::shared_ptr<ControllerClient> client);
    ControllerClient* controller_client() { return controller_client_.get(); }

    // Get session manager
    GrpcRelaySessionManager* session_manager() { return &session_manager_; }

    // Forward data to destination node
    bool forward_data(uint32_t src_node, uint32_t dst_node,
                      const std::vector<uint8_t>& data);

    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_forwarded{0};
        std::atomic<uint64_t> packets_forwarded{0};
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> connections_active{0};
        std::atomic<uint64_t> auth_failures{0};
    };
    const Stats& stats() const { return stats_; }

private:
    void setup_ssl_credentials();

    const ServerConfig& config_;
    GrpcRelaySessionManager session_manager_;

    std::unique_ptr<grpc::Server> server_;
    std::unique_ptr<RelayServiceImpl> relay_service_;
    std::unique_ptr<MeshServiceImpl> mesh_service_;

    std::shared_ptr<grpc::ServerCredentials> credentials_;
    std::shared_ptr<ControllerClient> controller_client_;

    uint32_t server_id_{0};
    std::atomic<bool> running_{false};
    Stats stats_;
};

} // namespace edgelink

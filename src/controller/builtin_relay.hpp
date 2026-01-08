#pragma once

#include "common/config.hpp"
#include "common/protocol.hpp"
#include "common/jwt.hpp"
#include "controller/db/database.hpp"

#include <grpcpp/grpcpp.h>
#include "edgelink.grpc.pb.h"

#include <memory>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>

namespace edgelink::controller {

// ============================================================================
// Relay Session Manager - Manages relay data connections
// ============================================================================
class RelaySessionManager {
public:
    RelaySessionManager(const std::string& jwt_secret);

    // Add/remove relay sessions
    void add_session(uint32_t node_id,
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream);
    void remove_session(uint32_t node_id);

    // Send data to a node
    bool send_to_node(uint32_t node_id, const edgelink::DataPacket& packet);

    // Token validation
    bool validate_relay_token(const std::string& token, uint32_t& node_id,
                              std::string& virtual_ip);

    // Get session count
    size_t session_count() const;

    const std::string& jwt_secret() const { return jwt_secret_; }

private:
    std::string jwt_secret_;

    mutable std::shared_mutex sessions_mutex_;
    std::unordered_map<uint32_t,
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>*> sessions_;
};

// ============================================================================
// Relay Stream Handler - Handles one client's relay connection
// ============================================================================
class RelayStreamHandler {
public:
    using DataCallback = std::function<void(uint32_t src_node, uint32_t dst_node,
                                            const std::vector<uint8_t>& data)>;
    using CloseCallback = std::function<void(uint32_t node_id)>;

    RelayStreamHandler(
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream,
        RelaySessionManager* session_manager);

    void run();

    uint32_t node_id() const { return node_id_; }
    bool is_authenticated() const { return authenticated_; }

    void set_data_callback(DataCallback cb) { data_callback_ = std::move(cb); }
    void set_close_callback(CloseCallback cb) { close_callback_ = std::move(cb); }

private:
    void handle_relay_auth(const edgelink::RelayAuth& auth);
    void handle_data(const edgelink::DataPacket& packet);
    void handle_ping(const edgelink::Ping& ping);

    void send_auth_response(bool success, uint32_t node_id, const std::string& error = "");
    void send_pong(uint64_t timestamp);
    void send_error(edgelink::ErrorCode code, const std::string& message);

    grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream_;
    RelaySessionManager* session_manager_;

    bool authenticated_{false};
    uint32_t node_id_{0};
    std::string virtual_ip_;

    DataCallback data_callback_;
    CloseCallback close_callback_;
};

// ============================================================================
// Built-in Relay Service Implementation
// ============================================================================
class BuiltinRelayServiceImpl final : public edgelink::RelayService::Service {
public:
    BuiltinRelayServiceImpl(RelaySessionManager* session_manager,
                            std::shared_ptr<Database> db);

    grpc::Status Relay(
        grpc::ServerContext* context,
        grpc::ServerReaderWriter<edgelink::RelayMessage, edgelink::RelayMessage>* stream
    ) override;

private:
    RelaySessionManager* session_manager_;
    std::shared_ptr<Database> db_;
};

// ============================================================================
// BuiltinRelay - Built-in relay functionality for Controller (gRPC version)
// ============================================================================
class BuiltinRelay {
public:
    BuiltinRelay(const BuiltinRelayConfig& config,
                 std::shared_ptr<Database> db,
                 const std::string& jwt_secret);
    ~BuiltinRelay();

    // Get the gRPC service implementation
    edgelink::RelayService::Service* get_service() { return relay_service_.get(); }

    // Forward data to destination node
    bool forward_data(uint32_t dst_node_id, const std::vector<uint8_t>& data,
                      uint32_t src_node_id);

    // Get session manager
    RelaySessionManager* session_manager() { return &session_manager_; }

    // Get database
    std::shared_ptr<Database> database() { return db_; }

    // Statistics
    struct Stats {
        std::atomic<uint64_t> bytes_forwarded{0};
        std::atomic<uint64_t> packets_forwarded{0};
        std::atomic<uint64_t> connections_total{0};
        std::atomic<uint64_t> connections_active{0};
    };
    const Stats& stats() const { return stats_; }

    // Configuration
    const BuiltinRelayConfig& config() const { return config_; }

    // Check if enabled
    bool is_enabled() const { return config_.enabled; }

private:
    BuiltinRelayConfig config_;
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;

    RelaySessionManager session_manager_;
    std::unique_ptr<BuiltinRelayServiceImpl> relay_service_;

    Stats stats_;
};

} // namespace edgelink::controller

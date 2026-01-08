#pragma once

#include "common/protocol.hpp"
#include "common/config.hpp"

#include <grpcpp/grpcpp.h>
#include "edgelink.grpc.pb.h"

#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>

namespace edgelink {

// Forward declarations
class GrpcRelayServer;

// ============================================================================
// ControllerClient - gRPC client to connect relay to controller
// ============================================================================
class ControllerClient : public std::enable_shared_from_this<ControllerClient> {
public:
    using ConnectCallback = std::function<void(bool success, const std::string& error)>;
    using MessageCallback = std::function<void(const edgelink::ServerMessage& msg)>;
    using DisconnectCallback = std::function<void(const std::string& reason)>;

    ControllerClient(GrpcRelayServer& server, const ServerConfig& config);
    ~ControllerClient();

    // Connect to controller
    void connect();

    // Disconnect
    void disconnect();

    // Send message to controller
    void send(const edgelink::ServerMessage& msg);

    // Check connection state
    bool is_connected() const { return connected_; }

    // Set callbacks
    void set_connect_callback(ConnectCallback cb) { connect_callback_ = std::move(cb); }
    void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
    void set_disconnect_callback(DisconnectCallback cb) { disconnect_callback_ = std::move(cb); }

    // Send latency report to controller
    void send_latency_report(const std::vector<std::tuple<std::string, uint32_t, uint32_t>>& entries);

    // Get server ID (assigned by controller)
    uint32_t server_id() const { return server_id_; }

private:
    void run_connection();
    void do_register();
    void process_message(const edgelink::ServerMessage& msg);
    void handle_server_node_loc(const edgelink::ServerNodeLoc& locs);
    void handle_server_relay_list(const edgelink::ServerRelayList& list);
    void handle_ping(const edgelink::Ping& ping);
    void schedule_reconnect();
    void start_heartbeat();

    GrpcRelayServer& server_;
    const ServerConfig& config_;

    // gRPC channel and stream
    std::shared_ptr<grpc::Channel> channel_;
    std::unique_ptr<edgelink::ServerService::Stub> stub_;
    std::unique_ptr<grpc::ClientContext> context_;
    std::unique_ptr<grpc::ClientReaderWriter<edgelink::ServerMessage, edgelink::ServerMessage>> stream_;

    // Connection thread
    std::unique_ptr<std::thread> connection_thread_;
    std::unique_ptr<std::thread> heartbeat_thread_;

    // State
    std::atomic<bool> connected_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> registered_{false};
    uint32_t server_id_{0};

    // Reconnection
    int reconnect_attempts_{0};
    static constexpr int MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr int BASE_RECONNECT_DELAY_MS = 1000;
    static constexpr int MAX_RECONNECT_DELAY_MS = 60000;

    // Callbacks
    ConnectCallback connect_callback_;
    MessageCallback message_callback_;
    DisconnectCallback disconnect_callback_;
};

} // namespace edgelink

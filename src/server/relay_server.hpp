#pragma once

#include "relay_session.hpp"
#include "common/config.hpp"
#include "common/jwt.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <memory>
#include <thread>
#include <atomic>

namespace edgelink {

namespace asio = boost::asio;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

// Forward declarations
class ControllerClient;
class MeshManager;

// ============================================================================
// RelayServer - Main relay server class
// ============================================================================
class RelayServer {
public:
    RelayServer(asio::io_context& ioc, const ServerConfig& config);
    ~RelayServer();
    
    // Start/stop the server
    void start();
    void stop();
    
    // Get session manager
    RelaySessionManager& session_manager() { return session_manager_; }
    
    // Get server ID (assigned by controller)
    uint32_t server_id() const { return server_id_; }
    void set_server_id(uint32_t id) { server_id_ = id; }
    
    // Set controller client for control plane communications
    void set_controller_client(std::shared_ptr<ControllerClient> client) { 
        controller_client_ = std::move(client); 
    }
    
    // Get controller client
    ControllerClient* controller_client() { return controller_client_.get(); }
    
    // Set mesh manager for Relay-to-Relay mesh forwarding
    // Note: Controller only decides paths, data flows through mesh connections
    void set_mesh_manager(std::shared_ptr<MeshManager> manager) {
        mesh_manager_ = std::move(manager);
    }
    
    // Get mesh manager
    MeshManager* mesh_manager() { return mesh_manager_.get(); }
    
    // Forward data to destination node
    bool forward_data(const DataPayload& data);
    
    // Broadcast to all connected nodes
    void broadcast(const Frame& frame);
    
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
    void do_accept();
    void on_accept(beast::error_code ec, tcp::socket socket);
    
    // Handle incoming frame from a session
    void on_message(std::shared_ptr<RelaySession> session, const Frame& frame);
    void on_close(std::shared_ptr<RelaySession> session);
    
    // Handle specific message types
    void handle_auth(std::shared_ptr<RelaySession> session, const Frame& frame);
    void handle_data(std::shared_ptr<RelaySession> session, const Frame& frame);
    void handle_ping(std::shared_ptr<RelaySession> session, const Frame& frame);
    void handle_mesh_hello(std::shared_ptr<RelaySession> session, const Frame& frame);
    
    asio::io_context& ioc_;
    const ServerConfig& config_;
    JWTManager jwt_manager_;
    RelaySessionManager session_manager_;
    
    // TCP acceptor
    tcp::acceptor acceptor_;
    
    // SSL context (if TLS enabled)
    std::unique_ptr<ssl::context> ssl_ctx_;
    
    // Controller client for control plane communications
    std::shared_ptr<ControllerClient> controller_client_;
    
    // Mesh manager for Relay-to-Relay data forwarding
    std::shared_ptr<MeshManager> mesh_manager_;
    
    // Server ID (assigned by controller)
    uint32_t server_id_{0};
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Statistics
    Stats stats_;
};

} // namespace edgelink

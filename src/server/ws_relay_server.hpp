#pragma once

#include "common/protocol.hpp"
#include "common/frame.hpp"
#include "common/config.hpp"
#include "common/jwt.hpp"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/ssl.hpp>

#include <memory>
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <functional>
#include <atomic>
#include <thread>

namespace edgelink {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = boost::asio::ip::tcp;

// Forward declarations
class ControllerClient;
class MeshManager;

// ============================================================================
// WebSocket Relay Session Manager
// ============================================================================

class WsRelaySessionManager {
public:
    WsRelaySessionManager(const std::string& jwt_secret);

    // Client session management
    void add_client_session(uint32_t node_id, void* session);
    void remove_client_session(uint32_t node_id);
    void* get_client_session(uint32_t node_id);

    // Mesh session management
    void add_mesh_session(uint32_t server_id, void* session);
    void remove_mesh_session(uint32_t server_id);
    void* get_mesh_session(uint32_t server_id);

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
    std::unordered_map<uint32_t, void*> client_sessions_;

    // Mesh sessions (to other relays)
    mutable std::shared_mutex mesh_mutex_;
    std::unordered_map<uint32_t, void*> mesh_sessions_;

    // Token blacklist
    mutable std::shared_mutex blacklist_mutex_;
    std::unordered_map<std::string, int64_t> token_blacklist_;

    // Node locations
    mutable std::shared_mutex locations_mutex_;
    std::unordered_map<uint32_t, std::vector<uint32_t>> node_locations_;
};

// ============================================================================
// WebSocket Relay Server
// ============================================================================

class WsRelayServer {
public:
    WsRelayServer(net::io_context& ioc, const ServerConfig& config);
    ~WsRelayServer();

    void start();
    void stop();

    // Server ID management
    uint32_t server_id() const { return server_id_; }
    void set_server_id(uint32_t id) { server_id_ = id; }

    // Controller client
    void set_controller_client(std::shared_ptr<ControllerClient> client);
    ControllerClient* controller_client() { return controller_client_.get(); }

    // Get session manager
    WsRelaySessionManager* session_manager() { return &session_manager_; }

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
    void do_accept();

    net::io_context& ioc_;
    const ServerConfig& config_;
    WsRelaySessionManager session_manager_;

    std::unique_ptr<tcp::acceptor> acceptor_;
    ssl::context ssl_ctx_{ssl::context::tlsv12_server};

    std::shared_ptr<ControllerClient> controller_client_;

    uint32_t server_id_{0};
    std::atomic<bool> running_{false};
    Stats stats_;
};

} // namespace edgelink

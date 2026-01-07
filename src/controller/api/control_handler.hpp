#pragma once

#include <memory>
#include <string>
#include <functional>
#include <nlohmann/json.hpp>

#include "controller/db/database.hpp"

namespace edgelink::controller {

class WebSocketSession;
class PathService;

// ============================================================================
// Control Protocol Handler
// Handles WebSocket messages for /ws/control (client nodes)
// ============================================================================
class ControlProtocolHandler {
public:
    using SendCallback = std::function<void(const std::string&)>;
    
    explicit ControlProtocolHandler(std::shared_ptr<Database> db, 
                                    const std::string& jwt_secret,
                                    std::shared_ptr<PathService> path_service = nullptr);
    
    // Handle incoming message, returns response to send (empty if none)
    std::string handle_message(const std::string& message, 
                               const std::string& query_string);
    
    // Get node ID after authentication
    uint32_t get_node_id() const { return node_id_; }
    uint32_t get_network_id() const { return network_id_; }
    bool is_authenticated() const { return authenticated_; }
    
    // Set path service (can be set after construction)
    void set_path_service(std::shared_ptr<PathService> path_service) {
        path_service_ = std::move(path_service);
    }
    
    // Generate config update message (public for push updates)
    std::string generate_config_update();
    
private:
    // Message handlers
    std::string handle_auth(const nlohmann::json& msg);
    std::string handle_heartbeat(const nlohmann::json& msg);
    std::string handle_endpoint_report(const nlohmann::json& msg);
    std::string handle_latency_report(const nlohmann::json& msg);
    std::string handle_key_rotation(const nlohmann::json& msg);
    std::string handle_relay_connect(const nlohmann::json& msg);
    std::string handle_relay_disconnect(const nlohmann::json& msg);
    std::string handle_p2p_request(const nlohmann::json& msg);
    
    // Generate path info for a specific peer
    nlohmann::json generate_peer_path_info(uint32_t peer_node_id);
    
    // Generate JWT tokens
    std::string generate_auth_token(uint32_t node_id);
    std::string generate_relay_token(uint32_t node_id);
    
    // Parse machine key from query string
    std::string extract_machine_key(const std::string& query);
    
    std::shared_ptr<Database> db_;
    std::shared_ptr<PathService> path_service_;
    std::string jwt_secret_;
    
    // Session state
    bool authenticated_ = false;
    uint32_t node_id_ = 0;
    uint32_t network_id_ = 0;
    std::string machine_key_;
    std::string virtual_ip_;
};

// ============================================================================
// Server Protocol Handler  
// Handles WebSocket messages for /ws/server (relay servers)
// ============================================================================
class ServerProtocolHandler {
public:
    using SendCallback = std::function<void(const std::string&)>;
    using MeshForwardCallback = std::function<void(uint32_t relay_id, const std::string& message)>;
    
    explicit ServerProtocolHandler(std::shared_ptr<Database> db,
                                   const std::string& jwt_secret,
                                   const std::string& server_token = "");
    
    std::string handle_message(const std::string& message,
                               const std::string& query_string);
    
    uint32_t get_server_id() const { return server_id_; }
    bool is_authenticated() const { return authenticated_; }
    
    // Set callback for forwarding messages to other relays
    void set_mesh_forward_callback(MeshForwardCallback cb) { 
        mesh_forward_callback_ = std::move(cb); 
    }
    
private:
    std::string handle_register(const nlohmann::json& msg);
    std::string handle_heartbeat(const nlohmann::json& msg);
    std::string handle_stats_report(const nlohmann::json& msg);
    std::string handle_mesh_forward(const nlohmann::json& msg);
    
    std::shared_ptr<Database> db_;
    std::string jwt_secret_;
    std::string server_token_;
    
    bool authenticated_ = false;
    uint32_t server_id_ = 0;
    std::string server_name_;
    
    MeshForwardCallback mesh_forward_callback_;
};

} // namespace edgelink::controller

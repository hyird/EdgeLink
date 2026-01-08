#include "controller/api/control_handler.hpp"
#include "controller/services/path_service.hpp"
#include "common/log.hpp"
#include "common/jwt.hpp"

#include <chrono>
#include <sstream>
#include <regex>

namespace edgelink::controller {

using json = nlohmann::json;

// ============================================================================
// ControlProtocolHandler
// ============================================================================

ControlProtocolHandler::ControlProtocolHandler(std::shared_ptr<Database> db,
                                               const std::string& jwt_secret,
                                               std::shared_ptr<PathService> path_service)
    : db_(std::move(db))
    , path_service_(std::move(path_service))
    , jwt_secret_(jwt_secret) {
}

std::string ControlProtocolHandler::handle_message(const std::string& message,
                                                   const std::string& query_string) {
    try {
        // First message might be empty (just connected)
        // Don't try to auto-authenticate from query string - wait for explicit auth message
        // This ensures auth_key can be included for new node registration
        if (message.empty()) {
            // Just save the machine_key for reference, but don't authenticate yet
            machine_key_ = extract_machine_key(query_string);
            LOG_DEBUG("ControlProtocolHandler: Empty message, machine_key from query: {}...", 
                      machine_key_.empty() ? "(none)" : machine_key_.substr(0, 10));
            return "";
        }
        
        json msg = json::parse(message);
        std::string type = msg.value("type", "");
        
        LOG_DEBUG("ControlProtocolHandler: Received message type: {}", type);
        
        if (type == "auth" || type == "authenticate") {
            return handle_auth(msg);
        }
        
        // Require authentication for other messages
        if (!authenticated_) {
            json error;
            error["type"] = "error";
            error["error"] = "not_authenticated";
            error["message"] = "Authentication required";
            return error.dump();
        }
        
        if (type == "heartbeat" || type == "ping") {
            return handle_heartbeat(msg);
        } else if (type == "endpoint_report") {
            return handle_endpoint_report(msg);
        } else if (type == "latency_report") {
            return handle_latency_report(msg);
        } else if (type == "key_rotation") {
            return handle_key_rotation(msg);
        } else if (type == "relay_connect") {
            return handle_relay_connect(msg);
        } else if (type == "relay_disconnect") {
            return handle_relay_disconnect(msg);
        } else if (type == "p2p_request") {
            return handle_p2p_request(msg);
        } else {
            LOG_WARN("ControlProtocolHandler: Unknown message type: {}", type);
            json error;
            error["type"] = "error";
            error["error"] = "unknown_type";
            error["message"] = "Unknown message type: " + type;
            return error.dump();
        }
    } catch (const json::parse_error& e) {
        LOG_ERROR("ControlProtocolHandler: JSON parse error: {}", e.what());
        json error;
        error["type"] = "error";
        error["error"] = "parse_error";
        error["message"] = "Invalid JSON";
        return error.dump();
    } catch (const std::exception& e) {
        LOG_ERROR("ControlProtocolHandler: Error handling message: {}", e.what());
        json error;
        error["type"] = "error";
        error["error"] = "internal_error";
        error["message"] = e.what();
        return error.dump();
    }
}

std::string ControlProtocolHandler::handle_auth(const json& msg) {
    // Get machine key from message or use already extracted one
    std::string key = msg.value("machine_key", machine_key_);
    if (key.empty()) {
        key = msg.value("machine_key_pub", "");
    }
    
    if (key.empty()) {
        json error;
        error["type"] = "auth_response";
        error["success"] = false;
        error["error"] = "missing_key";
        error["message"] = "Machine key required";
        return error.dump();
    }
    
    machine_key_ = key;
    
    // Check for auth_key (pre-authorization key)
    std::string auth_key = msg.value("auth_key", "");
    
    // Debug: log what we received
    LOG_DEBUG("ControlProtocolHandler: Received auth request - machine_key: {}..., auth_key: {}, msg_keys: {}", 
              key.substr(0, 10),
              auth_key.empty() ? "(empty)" : auth_key.substr(0, 8) + "...",
              msg.dump().substr(0, 200));
    
    // Look up node by machine key
    auto node_opt = db_->get_node_by_machine_key(key);
    
    if (!node_opt) {
        // Node not registered - need auth_key to register
        if (auth_key.empty()) {
            LOG_WARN("ControlProtocolHandler: Unknown machine key without auth_key: {}", 
                     key.substr(0, 10) + "...");
            json error;
            error["type"] = "auth_response";
            error["success"] = false;
            error["error"] = "unknown_node";
            error["message"] = "Node not registered. Provide auth_key to register.";
            return error.dump();
        }
        
        // Validate auth_key
        auto auth_key_opt = db_->get_auth_key_by_key(auth_key);
        if (!auth_key_opt) {
            LOG_WARN("ControlProtocolHandler: Invalid auth_key");
            json error;
            error["type"] = "auth_response";
            error["success"] = false;
            error["error"] = "invalid_auth_key";
            error["message"] = "Invalid auth key";
            return error.dump();
        }
        
        if (!db_->is_auth_key_valid(*auth_key_opt)) {
            LOG_WARN("ControlProtocolHandler: Expired or exhausted auth_key");
            json error;
            error["type"] = "auth_response";
            error["success"] = false;
            error["error"] = "auth_key_expired";
            error["message"] = "Auth key expired or usage limit reached";
            return error.dump();
        }
        
        // Register new node
        Node new_node;
        new_node.network_id = auth_key_opt->network_id;
        new_node.name = msg.value("hostname", "");
        new_node.machine_key_pub = key;
        new_node.node_key_pub = msg.value("node_key", "");
        new_node.hostname = msg.value("hostname", "");
        new_node.os = msg.value("os", "");
        new_node.arch = msg.value("arch", "");
        new_node.version = msg.value("version", "");
        new_node.authorized = true;  // Pre-authorized via auth_key
        new_node.online = true;
        
        // Allocate virtual IP
        new_node.virtual_ip = db_->allocate_virtual_ip(auth_key_opt->network_id);
        if (new_node.virtual_ip.empty()) {
            json error;
            error["type"] = "auth_response";
            error["success"] = false;
            error["error"] = "ip_exhausted";
            error["message"] = "No available IP addresses in network";
            return error.dump();
        }
        
        uint32_t node_id = db_->create_node(new_node);
        if (node_id == 0) {
            json error;
            error["type"] = "auth_response";
            error["success"] = false;
            error["error"] = "registration_failed";
            error["message"] = "Failed to register node";
            return error.dump();
        }
        
        // Increment auth_key usage
        db_->increment_auth_key_usage(auth_key_opt->id);
        
        LOG_INFO("ControlProtocolHandler: Registered new node {} ({}) via auth_key", 
                 node_id, new_node.hostname);
        
        // Set session state
        authenticated_ = true;
        node_id_ = node_id;
        network_id_ = auth_key_opt->network_id;
        virtual_ip_ = new_node.virtual_ip;
        
        return generate_config_update();
    }
    
    const Node& node = *node_opt;
    
    // Check authorization
    if (!node.authorized) {
        // If auth_key provided, authorize the node
        if (!auth_key.empty()) {
            auto auth_key_opt = db_->get_auth_key_by_key(auth_key);
            if (auth_key_opt && db_->is_auth_key_valid(*auth_key_opt) && 
                auth_key_opt->network_id == node.network_id) {
                // Authorize the node
                Node updated_node = node;
                updated_node.authorized = true;
                db_->update_node(updated_node);
                db_->increment_auth_key_usage(auth_key_opt->id);
                LOG_INFO("ControlProtocolHandler: Node {} authorized via auth_key", node.id);
            } else {
                json error;
                error["type"] = "auth_response";
                error["success"] = false;
                error["error"] = "invalid_auth_key";
                error["message"] = "Invalid auth key for this network";
                return error.dump();
            }
        } else {
            LOG_WARN("ControlProtocolHandler: Node {} not authorized", node.id);
            json error;
            error["type"] = "auth_response";
            error["success"] = false;
            error["error"] = "not_authorized";
            error["message"] = "Node pending authorization";
            return error.dump();
        }
    }
    
    // Authentication successful
    authenticated_ = true;
    node_id_ = node.id;
    network_id_ = node.network_id;
    virtual_ip_ = node.virtual_ip;
    
    // Update last seen and online status
    {
        Node updated_node = node;
        updated_node.online = true;
        updated_node.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        db_->update_node(updated_node);
    }
    
    LOG_INFO("ControlProtocolHandler: Node {} ({}) authenticated", 
             node_id_, node.hostname);
    
    // Generate tokens
    std::string auth_token = generate_auth_token(node_id_);
    std::string relay_token = generate_relay_token(node_id_);
    
    // Build auth response with full config
    return generate_config_update();
}

std::string ControlProtocolHandler::handle_heartbeat(const json& msg) {
    // Update last seen - get node, update, and save
    auto node_opt = db_->get_node(node_id_);
    if (node_opt) {
        Node node = *node_opt;
        node.online = true;
        node.last_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        db_->update_node(node);
    }
    
    json response;
    response["type"] = "pong";
    response["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Check if config has changed
    // TODO: Implement config versioning
    
    return response.dump();
}

std::string ControlProtocolHandler::handle_endpoint_report(const json& msg) {
    // Parse endpoints from message
    auto endpoints_json = msg.value("endpoints", json::array());
    std::string nat_type_str = msg.value("nat_type", "unknown");
    
    LOG_DEBUG("ControlProtocolHandler: Node {} reported {} endpoints, NAT type: {}",
              node_id_, endpoints_json.size(), nat_type_str);
    
    // Convert to NodeEndpoint format and store
    std::vector<NodeEndpoint> endpoints;
    for (const auto& ep : endpoints_json) {
        NodeEndpoint nep;
        nep.node_id = node_id_;
        if (ep.is_string()) {
            // Parse "ip:port" format
            std::string ep_str = ep.get<std::string>();
            auto colon_pos = ep_str.find(':');
            if (colon_pos != std::string::npos) {
                nep.ip = ep_str.substr(0, colon_pos);
                nep.port = static_cast<uint16_t>(std::stoi(ep_str.substr(colon_pos + 1)));
                nep.type = "stun";  // Default type
                endpoints.push_back(nep);
            }
        } else if (ep.is_object()) {
            nep.ip = ep.value("address", ep.value("ip", ""));
            nep.port = ep.value("port", 0);
            nep.type = ep.value("type", "stun");
            if (!nep.ip.empty() && nep.port > 0) {
                endpoints.push_back(nep);
            }
        }
    }
    
    // Store endpoints in database
    if (!endpoints.empty()) {
        db_->update_node_endpoints(node_id_, endpoints);
    }
    
    // Update NAT type in node record
    // TODO: Add nat_type field to nodes table
    
    json response;
    response["type"] = "endpoint_ack";
    response["success"] = true;
    response["stored_count"] = endpoints.size();
    return response.dump();
}

std::string ControlProtocolHandler::handle_p2p_request(const json& msg) {
    // Client is requesting P2P connection to a peer
    uint32_t peer_node_id = msg.value("peer_node_id", 0);
    
    if (peer_node_id == 0) {
        json error;
        error["type"] = "error";
        error["error"] = "invalid_peer_id";
        error["message"] = "peer_node_id is required";
        return error.dump();
    }
    
    LOG_INFO("ControlProtocolHandler: Node {} requesting P2P to peer {}", 
             node_id_, peer_node_id);
    
    // Get peer's endpoints from database
    auto peer_endpoints = db_->get_node_endpoints(peer_node_id);
    
    if (peer_endpoints.empty()) {
        json response;
        response["type"] = "p2p_response";
        response["success"] = false;
        response["peer_node_id"] = peer_node_id;
        response["error"] = "no_endpoints";
        response["message"] = "Peer has no reported endpoints";
        return response.dump();
    }
    
    // Build response with peer's endpoints
    json response;
    response["type"] = "p2p_response";
    response["success"] = true;
    response["peer_node_id"] = peer_node_id;
    
    json ep_array = json::array();
    for (const auto& ep : peer_endpoints) {
        json ep_obj;
        ep_obj["address"] = ep.ip;
        ep_obj["port"] = ep.port;
        ep_obj["type"] = ep.type;
        ep_array.push_back(ep_obj);
    }
    response["endpoints"] = ep_array;
    
    // TODO: Include peer's NAT type
    response["nat_type"] = "unknown";
    
    return response.dump();
}

std::string ControlProtocolHandler::handle_latency_report(const json& msg) {
    // Parse latency measurements
    // Format: { "measurements": [ {"server_id": 1, "rtt_ms": 50}, ... ] }
    auto measurements = msg.value("measurements", json::array());
    
    LOG_DEBUG("ControlProtocolHandler: Node {} reported {} latency measurements",
              node_id_, measurements.size());
    
    // Store latency data in PathService
    if (path_service_) {
        for (const auto& m : measurements) {
            uint32_t server_id = m.value("server_id", 0);
            uint32_t rtt_ms = m.value("rtt_ms", 0);
            
            if (server_id > 0 && rtt_ms > 0) {
                path_service_->update_node_relay_latency(node_id_, server_id, rtt_ms);
            }
        }
    }
    
    // Also store in database directly
    for (const auto& m : measurements) {
        uint32_t server_id = m.value("server_id", 0);
        uint32_t rtt_ms = m.value("rtt_ms", 0);
        
        if (server_id > 0 && rtt_ms > 0) {
            db_->update_latency("node", node_id_, "server", server_id, rtt_ms);
        }
    }
    
    json response;
    response["type"] = "latency_ack";
    response["success"] = true;
    response["received_count"] = measurements.size();
    return response.dump();
}

std::string ControlProtocolHandler::handle_relay_connect(const json& msg) {
    uint32_t server_id = msg.value("server_id", 0);
    
    if (server_id == 0) {
        json error;
        error["type"] = "error";
        error["error"] = "invalid_server_id";
        return error.dump();
    }
    
    // Record node-server connection
    db_->update_node_server_connection(node_id_, server_id);
    
    LOG_INFO("ControlProtocolHandler: Node {} connected to relay {}", node_id_, server_id);
    
    json response;
    response["type"] = "relay_connect_ack";
    response["success"] = true;
    response["server_id"] = server_id;
    return response.dump();
}

std::string ControlProtocolHandler::handle_relay_disconnect(const json& msg) {
    uint32_t server_id = msg.value("server_id", 0);
    
    if (server_id == 0) {
        json error;
        error["type"] = "error";
        error["error"] = "invalid_server_id";
        return error.dump();
    }
    
    // Remove node-server connection
    db_->remove_node_server_connection(node_id_, server_id);
    
    LOG_INFO("ControlProtocolHandler: Node {} disconnected from relay {}", node_id_, server_id);
    
    json response;
    response["type"] = "relay_disconnect_ack";
    response["success"] = true;
    response["server_id"] = server_id;
    return response.dump();
}

std::string ControlProtocolHandler::handle_key_rotation(const json& msg) {
    // Parse new public key
    std::string new_key = msg.value("new_node_key_pub", "");
    std::string signature = msg.value("signature", "");  // Signed by old key
    
    if (new_key.empty()) {
        json error;
        error["type"] = "error";
        error["error"] = "missing_key";
        return error.dump();
    }
    
    // TODO: Verify signature with old key
    // TODO: Update key in database
    
    LOG_INFO("ControlProtocolHandler: Node {} rotated key", node_id_);
    
    json response;
    response["type"] = "key_rotation_ack";
    response["success"] = true;
    return response.dump();
}

std::string ControlProtocolHandler::generate_config_update() {
    json response;
    response["type"] = "config_update";
    response["success"] = true;
    
    // Get network info
    auto network_opt = db_->get_network(network_id_);
    if (network_opt) {
        const Network& net = *network_opt;
        response["network"] = {
            {"id", net.id},
            {"name", net.name},
            {"cidr", net.subnet},
            {"mtu", 1400}
        };
    }
    
    // Node info
    response["node"] = {
        {"id", node_id_},
        {"virtual_ip", virtual_ip_}
    };
    
    // Generate tokens
    response["auth_token"] = generate_auth_token(node_id_);
    response["relay_token"] = generate_relay_token(node_id_);
    
    // Get peer list with path info
    json peers = json::array();
    auto nodes = db_->list_nodes(network_id_);
    for (const auto& n : nodes) {
        if (n.id == node_id_) continue;  // Skip self
        if (!n.authorized) continue;     // Skip unauthorized
        
        json peer;
        peer["node_id"] = n.id;
        peer["hostname"] = n.hostname;
        peer["virtual_ip"] = n.virtual_ip;
        peer["node_key_pub"] = n.node_key_pub;  // X25519 public key
        peer["online"] = n.online;
        peer["nat_type"] = n.nat_type;
        
        // Add path info if PathService is available
        if (path_service_ && n.online) {
            peer["path"] = generate_peer_path_info(n.id);
        }
        
        peers.push_back(peer);
    }
    response["peers"] = peers;
    
    // Get relay servers
    json relays = json::array();
    auto servers = db_->list_enabled_servers();
    for (const auto& s : servers) {
        json relay;
        relay["server_id"] = s.id;
        relay["name"] = s.name;
        relay["region"] = s.region;
        relay["url"] = s.url;
        
        // Add latency if known
        if (path_service_) {
            uint32_t latency = path_service_->get_node_relay_latency(node_id_, s.id);
            if (latency > 0) {
                relay["latency_ms"] = latency;
            }
        }
        
        relays.push_back(relay);
    }
    response["relays"] = relays;
    
    // Add recommended relay
    if (path_service_) {
        auto recommended = path_service_->get_recommended_relay(node_id_);
        if (recommended) {
            response["recommended_relay_id"] = *recommended;
        }
    }
    
    // Get subnet routes (advertised by gateway nodes)
    json subnet_routes = json::array();
    auto all_routes = db_->get_all_routes(network_id_);
    for (const auto& route : all_routes) {
        if (!route.enabled) continue;
        
        // Check if the gateway node is online
        auto gateway_node = db_->get_node(route.node_id);
        bool gateway_online = gateway_node && gateway_node->online;
        
        json route_obj;
        route_obj["cidr"] = route.cidr;
        route_obj["via_node_id"] = route.node_id;
        route_obj["priority"] = route.priority;
        route_obj["weight"] = route.weight;
        route_obj["gateway_online"] = gateway_online;
        
        // Include gateway's virtual IP for reference
        if (gateway_node) {
            route_obj["gateway_ip"] = gateway_node->virtual_ip;
        }
        
        subnet_routes.push_back(route_obj);
    }
    response["subnet_routes"] = subnet_routes;
    
    LOG_DEBUG("ControlProtocolHandler: Sending config with {} peers, {} relays, {} subnet routes",
              peers.size(), relays.size(), subnet_routes.size());
    
    return response.dump();
}

nlohmann::json ControlProtocolHandler::generate_peer_path_info(uint32_t peer_node_id) {
    json path_info;
    
    if (!path_service_) {
        return path_info;
    }
    
    auto best_path = path_service_->calculate_best_path(node_id_, peer_node_id);
    if (!best_path) {
        path_info["available"] = false;
        return path_info;
    }
    
    path_info["available"] = true;
    path_info["total_latency_ms"] = best_path->total_latency_ms;
    path_info["hop_count"] = best_path->hop_count;
    
    // Path type
    switch (best_path->type) {
        case PathInfo::Type::DIRECT_RELAY:
            path_info["type"] = "direct_relay";
            break;
        case PathInfo::Type::CROSS_RELAY:
            path_info["type"] = "cross_relay";
            break;
        case PathInfo::Type::P2P_POSSIBLE:
            path_info["type"] = "p2p_possible";
            break;
        default:
            path_info["type"] = "unknown";
            break;
    }
    
    // Relay hops
    json hops = json::array();
    for (const auto& hop : best_path->hops) {
        json hop_info;
        hop_info["server_id"] = hop.server_id;
        hop_info["server_name"] = hop.server_name;
        hop_info["url"] = hop.server_url;
        hop_info["latency_ms"] = hop.latency_ms;
        hops.push_back(hop_info);
    }
    path_info["hops"] = hops;
    
    return path_info;
}

std::string ControlProtocolHandler::generate_auth_token(uint32_t node_id) {
    // Simple JWT-like token (not cryptographically secure for demo)
    // In production, use proper JWT library
    
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(24);
    
    json payload;
    payload["node_id"] = node_id;
    payload["network_id"] = network_id_;
    payload["type"] = "auth";
    payload["iat"] = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    payload["exp"] = std::chrono::duration_cast<std::chrono::seconds>(
        exp.time_since_epoch()).count();
    
    // For now, just base64 encode (not secure!)
    // TODO: Use proper JWT signing
    std::string token = "auth." + std::to_string(node_id) + "." + 
                        std::to_string(payload["exp"].get<int64_t>());
    return token;
}

std::string ControlProtocolHandler::generate_relay_token(uint32_t node_id) {
    auto now = std::chrono::system_clock::now();
    auto exp = now + std::chrono::hours(24);
    
    json payload;
    payload["node_id"] = node_id;
    payload["network_id"] = network_id_;
    payload["type"] = "relay";
    payload["iat"] = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    payload["exp"] = std::chrono::duration_cast<std::chrono::seconds>(
        exp.time_since_epoch()).count();
    
    // For now, just simple token
    std::string token = "relay." + std::to_string(node_id) + "." +
                        std::to_string(payload["exp"].get<int64_t>());
    return token;
}

std::string ControlProtocolHandler::extract_machine_key(const std::string& query) {
    // Parse query string: ?key=BASE64...
    std::regex key_regex(R"(key=([^&]+))");
    std::smatch match;
    
    if (std::regex_search(query, match, key_regex)) {
        return match[1].str();
    }
    return "";
}

// ============================================================================
// ServerProtocolHandler
// ============================================================================

ServerProtocolHandler::ServerProtocolHandler(std::shared_ptr<Database> db,
                                             const std::string& jwt_secret,
                                             const std::string& server_token)
    : db_(std::move(db))
    , jwt_secret_(jwt_secret)
    , server_token_(server_token) {
}

std::string ServerProtocolHandler::handle_message(const std::string& message,
                                                  const std::string& query_string) {
    try {
        if (message.empty()) {
            return "";
        }
        
        json msg = json::parse(message);
        std::string type = msg.value("type", "");
        
        LOG_DEBUG("ServerProtocolHandler: Received message type: {}", type);
        
        if (type == "register") {
            return handle_register(msg);
        }
        
        if (!authenticated_) {
            json error;
            error["type"] = "error";
            error["error"] = "not_authenticated";
            return error.dump();
        }
        
        if (type == "heartbeat" || type == "ping") {
            return handle_heartbeat(msg);
        } else if (type == "stats") {
            return handle_stats_report(msg);
        } else if (type == "mesh_forward") {
            return handle_mesh_forward(msg);
        } else {
            json error;
            error["type"] = "error";
            error["error"] = "unknown_type";
            return error.dump();
        }
    } catch (const std::exception& e) {
        LOG_ERROR("ServerProtocolHandler: Error: {}", e.what());
        json error;
        error["type"] = "error";
        error["error"] = "internal_error";
        return error.dump();
    }
}

std::string ServerProtocolHandler::handle_register(const json& msg) {
    // Verify server token
    std::string token = msg.value("token", "");
    if (!server_token_.empty() && token != server_token_) {
        LOG_WARN("ServerProtocolHandler: Invalid server token");
        json error;
        error["type"] = "register_response";
        error["success"] = false;
        error["error"] = "invalid_token";
        return error.dump();
    }
    
    server_name_ = msg.value("name", "unknown");
    std::string region = msg.value("region", "unknown");
    std::string url = msg.value("url", msg.value("relay_url", msg.value("external_url", "")));
    std::string stun_ip = msg.value("stun_ip", "");
    uint16_t stun_port = msg.value("stun_port", 3478);
    
    LOG_INFO("ServerProtocolHandler: Server '{}' registering from region '{}'",
             server_name_, region);
    
    // Check if server already exists by name
    bool found = false;
    auto servers = db_->list_servers();
    for (const auto& s : servers) {
        if (s.name == server_name_) {
            server_id_ = s.id;
            found = true;
            break;
        }
    }
    
    Server server;
    server.name = server_name_;
    server.region = region;
    server.url = url;
    server.stun_ip = stun_ip;
    server.stun_port = stun_port;
    server.enabled = true;
    server.type = "builtin";
    
    if (found) {
        server.id = server_id_;
        db_->update_server(server);
    } else {
        server_id_ = db_->create_server(server);
    }
    
    authenticated_ = true;
    
    LOG_INFO("ServerProtocolHandler: Server '{}' registered with ID {}", 
             server_name_, server_id_);
    
    json response;
    response["type"] = "register_response";
    response["success"] = true;
    response["server_id"] = server_id_;
    
    return response.dump();
}

std::string ServerProtocolHandler::handle_heartbeat(const json& msg) {
    // Update last heartbeat
    db_->update_server_heartbeat(server_id_);
    
    json response;
    response["type"] = "pong";
    response["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return response.dump();
}

std::string ServerProtocolHandler::handle_stats_report(const json& msg) {
    // Parse stats
    uint32_t active_connections = msg.value("active_connections", 0);
    uint64_t bytes_relayed = msg.value("bytes_relayed", 0);
    
    LOG_DEBUG("ServerProtocolHandler: Server {} stats: {} connections, {} bytes",
              server_id_, active_connections, bytes_relayed);
    
    // TODO: Store stats
    
    json response;
    response["type"] = "stats_ack";
    return response.dump();
}

std::string ServerProtocolHandler::handle_mesh_forward(const json& msg) {
    // Forward data between relays
    // Format: { "type": "mesh_forward", "src_node_id": X, "dst_node_id": Y, 
    //           "target_relays": [Z], "payload": {...} }
    
    uint32_t src_node_id = msg.value("src_node_id", 0);
    uint32_t dst_node_id = msg.value("dst_node_id", 0);
    
    if (src_node_id == 0 || dst_node_id == 0) {
        LOG_WARN("ServerProtocolHandler: Invalid mesh_forward - missing node IDs");
        json error;
        error["type"] = "error";
        error["error"] = "invalid_request";
        return error.dump();
    }
    
    auto target_relays = msg.value("target_relays", json::array());
    auto payload = msg.value("payload", json::object());
    
    if (target_relays.empty()) {
        LOG_DEBUG("ServerProtocolHandler: No target relays for mesh_forward");
        json error;
        error["type"] = "error";
        error["error"] = "no_target_relays";
        return error.dump();
    }
    
    // Build forward message for target relay
    json forward_msg;
    forward_msg["type"] = "mesh_data";
    forward_msg["src_node_id"] = src_node_id;
    forward_msg["dst_node_id"] = dst_node_id;
    forward_msg["from_relay_id"] = server_id_;
    forward_msg["payload"] = payload;
    
    std::string forward_str = forward_msg.dump();
    
    // Forward to each target relay
    int forwarded = 0;
    if (mesh_forward_callback_) {
        for (const auto& relay : target_relays) {
            uint32_t relay_id = relay.get<uint32_t>();
            LOG_DEBUG("ServerProtocolHandler: Forwarding mesh data to relay {}", relay_id);
            mesh_forward_callback_(relay_id, forward_str);
            forwarded++;
        }
    }
    
    LOG_DEBUG("ServerProtocolHandler: Mesh forwarded {} -> {} via {} relays",
              src_node_id, dst_node_id, forwarded);
    
    json response;
    response["type"] = "mesh_forward_ack";
    response["forwarded"] = forwarded;
    return response.dump();
}

} // namespace edgelink::controller

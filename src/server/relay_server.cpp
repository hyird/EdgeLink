#include "relay_server.hpp"
#include "mesh_manager.hpp"
#include "controller_client.hpp"
#include "common/log.hpp"

#include <boost/asio/strand.hpp>
#include <algorithm>

namespace edgelink {

// ============================================================================
// RelayToMeshAdapter - Wraps a RelaySession as MeshConnection for inbound mesh
// ============================================================================
class RelayToMeshAdapter : public MeshConnection, public std::enable_shared_from_this<RelayToMeshAdapter> {
public:
    RelayToMeshAdapter(std::shared_ptr<RelaySession> session, 
                       uint32_t peer_relay_id,
                       MeshManager& manager)
        : session_(session)
        , peer_relay_id_(peer_relay_id)
        , manager_(manager)
    {
        LOG_DEBUG("RelayToMeshAdapter created for relay {}", peer_relay_id);
    }
    
    ~RelayToMeshAdapter() {
        LOG_DEBUG("RelayToMeshAdapter destroyed for relay {}", peer_relay_id_);
    }
    
    void start() {
        // Set up message callback to forward to mesh manager
        session_->set_message_callback(
            [this, self = shared_from_this()](std::shared_ptr<RelaySession>, const Frame& frame) {
                // Forward all frames to mesh manager
                manager_.on_mesh_frame(peer_relay_id_, frame);
            });
        
        session_->set_close_callback(
            [this, self = shared_from_this()](std::shared_ptr<RelaySession>) {
                connected_ = false;
                manager_.on_peer_disconnected(peer_relay_id_);
            });
        
        connected_ = true;
        
        // Register with mesh manager as inbound connection
        // Note: MeshManager::accept_connection expects MeshSession, not MeshConnection
        // We need to add the adapter directly to the inbound peers
        manager_.register_inbound_adapter(peer_relay_id_, shared_from_this());
    }
    
    // MeshConnection interface
    void send(const Frame& frame) override {
        if (session_ && connected_) {
            session_->send(frame);
        }
    }
    
    void send(std::vector<uint8_t> data) override {
        if (session_ && connected_) {
            session_->send(std::move(data));
        }
    }
    
    bool is_connected() const override {
        return connected_ && session_;
    }
    
    uint32_t peer_relay_id() const override {
        return peer_relay_id_;
    }
    
    void close() override {
        if (session_) {
            session_->close();
        }
        connected_ = false;
    }

private:
    std::shared_ptr<RelaySession> session_;
    uint32_t peer_relay_id_;
    MeshManager& manager_;
    std::atomic<bool> connected_{false};
};

// ============================================================================
// RelayServer Implementation
// ============================================================================

RelayServer::RelayServer(asio::io_context& ioc, const ServerConfig& config)
    : ioc_(ioc)
    , config_(config)
    , jwt_manager_(config.controller.token, "HS256")  // Use server token as secret initially
    , session_manager_(jwt_manager_)
    , acceptor_(ioc)
{
    LOG_INFO("RelayServer initializing on {}:{}", config_.relay.listen_address, config_.relay.listen_port);
}

RelayServer::~RelayServer() {
    stop();
}

void RelayServer::start() {
    if (running_) {
        LOG_WARN("RelayServer already running");
        return;
    }
    
    running_ = true;
    
    // Setup SSL context if TLS is enabled
    if (config_.relay.tls.enabled) {
        ssl_ctx_ = std::make_unique<ssl::context>(ssl::context::tlsv12);
        
        try {
            ssl_ctx_->set_options(
                ssl::context::default_workarounds |
                ssl::context::no_sslv2 |
                ssl::context::no_sslv3 |
                ssl::context::single_dh_use);
            
            ssl_ctx_->use_certificate_chain_file(config_.relay.tls.cert_file);
            ssl_ctx_->use_private_key_file(config_.relay.tls.key_file, ssl::context::pem);
            
            LOG_INFO("TLS enabled with cert: {}", config_.relay.tls.cert_file);
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to setup TLS: {}", e.what());
            ssl_ctx_.reset();
        }
    }
    
    // Setup acceptor
    try {
        auto address = asio::ip::make_address(config_.relay.listen_address);
        tcp::endpoint endpoint(address, config_.relay.listen_port);
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(asio::socket_base::max_listen_connections);
        
        LOG_INFO("RelayServer listening on {}:{}", 
                 config_.relay.listen_address, config_.relay.listen_port);
        
        // Start mesh manager (connect to peer relays)
        if (mesh_manager_) {
            mesh_manager_->start();
        }
        
        // Start accepting connections
        do_accept();
        
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to start RelayServer: {}", e.what());
        running_ = false;
        throw;
    }
}

void RelayServer::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // Stop mesh manager
    if (mesh_manager_) {
        mesh_manager_->stop();
    }
    
    // Close acceptor
    boost::system::error_code ec;
    acceptor_.close(ec);
    
    // Close all sessions
    auto sessions = session_manager_.get_all_sessions();
    for (auto& session : sessions) {
        session->close();
    }
    
    LOG_INFO("RelayServer stopped");
}

void RelayServer::do_accept() {
    if (!running_) {
        return;
    }
    
    acceptor_.async_accept(
        asio::make_strand(ioc_),
        beast::bind_front_handler(&RelayServer::on_accept, this));
}

void RelayServer::on_accept(beast::error_code ec, tcp::socket socket) {
    if (ec) {
        if (ec != asio::error::operation_aborted) {
            LOG_ERROR("Accept error: {}", ec.message());
        }
        return;
    }
    
    stats_.connections_total++;
    stats_.connections_active++;
    
    // Get remote endpoint info
    std::string remote_ip = "unknown";
    uint16_t remote_port = 0;
    try {
        auto ep = socket.remote_endpoint();
        remote_ip = ep.address().to_string();
        remote_port = ep.port();
    } catch (...) {}
    
    LOG_DEBUG("New connection from {}:{}", remote_ip, remote_port);
    
    // Create a router to handle HTTP request and determine path
    // For simplicity, we'll detect the path after WebSocket handshake in the session
    // by checking the first message type
    
    // Create session
    std::shared_ptr<RelaySession> session;
    
    if (ssl_ctx_) {
        session = std::make_shared<RelaySession>(std::move(socket), *ssl_ctx_, session_manager_);
    } else {
        session = std::make_shared<RelaySession>(std::move(socket), session_manager_);
    }
    
    // Set path callback to handle /ws/mesh routing
    session->set_path_callback(
        [this, remote_ip, remote_port](std::shared_ptr<RelaySession> s, const std::string& path) {
            if (path == "/ws/mesh") {
                // This is a mesh connection from another relay
                LOG_INFO("Mesh connection detected from {}:{}", remote_ip, remote_port);
                
                // Remove from session manager (it will be managed by mesh_manager)
                session_manager_.remove_session(s);
                stats_.connections_active--;
                
                // Note: The mesh handshake (MESH_HELLO/MESH_HELLO_ACK) will be handled
                // by the session's message callback, which we'll route to mesh_manager
                // For now, mark this session as a mesh session by setting a flag
                // and handle MESH_HELLO in on_message
            }
            // For other paths (/ws/data, /ws/relay, /), continue as normal node session
        });
    
    // Set callbacks
    session->set_message_callback(
        [this](std::shared_ptr<RelaySession> s, const Frame& f) {
            on_message(s, f);
        });
    
    session->set_close_callback(
        [this](std::shared_ptr<RelaySession> s) {
            on_close(s);
        });
    
    // Add to manager and start
    session_manager_.add_session(session);
    session->start();
    
    // Accept next connection
    do_accept();
}

void RelayServer::on_message(std::shared_ptr<RelaySession> session, const Frame& frame) {
    switch (frame.header.type) {
        case MessageType::MESH_HELLO: {
            // This is a mesh connection from another relay
            LOG_INFO("MESH_HELLO received from {}:{}", session->observed_ip(), session->observed_port());
            handle_mesh_hello(session, frame);
            break;
        }
        
        case MessageType::RELAY_AUTH:
            handle_auth(session, frame);
            break;
            
        case MessageType::DATA:
            handle_data(session, frame);
            break;
            
        case MessageType::PING:
            handle_ping(session, frame);
            break;
            
        default:
            LOG_WARN("Unknown message type {} from node {}", 
                     static_cast<int>(frame.header.type), session->node_id());
            break;
    }
}

void RelayServer::on_close(std::shared_ptr<RelaySession> session) {
    stats_.connections_active--;
    session_manager_.remove_session(session);
    
    LOG_INFO("Session closed for node {} from {}:{}", 
             session->node_id(), session->observed_ip(), session->observed_port());
}

void RelayServer::handle_auth(std::shared_ptr<RelaySession> session, const Frame& frame) {
    // Parse relay auth payload
    RelayAuthPayload auth;
    if (!auth.from_json(frame.payload_json())) {
        LOG_WARN("Invalid relay auth payload from {}:{}", 
                 session->observed_ip(), session->observed_port());
        
        // Send error response
        ErrorPayload error;
        error.code = static_cast<int>(ErrorCode::INVALID_MESSAGE);
        error.message = "Invalid auth payload";
        Frame response = create_json_frame(MessageType::ERROR_MSG, error.to_json(), FrameFlags::NONE);
        
        session->send(response);
        session->close();
        return;
    }
    
    // Validate relay token
    uint32_t node_id;
    std::string virtual_ip;
    std::vector<uint32_t> allowed_relays;
    
    if (!session_manager_.validate_relay_token(auth.relay_token, node_id, virtual_ip, allowed_relays)) {
        LOG_WARN("Invalid relay token from {}:{}", 
                 session->observed_ip(), session->observed_port());
        
        stats_.auth_failures++;
        
        // Send error response
        ErrorPayload error;
        error.code = static_cast<int>(ErrorCode::AUTH_FAILED);
        error.message = "Invalid relay token";
        Frame response = create_json_frame(MessageType::ERROR_MSG, error.to_json(), FrameFlags::NONE);
        
        session->send(response);
        session->close();
        return;
    }
    
    // Check if this relay is in allowed list (if list is not empty)
    if (!allowed_relays.empty() && server_id_ != 0) {
        bool allowed = false;
        for (auto r : allowed_relays) {
            if (r == server_id_) {
                allowed = true;
                break;
            }
        }
        
        if (!allowed) {
            LOG_WARN("Node {} not authorized to connect to relay {}", node_id, server_id_);
            
            stats_.auth_failures++;
            
            ErrorPayload error;
            error.code = static_cast<int>(ErrorCode::NOT_AUTHORIZED);
            error.message = "Not authorized for this relay";
            Frame response = create_json_frame(MessageType::ERROR_MSG, error.to_json(), FrameFlags::NONE);
            
            session->send(response);
            session->close();
            return;
        }
    }
    
    // Set session as authenticated
    session->set_authenticated(node_id, virtual_ip);
    
    // Update session in manager (now with node_id)
    session_manager_.remove_session(session);
    session_manager_.add_session(session);
    
    LOG_INFO("Node {} authenticated on relay {}, virtual IP: {}", 
             node_id, server_id_, virtual_ip);
    
    // Send success response
    boost::json::object resp_json;
    resp_json["success"] = true;
    resp_json["server_id"] = server_id_;
    resp_json["observed_ip"] = session->observed_ip();
    resp_json["observed_port"] = session->observed_port();
    Frame response = create_json_frame(MessageType::RELAY_AUTH_RESP, resp_json, FrameFlags::NONE);
    
    session->send(response);
}

void RelayServer::handle_data(std::shared_ptr<RelaySession> session, const Frame& frame) {
    // Must be authenticated
    if (!session->is_authenticated()) {
        LOG_WARN("Data from unauthenticated session {}:{}", 
                 session->observed_ip(), session->observed_port());
        return;
    }
    
    // Parse data payload header to get destination
    DataPayload data;
    if (!data.from_json(frame.payload_json())) {
        LOG_WARN("Invalid data payload from node {}", session->node_id());
        return;
    }
    
    // Forward to destination
    if (!forward_data(data)) {
        LOG_DEBUG("Failed to forward data from {} to {}", data.src_node_id, data.dst_node_id);
    }
    
    stats_.packets_forwarded++;
    stats_.bytes_forwarded += frame.payload.size();
}

void RelayServer::handle_ping(std::shared_ptr<RelaySession> session, const Frame& frame) {
    // Send pong response
    Frame pong = Frame::create(MessageType::PONG, frame.payload, FrameFlags::NONE);
    session->send(pong);
}

void RelayServer::handle_mesh_hello(std::shared_ptr<RelaySession> session, const Frame& frame) {
    // Parse the MESH_HELLO message
    uint32_t peer_relay_id = 0;
    std::string peer_region;
    
    try {
        auto json = frame.payload_json();
        if (!json.is_object()) {
            throw std::runtime_error("Not a JSON object");
        }
        auto& obj = json.as_object();
        
        if (obj.contains("relay_id")) {
            peer_relay_id = static_cast<uint32_t>(obj.at("relay_id").as_int64());
        }
        if (obj.contains("region")) {
            peer_region = obj.at("region").as_string().c_str();
        }
    } catch (const std::exception& e) {
        LOG_WARN("Invalid MESH_HELLO from {}:{}: {}", 
                 session->observed_ip(), session->observed_port(), e.what());
        
        // Send rejection
        boost::json::object ack;
        ack["relay_id"] = server_id_;
        ack["accepted"] = false;
        ack["reason"] = "Invalid MESH_HELLO payload";
        Frame response = create_json_frame(MessageType::MESH_HELLO_ACK, ack, FrameFlags::NONE);
        session->send(response);
        session->close();
        return;
    }
    
    if (peer_relay_id == 0) {
        LOG_WARN("MESH_HELLO with invalid relay_id from {}:{}", 
                 session->observed_ip(), session->observed_port());
        
        boost::json::object ack;
        ack["relay_id"] = server_id_;
        ack["accepted"] = false;
        ack["reason"] = "Invalid relay_id";
        Frame response = create_json_frame(MessageType::MESH_HELLO_ACK, ack, FrameFlags::NONE);
        session->send(response);
        session->close();
        return;
    }
    
    LOG_INFO("Mesh connection accepted from relay {} ({}:{})", 
             peer_relay_id, session->observed_ip(), session->observed_port());
    
    // Send acceptance
    boost::json::object ack;
    ack["relay_id"] = server_id_;
    ack["accepted"] = true;
    Frame response = create_json_frame(MessageType::MESH_HELLO_ACK, ack, FrameFlags::NONE);
    session->send(response);
    
    // Remove from normal session manager
    session_manager_.remove_session(session);
    
    // Create a MeshSession wrapper and register with mesh_manager
    if (mesh_manager_) {
        // Create an adapter that wraps RelaySession as MeshSession
        auto mesh_adapter = std::make_shared<RelayToMeshAdapter>(session, peer_relay_id, *mesh_manager_);
        mesh_adapter->start();
    } else {
        LOG_WARN("Mesh manager not initialized, closing mesh connection from relay {}", peer_relay_id);
        session->close();
    }
}

bool RelayServer::forward_data(const DataPayload& data) {
    // Try to find destination node locally
    auto dst_session = session_manager_.get_session_by_node_id(data.dst_node_id);
    
    if (dst_session && dst_session->is_authenticated()) {
        // Forward directly to local session
        Frame forward_frame = create_json_frame(MessageType::DATA, data.to_json(), FrameFlags::NONE);
        dst_session->send(forward_frame);
        return true;
    }
    
    // Check if we know which relay the node is connected to
    auto relay_locations = session_manager_.get_node_relay_locations(data.dst_node_id);
    
    if (relay_locations.empty()) {
        LOG_DEBUG("No route to node {} - not connected to any known relay", data.dst_node_id);
        return false;
    }
    
    // Forward through Mesh connections to other relays (NOT through Controller)
    // Controller only decides paths, data flows directly between Relays
    if (!mesh_manager_) {
        LOG_DEBUG("Cannot forward to node {} - mesh manager not initialized", data.dst_node_id);
        return false;
    }
    
    // Find the best relay to forward to
    // Priority: pick the relay with lowest latency that has the destination node
    uint32_t best_relay_id = 0;
    uint32_t best_latency = UINT32_MAX;
    
    for (uint32_t relay_id : relay_locations) {
        if (relay_id == server_id_) {
            // Node should be on this relay but not found locally - skip
            continue;
        }
        
        // Check if we have a mesh connection to this relay
        auto connected_relays = mesh_manager_->get_connected_relays();
        bool is_connected = std::find(connected_relays.begin(), connected_relays.end(), relay_id) 
                           != connected_relays.end();
        
        if (!is_connected) {
            continue;
        }
        
        // Check latency to this relay
        auto latency = mesh_manager_->get_latency(relay_id);
        if (latency && *latency < best_latency) {
            best_latency = *latency;
            best_relay_id = relay_id;
        } else if (!latency && best_relay_id == 0) {
            // No latency info, but we're connected - use as fallback
            best_relay_id = relay_id;
        }
    }
    
    if (best_relay_id == 0) {
        LOG_DEBUG("No mesh connection available to reach node {}", data.dst_node_id);
        return false;
    }
    
    // Forward through mesh connection
    Frame forward_frame = create_json_frame(MessageType::DATA, data.to_json(), FrameFlags::NONE);
    
    if (mesh_manager_->forward_to_relay(best_relay_id, forward_frame)) {
        LOG_DEBUG("Forwarding data from {} to {} via mesh relay {} (latency: {}ms)",
                  data.src_node_id, data.dst_node_id, best_relay_id, best_latency);
        return true;
    }
    
    LOG_DEBUG("Failed to forward to node {} via relay {}", data.dst_node_id, best_relay_id);
    return false;
}

void RelayServer::broadcast(const Frame& frame) {
    auto sessions = session_manager_.get_all_sessions();
    
    for (auto& session : sessions) {
        if (session->is_authenticated()) {
            session->send(frame);
        }
    }
}

} // namespace edgelink

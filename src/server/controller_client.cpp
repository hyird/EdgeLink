#include "controller_client.hpp"
#include "relay_server.hpp"
#include "mesh_manager.hpp"
#include "common/log.hpp"
#include "common/config.hpp"

#include <regex>

namespace edgelink {

// ============================================================================
// ControllerClient Implementation
// ============================================================================

ControllerClient::ControllerClient(asio::io_context& ioc, RelayServer& server, const ServerConfig& config)
    : ioc_(ioc)
    , server_(server)
    , config_(config)
    , resolver_(ioc)
    , ssl_ctx_(ssl::context::tlsv12_client)
{
    // Parse controller URL
    // Expected format: wss://host:port or ws://host:port (path is fixed)
    std::regex url_regex(R"(^(wss?):\/\/([^:\/]+)(?::(\d+))?(\/.*)?$)");
    std::smatch match;
    
    if (std::regex_match(config_.controller.url, match, url_regex)) {
        std::string scheme = match[1];
        host_ = match[2];
        port_ = match[3].matched ? match[3].str() : (scheme == "wss" ? "443" : "80");
        path_ = paths::WS_SERVER;  // Fixed path, ignore any path in URL
        use_ssl_ = (scheme == "wss");
        
        LOG_DEBUG("Controller URL parsed: scheme={}, host={}, port={}, path={}", 
                  scheme, host_, port_, path_);
    } else {
        LOG_ERROR("Invalid controller URL: {}", config_.controller.url);
        throw std::runtime_error("Invalid controller URL");
    }
    
    // Setup SSL context
    if (use_ssl_) {
        ssl_ctx_.set_default_verify_paths();
        ssl_ctx_.set_verify_mode(ssl::verify_peer);
        
        // For self-signed certs in development, can disable verification
        // ssl_ctx_.set_verify_mode(ssl::verify_none);
    }
    
    LOG_INFO("ControllerClient connecting to {}://{}:{}{}", 
             use_ssl_ ? "wss" : "ws", host_, port_, path_);
}

ControllerClient::~ControllerClient() {
    disconnect();
}

beast::tcp_stream& ControllerClient::get_lowest_layer() {
    return std::visit([](auto& ws) -> beast::tcp_stream& {
        return beast::get_lowest_layer(*ws);
    }, ws_);
}

void ControllerClient::connect() {
    if (connecting_ || connected_) {
        LOG_WARN("Already connecting or connected to controller");
        return;
    }
    
    connecting_ = true;
    reconnect_attempts_ = 0;
    
    LOG_INFO("Connecting to controller at {}:{}", host_, port_);
    
    do_resolve();
}

void ControllerClient::disconnect() {
    if (!connected_ && !connecting_) {
        return;
    }
    
    connected_ = false;
    connecting_ = false;
    registered_ = false;
    
    // Cancel timers
    if (reconnect_timer_) {
        reconnect_timer_->cancel();
    }
    if (heartbeat_timer_) {
        heartbeat_timer_->cancel();
    }
    
    // Close WebSocket
    std::visit([](auto& ws) {
        if (ws) {
            boost::system::error_code ec;
            ws->close(websocket::close_code::normal, ec);
            ws.reset();
        }
    }, ws_);
    
    LOG_INFO("Disconnected from controller");
}

void ControllerClient::do_resolve() {
    resolver_.async_resolve(
        host_, port_,
        beast::bind_front_handler(&ControllerClient::on_resolve, shared_from_this()));
}

void ControllerClient::on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        LOG_ERROR("Failed to resolve controller address: {}", ec.message());
        schedule_reconnect();
        return;
    }
    
    // Connect to the first resolved endpoint
    do_connect(results.begin()->endpoint());
}

void ControllerClient::do_connect(tcp::resolver::results_type::endpoint_type ep) {
    // Create appropriate WebSocket stream based on SSL requirement
    if (use_ssl_) {
        ws_ = std::make_unique<ssl_ws_stream>(ioc_, ssl_ctx_);
    } else {
        ws_ = std::make_unique<plain_ws_stream>(ioc_);
    }
    
    // Set TCP options
    get_lowest_layer().expires_after(std::chrono::seconds(30));
    
    // Connect
    get_lowest_layer().async_connect(
        ep,
        beast::bind_front_handler(&ControllerClient::on_connect, shared_from_this()));
}

void ControllerClient::on_connect(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("Failed to connect to controller: {}", ec.message());
        schedule_reconnect();
        return;
    }
    
    LOG_DEBUG("TCP connection established to controller");
    
    if (use_ssl_) {
        do_ssl_handshake();
    } else {
        do_ws_handshake();
    }
}

void ControllerClient::do_ssl_handshake() {
    get_lowest_layer().expires_after(std::chrono::seconds(30));
    
    // Get SSL stream from variant
    auto& ssl_ws = std::get<std::unique_ptr<ssl_ws_stream>>(ws_);
    
    // Set SNI hostname
    if (!SSL_set_tlsext_host_name(ssl_ws->next_layer().native_handle(), host_.c_str())) {
        LOG_ERROR("Failed to set SNI hostname");
        schedule_reconnect();
        return;
    }
    
    ssl_ws->next_layer().async_handshake(
        ssl::stream_base::client,
        beast::bind_front_handler(&ControllerClient::on_ssl_handshake, shared_from_this()));
}

void ControllerClient::on_ssl_handshake(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("SSL handshake failed: {}", ec.message());
        schedule_reconnect();
        return;
    }
    
    LOG_DEBUG("SSL handshake completed");
    do_ws_handshake();
}

void ControllerClient::do_ws_handshake() {
    get_lowest_layer().expires_never();
    
    std::visit([this](auto& ws) {
        ws->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws->set_option(websocket::stream_base::decorator([](websocket::request_type& req) {
            req.set(beast::http::field::user_agent, "edgelink-server/1.0");
        }));
        
        std::string target = path_ + "?token=" + config_.controller.token;
        
        ws->async_handshake(host_, target,
            beast::bind_front_handler(&ControllerClient::on_ws_handshake, shared_from_this()));
    }, ws_);
}

void ControllerClient::on_ws_handshake(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("WebSocket handshake failed: {}", ec.message());
        schedule_reconnect();
        return;
    }
    
    connected_ = true;
    connecting_ = false;
    reconnect_attempts_ = 0;
    
    LOG_INFO("Connected to controller");
    
    // Notify callback
    if (connect_callback_) {
        connect_callback_(true, "");
    }
    
    // Register with controller
    do_register();
    
    // Start reading
    do_read();
    
    // Start heartbeat
    start_heartbeat();
}

void ControllerClient::do_register() {
    LOG_INFO("Registering with controller...");
    
    boost::json::object payload;
    payload["token"] = config_.controller.token;  // Server token for authentication
    payload["name"] = config_.name;
    payload["region"] = config_.relay.region;
    payload["relay_url"] = config_.relay.external_url;
    payload["stun_enabled"] = config_.stun.enabled;
    if (config_.stun.enabled) {
        payload["stun_port"] = config_.stun.external_port;
        if (!config_.stun.external_ip.empty()) {
            payload["stun_ip"] = config_.stun.external_ip;
        }
        if (!config_.stun.external_ip2.empty()) {
            payload["stun_ip2"] = config_.stun.external_ip2;
        }
    }
    
    Frame frame = create_json_frame(MessageType::SERVER_REGISTER, payload, FrameFlags::NONE);
    send(frame);
}

void ControllerClient::do_read() {
    std::visit([this](auto& ws) {
        ws->async_read(
            read_buffer_,
            beast::bind_front_handler(&ControllerClient::on_read, shared_from_this()));
    }, ws_);
}

void ControllerClient::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        if (ec != websocket::error::closed && ec != asio::error::operation_aborted) {
            LOG_ERROR("WebSocket read error: {}", ec.message());
        }
        
        connected_ = false;
        registered_ = false;
        
        if (disconnect_callback_) {
            disconnect_callback_(ec.message());
        }
        
        schedule_reconnect();
        return;
    }
    
    // Parse frame
    auto data = static_cast<const uint8_t*>(read_buffer_.data().data());
    std::span<const uint8_t> span(data, bytes_transferred);
    
    auto frame_result = Frame::deserialize(span);
    if (!frame_result) {
        LOG_WARN("Invalid frame from controller");
        read_buffer_.consume(bytes_transferred);
        do_read();
        return;
    }
    
    process_frame(*frame_result);
    
    read_buffer_.consume(bytes_transferred);
    do_read();
}

void ControllerClient::process_frame(const Frame& frame) {
    switch (frame.header.type) {
        case MessageType::SERVER_REGISTER_RESP:
            // Handle registration response
            {
                auto json = frame.payload_json();
                if (json.is_object() && json.as_object().contains("server_id")) {
                    uint32_t server_id = static_cast<uint32_t>(json.as_object()["server_id"].as_int64());
                    server_.set_server_id(server_id);
                    registered_ = true;
                    LOG_INFO("Registered with controller as server ID {}", server_id);
                } else if (json.is_object() && json.as_object().contains("error")) {
                    LOG_ERROR("Registration failed: {}", 
                              json.as_object()["error"].as_string().c_str());
                }
            }
            break;
            
        case MessageType::SERVER_NODE_LOC:
            handle_server_node_loc(frame);
            break;
            
        case MessageType::SERVER_BLACKLIST:
            handle_server_blacklist(frame);
            break;
            
        case MessageType::SERVER_RELAY_LIST:
            handle_server_relay_list(frame);
            break;
            
        case MessageType::PING:
            handle_ping(frame);
            break;
            
        case MessageType::ERROR_MSG:
            handle_error(frame);
            break;
            
        case MessageType::CONTROL:
            // Handle control messages (including mesh_data)
            handle_control_message(frame);
            break;
            
        default:
            LOG_DEBUG("Unhandled message type {} from controller", static_cast<int>(frame.header.type));
            if (message_callback_) {
                message_callback_(frame);
            }
            break;
    }
}

void ControllerClient::handle_server_node_loc(const Frame& frame) {
    // Parse node locations from controller
    // Format: { "locations": [ { "node_id": X, "relay_ids": [Y, Z, ...] }, ... ] }
    
    try {
        auto json = frame.payload_json();
        if (!json.is_object() || !json.as_object().contains("locations")) {
            LOG_WARN("Invalid node location payload");
            return;
        }
        
        std::vector<std::pair<uint32_t, std::vector<uint32_t>>> locations;
        
        for (const auto& loc : json.as_object()["locations"].as_array()) {
            uint32_t node_id = static_cast<uint32_t>(loc.as_object().at("node_id").as_int64());
            std::vector<uint32_t> relay_ids;
            
            for (const auto& rid : loc.as_object().at("relay_ids").as_array()) {
                relay_ids.push_back(static_cast<uint32_t>(rid.as_int64()));
            }
            
            locations.emplace_back(node_id, std::move(relay_ids));
        }
        
        server_.session_manager().update_node_locations(locations);
        LOG_DEBUG("Updated node locations: {} entries", locations.size());
        
    } catch (const std::exception& e) {
        LOG_WARN("Failed to parse node locations: {}", e.what());
    }
}

void ControllerClient::handle_server_blacklist(const Frame& frame) {
    // Parse token blacklist from controller
    // Format: { "entries": [ { "jti": "xxx", "expires_at": 123456 }, ... ] }
    
    try {
        auto json = frame.payload_json();
        if (!json.is_object() || !json.as_object().contains("entries")) {
            LOG_WARN("Invalid blacklist payload");
            return;
        }
        
        std::vector<std::pair<std::string, int64_t>> entries;
        
        for (const auto& entry : json.as_object()["entries"].as_array()) {
            std::string jti = entry.as_object().at("jti").as_string().c_str();
            int64_t expires_at = entry.as_object().at("expires_at").as_int64();
            entries.emplace_back(jti, expires_at);
        }
        
        server_.session_manager().set_blacklist(entries);
        LOG_DEBUG("Updated token blacklist: {} entries", entries.size());
        
    } catch (const std::exception& e) {
        LOG_WARN("Failed to parse blacklist: {}", e.what());
    }
}

void ControllerClient::handle_server_relay_list(const Frame& frame) {
    // Parse relay list from controller
    // Format: { "relays": [ { "relay_id": X, "url": "wss://...", "region": "..." }, ... ] }
    
    try {
        auto json = frame.payload_json();
        if (!json.is_object() || !json.as_object().contains("relays")) {
            LOG_WARN("Invalid relay list payload");
            return;
        }
        
        std::vector<MeshPeerInfo> peers;
        
        for (const auto& relay : json.as_object()["relays"].as_array()) {
            MeshPeerInfo peer;
            peer.relay_id = static_cast<uint32_t>(relay.as_object().at("relay_id").as_int64());
            peer.url = relay.as_object().at("url").as_string().c_str();
            
            if (relay.as_object().contains("region")) {
                peer.region = relay.as_object().at("region").as_string().c_str();
            }
            
            // Skip self
            if (peer.relay_id != server_.server_id()) {
                peers.push_back(peer);
            }
        }
        
        LOG_INFO("Received relay list from controller: {} peers", peers.size());
        
        // Update mesh manager with new peer list
        auto* mesh_mgr = server_.mesh_manager();
        if (mesh_mgr) {
            mesh_mgr->update_peers(peers);
        }
        
    } catch (const std::exception& e) {
        LOG_WARN("Failed to parse relay list: {}", e.what());
    }
}

void ControllerClient::handle_ping(const Frame& frame) {
    // Send pong
    Frame pong = Frame::create(MessageType::PONG, frame.payload, FrameFlags::NONE);
    send(pong);
}

void ControllerClient::handle_error(const Frame& frame) {
    ErrorPayload error;
    if (error.from_json(frame.payload_json())) {
        LOG_ERROR("Error from controller: {} - {}", error.code, error.message);
    }
}

void ControllerClient::handle_control_message(const Frame& frame) {
    // Parse JSON control message
    try {
        auto json = frame.payload_json();
        if (!json.is_object()) {
            LOG_WARN("Invalid control message - not a JSON object");
            return;
        }
        
        std::string msg_type;
        if (json.as_object().contains("type")) {
            msg_type = json.as_object()["type"].as_string().c_str();
        }
        
        if (msg_type == "mesh_data") {
            // Data forwarded from another relay via controller
            uint32_t src_node_id = static_cast<uint32_t>(
                json.as_object()["src_node_id"].as_int64());
            uint32_t dst_node_id = static_cast<uint32_t>(
                json.as_object()["dst_node_id"].as_int64());
            auto payload = json.as_object()["payload"];
            
            LOG_DEBUG("ControllerClient: Received mesh_data {} -> {}", 
                      src_node_id, dst_node_id);
            
            // Find destination node's local session and forward
            auto dst_session = server_.session_manager().get_session_by_node_id(dst_node_id);
            if (dst_session && dst_session->is_authenticated()) {
                // Reconstruct data payload
                DataPayload data;
                data.from_json(payload);
                
                Frame forward_frame = create_json_frame(MessageType::DATA, 
                                                        data.to_json(), 
                                                        FrameFlags::NONE);
                dst_session->send(forward_frame);
                
                LOG_DEBUG("ControllerClient: Forwarded mesh_data to local node {}", 
                          dst_node_id);
            } else {
                LOG_WARN("ControllerClient: Destination node {} not found locally", 
                         dst_node_id);
            }
        } else {
            LOG_DEBUG("ControllerClient: Unknown control message type: {}", msg_type);
        }
        
    } catch (const std::exception& e) {
        LOG_WARN("ControllerClient: Failed to parse control message: {}", e.what());
    }
}

void ControllerClient::send(const Frame& frame) {
    send(frame.serialize());
}

void ControllerClient::send(std::vector<uint8_t> data) {
    if (!connected_) {
        LOG_WARN("Cannot send - not connected to controller");
        return;
    }
    
    bool need_write = write_queue_.empty();
    write_queue_.push(std::move(data));
    
    if (need_write && !writing_) {
        do_write();
    }
}

void ControllerClient::do_write() {
    if (write_queue_.empty()) {
        writing_ = false;
        return;
    }
    
    writing_ = true;
    auto& data = write_queue_.front();
    
    std::visit([this, &data](auto& ws) {
        ws->binary(true);
        ws->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&ControllerClient::on_write, shared_from_this()));
    }, ws_);
}

void ControllerClient::on_write(beast::error_code ec, std::size_t /*bytes_transferred*/) {
    if (ec) {
        LOG_ERROR("WebSocket write error: {}", ec.message());
        writing_ = false;
        return;
    }
    
    write_queue_.pop();
    do_write();
}

void ControllerClient::send_latency_report(
    const std::vector<std::tuple<std::string, uint32_t, uint32_t>>& entries) {
    
    if (!registered_) {
        return;
    }
    
    boost::json::array latencies;
    for (const auto& [peer_url, latency_ms, jitter_ms] : entries) {
        boost::json::object entry;
        entry["peer"] = peer_url;
        entry["latency_ms"] = latency_ms;
        entry["jitter_ms"] = jitter_ms;
        latencies.push_back(entry);
    }
    
    boost::json::object payload;
    payload["latencies"] = latencies;
    Frame frame = create_json_frame(MessageType::SERVER_LATENCY, payload, FrameFlags::NONE);
    
    send(frame);
}

void ControllerClient::schedule_reconnect() {
    connecting_ = false;
    
    if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
        LOG_ERROR("Max reconnection attempts reached");
        if (disconnect_callback_) {
            disconnect_callback_("Max reconnection attempts reached");
        }
        return;
    }
    
    reconnect_attempts_++;
    
    // Exponential backoff
    int delay_ms = std::min(
        BASE_RECONNECT_DELAY_MS * (1 << reconnect_attempts_),
        MAX_RECONNECT_DELAY_MS);
    
    LOG_INFO("Scheduling reconnect attempt {} in {} ms", reconnect_attempts_, delay_ms);
    
    if (!reconnect_timer_) {
        reconnect_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    }
    
    reconnect_timer_->expires_after(std::chrono::milliseconds(delay_ms));
    reconnect_timer_->async_wait([self = shared_from_this()](boost::system::error_code ec) {
        if (!ec) {
            self->do_reconnect();
        }
    });
}

void ControllerClient::do_reconnect() {
    LOG_INFO("Attempting to reconnect to controller...");
    
    // Reset state
    std::visit([](auto& ws) {
        ws.reset();
    }, ws_);
    
    connecting_ = true;
    do_resolve();
}

void ControllerClient::start_heartbeat() {
    if (!heartbeat_timer_) {
        heartbeat_timer_ = std::make_unique<asio::steady_timer>(ioc_);
    }
    
    heartbeat_timer_->expires_after(std::chrono::seconds(HEARTBEAT_INTERVAL_SEC));
    heartbeat_timer_->async_wait([self = shared_from_this()](boost::system::error_code ec) {
        if (!ec && self->connected_) {
            self->on_heartbeat_timer();
        }
    });
}

void ControllerClient::on_heartbeat_timer() {
    // Send heartbeat
    boost::json::object payload;
    payload["connected_nodes"] = static_cast<int64_t>(server_.session_manager().session_count());
    payload["bytes_forwarded"] = static_cast<int64_t>(server_.stats().bytes_forwarded.load());
    payload["packets_forwarded"] = static_cast<int64_t>(server_.stats().packets_forwarded.load());
    Frame frame = create_json_frame(MessageType::SERVER_HEARTBEAT, payload, FrameFlags::NONE);
    
    send(frame);
    
    // Schedule next heartbeat
    start_heartbeat();
}

} // namespace edgelink

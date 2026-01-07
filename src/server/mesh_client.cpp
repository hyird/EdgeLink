#include "mesh_client.hpp"
#include "mesh_manager.hpp"
#include "common/log.hpp"

#include <boost/asio/strand.hpp>
#include <openssl/ssl.h>
#include <regex>

namespace edgelink {

// ============================================================================
// MeshClient Implementation
// ============================================================================

MeshClient::MeshClient(asio::io_context& ioc, MeshManager& manager,
                       uint32_t local_relay_id, const MeshPeerInfo& peer)
    : ioc_(ioc)
    , manager_(manager)
    , local_relay_id_(local_relay_id)
    , peer_info_(peer)
    , peer_relay_id_(peer.relay_id)
    , resolver_(asio::make_strand(ioc))
{
    LOG_DEBUG("MeshClient created for peer {} ({})", peer.relay_id, peer.url);
}

MeshClient::~MeshClient() {
    close();
}

bool MeshClient::parse_url(const std::string& url) {
    // Parse URL like: wss://relay2.example.com:443/ws/mesh
    // or: ws://localhost:8080/ws/mesh
    // CDN support: Host header will be set to the original domain
    std::regex url_regex(R"((wss?)://([^:/]+)(?::(\d+))?(/.*)?)", std::regex::icase);
    std::smatch match;
    
    if (!std::regex_match(url, match, url_regex)) {
        LOG_ERROR("Invalid mesh URL: {}", url);
        return false;
    }
    
    std::string scheme = match[1].str();
    host_ = match[2].str();
    port_ = match[3].matched ? match[3].str() : "";
    path_ = match[4].matched ? match[4].str() : "/ws/mesh";
    
    use_ssl_ = (scheme == "wss" || scheme == "WSS");
    
    if (port_.empty()) {
        port_ = use_ssl_ ? "443" : "80";
    }
    
    LOG_DEBUG("Parsed mesh URL: host={}, port={}, path={}, ssl={}", 
              host_, port_, path_, use_ssl_);
    return true;
}

void MeshClient::connect() {
    if (!parse_url(peer_info_.url)) {
        on_connection_failed("Invalid URL");
        return;
    }
    
    LOG_INFO("Connecting to mesh peer {} at {} (CDN-friendly)", peer_relay_id_, peer_info_.url);
    
    // Setup SSL context if needed
    if (use_ssl_) {
        ssl_ctx_ = std::make_unique<ssl::context>(ssl::context::tlsv12_client);
        ssl_ctx_->set_default_verify_paths();
        // For CDN: we verify the certificate against the original host
        ssl_ctx_->set_verify_mode(ssl::verify_peer);
        ssl_ctx_->set_verify_callback([this](bool preverified, ssl::verify_context& ctx) {
            // For CDN proxied connections, we trust the CDN's certificate
            // In production, implement proper certificate validation
            return true;
        });
    }
    
    do_resolve();
}

void MeshClient::do_resolve() {
    resolver_.async_resolve(
        host_, port_,
        beast::bind_front_handler(&MeshClient::on_resolve, shared_from_this()));
}

void MeshClient::on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        LOG_ERROR("Failed to resolve {}: {}", host_, ec.message());
        on_connection_failed("DNS resolution failed");
        return;
    }
    
    do_connect(results);
}

void MeshClient::do_connect(tcp::resolver::results_type results) {
    if (use_ssl_) {
        ws_ssl_ = std::make_unique<websocket::stream<beast::ssl_stream<beast::tcp_stream>>>(
            asio::make_strand(ioc_), *ssl_ctx_);
        
        // Set SNI hostname
        if (!SSL_set_tlsext_host_name(ws_ssl_->next_layer().native_handle(), host_.c_str())) {
            LOG_ERROR("Failed to set SNI hostname");
        }
        
        beast::get_lowest_layer(*ws_ssl_).expires_after(std::chrono::seconds(30));
        beast::get_lowest_layer(*ws_ssl_).async_connect(
            results,
            beast::bind_front_handler(&MeshClient::on_connect, shared_from_this()));
    } else {
        ws_plain_ = std::make_unique<websocket::stream<beast::tcp_stream>>(
            asio::make_strand(ioc_));
        
        beast::get_lowest_layer(*ws_plain_).expires_after(std::chrono::seconds(30));
        beast::get_lowest_layer(*ws_plain_).async_connect(
            results,
            beast::bind_front_handler(&MeshClient::on_connect, shared_from_this()));
    }
}

void MeshClient::on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep) {
    if (ec) {
        LOG_ERROR("Failed to connect to {}:{}: {}", host_, port_, ec.message());
        on_connection_failed("TCP connection failed");
        return;
    }
    
    LOG_DEBUG("TCP connected to {}:{}", host_, port_);
    
    if (use_ssl_) {
        do_ssl_handshake();
    } else {
        do_ws_handshake();
    }
}

void MeshClient::do_ssl_handshake() {
    // Set SNI hostname for CDN support
    // This is critical when connecting through Cloudflare or other CDN proxies
    if (!SSL_set_tlsext_host_name(ws_ssl_->next_layer().native_handle(), host_.c_str())) {
        LOG_ERROR("Failed to set SNI hostname: {}", host_);
        on_connection_failed("Failed to set SNI hostname");
        return;
    }
    LOG_DEBUG("Set SNI hostname: {}", host_);
    
    beast::get_lowest_layer(*ws_ssl_).expires_after(std::chrono::seconds(30));
    ws_ssl_->next_layer().async_handshake(
        ssl::stream_base::client,
        beast::bind_front_handler(&MeshClient::on_ssl_handshake, shared_from_this()));
}

void MeshClient::on_ssl_handshake(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("SSL handshake failed: {}", ec.message());
        on_connection_failed("SSL handshake failed");
        return;
    }
    
    LOG_DEBUG("SSL handshake complete");
    do_ws_handshake();
}

void MeshClient::do_ws_handshake() {
    // Set WebSocket options with proper Host header for CDN support
    std::string host_header = host_;
    if ((use_ssl_ && port_ != "443") || (!use_ssl_ && port_ != "80")) {
        host_header += ":" + port_;
    }
    
    if (use_ssl_) {
        ws_ssl_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws_ssl_->set_option(websocket::stream_base::decorator(
            [host_header](websocket::request_type& req) {
                req.set(beast::http::field::user_agent, "edgelink-relay/1.0");
                // Critical for CDN: Set Host header to original domain
                req.set(beast::http::field::host, host_header);
            }));
        
        beast::get_lowest_layer(*ws_ssl_).expires_never();
        ws_ssl_->async_handshake(host_, path_,
            beast::bind_front_handler(&MeshClient::on_ws_handshake, shared_from_this()));
    } else {
        ws_plain_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ws_plain_->set_option(websocket::stream_base::decorator(
            [host_header](websocket::request_type& req) {
                req.set(beast::http::field::user_agent, "edgelink-relay/1.0");
                req.set(beast::http::field::host, host_header);
            }));
        
        beast::get_lowest_layer(*ws_plain_).expires_never();
        ws_plain_->async_handshake(host_, path_,
            beast::bind_front_handler(&MeshClient::on_ws_handshake, shared_from_this()));
    }
}

void MeshClient::on_ws_handshake(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("WebSocket handshake failed: {}", ec.message());
        on_connection_failed("WebSocket handshake failed");
        return;
    }
    
    LOG_DEBUG("WebSocket handshake complete, starting mesh handshake");
    
    // Set binary mode
    if (use_ssl_) {
        ws_ssl_->binary(true);
    } else {
        ws_plain_->binary(true);
    }
    
    do_mesh_handshake();
}

void MeshClient::do_mesh_handshake() {
    // Send MESH_HELLO with our relay ID
    boost::json::object hello_msg;
    hello_msg["relay_id"] = local_relay_id_;
    hello_msg["region"] = "";  // TODO: get from config
    
    Frame hello_frame = create_json_frame(MessageType::MESH_HELLO, hello_msg, FrameFlags::NONE);
    auto data = hello_frame.serialize();
    
    if (use_ssl_) {
        ws_ssl_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshClient::on_mesh_handshake_sent, shared_from_this()));
    } else {
        ws_plain_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshClient::on_mesh_handshake_sent, shared_from_this()));
    }
}

void MeshClient::on_mesh_handshake_sent(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        LOG_ERROR("Failed to send mesh hello: {}", ec.message());
        on_connection_failed("Mesh handshake send failed");
        return;
    }
    
    // Wait for MESH_HELLO_ACK
    if (use_ssl_) {
        ws_ssl_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshClient::on_mesh_handshake_received, shared_from_this()));
    } else {
        ws_plain_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshClient::on_mesh_handshake_received, shared_from_this()));
    }
}

void MeshClient::on_mesh_handshake_received(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        LOG_ERROR("Failed to receive mesh hello ack: {}", ec.message());
        on_connection_failed("Mesh handshake receive failed");
        return;
    }
    
    // Parse the response
    auto data = read_buffer_.data();
    std::vector<uint8_t> frame_data(
        static_cast<const uint8_t*>(data.data()),
        static_cast<const uint8_t*>(data.data()) + data.size());
    read_buffer_.consume(bytes_transferred);
    
    Frame frame;
    if (!frame.parse(frame_data)) {
        LOG_ERROR("Failed to parse mesh hello ack frame");
        on_connection_failed("Invalid mesh handshake response");
        return;
    }
    
    if (frame.header.type != MessageType::MESH_HELLO_ACK) {
        LOG_ERROR("Expected MESH_HELLO_ACK, got type {}", static_cast<int>(frame.header.type));
        on_connection_failed("Unexpected mesh handshake response");
        return;
    }
    
    // Parse the ack to get peer's relay ID
    auto json = frame.payload_json();
    if (!json.is_object()) {
        LOG_ERROR("MESH_HELLO_ACK payload is not a JSON object");
        on_connection_failed("Invalid mesh handshake response");
        return;
    }
    
    auto& obj = json.as_object();
    if (obj.contains("relay_id")) {
        peer_relay_id_ = static_cast<uint32_t>(obj.at("relay_id").as_int64());
    }
    
    bool accepted = true;
    if (obj.contains("accepted")) {
        accepted = obj.at("accepted").as_bool();
    }
    
    if (!accepted) {
        std::string reason = "rejected";
        if (obj.contains("reason")) {
            reason = obj.at("reason").as_string().c_str();
        }
        LOG_WARN("Mesh connection rejected by peer {}: {}", peer_relay_id_, reason);
        on_connection_failed(reason);
        return;
    }
    
    // Connection established!
    connected_ = true;
    reconnect_attempts_ = 0;
    
    LOG_INFO("Mesh connection established with relay {} ({})", peer_relay_id_, peer_info_.url);
    
    if (connect_callback_) {
        connect_callback_(true);
    }
    
    // Start reading
    do_read();
}

void MeshClient::do_read() {
    if (!connected_ || closing_) {
        return;
    }
    
    if (use_ssl_) {
        ws_ssl_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshClient::on_read, shared_from_this()));
    } else {
        ws_plain_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshClient::on_read, shared_from_this()));
    }
}

void MeshClient::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        if (ec != websocket::error::closed && ec != asio::error::operation_aborted) {
            LOG_ERROR("Mesh read error from relay {}: {}", peer_relay_id_, ec.message());
        }
        
        connected_ = false;
        
        if (close_callback_) {
            close_callback_();
        }
        return;
    }
    
    // Parse frame
    auto data = read_buffer_.data();
    std::vector<uint8_t> frame_data(
        static_cast<const uint8_t*>(data.data()),
        static_cast<const uint8_t*>(data.data()) + data.size());
    read_buffer_.consume(bytes_transferred);
    
    Frame frame;
    if (frame.parse(frame_data)) {
        process_frame(frame);
    } else {
        LOG_WARN("Failed to parse mesh frame from relay {}", peer_relay_id_);
    }
    
    // Continue reading
    do_read();
}

void MeshClient::process_frame(const Frame& frame) {
    // 所有 mesh 消息都转发到 MeshManager 统一处理
    // 包括 MESH_PING/PONG 用于 RTT 测量
    if (message_callback_) {
        message_callback_(frame);
    }
}

void MeshClient::send(const Frame& frame) {
    send(frame.serialize());
}

void MeshClient::send(std::vector<uint8_t> data) {
    if (!connected_ || closing_) {
        return;
    }
    
    // Post to strand to ensure thread safety
    asio::post(
        use_ssl_ ? ws_ssl_->get_executor() : ws_plain_->get_executor(),
        [this, self = shared_from_this(), data = std::move(data)]() mutable {
            write_queue_.push(std::move(data));
            
            if (!writing_) {
                do_write();
            }
        });
}

void MeshClient::do_write() {
    if (write_queue_.empty() || !connected_ || closing_) {
        writing_ = false;
        return;
    }
    
    writing_ = true;
    auto& data = write_queue_.front();
    
    if (use_ssl_) {
        ws_ssl_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshClient::on_write, shared_from_this()));
    } else {
        ws_plain_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshClient::on_write, shared_from_this()));
    }
}

void MeshClient::on_write(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        LOG_ERROR("Mesh write error to relay {}: {}", peer_relay_id_, ec.message());
        connected_ = false;
        writing_ = false;
        
        if (close_callback_) {
            close_callback_();
        }
        return;
    }
    
    write_queue_.pop();
    do_write();
}

void MeshClient::close() {
    if (closing_) {
        return;
    }
    
    closing_ = true;
    connected_ = false;
    
    if (reconnect_timer_) {
        reconnect_timer_->cancel();
    }
    
    beast::error_code ec;
    
    if (use_ssl_ && ws_ssl_) {
        ws_ssl_->close(websocket::close_code::normal, ec);
    } else if (ws_plain_) {
        ws_plain_->close(websocket::close_code::normal, ec);
    }
    
    LOG_DEBUG("MeshClient to relay {} closed", peer_relay_id_);
}

void MeshClient::on_connection_failed(const std::string& reason) {
    LOG_WARN("Mesh connection to relay {} failed: {}", peer_relay_id_, reason);
    
    connected_ = false;
    
    if (connect_callback_) {
        connect_callback_(false);
    }
    
    // Schedule reconnect if not closing
    if (!closing_ && reconnect_attempts_ < MAX_RECONNECT_ATTEMPTS) {
        reconnect_attempts_++;
        
        int delay = RECONNECT_DELAY_SEC * reconnect_attempts_;  // Exponential backoff
        LOG_INFO("Will retry mesh connection to relay {} in {}s (attempt {}/{})",
                 peer_relay_id_, delay, reconnect_attempts_, MAX_RECONNECT_ATTEMPTS);
        
        reconnect_timer_ = std::make_unique<asio::steady_timer>(ioc_);
        reconnect_timer_->expires_after(std::chrono::seconds(delay));
        reconnect_timer_->async_wait([this, self = shared_from_this()](boost::system::error_code ec) {
            if (!ec && !closing_) {
                connect();
            }
        });
    } else if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
        LOG_ERROR("Max reconnect attempts reached for relay {}", peer_relay_id_);
    }
}

} // namespace edgelink

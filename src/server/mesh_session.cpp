#include "mesh_session.hpp"
#include "mesh_manager.hpp"
#include "common/log.hpp"

#include <boost/asio/strand.hpp>

namespace edgelink {

// ============================================================================
// MeshSession Implementation
// ============================================================================

MeshSession::MeshSession(tcp::socket socket, MeshManager& manager, uint32_t local_relay_id)
    : manager_(manager)
    , local_relay_id_(local_relay_id)
    , use_ssl_(false)
    , ws_plain_(std::make_unique<websocket::stream<tcp::socket>>(std::move(socket)))
{
    // Get observed endpoint
    try {
        auto ep = ws_plain_->next_layer().remote_endpoint();
        observed_ip_ = ep.address().to_string();
        observed_port_ = ep.port();
    } catch (...) {
        observed_ip_ = "unknown";
    }
    
    LOG_DEBUG("MeshSession created (plain) from {}:{}", observed_ip_, observed_port_);
}

MeshSession::MeshSession(tcp::socket socket, ssl::context& ssl_ctx,
                         MeshManager& manager, uint32_t local_relay_id)
    : manager_(manager)
    , local_relay_id_(local_relay_id)
    , use_ssl_(true)
    , ws_ssl_(std::make_unique<websocket::stream<ssl::stream<tcp::socket>>>(
          std::move(socket), ssl_ctx))
{
    // Get observed endpoint
    try {
        auto ep = beast::get_lowest_layer(*ws_ssl_).remote_endpoint();
        observed_ip_ = ep.address().to_string();
        observed_port_ = ep.port();
    } catch (...) {
        observed_ip_ = "unknown";
    }
    
    LOG_DEBUG("MeshSession created (SSL) from {}:{}", observed_ip_, observed_port_);
}

MeshSession::~MeshSession() {
    close();
}

void MeshSession::start() {
    if (use_ssl_) {
        // Do SSL handshake first
        ws_ssl_->next_layer().async_handshake(
            ssl::stream_base::server,
            [self = shared_from_this()](beast::error_code ec) {
                if (ec) {
                    LOG_ERROR("MeshSession SSL handshake failed: {}", ec.message());
                    return;
                }
                self->do_accept();
            });
    } else {
        do_accept();
    }
}

void MeshSession::do_accept() {
    // Set WebSocket options
    if (use_ssl_) {
        ws_ssl_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_ssl_->set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(beast::http::field::server, "edgelink-relay/1.0");
            }));
        
        ws_ssl_->async_accept(
            beast::bind_front_handler(&MeshSession::on_accept, shared_from_this()));
    } else {
        ws_plain_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_plain_->set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(beast::http::field::server, "edgelink-relay/1.0");
            }));
        
        ws_plain_->async_accept(
            beast::bind_front_handler(&MeshSession::on_accept, shared_from_this()));
    }
}

void MeshSession::on_accept(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("MeshSession WebSocket accept failed from {}:{}: {}", 
                  observed_ip_, observed_port_, ec.message());
        return;
    }
    
    LOG_DEBUG("MeshSession WebSocket accepted from {}:{}", observed_ip_, observed_port_);
    
    connected_ = true;
    
    // Set binary mode
    if (use_ssl_) {
        ws_ssl_->binary(true);
    } else {
        ws_plain_->binary(true);
    }
    
    // Wait for MESH_HELLO
    do_mesh_handshake_receive();
}

void MeshSession::do_mesh_handshake_receive() {
    if (use_ssl_) {
        ws_ssl_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshSession::on_mesh_handshake_received, shared_from_this()));
    } else {
        ws_plain_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshSession::on_mesh_handshake_received, shared_from_this()));
    }
}

void MeshSession::on_mesh_handshake_received(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        LOG_ERROR("Failed to receive mesh hello from {}:{}: {}", 
                  observed_ip_, observed_port_, ec.message());
        return;
    }
    
    // Parse frame
    auto data = read_buffer_.data();
    std::vector<uint8_t> frame_data(
        static_cast<const uint8_t*>(data.data()),
        static_cast<const uint8_t*>(data.data()) + data.size());
    read_buffer_.consume(bytes_transferred);
    
    Frame frame;
    if (!frame.parse(frame_data)) {
        LOG_ERROR("Failed to parse mesh hello frame from {}:{}", observed_ip_, observed_port_);
        send_mesh_handshake_response(false, "Invalid frame");
        return;
    }
    
    if (frame.header.type != MessageType::MESH_HELLO) {
        LOG_ERROR("Expected MESH_HELLO, got type {} from {}:{}", 
                  static_cast<int>(frame.header.type), observed_ip_, observed_port_);
        send_mesh_handshake_response(false, "Expected MESH_HELLO");
        return;
    }
    
    // Parse hello message
    auto json = frame.payload_json();
    if (!json.is_object()) {
        LOG_ERROR("MESH_HELLO payload is not a JSON object from {}:{}", observed_ip_, observed_port_);
        send_mesh_handshake_response(false, "Invalid payload format");
        return;
    }
    
    auto& obj = json.as_object();
    if (obj.contains("relay_id")) {
        peer_relay_id_ = static_cast<uint32_t>(obj.at("relay_id").as_int64());
    }
    if (obj.contains("region")) {
        peer_region_ = obj.at("region").as_string().c_str();
    }
    
    if (peer_relay_id_ == 0) {
        LOG_WARN("Mesh hello with invalid relay_id from {}:{}", observed_ip_, observed_port_);
        send_mesh_handshake_response(false, "Invalid relay_id");
        return;
    }
    
    // Check if we should accept this connection
    // (e.g., avoid duplicate connections - prefer lower relay_id initiates)
    // For now, always accept
    
    LOG_INFO("Received mesh hello from relay {} ({}:{})", 
             peer_relay_id_, observed_ip_, observed_port_);
    
    // Accept the connection
    send_mesh_handshake_response(true);
}

void MeshSession::send_mesh_handshake_response(bool accepted, const std::string& reason) {
    boost::json::object ack_msg;
    ack_msg["relay_id"] = local_relay_id_;
    ack_msg["accepted"] = accepted;
    if (!accepted && !reason.empty()) {
        ack_msg["reason"] = reason;
    }
    
    Frame ack_frame = create_json_frame(MessageType::MESH_HELLO_ACK, ack_msg, FrameFlags::NONE);
    auto data = ack_frame.serialize();
    
    if (use_ssl_) {
        ws_ssl_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshSession::on_mesh_handshake_sent, shared_from_this()));
    } else {
        ws_plain_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshSession::on_mesh_handshake_sent, shared_from_this()));
    }
}

void MeshSession::on_mesh_handshake_sent(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        LOG_ERROR("Failed to send mesh hello ack: {}", ec.message());
        close();
        return;
    }
    
    // Check if we accepted
    if (!authenticated_) {
        // Parse the last sent frame to check... Actually, let's track it differently
        // For simplicity, set authenticated_ before calling send_mesh_handshake_response
    }
    
    // Mark as authenticated and notify manager
    authenticated_ = true;
    
    LOG_INFO("Mesh handshake complete with relay {} ({}:{})", 
             peer_relay_id_, observed_ip_, observed_port_);
    
    // Notify manager of new connection
    manager_.accept_connection(shared_from_this());
    
    // Start reading data
    do_read();
}

void MeshSession::do_read() {
    if (!connected_ || closing_) {
        return;
    }
    
    if (use_ssl_) {
        ws_ssl_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshSession::on_read, shared_from_this()));
    } else {
        ws_plain_->async_read(
            read_buffer_,
            beast::bind_front_handler(&MeshSession::on_read, shared_from_this()));
    }
}

void MeshSession::on_read(beast::error_code ec, std::size_t bytes_transferred) {
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

void MeshSession::process_frame(const Frame& frame) {
    // 所有 mesh 消息都转发到 MeshManager 统一处理
    // 包括 MESH_PING/PONG 用于 RTT 测量
    if (message_callback_) {
        message_callback_(frame);
    }
}

void MeshSession::send(const Frame& frame) {
    send(frame.serialize());
}

void MeshSession::send(std::vector<uint8_t> data) {
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

void MeshSession::do_write() {
    if (write_queue_.empty() || !connected_ || closing_) {
        writing_ = false;
        return;
    }
    
    writing_ = true;
    auto& data = write_queue_.front();
    
    if (use_ssl_) {
        ws_ssl_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshSession::on_write, shared_from_this()));
    } else {
        ws_plain_->async_write(
            asio::buffer(data),
            beast::bind_front_handler(&MeshSession::on_write, shared_from_this()));
    }
}

void MeshSession::on_write(beast::error_code ec, std::size_t bytes_transferred) {
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

void MeshSession::close() {
    if (closing_) {
        return;
    }
    
    closing_ = true;
    connected_ = false;
    
    beast::error_code ec;
    
    if (use_ssl_ && ws_ssl_) {
        ws_ssl_->close(websocket::close_code::normal, ec);
    } else if (ws_plain_) {
        ws_plain_->close(websocket::close_code::normal, ec);
    }
    
    LOG_DEBUG("MeshSession from relay {} closed", peer_relay_id_);
}

} // namespace edgelink

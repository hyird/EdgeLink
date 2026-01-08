#include "client/control_channel.hpp"
#include "common/log.hpp"
#include "common/jwt.hpp"
#include "common/config.hpp"

#include <nlohmann/json.hpp>
#include <regex>
#include <charconv>

namespace edgelink::client {

using json = nlohmann::json;

// ============================================================================
// Base64 Decode Helper
// ============================================================================

static std::vector<uint8_t> decode_base64(const std::string& encoded) {
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    
    std::vector<uint8_t> result;
    int val = 0, bits = -8;
    
    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

// ============================================================================
// URL Parsing Helper
// ============================================================================

// Parse relay URL: ws://host:port/path or wss://host:port/path
static bool parse_relay_url(const std::string& url, 
                            std::string& host, 
                            uint16_t& port, 
                            std::string& path,
                            bool& use_tls) {
    // Default values
    host.clear();
    port = 443;
    path = paths::WS_DATA;
    use_tls = true;
    
    if (url.empty()) {
        return false;
    }
    
    size_t pos = 0;
    
    // Parse scheme
    if (url.substr(0, 6) == "wss://") {
        use_tls = true;
        port = 443;
        pos = 6;
    } else if (url.substr(0, 5) == "ws://") {
        use_tls = false;
        port = 80;
        pos = 5;
    } else {
        // No scheme, assume wss://
        use_tls = true;
        port = 443;
    }
    
    // Find end of host (: or / or end)
    size_t host_end = url.find_first_of(":/", pos);
    if (host_end == std::string::npos) {
        // Just host, no port or path
        host = url.substr(pos);
        return !host.empty();
    }
    
    host = url.substr(pos, host_end - pos);
    if (host.empty()) {
        return false;
    }
    
    pos = host_end;
    
    // Parse port if present
    if (pos < url.size() && url[pos] == ':') {
        pos++;  // skip ':'
        size_t port_end = url.find('/', pos);
        std::string port_str;
        if (port_end == std::string::npos) {
            port_str = url.substr(pos);
            pos = url.size();
        } else {
            port_str = url.substr(pos, port_end - pos);
            pos = port_end;
        }
        
        if (!port_str.empty()) {
            try {
                int port_val = std::stoi(port_str);
                if (port_val > 0 && port_val <= 65535) {
                    port = static_cast<uint16_t>(port_val);
                }
            } catch (...) {
                // Keep default port
            }
        }
    }
    
    // Parse path if present
    if (pos < url.size() && url[pos] == '/') {
        path = url.substr(pos);
        if (path.empty()) {
            path = paths::WS_DATA;
        }
    }
    
    return !host.empty();
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

ControlChannel::ControlChannel(
    net::io_context& ioc,
    ssl::context& ssl_ctx,
    const std::string& controller_url,
    const std::string& machine_key_pub_b64,
    const std::string& machine_key_priv_b64,
    const std::string& auth_key
)
    : ioc_(ioc)
    , ssl_ctx_(ssl_ctx)
    , resolver_(ioc)
    , heartbeat_timer_(ioc)
    , reconnect_timer_(ioc)
    , machine_key_pub_b64_(machine_key_pub_b64)
    , machine_key_priv_b64_(machine_key_priv_b64)
    , auth_key_(auth_key)
{
    // Parse controller URL: ws://host:port or wss://host:port (path is fixed)
    std::regex url_regex(R"((wss?)://([^:/]+)(?::(\d+))?(/.*)?)", std::regex::icase);
    std::smatch match;
    
    if (std::regex_match(controller_url, match, url_regex)) {
        std::string scheme = match[1].str();
        use_ssl_ = (scheme == "wss" || scheme == "WSS");
        controller_host_ = match[2].str();
        controller_port_ = match[3].matched ? match[3].str() : (use_ssl_ ? "443" : "80");
        controller_path_ = paths::WS_CONTROL;  // Fixed path, ignore any path in URL
    } else {
        LOG_ERROR("ControlChannel: Invalid controller URL: {}", controller_url);
        controller_host_ = controller_url;
        controller_port_ = "443";
        controller_path_ = paths::WS_CONTROL;
        use_ssl_ = true;
    }
    
    LOG_INFO("ControlChannel: Configured for {}:{}{} (SSL: {})", 
             controller_host_, controller_port_, controller_path_, use_ssl_ ? "yes" : "no");
}

ControlChannel::~ControlChannel() {
    disconnect();
}

void ControlChannel::set_callbacks(ControlCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

// ============================================================================
// Connection Management
// ============================================================================

void ControlChannel::connect() {
    if (state_ != State::DISCONNECTED && state_ != State::RECONNECTING) {
        LOG_WARN("ControlChannel: Already connecting or connected");
        return;
    }
    
    state_ = State::CONNECTING;
    reconnect_attempts_ = 0;
    last_pong_ = std::chrono::steady_clock::now();  // 初始化以避免虚假超时
    
    LOG_INFO("ControlChannel: Connecting to {}:{}", controller_host_, controller_port_);
    do_resolve();
}

void ControlChannel::disconnect() {
    // 增加连接代数，使所有旧的异步回调失效
    connection_gen_++;
    
    heartbeat_timer_.cancel();
    reconnect_timer_.cancel();
    resolver_.cancel();
    
    beast::error_code ec;
    if (use_ssl_) {
        if (ssl_ws_ && ssl_ws_->is_open()) {
            ssl_ws_->close(websocket::close_code::normal, ec);
        }
        ssl_ws_.reset();
    } else {
        if (plain_ws_ && plain_ws_->is_open()) {
            plain_ws_->close(websocket::close_code::normal, ec);
        }
        plain_ws_.reset();
    }
    
    // 清空写队列
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        std::queue<std::vector<uint8_t>> empty;
        write_queue_.swap(empty);
    }
    writing_ = false;
    
    state_ = State::DISCONNECTED;
    
    LOG_INFO("ControlChannel: Disconnected");
}

void ControlChannel::reconnect() {
    if (state_ == State::RECONNECTING) {
        return;
    }
    
    // 增加连接代数，使所有进行中的异步操作失效
    connection_gen_++;
    
    // 取消所有进行中的操作
    heartbeat_timer_.cancel();
    resolver_.cancel();
    
    // 关闭WebSocket连接（如果有的话）
    beast::error_code ec;
    if (use_ssl_) {
        if (ssl_ws_ && ssl_ws_->is_open()) {
            ssl_ws_->close(websocket::close_code::going_away, ec);
        }
        ssl_ws_.reset();
    } else {
        if (plain_ws_ && plain_ws_->is_open()) {
            plain_ws_->close(websocket::close_code::going_away, ec);
        }
        plain_ws_.reset();
    }
    
    // 清空写队列
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        std::queue<std::vector<uint8_t>> empty;
        write_queue_.swap(empty);
    }
    writing_ = false;
    
    state_ = State::RECONNECTING;
    schedule_reconnect();
}

// ============================================================================
// Connection Flow
// ============================================================================

void ControlChannel::do_resolve() {
    auto gen = connection_gen_.load();
    resolver_.async_resolve(
        controller_host_,
        controller_port_,
        [self = shared_from_this(), gen](beast::error_code ec, tcp::resolver::results_type results) {
            // 检查是否是旧的回调
            if (gen != self->connection_gen_) {
                LOG_DEBUG("ControlChannel: Ignoring stale resolve callback");
                return;
            }
            self->on_resolve(ec, results);
        }
    );
}

void ControlChannel::on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
    if (ec) {
        LOG_ERROR("ControlChannel: Resolve failed: {}", ec.message());
        reconnect();
        return;
    }
    
    auto ep = results.begin()->endpoint();
    do_connect(ep);
}

void ControlChannel::do_connect(tcp::resolver::results_type::endpoint_type ep) {
    auto gen = connection_gen_.load();
    
    if (use_ssl_) {
        ssl_ws_ = std::make_unique<SslWsStream>(ioc_, ssl_ctx_);
        
        // Set SNI hostname
        if (!SSL_set_tlsext_host_name(ssl_ws_->next_layer().native_handle(), controller_host_.c_str())) {
            LOG_ERROR("ControlChannel: Failed to set SNI hostname");
        }
        
        // Set TCP timeout
        beast::get_lowest_layer(*ssl_ws_).expires_after(std::chrono::seconds(30));
        
        beast::get_lowest_layer(*ssl_ws_).async_connect(
            ep,
            [self = shared_from_this(), gen](beast::error_code ec) {
                if (gen != self->connection_gen_) return;
                self->on_connect(ec);
            }
        );
    } else {
        plain_ws_ = std::make_unique<PlainWsStream>(ioc_);
        
        // Set TCP timeout
        beast::get_lowest_layer(*plain_ws_).expires_after(std::chrono::seconds(30));
        
        beast::get_lowest_layer(*plain_ws_).async_connect(
            ep,
            [self = shared_from_this(), gen](beast::error_code ec) {
                if (gen != self->connection_gen_) return;
                self->on_connect(ec);
            }
        );
    }
}

void ControlChannel::on_connect(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("ControlChannel: TCP connect failed: {}", ec.message());
        reconnect();
        return;
    }
    
    if (use_ssl_) {
        LOG_DEBUG("ControlChannel: TCP connected, starting SSL handshake");
        do_ssl_handshake();
    } else {
        LOG_DEBUG("ControlChannel: TCP connected, starting WebSocket handshake (no SSL)");
        do_websocket_handshake();
    }
}

void ControlChannel::do_ssl_handshake() {
    auto gen = connection_gen_.load();
    beast::get_lowest_layer(*ssl_ws_).expires_after(std::chrono::seconds(30));
    
    ssl_ws_->next_layer().async_handshake(
        ssl::stream_base::client,
        [self = shared_from_this(), gen](beast::error_code ec) {
            if (gen != self->connection_gen_) return;
            self->on_ssl_handshake(ec);
        }
    );
}

void ControlChannel::on_ssl_handshake(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("ControlChannel: SSL handshake failed: {}", ec.message());
        reconnect();
        return;
    }
    
    LOG_DEBUG("ControlChannel: SSL handshake complete, starting WebSocket handshake");
    do_ws_handshake();
}

void ControlChannel::do_ws_handshake() {
    auto gen = connection_gen_.load();
    // Include machine_key_pub in query string for initial identification
    std::string target = controller_path_ + "?key=" + machine_key_pub_b64_;
    
    if (use_ssl_) {
        beast::get_lowest_layer(*ssl_ws_).expires_never();
        
        // Set WebSocket options
        ssl_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        ssl_ws_->set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req) {
                req.set(beast::http::field::user_agent, "edgelink-client/1.0");
            }
        ));
        
        ssl_ws_->async_handshake(
            controller_host_,
            target,
            [self = shared_from_this(), gen](beast::error_code ec) {
                if (gen != self->connection_gen_) return;
                self->on_ws_handshake(ec);
            }
        );
    } else {
        beast::get_lowest_layer(*plain_ws_).expires_never();
        
        // Set WebSocket options
        plain_ws_->set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
        plain_ws_->set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req) {
                req.set(beast::http::field::user_agent, "edgelink-client/1.0");
            }
        ));
        
        plain_ws_->async_handshake(
            controller_host_,
            target,
            [self = shared_from_this(), gen](beast::error_code ec) {
                if (gen != self->connection_gen_) return;
                self->on_ws_handshake(ec);
            }
        );
    }
}

// For non-SSL path
void ControlChannel::do_websocket_handshake() {
    do_ws_handshake();
}

void ControlChannel::on_ws_handshake(beast::error_code ec) {
    if (ec) {
        LOG_ERROR("ControlChannel: WebSocket handshake failed: {}", ec.message());
        reconnect();
        return;
    }
    
    LOG_INFO("ControlChannel: WebSocket connected, authenticating");
    state_ = State::AUTHENTICATING;
    
    // Start reading immediately
    do_read();
    
    // Send authentication request
    do_authenticate();
}

// ============================================================================
// Authentication
// ============================================================================

void ControlChannel::do_authenticate() {
    // Build auth request as JSON text
    // Note: machine_key is also in query string, but send in body for explicitness
    
    auto now = std::chrono::system_clock::now();
    auto ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    
    json auth_data;
    auth_data["type"] = "authenticate";
    auth_data["machine_key"] = machine_key_pub_b64_;
    auth_data["timestamp"] = ts;
    // TODO: Sign the timestamp with machine_key_priv
    auth_data["signature"] = "";  // Placeholder
    
    // Include auth_key if provided (for registration/authorization)
    if (!auth_key_.empty()) {
        auth_data["auth_key"] = auth_key_;
        LOG_INFO("ControlChannel: Including auth_key for registration ({}...)", 
                 auth_key_.substr(0, std::min(size_t(8), auth_key_.size())));
    } else {
        LOG_WARN("ControlChannel: No auth_key provided - new node registration may fail");
    }
    
    // Include system info for registration
    #ifdef _WIN32
    auth_data["os"] = "windows";
    #elif __linux__
    auth_data["os"] = "linux";
    #elif __APPLE__
    auth_data["os"] = "darwin";
    #else
    auth_data["os"] = "unknown";
    #endif
    
    #ifdef __x86_64__
    auth_data["arch"] = "amd64";
    #elif __aarch64__
    auth_data["arch"] = "arm64";
    #elif _M_X64
    auth_data["arch"] = "amd64";
    #elif _M_ARM64
    auth_data["arch"] = "arm64";
    #else
    auth_data["arch"] = "unknown";
    #endif
    
    char hostname[256] = {0};
    gethostname(hostname, sizeof(hostname));
    auth_data["hostname"] = hostname;
    auth_data["version"] = "0.1.0";
    
    std::string payload = auth_data.dump();
    
    // Send as text (not binary Frame)
    send_json(payload);
    
    LOG_DEBUG("ControlChannel: Authentication request sent");
}

void ControlChannel::on_auth_response(const Frame& frame) {
    try {
        std::string payload_str(frame.payload.begin(), frame.payload.end());
        json response = json::parse(payload_str);
        
        if (!response.contains("success") || !response["success"].get<bool>()) {
            std::string error = response.value("error", "Unknown error");
            LOG_ERROR("ControlChannel: Authentication failed: {}", error);
            
            if (callbacks_.on_disconnected) {
                callbacks_.on_disconnected(ErrorCode::AUTH_FAILED);
            }
            
            disconnect();
            return;
        }
        
        // Extract node info
        node_id_ = response["node_id"].get<uint32_t>();
        virtual_ip_ = response["virtual_ip"].get<std::string>();
        auth_token_ = response["auth_token"].get<std::string>();
        relay_token_ = response["relay_token"].get<std::string>();
        
        LOG_INFO("ControlChannel: Authenticated as node {} ({})", node_id_, virtual_ip_);
        
        state_ = State::CONNECTED;
        reconnect_attempts_ = 0;
        last_pong_ = std::chrono::steady_clock::now();
        
        // Start heartbeat
        start_heartbeat();
        
        // Notify connected
        if (callbacks_.on_connected) {
            callbacks_.on_connected();
        }
        
        // Parse and notify config if included
        if (response.contains("config")) {
            std::string config_str = response["config"].dump();
            std::vector<uint8_t> config_data(config_str.begin(), config_str.end());
            auto config = parse_config_update(config_data);
            
            if (callbacks_.on_config_update) {
                callbacks_.on_config_update(config);
            }
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannel: Failed to parse auth response: {}", e.what());
        disconnect();
    }
}

// ============================================================================
// Message Handling
// ============================================================================

void ControlChannel::do_read() {
    auto gen = connection_gen_.load();
    
    if (use_ssl_) {
        ssl_ws_->async_read(
            read_buffer_,
            [self = shared_from_this(), gen](beast::error_code ec, std::size_t bytes) {
                if (gen != self->connection_gen_) return;
                self->on_read(ec, bytes);
            }
        );
    } else {
        plain_ws_->async_read(
            read_buffer_,
            [self = shared_from_this(), gen](beast::error_code ec, std::size_t bytes) {
                if (gen != self->connection_gen_) return;
                self->on_read(ec, bytes);
            }
        );
    }
}

void ControlChannel::on_read(beast::error_code ec, std::size_t bytes_transferred) {
    if (ec) {
        if (ec == websocket::error::closed) {
            LOG_INFO("ControlChannel: Connection closed by server");
        } else {
            LOG_ERROR("ControlChannel: Read error: {}", ec.message());
        }
        
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected(ErrorCode::DISCONNECTED);
        }
        
        reconnect();
        return;
    }
    
    // Get received data
    auto data = beast::buffers_to_string(read_buffer_.data());
    read_buffer_.consume(bytes_transferred);
    
    // Try to parse as JSON first (text protocol from Controller)
    if (!data.empty() && data[0] == '{') {
        try {
            json msg = json::parse(data);
            process_json_message(msg);
            
            // Continue reading
            if (state_ != State::DISCONNECTED) {
                do_read();
            }
            return;
        } catch (const json::parse_error&) {
            // Not valid JSON, try Frame format
        }
    }
    
    // Try to parse as Frame (binary protocol)
    std::vector<uint8_t> frame_data(data.begin(), data.end());
    auto frame_result = Frame::deserialize(frame_data);
    
    if (!frame_result) {
        LOG_ERROR("ControlChannel: Failed to deserialize frame");
        do_read();
        return;
    }
    
    process_frame(*frame_result);
    
    // Continue reading
    if (state_ != State::DISCONNECTED) {
        do_read();
    }
}

void ControlChannel::process_frame(const Frame& frame) {
    LOG_DEBUG("ControlChannel: Received frame type={}", static_cast<int>(frame.type));
    
    switch (frame.type) {
        case FrameType::CONTROL: {
            if (state_ == State::AUTHENTICATING) {
                on_auth_response(frame);
            } else {
                // Regular control message
                try {
                    std::string payload_str(frame.payload.begin(), frame.payload.end());
                    json msg = json::parse(payload_str);
                    
                    std::string msg_type = msg.value("type", "");
                    
                    if (msg_type == "config_update") {
                        auto config = parse_config_update(frame.payload);
                        if (callbacks_.on_config_update) {
                            callbacks_.on_config_update(config);
                        }
                    } else if (msg_type == "peer_online") {
                        uint32_t peer_id = msg["node_id"].get<uint32_t>();
                        PeerInfo peer = parse_peer_info(frame.payload);
                        if (callbacks_.on_peer_online) {
                            callbacks_.on_peer_online(peer_id, peer);
                        }
                    } else if (msg_type == "peer_offline") {
                        uint32_t peer_id = msg["node_id"].get<uint32_t>();
                        if (callbacks_.on_peer_offline) {
                            callbacks_.on_peer_offline(peer_id);
                        }
                    } else if (msg_type == "token_refresh") {
                        auth_token_ = msg["auth_token"].get<std::string>();
                        relay_token_ = msg["relay_token"].get<std::string>();
                        if (callbacks_.on_token_refresh) {
                            callbacks_.on_token_refresh(auth_token_, relay_token_);
                        }
                    } else if (msg_type == "peer_key_update") {
                        uint32_t peer_id = msg["node_id"].get<uint32_t>();
                        std::string key_b64 = msg["node_key_pub"].get<std::string>();
                        std::array<uint8_t, 32> key{};
                        auto key_bytes = decode_base64(key_b64);
                        if (key_bytes.size() == 32) {
                            std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
                        }
                        if (callbacks_.on_peer_key_update) {
                            callbacks_.on_peer_key_update(peer_id, key);
                        }
                    } else if (msg_type == "latency_request") {
                        uint32_t req_id = msg["request_id"].get<uint32_t>();
                        if (callbacks_.on_latency_request) {
                            callbacks_.on_latency_request(req_id);
                        }
                    }
                } catch (const std::exception& e) {
                    LOG_ERROR("ControlChannel: Failed to parse control message: {}", e.what());
                }
            }
            break;
        }
        
        case FrameType::PING: {
            // Respond with PONG
            Frame pong;
            pong.type = FrameType::PONG;
            pong.src_id = node_id_;
            pong.dst_id = 0;
            pong.payload = frame.payload;
            send_frame(std::move(pong));
            break;
        }
        
        case FrameType::PONG: {
            last_pong_ = std::chrono::steady_clock::now();
            missed_pongs_ = 0;
            break;
        }
        
        default:
            LOG_WARN("ControlChannel: Unexpected frame type: {}", static_cast<int>(frame.type));
            break;
    }
}

void ControlChannel::process_json_message(const json& msg) {
    std::string msg_type = msg.value("type", "");
    LOG_DEBUG("ControlChannel: Received JSON message type={}", msg_type);
    
    if (msg_type == "config_update" || msg_type == "auth_response") {
        // Handle authentication response / initial config
        if (state_ == State::AUTHENTICATING) {
            bool success = msg.value("success", false);
            if (success) {
                state_ = State::CONNECTED;
                LOG_INFO("ControlChannel: Authentication successful");
                
                // Parse node info
                if (msg.contains("node")) {
                    auto node = msg["node"];
                    node_id_ = node.value("id", 0u);
                    virtual_ip_ = node.value("virtual_ip", "");
                }
                
                // Store tokens
                auth_token_ = msg.value("auth_token", "");
                relay_token_ = msg.value("relay_token", "");
                
                // Parse network config
                ConfigUpdate config;
                if (msg.contains("network")) {
                    auto net = msg["network"];
                    config.network.network_id = net.value("id", 0u);
                    config.network.network_name = net.value("name", "");
                    config.network.cidr = net.value("cidr", "");
                    config.network.mtu = net.value("mtu", 1400);
                }
                
                // Parse peers
                if (msg.contains("peers") && msg["peers"].is_array()) {
                    for (const auto& p : msg["peers"]) {
                        PeerInfo peer;
                        peer.node_id = p.value("node_id", 0u);
                        peer.hostname = p.value("hostname", "");
                        peer.virtual_ip = p.value("virtual_ip", "");
                        peer.online = p.value("online", false);
                        // Parse node_key_pub as base64
                        std::string key_b64 = p.value("node_key_pub", "");
                        if (!key_b64.empty()) {
                            auto key_bytes = decode_base64(key_b64);
                            if (key_bytes.size() == 32) {
                                std::copy(key_bytes.begin(), key_bytes.end(), peer.node_key_pub.begin());
                            }
                        }
                        config.peers.push_back(peer);
                    }
                }
                
                // Parse relays
                if (msg.contains("relays") && msg["relays"].is_array()) {
                    for (const auto& r : msg["relays"]) {
                        std::string url = r.value("url", "");
                        
                        // Skip relays without URL (e.g., STUN-only servers)
                        if (url.empty()) {
                            continue;
                        }
                        
                        RelayServerInfo relay;
                        relay.server_id = r.value("server_id", 0u);
                        relay.name = r.value("name", "");
                        relay.region = r.value("region", "");
                        
                        // Parse URL: ws://host:port/path or wss://host:port/path
                        if (!parse_relay_url(url, relay.host, relay.port, relay.path, relay.use_tls)) {
                            LOG_WARN("ControlChannel: Invalid relay URL: {}", url);
                            continue;
                        }
                        
                        config.relays.push_back(relay);
                    }
                }
                
                config.auth_token = auth_token_;
                config.relay_token = relay_token_;
                
                if (callbacks_.on_config_update) {
                    callbacks_.on_config_update(config);
                }
                
                // Start heartbeat
                reconnect_attempts_ = 0;
                last_pong_ = std::chrono::steady_clock::now();
                start_heartbeat();
            } else {
                std::string error = msg.value("error", "unknown");
                std::string message = msg.value("message", "");
                LOG_ERROR("ControlChannel: Authentication failed: {} - {}", error, message);
                
                if (callbacks_.on_disconnected) {
                    callbacks_.on_disconnected(ErrorCode::AUTH_FAILED);
                }
                
                // Important: Don't reconnect on auth failure - it won't help
                // Just disconnect and let the user fix the issue (e.g., provide auth_key)
                disconnect();
            }
        } else {
            // Config update while connected - parse and notify
            LOG_INFO("ControlChannel: Received config update");
            
            ConfigUpdate config;
            
            // Parse network config
            if (msg.contains("network")) {
                auto net = msg["network"];
                config.network.network_id = net.value("id", 0u);
                config.network.network_name = net.value("name", "");
                config.network.cidr = net.value("cidr", "");
                config.network.mtu = net.value("mtu", 1400);
            }
            
            // Update tokens if present
            if (msg.contains("auth_token")) {
                auth_token_ = msg["auth_token"].get<std::string>();
                config.auth_token = auth_token_;
            }
            if (msg.contains("relay_token")) {
                relay_token_ = msg["relay_token"].get<std::string>();
                config.relay_token = relay_token_;
                if (callbacks_.on_token_refresh) {
                    callbacks_.on_token_refresh(auth_token_, relay_token_);
                }
            }
            
            // Parse peers
            if (msg.contains("peers") && msg["peers"].is_array()) {
                for (const auto& p : msg["peers"]) {
                    PeerInfo peer;
                    peer.node_id = p.value("node_id", 0u);
                    peer.hostname = p.value("hostname", "");
                    peer.virtual_ip = p.value("virtual_ip", "");
                    peer.online = p.value("online", false);
                    std::string key_b64 = p.value("node_key_pub", "");
                    if (!key_b64.empty()) {
                        auto key_bytes = decode_base64(key_b64);
                        if (key_bytes.size() == 32) {
                            std::copy(key_bytes.begin(), key_bytes.end(), peer.node_key_pub.begin());
                        }
                    }
                    config.peers.push_back(peer);
                }
            }
            
            // Parse relays
            if (msg.contains("relays") && msg["relays"].is_array()) {
                for (const auto& r : msg["relays"]) {
                    std::string url = r.value("url", "");
                    
                    // Skip relays without URL
                    if (url.empty()) {
                        continue;
                    }
                    
                    RelayServerInfo relay;
                    relay.server_id = r.value("server_id", 0u);
                    relay.name = r.value("name", "");
                    relay.region = r.value("region", "");
                    
                    if (!parse_relay_url(url, relay.host, relay.port, relay.path, relay.use_tls)) {
                        LOG_WARN("ControlChannel: Invalid relay URL: {}", url);
                        continue;
                    }
                    
                    config.relays.push_back(relay);
                }
            }
            
            if (callbacks_.on_config_update) {
                callbacks_.on_config_update(config);
            }
        }
    } else if (msg_type == "pong") {
        last_pong_ = std::chrono::steady_clock::now();
        missed_pongs_ = 0;
    } else if (msg_type == "peer_online") {
        uint32_t peer_id = msg.value("node_id", 0u);
        PeerInfo peer;
        peer.node_id = peer_id;
        peer.hostname = msg.value("hostname", "");
        peer.virtual_ip = msg.value("virtual_ip", "");
        peer.online = true;
        if (callbacks_.on_peer_online) {
            callbacks_.on_peer_online(peer_id, peer);
        }
    } else if (msg_type == "peer_offline") {
        uint32_t peer_id = msg.value("node_id", 0u);
        if (callbacks_.on_peer_offline) {
            callbacks_.on_peer_offline(peer_id);
        }
    } else if (msg_type == "p2p_response") {
        // Response to our P2P connection request
        uint32_t peer_id = msg.value("peer_node_id", 0u);
        bool success = msg.value("success", false);
        
        if (success && callbacks_.on_p2p_endpoints) {
            auto endpoints_json = msg.value("endpoints", json::array());
            std::string nat_type = msg.value("nat_type", "unknown");
            
            std::vector<std::string> endpoints;
            for (const auto& ep : endpoints_json) {
                if (ep.is_object()) {
                    std::string addr = ep.value("address", "");
                    uint16_t port = ep.value("port", 0);
                    if (!addr.empty() && port > 0) {
                        endpoints.push_back(addr + ":" + std::to_string(port));
                    }
                }
            }
            
            LOG_INFO("ControlChannel: Received {} P2P endpoints for peer {}",
                     endpoints.size(), peer_id);
            callbacks_.on_p2p_endpoints(peer_id, endpoints, nat_type);
        }
    } else if (msg_type == "p2p_init") {
        // Another peer wants to connect via P2P
        uint32_t peer_id = msg.value("peer_node_id", 0u);
        auto endpoints_json = msg.value("endpoints", json::array());
        std::string nat_type = msg.value("nat_type", "unknown");
        
        if (peer_id > 0 && callbacks_.on_p2p_init) {
            std::vector<std::string> endpoints;
            for (const auto& ep : endpoints_json) {
                if (ep.is_object()) {
                    std::string addr = ep.value("address", "");
                    uint16_t port = ep.value("port", 0);
                    if (!addr.empty() && port > 0) {
                        endpoints.push_back(addr + ":" + std::to_string(port));
                    }
                }
            }
            
            LOG_INFO("ControlChannel: Peer {} wants P2P, {} endpoints",
                     peer_id, endpoints.size());
            callbacks_.on_p2p_init(peer_id, endpoints, nat_type);
        }
    } else if (msg_type == "error") {
        std::string error = msg.value("error", "unknown");
        std::string message = msg.value("message", "");
        LOG_ERROR("ControlChannel: Server error: {} - {}", error, message);
    } else {
        LOG_WARN("ControlChannel: Unknown JSON message type: {}", msg_type);
    }
}

// ============================================================================
// Sending
// ============================================================================

void ControlChannel::send_json(const std::string& json_str) {
    std::vector<uint8_t> data(json_str.begin(), json_str.end());
    
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_queue_.push(std::move(data));
    }
    
    if (!writing_.exchange(true)) {
        do_write_text();
    }
}

void ControlChannel::send_frame(Frame frame) {
    auto data = frame.serialize();
    
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        write_queue_.push(std::move(data));
    }
    
    if (!writing_.exchange(true)) {
        do_write();
    }
}

void ControlChannel::do_write() {
    std::vector<uint8_t> data;
    
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (write_queue_.empty()) {
            writing_ = false;
            return;
        }
        data = std::move(write_queue_.front());
        write_queue_.pop();
    }
    
    auto gen = connection_gen_.load();
    
    if (use_ssl_) {
        ssl_ws_->binary(true);
        ssl_ws_->async_write(
            net::buffer(data),
            [self = shared_from_this(), gen, data = std::move(data)](beast::error_code ec, std::size_t) mutable {
                if (gen != self->connection_gen_) return;
                if (ec) {
                    LOG_ERROR("ControlChannel: Write error: {}", ec.message());
                    return;
                }
                self->do_write();
            }
        );
    } else {
        plain_ws_->binary(true);
        plain_ws_->async_write(
            net::buffer(data),
            [self = shared_from_this(), gen, data = std::move(data)](beast::error_code ec, std::size_t) mutable {
                if (gen != self->connection_gen_) return;
                if (ec) {
                    LOG_ERROR("ControlChannel: Write error: {}", ec.message());
                    return;
                }
                self->do_write();
            }
        );
    }
}

void ControlChannel::do_write_text() {
    std::vector<uint8_t> data;
    
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (write_queue_.empty()) {
            writing_ = false;
            return;
        }
        data = std::move(write_queue_.front());
        write_queue_.pop();
    }
    
    auto gen = connection_gen_.load();
    
    if (use_ssl_) {
        ssl_ws_->text(true);  // Send as text, not binary
        ssl_ws_->async_write(
            net::buffer(data),
            [self = shared_from_this(), gen, data = std::move(data)](beast::error_code ec, std::size_t) mutable {
                if (gen != self->connection_gen_) return;
                if (ec) {
                    LOG_ERROR("ControlChannel: Write error: {}", ec.message());
                    return;
                }
                self->do_write_text();
            }
        );
    } else {
        plain_ws_->text(true);  // Send as text, not binary
        plain_ws_->async_write(
            net::buffer(data),
            [self = shared_from_this(), gen, data = std::move(data)](beast::error_code ec, std::size_t) mutable {
                if (gen != self->connection_gen_) return;
                if (ec) {
                    LOG_ERROR("ControlChannel: Write error: {}", ec.message());
                    return;
                }
                self->do_write_text();
            }
        );
    }
}

// ============================================================================
// Heartbeat
// ============================================================================

void ControlChannel::start_heartbeat() {
    auto gen = connection_gen_.load();
    heartbeat_timer_.expires_after(std::chrono::seconds(NetworkConstants::DEFAULT_HEARTBEAT_INTERVAL));
    heartbeat_timer_.async_wait([self = shared_from_this(), gen](boost::system::error_code ec) {
        if (!ec && gen == self->connection_gen_) {
            self->on_heartbeat_timer();
        }
    });
}

void ControlChannel::on_heartbeat_timer() {
    if (state_ != State::CONNECTED) {
        return;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto since_pong = std::chrono::duration_cast<std::chrono::seconds>(now - last_pong_).count();
    
    if (since_pong > NetworkConstants::DEFAULT_HEARTBEAT_INTERVAL * 3) {
        LOG_WARN("ControlChannel: No pong received for {}s, reconnecting", since_pong);
        reconnect();
        return;
    }
    
    // Send JSON ping (Controller expects JSON format, not binary Frame)
    auto ts = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    json ping_msg;
    ping_msg["type"] = "ping";
    ping_msg["timestamp"] = ts;
    send_json(ping_msg.dump());
    
    // Reschedule
    start_heartbeat();
}

// ============================================================================
// Reconnection
// ============================================================================

void ControlChannel::schedule_reconnect() {
    if (reconnect_attempts_ >= MAX_RECONNECT_ATTEMPTS) {
        LOG_ERROR("ControlChannel: Max reconnect attempts reached");
        state_ = State::DISCONNECTED;
        if (callbacks_.on_disconnected) {
            callbacks_.on_disconnected(ErrorCode::MAX_RETRIES_EXCEEDED);
        }
        return;
    }
    
    // Exponential backoff
    auto delay = INITIAL_RECONNECT_DELAY * (1 << std::min(reconnect_attempts_, 6u));
    if (delay > MAX_RECONNECT_DELAY) {
        delay = MAX_RECONNECT_DELAY;
    }
    
    LOG_INFO("ControlChannel: Reconnecting in {} seconds (attempt {})",
             std::chrono::duration_cast<std::chrono::seconds>(delay).count(),
             reconnect_attempts_ + 1);
    
    auto gen = connection_gen_.load();
    reconnect_timer_.expires_after(delay);
    reconnect_timer_.async_wait([self = shared_from_this(), gen](boost::system::error_code ec) {
        if (!ec && gen == self->connection_gen_) {
            self->on_reconnect_timer();
        }
    });
}

void ControlChannel::on_reconnect_timer() {
    reconnect_attempts_++;
    
    // 初始化 last_pong_ 以避免立即超时
    last_pong_ = std::chrono::steady_clock::now();
    
    state_ = State::CONNECTING;
    LOG_INFO("ControlChannel: Connecting to {}:{}", controller_host_, controller_port_);
    do_resolve();
}

// ============================================================================
// Control Messages
// ============================================================================

void ControlChannel::report_latency(uint32_t peer_node_id, uint32_t relay_id, uint32_t latency_ms) {
    if (state_ != State::CONNECTED) {
        return;
    }
    
    // Format that Controller expects
    json msg;
    msg["type"] = "latency_report";
    
    // Create measurements array
    json measurements = json::array();
    json measurement;
    measurement["server_id"] = relay_id;
    measurement["rtt_ms"] = latency_ms;
    if (peer_node_id > 0) {
        measurement["peer_id"] = peer_node_id;  // Optional: if measuring to a specific peer
    }
    measurements.push_back(measurement);
    
    msg["measurements"] = measurements;
    
    send_json(msg.dump());
}

void ControlChannel::report_latency_batch(const std::vector<LatencyMeasurement>& measurements) {
    if (state_ != State::CONNECTED || measurements.empty()) {
        return;
    }
    
    json msg;
    msg["type"] = "latency_report";
    
    json meas_array = json::array();
    for (const auto& m : measurements) {
        json entry;
        entry["server_id"] = m.server_id;
        entry["rtt_ms"] = m.rtt_ms;
        if (m.peer_id > 0) {
            entry["peer_id"] = m.peer_id;
        }
        meas_array.push_back(entry);
    }
    
    msg["measurements"] = meas_array;
    
    LOG_DEBUG("ControlChannel: Reporting {} latency measurements", measurements.size());
    send_json(msg.dump());
}

void ControlChannel::report_relay_connection(uint32_t server_id, bool connected) {
    if (state_ != State::CONNECTED) {
        return;
    }
    
    json msg;
    msg["type"] = connected ? "relay_connect" : "relay_disconnect";
    msg["server_id"] = server_id;
    
    send_json(msg.dump());
}

void ControlChannel::report_endpoints(const std::vector<std::string>& endpoints) {
    if (state_ != State::CONNECTED) {
        return;
    }
    
    json msg;
    msg["type"] = "endpoints_report";
    msg["endpoints"] = endpoints;
    
    std::string payload = msg.dump();
    
    Frame frame;
    frame.type = FrameType::CONTROL;
    frame.src_id = node_id_;
    frame.dst_id = 0;
    frame.payload.assign(payload.begin(), payload.end());
    
    send_frame(std::move(frame));
}

void ControlChannel::request_peer_endpoints(uint32_t peer_node_id) {
    if (state_ != State::CONNECTED) {
        return;
    }
    
    LOG_DEBUG("ControlChannel: Requesting P2P endpoints for peer {}", peer_node_id);
    
    json msg;
    msg["type"] = "p2p_request";  // Match controller's handle_p2p_request
    msg["peer_node_id"] = peer_node_id;
    
    send_json(msg.dump());
}

void ControlChannel::report_key_rotation(const std::array<uint8_t, 32>& new_pubkey,
                                         const std::string& signature_b64) {
    if (state_ != State::CONNECTED) {
        return;
    }
    
    // TODO: Encode pubkey to base64
    json msg;
    msg["type"] = "key_rotation";
    msg["node_key_pub"] = "";  // base64 encoded
    msg["signature"] = signature_b64;
    
    std::string payload = msg.dump();
    
    Frame frame;
    frame.type = FrameType::CONTROL;
    frame.src_id = node_id_;
    frame.dst_id = 0;
    frame.payload.assign(payload.begin(), payload.end());
    
    send_frame(std::move(frame));
}

// ============================================================================
// Parsing Helpers
// ============================================================================

ConfigUpdate ControlChannel::parse_config_update(const std::vector<uint8_t>& payload) {
    ConfigUpdate config;
    
    try {
        std::string payload_str(payload.begin(), payload.end());
        json data = json::parse(payload_str);
        
        // Parse network config
        if (data.contains("network")) {
            auto& net = data["network"];
            config.network.network_id = net.value("id", 0u);
            config.network.network_name = net.value("name", "");
            config.network.cidr = net.value("cidr", "");
            config.network.derp_enabled = net.value("derp_enabled", true);
            config.network.mtu = net.value("mtu", NetworkConstants::DEFAULT_TUN_MTU);
        }
        
        // Parse peers
        if (data.contains("peers") && data["peers"].is_array()) {
            for (auto& p : data["peers"]) {
                PeerInfo peer;
                peer.node_id = p.value("id", 0u);
                peer.hostname = p.value("hostname", "");
                peer.virtual_ip = p.value("virtual_ip", "");
                peer.online = p.value("online", false);
                
                if (p.contains("endpoints") && p["endpoints"].is_array()) {
                    for (auto& ep : p["endpoints"]) {
                        peer.endpoints.push_back(ep.get<std::string>());
                    }
                }
                
                // TODO: Parse node_key_pub from base64
                
                config.peers.push_back(std::move(peer));
            }
        }
        
        // Parse relays
        if (data.contains("relays") && data["relays"].is_array()) {
            for (auto& r : data["relays"]) {
                RelayServerInfo relay;
                relay.server_id = r.value("id", 0u);
                relay.name = r.value("name", "");
                relay.region = r.value("region", "");
                relay.host = r.value("host", "");
                relay.port = r.value("port", 443);
                relay.path = r.value("path", "/ws/data");
                relay.capabilities = r.value("capabilities", 0);
                relay.available = r.value("available", true);
                
                config.relays.push_back(std::move(relay));
            }
        }
        
        // Parse tokens
        config.auth_token = data.value("auth_token", auth_token_);
        config.relay_token = data.value("relay_token", relay_token_);
        
        // Parse recommended relay
        config.recommended_relay_id = data.value("recommended_relay_id", 0u);
        
        // Parse subnet routes
        if (data.contains("subnet_routes") && data["subnet_routes"].is_array()) {
            for (auto& sr : data["subnet_routes"]) {
                SubnetRouteInfo route;
                route.cidr = sr.value("cidr", "");
                route.via_node_id = sr.value("via_node_id", 0u);
                route.gateway_ip = sr.value("gateway_ip", "");
                route.priority = sr.value("priority", 100);
                route.weight = sr.value("weight", 100);
                route.gateway_online = sr.value("gateway_online", false);
                
                if (!route.cidr.empty() && route.via_node_id > 0) {
                    config.subnet_routes.push_back(std::move(route));
                }
            }
        }
        
        config.timestamp = std::chrono::system_clock::now();
        
    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannel: Failed to parse config update: {}", e.what());
    }
    
    return config;
}

PeerInfo ControlChannel::parse_peer_info(const std::vector<uint8_t>& data) {
    PeerInfo peer;
    
    try {
        std::string data_str(data.begin(), data.end());
        json p = json::parse(data_str);
        
        peer.node_id = p.value("node_id", 0u);
        peer.hostname = p.value("hostname", "");
        peer.virtual_ip = p.value("virtual_ip", "");
        peer.online = p.value("online", false);
        
        if (p.contains("endpoints") && p["endpoints"].is_array()) {
            for (auto& ep : p["endpoints"]) {
                peer.endpoints.push_back(ep.get<std::string>());
            }
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("ControlChannel: Failed to parse peer info: {}", e.what());
    }
    
    return peer;
}

} // namespace edgelink::client

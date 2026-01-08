#pragma once

#include <string>
#include <memory>
#include <functional>
#include <expected>
#include <vector>
#include <atomic>
#include <mutex>
#include <queue>
#include <chrono>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <nlohmann/json.hpp>

#include "common/protocol.hpp"
#include "common/frame.hpp"

namespace edgelink::client {

namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;

// ============================================================================
// Network Configuration (received from Controller)
// ============================================================================
struct NetworkConfig {
    uint32_t network_id = 0;
    std::string network_name;
    std::string cidr;                     // e.g., "10.100.0.0/16"
    bool derp_enabled = true;
    uint16_t mtu = NetworkConstants::DEFAULT_TUN_MTU;
};

// ============================================================================
// Peer Information (received from Controller)
// ============================================================================
struct PeerInfo {
    uint32_t node_id = 0;
    std::string hostname;
    std::string virtual_ip;
    std::array<uint8_t, 32> node_key_pub;  // X25519 public key
    bool online = false;
    std::vector<std::string> endpoints;    // Known endpoints
    std::chrono::system_clock::time_point last_seen;
};

// ============================================================================
// Relay Server Info (received from Controller)
// ============================================================================
struct RelayServerInfo {
    uint32_t server_id = 0;
    std::string name;
    std::string region;
    std::string host;
    uint16_t port = 443;
    std::string path = "/ws/data";
    bool use_tls = true;
    uint8_t capabilities = 0;
    bool available = true;
};

// ============================================================================
// Subnet Route (advertised by gateway nodes)
// ============================================================================
struct SubnetRouteInfo {
    std::string cidr;                  // e.g., "192.168.1.0/24"
    uint32_t via_node_id = 0;          // Gateway node ID
    std::string gateway_ip;            // Gateway's virtual IP
    uint16_t priority = 100;           // Higher = more preferred
    uint16_t weight = 100;             // For load balancing
    bool gateway_online = false;       // Is gateway currently online?
};

// ============================================================================
// Full Configuration Update
// ============================================================================
struct ConfigUpdate {
    NetworkConfig network;
    std::vector<PeerInfo> peers;
    std::vector<RelayServerInfo> relays;
    std::vector<SubnetRouteInfo> subnet_routes;  // Subnet routes from gateways
    std::string auth_token;
    std::string relay_token;
    uint32_t recommended_relay_id = 0;           // Controller's recommended relay
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Control Channel Callbacks
// ============================================================================
struct ControlCallbacks {
    // Called when configuration is received/updated
    std::function<void(const ConfigUpdate&)> on_config_update;
    
    // Called when connected to controller
    std::function<void()> on_connected;
    
    // Called when disconnected from controller
    std::function<void(ErrorCode)> on_disconnected;
    
    // Called when a peer comes online
    std::function<void(uint32_t node_id, const PeerInfo&)> on_peer_online;
    
    // Called when a peer goes offline
    std::function<void(uint32_t node_id)> on_peer_offline;
    
    // Called when token needs refresh
    std::function<void(const std::string& new_auth_token, 
                       const std::string& new_relay_token)> on_token_refresh;
    
    // Called for peer key update (rotation)
    std::function<void(uint32_t node_id, 
                       const std::array<uint8_t, 32>& new_pubkey)> on_peer_key_update;
    
    // Called for latency measurement request
    std::function<void(uint32_t request_id)> on_latency_request;
    
    // P2P callbacks
    // Called when we receive peer's P2P endpoints (response to our request)
    std::function<void(uint32_t peer_id, 
                       const std::vector<std::string>& endpoints,
                       const std::string& nat_type)> on_p2p_endpoints;
    
    // Called when a peer wants to initiate P2P with us
    std::function<void(uint32_t peer_id,
                       const std::vector<std::string>& endpoints,
                       const std::string& nat_type)> on_p2p_init;
};

// ============================================================================
// Control Channel - WebSocket connection to Controller
// ============================================================================
class ControlChannel : public std::enable_shared_from_this<ControlChannel> {
public:
    using SslWsStream = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;
    using PlainWsStream = websocket::stream<beast::tcp_stream>;
    // Backward compatibility alias
    using WsStream = SslWsStream;
    
    enum class State {
        DISCONNECTED,
        CONNECTING,
        AUTHENTICATING,
        CONNECTED,
        RECONNECTING
    };
    
    ControlChannel(
        net::io_context& ioc,
        ssl::context& ssl_ctx,
        const std::string& controller_url,
        const std::string& machine_key_pub_b64,
        const std::string& machine_key_priv_b64,
        const std::string& auth_key = ""
    );
    
    ~ControlChannel();
    
    // Non-copyable
    ControlChannel(const ControlChannel&) = delete;
    ControlChannel& operator=(const ControlChannel&) = delete;
    
    // ========================================================================
    // Connection Management
    // ========================================================================
    
    // Start connection to controller
    void connect();
    
    // Disconnect from controller
    void disconnect();
    
    // Reconnect (with exponential backoff)
    void reconnect();
    
    // Check connection state
    State state() const { return state_.load(); }
    bool is_connected() const { return state_ == State::CONNECTED; }
    
    // Set callbacks
    void set_callbacks(ControlCallbacks callbacks);
    
    // ========================================================================
    // Control Messages
    // ========================================================================
    
    // Report latency measurements to controller
    void report_latency(uint32_t peer_node_id, uint32_t relay_id, uint32_t latency_ms);
    
    // Batch report multiple latency measurements
    struct LatencyMeasurement {
        uint32_t server_id = 0;
        uint32_t peer_id = 0;    // 0 means to the relay itself
        uint32_t rtt_ms = 0;
    };
    void report_latency_batch(const std::vector<LatencyMeasurement>& measurements);
    
    // Report relay connection/disconnection
    void report_relay_connection(uint32_t server_id, bool connected);
    
    // Report endpoints discovered via STUN/local
    void report_endpoints(const std::vector<std::string>& endpoints);
    
    // Request peer endpoints for P2P connection
    void request_peer_endpoints(uint32_t peer_node_id);
    
    // Report our new node_key_pub after rotation
    void report_key_rotation(const std::array<uint8_t, 32>& new_pubkey,
                             const std::string& signature_b64);
    
    // ========================================================================
    // Getters
    // ========================================================================
    
    uint32_t node_id() const { return node_id_; }
    const std::string& virtual_ip() const { return virtual_ip_; }
    const std::string& auth_token() const { return auth_token_; }
    const std::string& relay_token() const { return relay_token_; }
    const NetworkConfig& network_config() const { return network_config_; }

private:
    // Connection flow
    void do_resolve();
    void on_resolve(beast::error_code ec, tcp::resolver::results_type results);
    void do_connect(tcp::resolver::results_type::endpoint_type ep);
    void on_connect(beast::error_code ec);
    void do_ssl_handshake();
    void on_ssl_handshake(beast::error_code ec);
    void do_websocket_handshake();  // For non-SSL path
    void do_ws_handshake();
    void on_ws_handshake(beast::error_code ec);
    
    // Authentication
    void do_authenticate();
    void on_auth_response(const Frame& frame);
    
    // Message handling
    void do_read();
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void process_frame(const Frame& frame);
    void process_json_message(const nlohmann::json& msg);
    
    // Sending
    void do_write();
    void do_write_text();
    void send_frame(Frame frame);
    void send_json(const std::string& json_str);
    
    // Heartbeat
    void start_heartbeat();
    void on_heartbeat_timer();
    
    // Reconnection
    void schedule_reconnect();
    void on_reconnect_timer();
    
    // Parsing helpers
    ConfigUpdate parse_config_update(const std::vector<uint8_t>& payload);
    PeerInfo parse_peer_info(const std::vector<uint8_t>& data);
    
    // IO context
    net::io_context& ioc_;
    ssl::context& ssl_ctx_;
    tcp::resolver resolver_;
    std::unique_ptr<SslWsStream> ssl_ws_;
    std::unique_ptr<PlainWsStream> plain_ws_;
    bool use_ssl_ = true;
    
    // Connection state
    std::atomic<State> state_{State::DISCONNECTED};
    std::atomic<uint32_t> connection_gen_{0};  // 连接代数，用于使旧的回调失效
    std::string controller_host_;
    std::string controller_port_;
    std::string controller_path_;
    
    // Authentication
    std::string machine_key_pub_b64_;
    std::string machine_key_priv_b64_;
    std::string auth_key_;
    uint32_t node_id_ = 0;
    std::string virtual_ip_;
    std::string auth_token_;
    std::string relay_token_;
    
    // Network configuration
    NetworkConfig network_config_;
    
    // Callbacks
    ControlCallbacks callbacks_;
    
    // Read buffer
    beast::flat_buffer read_buffer_;
    
    // Write queue
    std::mutex write_mutex_;
    std::queue<std::vector<uint8_t>> write_queue_;
    std::atomic<bool> writing_{false};
    
    // Heartbeat
    net::steady_timer heartbeat_timer_;
    std::chrono::steady_clock::time_point last_pong_{std::chrono::steady_clock::now()};  // 初始化！
    uint32_t missed_pongs_ = 0;
    
    // Reconnection
    net::steady_timer reconnect_timer_;
    uint32_t reconnect_attempts_ = 0;
    static constexpr uint32_t MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr auto INITIAL_RECONNECT_DELAY = std::chrono::seconds(1);
    static constexpr auto MAX_RECONNECT_DELAY = std::chrono::minutes(5);
};

} // namespace edgelink::client
